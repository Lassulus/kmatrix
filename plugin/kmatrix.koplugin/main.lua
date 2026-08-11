--[[--
Matrix chat client for KOReader.

All the heavy lifting (HTTP, sync, E2EE, storage) happens in `kmatrixd`, a
separate daemon running on the same device. This plugin only speaks the
line-delimited JSON protocol described in PROTOCOL.md over loopback TCP, so the
UI thread never blocks on the network.

@module koplugin.kmatrix
--]]

local ButtonDialog = require("ui/widget/buttondialog")
local Font = require("ui/font")
local IPC = require("ipc")
local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local Menu = require("ui/widget/menu")
local MultiInputDialog = require("ui/widget/multiinputdialog")
local TextViewer = require("ui/widget/textviewer")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local datetime = require("datetime")
local lfs = require("libs/libkoreader-lfs")
local logger = require("logger")
local util = require("util")
local _ = require("gettext")
local T = require("ffi/util").template

-- The daemon needs a moment to bind its socket and write the port file.
local DAEMON_POLL_INTERVAL = 0.5 -- seconds between port-file probes
local DAEMON_POLL_TRIES = 20     -- ~10 s before giving up

local MESSAGE_LIMIT = 100

-- Backfill: how many events the daemon fetches per /messages page, and the
-- ceiling on how much of that history the timeline keeps on screen -- every
-- row costs memory on a device that has a few megabytes to spare.
local BACKFILL_LIMIT = 50
local MESSAGE_WINDOW_MAX = 500

local STATE_LABELS = {
    logged_out = _("Logged out"),
    connecting = _("Connecting…"),
    syncing = _("Syncing"),
    offline = _("Offline"),
}

local function shellQuote(str)
    return "'" .. (str:gsub("'", "'\\''")) .. "'"
end

--- "@alice:example.org" -> "alice"; anything unexpected is passed through.
local function shortSender(user_id)
    if not user_id then return "?" end
    return user_id:match("^@([^:]+):") or user_id
end

--- A field the daemon may omit, as a string or nil.
--
-- The JSON decoder renders a null as a truthy sentinel rather than nil, so
-- `resp.field or fallback` silently yields the sentinel and the next
-- concatenation throws. Anything that is not a string did not arrive.
local function str(value)
    return type(value) == "string" and value or nil
end

-- Milliseconds the device clock runs ahead of real time, as measured by the
-- daemon against the homeserver's Date header and reported by `status`.
--
-- Message timestamps are honest UTC, but `os.date` renders them in the
-- device's own frame, and e-readers are often set wrong: this Kindle keeps
-- Berlin time in a clock labelled UTC, which its native UI hides by also
-- claiming to be in GMT. Rendering raw UTC there reads as two hours stale.
-- Adding the measured offset puts chat times in the same frame as every
-- other clock on the device, and does nothing at all once the clock is right.
local clock_skew_ms = 0

local function localise(ts_ms)
    return math.floor((ts_ms + clock_skew_ms) / 1000)
end

local function clockOf(ts_ms)
    if not ts_ms or ts_ms <= 0 then return nil end
    return datetime.secondsToHour(localise(ts_ms),
        G_reader_settings:isTrue("twelve_hour_clock"))
end

local function dateTimeOf(ts_ms)
    if not ts_ms or ts_ms <= 0 then return "" end
    return datetime.secondsToDateTime(localise(ts_ms))
end

local KMatrix = WidgetContainer:extend{
    name = "kmatrix",
    is_doc_only = false,
}

function KMatrix:init()
    self.ipc = nil
    self.message_queue = nil
    self.start_poll = nil
    self.busy_msg = nil
    self.room_menu = nil
    self.timeline = nil
    self.verify_dialog = nil
    self.rooms = {}
    self.state = nil
    self.user_id = nil
    self.device_id = nil
    self.homeserver = nil
    self.backup = nil
    self.reconnect_on_resume = false
    self.ui.menu:registerToMainMenu(self)
end

function KMatrix:addToMainMenu(menu_items)
    menu_items.kmatrix = {
        text = _("Matrix"),
        sorting_hint = "more_tools",
        callback = function()
            self:openMatrix()
        end,
    }
end

--[[ Notifications ]]--

function KMatrix:notify(text, timeout)
    UIManager:show(InfoMessage:new{
        text = text,
        timeout = timeout or 3,
    })
end

function KMatrix:setBusy(text)
    self:clearBusy()
    self.busy_msg = InfoMessage:new{ text = text }
    UIManager:show(self.busy_msg)
end

function KMatrix:clearBusy()
    if self.busy_msg then
        UIManager:close(self.busy_msg)
        self.busy_msg = nil
    end
end

--[[ Daemon lifecycle and connection ]]--

function KMatrix:isConnected()
    return self.ipc ~= nil and self.ipc:isConnected()
end

--- Guard for anything that needs a live daemon; never raises.
function KMatrix:daemonReady()
    if self:isConnected() then return true end
    self:notify(_("The Matrix daemon is not running."))
    return false
end

--- Launches kmatrixd detached. Returns false (with a message shown) when the
-- binary is not installed.
function KMatrix:spawnDaemon()
    local dir = IPC.dataDir()
    util.makePath(dir)
    local binary = dir .. "/kmatrixd"
    if lfs.attributes(binary, "mode") ~= "file" then
        -- Say which of the two it is. Everything here lives on /mnt/us, which
        -- is not there while the Kindle is plugged into a computer, and a
        -- daemon that is merely out of sight reads as uninstalled -- the same
        -- message for a missing file and a missing volume sends you looking
        -- in the wrong place.
        local seen = lfs.attributes(dir, "mode")
        logger.warn("kmatrix: cannot launch", binary, "- data dir is", tostring(seen))
        if seen ~= "directory" then
            self:notify(T(_("Cannot see %1.\nIf the device is plugged into a computer, unplug it and try again."), dir), 5)
        else
            self:notify(T(_("The Matrix daemon is not installed.\nExpected it at: %1"), binary), 5)
        end
        return false
    end
    local command = string.format("%s --data-dir %s >> %s 2>&1 &",
        shellQuote(binary), shellQuote(dir), shellQuote(dir .. "/kmatrix.log"))
    -- Logged at info so that a launch that goes nowhere leaves a trace in
    -- crash.log: the daemon's own log only exists once it gets as far as
    -- writing to it.
    logger.info("kmatrix: launching daemon:", command)
    os.execute(command)
    return true
end

function KMatrix:openConnection(port, token)
    local ipc = IPC:new{
        on_event = function(event) self:onDaemonEvent(event) end,
        on_disconnect = function(err) self:onDaemonDisconnect(err) end,
    }
    local ok, err = ipc:connect(port, token)
    if not ok then
        logger.dbg("kmatrix: cannot reach daemon on port", port, err)
        return false
    end
    self.ipc = ipc
    self.message_queue = UIManager:insertZMQ(ipc)
    logger.dbg("kmatrix: connected to daemon on port", port)
    return true
end

--- Connects, spawning and waiting for the daemon if needed.
-- @tparam func done called with a boolean; never called synchronously twice.
function KMatrix:ensureConnected(done)
    if self:isConnected() then
        done(true)
        return
    end
    self:teardownConnection()

    -- A stale port file from a dead daemon simply fails to connect below.
    local port, token = IPC.readPortFile()
    if port and self:openConnection(port, token) then
        done(true)
        return
    end
    if not self:spawnDaemon() then
        done(false)
        return
    end
    self:setBusy(_("Starting the Matrix daemon…"))
    self:pollForDaemon(DAEMON_POLL_TRIES, done)
end

--- Waits for the port file without blocking the UI: one probe per scheduler tick.
function KMatrix:pollForDaemon(tries, done)
    self.start_poll = function()
        self.start_poll = nil
        local port, token = IPC.readPortFile()
        if port and self:openConnection(port, token) then
            self:clearBusy()
            done(true)
            return
        end
        if tries <= 1 then
            self:clearBusy()
            self:notify(T(_("Could not start the Matrix daemon.\nSee %1"),
                IPC.dataDir() .. "/kmatrix.log"), 5)
            done(false)
            return
        end
        self:pollForDaemon(tries - 1, done)
    end
    UIManager:scheduleIn(DAEMON_POLL_INTERVAL, self.start_poll)
end

function KMatrix:teardownConnection()
    self:closeVerification()
    if self.start_poll then
        UIManager:unschedule(self.start_poll)
        self.start_poll = nil
    end
    if self.ipc then
        -- We are tearing down on purpose: no disconnect notification wanted.
        self.ipc.on_disconnect = nil
        self.ipc:stop()
        self.ipc = nil
    end
    if self.message_queue then
        UIManager:removeZMQ(self.message_queue)
        self.message_queue = nil
    end
end

--- Whether any Matrix screen is still on show.
function KMatrix:uiVisible()
    return self.room_menu ~= nil or self.timeline ~= nil
end

--- Called when one of our screens closes: if it was the last, drop the
-- connection, which is what tells the daemon to exit.
--
-- The daemon syncs for a screen, so it should not outlive one. Reading a book
-- with Matrix opened an hour ago is not reading Matrix.
--
-- Deferred a tick because a close is not always a departure: leaving a room
-- puts the room list back in front, and the check has to run after whatever
-- comes next has had its chance to open.
function KMatrix:releaseIfHidden()
    UIManager:nextTick(function()
        if self:uiVisible() or not self:isConnected() then return end
        logger.dbg("kmatrix: last screen closed, releasing the daemon")
        self:teardownConnection()
    end)
end

function KMatrix:onDaemonDisconnect(err)
    -- We are called from inside UIManager's ZMQ iteration; mutating the ZMQ
    -- list right now would confuse it, so defer the cleanup by one tick.
    UIManager:nextTick(function()
        self:teardownConnection()
        self.state = "offline"
        self:updateSubtitle()
    end)
    if self.room_menu or self.timeline then
        self:notify(T(_("Lost the connection to the Matrix daemon: %1"), tostring(err)))
    end
end

--[[ Entry point ]]--

function KMatrix:openMatrix()
    self:ensureConnected(function(connected)
        if not connected then return end
        self:refreshStatus(function(ok)
            if not ok then
                self:notify(_("The Matrix daemon did not answer."))
                return
            end
            if self.state == "logged_out" then
                self:showLoginDialog()
            else
                self:showRoomList()
            end
        end)
    end)
end

function KMatrix:refreshStatus(done)
    if not self:isConnected() then
        if done then done(false) end
        return
    end
    self.ipc:request("status", nil, function(resp)
        if resp.ok then
            self.state = resp.state
            self.user_id = resp.user_id
            self.device_id = resp.device_id
            self.homeserver = resp.homeserver
            self.backup = resp.backup
            -- Rendered timestamps follow the device's clock, however wrong.
            clock_skew_ms = tonumber(resp.clock_skew_ms) or 0
        end
        self:updateSubtitle()
        if done then done(resp.ok == true) end
    end)
end

function KMatrix:statusText()
    local label = STATE_LABELS[self.state or "offline"] or self.state
    -- Terse on purpose: this is a title bar on e-ink.
    if self.backup == false and self.state ~= "logged_out" then
        label = label .. "  ·  " .. _("no key backup")
    end
    if self.user_id then
        return self.user_id .. "  ·  " .. label
    end
    return label
end

--[[ Login ]]--

function KMatrix:showLoginDialog()
    local dialog
    dialog = MultiInputDialog:new{
        title = _("Matrix login"),
        fields = {
            {
                description = _("Homeserver"),
                text = self.homeserver or "https://matrix.org",
                hint = "https://matrix.org",
            },
            {
                description = _("User"),
                text = self.user_id or "",
                hint = "@you:matrix.org",
            },
            {
                description = _("Password"),
                text = "",
                hint = _("Password"),
                text_type = "password",
            },
        },
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(dialog)
                    end,
                },
                {
                    text = _("Log in"),
                    is_enter_default = true,
                    callback = function()
                        local fields = dialog:getFields()
                        local homeserver = util.trim(fields[1] or "")
                        local user = util.trim(fields[2] or "")
                        local password = fields[3] or ""
                        if homeserver == "" or user == "" or password == "" then
                            self:notify(_("Homeserver, user and password are all required."))
                            return
                        end
                        UIManager:close(dialog)
                        self:doLogin(homeserver, user, password)
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

function KMatrix:doLogin(homeserver, user, password)
    if not self:daemonReady() then return end
    self:setBusy(_("Logging in…"))
    self.ipc:request("login", {
        homeserver = homeserver,
        user = user,
        password = password,
    }, function(resp)
        self:clearBusy()
        if not resp.ok then
            self:notify(T(_("Login failed: %1"), tostring(resp.error)), 5)
            return
        end
        self.homeserver = homeserver
        self.user_id = resp.user_id
        self.device_id = resp.device_id
        self.state = "connecting"
        self:showRoomList()
    end)
end

function KMatrix:logout()
    if not self:daemonReady() then return end
    self.ipc:request("logout", nil, function(resp)
        if not resp.ok then
            self:notify(T(_("Logout failed: %1"), tostring(resp.error)))
            return
        end
        self.state = "logged_out"
        self.rooms = {}
        self.user_id = nil
        self.backup = nil
        if self.timeline then
            UIManager:close(self.timeline.menu)
            self.timeline = nil
        end
        self:refreshRoomList()
        self:showLoginDialog()
    end)
end

function KMatrix:syncNow()
    if not self:daemonReady() then return end
    self.ipc:request("sync_now", nil, function(resp)
        if not resp.ok then
            self:notify(T(_("Sync failed: %1"), tostring(resp.error)))
        end
    end)
end

--[[ Key backup ]]--

--- Asks for the Security Key that unlocks the server-side room-key backup.
-- The key is base58 and mixed case, so the field stays readable: a masked
-- field would make a single mistyped character impossible to spot.
function KMatrix:showKeyBackupDialog()
    if not self:daemonReady() then return end
    local dialog
    dialog = InputDialog:new{
        title = _("Key backup recovery key"),
        description = _("The Security Key that Element showed you when the key backup was set up. It unlocks messages older than this device."),
        input = "",
        input_type = "text",
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(dialog)
                    end,
                },
                {
                    text = _("Restore"),
                    is_enter_default = true,
                    callback = function()
                        local key = util.trim(dialog:getInputText() or "")
                        if key == "" then
                            self:notify(_("Enter the recovery key first."))
                            return
                        end
                        UIManager:close(dialog)
                        self:restoreKeyBackup(key)
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

function KMatrix:restoreKeyBackup(key)
    if not self:daemonReady() then return end
    self:setBusy(_("Restoring key backup…"))
    self.ipc:request("backup_key", { key = key }, function(resp)
        self:clearBusy()
        if not resp.ok then
            -- The daemon words these precisely (bad checksum, wrong backup,
            -- …), and which one it is decides what the user has to fix.
            self:notify(resp.error and tostring(resp.error)
                or _("Could not restore the key backup."), 5)
            return
        end
        self.backup = true
        self:notify(_("Key backup restored. Older messages will decrypt as you open rooms."), 5)
        self:refreshVisibleView()
    end)
end

--- Re-asks the daemon for whatever is on screen, so bodies that only became
-- readable now replace their locked placeholders. Both paths repaint through
-- Menu:switchItemTable, exactly like the `messages` and `rooms` events do.
function KMatrix:refreshVisibleView()
    self:updateSubtitle()
    if self.timeline then
        self:requestMessages(self.timeline.room)
    end
    if self.room_menu then
        self:requestRooms()
    end
end

--[[ Device verification ]]--

--- Composes the emoji comparison text.
-- The pictographs are not guaranteed to exist in KOReader's fonts, so the
-- English descriptions carry the comparison and the glyph is decoration only:
-- a column of missing-glyph boxes still leaves a readable, ordered word list,
-- which is all the user needs to match against the other client.
local function verificationText(device, emoji)
    local lines = {
        T(_("Other device: %1"), device),
        "",
        _("Both devices must show the same words, in the same order:"),
        "",
    }
    for i = 1, #emoji do
        local pair = emoji[i]
        local glyph, name
        if type(pair) == "table" then
            glyph, name = pair[1], pair[2]
        end
        lines[#lines + 1] = T(_("%1. %2  %3"), i, tostring(name or "?"), tostring(glyph or ""))
    end
    return table.concat(lines, "\n")
end

function KMatrix:closeVerification()
    if self.verify_dialog then
        UIManager:close(self.verify_dialog)
        self.verify_dialog = nil
    end
end

--- Shows the emoji the daemon computed. Any prompt still on screen is replaced:
-- only the newest transaction can still be answered.
function KMatrix:showVerificationEmoji(event)
    local emoji = event.emoji or {}
    if not event.transaction or #emoji == 0 then
        logger.warn("kmatrix: verification prompt without emoji, ignoring")
        return
    end
    self:closeVerification()
    self:clearBusy()
    local transaction = event.transaction
    self.verify_dialog = ButtonDialog:new{
        title = verificationText(tostring(event.device or "?"), emoji),
        title_align = "left",
        -- Bold and a size up: this is the one screen the user has to read
        -- carefully, and it is read on a grey panel with no backlight to spare.
        use_info_style = false,
        title_face = Font:getFace("smalltfont", 26),
        -- A stray tap must not silently abandon a half-finished verification.
        dismissable = false,
        buttons = {
            {
                {
                    text = _("They don't match"),
                    callback = function()
                        self:closeVerification()
                        self:confirmVerification(transaction, false)
                    end,
                },
                {
                    text = _("They match"),
                    callback = function()
                        self:closeVerification()
                        self:confirmVerification(transaction, true)
                    end,
                },
            },
        },
    }
    UIManager:show(self.verify_dialog)
end

--- A confirmed match is only really finished once the daemon has exchanged the
-- MACs, so success is announced by the `done` event, not from here.
function KMatrix:confirmVerification(transaction, confirm)
    if not self:daemonReady() then return end
    self.ipc:request("verify_confirm", { transaction = transaction, confirm = confirm },
        function(resp)
            if not resp.ok then
                self:notify(resp.error and tostring(resp.error)
                    or _("Could not answer the verification request."), 5)
            elseif not confirm then
                self:notify(_("Verification refused."))
            end
        end)
end

--- We only ever answer a verification, we never open one.
function KMatrix:showVerificationHelp()
    UIManager:show(InfoMessage:new{
        text = _("Start the verification on your other client: Settings > Devices > this device > Verify. The emoji to compare then appear here."),
    })
end

function KMatrix:onVerificationEvent(event)
    local phase = event.phase
    if phase == "emoji" then
        self:showVerificationEmoji(event)
    elseif phase == "done" then
        self:closeVerification()
        self:notify(T(_("Device %1 is verified. The key backup can now be fetched without typing the recovery key."),
            tostring(event.device or "?")), 5)
    elseif phase == "cancelled" then
        self:closeVerification()
        self:notify(T(_("Verification stopped: %1"),
            tostring(event.reason or _("no reason given"))), 5)
    elseif phase == "secret" then
        if event.name == "m.megolm_backup.v1" then
            self.backup = true
            self:notify(_("Key backup key received from your other device. Older messages will decrypt as you open rooms."), 5)
        else
            self:notify(T(_("Received the secret %1 from your other device."),
                tostring(event.name or "?")))
        end
        self:refreshVisibleView()
    else
        logger.dbg("kmatrix: ignoring unknown verification phase", tostring(phase))
    end
end

function KMatrix:shutdownDaemon()
    if not self:daemonReady() then return end
    -- The daemon closes the socket as it exits, and that close drives our own
    -- teardown through on_disconnect: no need to race the outgoing write here.
    self.ipc:request("shutdown", nil, function(resp)
        if not resp.ok then
            self:notify(T(_("Could not stop the daemon: %1"), tostring(resp.error)))
        end
    end)
    if self.timeline then
        UIManager:close(self.timeline.menu)
        self.timeline = nil
    end
    if self.room_menu then
        UIManager:close(self.room_menu)
        self.room_menu = nil
    end
    self:notify(_("Stopping the Matrix daemon…"))
end

--[[ Room list ]]--

function KMatrix:roomItems()
    local items = {}
    for i = 1, #self.rooms do
        local room = self.rooms[i]
        local unread = room.unread or 0
        local text = room.name or room.id
        local suffix = {}
        if unread > 0 then
            table.insert(suffix, T(_("%1 unread"), unread))
        end
        if room.last_preview and room.last_preview ~= "" then
            table.insert(suffix, room.last_preview)
        end
        if #suffix > 0 then
            text = text .. "  —  " .. table.concat(suffix, "  ·  ")
        end
        items[i] = {
            text = text,
            mandatory = clockOf(room.last_ts),
            bold = unread > 0 or nil,
            room_id = room.id,
            room_name = room.name or room.id,
        }
    end
    return items
end

function KMatrix:showRoomList()
    if self.room_menu then
        self:requestRooms()
        return
    end
    self.room_menu = Menu:new{
        title = _("Matrix"),
        subtitle = self:statusText(),
        item_table = self:roomItems(),
        covers_fullscreen = true,
        is_borderless = true,
        is_popout = false,
        title_bar_fm_style = true,
        title_bar_left_icon = "appbar.menu",
        items_max_lines = 2, -- variable item height: name plus preview
        onLeftButtonTap = function()
            self:showAccountDialog()
        end,
        onMenuSelect = function(menu_self, item) -- luacheck: ignore menu_self
            if item.room_id then
                self:openTimeline(item.room_id, item.room_name)
            end
            return true
        end,
        close_callback = function()
            self.room_menu = nil
            self:releaseIfHidden()
        end,
    }
    -- Whole screen changes: this is the one place a partial refresh is right.
    UIManager:show(self.room_menu, "partial")
    self:requestRooms()
end

function KMatrix:requestRooms()
    if not self:isConnected() then return end
    self.ipc:request("rooms", nil, function(resp)
        if resp.ok then
            self.rooms = resp.rooms or {}
            self:refreshRoomList()
        end
    end)
end

--- Repaints the room list in place (Menu:switchItemTable refreshes as "ui").
function KMatrix:refreshRoomList()
    if not self.room_menu then return end
    self.room_menu:switchItemTable(nil, self:roomItems(), -1, nil, self:statusText())
end

function KMatrix:updateSubtitle()
    if not self.room_menu then return end
    self.room_menu:switchItemTable(nil, nil, -1, nil, self:statusText())
end

function KMatrix:showAccountDialog()
    local dialog
    local buttons = {
        {{
            text = "\u{f021} " .. _("Sync now"), -- 'refresh' sign
            align = "left",
            callback = function()
                UIManager:close(dialog)
                self:syncNow()
            end,
        }},
        {{
            text = "\u{f084} " .. _("Restore key backup"), -- 'key' sign
            align = "left",
            callback = function()
                UIManager:close(dialog)
                self:showKeyBackupDialog()
            end,
        }},
        {{
            text = "\u{f00c} " .. _("Verify this device"), -- 'check' sign
            align = "left",
            callback = function()
                UIManager:close(dialog)
                self:showVerificationHelp()
            end,
        }},
        {{
            text = "\u{f2f5} " .. _("Log out"), -- 'sign out' sign
            align = "left",
            callback = function()
                UIManager:close(dialog)
                self:logout()
            end,
        }},
        {}, -- separator
        {{
            text = "\u{f011} " .. _("Stop the daemon"), -- 'power' sign
            align = "left",
            callback = function()
                UIManager:close(dialog)
                self:shutdownDaemon()
            end,
        }},
    }
    dialog = ButtonDialog:new{
        buttons = buttons,
        shrink_unneeded_width = true,
        anchor = function()
            return self.room_menu.title_bar.left_button.image.dimen
        end,
    }
    UIManager:show(dialog)
end

--[[ Timeline ]]--

function KMatrix:messageItems()
    local items = {}
    local timeline = self.timeline
    if not timeline then return items end
    if not timeline.exhausted then
        -- Synthetic first row: history older than the sync window is fetched
        -- on demand, so the top of the list is a button, not a message.
        items[1] = {
            text = "\u{2191} " .. _("Load older messages"), -- 'upwards arrow'
            is_load_older = true,
        }
    end
    for i = 1, #timeline.messages do
        local message = timeline.messages[i]
        -- The display name where the room knows one: a bridged contact's
        -- localpart is a Signal uuid or a bare phone number.
        local sender = message.mine and _("Me")
            or str(message.sender_name)
            or shortSender(message.sender)
        local body = message.body or ""
        if message.encrypted and not message.decrypted then
            body = "\u{f023} " .. body -- 'lock' sign: could not be decrypted
        end
        items[#items + 1] = {
            text = sender .. ": " .. body,
            mandatory = clockOf(message.ts),
            bold = message.mine or nil,
            body = body,
            header = sender .. "  ·  " .. dateTimeOf(message.ts),
            event_id = message.event_id, -- anchor for a position-keeping refresh
        }
    end
    return items
end

function KMatrix:openTimeline(room_id, room_name)
    self.timeline = {
        room = room_id,
        name = room_name,
        messages = {},
        seen = {},
        window = MESSAGE_LIMIT, -- messages asked of the daemon; backfill grows it
        exhausted = false,      -- true once the start of the room is reached
        loading_older = false,
    }
    local menu = Menu:new{
        title = room_name,
        subtitle = "",
        item_table = {},
        covers_fullscreen = true,
        is_borderless = true,
        is_popout = false,
        title_bar_fm_style = true,
        title_bar_left_icon = "edit",
        items_max_lines = 4, -- long messages get up to four lines, then ellipsis
        onLeftButtonTap = function()
            self:showComposer()
        end,
        onMenuSelect = function(menu_self, item) -- luacheck: ignore menu_self
            if item.is_load_older then
                self:loadOlderMessages()
            else
                self:showFullMessage(item)
            end
            return true
        end,
        close_callback = function()
            self.timeline = nil
            self:releaseIfHidden()
        end,
    }
    self.timeline.menu = menu
    UIManager:show(menu, "partial")
    self:requestMessages(room_id)
end

--- Asks for the newest messages of a room. `limit` defaults to the timeline's
-- current window, so an incidental refresh never shrinks history that backfill
-- already widened. With `keep_page` the reading position survives the repaint.
function KMatrix:requestMessages(room_id, limit, keep_page)
    if not self:isConnected() then return end
    local window = limit
        or (self.timeline and self.timeline.room == room_id and self.timeline.window)
        or MESSAGE_LIMIT
    self.ipc:request("messages", { room = room_id, limit = window }, function(resp)
        if not resp.ok then
            self:notify(T(_("Could not load messages: %1"), tostring(resp.error)))
            return
        end
        if not self.timeline or self.timeline.room ~= resp.room then return end
        self.timeline.messages = {}
        self.timeline.seen = {}
        self:appendMessages(resp.messages or {}, keep_page)
    end)
end

--- Walks the room's history one /messages page further back. The daemon stores
-- what it fetches -- upgrading rows it already had, ciphertext included -- so
-- nothing is merged here: the window is simply re-read afterwards, which is
-- also what makes placeholders the backfill decrypted appear.
function KMatrix:loadOlderMessages()
    local timeline = self.timeline
    if not timeline or timeline.loading_older then return end
    if not self:daemonReady() then return end
    if timeline.window >= MESSAGE_WINDOW_MAX then
        -- Fetching pages the timeline cannot show would only cost memory.
        self:notify(T(_("The timeline shows the most recent %1 messages; that is as far back as it goes."),
            MESSAGE_WINDOW_MAX), 5)
        return
    end
    local room = timeline.room
    timeline.loading_older = true
    self:setBusy(_("Loading older messages…"))
    self.ipc:request("load_older", { room = room, limit = BACKFILL_LIMIT }, function(resp)
        self:clearBusy()
        timeline.loading_older = false
        if not resp.ok then
            -- The daemon words the failure (no history token yet, HTTP status,
            -- …), and which one it is decides what the user can do about it.
            self:notify(resp.error and tostring(resp.error)
                or _("Could not load older messages."), 5)
            return
        end
        if self.timeline ~= timeline then return end -- the room closed meanwhile
        local added = tonumber(resp.added) or 0
        timeline.exhausted = resp.exhausted == true
        if added == 0 then
            if timeline.exhausted then
                self:notify(_("No older messages."))
                self:refreshTimeline(true) -- the row has nothing left to load
                return
            end
            -- The page held only events we had already stored, but backfill may
            -- have upgraded them, so re-read rather than merely repaint.
            self:requestMessages(room, timeline.window, true)
            return
        end
        timeline.window = math.min(timeline.window + added, MESSAGE_WINDOW_MAX)
        self:requestMessages(room, timeline.window, true)
    end)
end

--- Adds messages we have not seen yet, and rewrites the ones we have whose
-- text moved on: the daemon resends an event under its own id after another
-- client edited it, and after a backfill decrypts what was a locked
-- placeholder. Both must change the row where it stands.
function KMatrix:appendMessages(messages, keep_page)
    local timeline = self.timeline
    if not timeline then return end
    local added, updated = false, false
    for i = 1, #messages do
        local message = messages[i]
        local key = message.event_id
        if key then
            local stored = timeline.seen[key]
            if not stored then
                timeline.seen[key] = message
                table.insert(timeline.messages, message)
                added = true
            elseif stored.body ~= message.body
                or stored.decrypted ~= message.decrypted
                or str(stored.sender_name) ~= str(message.sender_name) then
                -- Text and attribution only: an edit keeps the original
                -- event's place in the room's history, so the timestamp the
                -- row sorts and displays by stays the one it was first sent
                -- at. A sender can gain a name after we look their profile up.
                stored.body = message.body
                stored.decrypted = message.decrypted
                stored.sender_name = str(message.sender_name)
                updated = true
            end
        end
    end
    -- Every sync arrives here, almost always with nothing new; a repaint costs
    -- an e-ink refresh, so an unchanged resend must fall out silently.
    if not (added or updated) then return end
    -- Only a new message may pull the view down to the newest page. A rewrite
    -- happens under the reader, who did not ask to be moved.
    self:refreshTimeline(keep_page or not added)
    self:markRead()
end

--- Event id of the topmost message row on the menu's current page: the anchor a
-- prepending refresh scrolls back to. nil when the page carries no message row
-- (only the synthetic "load older" one).
local function topEventId(menu)
    local page_items = menu.page_items and menu.page_items[menu.page or 1]
    if not page_items then return nil end
    local item_table = menu.item_table or {}
    for i = 1, #page_items do
        local item = item_table[page_items[i]]
        if item and item.event_id then return item.event_id end
    end
    return nil
end

local function indexOfEvent(items, event_id)
    for i = 1, #items do
        if items[i].event_id == event_id then return i end
    end
    return nil
end

--- Repaints the timeline. Normally the newest message is brought on screen;
-- with `keep_page` the row that was at the top of the visible page stays there,
-- which is what backfill needs: it prepends rows above the reader's position,
-- so the page number on its own no longer points at the same place.
function KMatrix:refreshTimeline(keep_page)
    local timeline = self.timeline
    if not timeline then return end
    local menu = timeline.menu
    local anchor
    if keep_page then
        anchor = topEventId(menu)
    end
    local items = self:messageItems()
    -- Do NOT pass an itemnumber here. With items_max_lines set,
    -- switchItemTable resolves the page via Menu:getPageNumber(), which walks
    -- self.page_items -- but page_items is only rebuilt later, by
    -- setupItemHeights() inside updateItems(). On the first population the
    -- previous table was empty, so getPageNumber() falls out of its loop and
    -- returns #page_items == 0. updateItems() then clamps only page > page_num,
    -- never page < 1, so the menu renders page 0: blank, i.e. "No items".
    -- The room list dodged this by passing -1 (keep current page).
    menu:switchItemTable(nil, items)
    if #items == 0 then return end
    if keep_page then
        -- That switchItemTable rebuilt page_items for the new table, so
        -- getPageNumber() now resolves against the prepended rows.
        local index = anchor and indexOfEvent(items, anchor)
        if index then
            menu:onGotoPage(menu:getPageNumber(index))
        end
        -- Without an anchor the page held no message anyway, and page 1 -- where
        -- switchItemTable just left us -- is the older end of the timeline.
        return
    end
    if (menu.page_num or 1) > 1 then
        menu:onLastPage() -- newest message sits at the bottom
    end
end

function KMatrix:markRead()
    local timeline = self.timeline
    if not timeline or not self:isConnected() then return end
    local last = timeline.messages[#timeline.messages]
    if not last or not last.event_id or last.event_id == timeline.read_up_to then return end
    timeline.read_up_to = last.event_id
    self.ipc:request("mark_read", { room = timeline.room, event_id = last.event_id },
        function(resp)
            if not resp.ok then
                logger.dbg("kmatrix: mark_read failed:", tostring(resp.error))
            end
        end)
end

function KMatrix:showFullMessage(item)
    if not item or not item.body then return end
    UIManager:show(TextViewer:new{
        title = item.header,
        text = item.body,
        text_type = "lookup", -- unjustified, proportional: reads like a message
    })
end

function KMatrix:showComposer()
    if not self.timeline then return end
    if not self:daemonReady() then return end
    local room = self.timeline.room
    local dialog
    dialog = InputDialog:new{
        title = T(_("Message to %1"), self.timeline.name),
        input = "",
        input_type = "text",
        allow_newline = true,
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(dialog)
                    end,
                },
                {
                    text = _("Send"),
                    is_enter_default = true,
                    callback = function()
                        local body = util.trim(dialog:getInputText() or "")
                        UIManager:close(dialog)
                        if body ~= "" then
                            self:sendMessage(room, body)
                        end
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

--- Fire and forget: our own message comes back through the `messages` event.
function KMatrix:sendMessage(room, body)
    if not self:daemonReady() then return end
    self.ipc:request("send", { room = room, body = body }, function(resp)
        if not resp.ok then
            self:notify(T(_("Could not send the message: %1"), tostring(resp.error)), 5)
        end
    end)
end

--[[ Unsolicited daemon events ]]--

function KMatrix:onDaemonEvent(event)
    if event.event == "state" then
        self.state = event.state
        self:updateSubtitle()
        if event.error then
            logger.warn("kmatrix: daemon reported", event.state, event.error)
        end
    elseif event.event == "rooms" then
        self.rooms = event.rooms or {}
        self:refreshRoomList()
    elseif event.event == "messages" then
        if self.timeline and event.room == self.timeline.room then
            self:appendMessages(event.messages or {})
        end
    elseif event.event == "verification" then
        self:onVerificationEvent(event)
    else
        logger.dbg("kmatrix: ignoring unknown daemon event", tostring(event.event))
    end
end

--[[ KOReader lifecycle ]]--

function KMatrix:onSuspend()
    logger.dbg("kmatrix: onSuspend")
    self.reconnect_on_resume = self:isConnected()
    self:teardownConnection()
end

function KMatrix:onResume()
    logger.dbg("kmatrix: onResume")
    if not self.reconnect_on_resume then return end
    self.reconnect_on_resume = false
    self:ensureConnected(function(connected)
        if not connected then return end
        self:refreshStatus(function()
            self:requestRooms()
            if self.timeline then
                self:requestMessages(self.timeline.room)
            end
        end)
    end)
end

function KMatrix:onCloseWidget()
    logger.dbg("kmatrix: onCloseWidget")
    self:clearBusy()
    self:teardownConnection()
end

function KMatrix:onExit()
    logger.dbg("kmatrix: onExit")
    self:teardownConnection()
end

return KMatrix
