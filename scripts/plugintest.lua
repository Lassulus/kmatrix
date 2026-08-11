-- Headless regression test for the KOReader plugin.
--
--   usage: luajit scripts/plugintest.lua [path/to/kmatrix.koplugin]
--
-- This loads the *real* plugin/kmatrix.koplugin/main.lua and drives its
-- timeline handlers directly. Everything KOReader would supply -- widgets,
-- UIManager, fonts, gettext, logger, the settings singleton -- is stubbed by a
-- package loader installed ahead of the real one, so the test needs no
-- KOReader, no daemon, no network and no device. Only main.lua is under test;
-- the stubs are deliberately dumb.
--
-- The one stub that is not dumb is Menu. The bugs this file exists to catch
-- were all *pagination* bugs: a repaint that silently threw the reader back to
-- the newest page, an edit appended as a duplicate row instead of rewritten in
-- place, a re-read that lost the reading position. A stub that recorded calls
-- and answered "sure, page 6" would have passed every one of them. So FakeMenu
-- reimplements the arithmetic from KOReader's frontend/ui/widget/menu.lua --
-- greedy variable-height fill into pages, getPageNumber, the page clamp in
-- _recalculateDimen -- against one-line-tall rows. Page numbers are then
-- computed the way the device computes them rather than asserted into
-- existence, and `view()` can state exactly what the reader is looking at.
--
-- Every case below is a bug that reached a physical Kindle. Do not delete one
-- because it looks redundant.

--[[ Locate the plugin: next to this script, or wherever arg[1] says ]]--

local script_dir = (arg[0] or ""):match("^(.*)[/\\][^/\\]*$") or "."
local PLUGIN = arg[1] or (script_dir .. "/../plugin/kmatrix.koplugin")

local shown = {}   -- InfoMessage texts, newest last
local sent = {}    -- {cmd, args} the plugin handed to the IPC layer
local replies = {} -- cmd -> function(args) -> response
local repaints = 0 -- switchItemTable calls: one e-ink refresh each

--[[ Menu fake: mirrors frontend/ui/widget/menu.lua ]]--

local PAGE_HEIGHT = 8 -- eight one-line rows per page
local FakeMenu = {}
FakeMenu.__index = FakeMenu

function FakeMenu.new()
    return setmetatable({ item_table = {}, page = 1, page_num = 1, page_items = { {} } }, FakeMenu)
end

-- Menu:setupItemHeights(), greedy fill, every row one "line" tall.
function FakeMenu:setupItemHeights()
    if #self.item_table == 0 then
        self.page_items = { {} }
        return
    end
    self.page_items = {}
    local items, height = {}, 0
    for i = 1, #self.item_table do
        height = height + 1
        if height <= PAGE_HEIGHT then
            table.insert(items, i)
        else
            table.insert(self.page_items, items)
            items, height = { i }, 1
        end
        if i == #self.item_table then
            table.insert(self.page_items, items)
        end
    end
end

function FakeMenu:getPageNumber(item_number)
    if #self.item_table == 0 or item_number == 0 then return 1 end
    for page, items in ipairs(self.page_items) do
        if item_number <= items[#items] then return page end
    end
    return #self.page_items
end

function FakeMenu:_recalculateDimen()
    self:setupItemHeights()
    self.page_num = self:getPageNumber(#self.item_table)
    if self.page > self.page_num then self.page = self.page_num end
end

function FakeMenu:switchItemTable(_title, new_item_table, itemnumber)
    repaints = repaints + 1
    self.item_table = new_item_table
    self:setupItemHeights()
    if itemnumber then self.page = self:getPageNumber(itemnumber) end
    self:_recalculateDimen()
end

function FakeMenu:onGotoPage(page)
    self.page = page
    return true
end

function FakeMenu:onLastPage()
    return self:onGotoPage(self.page_num)
end

--- Indices currently on screen.
function FakeMenu:visible()
    return self.page_items[self.page] or {}
end

function FakeMenu:showsEvent(event_id)
    for _i, index in ipairs(self:visible()) do
        local item = self.item_table[index]
        if item and item.event_id == event_id then return true end
    end
    return false
end

--[[ Module stubs ]]--

local function widget()
    local W = {}
    W.__index = W
    function W:extend(t)
        t = t or {}
        return setmetatable(t, { __index = self })
    end
    function W:new(t)
        t = t or {}
        return setmetatable(t, { __index = self })
    end
    return W
end

local InfoMessage = widget()
function InfoMessage:new(t)
    table.insert(shown, t.text)
    return setmetatable(t, { __index = self })
end

-- Whether the stubbed filesystem can see the data directory at all.
local data_dir_visible = true

local stubs = {
    ["ui/widget/buttondialog"] = widget(),
    ["ui/font"] = { getFace = function() return {} end },
    ["ui/widget/infomessage"] = InfoMessage,
    ["ui/widget/inputdialog"] = widget(),
    -- Menu:new returns the pagination fake carrying what the plugin passed.
    -- The real Menu keeps its config on the widget, and `close_callback` in
    -- particular is how KOReader tells the plugin a screen went away: a stub
    -- that dropped it would leave the wiring untested.
    ["ui/widget/menu"] = {
        new = function(_self, config)
            local m = FakeMenu.new()
            for k, v in pairs(config or {}) do
                if m[k] == nil then m[k] = v end
            end
            return m
        end,
    },
    ["ui/widget/multiinputdialog"] = widget(),
    ["ui/widget/textviewer"] = widget(),
    ["ui/uimanager"] = {
        show = function() end,
        close = function() end,
        -- Runs the callback rather than dropping it. Deferred work is still
        -- work: the plugin decides whether to release the daemon on a
        -- nextTick, and a stub that swallowed it would report that decision
        -- as never taken.
        nextTick = function(_self, fn) fn() end,
        scheduleIn = function() end,
        unschedule = function() end,
        removeZMQ = function() end,
        insertZMQ = function() return {} end,
    },
    ["ui/widget/container/widgetcontainer"] = widget(),
    datetime = {
        secondsToHour = function() return "12:00" end,
        secondsToDateTime = function() return "2026-08-08 12:00" end,
    },
    -- The data directory is there and nothing in it is: what a device looks
    -- like before the daemon is installed. `data_dir_visible` flips it to the
    -- other case, where /mnt/us itself has gone -- the two the plugin has to
    -- tell apart.
    ["libs/libkoreader-lfs"] = {
        attributes = function(path, what)
            if what == "mode" and data_dir_visible and path == "/tmp/kmatrix" then
                return "directory"
            end
            return nil
        end,
    },
    logger = { dbg = function() end, warn = function() end, info = function() end },
    util = { trim = function(s) return s end, makePath = function() end },
    gettext = setmetatable({}, { __call = function(_self, s) return s end }),
    ["ffi/util"] = {
        template = function(fmt, ...)
            local args = { ... }
            return (fmt:gsub("%%(%d)", function(n) return tostring(args[tonumber(n)]) end))
        end,
    },
    kmatrix_ipc = { dataDir = function() return "/tmp/kmatrix" end },
    -- A decoy under the name this plugin used to use. Another plugin on the
    -- device ships its own IPC helper, and Lua's module cache is global: two
    -- plugins that both `require("ipc")` get whichever loaded first. That is
    -- not hypothetical -- installing covibe alongside made the Matrix plugin
    -- read covibe's data directory and report its own daemon missing at
    -- `.../covibe/kmatrixd`. Requiring a name nobody else uses is the fix,
    -- and this entry fails the test if anything reaches for the old one.
    ipc = { dataDir = function() return "/tmp/SOMEONE-ELSES-PLUGIN" end },
}

-- Ahead of the real searchers, so `require` never reaches KOReader's tree.
table.insert(package.loaders, 1, function(name)
    local stub = stubs[name]
    if stub then return function() return stub end end
    return nil
end)

G_reader_settings = { isTrue = function() return false end, readSetting = function() return nil end }

local main = PLUGIN .. "/main.lua"
local chunk, load_err = loadfile(main)
if not chunk then
    io.stderr:write("cannot load the plugin at " .. main .. "\n  " .. tostring(load_err) .. "\n")
    os.exit(1)
end
local KMatrix = chunk()

--[[ Instance wired to the fakes ]]--

local km = setmetatable({}, { __index = KMatrix })
local ipc_stopped -- set when the plugin stops the IPC layer
km.ipc = {
    stop = function() ipc_stopped = true end,
    isConnected = function() return true end,
    request = function(_self, cmd, args, cb)
        table.insert(sent, { cmd = cmd, args = args })
        local reply = replies[cmd]
        if reply then cb(reply(args)) end
    end,
}

local menu = FakeMenu.new()

local function message(n)
    return { event_id = "$e" .. n, sender = "@bob:example.org", body = "body " .. n, ts = 1000 * n }
end

--- The daemon's store: `count` messages, newest last, ids $e1..$eN offset by `oldest`.
local store = { oldest = 1, newest = 100 }
replies.messages = function(args)
    local msgs = {}
    local first = math.max(store.oldest, store.newest - args.limit + 1)
    for n = first, store.newest do
        table.insert(msgs, message(n))
    end
    return { ok = true, room = args.room, messages = msgs }
end
replies.mark_read = function() return { ok = true } end

local checked, fails = 0, 0
local function check(what, cond, detail)
    checked = checked + 1
    if cond then
        print("ok   " .. what)
    else
        fails = fails + 1
        print("FAIL " .. what)
        if detail ~= nil then print("       " .. tostring(detail)) end
    end
end

local function openRoom()
    km.timeline = {
        room = "!room:example.org",
        name = "Room",
        messages = {},
        seen = {},
        window = 100,
        exhausted = false,
        loading_older = false,
        menu = menu,
    }
    km:requestMessages(km.timeline.room)
end

--- The item row the timeline currently renders for `event_id`.
local function rowOf(event_id)
    for _i, item in ipairs(menu.item_table) do
        if item.event_id == event_id then return item end
    end
    return nil
end

--- Everything the reader can see: which page, and the rows on it.
local function view()
    local ids = {}
    for _i, index in ipairs(menu:visible()) do
        table.insert(ids, menu.item_table[index].event_id or "<load-older>")
    end
    return ("page %d/%d [%s]"):format(menu.page, menu.page_num, table.concat(ids, " "))
end

--[[ 1. Open the room and park the reader in the middle of the history ]]--

openRoom()
check("populated", #km.timeline.messages == 100, #km.timeline.messages .. " messages")
menu:onGotoPage(6)
local parked_page, parked_view = menu.page, view()
local parked_top = menu.item_table[menu:visible()[1]].event_id
print("   parked at " .. parked_view)
check("the parked page is not the newest one", menu.page < menu.page_num, parked_view)

--[[ 2. A sync that brings nothing new must not touch the screen ]]--

repaints = 0
km:appendMessages(replies.messages({ room = km.timeline.room, limit = 100 }).messages)
check("unchanged resend repaints nothing", repaints == 0, repaints .. " repaints")
check("unchanged resend leaves the view alone", view() == parked_view, view())

--[[ 3. An edit rewrites the row in place, where the reader is ]]--

local edited = message(50)
edited.body = "the corrected text"
km:appendMessages({ edited })
check("edit repainted once", repaints == 1, repaints .. " repaints")
check("the row shows the new text", rowOf("$e50").text == "bob: the corrected text", rowOf("$e50").text)
check("the row's own body was updated too", rowOf("$e50").body == "the corrected text", rowOf("$e50").body)
check("no duplicate row was added", #km.timeline.messages == 100, #km.timeline.messages .. " messages")
check("the stored message carries the new text", km.timeline.messages[50].body == "the corrected text",
    km.timeline.messages[50].body)
check("the message kept its original timestamp", km.timeline.messages[50].ts == 50 * 1000,
    km.timeline.messages[50].ts)
check("the same rows are still on screen", view() == parked_view, view() .. " wanted " .. parked_view)
check("still anchored on the same top row", menu.item_table[menu:visible()[1]].event_id == parked_top,
    menu.item_table[menu:visible()[1]].event_id)
print("   after the edit " .. view())

--[[ 4. Re-editing to the same text is once again a no-op ]]--

repaints = 0
km:appendMessages({ edited })
check("resending the edit repaints nothing", repaints == 0, repaints .. " repaints")

--[[ 5. A locked placeholder that backfill decrypted updates in place ]]--

local locked = message(101)
locked.encrypted, locked.decrypted, locked.body = true, false, "Encrypted message"
km:appendMessages({ locked })
check("the placeholder arrived as a new message", #km.timeline.messages == 101,
    #km.timeline.messages .. " messages")
check("it is drawn with the lock sign", rowOf("$e101").text == "bob: \u{f023} Encrypted message",
    rowOf("$e101").text)

menu:onGotoPage(parked_page)
repaints = 0
local opened = message(101)
opened.encrypted, opened.decrypted, opened.body = true, true, "hello from the past"
km:appendMessages({ opened })
check("decryption repainted once", repaints == 1, repaints .. " repaints")
check("the lock is gone and the text is real", rowOf("$e101").text == "bob: hello from the past",
    rowOf("$e101").text)
check("decrypted was recorded", km.timeline.messages[101].decrypted == true,
    tostring(km.timeline.messages[101].decrypted))
check("decryption did not move the reader", menu.page == parked_page, view())
print("   after the decryption " .. view())

--[[ 6. A genuinely new message still pulls the view to the newest page ]]--

repaints = 0
km:appendMessages({ message(102) })
check("new message repainted", repaints == 1, repaints .. " repaints")
check("new message jumps to the last page", menu.page == menu.page_num, view())
check("the new message is on screen", menu:showsEvent("$e102"), view())

--[[ 7. An edit arriving alongside a new message: the new message wins ]]--

menu:onGotoPage(parked_page)
local edit_again = message(50)
edit_again.body = "edited once more"
km:appendMessages({ edit_again, message(103) })
check("both were applied", rowOf("$e50").text == "bob: edited once more" and menu:showsEvent("$e103"),
    rowOf("$e50").text .. " / " .. view())
check("a new message still wins the scroll", menu.page == menu.page_num, view())

--[[ 8. A refresh that re-reads the window keeps the edit and the position ]]--

menu:onGotoPage(parked_page)
local before = view()
km:requestMessages(km.timeline.room, 100, true)
check("re-read kept the position", view() == before, view() .. " wanted " .. before)

--[[ 9. KOReader's JSON decoder renders a JSON null as a truthy *function*
     sentinel, so `msg.sender_name or fallback` keeps the sentinel and the
     whole handler blows up, blanking the room. A message with no display
     name must still render, as the localpart. ]]--

local NULL = function() end -- exactly what require("json") yields for null

local nulled = message(104)
nulled.sender_name = NULL
local ok, err = pcall(function() km:appendMessages({ nulled }) end)
check("a null sender_name does not throw", ok, err)
check("it falls back to the localpart", rowOf("$e104") and rowOf("$e104").text:match("^bob: "),
    rowOf("$e104") and rowOf("$e104").text or "no row at all")

local named = message(105)
named.sender_name = "Oliver Habryka (S)"
km:appendMessages({ named })
check("a real name is used", rowOf("$e105").text:match("^Oliver Habryka %(S%): "), rowOf("$e105").text)

--[[ The daemon lives exactly as long as a screen does ]]--

-- kmatrixd exits when its last client disconnects, so what the plugin holds
-- the connection for is what the daemon costs. Held for the whole KOReader
-- session it syncs while the reader is in a book; held only while a screen is
-- up it is there to be read and gone otherwise.
--
-- The trap is that closing a screen is not always leaving: stepping out of a
-- room lands back on the room list, which still needs the daemon. So this
-- drives the close callbacks the plugin really installs, not the handler
-- directly -- the wiring is the part that can be forgotten.

km.rooms = { { id = "!r:example.org", name = "room" } }
ipc_stopped = nil
km:showRoomList()
check("the room list installed a close callback",
    type(km.room_menu.close_callback) == "function", type(km.room_menu.close_callback))

km:openTimeline("!r:example.org", "room")
local timeline_menu = km.timeline.menu
check("the room view installed a close callback",
    type(timeline_menu.close_callback) == "function", type(timeline_menu.close_callback))

timeline_menu.close_callback()
check("leaving a room for the room list keeps the daemon",
    km.ipc ~= nil and not ipc_stopped, tostring(km.ipc) .. " stopped=" .. tostring(ipc_stopped))

km.room_menu.close_callback()
check("closing the last screen releases the daemon",
    km.ipc == nil and ipc_stopped == true, tostring(km.ipc) .. " stopped=" .. tostring(ipc_stopped))

check("releasing twice is harmless", pcall(function() km:releaseIfHidden() end))

--[[ The daemon is looked for in our own directory ]]--

-- Two plugins that both `require("ipc")` share one module: Lua caches modules
-- by name across the whole interpreter, so whichever plugin loads first wins
-- for both. Installing covibe beside this one did exactly that, and the Matrix
-- plugin went looking for its daemon in covibe's data directory and reported
-- it missing at `.../covibe/kmatrixd`. The stubs register a decoy under the
-- old shared name; anything that reaches for it shows up in the path below.

km.room_menu = nil
km.timeline = nil
local said = #shown
check("a missing daemon is reported", km:spawnDaemon() == false)
local complaint = shown[#shown] or ""
check("the complaint was shown", #shown > said, tostring(#shown))
check("and it names our own directory, not another plugin's",
    complaint:find("/tmp/kmatrix/kmatrixd", 1, true) ~= nil, complaint)
check("nothing reached for the shared `ipc` name",
    complaint:find("SOMEONE%-ELSES%-PLUGIN") == nil, complaint)

-- And the other half of that message: a volume that is not mounted is not a
-- daemon that was never installed. On a Kindle everything lives on /mnt/us,
-- which disappears while the device is plugged into a computer.
data_dir_visible = false
check("a vanished data directory is reported too", km:spawnDaemon() == false)
local gone = shown[#shown] or ""
check("and it says the directory cannot be seen, not that nothing is installed",
    gone:find("Cannot see /tmp/kmatrix", 1, true) ~= nil, gone)
data_dir_visible = true

--[[ Verdict ]]--

print(("%d/%d checks passed"):format(checked - fails, checked))
if fails > 0 then
    print(("%d CHECK%s FAILED"):format(fails, fails == 1 and "" or "S"))
    os.exit(1)
end
print("ALL OK")
