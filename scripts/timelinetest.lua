-- Replays what the plugin does when you open a room, using the real ipc.lua
-- and the real daemon, with the KOReader widget layer stubbed out. This
-- isolates "is the daemon wrong" from "is the plugin wrong".
--
--   usage: luajit scripts/timelinetest.lua <data-dir>

local data_dir = assert(arg[1], "usage: timelinetest.lua <data-dir>")

package.preload["datastorage"] = function()
    return { getDataDir = function() return data_dir end }
end
package.preload["ui/event"] = function()
    return { new = function(_, name) return { handler = name } end }
end
package.preload["logger"] = function()
    local function noop() end
    return { dbg = noop, info = noop, warn = noop, err = noop }
end
package.preload["json"] = function() return require("dkjson") end

package.path = "plugin/kmatrix.koplugin/?.lua;" .. package.path
local IPC = require("ipc")
local socket = require("socket")

local function poll(client, seconds)
    local deadline = socket.gettime() + seconds
    while socket.gettime() < deadline do
        for _ in client.waitEvent, client do end
        socket.sleep(0.02)
    end
end

local port, token = IPC.readPortFile()
assert(port, "no port file")
local client = IPC:new{ on_event = function() end, on_disconnect = function() end }
assert(client:connect(port, token))

-- 1. Exactly what KMatrix:requestRooms does.
local rooms
client:request("rooms", nil, function(resp) rooms = resp end)
poll(client, 5)
assert(rooms and rooms.ok, "rooms request failed")
print(("rooms: %d"):format(#rooms.rooms))

-- Pick the first room the room list would show as having content.
local target
for i = 1, #rooms.rooms do
    if (rooms.rooms[i].last_ts or 0) > 0 then target = rooms.rooms[i] break end
end
assert(target, "no room with messages")
print(("target: %s  id=%s"):format(target.name, target.id))

-- 2. Exactly what KMatrix:requestMessages does, including the guard that
--    decides whether the timeline is populated or left showing "No items".
local got
client:request("messages", { room = target.id, limit = 100 }, function(resp) got = resp end)
poll(client, 8)

if not got then
    print("FAIL: no response to 'messages' at all")
    os.exit(1)
end
print(("resp.ok       = %s"):format(tostring(got.ok)))
print(("resp.room     = %s"):format(tostring(got.room)))
print(("target.id     = %s"):format(tostring(target.id)))
print(("resp.messages = %s"):format(got.messages and #got.messages or "nil"))

-- This is the plugin's guard, verbatim.
local timeline_room = target.id
if timeline_room ~= got.room then
    print("FAIL: guard `self.timeline.room ~= resp.room` would DISCARD this response")
    print("      -> the timeline stays empty and renders 'No items'")
    os.exit(1)
end
print("guard passes: messages would be appended")

client:stop()
