-- Drives plugin/kmatrix.koplugin/ipc.lua against a live kmatrixd, with the
-- handful of KOReader modules it imports replaced by minimal stubs. This
-- exercises the part of the Lua side that is easy to get wrong -- non-blocking
-- reads, partial-line buffering and request/response correlation -- without
-- needing a device or a running KOReader.
--
--   usage: luajit scripts/ipctest.lua <data-dir>

local data_dir = assert(arg[1], "usage: ipctest.lua <data-dir>")

-- --------------------------------------------------------------- stubs
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

-- --------------------------------------------------------------- helpers
-- Wall clock, not os.clock(): os.clock() reports CPU time, which barely
-- advances while we are sleeping, so a poll loop built on it never ends.
local socket = require("socket")

local function poll(client, seconds)
    local deadline = socket.gettime() + seconds
    while socket.gettime() < deadline do
        for _ in client.waitEvent, client do end -- drain this round
        socket.sleep(0.02)
    end
end

local failures = 0
local function check(name, cond, detail)
    if cond then
        print(("  ok   %s"):format(name))
    else
        failures = failures + 1
        print(("  FAIL %s%s"):format(name, detail and (" -- " .. detail) or ""))
    end
end

-- --------------------------------------------------------------- run
local port, token = IPC.readPortFile()
check("readPortFile", port and token, "port=" .. tostring(port))

local events = {}
local client = IPC:new{
    on_event = function(ev) events[#events + 1] = ev end,
    on_disconnect = function() events[#events + 1] = { event = "__disconnect" } end,
}

local connected, err = client:connect(port, token)
check("connect + hello", connected, tostring(err))

local got = {}
client:request("status", nil, function(resp) got.status = resp end)
poll(client, 2)
check("status response correlated", got.status ~= nil)
check("status ok", got.status and got.status.ok == true)
print("       state = " .. tostring(got.status and got.status.state))

-- Several requests in flight at once must each reach their own callback.
local n = 0
for i = 1, 5 do
    client:request("rooms", nil, function(resp)
        n = n + 1
        got["rooms" .. i] = resp.ok
    end)
end
poll(client, 3)
check("5 concurrent requests all correlated", n == 5, "got " .. n)

-- A large response forces the reader across multiple recv() boundaries,
-- which is exactly where naive line handling breaks.
local big
client:request("messages", { room = "!nonexistent:localhost", limit = 50 },
    function(resp) big = resp end)
poll(client, 3)
check("messages response parsed", big ~= nil and big.ok == true)

client:stop()
check("stop is clean", not client:isConnected())
client:stop() -- must be idempotent
check("stop is idempotent", true)

print(("\n%s: %d failure(s)"):format(failures == 0 and "PASS" or "FAIL", failures))
os.exit(failures == 0 and 0 or 1)
