--[[--
Line-delimited JSON IPC client for the local `kmatrixd` daemon.

The daemon listens on 127.0.0.1 (KOReader's LuaSocket has no AF_UNIX) and writes
`<data_dir>/kmatrix.port` holding two lines: the port and a shared secret token.

The object is meant to be handed to `UIManager:insertZMQ()`: KOReader then calls
`waitEvent()` as an iterator (`for ev in obj.waitEvent, obj`) every 50 ms, so
`waitEvent()` must never block and must return nil once it has nothing left to
read. All socket I/O below is non-blocking; partial reads are buffered until a
complete `\n` terminated line is available.

@module kmatrix.ipc
--]]

local DataStorage = require("datastorage")
local Event = require("ui/event")
local JSON = require("json")
local logger = require("logger")
local socket = require("socket")

-- A loopback connect either completes or is refused within the syscall, so this
-- is only a safety net against a pathological kernel state; it is never hit in
-- practice and therefore never stalls the UI thread.
local CONNECT_TIMEOUT = 2

local IPC = {
    -- Set by the caller:
    on_event = nil,      -- function(event_table) for unsolicited daemon events
    on_disconnect = nil, -- function(err) when the connection is lost
}

function IPC:new(o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    o.sock = nil
    o.rx_buf = ""       -- incomplete line carried over between polls
    o.tx_buf = ""       -- bytes the socket would not accept yet
    o.pending = {}      -- request id -> callback
    o.next_id = 1
    o.connected = false
    o.version = nil
    return o
end

--- Reads port and token from the daemon's handshake file.
-- @treturn number|nil port
-- @treturn string token, or an error message when port is nil
function IPC.readPortFile()
    local path = IPC.portFilePath()
    local f = io.open(path, "r")
    if not f then
        return nil, "no port file at " .. path
    end
    local port_line = f:read("*l")
    local token_line = f:read("*l")
    f:close()
    local port = tonumber(port_line and port_line:match("^%s*(%d+)%s*$"))
    local token = token_line and token_line:match("^%s*(%S+)%s*$")
    if not port or not token then
        return nil, "malformed port file at " .. path
    end
    return port, token
end

function IPC.dataDir()
    return DataStorage:getDataDir() .. "/kmatrix"
end

function IPC.portFilePath()
    return IPC.dataDir() .. "/kmatrix.port"
end

--- Opens the connection and sends the mandatory `hello` handshake.
-- @int port
-- @string token
-- @treturn boolean success
-- @treturn string error message on failure
function IPC:connect(port, token)
    if self.sock then
        self:stop()
    end
    local sock, err = socket.tcp()
    if not sock then
        return false, err or "cannot create socket"
    end
    sock:settimeout(CONNECT_TIMEOUT)
    local ok, cerr = sock:connect("127.0.0.1", port)
    if not ok then
        sock:close()
        return false, cerr or "connection refused"
    end
    -- Everything past the handshake runs on the UI thread: never block on it.
    sock:settimeout(0)
    pcall(sock.setoption, sock, "tcp-nodelay", true)

    self.sock = sock
    self.rx_buf = ""
    self.tx_buf = ""
    self.pending = {}
    self.next_id = 1
    self.connected = true
    self.version = nil

    -- `hello` must be the very first line or the daemon drops us.
    self:request("hello", { token = token }, function(resp)
        if resp.ok then
            self.version = resp.version
            logger.dbg("kmatrix: IPC handshake accepted, daemon version", tostring(resp.version))
        else
            logger.warn("kmatrix: IPC handshake rejected:", tostring(resp.error))
            self:fail(resp.error or "handshake rejected")
        end
    end)
    return true
end

function IPC:isConnected()
    return self.connected and self.sock ~= nil
end

--- Queues a request and calls back with the decoded response.
-- @string cmd command name
-- @tparam[opt] table fields extra request fields
-- @tparam[opt] func callback called with the response table (or a synthetic
--   failure table when the daemon is gone)
-- @treturn boolean whether the request was queued
function IPC:request(cmd, fields, callback)
    if not self:isConnected() then
        if callback then
            callback({ ok = false, error = "not connected" })
        end
        return false
    end
    local msg = { id = self.next_id, cmd = cmd }
    if fields then
        for k, v in pairs(fields) do
            msg[k] = v
        end
    end
    local ok, line = pcall(JSON.encode, msg)
    if not ok then
        logger.err("kmatrix: cannot encode request", cmd, line)
        if callback then
            callback({ ok = false, error = "encode failed" })
        end
        return false
    end
    self.next_id = self.next_id + 1
    if callback then
        self.pending[msg.id] = callback
    end
    self.tx_buf = self.tx_buf .. line .. "\n"
    self:flush()
    return true
end

--- Pushes as much of the outgoing buffer as the socket accepts.
function IPC:flush()
    if not self.sock or self.tx_buf == "" then return end
    local sent, err, last = self.sock:send(self.tx_buf)
    if sent then
        self.tx_buf = ""
    elseif err == "timeout" then
        -- Partial write: keep the tail for the next poll.
        self.tx_buf = self.tx_buf:sub((last or 0) + 1)
    else
        self:fail(err or "closed")
    end
end

--- Non-blocking poll, called as an iterator by `UIManager:processZMQs()`.
-- Handles at most one complete line per call and returns a non-nil value so
-- the iterator comes back for whatever else is already buffered; returns nil
-- as soon as no complete line is available.
function IPC:waitEvent()
    if not self.sock then return nil end
    self:flush()
    local line, err, partial = self.sock:receive("*l")
    if line then
        if self.rx_buf ~= "" then
            line = self.rx_buf .. line
            self.rx_buf = ""
        end
        self:handleLine(line)
        -- Treated like an input event so the standby/suspend timer is reset.
        return Event:new("InputEvent")
    end
    -- LuaSocket hands back whatever it consumed of an unterminated line; it is
    -- gone from the socket, so we must carry it until the terminator shows up.
    if partial and partial ~= "" then
        self.rx_buf = self.rx_buf .. partial
    end
    if err ~= "timeout" then
        self:fail(err or "closed")
    end
    return nil
end

function IPC:handleLine(line)
    if line == "" then return end
    local ok, msg = pcall(JSON.decode, line)
    if not ok or type(msg) ~= "table" then
        logger.warn("kmatrix: undecodable IPC line:", line)
        return
    end
    if msg.id then
        local callback = self.pending[msg.id]
        self.pending[msg.id] = nil
        if callback then
            local cb_ok, cb_err = pcall(callback, msg)
            if not cb_ok then
                logger.err("kmatrix: IPC response handler failed:", cb_err)
            end
        else
            logger.dbg("kmatrix: response for unknown request id", msg.id)
        end
    elseif msg.event then
        if self.on_event then
            local cb_ok, cb_err = pcall(self.on_event, msg)
            if not cb_ok then
                logger.err("kmatrix: IPC event handler failed:", cb_err)
            end
        end
    else
        logger.warn("kmatrix: IPC line is neither response nor event:", line)
    end
end

--- Tears the connection down after a socket error and notifies the owner.
function IPC:fail(err)
    if not self.connected then return end
    logger.warn("kmatrix: IPC connection lost:", tostring(err))
    local pending = self.pending
    self:stop()
    for _, callback in pairs(pending) do
        pcall(callback, { ok = false, error = err or "disconnected" })
    end
    if self.on_disconnect then
        pcall(self.on_disconnect, err)
    end
end

--- Closes the socket. Idempotent: `UIManager:quit()` also calls this.
function IPC:stop()
    self.connected = false
    self.pending = {}
    self.rx_buf = ""
    self.tx_buf = ""
    if self.sock then
        self.sock:close()
        self.sock = nil
    end
end

return IPC
