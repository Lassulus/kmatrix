#!/usr/bin/env bash
# Local matrix-conduit homeserver for kmatrix smoke tests.
#
# Conduit 0.10 reads CONDUIT_CONFIG (a required env var) and merges CONDUIT_*
# env vars on top. We hand it a generated TOML so every setting lives in one
# reviewable place. With allow_registration = true and no registration_token
# set, conduit offers the m.login.dummy UIAA flow, which is what `register`
# below drives.
set -euo pipefail

# Deliberately NOT $TMPDIR: `nix develop` sets a fresh per-invocation TMPDIR,
# so start/stop/status in separate shells would each pick a different state
# directory and never find one another. Override with KMATRIX_TESTSERVER_DIR.
DATA_DIR="${KMATRIX_TESTSERVER_DIR:-/tmp/kmatrix-testserver}"
CONFIG="$DATA_DIR/conduit.toml"
DB_DIR="$DATA_DIR/db"
PIDFILE="$DATA_DIR/conduit.pid"
LOGFILE="$DATA_DIR/conduit.log"

HOST="127.0.0.1"
PORT="6167"
BASE="http://$HOST:$PORT"
START_TIMEOUT="${KMATRIX_TESTSERVER_TIMEOUT:-60}"

die() {
	printf 'testserver: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<EOF
usage: ${0##*/} <command>

  start                 start conduit on $BASE and wait until it answers
  stop                  terminate the running conduit
  status                report whether conduit is running and reachable
  register <user> <pw>  create an account, print user_id and access_token

State lives in $DATA_DIR (log: $LOGFILE).
EOF
}

conduit_bin() {
	if command -v conduit >/dev/null 2>&1; then
		command -v conduit
		return
	fi
	command -v nix >/dev/null 2>&1 ||
		die "conduit not on PATH and nix unavailable; enter the dev shell first"
	local out
	out="$(nix build --no-link --print-out-paths nixpkgs#matrix-conduit)" ||
		die "could not build nixpkgs#matrix-conduit"
	printf '%s/bin/conduit\n' "$out"
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"
}

running_pid() {
	[ -f "$PIDFILE" ] || return 1
	local pid
	pid="$(cat "$PIDFILE")"
	[ -n "$pid" ] || return 1
	kill -0 "$pid" 2>/dev/null || return 1
	printf '%s\n' "$pid"
}

reachable() {
	curl -fsS --max-time 2 -o /dev/null "$BASE/_matrix/client/versions" 2>/dev/null
}

write_config() {
	mkdir -p "$DB_DIR"
	cat >"$CONFIG" <<EOF
[global]
server_name = "localhost"
address = "$HOST"
port = $PORT
database_backend = "sqlite"
database_path = "$DB_DIR"
allow_registration = true
allow_encryption = true
allow_federation = false
allow_check_for_updates = false
enable_lightning_bolt = false
trusted_servers = []
log = "warn"
EOF
}

cmd_start() {
	need curl
	if running_pid >/dev/null; then
		printf 'already running (pid %s) on %s\n' "$(running_pid)" "$BASE"
		return 0
	fi
	if reachable; then
		die "something is already listening on $BASE"
	fi

	local bin
	bin="$(conduit_bin)"
	write_config

	CONDUIT_CONFIG="$CONFIG" "$bin" >"$LOGFILE" 2>&1 &
	local pid=$!
	printf '%s\n' "$pid" >"$PIDFILE"

	local waited=0
	while :; do
		if reachable; then
			printf 'conduit ready on %s (pid %s)\n' "$BASE" "$pid"
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			rm -f "$PIDFILE"
			printf 'conduit exited during startup; last log lines:\n' >&2
			tail -n 20 "$LOGFILE" >&2 || true
			exit 1
		fi
		if [ "$waited" -ge "$START_TIMEOUT" ]; then
			kill "$pid" 2>/dev/null || true
			rm -f "$PIDFILE"
			printf 'conduit did not answer %s within %ss; last log lines:\n' \
				"$BASE/_matrix/client/versions" "$START_TIMEOUT" >&2
			tail -n 20 "$LOGFILE" >&2 || true
			exit 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
}

cmd_stop() {
	local pid
	if ! pid="$(running_pid)"; then
		rm -f "$PIDFILE"
		printf 'not running\n'
		return 0
	fi
	kill "$pid" 2>/dev/null || true
	local waited=0
	while kill -0 "$pid" 2>/dev/null; do
		if [ "$waited" -ge 10 ]; then
			kill -9 "$pid" 2>/dev/null || true
			break
		fi
		sleep 1
		waited=$((waited + 1))
	done
	rm -f "$PIDFILE"
	printf 'stopped (pid %s)\n' "$pid"
}

cmd_status() {
	need curl
	local pid state="stopped"
	if pid="$(running_pid)"; then
		state="running (pid $pid)"
	fi
	printf 'process:   %s\n' "$state"
	if reachable; then
		printf 'endpoint:  %s responds\n' "$BASE/_matrix/client/versions"
	else
		printf 'endpoint:  %s unreachable\n' "$BASE/_matrix/client/versions"
	fi
	printf 'data dir:  %s\n' "$DATA_DIR"
	printf 'log:       %s\n' "$LOGFILE"
	running_pid >/dev/null && reachable
}

cmd_register() {
	need curl
	need jq
	[ "$#" -eq 2 ] || die "register needs exactly <user> <password>"
	local user="$1" pass="$2" payload tmp code body
	payload="$(jq -n --arg u "$user" --arg p "$pass" \
		'{username: $u, password: $p, device_id: "TEST",
		  initial_device_display_name: "kmatrix test",
		  auth: {type: "m.login.dummy"}}')"

	tmp="$(mktemp "$DATA_DIR/register.XXXXXX" 2>/dev/null || mktemp)"
	code="$(curl -sS -o "$tmp" -w '%{http_code}' \
		-X POST "$BASE/_matrix/client/v3/register" \
		-H 'Content-Type: application/json' \
		--data-binary "$payload")" || {
		rm -f "$tmp"
		die "could not reach $BASE - is the server started?"
	}
	body="$(cat "$tmp")"
	rm -f "$tmp"

	if [ "$code" != "200" ]; then
		printf 'registration failed (HTTP %s): %s\n' "$code" "$body" >&2
		exit 1
	fi

	printf 'homeserver:   %s\n' "$BASE"
	printf 'user_id:      %s\n' "$(printf '%s' "$body" | jq -r '.user_id')"
	printf 'device_id:    %s\n' "$(printf '%s' "$body" | jq -r '.device_id')"
	printf 'access_token: %s\n' "$(printf '%s' "$body" | jq -r '.access_token')"
}

mkdir -p "$DATA_DIR"

case "${1-}" in
start)
	cmd_start
	;;
stop)
	cmd_stop
	;;
status)
	cmd_status
	;;
register)
	shift
	cmd_register "$@"
	;;
-h | --help | help | "")
	usage
	;;
*)
	usage >&2
	die "unknown command: $1"
	;;
esac
