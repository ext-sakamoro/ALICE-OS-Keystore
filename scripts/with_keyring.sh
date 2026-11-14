#!/bin/bash
# scripts/with_keyring.sh <command...>
#
# Runs <command> with a Secret Service: on Linux inside a private D-Bus session
# (dbus-run-session) with gnome-keyring started and its login keyring unlocked, so
# the Linux key store's tests talk to a real Secret Service. Elsewhere it runs the
# command unchanged. The keyring password is a throwaway, used only inside this private bus, and the
# keyring files are kept under the session's temporary directory (XDG_DATA_HOME), never in the caller's
# own keyrings: a machine user's login keyring would not open with the throwaway password, and the tests'
# items do not belong in it.
#
# The daemon runs in the foreground as a child of this script, with its own output kept in a
# log file (ALICE_KEYRING_LOG, default under the session's temporary directory). The command
# starts only after org.freedesktop.secrets is owned by that daemon, and its pid is exported
# as ALICE_KEYRING_PID. The private bus has no activatable services, so if the daemon exits
# nothing replaces it: calls fail at once instead of reaching a fresh locked keyring. If the
# daemon is gone, or no longer owns the name, when the command ends, the script fails and
# prints the log, whatever the command returned.
#
# The private bus is also recorded by dbus-monitor from before the daemon starts (ALICE_KEYRING_BUS_LOG,
# default beside the daemon log): Secret Service method calls with their sender, errors, and
# NameOwnerChanged (a connection that leaves the bus). Its last lines are printed with the daemon log,
# so a daemon that dies during the command shows which connection sent the last calls and which left.
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  exec "$@"
fi

# the pid owning org.freedesktop.secrets, or nothing while the name has no owner (never fails, so
# `owner=$(owner_pid)` does not end the script under set -e / pipefail)
owner_pid() {
  { dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
      org.freedesktop.DBus.GetConnectionUnixProcessID string:org.freedesktop.secrets 2>/dev/null || true; } \
    | awk '/uint32/ { print $2 }'
}

show_log() {
  echo "with_keyring: gnome-keyring-daemon log ($ALICE_KEYRING_LOG):" >&2
  sed 's/^/  | /' "$ALICE_KEYRING_LOG" >&2 || true
  echo "with_keyring: D-Bus messages, last 400 lines ($ALICE_KEYRING_BUS_LOG):" >&2
  tail -n 400 "$ALICE_KEYRING_BUS_LOG" 2>/dev/null | sed 's/^/  > /' >&2 || true
}

if [ "${ALICE_KEYRING_SESSION:-}" != 1 ]; then
  for tool in dbus-run-session dbus-send dbus-monitor gnome-keyring-daemon; do
    command -v "$tool" >/dev/null || { echo "with_keyring: $tool not found (install dbus and gnome-keyring)" >&2; exit 2; }
  done
  tmp=$(mktemp -d)
  # a session bus with no <servicedir>: nothing can be started by activation
  cat >"$tmp/session.conf" <<'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <keep_umask/>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
  mkdir -m 700 "$tmp/run" "$tmp/data"
  export ALICE_KEYRING_LOG="${ALICE_KEYRING_LOG:-$tmp/gnome-keyring.log}"
  export ALICE_KEYRING_BUS_LOG="${ALICE_KEYRING_BUS_LOG:-$tmp/bus.log}"
  ALICE_KEYRING_SESSION=1 XDG_RUNTIME_DIR="$tmp/run" XDG_DATA_HOME="$tmp/data" exec dbus-run-session --config-file="$tmp/session.conf" -- "$0" "$@"
fi

# inside the session: create / unlock the login keyring in a foreground daemon, then start its
# secrets component on the bus
: >"$ALICE_KEYRING_LOG"
# the bus recording starts first, so the daemon's whole life is in it
dbus-monitor --session "type='method_call',interface='org.freedesktop.Secret.Service'" \
  "type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'" "type='error'" \
  >"$ALICE_KEYRING_BUS_LOG" 2>&1 &
monitor=$!
trap 'kill "$monitor" 2>/dev/null || true' EXIT
printf 'throwaway' | G_MESSAGES_DEBUG=all gnome-keyring-daemon --foreground --unlock --components=secrets >>"$ALICE_KEYRING_LOG" 2>&1 &
daemon=$!
for _ in $(seq 100); do
  [ -S "$XDG_RUNTIME_DIR/keyring/control" ] && break
  kill -0 "$daemon" 2>/dev/null || break
  sleep 0.1
done
gnome-keyring-daemon --start --components=secrets >/dev/null 2>>"$ALICE_KEYRING_LOG" || true
owner=
for _ in $(seq 100); do
  owner=$(owner_pid)
  [ "$owner" = "$daemon" ] && break
  kill -0 "$daemon" 2>/dev/null || break
  sleep 0.1
done
if [ "$owner" != "$daemon" ]; then
  echo "with_keyring: org.freedesktop.secrets is owned by '${owner:-nobody}', not the daemon started here (pid $daemon)" >&2
  show_log
  exit 2
fi

export ALICE_KEYRING_PID=$daemon
set +e
"$@"
rc=$?
set -e
if ! kill -0 "$daemon" 2>/dev/null; then
  echo "with_keyring: gnome-keyring-daemon (pid $daemon) exited during the command" >&2
  show_log
  exit 1
fi
owner=$(owner_pid)
if [ "$owner" != "$daemon" ]; then
  echo "with_keyring: org.freedesktop.secrets moved from pid $daemon to '${owner:-nobody}' during the command" >&2
  show_log
  exit 1
fi
[ "$rc" = 0 ] || show_log
kill "$daemon" 2>/dev/null || true
exit "$rc"
