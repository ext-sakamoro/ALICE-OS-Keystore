#!/bin/bash
# scripts/with_keyring.sh <command...>
#
# Runs <command> with a Secret Service: on Linux inside a private D-Bus session
# (dbus-run-session) with gnome-keyring started and its login keyring unlocked, so
# the Linux key store's tests talk to a real Secret Service. Elsewhere it runs the
# command unchanged. The keyring password is a throwaway, used only inside this private bus.
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  exec "$@"
fi
if [ "${ALICE_KEYRING_SESSION:-}" != 1 ]; then
  command -v dbus-run-session >/dev/null || { echo "with_keyring: dbus-run-session not found (install dbus)" >&2; exit 2; }
  command -v gnome-keyring-daemon >/dev/null || { echo "with_keyring: gnome-keyring-daemon not found (install gnome-keyring)" >&2; exit 2; }
  ALICE_KEYRING_SESSION=1 exec dbus-run-session -- "$0" "$@"
fi
# inside the session: create / unlock the login keyring, then start its secrets component
printf 'throwaway' | gnome-keyring-daemon --unlock --components=secrets >/dev/null
gnome-keyring-daemon --start --components=secrets >/dev/null
exec "$@"
