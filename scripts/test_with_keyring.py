#!/usr/bin/env python3
"""Tests for scripts/with_keyring.sh on Linux, against a real gnome-keyring in the
script's private D-Bus session: the command runs with the daemon owning
org.freedesktop.secrets (and its pid exported), a failing command's exit code is
returned, a daemon that exits during a command fails the run even when the command
succeeds, and once the daemon is gone the name has no owner (nothing is started in
its place by activation). Each of the last two is also run against a copy of the
script with that safeguard removed, which must let the failure through, so the
tests are known to detect it. Elsewhere the script runs the command unchanged and
these tests are skipped; on Linux a missing dbus or gnome-keyring is a failure,
not a skip."""
import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "with_keyring.sh"
LINUX = platform.system() == "Linux"

OWNER = ("dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus "
         "org.freedesktop.DBus.GetConnectionUnixProcessID string:org.freedesktop.secrets")
PING = ("dbus-send --session --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets "
        "org.freedesktop.DBus.Peer.Ping")
KILL = 'kill "$ALICE_KEYRING_PID"; while kill -0 "$ALICE_KEYRING_PID" 2>/dev/null; do sleep 0.1; done'


def run(command, script=SCRIPT):
    return subprocess.run(["bash", str(script), "bash", "-c", command],
                          capture_output=True, text=True, timeout=120)


def mutant(*edits):
    """A copy of the script with safeguards replaced: each (old, new) pair, where `old`
    occurs exactly once."""
    text = SCRIPT.read_text()
    for old, new in edits:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    path = Path(tempfile.mkdtemp()) / "with_keyring.sh"
    path.write_text(text)
    path.chmod(0o755)
    return path


@unittest.skipUnless(LINUX, "with_keyring.sh only starts a keyring on Linux")
class WithKeyring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [t for t in ("dbus-run-session", "dbus-send", "gnome-keyring-daemon") if shutil.which(t) is None]
        if missing:
            raise AssertionError(f"missing on Linux: {', '.join(missing)} (install dbus and gnome-keyring)")

    def test_the_command_runs_with_the_started_daemon_owning_the_name(self):
        r = run(f'test -n "$ALICE_KEYRING_PID" && {OWNER} | grep -q "uint32 $ALICE_KEYRING_PID$"')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_failing_command_returns_its_exit_code(self):
        r = run("exit 3")
        self.assertEqual(r.returncode, 3, r.stderr)

    def test_a_daemon_that_exits_during_the_command_fails_the_run(self):
        r = run(f"{KILL}; exit 0")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exited during the command", r.stderr)
        self.assertIn("gnome-keyring-daemon log", r.stderr)

    def test_a_dead_daemon_is_not_replaced(self):
        r = run(f"{KILL}; if {PING}; then echo REPLACED; fi")
        self.assertNotIn("REPLACED", r.stdout, r.stderr)

    def test_without_the_liveness_check_a_dead_daemon_goes_unnoticed(self):
        m = mutant(('if ! kill -0 "$daemon" 2>/dev/null; then\n  echo "with_keyring: gnome-keyring-daemon',
                    'if false; then\n  echo "with_keyring: gnome-keyring-daemon'),
                   ('if [ "$owner" != "$daemon" ]; then\n  echo "with_keyring: org.freedesktop.secrets moved',
                    'if false; then\n  echo "with_keyring: org.freedesktop.secrets moved'))
        r = run(f"{KILL}; exit 0", script=m)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_with_activation_allowed_a_dead_daemon_is_replaced(self):
        m = mutant(("  <type>session</type>\n", "  <type>session</type>\n  <standard_session_servicedirs/>\n"))
        r = run(f"{KILL}; if {PING}; then echo REPLACED; fi", script=m)
        self.assertIn("REPLACED", r.stdout, r.stderr)


if __name__ == "__main__":
    unittest.main()
