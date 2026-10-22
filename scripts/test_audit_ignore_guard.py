#!/usr/bin/env python3
"""Tests of scripts/audit_ignore_guard.py on small throwaway crates (offline, from the cargo cache).

  - lock-only (uniffi 0.28 without its generator)  -> 0 (ignore valid)
  - reachable (uniffi 0.28 with `cli`)             -> 1 (built: the ignore would hide it)
  - stale (no uniffi at all)                       -> 1 (not in the lock: remove the ignore)
  - no Cargo.lock                                  -> 2 (nothing compared)
"""

import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_ignore_guard as guard  # noqa: E402


def crate(tmp, name, deps):
    d = pathlib.Path(tmp) / name
    (d / "src").mkdir(parents=True)
    (d / "src/lib.rs").write_text("", encoding="utf-8")
    (d / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
        f"[dependencies]\n{deps}\n\n[workspace]\n", encoding="utf-8")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=d, check=True, capture_output=True)
    return d


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        cases = [
            ("lock-only", 'uniffi = "=0.28.3"', 0),
            ("reachable", 'uniffi = { version = "=0.28.3", features = ["cli"] }', 1),
            ("stale", 'zeroize = "1"', 1),
        ]
        for name, deps, want in cases:
            rc, msg = guard.check("basic-toml", crate(tmp, name, deps))
            if rc != want:
                failures.append(f"{name}: rc {rc} (want {want}): {msg}")
        empty = pathlib.Path(tmp) / "empty"
        empty.mkdir()
        rc, msg = guard.check("basic-toml", empty)
        if rc != 2:
            failures.append(f"no lock: rc {rc} (want 2): {msg}")
    if failures:
        print("test_audit_ignore_guard FAIL:", *failures, sep="\n  ")
        return 1
    print("test_audit_ignore_guard OK (4 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
