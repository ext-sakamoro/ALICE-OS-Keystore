#!/usr/bin/env python3
"""Tests of scripts/audit_ignore_guard.py on small throwaway crates (resolved from crates.io; CI starts with an empty or partial cargo cache).

  - lock-only (uniffi 0.28 without its generator)  -> 0 (ignore valid)
  - reachable (uniffi 0.28 with `cli`)             -> 1 (built: the ignore would hide it)
  - stale (no uniffi at all)                       -> 1 (not in the lock: remove the ignore)
  - reachable only on iOS (target-specific)        -> 1 (`--target all` sees it)
  - reachable only behind a feature                -> 1 (`--all-features` sees it)
  - cargo tree fails (manifest broken after lock)  -> 2 (nothing compared, never "valid")
  - a Cargo.lock with no packages                  -> 2 (nothing compared)
  - no Cargo.lock                                  -> 2 (nothing compared)
"""

import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_ignore_guard as guard  # noqa: E402


def crate(tmp, name, deps, table="[dependencies]", extra=""):
    d = pathlib.Path(tmp) / name
    (d / "src").mkdir(parents=True)
    (d / "src/lib.rs").write_text("", encoding="utf-8")
    (d / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
        f"{table}\n{deps}\n\n{extra}[workspace]\n", encoding="utf-8")
    subprocess.run(["cargo", "generate-lockfile"], cwd=d, check=True, capture_output=True)
    return d


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        cli = 'uniffi = { version = "=0.28.3", features = ["cli"] }'
        cases = [
            # (name, deps, table, want rc, a word the message must contain)
            ("lock-only", 'uniffi = "=0.28.3"', "[dependencies]", 0, "still valid"),
            ("reachable", cli, "[dependencies]", 1, "reachable"),
            ("reachable on ios only", cli, "[target.'cfg(target_os = \"ios\")'.dependencies]", 1, "reachable"),
            ("stale", 'zeroize = "1"', "[dependencies]", 1, "stale"),
        ]
        for name, deps, table, want, word in cases:
            rc, msg = guard.check("basic-toml", crate(tmp, name.replace(" ", "-"), deps, table))
            if rc != want or word not in msg:
                failures.append(f"{name}: rc {rc} (want {want}, message with {word!r}): {msg}")

        # reachable only when a feature is on: the guard resolves all features
        gated = crate(tmp, "feature-gated", 'uniffi = { version = "=0.28.3", optional = true }',
                      extra='[features]\ngen = ["dep:uniffi", "uniffi/cli"]\n\n')
        rc, msg = guard.check("basic-toml", gated)
        if rc != 1 or "reachable" not in msg:
            failures.append(f"reachable behind a feature: rc {rc} (want 1): {msg}")

        # cargo tree cannot run (the manifest is broken after the lock was made): never "valid"
        broken = crate(tmp, "broken", 'uniffi = "=0.28.3"')
        (broken / "Cargo.toml").write_text("[package\n", encoding="utf-8")
        rc, msg = guard.check("basic-toml", broken)
        if rc != 2 or "cargo tree failed" not in msg:
            failures.append(f"cargo tree fails: rc {rc} (want 2): {msg}")

        # a Cargo.lock that lists no packages compares nothing
        bare = pathlib.Path(tmp) / "bare"
        bare.mkdir()
        (bare / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        rc, msg = guard.check("basic-toml", bare)
        if rc != 2 or "no packages" not in msg:
            failures.append(f"empty lock: rc {rc} (want 2): {msg}")
        empty = pathlib.Path(tmp) / "empty"
        empty.mkdir()
        rc, msg = guard.check("basic-toml", empty)
        if rc != 2 or "not found" not in msg:
            failures.append(f"no lock: rc {rc} (want 2): {msg}")
    if failures:
        print("test_audit_ignore_guard FAIL:", *failures, sep="\n  ")
        return 1
    print("test_audit_ignore_guard OK (8 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
