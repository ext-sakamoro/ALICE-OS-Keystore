#!/usr/bin/env python3
"""Keep a `cargo audit --ignore` for a lockfile-only advisory honest.

An advisory is ignored because the crate it names is recorded in Cargo.lock but
built by no feature of this crate. Both halves of that reason are checked, so
the ignore cannot outlive it:

  - reachable: `cargo tree -i <crate> --all-features -e all --target all`
    prints a dependency path -> fail (the crate is built now; the ignore would
    hide a real dependency). cargo-deny, which resolves features, would also
    report it.
  - stale: Cargo.lock has no `name = "<crate>"` entry -> fail (the ignore no
    longer applies: remove it from the audit step).

It fails when it could not compare anything (no Cargo.lock, or cargo tree did
not run), so it never passes vacuously.

    python3 scripts/audit_ignore_guard.py basic-toml [--dir .]
"""

import argparse
import pathlib
import subprocess
import sys
import tomllib


def check(crate, root):
    lock = root / "Cargo.lock"
    if not lock.is_file():
        return 2, f"audit_ignore_guard: {lock} not found (nothing to compare)"
    names = {p.get("name") for p in tomllib.loads(lock.read_text(encoding="utf-8")).get("package", [])}
    if not names:
        return 2, "audit_ignore_guard: Cargo.lock lists no packages (nothing to compare)"
    if crate not in names:
        return 1, f"audit_ignore_guard: {crate} is no longer in Cargo.lock: the ignore is stale, remove it"
    tree = subprocess.run(
        ["cargo", "tree", "--offline", "-i", crate, "--all-features", "-e", "all", "--target", "all"],
        cwd=root, capture_output=True, text=True,
    )
    if tree.returncode != 0:
        return 2, f"audit_ignore_guard: cargo tree failed (rc {tree.returncode}): {tree.stderr.strip()[:300]}"
    if tree.stdout.strip():
        return 1, f"audit_ignore_guard: {crate} is reachable, the ignore would hide a built dependency:\n{tree.stdout}"
    return 0, f"audit_ignore_guard: {crate} is in Cargo.lock ({len(names)} packages) and built by no feature: ignore still valid"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("crate")
    ap.add_argument("--dir", default=".")
    args = ap.parse_args(argv)
    rc, message = check(args.crate, pathlib.Path(args.dir).resolve())
    print(message, file=sys.stderr if rc else sys.stdout)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
