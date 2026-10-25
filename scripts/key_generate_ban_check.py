#!/usr/bin/env python3
"""Check that the clippy.toml ban on `alice_crypto::Key::generate` is live: the
crate's one key-generation site, `crate::fresh_key` in src/lib.rs, is the only
call, and clippy flags it once its `#[allow]` is taken away.

The canary (scripts/clippy_canary.py) cannot plant this entry, because
alice-crypto is a git dependency and the canary crate depends on registry
crates only. This check uses the crate itself instead: it copies the manifest,
the lock, clippy.toml, the toolchain file and src/ into a temporary directory and
runs `cargo clippy --lib --all-features` twice:

  control  the copy as it is: no disallowed_methods diagnostic naming
           `alice_crypto::Key::generate`, and clippy exits 0
  mutant   the copy with the `#[allow(clippy::disallowed_methods, ...)]` right
           above `pub(crate) fn fresh_key` removed: exactly one such
           diagnostic, in src/lib.rs

It fails when the allow is not found exactly once (compared nothing), when the
control is not clean, or when the mutant does not give exactly one diagnostic.
Builds go to target/key-generate-ban so a second run reuses the dependencies.

usage: scripts/key_generate_ban_check.py
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANNED = "alice_crypto::Key::generate"
ALLOW = re.compile(
    r'#\[allow\(\s*clippy::disallowed_methods,\s*reason\s*=\s*"[^"]*"\s*,?\s*\)\]\n'
    r'(?=pub\(crate\) fn fresh_key\()'
)
COPIED = ("Cargo.toml", "Cargo.lock", "clippy.toml", "rust-toolchain.toml")


def strip_allow(lib: str) -> tuple[str, int]:
    """src/lib.rs without the allow above fresh_key, and how many allows matched."""
    return ALLOW.subn("", lib)


def named_diagnostics(stdout: str) -> list[tuple[str, int]]:
    """(file, line) of every disallowed_methods diagnostic naming BANNED."""
    out = []
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        m = msg.get("message", {})
        if (m.get("code") or {}).get("code") != "clippy::disallowed_methods":
            continue
        if f"`{BANNED}`" not in m.get("message", ""):
            continue
        span = next((s for s in m.get("spans", []) if s.get("is_primary")), {})
        out.append((span.get("file_name", "?"), span.get("line_start", 0)))
    return out


def judge(matched: int, control_rc: int, control: list[tuple[str, int]],
          mutant: list[tuple[str, int]]) -> list[str]:
    if matched != 1:
        return [f"found {matched} #[allow(clippy::disallowed_methods)] right above `pub(crate) fn fresh_key` "
                "in src/lib.rs (expected exactly 1; compared nothing)"]
    problems = []
    if control_rc != 0:
        problems.append(f"the unmodified crate does not pass clippy (exit {control_rc})")
    if control:
        problems.append(f"the unmodified crate has {len(control)} diagnostic(s) naming `{BANNED}`: {control}")
    if len(mutant) != 1:
        problems.append(f"with the allow removed, clippy gave {len(mutant)} diagnostic(s) naming `{BANNED}` "
                        f"(expected exactly 1): {mutant}")
    elif not mutant[0][0].endswith("src/lib.rs"):
        problems.append(f"with the allow removed, the diagnostic is at {mutant[0]}, not in src/lib.rs")
    return problems


def clippy(root: Path, lib: str | None, target: Path) -> tuple[int, str, str]:
    tmp = Path(tempfile.mkdtemp(prefix="key-generate-ban-"))
    try:
        for name in COPIED:
            if (root / name).exists():
                shutil.copyfile(root / name, tmp / name)
        shutil.copytree(root / "src", tmp / "src")
        if lib is not None:
            (tmp / "src" / "lib.rs").write_text(lib, encoding="utf-8")
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        p = subprocess.run(["cargo", "clippy", "--lib", "--all-features", "--quiet", "--message-format=json",
                            "--", "-D", "warnings"],
                           cwd=tmp, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    lib = (ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
    mutated, matched = strip_allow(lib)
    control_rc, control, mutant = 0, [], []
    if matched == 1:
        target = ROOT / "target" / "key-generate-ban"
        control_rc, out, err = clippy(ROOT, None, target)
        control = named_diagnostics(out)
        if control_rc != 0:
            sys.stderr.write(err[-4000:])
        _, out, _ = clippy(ROOT, mutated, target)
        mutant = named_diagnostics(out)
    problems = judge(matched, control_rc, control, mutant)
    if problems:
        for p in problems:
            print(f"key_generate_ban_check: {p}", file=sys.stderr)
        return 1
    print(f"key_generate_ban_check: 1 allow removed, `{BANNED}` flagged once at {mutant[0][0]}:{mutant[0][1]}, "
          "control clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
