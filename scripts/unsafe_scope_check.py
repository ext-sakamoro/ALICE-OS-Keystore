#!/usr/bin/env python3
"""`unsafe` code is allowed only in src/sys/, and every block there says why it is sound.

The crate denies `unsafe_code` (Cargo.toml `[lints.rust]`) and allows it on one module,
`mod sys` in src/lib.rs. This check reads every tracked Rust file under src/ (comments and string
literals removed) and fails when:

* the word `unsafe` appears in a file outside src/sys/;
* an `unsafe` block or call in src/sys/ is not preceded (within 3 lines) by a `// SAFETY:` note;
* `allow(unsafe_code)` appears anywhere but once, on `mod sys` in src/lib.rs, or Cargo.toml no
  longer denies `unsafe_code`;
* no file was read, or src/sys/ has no `unsafe` at all (the Windows console calls live there, so
  zero means the check did not read what it should).

  python3 scripts/unsafe_scope_check.py [--root DIR]

Prints `unsafe scope: read N files, M unsafe in src/sys/, K finding(s)`. Exit 0 when clean, 1 on a
finding, 2 when nothing was read.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

WORD = re.compile(r"\bunsafe\b")
ALLOW = re.compile(r"allow\s*\(\s*unsafe_code\s*\)")


def strip(text: str) -> str:
    """Remove comments, string and char literals, keeping line breaks so line numbers stay."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    out.append("\n" if text[i] == "\n" else "")
                    i += 1
        elif c == "r" and re.match(r'r#*"', text[i:]):
            hashes = re.match(r'r(#*)"', text[i:]).group(1)
            end = text.find('"' + hashes, i + 2 + len(hashes))
            end = n if end < 0 else end + 1 + len(hashes)
            out.append("\n" * text.count("\n", i, end))
            i = end
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append("\n" * text.count("\n", i, j))
            i = j + 1
        elif c == "'" and re.match(r"'(\\.|[^\\'])'", text[i:]):
            i += len(re.match(r"'(\\.|[^\\'])'", text[i:]).group(0))
        else:
            out.append(c)
            i += 1
    return "".join(out)


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "src"], capture_output=True, check=True
    ).stdout
    return sorted(p for p in out.decode().split("\0") if p.endswith(".rs"))


def check(root: Path) -> tuple[int, int, list[str]]:
    findings: list[str] = []
    files = tracked(root)
    in_sys = 0
    allows = []
    for rel in files:
        raw = (root / rel).read_text(encoding="utf-8")
        code = strip(raw)
        code_lines = code.split("\n")
        raw_lines = raw.split("\n")
        for no, line in enumerate(code_lines, 1):
            if ALLOW.search(line):
                allows.append((rel, no))
            if not WORD.search(line):
                continue
            if not rel.startswith("src/sys/"):
                findings.append(f"{rel}:{no}: unsafe outside src/sys/")
                continue
            in_sys += 1
            before = raw_lines[max(0, no - 4) : no - 1]
            if not any("SAFETY:" in b for b in before):
                findings.append(f"{rel}:{no}: unsafe without a `// SAFETY:` note in the 3 lines before")
    if len(allows) != 1 or allows[0][0] != "src/lib.rs":
        findings.append(f"allow(unsafe_code) must appear exactly once, in src/lib.rs on `mod sys`: {allows}")
    else:
        rel, no = allows[0]
        lines = strip((root / rel).read_text(encoding="utf-8")).split("\n")
        # the item the attribute applies to: the first line after it that is not blank or another attribute
        item = next(
            (l.strip() for l in lines[no:] if l.strip() and not l.strip().startswith("#[")),
            "",
        )
        if not re.fullmatch(r"(pub(\([^)]*\))?\s+)?mod\s+sys\s*;", item):
            findings.append(f"{rel}:{no}: allow(unsafe_code) is not on `mod sys`")
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    if not re.search(r'^\s*unsafe_code\s*=\s*"(deny|forbid)"', cargo, re.M):
        findings.append('Cargo.toml: [lints.rust] unsafe_code is not "deny"')
    if files and in_sys == 0:
        findings.append("src/sys/ has no unsafe: the check did not read the operating system calls")
    return len(files), in_sys, findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    read, in_sys, findings = check(args.root)
    for f in findings:
        print(f"unsafe scope: {f}", file=sys.stderr)
    print(f"unsafe scope: read {read} files, {in_sys} unsafe in src/sys/, {len(findings)} finding(s)")
    if read == 0:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
