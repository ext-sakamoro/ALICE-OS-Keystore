#!/usr/bin/env python3
"""Tests for scripts/unsafe_scope_check.py (each case builds a small git tree)."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECK = HERE / "unsafe_scope_check.py"

CARGO = '[package]\nname = "x"\n\n[lints.rust]\nunsafe_code = "deny"\n'
LIB = "pub mod prompt;\n#[allow(unsafe_code)]\nmod sys;\n"
SYS = (
    "pub fn f() {\n"
    "    // SAFETY: nothing is dereferenced\n"
    "    unsafe { g() }\n"
    "}\n"
)
PROMPT = '//! no unsafe here, only the word in a comment\npub fn p() -> &\'static str { "unsafe in a string" }\n'


def tree(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="unsafe-scope-"))
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    subprocess.run(["git", "-C", str(d), "add", "-A"], check=True)
    return d


def run(files: dict[str, str]) -> tuple[int, str]:
    d = tree(files)
    r = subprocess.run([sys.executable, str(CHECK), "--root", str(d)], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def base(**over: str) -> dict[str, str]:
    files = {"Cargo.toml": CARGO, "src/lib.rs": LIB, "src/sys/mod.rs": SYS, "src/prompt.rs": PROMPT}
    files.update(over)
    return files


def expect(name: str, files: dict[str, str], code: int, text: str) -> None:
    got, out = run(files)
    assert got == code and text in out, f"{name}: exit {got}, expected {code} with {text!r}\n{out}"
    print(f"ok  {name}")


def main() -> int:
    expect("clean tree", base(), 0, "1 unsafe in src/sys/, 0 finding(s)")
    expect(
        "unsafe outside src/sys/",
        base(**{"src/prompt.rs": "pub fn p() { unsafe { q() } }\n"}),
        1,
        "src/prompt.rs:1: unsafe outside src/sys/",
    )
    expect(
        "unsafe fn outside src/sys/",
        base(**{"src/other.rs": "pub unsafe fn p() {}\n"}),
        1,
        "src/other.rs:1: unsafe outside src/sys/",
    )
    expect(
        "no SAFETY note",
        base(**{"src/sys/mod.rs": "pub fn f() {\n    unsafe { g() }\n}\n"}),
        1,
        "without a `// SAFETY:` note",
    )
    expect(
        "SAFETY note too far above",
        base(**{"src/sys/mod.rs": "// SAFETY: far\n\n\n\n\nunsafe { g() }\n"}),
        1,
        "without a `// SAFETY:` note",
    )
    expect(
        "second allow",
        base(**{"src/prompt.rs": "#[allow(unsafe_code)]\nmod x;\n"}),
        1,
        "must appear exactly once",
    )
    expect(
        "allow not on mod sys",
        base(**{"src/lib.rs": "#[allow(unsafe_code)]\nmod other;\nmod sys;\n"}),
        1,
        "is not on `mod sys`",
    )
    expect(
        "lint no longer denies",
        base(**{"Cargo.toml": '[package]\nname = "x"\n\n[lints.rust]\nunsafe_code = "allow"\n'}),
        1,
        "is not \"deny\"",
    )
    expect(
        "src/sys/ without unsafe",
        base(**{"src/sys/mod.rs": "pub fn f() {}\n"}),
        1,
        "src/sys/ has no unsafe",
    )
    expect("nothing read", {"Cargo.toml": CARGO}, 2, "read 0 files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
