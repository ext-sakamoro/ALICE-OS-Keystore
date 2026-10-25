#!/usr/bin/env python3
"""ALICE-Law G4 / G6 / G7 / G9 scope check: this crate has no Law-bearing value,
and every byte boundary of its public surface is listed with what it carries.

The crate stores and serves keys. What crosses its public surface is key
material (`alice_crypto::Key` and the raw bytes the foreign interface hands
over), passphrases and data read from the operating system's stores, none of
which is computed by a Law: the gates about a Law-bearing value's semantics
identifier (G4 / G6), carrying it across crates (G7) and its history (G9) have
nothing to apply to. This script measures that claim from the rustdoc JSON of
the library (every feature named on the command line):

- every item of the crate that carries bytes in its signature (`u8` anywhere,
  or `alice_crypto::Key`) must be listed in scripts/law_boundary_table.toml
  with its class and a reason. The items are: public functions and methods,
  trait methods and the methods of trait impls (rustdoc gives them the
  `default` visibility), and public struct fields (a UniFFI record field
  crosses to the foreign side as it is);
- an entry is keyed by file, parent (the trait, `Trait for Type`, the type of
  an inherent impl, or the struct; empty for a free function) and name;
- an entry with `os` is the platform store compiled only there: it is checked
  for staleness only when `--os` names that platform;
- a listed item that the scan no longer finds fails (remove it);
- scanning no item, or reading no table entry, fails.

    python3 scripts/law_boundary_scan.py --os linux --json target/doc/alice_os_keystore.json
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "scripts" / "law_boundary_table.toml"
KEY_PATH = ("alice_crypto", "Key")
HOST_OS = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system(), "")


def carries_bytes(t, paths: dict) -> bool:
    if isinstance(t, dict):
        if t.get("primitive") == "u8":
            return True
        rp = t.get("resolved_path")
        if isinstance(rp, dict):
            p = (paths.get(str(rp.get("id"))) or {}).get("path") or []
            if len(p) >= 2 and (p[0], p[-1]) == KEY_PATH:
                return True
        return any(carries_bytes(v, paths) for v in t.values())
    if isinstance(t, list):
        return any(carries_bytes(v, paths) for v in t)
    return False


def type_name(t) -> str:
    rp = (t or {}).get("resolved_path") if isinstance(t, dict) else None
    return rp.get("path", "?") if isinstance(rp, dict) else "?"


def parents(index: dict) -> dict[str, str]:
    """item id -> parent label, for the items of traits, impls and structs of the crate"""
    out = {}
    for item in index.values():
        if item.get("crate_id") != 0:
            continue
        inner = item.get("inner") or {}
        if "trait" in inner:
            for i in inner["trait"].get("items", []):
                out[str(i)] = item.get("name", "?")
        elif "impl" in inner:
            im = inner["impl"]
            if im.get("is_synthetic") or im.get("blanket_impl"):
                continue
            label = type_name(im.get("for"))
            if im.get("trait"):
                label = f"{im['trait'].get('path', '?')} for {label}"
            for i in im.get("items", []):
                out[str(i)] = label
        elif "struct" in inner:
            kind = inner["struct"].get("kind") or {}
            fields = (kind.get("plain") or {}).get("fields", []) + (kind.get("tuple") or [])
            for i in fields:
                if i is not None:
                    out[str(i)] = item.get("name", "?")
    return out


def boundary_items(doc: dict) -> list[dict]:
    """items of the crate whose signature carries bytes"""
    index = doc.get("index", {})
    paths = doc.get("paths", {})
    parent = parents(index)
    out = []
    for iid, item in index.items():
        if item.get("crate_id") != 0:
            continue
        inner = item.get("inner") or {}
        vis = item.get("visibility")
        if "function" in inner and vis in ("public", "default"):
            if vis == "default" and iid not in parent:
                continue
            sig = inner["function"].get("sig", {})
            carried = [t for _, t in sig.get("inputs", [])] + [sig.get("output")]
        elif "struct_field" in inner and vis == "public":
            carried = [inner["struct_field"]]
        else:
            continue
        if not carries_bytes(carried, paths):
            continue
        span = item.get("span") or {}
        out.append({
            "file": span.get("filename", ""),
            "line": (span.get("begin") or [0])[0],
            "parent": parent.get(iid, ""),
            "name": item.get("name", ""),
        })
    return out


def check(doc: dict, table: dict, os_name: str) -> tuple[list[str], int, int]:
    found = boundary_items(doc)
    entries = table.get("item", [])
    listed = {}
    problems = []
    for e in entries:
        key = (e.get("file"), e.get("parent", ""), e.get("name"))
        if key in listed:
            problems.append(f"{key}: listed twice")
        listed[key] = e
    seen = set()
    for f in sorted(found, key=lambda f: (f["file"], f["line"], f["name"])):
        key = (f["file"], f["parent"], f["name"])
        if key in seen:
            continue
        seen.add(key)
        e = listed.get(key)
        where = f"{f['file']}:{f['line']} {f['parent'] + '::' if f['parent'] else ''}{f['name']}"
        if e is None:
            problems.append(f"{where}: a byte boundary not in scripts/law_boundary_table.toml")
        elif not str(e.get("reason", "")).strip() or not str(e.get("class", "")).strip():
            problems.append(f"{where}: table entry without a class and a reason")
        elif e.get("os") and e["os"] != os_name:
            problems.append(f"{where}: listed for os {e['os']!r} but found when scanning {os_name!r}")
    for key in sorted(set(listed) - seen):
        e = listed[key]
        if e.get("os") and e["os"] != os_name:
            continue
        problems.append(f"{key[0]} {key[1]} {key[2]}: listed in the table but not found (remove it)")
    return problems, len(seen), len(entries)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True, help="rustdoc JSON of the library")
    ap.add_argument("--os", default=HOST_OS, choices=("linux", "macos", "windows"),
                    help="the platform the JSON was built for (default: this machine's)")
    args = ap.parse_args(argv)
    doc = json.loads(Path(args.json).read_text(encoding="utf-8"))
    table = tomllib.loads(TABLE.read_text(encoding="utf-8"))
    problems, n_found, n_listed = check(doc, table, args.os)
    if n_found == 0 or n_listed == 0:
        problems.append(f"compared nothing ({n_found} items found, {n_listed} table entries)")
    for p in problems:
        print(f"error: {p}")
    print(f"law_boundary_scan: {n_found} byte-boundary items ({args.os}), {n_listed} table entries, "
          f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
