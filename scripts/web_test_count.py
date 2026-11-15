#!/usr/bin/env python3
"""Fail the browser lanes when they test nothing.

wasm-bindgen-test (one log per browser): `test result: ok. N passed` must say N > 0 in
every log, and no log may report a failure. Playwright (`--reporter=json`): every
project (chromium, firefox, webkit) must have passed at least one test and failed none.

  python3 scripts/web_test_count.py --wasm chrome.log firefox.log
  python3 scripts/web_test_count.py --playwright web-report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RESULT = re.compile(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed")
PROJECTS = ("chromium", "firefox", "webkit")


def wasm(logs: list[Path]) -> list[str]:
    problems = []
    for log in logs:
        found = RESULT.findall(log.read_text(encoding="utf-8", errors="replace"))
        passed = sum(int(p) for _, p, _ in found)
        failed = sum(int(f) for _, _, f in found)
        if not found:
            problems.append(f"{log}: no test result line")
        elif passed == 0:
            problems.append(f"{log}: 0 tests passed")
        if failed:
            problems.append(f"{log}: {failed} failed")
        print(f"{log}: {passed} passed, {failed} failed")
    return problems


def error_of(result: dict, limit: int = 1500) -> str:
    """the first error message of a Playwright result (its `error`, else its first `errors` entry), cut to `limit`"""
    err = result.get("error") or next(iter(result.get("errors") or []), None) or {}
    message = (err.get("message") or err.get("value") or "").strip() or "(no error message in the report)"
    return message if len(message) <= limit else message[:limit] + " [...]"


def playwright(report: Path) -> list[str]:
    data = json.loads(report.read_text(encoding="utf-8"))
    counts = {p: [0, 0] for p in PROJECTS}

    not_passed = []

    def walk(suite: dict) -> None:
        for spec in suite.get("specs", []):
            for t in spec.get("tests", []):
                project = t.get("projectName", "")
                for r in t.get("results", []):
                    if project in counts:
                        ok = r.get("status") == "passed"
                        counts[project][0 if ok else 1] += 1
                        if not ok:
                            not_passed.append((project, spec.get("title", "?"), r))
        for s in suite.get("suites", []):
            walk(s)

    for s in data.get("suites", []):
        walk(s)
    # why each one did not pass, so a failure is explained by the log (the report itself is not kept)
    for project, title, r in not_passed:
        print(f"not passed: {project}: {title}: {r.get('status', '?')} (retry {r.get('retry', 0)})")
        print("  " + error_of(r).replace("\n", "\n  "))
    problems = []
    for project, (passed, failed) in counts.items():
        print(f"{project}: {passed} passed, {failed} not passed")
        if passed == 0:
            problems.append(f"{project}: 0 tests passed")
        if failed:
            problems.append(f"{project}: {failed} not passed")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", nargs="+", type=Path, default=[])
    ap.add_argument("--playwright", type=Path)
    a = ap.parse_args()
    if not a.wasm and not a.playwright:
        print("web_test_count: nothing to check", file=sys.stderr)
        return 1
    problems = wasm(a.wasm) + (playwright(a.playwright) if a.playwright else [])
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
