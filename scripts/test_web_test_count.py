#!/usr/bin/env python3
"""Tests for scripts/web_test_count.py's Playwright report reading: counts per browser, a browser with no test
passed is a failure, and every result that did not pass is printed with its test and its error message (the
report is not kept, so the log is the only record of why a browser failed)."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import web_test_count as w  # noqa: E402


def report(results: dict) -> dict:
    """a Playwright JSON report with one spec, one test per browser, `results[browser]` its results"""
    return {"suites": [{"title": "reload.spec.ts", "specs": [{"title": "keys survive a reload", "tests": [
        {"projectName": p, "results": rs} for p, rs in results.items()]}]}]}


def run(data: dict) -> tuple[list[str], str]:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            problems = w.playwright(path)
    return problems, out.getvalue()


PASS = {"status": "passed"}


class Playwright(unittest.TestCase):
    def test_all_passed_is_no_problem(self):
        problems, out = run(report({p: [PASS] for p in w.PROJECTS}))
        self.assertEqual(problems, [])
        self.assertNotIn("not passed:", out)

    def test_a_failure_prints_its_test_and_error(self):
        failed = {"status": "timedOut", "retry": 0,
                  "error": {"message": "Timeout 30000ms exceeded.\nwaiting for locator('#sealed')"}}
        problems, out = run(report({**{p: [PASS] for p in w.PROJECTS}, "webkit": [failed]}))
        self.assertIn("webkit: 0 tests passed", problems)
        self.assertIn("webkit: 1 not passed", problems)
        self.assertIn("not passed: webkit: keys survive a reload: timedOut (retry 0)", out)
        self.assertIn("Timeout 30000ms exceeded.", out)
        self.assertIn("waiting for locator('#sealed')", out)

    def test_an_error_only_in_errors_is_printed(self):
        failed = {"status": "failed", "errors": [{"message": "page crashed"}]}
        _, out = run(report({**{p: [PASS] for p in w.PROJECTS}, "firefox": [failed]}))
        self.assertIn("page crashed", out)

    def test_a_failure_without_a_message_says_so(self):
        _, out = run(report({**{p: [PASS] for p in w.PROJECTS}, "chromium": [{"status": "interrupted"}]}))
        self.assertIn("(no error message in the report)", out)

    def test_a_long_message_is_cut(self):
        self.assertTrue(w.error_of({"error": {"message": "x" * 5000}}, limit=100).endswith(" [...]"))


if __name__ == "__main__":
    unittest.main()
