#!/usr/bin/env python3
"""Tests for scripts/key_generate_ban_check.py (the parts that do not run clippy)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import key_generate_ban_check as k  # noqa: E402

ALLOW = ('#[allow(\n    clippy::disallowed_methods,\n    reason = "the one key generation"\n)]\n')
FN = "pub(crate) fn fresh_key() -> Result<Key, KeyProviderError> {\n    Key::generate()\n}\n"


def diag(code: str, text: str, file: str = "src/lib.rs", line: int = 9) -> str:
    return json.dumps({"reason": "compiler-message", "message": {
        "code": {"code": code}, "message": text,
        "spans": [{"is_primary": True, "file_name": file, "line_start": line}]}})


NAMED = diag("clippy::disallowed_methods", "use of a disallowed method `alice_crypto::Key::generate`")


class Strip(unittest.TestCase):
    def test_the_allow_above_fresh_key_is_removed(self):
        out, n = k.strip_allow("// a\n" + ALLOW + FN)
        self.assertEqual(n, 1)
        self.assertEqual(out, "// a\n" + FN)

    def test_an_allow_above_another_function_is_kept(self):
        src = ALLOW + "pub(crate) fn other() {}\n" + FN
        out, n = k.strip_allow(src)
        self.assertEqual((out, n), (src, 0))

    def test_a_missing_allow_compares_nothing(self):
        _, n = k.strip_allow(FN)
        self.assertEqual(n, 0)
        self.assertIn("compared nothing", k.judge(n, 0, [], [("src/lib.rs", 1)])[0])

    def test_two_allows_compare_nothing(self):
        self.assertTrue(k.judge(2, 0, [], [("src/lib.rs", 1)]))


class Diagnostics(unittest.TestCase):
    def test_only_the_named_disallowed_method_counts(self):
        out = "\n".join([
            NAMED,
            diag("clippy::disallowed_methods", "use of a disallowed method `std::time::Instant::now`"),
            diag("clippy::disallowed_types", "use of a disallowed type `alice_crypto::Key::generate`"),
            '{"reason": "build-finished", "success": false}',
            "not json",
        ])
        self.assertEqual(k.named_diagnostics(out), [("src/lib.rs", 9)])


class Judge(unittest.TestCase):
    def test_one_diagnostic_in_lib_and_a_clean_control_pass(self):
        self.assertEqual(k.judge(1, 0, [], [("src/lib.rs", 9)]), [])

    def test_no_diagnostic_with_the_allow_removed_is_red(self):
        self.assertTrue(k.judge(1, 0, [], []))

    def test_two_diagnostics_with_the_allow_removed_are_red(self):
        self.assertTrue(k.judge(1, 0, [], [("src/lib.rs", 9), ("src/desktop.rs", 4)]))

    def test_a_diagnostic_outside_lib_is_red(self):
        self.assertTrue(k.judge(1, 0, [], [("src/desktop.rs", 4)]))

    def test_a_control_that_fails_clippy_is_red(self):
        self.assertTrue(k.judge(1, 101, [], [("src/lib.rs", 9)]))

    def test_a_control_with_the_diagnostic_is_red(self):
        self.assertTrue(k.judge(1, 0, [("src/desktop.rs", 4)], [("src/lib.rs", 9)]))


class RealSource(unittest.TestCase):
    def test_the_crate_has_exactly_one_allow_to_remove(self):
        lib = (k.ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertEqual(k.strip_allow(lib)[1], 1)


if __name__ == "__main__":
    unittest.main()
