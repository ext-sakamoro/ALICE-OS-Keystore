"""Tests of scripts/law_boundary_scan.py on synthetic rustdoc JSON"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import law_boundary_scan as lb  # noqa: E402

U8 = {"primitive": "u8"}
U64 = {"primitive": "u64"}
SLICE = {"borrowed_ref": {"type": {"slice": U8}}}
KEY = {"resolved_path": {"path": "Key", "id": 900, "args": None}}
OTHER = {"resolved_path": {"path": "Key", "id": 901, "args": None}}
PATHS = {"900": {"crate_id": 1, "path": ["alice_crypto", "Key"]},
         "901": {"crate_id": 2, "path": ["other", "Key"]}}


def fn(name, inputs, output, file="src/lib.rs", vis="public", line=1):
    return {"crate_id": 0, "visibility": vis, "name": name,
            "span": {"filename": file, "begin": [line, 0]},
            "inner": {"function": {"sig": {"inputs": [["x", t] for t in inputs], "output": output}}}}


def impl(items, for_, trait=None):
    return {"crate_id": 0, "visibility": "default", "name": None,
            "inner": {"impl": {"trait": {"path": trait} if trait else None,
                               "for": {"resolved_path": {"path": for_, "id": 1}}, "items": items}}}


def doc(items):
    return {"index": {str(i): it for i, it in items.items()}, "paths": PATHS}


def table(*entries):
    return {"item": [dict({"file": "src/lib.rs", "parent": "", "class": "c", "reason": "r"}, **e) for e in entries]}


class Scan(unittest.TestCase):
    def test_a_listed_function_passes(self):
        d = doc({1: fn("seal", [SLICE], None)})
        self.assertEqual(lb.check(d, table({"name": "seal"}), "linux"), ([], 1, 1))

    def test_an_unlisted_boundary_and_a_stale_entry_fail(self):
        d = doc({1: fn("seal", [SLICE], None)})
        problems, _, _ = lb.check(d, table({"name": "open"}), "linux")
        self.assertTrue(any("not in scripts/law_boundary_table.toml" in p for p in problems))
        self.assertTrue(any("listed in the table but not found" in p for p in problems))

    def test_an_alice_crypto_key_is_a_byte_boundary_and_another_crates_key_is_not(self):
        d = doc({1: fn("current", [], KEY), 2: fn("other", [], OTHER)})
        self.assertEqual([f["name"] for f in lb.boundary_items(d)], ["current"])

    def test_a_trait_impl_method_is_keyed_by_its_impl(self):
        d = doc({1: fn("current", [], KEY, vis="default"), 2: impl([1], "Vault", "KeyProvider")})
        self.assertEqual(lb.boundary_items(d)[0]["parent"], "KeyProvider for Vault")
        self.assertEqual(lb.check(d, table({"parent": "KeyProvider for Vault", "name": "current"}), "linux")[0], [])

    def test_a_default_visibility_function_without_a_parent_is_skipped(self):
        d = doc({1: fn("current", [], KEY, vis="default")})
        self.assertEqual(lb.boundary_items(d), [])

    def test_a_public_struct_field_carrying_bytes_is_a_boundary(self):
        field = {"crate_id": 0, "visibility": "public", "name": "key", "span": {"filename": "src/ffi.rs"},
                 "inner": {"struct_field": {"resolved_path": {"path": "Vec", "id": 5,
                                                             "args": {"angle_bracketed": {"args": [{"type": U8}]}}}}}}
        st = {"crate_id": 0, "visibility": "public", "name": "Record",
              "inner": {"struct": {"kind": {"plain": {"fields": [1]}}}}}
        d = doc({1: field, 2: st})
        self.assertEqual([(f["parent"], f["name"]) for f in lb.boundary_items(d)], [("Record", "key")])

    def test_functions_without_bytes_are_not_boundaries(self):
        self.assertEqual(lb.boundary_items(doc({1: fn("count", [U64], U64)})), [])

    def test_an_os_entry_is_not_stale_on_another_platform(self):
        d = doc({1: fn("seal", [SLICE], None)})
        t = table({"name": "seal"}, {"name": "keychain", "os": "macos"})
        self.assertEqual(lb.check(d, t, "linux")[0], [])
        self.assertTrue(any("not found" in p for p in lb.check(d, t, "macos")[0]))

    def test_an_os_entry_found_on_another_platform_fails(self):
        d = doc({1: fn("keychain", [SLICE], None)})
        problems, _, _ = lb.check(d, table({"name": "keychain", "os": "macos"}), "linux")
        self.assertTrue(any("listed for os 'macos'" in p for p in problems))

    def test_an_entry_without_a_reason_fails(self):
        d = doc({1: fn("seal", [SLICE], None)})
        problems, _, _ = lb.check(d, table({"name": "seal", "reason": " "}), "linux")
        self.assertTrue(any("without a class and a reason" in p for p in problems))

    def test_an_entry_listed_twice_fails(self):
        d = doc({1: fn("seal", [SLICE], None)})
        problems, _, _ = lb.check(d, table({"name": "seal"}, {"name": "seal"}), "linux")
        self.assertTrue(any("listed twice" in p for p in problems))

    def test_scanning_nothing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            j = Path(tmp) / "doc.json"
            j.write_text(json.dumps(doc({1: fn("count", [U64], U64)})), encoding="utf-8")
            t = Path(tmp) / "table.toml"
            t.write_text("", encoding="utf-8")
            with mock.patch.object(lb, "TABLE", t), redirect_stdout(io.StringIO()) as out:
                rc = lb.main(["--os", "linux", "--json", str(j)])
        self.assertEqual(rc, 1)
        self.assertIn("compared nothing", out.getvalue())

    def test_the_repository_table_parses_and_is_not_empty(self):
        import tomllib
        t = tomllib.loads(lb.TABLE.read_text(encoding="utf-8"))
        self.assertGreater(len(t.get("item", [])), 0)


if __name__ == "__main__":
    unittest.main()
