#!/usr/bin/env python3
"""Tests of scripts/alice_local_registry.py.

Fixture repositories in a temporary directory, built with the real cargo (no crates.io
dependency, so nothing is downloaded; cargo still reads the crates.io index for the patch):
ALICE-Fa (alice-fa 0.2.0), ALICE-Fb (alice-fb 0.3.0, depends on alice-fa by path and
"0.2"), and the crate under test ALICE-App-<unique per test> (depends on alice-fb by path; the
name is unique so its registry directory under /tmp/alice-local-registry is not shared with a
parallel run, and the test removes it afterwards). The siblings are
given with --sibling-src, so nothing is fetched from GitHub.

- with both siblings pinned it exits 0, prints one `alice-local:` line per crate (name,
  version, pinned commit, the sha256 of the .crate) and the count, and leaves the
  repository clean (it packages a copy of HEAD);
- the transitive sibling unpinned exits 2 naming it and who needs it;
- a pinned version that does not satisfy the requirement exits 1 with cargo's message;
- no alice-* path dependency, and a malformed pin, exit 2;
- a registry directory it did not make, a link, or one others can write to is refused and
  left alone;
- two runs give the same checksums (the .crate of a commit is reproducible);
- a problem the lock check reports fails the run;
- one alice-* crate wanted at two commits (by git and git, or by git and a different pin) exits 1
  naming both, and wanted twice at the same commit is registered once;
- the lock check rejects an alice-* package from crates.io (registered or not), a checksum that is not the
  .crate built here, and a registered crate missing from the lock.

Not tested: the check that the checked-out HEAD is the pinned commit; the checkout is made
by that commit (`git checkout <sha>` / fetch by SHA), so it cannot differ, and the check is
defensive.

usage: python3 scripts/test_alice_local_registry.py
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "alice_local_registry.py"
LINE = re.compile(r"^alice-local: (\S+) (\S+) (\S+)@([0-9a-f]{40}) cksum ([0-9a-f]{64})$", re.M)


def git(*args: str, cwd: Path) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                          check=True, capture_output=True, text=True, env=env).stdout.strip()


def crate(dir_: Path, name: str, version: str, deps: str = "") -> str:
    """a git repository holding one library crate; returns its HEAD"""
    (dir_ / "src").mkdir(parents=True)
    (dir_ / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2021"\n'
        f'license = "MIT"\ndescription = "fixture"\n\n[dependencies]\n{deps}')
    (dir_ / "src" / "lib.rs").write_text("pub fn f() -> u32 { 1 }\n")
    git("init", "-q", "-b", "main", cwd=dir_)
    git("add", "-A", cwd=dir_)
    git("commit", "-q", "-m", "c", cwd=dir_)
    return git("rev-parse", "HEAD", cwd=dir_)


def load_script():
    spec = importlib.util.spec_from_file_location("alice_local_registry", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LocalRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alice-local-registry-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fa = crate(self.tmp / "ALICE-Fa", "alice-fa", "0.2.0")
        self.fb = crate(self.tmp / "ALICE-Fb", "alice-fb", "0.3.0",
                        'alice-fa = { path = "../ALICE-Fa", version = "0.2" }\n')
        self.app = self.tmp / f"ALICE-App-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.spot = Path("/tmp/alice-local-registry") / self.app.name
        self.addCleanup(self.clear_spot)
        self.addCleanup(lambda: Path(f"{self.spot}.lock").unlink(missing_ok=True))

    def clear_spot(self) -> None:
        if self.spot.is_symlink() or self.spot.is_file():
            self.spot.unlink()
        elif self.spot.exists():
            self.spot.chmod(0o700)
            shutil.rmtree(self.spot, ignore_errors=True)

    def make_app(self, deps: str, pins: str | None) -> None:
        crate(self.app, "alice-app", "0.1.0", deps)
        if pins is not None:
            (self.app / ".github").mkdir()
            (self.app / ".github" / "alice-siblings").write_text(pins)
        git("add", "-A", cwd=self.app)
        git("commit", "-q", "--allow-empty", "-m", "pins", cwd=self.app)

    GIT_FA = "https://github.com/ext-sakamoro/ALICE-Fa"

    def both_pins(self) -> str:
        return f"# pinned\nALICE-Fa {self.fa}\nALICE-Fb {self.fb}\n"

    def run_script(self) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["CARGO_TARGET_DIR"] = str(self.tmp / "target")
        return subprocess.run([sys.executable, str(SCRIPT), "--sibling-src", f"ALICE-Fa={self.tmp / 'ALICE-Fa'}",
                               "--sibling-src", f"ALICE-Fb={self.tmp / 'ALICE-Fb'}"], cwd=self.app,
                              capture_output=True, text=True, env=env, timeout=600)

    def test_transitive_siblings_come_from_the_local_registry(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', self.both_pins())
        p = self.run_script()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        lines = LINE.findall(p.stdout)
        self.assertEqual([(n, v, r, s) for n, v, r, s, _ in lines],
                         [("alice-fa", "0.2.0", "ALICE-Fa", self.fa), ("alice-fb", "0.3.0", "ALICE-Fb", self.fb)])
        self.assertIn("2 alice-* crate(s) from the local registry", p.stdout)
        self.assertEqual(git("status", "--porcelain", cwd=self.app), "")

    def test_two_runs_give_the_same_checksums(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', self.both_pins())
        a, b = self.run_script(), self.run_script()
        self.assertEqual((a.returncode, b.returncode), (0, 0), a.stderr + b.stderr)
        self.assertEqual([x[4] for x in LINE.findall(a.stdout)], [x[4] for x in LINE.findall(b.stdout)])
        self.assertEqual(len(LINE.findall(a.stdout)), 2)

    def test_an_unpinned_transitive_sibling_exits_2_naming_it(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', f"ALICE-Fb {self.fb}\n")
        p = self.run_script()
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("alice-fa (path ../ALICE-Fa, needed by ALICE-Fb) has no line in .github/alice-siblings",
                      p.stderr)

    def test_a_pinned_version_that_does_not_satisfy_the_requirement_fails(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.4" }\n', self.both_pins())
        p = self.run_script()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn('failed to select a version for the requirement `alice-fb = "^0.4"`', p.stderr)

    def test_no_alice_path_dependency_exits_2(self) -> None:
        self.make_app("", self.both_pins())
        p = self.run_script()
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("no alice-* path dependency", p.stderr)

    def test_a_registry_dir_it_did_not_make_is_refused(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', self.both_pins())
        foreign = self.spot
        foreign.mkdir(parents=True)
        (foreign / "keep").write_text("not the script's\n")
        p = self.run_script()
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("was not made by this script", p.stderr)
        self.assertTrue((foreign / "keep").is_file())

    def test_a_link_or_a_shared_registry_dir_is_refused(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', self.both_pins())
        spot = self.spot
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / ".alice-local-registry").write_text("looks like ours\n")
        spot.parent.mkdir(parents=True, exist_ok=True)
        spot.symlink_to(elsewhere)
        p = self.run_script()
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("is not a directory (a link or a file)", p.stderr)
        self.assertTrue((elsewhere / ".alice-local-registry").is_file())
        self.clear_spot()
        spot.mkdir()
        (spot / ".alice-local-registry").write_text("ours\n")
        spot.chmod(0o777)
        p = self.run_script()
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("is writable by others", p.stderr)

    def test_a_lock_problem_fails_the_run(self) -> None:
        # the run must act on the lock check, not only compute it
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', self.both_pins())
        mod = load_script()
        mod.lock_problems = lambda *a: ["alice-fb comes from somewhere else"]
        cwd = Path.cwd()
        os.chdir(self.app)
        self.addCleanup(os.chdir, cwd)
        with self.assertRaises(mod.Failed) as e:
            mod.main(["--sibling-src", f"ALICE-Fa={self.tmp / 'ALICE-Fa'}",
                      "--sibling-src", f"ALICE-Fb={self.tmp / 'ALICE-Fb'}"])
        self.assertIn("alice-fb comes from somewhere else", str(e.exception))

    def test_a_git_rev_dependency_comes_from_the_local_registry_without_a_pin_file(self) -> None:
        # a public sibling taken by git: the rev is the pin (no .github/alice-siblings needed), the commit is fetched,
        # packaged and registered like a path sibling's pinned commit
        self.make_app(f'alice-fa = {{ git = "{self.GIT_FA}", rev = "{self.fa}", version = "0.2" }}\n', None)
        p = self.run_script()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual([(n, v, r, s) for n, v, r, s, _ in LINE.findall(p.stdout)],
                         [("alice-fa", "0.2.0", "ALICE-Fa", self.fa)])
        self.assertIn("1 alice-* crate(s) from the local registry", p.stdout)
        self.assertEqual(git("status", "--porcelain", cwd=self.app), "")

    def test_a_git_and_a_path_dependency_together(self):
        # the path sibling ALICE-Fb depends on alice-fa by path; alice-fa is this crate's git dependency, so it is the
        # crate registered from the rev (not looked up again in the pin file)
        self.make_app(f'alice-fa = {{ git = "{self.GIT_FA}", rev = "{self.fa}", version = "0.2" }}\n'
                      'alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', f"ALICE-Fb {self.fb}\n")
        p = self.run_script()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(sorted(n for n, *_ in LINE.findall(p.stdout)), ["alice-fa", "alice-fb"])

    def test_a_git_dependency_not_pinned_by_a_full_rev_exits_2(self):
        for pin in ('branch = "main"', f'rev = "{self.fa[:7]}"'):
            with self.subTest(pin=pin):
                shutil.rmtree(self.app, ignore_errors=True)
                self.make_app(f'alice-fa = {{ git = "{self.GIT_FA}", {pin}, version = "0.2" }}\n', None)
                p = self.run_script()
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("40-hex rev", p.stderr)

    def recommit(self, repo: str, files: dict[str, str]) -> str:
        """a new commit of a fixture sibling (the earlier commit stays fetchable); returns its HEAD"""
        d = self.tmp / repo
        for rel, text in files.items():
            (d / rel).write_text(text)
        git("commit", "-q", "-am", "next", cwd=d)
        return git("rev-parse", "HEAD", cwd=d)

    def fb_on_fa_by_git(self, rev: str) -> str:
        return self.recommit("ALICE-Fb", {"Cargo.toml": (
            '[package]\nname = "alice-fb"\nversion = "0.3.0"\nedition = "2021"\nlicense = "MIT"\n'
            f'description = "fixture"\n\n[dependencies]\nalice-fa = {{ git = "{self.GIT_FA}", rev = "{rev}", '
            'version = "0.2" }\n')})

    def test_one_crate_wanted_at_two_commits_by_git_fails_naming_both(self):
        # this crate takes alice-fa at fa by git, ALICE-Fb takes it at fa2 by git: one registry holds one alice-fa,
        # so the run fails instead of checking ALICE-Fb against a commit it does not declare
        fa2 = self.recommit("ALICE-Fa", {"src/lib.rs": "pub fn f() -> u32 { 2 }\n"})
        fb2 = self.fb_on_fa_by_git(fa2)
        self.make_app(f'alice-fa = {{ git = "{self.GIT_FA}", rev = "{self.fa}", version = "0.2" }}\n'
                      'alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', f"ALICE-Fb {fb2}\n")
        p = self.run_script()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn(f"alice-fa is wanted at two commits: ALICE-Fa@{self.fa} by this crate and ALICE-Fa@{fa2} "
                      "by ALICE-Fb", p.stderr)

    def test_one_crate_wanted_by_git_and_by_a_different_pin_fails_naming_both(self):
        # this crate takes alice-fa at fa by git; the pin file pins ALICE-Fa (needed by ALICE-Fb by path) at fa2
        fa2 = self.recommit("ALICE-Fa", {"src/lib.rs": "pub fn f() -> u32 { 2 }\n"})
        self.make_app(f'alice-fa = {{ git = "{self.GIT_FA}", rev = "{self.fa}", version = "0.2" }}\n'
                      'alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n',
                      f"ALICE-Fa {fa2}\nALICE-Fb {self.fb}\n")
        p = self.run_script()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn(f"alice-fa is wanted at two commits: ALICE-Fa@{self.fa} by this crate and ALICE-Fa@{fa2} "
                      "by ALICE-Fb", p.stderr)

    def test_one_crate_wanted_twice_at_the_same_commit_is_registered_once(self):
        # by git twice, and by git and by an equal pin: the same commit, one registration
        fb2 = self.fb_on_fa_by_git(self.fa)
        for pins in (f"ALICE-Fb {fb2}\n", f"ALICE-Fa {self.fa}\nALICE-Fb {self.fb}\n"):
            with self.subTest(pins=pins):
                shutil.rmtree(self.app, ignore_errors=True)
                self.clear_spot()
                self.make_app(f'alice-fa = {{ git = "{self.GIT_FA}", rev = "{self.fa}", version = "0.2" }}\n'
                              'alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', pins)
                p = self.run_script()
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(sorted((n, s) for n, _, _, s, _ in LINE.findall(p.stdout) if n == "alice-fa"),
                                 [("alice-fa", self.fa)])

    def test_a_malformed_pin_exits_2(self) -> None:
        self.make_app('alice-fb = { path = "../ALICE-Fb", version = "0.3" }\n', "ALICE-Fb abc\n")
        p = self.run_script()
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("needs '<Repo> <40 hex>'", p.stderr)


class LockCheck(unittest.TestCase):
    URI = "file:///reg/index"
    GOOD = ('[[package]]\nname = "alice-app"\nversion = "0.1.0"\n\n'
            '[[package]]\nname = "alice-fb"\nversion = "0.3.0"\n'
            'source = "registry+file:///reg/index"\nchecksum = "' + "a" * 64 + '"\n')

    def setUp(self) -> None:
        self.mod = load_script()

    def test_a_lock_from_the_local_registry_passes(self) -> None:
        self.assertEqual(self.mod.lock_problems(self.GOOD, self.URI, {"alice-fb": "a" * 64}), [])

    def test_an_alice_package_from_crates_io_is_refused(self) -> None:
        lock = self.GOOD.replace("registry+file:///reg/index",
                                 "registry+https://github.com/rust-lang/crates.io-index")
        problems = self.mod.lock_problems(lock, self.URI, {"alice-fb": "a" * 64})
        self.assertEqual(len(problems), 1)
        self.assertIn("not the local registry", problems[0])

    def test_a_checksum_that_is_not_the_crate_built_here_is_refused(self) -> None:
        problems = self.mod.lock_problems(self.GOOD, self.URI, {"alice-fb": "b" * 64})
        self.assertEqual(len(problems), 1)
        self.assertIn("is not the .crate built here", problems[0])

    def test_an_unregistered_alice_package_from_crates_io_is_refused(self) -> None:
        # every alice-* package of the lock is checked, not only the registered ones
        lock = self.GOOD + ('\n[[package]]\nname = "alice-zz"\nversion = "1.0.0"\n'
                            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                            'checksum = "' + "d" * 64 + '"\n')
        problems = self.mod.lock_problems(lock, self.URI, {"alice-fb": "a" * 64})
        self.assertEqual(len(problems), 1)
        self.assertIn("alice-zz 1.0.0 comes from registry+https://github.com/rust-lang/crates.io-index", problems[0])

    def test_a_registered_crate_missing_from_the_lock_is_refused(self) -> None:
        problems = self.mod.lock_problems(self.GOOD, self.URI, {"alice-fb": "a" * 64, "alice-fa": "c" * 64})
        self.assertEqual(problems, ["alice-fa was registered but is not in the packaged Cargo.lock"])


if __name__ == "__main__":
    unittest.main()
