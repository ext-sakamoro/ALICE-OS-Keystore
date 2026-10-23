#!/usr/bin/env python3
"""Package this crate against a local registry of its pinned ALICE siblings.

`cargo package` resolves every dependency from a registry. The ALICE siblings this crate
depends on by path are not published at the versions the repository requires (the
crates.io releases are frozen; versions are kept consistent inside the repositories, by
path and by the commits `.github/alice-siblings` pins). So instead of crates.io, the
`alice-*` crates come from a registry built here, on a file:// index, out of exactly the
pinned commits; every other crate still comes from crates.io.

Siblings are taken two ways: a private sibling by path (its commit pinned in `.github/alice-siblings`),
a public one by git (`git = "https://github.com/ext-sakamoro/<Repo>"`, a 40-hex `rev`: the rev is the pin).

Steps:
- the `alice-*` path and git dependencies of this crate are read from `cargo metadata`; none is a
  failure (there is nothing to check); each path one must have a line in `.github/alice-siblings`
  (the file is needed only when there is one), each git one must be pinned by a 40-hex rev on the
  public repository's https URL (a branch, a tag or a short rev is a usage error);
- each sibling is fetched at its commit (the checked-out HEAD must be that commit)
  and packaged with `cargo package`; its own `alice-*` path dependencies must be pinned in
  the same file and are packaged first, into the same registry (none falls through to
  crates.io); the index entry is read from the packaged manifest, its checksum is the
  sha256 of the `.crate`; one crate wanted at two commits (by git and git, or by git and a
  different pin) is a failure naming both (the registry holds one version of it), the same
  commit wanted twice is registered once;
- the committed tree (HEAD) is copied beside the fetched siblings and packaged with the
  registry and a `[patch.crates-io]` entry per `alice-*` crate (dotted `--config` keys);
- every `alice-*` package in the packaged Cargo.lock must come from the local registry with
  the checksum of the `.crate` built here, and the count must equal the crates registered;
- the packaged crate is extracted and built on its own (`cargo check --all-features --locked`).

The registry lives in /tmp/alice-local-registry/<this repository's directory name>, the same
absolute path on every machine (a link, another user's or a group / world writable directory
there, or one not made by this script, is refused): the
packaged lock of a sibling with its own alice-* dependency records the registry's URL, so the
`.crate` checksums are the same on every machine for the same pins.

cargo prints "patch ... was not used in the crate graph" while packaging (the workspace
graph uses the path dependency); that is expected and only the lock assertion decides.

One line per registered crate: `alice-local: <name> <version> <Repo>@<sha> cksum <sha256>`.
Exit 1 on a failed check, 2 when it cannot know what to check (no `alice-*` dependency,
a missing or malformed pin).

usage: scripts/alice_local_registry.py [--sibling-src <Repo>=<dir> ...]
  --sibling-src uses a local git checkout (at the pinned commit) instead of fetching
  https://github.com/ext-sakamoro/<Repo>
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

PIN = ".github/alice-siblings"
CRATES_IO = "https://github.com/rust-lang/crates.io-index"
REGISTRY = "alice-local"
BASE = Path("/tmp/alice-local-registry")
MARKER = ".alice-local-registry"
SHA = re.compile(r"^[0-9a-f]{40}$")


class Usage(Exception):
    """Cannot know what to check (exit 2)."""


class Failed(Exception):
    """A check failed (exit 1)."""


def run(cmd: list, cwd: Path, env: dict | None = None) -> str:
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True, env=env)
    if p.returncode != 0:
        raise Failed(f"{' '.join(str(c) for c in cmd)} (in {cwd}) exited {p.returncode}:\n{p.stdout}{p.stderr}")
    return p.stdout


def owned_private_dir(path: Path) -> None:
    """refuse a link, a non-directory, another user's directory, or one others can write to"""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise Usage(f"{path} is not a directory (a link or a file): remove it first")
    if st.st_uid != os.getuid():
        raise Usage(f"{path} belongs to uid {st.st_uid}, not this user ({os.getuid()}): remove it first")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Usage(f"{path} is writable by others (mode {stat.S_IMODE(st.st_mode):o}): remove it first")


def read_pins(root: Path) -> dict[str, str]:
    path = root / PIN
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise Usage(f"{PIN}: cannot read ({e.strerror})") from None
    pins = {}
    for n, line in enumerate(text.splitlines(), 1):
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if len(f) != 2 or not SHA.match(f[1]):
            raise Usage(f"{PIN}:{n}: needs '<Repo> <40 hex>', got {line!r}")
        pins[f[0]] = f[1]
    return pins


def alice_path_deps(manifest_dir: Path) -> dict[str, str]:
    """{crate name: sibling repository name} of the `alice-*` path dependencies"""
    meta = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"], manifest_dir))
    pkg = next(p for p in meta["packages"] if Path(p["manifest_path"]).parent.resolve() == manifest_dir.resolve())
    deps = {}
    for d in pkg["dependencies"]:
        if d["name"].startswith("alice-") and d.get("path"):
            deps[d["name"]] = Path(d["path"]).name
    return deps


GIT_SOURCE = re.compile(r"^git\+(https://github\.com/ext-sakamoro/([A-Za-z0-9_.-]+?)(?:\.git)?/?)\?(\w+)=([^#]+)")


def alice_git_deps(manifest_dir: Path) -> dict[str, tuple[str, str, str]]:
    """{crate name: (sibling repository name, its https URL, the 40-hex rev)} of the `alice-*` git dependencies; a git
    dependency that is not pinned by a full rev on the public repository's https URL is a usage error (its commit
    is not fixed, so nothing reproducible can be packaged)"""
    meta = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"], manifest_dir))
    pkg = next(p for p in meta["packages"] if Path(p["manifest_path"]).parent.resolve() == manifest_dir.resolve())
    deps = {}
    for d in pkg["dependencies"]:
        src = d.get("source") or ""
        if not d["name"].startswith("alice-") or not src.startswith("git+"):
            continue
        m = GIT_SOURCE.match(src)
        if not m or m.group(3) != "rev" or not SHA.match(m.group(4)):
            raise Usage(f"{d['name']} (git {src.removeprefix('git+')}) is not pinned by a 40-hex rev on "
                        "https://github.com/ext-sakamoro/<Repo>")
        deps[d["name"]] = (m.group(2), m.group(1), m.group(4))
    return deps


def fetch(repo: str, sha: str, dest: Path, sources: dict[str, Path]) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    if repo in sources:
        run(["git", "clone", "-q", "--no-checkout", sources[repo], dest], dest.parent, env)
        run(["git", "checkout", "-q", "--detach", sha], dest, env)
    else:
        dest.mkdir()
        run(["git", "init", "-q"], dest, env)
        run(["git", "fetch", "-q", "--depth", "1", f"https://github.com/ext-sakamoro/{repo}", sha], dest, env)
        run(["git", "checkout", "-q", "FETCH_HEAD"], dest, env)
    head = run(["git", "rev-parse", "HEAD"], dest, env).strip()
    if head != sha:
        raise Failed(f"{repo}: checked out {head}, pinned {sha}")


def cargo_config(index: Path, registered: dict[str, str]) -> list[str]:
    # a git dependency needs no patch of its own: `cargo package` locks the packaged (normalized) manifest, where the
    # git source is gone and only the version requirement is left, which the crates-io patch below resolves
    args = ["--config", f'registries.{REGISTRY}.index="{index.as_uri()}"']
    for name, version in sorted(registered.items()):
        args += ["--config", f'patch.crates-io.{name}.version="={version}"',
                 "--config", f'patch.crates-io.{name}.registry="{REGISTRY}"']
    return args


def index_path(index: Path, name: str) -> Path:
    n = name.lower()
    if len(n) <= 2:
        return index / str(len(n)) / n
    if len(n) == 3:
        return index / "3" / n[0] / n
    return index / n[:2] / n[2:4] / n


def commit_index(index: Path) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    if not (index / ".git").exists():
        run(["git", "init", "-q"], index, env)
    run(["git", "add", "-A"], index, env)
    run(["git", "-c", "user.name=r", "-c", "user.email=r@r.invalid", "commit", "-q", "--allow-empty", "-m", "i"],
        index, env)


def package(src: Path, target: Path, config: list[str]) -> Path:
    shutil.rmtree(target / "package", ignore_errors=True)
    run(["cargo", "package", "--no-verify", "--allow-dirty", "--target-dir", target, *config], src)
    crates = sorted((target / "package").glob("*.crate"))
    if len(crates) != 1:
        raise Failed(f"{src}: cargo package wrote {len(crates)} .crate file(s), want 1")
    return crates[0]


def extract(crate: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(crate) as t:
        t.extractall(dest, filter="data")
    return next(p for p in dest.iterdir() if p.is_dir())


def index_entry(pkgdir: Path, cksum: str) -> dict:
    """the registry index line of a packaged crate, from its packaged (normalized) manifest"""
    meta = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"], pkgdir))
    pkg = meta["packages"][0]
    deps = []
    for d in pkg["dependencies"]:
        e = {"name": d["rename"] or d["name"], "req": d["req"], "features": d["features"],
             "optional": d["optional"], "default_features": d["uses_default_features"],
             "target": d["target"], "kind": d["kind"] or "normal", "registry": d.get("registry") or CRATES_IO}
        if d["rename"]:
            e["package"] = d["name"]
        deps.append(e)
    return {"name": pkg["name"], "vers": pkg["version"], "deps": deps, "cksum": cksum,
            "features": pkg["features"], "yanked": False, "links": pkg.get("links")}


def lock_problems(lock_text: str, registry_uri: str, expected: dict[str, str]) -> list[str]:
    """every `alice-*` package of a packaged Cargo.lock must come from the local registry with the
    checksum of the `.crate` built here ({name: cksum}); returns what is wrong"""
    lock = tomllib.loads(lock_text)
    problems, seen = [], set()
    for p in lock.get("package", []):
        name = p["name"]
        if not name.startswith("alice-") or "source" not in p:
            continue  # the packaged crate itself has no source
        seen.add(name)
        if p["source"] != f"registry+{registry_uri}":
            problems.append(f"{name} {p['version']} comes from {p['source']}, not the local registry "
                            f"(add its repository to {PIN})")
        elif p.get("checksum") != expected.get(name):
            problems.append(f"{name} {p['version']} checksum {p.get('checksum')} is not the .crate built here "
                            f"({expected.get(name)})")
    for name in sorted(set(expected) - seen):
        problems.append(f"{name} was registered but is not in the packaged Cargo.lock")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sibling-src", action="append", default=[], metavar="REPO=DIR")
    args = ap.parse_args(argv)
    sources = {}
    for s in args.sibling_src:
        repo, _, d = s.partition("=")
        sources[repo] = Path(d).resolve()

    root = Path(run(["git", "rev-parse", "--show-toplevel"], Path.cwd()).strip())
    direct = alice_path_deps(root)
    direct_git = alice_git_deps(root)
    if not direct and not direct_git:
        raise Usage("no alice-* path dependency and no alice-* git dependency in Cargo.toml: nothing to package "
                    "against the local registry")
    # the pin file holds the commits of the path siblings; a crate that takes its siblings by git rev needs none
    pins = read_pins(root) if direct or (root / PIN).exists() else {}

    # one fixed absolute directory, the same on every machine: the packaged Cargo.lock of a
    # sibling that depends on another alice-* crate records the registry's file:// URL, so the
    # .crate (and its checksum) is the same everywhere only while that URL is (the path is not
    # resolved: on macOS /tmp is a link to /private/tmp, the URL keeps /tmp)
    # /tmp is shared: the directories must be real directories this user owns, not links,
    # and nobody else may write into them (the .crate files and the index are trusted below)
    try:
        BASE.mkdir(mode=0o700)
    except FileExistsError:
        pass
    owned_private_dir(BASE)
    try:
        fd = os.open(BASE / f"{root.name}.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise Usage(f"{BASE / (root.name + '.lock')}: cannot open without following a link ({e.strerror})") from None
    lock_file = os.fdopen(fd, "w")
    fcntl.flock(lock_file, fcntl.LOCK_EX)
    tmp = BASE / root.name
    if os.path.lexists(tmp):
        try:
            owned_private_dir(tmp)
        except Usage:
            lock_file.close()
            raise
        if not (tmp / MARKER).is_file():
            lock_file.close()
            raise Usage(f"{tmp} exists and was not made by this script (no {MARKER}): remove it first")
        shutil.rmtree(tmp)
    tmp.mkdir(mode=0o700)
    (tmp / MARKER).write_text("made by scripts/alice_local_registry.py\n")
    try:
        reg, index, layout, target = tmp / "registry", tmp / "registry" / "index", tmp / "layout", tmp / "target"
        (reg / "crates").mkdir(parents=True)
        index.mkdir()
        (index / "config.json").write_text(json.dumps({"dl": f"{(reg / 'crates').as_uri()}/{{crate}}-{{version}}.crate"}))
        commit_index(index)
        layout.mkdir()

        registered: dict[str, str] = {}   # name -> version
        cksums: dict[str, str] = {}       # name -> sha256
        wanted: dict[str, tuple[str, str, str]] = {}  # name -> (repo, commit, who wanted it first)
        visiting: list[str] = []

        def register(name: str, repo: str, wanted_by: str, rev: str | None = None) -> None:
            """`rev` for a sibling taken by git (the rev is the pin), None for a path sibling (pinned in the pin
            file)"""
            if name in registered:
                # one registry holds one version of a crate: a second requester at another commit would be checked
                # against a commit it does not declare. A path sibling with no pin line takes the registered commit
                first_repo, first_sha, first_by = wanted[name]
                sha = rev or pins.get(repo)
                if sha is not None and (repo, sha) != (first_repo, first_sha):
                    raise Failed(f"{name} is wanted at two commits: {first_repo}@{first_sha} by {first_by} and "
                                 f"{repo}@{sha} by {wanted_by} (one local registry holds one {name}: pin both to "
                                 "the same commit)")
                return
            if repo in visiting:
                raise Failed(f"cycle of alice-* dependencies: {' -> '.join(visiting + [repo])}")
            if rev is None and repo not in pins:
                raise Usage(f"{name} (path ../{repo}, needed by {wanted_by}) has no line in {PIN}")
            sha = rev or pins[repo]
            visiting.append(repo)
            dest = layout / repo
            if not dest.exists():
                fetch(repo, sha, dest, sources)
            for dep, (dep_repo, _, dep_rev) in sorted(alice_git_deps(dest).items()):
                register(dep, dep_repo, repo, dep_rev)
            for dep, dep_repo in sorted(alice_path_deps(dest).items()):
                register(dep, dep_repo, repo)
            crate = package(dest, target, cargo_config(index, registered))
            cksum = hashlib.sha256(crate.read_bytes()).hexdigest()
            entry = index_entry(extract(crate, tmp / "extract" / repo), cksum)
            if entry["name"] != name:
                raise Failed(f"../{repo} packages {entry['name']}, the path dependency names {name}")
            shutil.copy(crate, reg / "crates" / f"{entry['name']}-{entry['vers']}.crate")
            ip = index_path(index, entry["name"])
            ip.parent.mkdir(parents=True, exist_ok=True)
            ip.write_text(json.dumps(entry, separators=(",", ":")) + "\n")
            commit_index(index)
            registered[name], cksums[name] = entry["vers"], cksum
            wanted[name] = (repo, sha, wanted_by)
            print(f"alice-local: {name} {entry['vers']} {repo}@{sha} cksum {cksum}")
            visiting.pop()

        # the git siblings first: a path sibling that names the same crate by path takes the commit this crate pins
        for name, (repo, _, rev) in sorted(direct_git.items()):
            register(name, repo, "this crate", rev)
        for name, repo in sorted(direct.items()):
            register(name, repo, "this crate")

        me = layout / root.name
        me.mkdir()
        archive = subprocess.run(["git", "archive", "HEAD"], cwd=root, capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", me], input=archive, check=True)
        config = cargo_config(index, registered)
        crate = package(me, target, config)
        pkgdir = extract(crate, tmp / "extract" / root.name)
        problems = lock_problems((pkgdir / "Cargo.lock").read_text(encoding="utf-8"), index.as_uri(), cksums)
        if problems:
            raise Failed("packaged Cargo.lock:\n  " + "\n  ".join(problems))
        with (pkgdir / "Cargo.toml").open("a", encoding="utf-8") as f:
            f.write("\n[workspace]\n")
        run(["cargo", "check", "--all-features", "--locked", "--target-dir", target, *config], pkgdir)
        print(f"package integrity: {crate.name} packaged and built on its own, "
              f"{len(registered)} alice-* crate(s) from the local registry")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        lock_file.close()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Usage as e:
        print(f"alice_local_registry: {e}", file=sys.stderr)
        sys.exit(2)
    except Failed as e:
        print(f"alice_local_registry: {e}", file=sys.stderr)
        sys.exit(1)
