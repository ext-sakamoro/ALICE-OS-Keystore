#!/usr/bin/env bash
# scripts/preflight.sh — local reproduction of the CI gates before `git push`.
# Every command is the one CI runs. A step this file does not cover is a step
# that can only fail remotely — when a workflow changes, regenerate this file
# in the same commit (checks no workflow runs go in scripts/preflight.local.sh).
# Run `--quick` before every push.
#
# usage: scripts/preflight.sh [--quick]   (--quick skips the test / bench suites)
# generator rev 6b6e5b67702f00636f3dd23b6b6691c24b1420b9
set -euo pipefail
cd "$(dirname "$0")/.."
# --- heavy slot (begin) ---
# one heavy run at a time on this machine: a lock the kernel holds (flock on $ALICE_HEAVY_SLOT_DIR/lock, default
# $HOME/.cache/alice-heavy-slot) for as long as the holder lives. A small keeper process (perl) takes it and exits
# within a second of the holder's death, so a killed holder frees the slot and no child of the holder keeps it.
# `info` only names the holder for the waiting line. A wait past ALICE_HEAVY_SLOT_TIMEOUT seconds (default 7200)
# fails; the holder's own nested runs (ALICE_HEAVY_SLOT_HELD) run inside it.
heavy_slot_dir() { printf '%s\n' "${ALICE_HEAVY_SLOT_DIR:-$HOME/.cache/alice-heavy-slot}"; }
heavy_slot_acquire() {
  local label=$1 tool=$2 d line info err limit="${ALICE_HEAVY_SLOT_TIMEOUT:-7200}"
  d=$(heavy_slot_dir)
  if [ -n "${ALICE_HEAVY_SLOT_HELD:-}" ] && [ "$(sed -n 1p "$d/info" 2>/dev/null)" = "$ALICE_HEAVY_SLOT_HELD" ] \
     && kill -0 "$ALICE_HEAVY_SLOT_HELD" 2>/dev/null; then
    return 0
  fi
  if ! err=$(mkdir -p "$d" 2>&1) || ! err=$({ : >> "$d/lock"; } 2>&1); then
    echo "heavy slot: cannot create $d: ${err:-not writable}" >&2
    return 1
  fi
  exec 8< <(exec perl -MFcntl=:flock -e '
    my ($file, $limit) = @ARGV; my $parent = getppid(); $| = 1;
    open(my $fh, ">>", $file) or do { print "error $!\n"; exit 2 };
    print "pid $$\n";
    my $t = 0;
    until (flock($fh, LOCK_EX | LOCK_NB)) {
      if ($t >= $limit) { print "timeout\n"; exit 1 }
      print "wait $t\n" if $t % 30 == 0;
      sleep 1; $t++;
      exit 3 if getppid() != $parent;
    }
    print "held\n"; close(STDOUT);
    sleep 1 while getppid() == $parent;
  ' "$d/lock" "$limit")
  while IFS= read -r line <&8; do
    case "$line" in
      "pid "*) HEAVY_SLOT_KEEPER=${line#pid } ;;
      "wait "*)
        info=$(cat "$d/info" 2>/dev/null || true)
        echo "heavy slot: waiting for $(printf '%s\n' "$info" | sed -n 3p) pid $(printf '%s\n' "$info" | sed -n 1p) ($(printf '%s\n' "$info" | sed -n 4p))" >&2
        ;;
      held)
        exec 8<&-
        printf '%s\n%s\n%s\n%s\n' "$$" "$(date +%s)" "$label" "$tool" > "$d/info"
        ALICE_HEAVY_SLOT_HELD=$$
        export ALICE_HEAVY_SLOT_HELD
        return 0
        ;;
      timeout)
        exec 8<&-
        info=$(cat "$d/info" 2>/dev/null || true)
        echo "heavy slot: waited ${limit}s for $(printf '%s\n' "$info" | sed -n 3p) pid $(printf '%s\n' "$info" | sed -n 1p); giving up (ALICE_HEAVY_SLOT_TIMEOUT=$limit)" >&2
        return 1
        ;;
      "error "*)
        exec 8<&-
        echo "heavy slot: cannot open $d/lock: ${line#error }" >&2
        return 1
        ;;
    esac
  done
  exec 8<&-
  echo "heavy slot: the lock keeper stopped (is perl on PATH?)" >&2
  return 1
}
heavy_slot_release() {
  local d
  d=$(heavy_slot_dir)
  if [ "${ALICE_HEAVY_SLOT_HELD:-}" = "$$" ] && [ -n "${HEAVY_SLOT_KEEPER:-}" ]; then
    # the info first: once the keeper is gone the next holder writes its own
    rm -f "$d/info"
    kill "$HEAVY_SLOT_KEEPER" 2>/dev/null || true
    HEAVY_SLOT_KEEPER=
  fi
}
# memory: `heavy_slot_watch <pid> &` sums the RSS of that process and its descendants about once a second
# (ALICE_HEAVY_SLOT_RSS_POLL) and past ALICE_HEAVY_SLOT_RSS_CAP_MIB (default 8192 = 8 GiB) kills the tree (itself
# aside) and prints `[heavy-slot] RSS cap <N>GiB exceeded by <pid> <cmd> (tree <M> MiB)`; it returns once the
# process is gone. A time limit does not bound memory (a test that loops while pushing fills the machine inside
# its timeout), this does. A `ps` that cannot list the tree turns the cap off with a note, not silently.
heavy_slot_cap_ok() {
  case "${ALICE_HEAVY_SLOT_RSS_CAP_MIB:-8192}" in
    '' | *[!0-9]* | 0) echo "heavy slot: ALICE_HEAVY_SLOT_RSS_CAP_MIB must be a positive integer" >&2; return 2 ;;
  esac
}
# "<pid> <rss KiB> <command>" for the process $1 and its descendants, leaving out $2 and its descendants
heavy_slot_tree() {
  ps -A -o pid=,ppid=,rss=,comm= | awk -v root="$1" -v skip="${2:-}" '
    { pid[NR] = $1; ppid[NR] = $2; rss[NR] = $3; $1 = $2 = $3 = ""; cmd[NR] = substr($0, 4) }
    END {
      in_tree[root] = 1; grew = 1
      while (grew) {
        grew = 0
        for (i = 1; i <= NR; i++)
          if (!(pid[i] in in_tree) && pid[i] != skip && (ppid[i] in in_tree)) { in_tree[pid[i]] = 1; grew = 1 }
      }
      for (i = 1; i <= NR; i++) if (pid[i] in in_tree) print pid[i], rss[i], cmd[i]
    }'
}
# whether $1 runs (a zombie has ended: a watcher started by the process it watches outlives it until reaped)
heavy_slot_alive() {
  local st
  st=$(ps -o stat= -p "$1" 2>/dev/null) || return 1
  case "$st" in '' | *Z*) return 1 ;; esac
}
heavy_slot_watch() {
  local root=$1 cap="${ALICE_HEAVY_SLOT_RSS_CAP_MIB:-8192}" poll="${ALICE_HEAVY_SLOT_RSS_POLL:-1}" self tree sum \
    top peak=0 samples=0 noted=0
  self=$(exec sh -c 'echo "$PPID"')
  if kill -0 "$root" 2>/dev/null && ! heavy_slot_alive "$root"; then
    echo "[heavy-slot] note: ps does not show pid $root here, so the memory cap is off" >&2
    return 0
  fi
  while heavy_slot_alive "$root"; do
    tree=$(heavy_slot_tree "$root" "$self" 2>/dev/null) || tree=""
    if [ -z "$tree" ]; then
      if [ "$noted" = 0 ] && heavy_slot_alive "$root"; then
        echo "[heavy-slot] note: ps does not list pid $root here, so the memory cap is off" >&2
        noted=1
      fi
    else
      sum=$(printf '%s\n' "$tree" | awk '{ s += $2 } END { printf "%d", s / 1024 }')
      samples=$((samples + 1))
      if [ "$sum" -gt "$peak" ]; then peak=$sum; fi
      if [ "$sum" -gt "$cap" ]; then
        top=$(printf '%s\n' "$tree" | sort -k2,2nr | head -1)
        # shellcheck disable=SC2046 # one pid per word
        kill -9 $(printf '%s\n' "$tree" | cut -d" " -f1) 2>/dev/null || true
        echo "[heavy-slot] RSS cap $(awk -v c="$cap" 'BEGIN { printf "%g", c / 1024 }')GiB exceeded by ${top%% *} $(printf '%s\n' "$top" | cut -d" " -f3-) (tree $sum MiB)" >&2
        return 137
      fi
    fi
    sleep "$poll"
  done
  if [ "${ALICE_HEAVY_SLOT_RSS_REPORT:-}" = 1 ]; then echo "[heavy-slot] RSS peak $peak MiB over $samples samples" >&2; fi
  return 0
}
# --- heavy slot (end) ---
heavy_slot_acquire "$(basename "$PWD")" preflight || exit 1
trap heavy_slot_release EXIT
heavy_slot_cap_ok || exit 2
heavy_slot_watch "$$" >/dev/null &

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
# `cargo clippy` reuses fresh `cargo check` artifacts and then lints nothing;
# touching the crate roots invalidates only this repo's fingerprints.
relint() { git ls-files | grep -E '(^|/)src/(lib|main)\.rs$' | xargs -r touch; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }
has_toolchain() { rustup toolchain list | grep -q "^$1"; }

# Steps CI runs that this file cannot reproduce locally (they can only fail remotely):
#   - security-audit.yml:audit:Install cargo-audit (needs network / runner-only)
#   - security-audit.yml:tools-audit:Install cargo-audit (continue-on-error, needs network / runner-only)
#   - security-audit.yml:tools-audit:Run cargo audit on the tool's lock (continue-on-error, no count guard for cargo audit)
#   - security-audit.yml:deny:Install cargo-deny (needs network / runner-only)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_foreign_key_bytes] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_foreign_key_bytes] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_foreign_key_bytes] (runner-only (open-ended or unprovable-bounded fuzz run))
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_memory_vault_ops] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_memory_vault_ops] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_memory_vault_ops] (runner-only (open-ended or unprovable-bounded fuzz run))
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_foreign_errors] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_foreign_errors] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_foreign_errors] (runner-only (open-ended or unprovable-bounded fuzz run))

need cargo-audit "cargo install cargo-audit --locked"
need cargo-deny "cargo install cargo-deny --locked"
need cargo-machete "cargo install cargo-machete --locked"

step "ci.yml / fmt: run"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; cargo fmt --all -- --check )

step "ci.yml / clippy: Clippy (default features, all targets)"
relint
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; cargo clippy --all-targets -- -D warnings -W clippy::pedantic )

step "ci.yml / clippy: Clippy (all features, all targets)"
relint
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic )

step "ci.yml / doc: run"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" RUSTDOCFLAGS="-Dwarnings"; cargo doc --no-deps --all-features )

step "ci.yml / scripts: run"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; python3 scripts/test_run_tests.py )

step "ci.yml / scripts: run"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; python3 scripts/test_unsafe_scope_check.py )

step "ci.yml / scripts: run"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; python3 scripts/unsafe_scope_check.py )

step "security-audit.yml / audit: Fetch dependencies (the guard reads the dependency tree offline)"
( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; cargo fetch --locked )

step "security-audit.yml / audit: Audit ignore guard (tests, then basic-toml)"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  python3 scripts/test_audit_ignore_guard.py
  python3 scripts/audit_ignore_guard.py basic-toml
)

step "security-audit.yml / deny: Run cargo deny check all"
( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; cargo deny --all-features check all )

step "security-audit.yml / unused-deps: cargo machete"
cargo machete

step "security-audit.yml / stub-guard: Block panic!(STUB) in src/**"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rnE 'panic!\([^)]*STUB' \
    src/ --include="*.rs" \
    --exclude-dir=bin \
    | grep -v ':[[:space:]]*//' \
    | grep -vE ':[[:space:]]*/\*' \
    || true)
  if [ -n "$hits" ]; then
    echo "❌ Explicit STUB panic detected in src/ (production path):"
    echo "$hits"
    exit 1
  fi
  echo "✓ No panic!(STUB) in src/"
)

step "security-audit.yml / stub-guard: Detect todo! / unimplemented! (informational, not blocking)"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rnE 'todo!\(|unimplemented!\(' \
    src/ --include="*.rs" \
    --exclude-dir=bin \
    | grep -v ':[[:space:]]*//' \
    | grep -vE ':[[:space:]]*/\*' \
    || true)
  if [ -n "$hits" ]; then
    count=$(echo "$hits" | wc -l | tr -d ' ')
    echo "::warning::${count} todo!()/unimplemented!() marker(s) in src/ (informational: these are the endorsed fail-fast idiom, not stubs):"
    echo "$hits" | head -20
  else
    echo "✓ No todo!/unimplemented! markers in src/"
  fi
)

step "security-audit.yml / stub-guard: Detect dbg!() residual in src/**"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rn 'dbg!(' src/ --include="*.rs" || true)
  if [ -n "$hits" ]; then
    echo "❌ dbg!() macro left in src/:"
    echo "$hits"
    exit 1
  fi
  echo "✓ No dbg!() in src/"
)

step "security-audit.yml / stub-guard: Detect TODO / FIXME / XXX / HACK (informational)"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rnE 'TODO|FIXME|XXX|HACK' src/ --include="*.rs" || true)
  if [ -n "$hits" ]; then
    echo "::warning::TODO/FIXME/XXX/HACK found in src/ (informational, not blocking):"
    echo "$hits" | head -50
  else
    echo "✓ No TODO/FIXME/XXX/HACK in src/"
  fi
)

step "security-audit.yml / package-integrity: cargo package (.crate を作る)"
( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; cargo package --no-verify --allow-dirty )

step "security-audit.yml / package-integrity: 展開して隔離 build"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -euo pipefail
  crate=$(find "${CARGO_TARGET_DIR:-target}"/package -maxdepth 1 -name '*.crate' | head -1)
  [ -n "$crate" ] || { echo "::error::.crate が生成されていない"; exit 1; }
  echo "packaged: $(basename "$crate") ($(du -h "$crate" | cut -f1))"
  tmp=$(mktemp -d)
  tar xzf "$crate" -C "$tmp"
  cd "$tmp"/*/
  # 親 workspace を継承すると member 扱いになり、境界を越えた file が
  # 再び見えてしまう (検査の意味が消える) ので単独 package として build
  printf '\n[workspace]\n' >> Cargo.toml
  cargo check --all-features
)

step "fuzz.yml / fuzz: Build fuzz target [target=fuzz_foreign_key_bytes]"
if has_toolchain nightly && cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    export CARGO_TERM_COLOR="always"
    cd fuzz
    cargo +nightly fuzz build "fuzz_foreign_key_bytes"
  )
else
  echo 'PREFLIGHT-SKIP: fuzz.yml / fuzz: Build fuzz target [target=fuzz_foreign_key_bytes]: nightly / cargo-fuzz not installed' >&2
fi

step "fuzz.yml / fuzz: Build fuzz target [target=fuzz_memory_vault_ops]"
if has_toolchain nightly && cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    export CARGO_TERM_COLOR="always"
    cd fuzz
    cargo +nightly fuzz build "fuzz_memory_vault_ops"
  )
else
  echo 'PREFLIGHT-SKIP: fuzz.yml / fuzz: Build fuzz target [target=fuzz_memory_vault_ops]: nightly / cargo-fuzz not installed' >&2
fi

step "fuzz.yml / fuzz: Build fuzz target [target=fuzz_foreign_errors]"
if has_toolchain nightly && cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    export CARGO_TERM_COLOR="always"
    cd fuzz
    cargo +nightly fuzz build "fuzz_foreign_errors"
  )
else
  echo 'PREFLIGHT-SKIP: fuzz.yml / fuzz: Build fuzz target [target=fuzz_foreign_errors]: nightly / cargo-fuzz not installed' >&2
fi

if [[ $quick -eq 1 ]]; then
  echo; echo "preflight --quick OK (test / bench suites skipped)"; exit 0
fi

step "ci.yml / test: Test (default features)"
(
  export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"
  if [ "${RUNNER_OS:-}" = Windows ]; then read_min=1; swap_min=1; else read_min=10; swap_min=5; fi
  scripts/run_tests.sh vault_oracle=10,desktop_gaps=3,read_secret="$read_min",exchange="$swap_min" -- cargo test
)

step "ci.yml / test: Test (all features)"
(
  export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"
  if [ "${RUNNER_OS:-}" = Windows ]; then read_min=1; swap_min=1; else read_min=10; swap_min=5; fi
  scripts/run_tests.sh vault_oracle=10,desktop_gaps=3,foreign_oracle=5,read_secret="$read_min",exchange="$swap_min" -- cargo test --all-features
)

step "ci.yml / apple: run"
if command -v xcodebuild >/dev/null 2>&1; then
  ( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; scripts/apple_check.sh )
else
  echo 'PREFLIGHT-SKIP: ci.yml / apple: run: xcodebuild not installed (skipped-tool)' >&2
fi

step "security-audit.yml / audit: Run cargo audit"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  cargo audit \
    --deny yanked \
    --ignore RUSTSEC-2024-0436 \
    --ignore RUSTSEC-2025-0141 \
    --ignore RUSTSEC-2026-0192 \
    --ignore RUSTSEC-2026-0204 \
    --ignore RUSTSEC-2025-0020 \
    --ignore RUSTSEC-2026-0176 \
    --ignore RUSTSEC-2026-0177 \
    --ignore RUSTSEC-2026-0374
)

step "security-audit.yml / tools-audit: Run cargo audit on the tool's lock"
echo 'PREFLIGHT-SKIP: security-audit.yml / tools-audit: Run cargo audit on the tool'"'"'s lock: continue-on-error, no count guard for cargo audit' >&2

step "security-audit.yml / coverage: Run coverage"
(
  log="$(mktemp)"
  set +e
  {
    (
      export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
      set -o pipefail
      cargo llvm-cov --all-features --summary-only 2>&1 | tee coverage-summary.txt \
        | awk '{ print } $1 == "TOTAL" { found = 1; if ($10 + 0 < 85) { print "line coverage below the 85% floor: " $0; bad = 1 } } END { if (!found) { print "no TOTAL line"; bad = 1 } exit bad }'
    )
  } 2>&1 | tee "${log}"
  rc=${PIPESTATUS[0]}
  n=$(sed $'s/\033\[[0-9;]*m//g' "${log}" | awk '$1 == "TOTAL" && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {n = $2 - $3} END {print n + 0}')
  rm -f "${log}"
  set -e
  if [ -z "${n}" ] || [ "${n}" -eq 0 ]; then echo 'security-audit.yml / coverage: Run coverage: cargo-llvm-cov compared nothing (continue-on-error in CI; a run with no count fails)' >&2; exit 1; fi
  echo 'PREFLIGHT-INFO: security-audit.yml / coverage: Run coverage: continue-on-error in CI, '"exit ${rc}, ${n} compared" >&2
)

echo; echo "preflight OK"
