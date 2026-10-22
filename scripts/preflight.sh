#!/usr/bin/env bash
# scripts/preflight.sh — local reproduction of the CI gates before `git push`.
# Every command is the one CI runs. A step this file does not cover is a step
# that can only fail remotely — when a workflow changes, regenerate this file
# in the same commit (checks no workflow runs go in scripts/preflight.local.sh).
# Run `--quick` before every push.
#
# usage: scripts/preflight.sh [--quick]   (--quick skips the test / bench suites)
# generator rev e1525210a18e647fc6afa3496f68c5439fd7727d
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
# --- heavy slot (end) ---
heavy_slot_acquire "$(basename "$PWD")" preflight || exit 1
trap heavy_slot_release EXIT

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
# `cargo clippy` reuses fresh `cargo check` artifacts and then lints nothing;
# touching the crate roots invalidates only this repo's fingerprints.
relint() { git ls-files | grep -E '(^|/)src/(lib|main)\.rs$' | xargs -r touch; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }
has_toolchain() { rustup toolchain list | grep -q "^$1"; }

# Steps CI runs that this file cannot reproduce locally (they can only fail remotely):
#   - ci.yml:apple:run (no cargo / grep)
#   - security-audit.yml:audit:Install cargo-audit (needs network / runner-only)
#   - security-audit.yml:deny:Install cargo-deny (needs network / runner-only)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_foreign_key_bytes] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_foreign_key_bytes] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_foreign_key_bytes] (needs network / runner-only)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_memory_vault_ops] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_memory_vault_ops] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_memory_vault_ops] (needs network / runner-only)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_foreign_errors] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_foreign_errors] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_foreign_errors] (needs network / runner-only)

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
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; scripts/run_tests.sh vault_oracle=8,desktop_gaps=3 -- cargo test )

step "ci.yml / test: Test (all features)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"; scripts/run_tests.sh vault_oracle=8,desktop_gaps=3,foreign_oracle=4 -- cargo test --all-features )

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
    --ignore RUSTSEC-2026-0177
)

step "security-audit.yml / coverage: Run coverage"
(
  log="$(mktemp)"
  set +e
  {
    ( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; cargo llvm-cov --lib --summary-only 2>&1 )
  } 2>&1 | tee "${log}"
  rc=${PIPESTATUS[0]}
  n=$(sed $'s/\033\[[0-9;]*m//g' "${log}" | awk '$1 == "TOTAL" && $2 ~ /^[0-9]+$/ {n = $2} END {print n + 0}')
  rm -f "${log}"
  set -e
  if [ -z "${n}" ] || [ "${n}" -eq 0 ]; then echo 'security-audit.yml / coverage: Run coverage: cargo-llvm-cov compared nothing (continue-on-error in CI; a run with no count fails)' >&2; exit 1; fi
  echo 'PREFLIGHT-INFO: security-audit.yml / coverage: Run coverage: continue-on-error in CI, '"exit ${rc}, ${n} compared" >&2
)

echo; echo "preflight OK"
