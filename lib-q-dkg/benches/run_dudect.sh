#!/usr/bin/env bash
# Hardened constant-time (dudect) measurement run for the two secret-dependent components in
# lib-q-dkg (see ../../dev/conformance/integration/lib-q-threshold-raccoon/SECURITY_ANALYSIS.md §8).
#
# This is the "production sign-off" harness: a quiet, core-pinned, frequency-locked run on
# bare-metal Linux. It needs no code changes — it just drives benches/ct_dudect.rs under the right
# environment. The construction-level review + unit tests + the dev-host measurement are already
# done; this exists for the eventual formal CT audit.
#
# GOLD-STANDARD HOST (do NOT use a laptop — thermal throttling reintroduces the jitter you are
# trying to remove). Use a quiet desktop/server with an isolated core:
#   1. Boot param (set once in the bootloader, then reboot): isolcpus=3 nohz_full=3 rcu_nocbs=3
#      -> reserves core 3 from the scheduler. Pick a real physical core (avoid SMT siblings).
#   2. Nothing else running on the box. AC power.
#   3. Run:  ./run_dudect.sh 3 300      (core 3, 300 s per bench)
#
# Verdict rule of thumb: max |t| < 10 and NON-divergent as sample count (n) grows => no leakage.
# A leaky routine's |t| climbs without bound as n increases.

set -euo pipefail

CORE="${1:-3}"            # physical core to pin to (ideally isolcpus-reserved)
DUR="${2:-300}"          # seconds per bench
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE_DIR="$(cd "$HERE/.." && pwd)"
OUT_DIR="${TMPDIR:-/tmp}/libq-dudect"
mkdir -p "$OUT_DIR"

echo "== lib-q-dkg dudect CT measurement =="
echo "core=$CORE  duration=${DUR}s/bench  out=$OUT_DIR"

# --- lock CPU frequency (performance governor) on the target core, if permitted ---
GOV_PATH="/sys/devices/system/cpu/cpu${CORE}/cpufreq/scaling_governor"
if [ -w "$GOV_PATH" ]; then
  PREV_GOV="$(cat "$GOV_PATH")"
  echo performance > "$GOV_PATH" && echo "governor[cpu${CORE}]: $PREV_GOV -> performance"
  restore_gov() { echo "$PREV_GOV" > "$GOV_PATH" 2>/dev/null && echo "governor restored to $PREV_GOV"; }
  trap restore_gov EXIT
else
  echo "WARN: cannot set governor (need root / cpufreq). Run as root or 'cpupower frequency-set -g performance'."
fi

# isolation sanity check
if ! grep -qE "(^| )isolcpus=[^ ]*\b${CORE}\b" /proc/cmdline 2>/dev/null; then
  echo "WARN: core ${CORE} is not in isolcpus= on /proc/cmdline -- measurement will be noisier."
fi

command -v taskset >/dev/null || { echo "ERROR: taskset not found (apt install util-linux)"; exit 1; }

echo "building release bench..."
( cd "$CRATE_DIR" && cargo bench -p lib-q-dkg --bench ct_dudect --no-run >/dev/null 2>&1 )
EXE="$(cd "$CRATE_DIR" && ls -t ../target/release/deps/ct_dudect-* 2>/dev/null | grep -vE '\.(d|pdb)$' | head -1)"
EXE="$(cd "$CRATE_DIR" && realpath "$EXE")"
echo "bench exe: $EXE"

for BENCH in bench_secret_sampler bench_ring_reduce; do
  LOG="$OUT_DIR/${BENCH}.log"
  echo
  echo "--- $BENCH (taskset -c $CORE, continuous, ${DUR}s) ---"
  # nice -n -20 needs root; ignore failure and keep going at default priority.
  timeout "${DUR}s" taskset -c "$CORE" nice -n -20 "$EXE" --continuous "$BENCH" > "$LOG" 2>&1 || true
  tail -n 3 "$LOG"
done

echo
echo "== done. full logs in $OUT_DIR =="
echo "PASS iff both report max |t| < 10 and t stays bounded as n grows."
