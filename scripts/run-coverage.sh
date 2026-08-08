#!/usr/bin/env bash
# Bash script for running targeted test coverage analysis

set -euo pipefail

CRATE=""
SHOW_REPORT=true
OUTPUT_DIR="coverage"
OUTPUT_FORMAT="Html"
IGNORE_TESTS=true
IGNORE_PANICS=true
LINE_THRESHOLD="95"
TOOLCHAIN="stable"
# When set with --crate lib-q-ml-dsa: enable simd256+acvp and include AVX2 sources in the report (x86_64).
ML_DSA_SIMD256=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

while [[ $# -gt 0 ]]; do
  case $1 in
    --crate)
      CRATE="$2"
      shift 2
      ;;
    --no-report)
      SHOW_REPORT=false
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --format)
      OUTPUT_FORMAT="$2"
      shift 2
      ;;
    --with-tests)
      IGNORE_TESTS=false
      shift
      ;;
    --with-panics)
      IGNORE_PANICS=false
      shift
      ;;
    --threshold)
      LINE_THRESHOLD="$2"
      shift 2
      ;;
    --toolchain)
      TOOLCHAIN="$2"
      shift 2
      ;;
    --ml-dsa-simd256)
      ML_DSA_SIMD256=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--crate CRATE] [--ml-dsa-simd256] [--no-report] [--output-dir DIR] [--format FORMAT] [--with-tests] [--with-panics] [--threshold THRESHOLD] [--toolchain TOOLCHAIN]"
      exit 1
      ;;
  esac
done

if [[ "$ML_DSA_SIMD256" == true ]]; then
  if [[ "$CRATE" != "lib-q-ml-dsa" ]]; then
    echo "ERROR: --ml-dsa-simd256 requires --crate lib-q-ml-dsa" >&2
    exit 1
  fi
fi

if [[ "${OUTPUT_FORMAT}" == "Html" ]]; then
  OUTPUT_FORMAT="Html,Xml"
elif [[ "${OUTPUT_FORMAT}" == *"Html"* ]] && [[ "${OUTPUT_FORMAT}" != *"Xml"* ]] && [[ "${OUTPUT_FORMAT}" != *"Cobertura"* ]]; then
  OUTPUT_FORMAT="${OUTPUT_FORMAT},Xml"
fi

mkdir -p "$OUTPUT_DIR"

# Linux default is ptrace; it can spuriously fail after successful libtest runs
# (e.g. AVX2-heavy crates). LLVM instrumentation matches macOS/Windows and is
# recommended in tarpaulin TROUBLESHOOTING.md for Linux CI.
if [[ "$TOOLCHAIN" == "stable" ]]; then
  CMD="cargo tarpaulin --engine llvm --timeout 180"
else
  CMD="cargo +$TOOLCHAIN tarpaulin --engine llvm --timeout 180"
fi

if [[ -n "$CRATE" ]]; then
  CMD="$CMD --packages $CRATE"
  if [[ -f "$CRATE/.tarpaulin.toml" ]]; then
    CMD="$CMD --config $CRATE/.tarpaulin.toml"
  fi
  if [[ "$CRATE" == "lib-q-core" ]]; then
    CMD="$CMD --features std,rand"
  elif [[ "$CRATE" == "lib-q-fn-dsa" ]]; then
    CMD="$CMD --features std,rand"
  elif [[ "$CRATE" == "lib-q" ]]; then
    CMD="$CMD --features all-algorithms"
  elif [[ "$CRATE" == "lib-q-cb-kem" ]]; then
    CMD="$CMD --features std,rand,getrandom,alloc,zeroize,cbkem348864"
  elif [[ "$CRATE" == "lib-q-kem" ]]; then
    # Default features are empty; tests and implementations are behind ml-kem/hqc/alloc.
    CMD="$CMD --features std,alloc,ml-kem,hqc"
  elif [[ "$CRATE" == "lib-q-saturnin" ]]; then
    # `aead-short` and `qcb` are deliberately non-default (see the crate's [features]
    # comment: QCB is nonce-catastrophic and currently has no consumers). They are still
    # shipped, published code with their own tests -- tests/nonce_misuse.rs among them -- so
    # a default-features run leaves src/aead_short.rs, src/tbc.rs and src/commit.rs
    # uncompiled and therefore unmeasured. Enabling them here measures what is published
    # rather than only what is on by default.
    # `simd-avx2` is added too: src/simd/avx2.rs is gated on the feature AND x86_64, and the
    # crate ships tests/simd_equivalence.rs to exercise it, so on an x86_64 runner it is both
    # compilable and tested -- leaving it off measured 0/39 on code that has a test.
    # `simd-neon` is NOT added: it is gated on aarch64, so on x86_64 (CI and dev) it would sit
    # in the denominator at 0 however good the tests are. Same argument as the lib-q-keccak /
    # lib-q-ml-dsa / lib-q-stark-monty31 entries below.
    CMD="$CMD --features std,alloc,aead,block-cipher,hash,stream,aead-short,qcb,simd-avx2"
  elif [[ "$CRATE" == "lib-q-blind-pcs" ]]; then
    # Default features are EMPTY and the whole implementation sits behind `blind-pcs`
    # (src/lib.rs gates the module on it), so a default run instruments an empty crate:
    # tarpaulin reports "No coverable lines found" and 0%, which a threshold of 0 accepts.
    # Without this the crate cannot be gated at all -- there is nothing to measure.
    CMD="$CMD --features blind-pcs"
  elif [[ "$CRATE" == "lib-q-ml-kem" ]]; then
    # ACVP integration tests (kem/pke paths) are behind `deterministic`.
    CMD="$CMD --features std,deterministic"
  elif [[ "$CRATE" == "lib-q-ml-dsa" ]]; then
    if [[ "$ML_DSA_SIMD256" == true ]]; then
      # AVX2 backend + ACVP hooks (aligns with ci.yml ml-dsa-compliance simd256 job).
      CMD="$CMD --features simd256,acvp"
    else
      # Default portable gate: match ci.yml feature matrix so ACVP/FIPS/hardened tests run
      # (they are not enabled by crate default-features alone).
      CMD="$CMD --features std,random,acvp,fips-mode,hardened,mldsa44,mldsa65,mldsa87"
    fi
  elif [[ "$CRATE" == "lib-q-intrinsics" ]]; then
    # Enable SIMD feature gates so platform helpers and arch-specific modules are built.
    # `std` is no longer listed here: lib-q-intrinsics now has its own `std` feature
    # (`std = ["lib-q-platform/std"]`) which is ON BY DEFAULT, so the lib-q-platform → lib-q-core
    # chain builds with std and tarpaulin's panic=unwind harness links. Before that fix this line
    # had to force `lib-q-platform/std` by hand, or the chain built no_std, lib-q-core's cdylib
    # needed a panic runtime it could not get, and the build failed with
    # "unwinding panics are not supported without std".
    CMD="$CMD --features simd256,simd128,simd512"
  fi
fi

if [[ "$IGNORE_TESTS" == true ]]; then
  CMD="$CMD --ignore-tests"
fi
if [[ "$IGNORE_PANICS" == true ]]; then
  CMD="$CMD --ignore-panics"
fi

CMD="$CMD --exclude-files 'target/*' --exclude-files 'benches/*' --exclude-files 'examples/*'"

if [[ "$CRATE" == "lib-q-core" ]]; then
  CMD="$CMD --exclude-files 'lib-q-hash/*' --exclude-files 'lib-q-hpke/*' --exclude-files 'lib-q-intrinsics/*' --exclude-files 'lib-q-k12/*' --exclude-files 'lib-q-keccak/*' --exclude-files 'lib-q-kem/*' --exclude-files 'lib-q-ml-dsa/*' --exclude-files 'lib-q-ml-kem/*' --exclude-files 'lib-q-sha3/*' --exclude-files 'lib-q-sig/*' --exclude-files 'lib-q-aead/*' --exclude-files 'lib-q-platform/*' --exclude-files 'lib-q-utils/*' --exclude-files 'lib-q-zkp/*'"
  # std,rand coverage builds skip wasm; exclude so denominators match PR rust-test action
  CMD="$CMD --exclude-files 'lib-q-core/src/wasm/*' --exclude-files 'lib-q-core\\src\\wasm\\*'"
  CMD="$CMD --include-files 'lib-q-core/src/*' --include-files 'lib-q-core/src/**' --include-files 'lib-q-core\\src\\*'"
elif [[ "$CRATE" == "lib-q" ]]; then
  CMD="$CMD --include-files 'lib-q/src/*' --include-files 'lib-q/src/**' --include-files 'lib-q\\src\\*'"
elif [[ "$CRATE" == "lib-q-keccak" ]]; then
  CMD="$CMD --include-files 'lib-q-keccak/src/*' --include-files 'lib-q-keccak/src/**' --include-files 'lib-q-keccak\\src\\*'"
  CMD="$CMD --exclude-files 'lib-q-keccak/src/advanced_simd.rs' --exclude-files 'lib-q-keccak\\src\\advanced_simd.rs'"
  # AVX-512 batched permutation and the x86 SIMD absorption entrypoints are behind
  # `#[target_feature]` / `target_feature` cfgs; on a runner without AVX-512/AVX2 the
  # intrinsic bodies never execute (the equivalence tests take the scalar fallback),
  # so they read as 0/N. Exclude them from the denominator — same rationale as
  # advanced_simd.rs above and the ml-dsa AVX2 excludes below. (multithreading.rs is
  # std-gated, not SIMD, so it stays measured.)
  CMD="$CMD --exclude-files 'lib-q-keccak/src/x86_simd_avx512.rs' --exclude-files 'lib-q-keccak\\src\\x86_simd_avx512.rs'"
  CMD="$CMD --exclude-files 'lib-q-keccak/src/x86.rs' --exclude-files 'lib-q-keccak\\src\\x86.rs'"
elif [[ "$CRATE" == "lib-q-hash" ]]; then
  CMD="$CMD --include-files 'lib-q-hash/src/*' --include-files 'lib-q-hash/src/**' --include-files 'lib-q-hash\\src\\*'"
elif [[ -n "$CRATE" ]]; then
  PIN="${SCRIPT_DIR}/print-tarpaulin-include-args.sh"
  if [[ ! -f "$PIN" ]]; then
    echo "ERROR: Missing ${PIN}" >&2
    exit 1
  fi
  if ! INC="$(bash "$PIN" "$CRATE" | tr -d '\r')"; then
    echo "ERROR: Could not resolve tarpaulin --include-files for crate '${CRATE}' (see messages above)." >&2
    exit 1
  fi
  CMD="$CMD ${INC}"
fi

# ML-DSA: AVX2 tree and simd256-only instantiations are behind `feature = "simd256"`.
# Default tarpaulin builds use portable paths only; excluding these files matches the
# instrumented binary and mirrors lib-q-keccak/advanced_simd.rs. Use --ml-dsa-simd256 to
# measure AVX2-inclusive coverage (x86_64; informational in coverage.yml).
# Omit backslash '**' excludes: tarpaulin's glob uses '/' as the only path separator.
if [[ "$CRATE" == "lib-q-ml-dsa" && "$ML_DSA_SIMD256" != true ]]; then
  # Module root `simd/avx2.rs` is not matched by `avx2/*` (directory globs); exclude explicitly.
  CMD="$CMD --exclude-files 'lib-q-ml-dsa/src/simd/avx2.rs'"
  CMD="$CMD --exclude-files 'lib-q-ml-dsa\\src\\simd\\avx2.rs'"
  CMD="$CMD --exclude-files 'lib-q-ml-dsa/src/simd/avx2/*' --exclude-files 'lib-q-ml-dsa/src/simd/avx2/**'"
  CMD="$CMD --exclude-files 'lib-q-ml-dsa\\src\\simd\\avx2\\*'"
  CMD="$CMD --exclude-files 'lib-q-ml-dsa/src/ml_dsa_generic/instantiations/avx2.rs'"
  CMD="$CMD --exclude-files 'lib-q-ml-dsa\\src\\ml_dsa_generic\\instantiations\\avx2.rs'"
fi

# lib-q-hqc: only the two files whose function bodies carry `#[target_feature(enable = "avx2",
# enable = "pclmulqdq")]` are excluded, plus the feature-gated wasm binding.
# NOT the whole simd/avx2 directory: that module is gated on `#[cfg(target_arch = "x86_64")]`
# (simd/mod.rs:35), NOT on the `simd-avx2` feature, so mod.rs / polynomial.rs / syndrome.rs /
# vector.rs ARE compiled in a default x86_64 build and must stay in the denominator. Excluding
# them would hide compiled code rather than measure it, which is what
# ci_guard_coverage_honesty.py's SRC_EXCLUDE_ALLOWLIST exists to prevent.
if [[ "$CRATE" == "lib-q-hqc" ]]; then
  CMD="$CMD --exclude-files 'lib-q-hqc/src/wasm.rs' --exclude-files 'lib-q-hqc\\src\\wasm.rs'"
  CMD="$CMD --exclude-files 'lib-q-hqc/src/simd/avx2/gf2x.rs' --exclude-files 'lib-q-hqc\\src\\simd\\avx2\\gf2x.rs'"
  CMD="$CMD --exclude-files 'lib-q-hqc/src/simd/avx2/gf2x_toom3.rs' --exclude-files 'lib-q-hqc\\src\\simd\\avx2\\gf2x_toom3.rs'"
fi

# lib-q-stark-monty31: the three packed backends are gated on `target_feature` ("avx2",
# "avx512f", "neon") in src/lib.rs, NOT merely on target_arch, so a default build compiles only
# the `no_packing` scalar fallback and these read 0/N however good the tests are. Measured: 1244
# of 2052 lines, which drags a genuine 77.9% down to a reported 30.7%. Same argument and same
# shape as the lib-q-keccak and lib-q-ml-dsa entries above.
# `no_packing/` is deliberately NOT excluded — it IS compiled by default and must stay measured.
if [[ "$CRATE" == "lib-q-stark-monty31" ]]; then
  CMD="$CMD --exclude-files 'lib-q-stark-monty31/src/x86_64_avx2/*' --exclude-files 'lib-q-stark-monty31/src/x86_64_avx2/**'"
  CMD="$CMD --exclude-files 'lib-q-stark-monty31\\src\\x86_64_avx2\\*'"
  CMD="$CMD --exclude-files 'lib-q-stark-monty31/src/x86_64_avx512/*' --exclude-files 'lib-q-stark-monty31/src/x86_64_avx512/**'"
  CMD="$CMD --exclude-files 'lib-q-stark-monty31\\src\\x86_64_avx512\\*'"
  CMD="$CMD --exclude-files 'lib-q-stark-monty31/src/aarch64_neon/*' --exclude-files 'lib-q-stark-monty31/src/aarch64_neon/**'"
  CMD="$CMD --exclude-files 'lib-q-stark-monty31\\src\\aarch64_neon\\*'"
fi

# lib-q-zkp: recursive verifier internals are experimental and currently covered by dedicated
# long-running integration suites. Exclude them from the default crate gate so coverage tracks
# the stable high-level API and production paths.
if [[ "$CRATE" == "lib-q-zkp" ]]; then
  CMD="$CMD --exclude-files 'lib-q-zkp/src/aggregation.rs'"
  CMD="$CMD --exclude-files 'lib-q-zkp/src/air/stark_verifier.rs'"
  CMD="$CMD --exclude-files 'lib-q-zkp/src/air/fri_verifier.rs'"
  CMD="$CMD --exclude-files 'lib-q-zkp/src/air/commitment_verifier.rs'"
  CMD="$CMD --exclude-files 'lib-q-zkp/src/air/constraint_verifier.rs'"
fi

# lib-q-intrinsics: only one of avx2.rs / arm64.rs is compiled per target; drop the other from
# the Cobertura denominator so the gate matches the instrumented binary (see lib-q-ml-dsa AVX2 excludes).
if [[ "$CRATE" == "lib-q-intrinsics" ]]; then
  ARCH_RAW="$(uname -m 2>/dev/null || echo unknown)"
  ARCH_CLEAN="${ARCH_RAW%%[$'\r']}"
  case "$ARCH_CLEAN" in
    x86_64|amd64)
      CMD="$CMD --exclude-files 'lib-q-intrinsics/src/arm64.rs'"
      CMD="$CMD --exclude-files 'lib-q-intrinsics\\src\\arm64.rs'"
      ;;
    aarch64|arm64)
      CMD="$CMD --exclude-files 'lib-q-intrinsics/src/avx2.rs'"
      CMD="$CMD --exclude-files 'lib-q-intrinsics\\src\\avx2.rs'"
      ;;
    *)
      CMD="$CMD --exclude-files 'lib-q-intrinsics/src/arm64.rs'"
      CMD="$CMD --exclude-files 'lib-q-intrinsics\\src\\arm64.rs'"
      CMD="$CMD --exclude-files 'lib-q-intrinsics/src/avx2.rs'"
      CMD="$CMD --exclude-files 'lib-q-intrinsics\\src\\avx2.rs'"
      ;;
  esac
fi

if [[ -n "$CRATE" ]] && [[ "$CMD" != *"--include-files"* ]]; then
  echo "ERROR: tarpaulin command is missing --include-files for crate '${CRATE}' (Cobertura would mix dependency lines)." >&2
  exit 1
fi

OUT_EXTRA=""
IFS=',' read -ra FORMAT_PARTS <<< "$OUTPUT_FORMAT"
for part in "${FORMAT_PARTS[@]}"; do
  part="${part// /}"
  [[ -z "$part" ]] && continue
  OUT_EXTRA+=" --out $part"
done
CMD="$CMD${OUT_EXTRA} --output-dir $OUTPUT_DIR"

# NEVER add a test-NAME filter here. A name filter shrinks the set of tests that runs while
# leaving --include-files (the denominator) untouched, so the resulting percentage describes
# the filter, not the crate. lib-q-fn-dsa used to carry
#   -- keypair_generation test_basic_fn_dsa_functionality sign_and_verify seeded_sign
# which ran 6 of the crate's 34 tests against all of lib-q-fn-dsa/src/lib.rs and scored
# 69/161 = 42.86% against a 68% floor -- a red gate that said nothing about the code.
# The identical filter in .github/actions/rust-test/action.yml was removed for the same
# reason (see the comment there). scripts/ci-guard-coverage-honesty.sh enforces this:
# only libtest FLAGS may follow the `--` separator, never test names.
if [[ "$CRATE" == "lib-q-kem" ]]; then
  # Serial libtest lowers load on large HQC integration tests under LLVM instrumentation.
  # A scheduling flag, not a test selector: every test still runs.
  CMD="$CMD -- --test-threads=1"
fi

echo "Running: $CMD"
eval "$CMD"
RESULT=$?

if [[ "${RESULT}" -ne 0 ]]; then
  echo -e "\e[31m❌ cargo tarpaulin exited with status ${RESULT}\e[0m"
  exit "${RESULT}"
fi

if [[ "$SHOW_REPORT" == true ]]; then
  report=""
  if [[ -f "$OUTPUT_DIR/index.html" ]]; then
    report="$OUTPUT_DIR/index.html"
  elif [[ -f "$OUTPUT_DIR/tarpaulin-report.html" ]]; then
    report="$OUTPUT_DIR/tarpaulin-report.html"
  fi
  if [[ -n "$report" ]]; then
    skip_open=""
    if [[ -n "${CI:-}" ]] || [[ -n "${GITHUB_ACTIONS:-}" ]]; then
      skip_open=1
    elif [[ "$(uname -s)" == "Linux" ]] && [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
      skip_open=1
    fi
    if [[ -n "$skip_open" ]]; then
      echo "Coverage report written to $report (skipped opening browser: CI or headless session)"
    else
      echo "Opening coverage report..."
      if command -v xdg-open &> /dev/null; then xdg-open "$report" 2>/dev/null || true
      elif command -v open &> /dev/null; then open "$report" 2>/dev/null || true
      else echo "Open manually: $report"; fi
    fi
  fi
fi

COVERAGE=""
if COVERAGE="$(bash "${SCRIPT_DIR}/extract-coverage-percent.sh" "$OUTPUT_DIR")"; then
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "COVERAGE_PERCENT=${COVERAGE}" >>"${GITHUB_ENV}"
  fi
  if awk -v c="${COVERAGE}" -v t="${LINE_THRESHOLD}" 'BEGIN { exit !(c < t) }'; then
    echo -e "\e[31m❌ Coverage is ${COVERAGE}%, which is below the ${LINE_THRESHOLD}% threshold.\e[0m"
    exit 1
  else
    echo -e "\e[32m✅ Coverage is ${COVERAGE}%, which meets or exceeds the ${LINE_THRESHOLD}% threshold.\e[0m"
  fi
  exit 0
else
  echo -e "\e[31m❌ Could not determine coverage percentage.\e[0m"
  echo "Expected ${OUTPUT_DIR}/cobertura.xml and/or HTML report. Directory contents:"
  ls -la "$OUTPUT_DIR" 2>/dev/null || true
  exit 1
fi
