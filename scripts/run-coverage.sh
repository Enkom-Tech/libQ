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
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--crate CRATE] [--no-report] [--output-dir DIR] [--format FORMAT] [--with-tests] [--with-panics] [--threshold THRESHOLD] [--toolchain TOOLCHAIN]"
      exit 1
      ;;
  esac
done

if [[ "${OUTPUT_FORMAT}" == "Html" ]]; then
  OUTPUT_FORMAT="Html,Xml"
elif [[ "${OUTPUT_FORMAT}" == *"Html"* ]] && [[ "${OUTPUT_FORMAT}" != *"Xml"* ]] && [[ "${OUTPUT_FORMAT}" != *"Cobertura"* ]]; then
  OUTPUT_FORMAT="${OUTPUT_FORMAT},Xml"
fi

mkdir -p "$OUTPUT_DIR"

if [[ "$TOOLCHAIN" == "stable" ]]; then
  CMD="cargo tarpaulin"
else
  CMD="cargo +$TOOLCHAIN tarpaulin"
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
  elif [[ "$CRATE" == "lib-q-ml-kem" ]]; then
    # ACVP integration tests (kem/pke paths) are behind `deterministic`.
    CMD="$CMD --features std,deterministic"
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

if [[ "$CRATE" == "lib-q-fn-dsa" ]]; then
  CMD="$CMD -- keypair_generation test_basic_fn_dsa_functionality"
elif [[ "$CRATE" == "lib-q-kem" ]]; then
  # Serial libtest lowers load on large HQC integration tests under LLVM instrumentation.
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
