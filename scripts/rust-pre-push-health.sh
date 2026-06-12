#!/usr/bin/env bash
# Rust pre-push code-health gate (Fallow-inspired hygiene for Cargo workspaces).
# Configured via .rust-pre-push-health.json in the repo root.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

CONFIG_FILE="${RUST_PRE_PUSH_CONFIG:-$ROOT/.rust-pre-push-health.json}"
MODE="${RUST_PRE_PUSH_MODE:-}"
OUTPUT_JSON=""

# --- colors (disabled when not a tty) ---
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[1;33m'
  CYAN=$'\033[0;36m'
  BOLD=$'\033[1m'
  NC=$'\033[0m'
else
  RED="" GREEN="" YELLOW="" CYAN="" BOLD="" NC=""
fi

# check_name -> status (pass|fail|warn|skip) duration_ms blocking message
declare -A CHECK_STATUS CHECK_MS CHECK_BLOCKING CHECK_MSG

usage() {
  cat <<'EOF'
Usage: rust-pre-push-health.sh [OPTIONS]

Rust code-health gate before git push. Exits non-zero only on blocking failures.

Options:
  --strict          CI-style: optional checks block when they find issues
  --soft            Local dev: only fmt, clippy, audit block (default)
  --config PATH     Config JSON (default: .rust-pre-push-health.json)
  --skip CHECK      Disable a check (fmt|clippy|audit|deps|warnalyzer|dupes|metrics)
  --only CHECK      Run only the named check (repeatable)
  --help            Show this help

Environment:
  RUST_PRE_PUSH_MODE    strict | soft
  RUST_PRE_PUSH_CONFIG  Path to config JSON
EOF
}

SKIP_CHECKS=()
ONLY_CHECKS=()

upper() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict) MODE="strict" ;;
    --soft) MODE="soft" ;;
    --config) shift; CONFIG_FILE="${1:?--config requires a path}" ;;
    --skip) shift; SKIP_CHECKS+=("${1:?--skip requires a check name}") ;;
    --only) shift; ONLY_CHECKS+=("${1:?--only requires a check name}") ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

# --- not a Rust repo: exit cleanly ---
if [[ ! -f "$ROOT/Cargo.toml" ]]; then
  echo "rust-pre-push-health: no Cargo.toml at repo root — skipping (not a Rust project)"
  exit 0
fi

now_ms() {
  local ms
  if ms="$(run_python -c 'import time; print(int(time.time() * 1000))' 2>/dev/null)"; then
    echo "$ms"
  else
    echo $(( $(date +%s) * 1000 ))
  fi
}

# Resolve a Python interpreter that can import json (skip Windows Store stubs).
run_python() {
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import json' >/dev/null 2>&1; then
    python3 "$@"
  elif command -v python >/dev/null 2>&1 && python -c 'import json' >/dev/null 2>&1; then
    python "$@"
  elif command -v py >/dev/null 2>&1 && py -3 -c 'import json' >/dev/null 2>&1; then
    py -3 "$@"
  else
    return 1
  fi
}

python_available() {
  run_python -c 'import json' >/dev/null 2>&1
}

# Load config via Python when available; otherwise use defaults.
load_config() {
  MODE="${MODE:-soft}"
  CHECK_FMT=1 CHECK_CLIPPY=1 CHECK_AUDIT=1 CHECK_DEPS=1
  CHECK_WARNALYZER=1 CHECK_DUPES=1 CHECK_METRICS=1
  BLOCK_FMT="" BLOCK_CLIPPY="" BLOCK_AUDIT=""
  BLOCK_DEPS="" BLOCK_WARNALYZER="" BLOCK_DUPES="" BLOCK_METRICS=""
  DEPS_TOOL="auto"
  CLIPPY_ARGS=(--workspace --all-targets --all-features -- -D warnings)
  FMT_ARGS=(--all -- --check)

  if [[ ! -f "$CONFIG_FILE" ]]; then
    return 0
  fi

  if ! python_available; then
    echo "${YELLOW}warn${NC}: config file present but Python unavailable — using defaults" >&2
    return 0
  fi

  # shellcheck disable=SC2016
  eval "$(run_python - "$CONFIG_FILE" "$MODE" <<'PY'
import json, shlex, sys
path, cli_mode = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    cfg = json.load(f)
mode = cli_mode or cfg.get("mode", "soft")
checks = cfg.get("checks", {})
def en(k, default=True):
    c = checks.get(k, {})
    return "1" if c.get("enabled", default) else "0"
def blk(k):
    c = checks.get(k, {})
    b = c.get("blocking")
    return "" if b is None else ("1" if b else "0")
def bash_array(name, values):
    if values:
        print(f"{name}=({' '.join(shlex.quote(v) for v in values)})")
deps = checks.get("deps", {})
print(f"MODE={mode}")
print(f"OUTPUT_JSON={cfg.get('output_json', '')}")
print(f"CHECK_FMT={en('fmt')}")
print(f"CHECK_CLIPPY={en('clippy')}")
print(f"CHECK_AUDIT={en('audit')}")
print(f"CHECK_DEPS={en('deps')}")
print(f"CHECK_WARNALYZER={en('warnalyzer')}")
print(f"CHECK_DUPES={en('dupes')}")
print(f"CHECK_METRICS={en('metrics')}")
print(f"BLOCK_FMT={blk('fmt')}")
print(f"BLOCK_CLIPPY={blk('clippy')}")
print(f"BLOCK_AUDIT={blk('audit')}")
print(f"BLOCK_DEPS={blk('deps')}")
print(f"BLOCK_WARNALYZER={blk('warnalyzer')}")
print(f"BLOCK_DUPES={blk('dupes')}")
print(f"BLOCK_METRICS={blk('metrics')}")
print(f"DEPS_TOOL={deps.get('tool', 'auto')}")
bash_array("CLIPPY_ARGS", cfg.get("clippy_args"))
bash_array("FMT_ARGS", cfg.get("fmt_args"))
PY
)"
}

check_enabled() {
  local name="$1"
  local var="CHECK_$(upper "$name")"
  local val=1
  eval "val=\${${var}-1}"
  [[ "$val" == "1" ]]
}

check_skipped_by_cli() {
  local c="$1"
  local s
  for s in "${SKIP_CHECKS[@]}"; do
    [[ "$s" == "$c" ]] && return 0
  done
  return 1
}

check_in_only_filter() {
  [[ ${#ONLY_CHECKS[@]} -eq 0 ]] && return 0
  local c="$1" o
  for o in "${ONLY_CHECKS[@]}"; do
    [[ "$o" == "$c" ]] && return 0
  done
  return 1
}

should_run() {
  local c="$1"
  check_skipped_by_cli "$c" && return 1
  check_in_only_filter "$c" || return 1
  check_enabled "$c"
}

is_blocking() {
  local c="$1"
  local var="BLOCK_$(upper "$c")"
  local override=""
  eval "override=\${${var}-}"
  if [[ -n "$override" ]]; then
    [[ "$override" == "1" ]]
    return
  fi
  case "$MODE" in
    strict) return 0 ;;
    soft)
      case "$c" in fmt|clippy|audit) return 0 ;; *) return 1 ;; esac
      ;;
    *) return 1 ;;
  esac
}

record() {
  local name="$1" status="$2" ms="$3" blocking="$4" msg="${5:-}"
  CHECK_STATUS[$name]="$status"
  CHECK_MS[$name]="$ms"
  CHECK_BLOCKING[$name]="$blocking"
  CHECK_MSG[$name]="$msg"
}

print_header() {
  echo ""
  echo "${BOLD}Rust pre-push health${NC}  mode=${CYAN}${MODE}${NC}  root=${ROOT}"
  echo "────────────────────────────────────────────────────────"
}

print_tool_missing() {
  local tool="$1" install="$2" blocking="$3"
  if [[ "$blocking" == "yes" ]]; then
    echo "${RED}MISSING (blocking)${NC}: $tool"
  else
    echo "${YELLOW}MISSING (optional)${NC}: $tool"
  fi
  echo "  install: $install"
}

run_check() {
  local name="$1" label="$2"
  shift 2
  local start end ms rc=0
  start="$(now_ms)"
  echo ""
  echo "${BOLD}▶ ${label}${NC}"
  if "$@"; then
    rc=0
  else
    rc=$?
  fi
  end="$(now_ms)"
  ms=$(( end - start ))
  echo "${CYAN}  (${ms} ms)${NC}"
  return "$rc"
}

is_windows() {
  case "$(uname -s 2>/dev/null)" in
    MINGW* | MSYS* | CYGWIN*) return 0 ;;
  esac
  [[ "${OS:-}" == "Windows_NT" ]]
}

fmt_args_include_all() {
  local arg
  for arg in "${FMT_ARGS[@]}"; do
    [[ "$arg" == "--all" ]] && return 0
  done
  return 1
}

list_workspace_packages() {
  if python_available; then
    run_python - <<'PY'
import json, subprocess

meta = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        text=True,
    )
)
for pkg in meta["packages"]:
    print(pkg["name"])
PY
    return 0
  fi

  cargo metadata --no-deps --format-version 1 2>/dev/null \
    | tr ',' '\n' \
    | sed -n 's/^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | sort -u
}

run_cargo_fmt_per_package() {
  local pkg failed=0 found=0
  while IFS= read -r pkg; do
    pkg="${pkg//$'\r'/}"
    [[ -z "$pkg" ]] && continue
    found=1
    if ! cargo fmt -p "$pkg" -- --check; then
      failed=1
    fi
  done < <(list_workspace_packages)

  if [[ "$found" -eq 0 ]]; then
    echo "${RED}error${NC}: could not enumerate workspace packages for fmt fallback" >&2
    return 1
  fi
  return "$failed"
}

run_cargo_fmt() {
  local errfile rc
  errfile="$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/rust-pre-push-fmt.$$")"
  if cargo fmt "${FMT_ARGS[@]}" 2>"$errfile"; then
    rm -f "$errfile"
    return 0
  fi
  rc=$?
  cat "$errfile" >&2

  if fmt_args_include_all \
    && { is_windows || grep -qE 'too long|os error 206' "$errfile" 2>/dev/null; }; then
    echo "${YELLOW}warn${NC}: cargo fmt --all hit platform path limits; checking workspace members individually" >&2
    rm -f "$errfile"
    run_cargo_fmt_per_package
    return $?
  fi

  rm -f "$errfile"
  return "$rc"
}

# --- individual checks ---

do_fmt() {
  if ! command -v cargo >/dev/null 2>&1; then
    print_tool_missing "cargo (rustup)" "https://rustup.rs/" "yes"
    record "fmt" "fail" 0 "yes" "cargo not found"
    return 1
  fi
  if ! run_cargo_fmt; then
    record "fmt" "fail" "${CHECK_MS[fmt]:-0}" "yes" "run: cargo fmt --all"
    return 1
  fi
  record "fmt" "pass" "${CHECK_MS[fmt]:-0}" "yes" ""
  return 0
}

do_clippy() {
  if ! command -v cargo >/dev/null 2>&1; then
    record "clippy" "fail" 0 "yes" "cargo not found"
    return 1
  fi
  # shellcheck disable=SC2086
  if ! cargo clippy "${CLIPPY_ARGS[@]}"; then
    record "clippy" "fail" "${CHECK_MS[clippy]:-0}" "yes" "fix clippy warnings or run with guidance from cargo clippy"
    return 1
  fi
  record "clippy" "pass" "${CHECK_MS[clippy]:-0}" "yes" ""
  return 0
}

do_audit() {
  if ! command -v cargo-audit >/dev/null 2>&1; then
    print_tool_missing "cargo-audit" "cargo install cargo-audit --locked" "$(
      is_blocking audit && echo yes || echo no
    )"
    if is_blocking audit; then
      record "audit" "fail" 0 "yes" "install cargo-audit"
      return 1
    fi
    record "audit" "skip" 0 "no" "cargo-audit not installed"
    return 0
  fi
  if ! cargo audit --deny warnings; then
    record "audit" "fail" "${CHECK_MS[audit]:-0}" "yes" "run: cargo audit --deny warnings"
    return 1
  fi
  record "audit" "pass" "${CHECK_MS[audit]:-0}" "yes" ""
  return 0
}

pick_deps_tool() {
  case "$DEPS_TOOL" in
    machete)
      echo "machete"
      return
      ;;
    udeps)
      echo "udeps"
      return
      ;;
  esac
  if command -v cargo-machete >/dev/null 2>&1 || cargo machete --version >/dev/null 2>&1; then
    echo "machete"
  elif command -v cargo-udeps >/dev/null 2>&1 || cargo udeps --version >/dev/null 2>&1; then
    echo "udeps"
  else
    echo "none"
  fi
}

do_deps() {
  local tool issues=0
  tool="$(pick_deps_tool)"
  case "$tool" in
    machete)
      if ! cargo machete 2>&1; then
        issues=1
      fi
      ;;
    udeps)
      if ! cargo +nightly udeps --all-targets 2>&1; then
        issues=1
      fi
      ;;
    none)
      print_tool_missing "cargo-machete (preferred) or cargo-udeps" \
        "cargo install cargo-machete   # or: cargo install cargo-udeps --locked (requires nightly)" \
        "no"
      record "deps" "skip" 0 "no" "no unused-deps tool installed"
      return 0
      ;;
  esac
  if [[ "$issues" -eq 1 ]]; then
    if is_blocking deps; then
      record "deps" "fail" "${CHECK_MS[deps]:-0}" "yes" "remove unused dependencies ($tool)"
      return 1
    fi
    record "deps" "warn" "${CHECK_MS[deps]:-0}" "no" "unused dependencies reported ($tool)"
    return 0
  fi
  record "deps" "pass" "${CHECK_MS[deps]:-0}" "$(is_blocking deps && echo yes || echo no)" ""
  return 0
}

do_warnalyzer() {
  if ! command -v warnalyzer >/dev/null 2>&1; then
    print_tool_missing "warnalyzer" "cargo install warnalyzer" "no"
    record "warnalyzer" "skip" 0 "no" "warnalyzer not installed"
    return 0
  fi
  if ! command -v rust-analyzer >/dev/null 2>&1; then
    print_tool_missing "rust-analyzer" "rustup component add rust-analyzer" "no"
    record "warnalyzer" "skip" 0 "no" "rust-analyzer required for warnalyzer SCIP backend"
    return 0
  fi
  local out rc=0
  out="$(warnalyzer "$ROOT" 2>&1)" || rc=$?
  echo "$out"
  if [[ "$rc" -ne 0 ]]; then
    if is_blocking warnalyzer; then
      record "warnalyzer" "fail" "${CHECK_MS[warnalyzer]:-0}" "yes" "review dead/unused code"
      return 1
    fi
    record "warnalyzer" "warn" "${CHECK_MS[warnalyzer]:-0}" "no" "warnalyzer reported issues"
    return 0
  fi
  # warnalyzer exits 0 even with findings — treat non-empty suspicious output as warn in soft mode
  if [[ -n "$out" ]] && echo "$out" | grep -qiE 'unused|dead|never used'; then
    if is_blocking warnalyzer; then
      record "warnalyzer" "fail" "${CHECK_MS[warnalyzer]:-0}" "yes" "review dead/unused code"
      return 1
    fi
    record "warnalyzer" "warn" "${CHECK_MS[warnalyzer]:-0}" "no" "possible unused code"
    return 0
  fi
  record "warnalyzer" "pass" "${CHECK_MS[warnalyzer]:-0}" "$(is_blocking warnalyzer && echo yes || echo no)" ""
  return 0
}

do_dupes() {
  if ! cargo dupes --version >/dev/null 2>&1; then
    print_tool_missing "cargo-dupes (code-dupes)" "cargo install code-dupes" "no"
    record "dupes" "skip" 0 "no" "cargo-dupes not installed"
    return 0
  fi
  local rc=0
  if ! cargo dupes stats --exclude-tests 2>&1; then
    rc=$?
  fi
  if [[ "$rc" -ne 0 ]]; then
    if is_blocking dupes; then
      record "dupes" "fail" "${CHECK_MS[dupes]:-0}" "yes" "run: cargo dupes report"
      return 1
    fi
    record "dupes" "warn" "${CHECK_MS[dupes]:-0}" "no" "duplicate code detected"
    return 0
  fi
  record "dupes" "pass" "${CHECK_MS[dupes]:-0}" "$(is_blocking dupes && echo yes || echo no)" ""
  return 0
}

do_metrics() {
  if ! command -v rust-code-analysis-cli >/dev/null 2>&1; then
    print_tool_missing "rust-code-analysis-cli" "cargo install rust-code-analysis-cli" "no"
    record "metrics" "skip" 0 "no" "rust-code-analysis-cli not installed"
    return 0
  fi
  # Non-blocking reporting: summarize maintainability metrics for src trees
  local rc=0
  if ! rust-code-analysis-cli -m -p "$ROOT" -I "*.rs" -X "target/*" -X "vendor/*" 2>&1 | tail -n 40; then
    rc=$?
  fi
  if [[ "$rc" -ne 0 ]]; then
    record "metrics" "warn" "${CHECK_MS[metrics]:-0}" "no" "metrics command failed (informational)"
    return 0
  fi
  record "metrics" "pass" "${CHECK_MS[metrics]:-0}" "no" "report only"
  return 0
}

write_json_summary() {
  [[ -z "$OUTPUT_JSON" ]] && return 0
  local out="$ROOT/$OUTPUT_JSON"
  mkdir -p "$(dirname "$out")"
  if ! python_available; then
    return 0
  fi
  CHECKS_JSON="$(
    for k in fmt clippy audit deps warnalyzer dupes metrics; do
      printf '%s|%s|%s|%s|%s\n' \
        "$k" "${CHECK_STATUS[$k]:-skip}" "${CHECK_MS[$k]:-0}" \
        "${CHECK_BLOCKING[$k]:-no}" "${CHECK_MSG[$k]:-}"
    done
  )" MODE="$MODE" OUT="$out" ROOT="$ROOT" run_python <<'PY'
import json, os, time
checks = {}
for line in os.environ.get("CHECKS_JSON", "").splitlines():
    if not line.strip():
        continue
    name, status, ms, blocking, msg = line.split("|", 4)
    checks[name] = {
        "status": status,
        "duration_ms": int(ms or 0),
        "blocking": blocking == "yes",
        "message": msg,
    }
doc = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "mode": os.environ.get("MODE", "soft"),
    "root": os.environ.get("ROOT", ""),
    "checks": checks,
    "passed": all(
        c["status"] in ("pass", "skip", "warn") or not c["blocking"]
        for c in checks.values()
    ),
}
with open(os.environ["OUT"], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

print_summary() {
  echo ""
  echo "${BOLD}Summary${NC}"
  echo "────────────────────────────────────────────────────────"
  local name label status ms
  local -a order=(fmt clippy audit deps warnalyzer dupes metrics)
  local -a labels=("format" "clippy" "audit" "deps" "dead-code" "dupes" "metrics")
  local i=0 failed=0
  for name in "${order[@]}"; do
    label="${labels[$i]}"
    status="${CHECK_STATUS[$name]:-skip}"
    ms="${CHECK_MS[$name]:-0}"
    case "$status" in
      pass) echo "  ${GREEN}✓${NC} ${label}: pass (${ms} ms)" ;;
      fail)
        echo "  ${RED}✗${NC} ${label}: ${RED}FAIL${NC} (${ms} ms)"
        [[ -n "${CHECK_MSG[$name]:-}" ]] && echo "      → ${CHECK_MSG[$name]}"
        failed=$(( failed + 1 ))
        ;;
      warn) echo "  ${YELLOW}!${NC} ${label}: warn (${ms} ms)" ;;
      skip) echo "  ${YELLOW}-${NC} ${label}: skipped" ;;
    esac
    i=$(( i + 1 ))
  done
  echo "────────────────────────────────────────────────────────"
  if [[ "$failed" -gt 0 ]]; then
    echo "${RED}${BOLD}BLOCKED${NC}: fix failing checks before push."
    return 1
  fi
  echo "${GREEN}${BOLD}OK${NC}: pre-push health checks passed."
  return 0
}

# --- main ---

load_config

# Apply --skip to env flags
for s in "${SKIP_CHECKS[@]}"; do
  u="$(upper "$s")"
  printf -v "CHECK_${u}" '%s' "0"
done

print_header

OVERALL=0

run_named() {
  local key="$1" label="$2"
  should_run "$key" || return 0
  local start end
  start="$(now_ms)"
  if ! "do_${key}"; then
    OVERALL=1
  fi
  end="$(now_ms)"
  CHECK_MS[$key]=$(( end - start ))
}

run_named fmt "cargo fmt --check"
run_named clippy "cargo clippy (-D warnings)"
run_named audit "cargo audit"
run_named deps "unused dependencies (machete/udeps)"
run_named warnalyzer "warnalyzer (dead code)"
run_named dupes "cargo dupes (duplicate code)"
run_named metrics "rust-code-analysis-cli (metrics)"

write_json_summary
print_summary || exit 1
exit "$OVERALL"
