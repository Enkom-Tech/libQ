#!/usr/bin/env bash
# Validate benchmark-shards.toml against the workspace.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON=()
for py in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c "import tomllib" 2>/dev/null; then
    PYTHON=("$py")
    break
  fi
done
if [[ ${#PYTHON[@]} -eq 0 ]] && command -v py >/dev/null 2>&1 && py -3 -c "import tomllib" 2>/dev/null; then
  PYTHON=(py -3)
fi
if [[ ${#PYTHON[@]} -eq 0 ]]; then
  echo "ERROR: need Python 3.11+ (stdlib tomllib); install python3.11 or newer" >&2
  exit 1
fi

MANIFEST="${ROOT}/.github/benchmark-shards.toml"
if [[ ! -f "$MANIFEST" ]]; then
  echo "ERROR: missing $MANIFEST" >&2
  exit 1
fi

echo "== Parsing benchmark manifest =="
"${PYTHON[@]}" -c "
import tomllib
from pathlib import Path
data = tomllib.loads(Path('$MANIFEST').read_text(encoding='utf-8'))
ids = [s['id'] for s in data.get('shard', []) if s.get('enabled', True) is not False]
if len(ids) != len(set(ids)):
    raise SystemExit('duplicate shard id in manifest')
print(f'Shards enabled: {len(ids)}')
"

FAIL=0

echo "== Auditing shard bench configuration =="
if ! "${PYTHON[@]}" scripts/bench_shards_lib.py audit; then
  FAIL=1
fi

echo "== Resolving workspace packages =="
WORKSPACE_PKGS="$(cargo metadata --format-version 1 --no-deps \
  | "${PYTHON[@]}" -c "
import json, sys
m = json.load(sys.stdin)
members = set(m['workspace_members'])
print('\n'.join(sorted(p['name'] for p in m['packages'] if p['id'] in members)))
")"

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  eval "$line"
  id="$ID"
  package="$PACKAGE"
  features="${FEATURES:-}"
  bench="${BENCH:-}"

  if ! grep -qx "$package" <<<"$WORKSPACE_PKGS"; then
    echo "ERROR: shard $id: package $package is not a workspace member" >&2
    FAIL=1
    continue
  fi

  BENCHES=()
  if [[ -n "$bench" ]]; then
    BENCHES=("$bench")
  else
    mapfile -t BENCHES < <("${PYTHON[@]}" scripts/bench_shards_lib.py criterion-benches "$package" "$features")
    if [[ ${#BENCHES[@]} -eq 0 ]]; then
      echo "ERROR: shard $id: no Criterion bench targets for $package" >&2
      FAIL=1
      continue
    fi
  fi

  for target in "${BENCHES[@]}"; do
    CMD=(cargo bench -p "$package" --bench "$target" --no-run)
    if [[ -n "$features" ]]; then
      CMD+=(--features "$features")
    fi

    echo "  compile-check: $id --bench $target"
    if ! "${CMD[@]}" >/dev/null 2>&1; then
      echo "ERROR: shard $id: cargo bench compile failed for --bench $target" >&2
      "${CMD[@]}" 2>&1 | tail -20 >&2 || true
      FAIL=1
    fi
  done
done < <("${PYTHON[@]}" -c "
import tomllib
from pathlib import Path
for s in tomllib.loads(Path('$MANIFEST').read_text(encoding='utf-8')).get('shard', []):
    if s.get('enabled', True) is False:
        continue
    f = s.get('features', '')
    b = s.get('bench', '')
    print(f\"ID={s['id']!r} PACKAGE={s['package']!r} FEATURES={f!r} BENCH={b!r}\")
")

echo "== Checking for bench targets missing from manifest =="
WARN=0
ORPHAN_WARN="$("${PYTHON[@]}" -c "
import re
import subprocess
import tomllib
from pathlib import Path

root = Path('$ROOT')
manifest = tomllib.loads((root / '.github/benchmark-shards.toml').read_text(encoding='utf-8'))
sharded = {row['package'] for row in manifest.get('shard', [])}

meta = subprocess.run(
    ['cargo', 'metadata', '--format-version', '1', '--no-deps'],
    cwd=root, check=True, capture_output=True, text=True,
).stdout
import json
data = json.loads(meta)
members = set(data['workspace_members'])
bench_re = re.compile(r'^\\[\\[bench\\]\\]', re.MULTILINE)

for pkg in data['packages']:
    if pkg['id'] not in members:
        continue
    path = Path(pkg['manifest_path'])
    if not bench_re.search(path.read_text(encoding='utf-8')):
        continue
    if pkg['name'] not in sharded:
        print(pkg['name'])
")"
while IFS= read -r pkg; do
  [[ -z "$pkg" ]] && continue
  echo "WARN: ${pkg} has [[bench]] but no shard in benchmark-shards.toml" >&2
  WARN=1
done <<<"$ORPHAN_WARN"

if [[ "$FAIL" -ne 0 ]]; then
  echo "validate-bench-shards: FAILED" >&2
  exit 1
fi

if [[ "$WARN" -ne 0 ]]; then
  echo "validate-bench-shards: OK (with warnings)" >&2
else
  echo "validate-bench-shards: OK"
fi
