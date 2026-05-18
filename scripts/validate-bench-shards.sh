#!/usr/bin/env bash
# Validate benchmark-shards.toml against the workspace.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PYTHON=(python3)
elif command -v py >/dev/null 2>&1; then
  PYTHON=(py -3)
else
  echo "ERROR: python3 or py not found" >&2
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
data = tomllib.loads(Path('$MANIFEST').read_bytes())
ids = [s['id'] for s in data.get('shard', []) if s.get('enabled', True) is not False]
if len(ids) != len(set(ids)):
    raise SystemExit('duplicate shard id in manifest')
print(f'Shards enabled: {len(ids)}')
"

echo "== Resolving workspace packages =="
WORKSPACE_PKGS="$(cargo metadata --format-version 1 --no-deps \
  | "${PYTHON[@]}" -c "import json,sys; m=json.load(sys.stdin); print('\n'.join(sorted(p['name'] for p in m['packages'])))")"

FAIL=0

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

  CMD=(cargo bench -p "$package" --no-run)
  if [[ -n "$features" ]]; then
    CMD+=(--features "$features")
  fi
  if [[ -n "$bench" ]]; then
    CMD+=(--bench "$bench")
  fi

  echo "  compile-check: $id (${CMD[*]})"
  if ! "${CMD[@]}" >/dev/null 2>&1; then
    echo "ERROR: shard $id: cargo bench compile failed" >&2
    "${CMD[@]}" 2>&1 | tail -20 >&2 || true
    FAIL=1
  fi
done < <("${PYTHON[@]}" -c "
import tomllib
from pathlib import Path
for s in tomllib.loads(Path('$MANIFEST').read_bytes()).get('shard', []):
    if s.get('enabled', True) is False:
        continue
    f = s.get('features', '')
    b = s.get('bench', '')
    print(f\"ID={s['id']!r} PACKAGE={s['package']!r} FEATURES={f!r} BENCH={b!r}\")
")

echo "== Checking for bench targets missing from manifest =="
WARN=0
while IFS= read -r toml; do
  pkg="$(grep -E '^name = ' "$(dirname "$toml")/Cargo.toml" 2>/dev/null | head -1 | sed 's/name = "\(.*\)"/\1/')"
  [[ -z "$pkg" ]] && continue
  if grep -q '^\[\[bench\]\]' "$toml" 2>/dev/null; then
    if ! grep -q "^package = \"${pkg}\"" "$MANIFEST"; then
      echo "WARN: ${pkg} has [[bench]] but no shard in benchmark-shards.toml" >&2
      WARN=1
    fi
  fi
done < <(find . -path './target' -prune -o -name 'Cargo.toml' -print 2>/dev/null)

if [[ "$FAIL" -ne 0 ]]; then
  echo "validate-bench-shards: FAILED" >&2
  exit 1
fi

if [[ "$WARN" -ne 0 ]]; then
  echo "validate-bench-shards: OK (with warnings)" >&2
else
  echo "validate-bench-shards: OK"
fi
