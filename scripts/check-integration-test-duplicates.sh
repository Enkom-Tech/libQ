#!/usr/bin/env bash
# Fail if any tests/*.rs integration crate uses `mod foo;` while tests/foo.rs also exists:
# Cargo would build the same sources twice (two integration test binaries).
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-integration-test-duplicates.sh: python3 is required" >&2
  exit 1
fi

python3 <<'PY'
import re
import sys
from pathlib import Path

root = Path(".").resolve()
mod_decl = re.compile(r"^\s*mod\s+([a-zA-Z0-9_]+)\s*;", re.MULTILINE)
skip_parts = frozenset({"target", "reference"})

issues = []
for tests_dir in root.rglob("tests"):
    if not tests_dir.is_dir():
        continue
    if skip_parts.intersection(tests_dir.parts):
        continue
    top_rs = [p for p in tests_dir.iterdir() if p.suffix == ".rs" and p.is_file()]
    for entry in top_rs:
        text = entry.read_text(encoding="utf-8", errors="replace")
        for m in mod_decl.finditer(text):
            name = m.group(1)
            sibling = tests_dir / f"{name}.rs"
            if sibling.is_file() and sibling.resolve() != entry.resolve():
                issues.append((entry, sibling))

if issues:
    print(
        "Integration test layout error: a tests/*.rs file declares `mod NAME;` "
        "while tests/NAME.rs also exists. Cargo builds both as separate test crates.\n"
        "Fix: move shared code to tests/NAME/mod.rs (no tests/NAME.rs) or merge crates.\n",
        file=sys.stderr,
    )
    for a, b in sorted(set(issues), key=lambda x: str(x[0])):
        print(f"  {a} -> also {b}", file=sys.stderr)
    sys.exit(1)

print("check-integration-test-duplicates: ok")
PY
