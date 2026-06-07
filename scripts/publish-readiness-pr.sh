#!/usr/bin/env bash
# PR publish-readiness for new primitive crates.
#
# Full `cargo publish --dry-run` cannot resolve path deps at the new workspace version
# until CD publishes upstream tiers (docs/crates-io-publish.md). Validate manifest pins
# for every crate; run dry-run only when the crate has no in-repo production deps.
set -euo pipefail

PKG="${1:?usage: publish-readiness-pr.sh <package>}"
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

WS_VERSION="$(
  sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml \
    | grep '^version = ' \
    | head -1 \
    | cut -d'"' -f2
)"

MANIFEST="$ROOT/$PKG/Cargo.toml"
if [[ ! -f "$MANIFEST" ]]; then
  echo "ERROR: missing manifest for $PKG at $MANIFEST" >&2
  exit 1
fi

python3 - "$MANIFEST" "$WS_VERSION" "$PKG" <<'PY'
import pathlib
import re
import sys

manifest, ws_version, pkg = sys.argv[1:4]
text = pathlib.Path(manifest).read_text(encoding="utf-8")

if f'version.workspace = true' not in text and '[package]' in text:
    if f'version = "{ws_version}"' not in text:
        raise SystemExit(f"{pkg}: [package] version must match workspace {ws_version}")

sections = ("dependencies", "dev-dependencies", "build-dependencies")
has_workspace_prod = False
for section in sections:
    m = re.search(rf"\[{re.escape(section)}\](.*?)(?=\n\[|\Z)", text, re.DOTALL)
    if not m:
        continue
    block = m.group(1)
    for line in block.splitlines():
        if "path" not in line or "../" not in line:
            continue
        if not re.search(rf'version\s*=\s*"{re.escape(ws_version)}"', line):
            raise SystemExit(
                f"{pkg}: path dependency missing version = \"{ws_version}\":\n  {line.strip()}"
            )
        if section == "dependencies":
            has_workspace_prod = True

cd = (pathlib.Path("Cargo.toml").parent / ".github/workflows/cd.yml").read_text(encoding="utf-8")
if pkg not in re.findall(r'package:\s*"(lib-q[^"]+)"', cd):
    raise SystemExit(f"{pkg}: missing from cd.yml publish-rust jobs")

print(f"manifest pins: OK ({pkg})")

# lib-q-fhe dev-deps reference lib-q-blind-pcs (unpublished until tier 4b).
skip_dry_run = has_workspace_prod or pkg == "lib-q-fhe"
if skip_dry_run:
    reason = (
        "workspace prod deps"
        if has_workspace_prod
        else "dev-deps reference unpublished workspace crate"
    )
    print(f"publish dry-run: skipped ({pkg}: {reason}; validated at CD tier publish)")
    raise SystemExit(0)

import subprocess

subprocess.run(
    ["cargo", "publish", "--dry-run", "--no-verify", "--locked", "-p", pkg],
    check=True,
)
print(f"publish dry-run: OK ({pkg})")
PY
