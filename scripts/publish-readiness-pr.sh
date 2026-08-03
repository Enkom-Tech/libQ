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

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute (same probe as scripts/ci-guard-*.sh).
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ERROR: publish-readiness-pr.sh needs a working python3 interpreter" >&2
  exit 1
fi

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

"$PY_BIN" - "$MANIFEST" "$WS_VERSION" "$PKG" <<'PY'
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

# cd.yml publishes a crate in one of two shapes: a quoted matrix entry (`- package: "lib-q-foo"`)
# or an unquoted single-package step (`package: lib-q-foo`). The old check here matched only the
# quoted form, so 20 of cd.yml's 80 crates would have been reported "missing from cd.yml" — the
# gate was self-consistent only because every crate ci.yml actually guards happened to be a quoted
# entry. Moving any of them to a single-package job would have false-failed this gate. Resolve the
# list through the shared derivation instead of re-implementing the match.
sys.path.insert(0, str(pathlib.Path("scripts").resolve()))
from cd_publish_manifest import crate_names  # noqa: E402

published = crate_names(pathlib.Path("."))
if pkg not in published:
    raise SystemExit(
        f"{pkg}: missing from cd.yml publish-rust jobs "
        f"(cd.yml publishes {len(published)} crates; add it to a publish-rust-* job)"
    )

print(f"manifest pins: OK ({pkg})")

if has_workspace_prod:
    print(
        f"publish dry-run: skipped ({pkg}: workspace prod deps; "
        "validated at CD tier publish)"
    )
    raise SystemExit(0)

import subprocess

subprocess.run(
    ["cargo", "publish", "--dry-run", "--no-verify", "--locked", "-p", pkg],
    check=True,
)
print(f"publish dry-run: OK ({pkg})")
PY
