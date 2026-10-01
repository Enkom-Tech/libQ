#!/usr/bin/env bash
set -euo pipefail

# Before an npm package under npm/<name>/package.json can be `npm install`ed and `npm test`ed in
# CI (or locally), any of its dependencies that name an `@lib-q/*` wasm-pack package have to
# resolve. Most already do, from the registry. But a PR that changes the underlying Rust crate --
# e.g. this branch's MlDsa factory-method fix in lib-q-sig -- has to test against the NEW behavior,
# which is not on npm yet, so the dependency version in package.json is bumped ahead of what's
# published (a "-enkNNNN.0" prerelease suffix). `npm install` against the registry then fails with
# ETARGET: "No matching version found for @lib-q/sig@0.0.11-jose.0" -- that is what this script
# exists to avoid.
#
# This is the SAME build cd.yml's `publish-wasm-packages` job runs at release time (wasm-pack
# --target nodejs --release, the exact `features`/`out-dir` that job's matrix uses for that
# working-directory), just pointed at a scratch directory instead of the npm registry, and linked
# in with a `file:` dependency instead of `npm publish`. This script itself never edits the
# caller's npm package's package.json (the one at $1) -- the only package.json it stamps a
# name/version onto is the wasm-pack build output it writes under the scratch directory ($2), and
# the caller is responsible for pointing its own package.json's dependency at the tarball this
# script prints.
#
# Usage: ci-link-local-wasm-companions.sh <npm-package-dir> <scratch-root>
# Prints, to stdout, one "name=path" line per @lib-q/* dependency that was built and linked
# locally (path is the directory `npm install` should be pointed at for that name); nothing is
# printed for a dependency this script leaves for the registry.

ROOT="$(git rev-parse --show-toplevel)"
PKG_DIR="$(cd "$1" && pwd)"
SCRATCH="$2"
mkdir -p "$SCRATCH"

CD_YML="$ROOT/.github/workflows/cd.yml"

PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
[[ -n "$PY_BIN" ]] || { echo "ci-link-local-wasm-companions: no working python3 interpreter" >&2; exit 1; }

# Emit "package-name working-directory features out-dir" for every publish-wasm-packages matrix
# entry, one per line, tab-separated. cd.yml is the source of truth for what CD actually builds;
# duplicating that mapping by hand here would drift the moment a matrix entry changes.
MATRIX="$("$PY_BIN" - "$CD_YML" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
block = text.split("publish-wasm-packages:", 1)[1]
block = block.split("\n  publish-npm-types:", 1)[0]
entries = re.split(r"\n\s*-\s*working-directory:", block)[1:]
for raw in entries:
    entry = "working-directory:" + raw
    def field(name, default=""):
        m = re.search(rf'{name}:\s*"([^"]*)"', entry)
        return m.group(1) if m else default
    wd = field("working-directory")
    name = field("package-name")
    features = field("features")
    out_dir = field("out-dir", "pkg")
    if wd and name:
        print(f"{name}\t{wd}\t{features}\t{out_dir}")
PY
)"

# Which @lib-q/* deps does this npm package actually declare?
DEPS="$("$PY_BIN" - "$PKG_DIR/package.json" <<'PY'
import json, sys
pkg = json.load(open(sys.argv[1], encoding="utf-8"))
deps = {}
deps.update(pkg.get("dependencies") or {})
deps.update(pkg.get("devDependencies") or {})
for name, version in deps.items():
    if name.startswith("@lib-q/"):
        print(f"{name}\t{version}")
PY
)"

[[ -n "$DEPS" ]] || exit 0

WASM_PACK_BIN="$(command -v wasm-pack || true)"
if [[ -z "$WASM_PACK_BIN" ]]; then
  echo "ci-link-local-wasm-companions: installing wasm-pack (cargo install --locked)" >&2
  cargo install wasm-pack --locked
  WASM_PACK_BIN="$(command -v wasm-pack)"
fi

while IFS=$'\t' read -r dep_name dep_version; do
  [[ -n "$dep_name" ]] || continue
  entry="$(printf '%s\n' "$MATRIX" | awk -F'\t' -v n="$dep_name" '$1 == n { print; exit }')"
  if [[ -z "$entry" ]]; then
    # Not a wasm-pack-built package (e.g. @lib-q/types is hand-written TS) -- leave it to npm.
    continue
  fi
  IFS=$'\t' read -r pkg_name working_dir features out_dir <<<"$entry"
  crate_dir="$ROOT/$working_dir"
  [[ -d "$crate_dir" ]] || { echo "ci-link-local-wasm-companions: cd.yml names $working_dir but it does not exist" >&2; exit 1; }

  build_dir="$SCRATCH/$(printf '%s' "$pkg_name" | tr -c 'A-Za-z0-9' '-')"
  echo "ci-link-local-wasm-companions: building $pkg_name from $working_dir (features: ${features:-<default>}) for local test-only use" >&2
  build_args=(build --target nodejs --release -d "$build_dir")
  if [[ -n "$features" ]]; then
    build_args+=(-- --features "$features")
  fi
  ( cd "$crate_dir" && "$WASM_PACK_BIN" "${build_args[@]}" >&2 )

  # Real releases stamp name/version via `npm pkg set` (see .github/actions/npm-publish); match
  # that here so the linked package satisfies the semver range/exact-version the dependant asks for.
  # Strip whatever range operator package.json used (^, ~, >=, or a bare =) down to the plain
  # version -- `${dep_version#^}` alone left a stray `~`/`>=`/`=` in the stamped version string
  # for any dependency pinned with one of those instead of caret.
  pinned_version="$dep_version"
  for op in '>=' '~' '^' '='; do
    pinned_version="${pinned_version#"$op"}"
  done
  ( cd "$build_dir" && npm pkg set name="$pkg_name" version="$pinned_version" >/dev/null )

  # Pack to a tarball rather than pointing `file:` at the build directory itself: `npm install
  # file:<dir>` SYMLINKS node_modules to that directory, and on a Windows/Git-Bash host the path
  # `wasm-pack`/`npm pkg set` wrote (native Windows form) and the path this script's own `mktemp -d`
  # produced (MSYS/posix form, e.g. /c/tmp/...) do not always round-trip through npm's symlink
  # resolution the same way -- the symlink can end up dangling even though both forms name the same
  # directory. A tarball sidesteps that entirely: `npm install file:*.tgz` always extracts a real
  # copy into node_modules, on every OS.
  tarball="$(cd "$build_dir" && npm pack --silent | tail -1)"
  # `npm pkg set dependencies.x=file:<path>` below is a Windows-native npm.exe invocation on a
  # Git-Bash/MSYS host; MSYS's implicit POSIX-to-Windows path translation on that argument
  # sometimes rewrites a `/tmp/...` path it does not recognize as a real mount (e.g. one under
  # `mktemp -d`'s actual %TEMP%) to a literal, nonexistent `C:\tmp\...` instead of the real
  # directory -- silent on `npm pkg set` itself, and only surfaces later as `npm install` failing
  # to find the tarball. `pwd -W` (Git-Bash-only) gives back the native form directly, so the path
  # this script hands to npm is never translated at all. Elsewhere (Linux/macOS CI, no `pwd -W`)
  # the plain POSIX path already is the native form.
  if native_dir="$(cd "$build_dir" && pwd -W 2>/dev/null)"; then
    build_dir="$native_dir"
  fi
  echo "${dep_name}=${build_dir}/${tarball}"
done <<<"$DEPS"
