#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

python3 - <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(".")
workspace_toml = (root / "Cargo.toml").read_text(encoding="utf-8")

def extract_array(name: str) -> set[str]:
    m = re.search(rf"{name}\s*=\s*\[(.*?)\]", workspace_toml, re.DOTALL)
    if not m:
        return set()
    return set(re.findall(r'"([^"]+)"', m.group(1)))

members = extract_array("members")
exclude = extract_array("exclude")
workspace_manifests = {(root / member / "Cargo.toml").resolve() for member in members}
excluded_manifests = {(root / item / "Cargo.toml").resolve() for item in exclude}
allowed_untracked_dirs = {"benches"}

untracked = []

for child in root.iterdir():
    if not child.is_dir():
        continue
    cargo = child / "Cargo.toml"
    if not cargo.is_file():
        continue
    abs_manifest = cargo.resolve()
    txt = cargo.read_text(encoding="utf-8")
    if "[package]" not in txt:
        continue
    if abs_manifest in excluded_manifests:
        continue
    if child.name in allowed_untracked_dirs:
        continue
    if abs_manifest not in workspace_manifests:
        untracked.append(cargo.parent.relative_to(root).as_posix())

if untracked:
    print("ERROR: Found Cargo crates not tracked by workspace metadata:", file=sys.stderr)
    for item in sorted(set(untracked)):
        print(f"  - {item}", file=sys.stderr)
    print(
        "Add each crate directory to [workspace].members or [workspace].exclude in Cargo.toml.",
        file=sys.stderr,
    )
    sys.exit(1)

print("Workspace crate membership guard: OK")
PY

python3 - <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(".")
workspace_toml = (root / "Cargo.toml").read_text(encoding="utf-8")
m = re.search(r"members\s*=\s*\[(.*?)\]", workspace_toml, re.DOTALL)
if not m:
    print("ERROR: could not parse [workspace].members", file=sys.stderr)
    sys.exit(1)
members = [x for x in re.findall(r'"([^"]+)"', m.group(1)) if x != "examples"]


def package_name(member_path: str) -> str:
    cargo = root / member_path / "Cargo.toml"
    txt = cargo.read_text(encoding="utf-8")
    if "[package]" not in txt:
        raise RuntimeError(f"missing [package] in {cargo}")
    after = txt.split("[package]", 1)[1]
    head = re.split(r"\n\[", after, maxsplit=1)[0]
    n = re.search(r"^name\s*=\s*\"([^\"]+)\"", head, re.MULTILINE)
    if not n:
        raise RuntimeError(f"missing name in [package] for {cargo}")
    return n.group(1)


def is_publishable(member_path: str) -> bool:
    """Check if a crate should be published (publish != false)."""
    cargo = root / member_path / "Cargo.toml"
    txt = cargo.read_text(encoding="utf-8")
    if "[package]" not in txt:
        return True
    after = txt.split("[package]", 1)[1]
    head = re.split(r"\n\[", after, maxsplit=1)[0]
    # Check for `publish = false`
    pub = re.search(r"^publish\s*=\s*(false|true)", head, re.MULTILINE)
    if pub and pub.group(1) == "false":
        return False
    return True


expected: set[str] = set()
for mem in members:
    if not (root / mem / "Cargo.toml").is_file():
        print(f"ERROR: workspace member has no Cargo.toml: {mem}", file=sys.stderr)
        sys.exit(1)
    if is_publishable(mem):
        expected.add(package_name(mem))

cd_text = (root / ".github" / "workflows" / "cd.yml").read_text(encoding="utf-8")
published: set[str] = set()
for mm in re.finditer(r"^\s*-\s*package:\s*\"([^\"]+)\"", cd_text, re.MULTILINE):
    published.add(mm.group(1))
for mm in re.finditer(r"^\s+package:\s+(lib-q(?:[\w-]+)?)\s*$", cd_text, re.MULTILINE):
    published.add(mm.group(1))

missing = sorted(expected - published)
if missing:
    print(
        "ERROR: workspace crates missing from .github/workflows/cd.yml publish-rust jobs:",
        file=sys.stderr,
    )
    for name in missing:
        print(f"  - {name}", file=sys.stderr)
    print(
        "Add each crate to a publish-rust-* matrix (or single-crate publish step) in cd.yml.",
        file=sys.stderr,
    )
    sys.exit(1)

print("crates.io publish manifest guard: OK")
PY

npm_dirs=()
for p in "$ROOT"/*/package.json "$ROOT"/npm/*/package.json; do
  [[ -f "$p" ]] || continue
  npm_dirs+=("$p")
done

if [[ ${#npm_dirs[@]} -eq 0 ]]; then
  echo "npm package guard: no package.json files found"
else
echo "npm package guard: validating ${#npm_dirs[@]} package(s)"
for pkg_json in "${npm_dirs[@]}"; do
  dir="$(dirname "$pkg_json")"
  echo "-> validating npm package in $dir"
  pushd "$dir" > /dev/null
  if [[ -f package-lock.json ]]; then
    npm ci --ignore-scripts --no-audit --no-fund
  else
    npm install --ignore-scripts --no-audit --no-fund --package-lock=false
  fi
  npm run -s lint --if-present
  npm run -s test --if-present
  npm run -s build --if-present
  popd > /dev/null
done

echo "npm package guard: OK"
fi

python3 - <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(".")
cd = (root / ".github" / "workflows" / "cd.yml").read_text(encoding="utf-8")
block = cd.split("publish-wasm-packages:", 1)[1] if "publish-wasm-packages:" in cd else ""
# Matrix entries under publish-wasm-packages use `working-directory: "lib-q-..."` plus "." for lib-q.
wasm_dirs = set(m.group(1) for m in re.finditer(r"working-directory:\s*\"([^\"]+)\"", block))
workspace_toml = (root / "Cargo.toml").read_text(encoding="utf-8")
members_match = re.search(r"members\s*=\s*\[(.*?)\]", workspace_toml, re.DOTALL)
members = [] if not members_match else [m for m in re.findall(r'"([^"]+)"', members_match.group(1)) if m != "examples"]


def has_wasm_pack_release_metadata(txt: str) -> bool:
    """Crates that tune `wasm-pack` releases are expected to appear in cd.yml `publish-wasm-packages`."""
    return "[package.metadata.wasm-pack" in txt


required = set()
for mem in members:
    cargo = root / mem / "Cargo.toml"
    if not cargo.is_file():
        continue
    txt = cargo.read_text(encoding="utf-8")
    if has_wasm_pack_release_metadata(txt):
        required.add(mem)

for mem in list(required):
    if mem.startswith("examples/"):
        required.discard(mem)

# lib-q-core exposes lower-level Rust/WASM internals but is not an npm package root.
required.discard("lib-q-core")
present = set(wasm_dirs)
if "." in present:
    present.add("lib-q")

missing = sorted(required - present)
if missing:
    print(
        "ERROR: crates with `[package.metadata.wasm-pack]` are missing from cd.yml publish-wasm-packages matrix:",
        file=sys.stderr,
    )
    for mem in missing:
        print(f"  - {mem}", file=sys.stderr)
    print(
        "Add each crate to publish-wasm-packages (working-directory matrix entry).",
        file=sys.stderr,
    )
    sys.exit(1)

print("WASM npm coverage guard: OK")
PY
