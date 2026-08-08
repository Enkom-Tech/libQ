#!/usr/bin/env python3
"""Assert every dependency comes from crates.io or from inside this repository.

WHAT THIS REPLACES
------------------
`.github/workflows/security.yml` had a step named "Validate dependency sources" whose
entire body was:

    echo "🔗 Validating dependency sources..."
    # Ensure all dependencies come from trusted sources
    cargo tree --format "{p} {f}" | grep -v "crates.io" | grep -v "github.com" || true
    echo "✅ Dependency source validation completed"

Three things made that unable to fail:

  1. `cargo tree --format "{p} {f}"` prints a package and its features -- it does not print
     a source at all, so filtering for "crates.io" matched 0 of 1212 output lines. The
     filters were searching for text the command never emits.
  2. Whatever survived was discarded: the pipeline's output went nowhere and `|| true`
     erased its exit status.
  3. The step then echoed a check mark unconditionally, and that fed the workflow's
     "Overall Security Status: PASSED".

Even had the filters matched, `grep -v "github.com"` would have *excluded* git dependencies
from the report -- exactly the category the check exists to find.

WHAT IT CHECKS NOW
------------------
`cargo metadata` reports a `source` per package: null for workspace and path members, and
otherwise the registry or VCS it came from. A dependency is acceptable when it is either

  * from the crates.io registry, or
  * local to this repository (a workspace member or a path dependency inside the repo).

Anything else fails:

  * `git+https://...`   an unpublished revision. Not immutable in the way a registry
                        release is, cannot be vendored by `cargo vendor` the same way, and
                        for a cryptography library means shipping code no crates.io release
                        audit ever saw.
  * a non-crates.io registry, which consumers will not have configured.
  * a path dependency resolving OUTSIDE the repository, which builds only on the machine
    that has that directory.

Usage:
    python3 security_check_dependency_sources.py [REPO_ROOT]
    python3 security_check_dependency_sources.py --self-test
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def classify(package: dict, root: Path) -> tuple[str, str] | None:
    """Return (severity, message) when `package` is not from an acceptable source."""
    name = package.get("name", "<unnamed>")
    version = package.get("version", "?")
    source = package.get("source")

    if source is None:
        # Workspace member or path dependency. Acceptable only if it lives in the repo.
        manifest = package.get("manifest_path")
        if not manifest:
            return ("FAIL", f"{name} {version}: local package with no manifest_path")
        try:
            Path(manifest).resolve().relative_to(root)
        except ValueError:
            return (
                "FAIL",
                f"{name} {version}: path dependency outside the repository ({manifest}); "
                "this builds only where that directory exists",
            )
        return None

    if source == CRATES_IO:
        return None

    if source.startswith("git+"):
        return ("FAIL", f"{name} {version}: git dependency ({source})")

    return ("FAIL", f"{name} {version}: non-crates.io source ({source})")


def load_metadata(root: Path) -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out)


def check(packages: list[dict], root: Path) -> tuple[int, int]:
    """Print findings. Returns (failures, registry_count)."""
    failures = 0
    registry = 0
    local = 0
    for package in sorted(packages, key=lambda p: (p.get("name", ""), p.get("version", ""))):
        verdict = classify(package, root)
        if verdict is None:
            if package.get("source") == CRATES_IO:
                registry += 1
            else:
                local += 1
            continue
        severity, message = verdict
        print(f"  {severity}: {message}")
        failures += 1

    print(f"  {registry} crates.io dependencies, {local} local to this repo, {failures} rejected.")
    return failures, registry


SELF_TEST_PACKAGES = [
    {"name": "ok-registry", "version": "1.0.0", "source": CRATES_IO,
     "manifest_path": "/elsewhere/ok/Cargo.toml"},
    {"name": "ok-member", "version": "0.1.0", "source": None,
     "manifest_path": "__ROOT__/lib-q-thing/Cargo.toml"},
    {"name": "bad-git", "version": "0.1.0", "source": "git+https://github.com/x/y?rev=abc#abc",
     "manifest_path": "/elsewhere/bad/Cargo.toml"},
    {"name": "bad-registry", "version": "0.1.0", "source": "registry+https://example.com/index",
     "manifest_path": "/elsewhere/bad2/Cargo.toml"},
    {"name": "bad-path", "version": "0.1.0", "source": None,
     "manifest_path": "__OUTSIDE__/sibling/Cargo.toml"},
]


def self_test() -> int:
    """Prove each rejection fires, and that the two acceptable shapes do not.

    Load-bearing constructs:
      ok-registry   a crates.io dependency must NOT fire
      ok-member     a path package inside the repo must NOT fire
      bad-git       a git dependency must fire (the old grep -v actively hid these)
      bad-registry  an alternate registry must fire
      bad-path      a path dependency outside the repo must fire
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve() / "repo"
        outside = Path(tmp).resolve() / "outside"
        root.mkdir()
        outside.mkdir()

        packages = []
        for entry in SELF_TEST_PACKAGES:
            item = dict(entry)
            item["manifest_path"] = (
                item["manifest_path"]
                .replace("__ROOT__", str(root))
                .replace("__OUTSIDE__", str(outside))
            )
            packages.append(item)

        fired = {
            p["name"]: classify(p, root) is not None
            for p in packages
        }

    expected = {
        "ok-registry": False,
        "ok-member": False,
        "bad-git": True,
        "bad-registry": True,
        "bad-path": True,
    }
    if fired != expected:
        print("SELF-TEST FAILED -- the dependency-source check is not detecting what it claims:")
        for name, want in expected.items():
            if fired.get(name) != want:
                print(f"  - {name}: expected fired={want}, got fired={fired.get(name)}")
        return 1
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    root = (Path(argv[1]) if len(argv) > 1 else Path.cwd()).resolve()
    try:
        metadata = load_metadata(root)
    except subprocess.CalledProcessError as exc:
        print(f"  FAIL: cargo metadata failed: {exc.stderr.strip().splitlines()[-1:] or exc}")
        return 1
    failures, _ = check(metadata.get("packages", []), root)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
