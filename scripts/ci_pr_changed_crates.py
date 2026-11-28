#!/usr/bin/env python3
"""List the workspace crates a pull request changes, one package name per line.

The forge pull-request workflow (.forgejo/workflows/pr.yml) runs `cargo test -p <crate>` for every
crate this prints, so a PR is tested where it changed code without building and testing all of the
workspace's crates on every push. A changed file belongs to the crate whose manifest directory is
the longest prefix of its path, so a file in a nested crate counts for the nested crate only. Files
outside every crate (CI configuration, scripts, top-level docs) select no crate.

What this does NOT select: crates that merely depend on a changed crate. The workflow's fixed KAT
steps and the workspace clippy pass cover the shared primitives; reverse dependencies are tested by
GitHub CI after merge.

Feature-gated tests: `cargo test -p <crate>` uses default features, so a test target with
`required-features` that are off by default (a byte-equality KAT behind an opt-in interop feature,
say) is compiled by the workspace `--all-features` clippy pass but never executed. A crate lists the
extra feature sets its PR tests need in its own manifest, next to the features themselves:

  [package.metadata.libq-ci]
  pr-test-features = ["lazer-compat"]      # one entry per extra `cargo test --features <entry>` run

`--test-runs` prints one line per `cargo test` invocation for the changed crates: `<crate>` for the
default-feature run, then `<crate> <features>` for each declared set.

Usage:
  python3 scripts/ci_pr_changed_crates.py <base-commit>               # diff <base-commit>...HEAD
  python3 scripts/ci_pr_changed_crates.py --test-runs <base-commit>   # crates plus feature runs
  python3 scripts/ci_pr_changed_crates.py --self-test
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys


def crates_for(changed: list[str], crate_dirs: dict[str, str]) -> list[str]:
    """Map repo-relative changed paths to package names (sorted, unique) by longest dir prefix."""
    by_len = sorted(crate_dirs.items(), key=lambda kv: len(kv[1]), reverse=True)
    out = set()
    for path in changed:
        for name, d in by_len:
            if d and (path == d or path.startswith(d + "/")):
                out.add(name)
                break
    return sorted(out)


def pr_test_features(package: dict) -> list[str]:
    """The extra feature sets a package declares under [package.metadata.libq-ci].

    Refuses (ValueError) anything but a list of non-empty strings without whitespace, so a typo in a
    manifest fails the CI step instead of silently selecting nothing or splitting into two words.
    """
    entry = ((package.get("metadata") or {}).get("libq-ci") or {}).get("pr-test-features", [])
    if not isinstance(entry, list) or not all(
        isinstance(f, str) and f and not any(c.isspace() for c in f) for f in entry
    ):
        raise ValueError(
            f"{package.get('name')}: package.metadata.libq-ci.pr-test-features must be a list of "
            f"comma-separated feature strings without spaces, got {entry!r}"
        )
    return list(entry)


def test_runs(crates: list[str], features: dict[str, list[str]]) -> list[str]:
    """One line per `cargo test` invocation: `<crate>`, then `<crate> <features>` per declared set."""
    out = []
    for name in crates:
        out.append(name)
        out.extend(f"{name} {f}" for f in features.get(name, []))
    return out


def workspace_packages(root: pathlib.Path) -> list[dict]:
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout)
    members = set(meta["workspace_members"])
    return [pkg for pkg in meta["packages"] if pkg["id"] in members]


def workspace_crate_dirs(root: pathlib.Path, packages: list[dict]) -> dict[str, str]:
    out = {}
    for pkg in packages:
        d = pathlib.Path(pkg["manifest_path"]).resolve().parent
        out[pkg["name"]] = d.relative_to(root.resolve()).as_posix() if d != root.resolve() else ""
    return out


def self_test() -> bool:
    dirs = {"a": "lib-a", "a-inner": "lib-a/inner", "b": "lib-b", "root": ""}
    cases = [
        (["lib-a/src/x.rs"], ["a"]),
        (["lib-a/inner/src/y.rs"], ["a-inner"]),
        (["lib-a/inner/src/y.rs", "lib-a/Cargo.toml"], ["a", "a-inner"]),
        (["lib-ab/src/z.rs"], []),  # a sibling whose name shares a prefix is not lib-a
        ([".forgejo/workflows/pr.yml", "README.md"], []),  # the root package never matches
        (["lib-b/tests/t.rs", "lib-b/tests/u.rs"], ["b"]),
    ]
    ok = True
    for changed, want in cases:
        got = crates_for(changed, dirs)
        if got != want:
            print(f"  - self-test: {changed} -> {got}, expected {want}")
            ok = False

    feats = {"a": ["x", "x,y"]}
    run_cases = [
        (["a", "b"], ["a", "a x", "a x,y", "b"]),
        (["b"], ["b"]),  # a declared crate that did not change runs nothing
        ([], []),
    ]
    for crates, want in run_cases:
        got = test_runs(crates, feats)
        if got != want:
            print(f"  - self-test: test_runs({crates}) -> {got}, expected {want}")
            ok = False

    meta_cases = [
        ({"name": "p", "metadata": None}, []),
        ({"name": "p", "metadata": {"libq-ci": {"pr-test-features": ["lazer-compat"]}}}, ["lazer-compat"]),
        ({"name": "p", "metadata": {"other": {}}}, []),
    ]
    for pkg, want in meta_cases:
        got = pr_test_features(pkg)
        if got != want:
            print(f"  - self-test: pr_test_features({pkg}) -> {got}, expected {want}")
            ok = False
    for bad in ("lazer-compat", ["a b"], [""], [1]):
        try:
            pr_test_features({"name": "p", "metadata": {"libq-ci": {"pr-test-features": bad}}})
        except ValueError:
            continue
        print(f"  - self-test: pr_test_features accepted malformed {bad!r}")
        ok = False
    return ok


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--self-test"]:
        if self_test():
            print("ci_pr_changed_crates: self-test OK")
            return 0
        return 1
    runs = argv[1:2] == ["--test-runs"]
    args = argv[2:] if runs else argv[1:]
    if len(args) != 1:
        print("usage: ci_pr_changed_crates.py [--test-runs] <base-commit> | --self-test",
              file=sys.stderr)
        return 2
    if not self_test():
        print("ci_pr_changed_crates: SELF-TEST FAILED", file=sys.stderr)
        return 1
    root = pathlib.Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip())
    changed = subprocess.run(
        ["git", "diff", "--name-only", f"{args[0]}...HEAD"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.split()
    packages = workspace_packages(root)
    crates = crates_for(changed, workspace_crate_dirs(root, packages))
    if runs:
        crates = test_runs(crates, {p["name"]: pr_test_features(p) for p in packages})
    for line in crates:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
