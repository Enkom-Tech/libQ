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

Usage:
  python3 scripts/ci_pr_changed_crates.py <base-commit>   # diff <base-commit>...HEAD
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


def workspace_crate_dirs(root: pathlib.Path) -> dict[str, str]:
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout)
    members = set(meta["workspace_members"])
    out = {}
    for pkg in meta["packages"]:
        if pkg["id"] not in members:
            continue
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
    return ok


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--self-test"]:
        if self_test():
            print("ci_pr_changed_crates: self-test OK")
            return 0
        return 1
    if len(argv) != 2:
        print("usage: ci_pr_changed_crates.py <base-commit> | --self-test", file=sys.stderr)
        return 2
    if not self_test():
        print("ci_pr_changed_crates: SELF-TEST FAILED", file=sys.stderr)
        return 1
    root = pathlib.Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip())
    changed = subprocess.run(
        ["git", "diff", "--name-only", f"{argv[1]}...HEAD"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.split()
    for name in crates_for(changed, workspace_crate_dirs(root)):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
