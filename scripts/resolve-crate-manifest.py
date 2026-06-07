#!/usr/bin/env python3
"""Resolve a workspace package name to its Cargo.toml path for publish."""
from __future__ import annotations

import pathlib
import re
import sys


def package_name(cargo_toml: pathlib.Path) -> str | None:
    text = cargo_toml.read_text(encoding="utf-8")
    if "[package]" not in text:
        return None
    head = text.split("[package]", 1)[1].split("\n[", 1)[0]
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', head, re.MULTILINE)
    return m.group(1) if m else None


def workspace_members(root: pathlib.Path) -> list[str]:
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r"members\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def resolve(repo_root: pathlib.Path, package: str, working_directory: str) -> pathlib.Path:
    if working_directory != ".":
        candidate = repo_root / working_directory / "Cargo.toml"
        if candidate.is_file():
            return candidate.resolve()

    direct = repo_root / package / "Cargo.toml"
    if direct.is_file():
        return direct.resolve()

    for member in workspace_members(repo_root):
        cargo = repo_root / member / "Cargo.toml"
        if cargo.is_file() and package_name(cargo) == package:
            return cargo.resolve()

    raise SystemExit(f"manifest not found for package {package}")


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: resolve-crate-manifest.py <repo-root> <package> <working-directory>",
            file=sys.stderr,
        )
        return 2
    repo_root = pathlib.Path(sys.argv[1]).resolve()
    package = sys.argv[2]
    working_directory = sys.argv[3]
    print(resolve(repo_root, package, working_directory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
