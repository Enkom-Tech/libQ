#!/usr/bin/env python3
"""Add [package.metadata.cargo-machete] ignored entries from machete output."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_machete() -> str:
    proc = subprocess.run(
        ["cargo", "machete", "--with-metadata", "--skip-target-dir"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.stdout + proc.stderr


def parse_machete(text: str) -> dict[str, list[str]]:
    crates: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = re.match(r"^(\S+) -- (\./.+):$", line)
        if m:
            current = m.group(2)
            crates[current] = []
            continue
        if current and line.startswith("\t"):
            crates[current].append(line.strip())
    return crates


def insert_metadata(cargo_path: Path, deps: list[str]) -> None:
    content = cargo_path.read_text(encoding="utf-8")
    if "[package.metadata.cargo-machete]" in content:
        return
    block = (
        "\n[package.metadata.cargo-machete]\nignored = [\n"
        + "".join(f'    "{d}",\n' for d in deps)
        + "]\n"
    )
    # Insert after the [package] table (first top-level [section] after [package]).
    lines = content.splitlines(keepends=True)
    insert_idx = len(lines)
    in_package = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if in_package and stripped.startswith("[") and not stripped.startswith("[package"):
            insert_idx = i
            break
    lines.insert(insert_idx, block)
    cargo_path.write_text("".join(lines), encoding="utf-8")
    print(f"Updated {cargo_path.relative_to(ROOT)} ({len(deps)} ignored)")


def main() -> int:
    text = run_machete()
    if "cargo-machete found" not in text:
        print("No unused dependencies reported.")
        return 0
    crates = parse_machete(text)
    for rel, deps in sorted(crates.items()):
        if not deps:
            continue
        path = ROOT / rel.removeprefix("./")
        if path.exists():
            insert_metadata(path, deps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
