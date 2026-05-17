#!/usr/bin/env python3
"""
Add version = "0.0.x" to in-repo path dependencies so `cargo publish --verify` passes.
Version must match [workspace.package] version in the root Cargo.toml.
Skips lines that already specify `version =`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

def line_needs_version(line: str) -> bool:
    if "path" not in line or "../" not in line:
        return False
    if "version" in line and re.search(r"version\s*=", line):
        return False
    if line.strip().startswith("#"):
        return False
    return True


def add_version_to_line(line: str, ws_version: str) -> str:
    if not line_needs_version(line):
        return line
    return re.sub(
        r'path\s*=\s*"((?:\.\./)+[^"]+)"',
        rf'path = "\1", version = "{ws_version}"',
        line,
        count=1,
    )


def workspace_version(root: Path) -> str:
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    idx = text.find("[workspace.package]")
    if idx < 0:
        raise RuntimeError("Missing [workspace.package] in root Cargo.toml")
    chunk = text[idx : idx + 1200]
    m = re.search(r"^\s*version\s*=\s*\"([^\"]+)\"", chunk, re.MULTILINE)
    if not m:
        raise RuntimeError("Could not read [workspace.package] version from root Cargo.toml")
    return m.group(1)


def process_file(p: Path, ws_version: str) -> bool:
    text = p.read_text(encoding="utf-8")
    out_lines = []
    changed = False
    for line in text.splitlines(keepends=True):
        if line.endswith("\n"):
            body, nl = line[:-1], "\n"
        else:
            body, nl = line, ""
        new_body = add_version_to_line(body, ws_version)
        if new_body != body:
            changed = True
        out_lines.append(new_body + nl)
    if changed:
        p.write_text("".join(out_lines), encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    ws_version = workspace_version(root)
    skip = {"target", ".git", "node_modules", "reference"}
    changed: list[Path] = []
    for p in root.rglob("Cargo.toml"):
        if any(s in p.parts for s in skip):
            continue
        # Only workspace members and top-level benches/examples (not vendored trees)
        rel = p.relative_to(root)
        if rel.parts[0] not in (
            "lib-q",
            "benches",
            "examples",
        ) and not rel.parts[0].startswith("lib-q-"):
            continue
        if process_file(p, ws_version):
            changed.append(p)
    for c in changed:
        print(f"updated: {c.relative_to(root)}")
    print(f"done: {len(changed)} file(s) updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
