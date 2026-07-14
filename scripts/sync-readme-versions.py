#!/usr/bin/env python3
"""Keep README version/MSRV strings in sync with the workspace Cargo.toml.

The workspace root `Cargo.toml` (`[workspace.package]`) is the single source of
truth. crates.io renders READMEs as static markdown, so they can't read the
manifest at render time; instead we regenerate/validate the handful of version-
and MSRV-bearing strings from it.

Rewrites, in every README.md (excluding vendored / reference / node_modules /
target trees):

  * lib-q dependency pins        lib-q-foo = "0.0.5"                 -> workspace version
                                 lib-q-foo = { version = "0.0.5" }  -> workspace version
  * Rust-version badge           rustc-1.85+                         -> rustc-<msrv>+
  * MSRV prose                   Rust **1.85**                       -> Rust **<msrv>**
                                 1.85 or higher                      -> <msrv> or higher
                                 lines mentioning MSRV: bare 1.NN    -> <msrv>

Usage:
  python scripts/sync-readme-versions.py --check   # non-zero exit on drift (CI)
  python scripts/sync-readme-versions.py --fix     # rewrite in place
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
EXCLUDE_PARTS = {"reference", "node_modules", "target", "vendor", "pkg-build"}


def read_workspace_meta() -> tuple[str, str]:
    """Return (version, msrv_minor) from [workspace.package] in the root Cargo.toml."""
    text = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    block = re.search(r"\[workspace\.package\](.*?)(?:\n\[|\Z)", text, re.DOTALL)
    if not block:
        sys.exit("could not find [workspace.package] in Cargo.toml")
    body = block.group(1)
    version = re.search(r'^\s*version\s*=\s*"([^"]+)"', body, re.MULTILINE)
    rustver = re.search(r'^\s*rust-version\s*=\s*"([^"]+)"', body, re.MULTILINE)
    if not version or not rustver:
        sys.exit("workspace.package must set both version and rust-version")
    # MSRV is displayed as major.minor (1.96.0 -> 1.96) in badges/prose.
    msrv_full = rustver.group(1)
    msrv_minor = ".".join(msrv_full.split(".")[:2])
    return version.group(1), msrv_minor


def transform(text: str, version: str, msrv: str) -> str:
    # lib-q dependency pins: capture the prefix up to the opening quote, swap the 0.0.x.
    text = re.sub(
        r'(lib-q[\w-]*\s*=\s*(?:\{[^}\n]*?version\s*=\s*)?")0\.0\.\d+(")',
        lambda m: f"{m.group(1)}{version}{m.group(2)}",
        text,
    )
    # Rust-version badge (shields.io): rustc-1.85 -> rustc-<msrv>
    text = re.sub(r"rustc-1\.\d+(\.\d+)?", f"rustc-{msrv}", text)
    # Prose: **1.85** in a "Rust **x**" phrase
    text = re.sub(r"(Rust\s*\*\*)1\.\d+(\*\*)", lambda m: f"{m.group(1)}{msrv}{m.group(2)}", text)
    # Prose: "1.85 or higher"
    text = re.sub(r"1\.\d+(\.\d+)?( or higher)", lambda m: f"{msrv}{m.group(2)}", text)
    # Any line that talks about MSRV: normalise a bare 1.NN token on it.
    def fix_msrv_line(line: str) -> str:
        if "MSRV" in line:
            return re.sub(r"1\.\d+(\.\d+)?", msrv, line)
        return line
    text = "\n".join(fix_msrv_line(l) for l in text.split("\n"))
    return text


def iter_readmes() -> list[pathlib.Path]:
    out = []
    for p in REPO_ROOT.rglob("README.md"):
        rel = p.relative_to(REPO_ROOT)
        if EXCLUDE_PARTS & set(rel.parts):
            continue
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit non-zero if any README is out of sync")
    mode.add_argument("--fix", action="store_true", help="rewrite READMEs in place")
    args = ap.parse_args()

    version, msrv = read_workspace_meta()
    drift: list[pathlib.Path] = []
    for path in iter_readmes():
        original = path.read_text(encoding="utf-8")
        updated = transform(original, version, msrv)
        if updated != original:
            drift.append(path.relative_to(REPO_ROOT))
            if args.fix:
                path.write_text(updated, encoding="utf-8", newline="\n")

    if not drift:
        print(f"READMEs in sync (version {version}, MSRV {msrv}).")
        return 0
    if args.fix:
        print(f"Synced {len(drift)} README(s) to version {version}, MSRV {msrv}:")
        for d in drift:
            print(f"  {d.as_posix()}")
        return 0
    print(f"{len(drift)} README(s) out of sync with version {version} / MSRV {msrv}:", file=sys.stderr)
    for d in drift:
        print(f"  {d.as_posix()}", file=sys.stderr)
    print("Run: python scripts/sync-readme-versions.py --fix", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
