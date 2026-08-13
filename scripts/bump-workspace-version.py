#!/usr/bin/env python3
"""Bump every live version pin in the workspace from one release to the next.

WHY THIS EXISTS
---------------
`[workspace.package] version` is inherited, but this workspace ALSO carries hundreds of explicit
`version = "X.Y.Z"` pins on internal path dependencies (434 of them at 0.0.11), because a path
dependency without a version is stripped from the published manifest and would break consumers.
Bumping those by hand is not viable, and missing one is not a build error -- `cargo publish` fails
on it mid-release, after earlier crates are already immutable on crates.io.

WHAT IT TOUCHES, AND WHAT IT DELIBERATELY DOES NOT
---------------------------------------------------
  * Cargo.toml under the workspace  -- REWRITTEN. The exact token `version = "<from>"`, any spacing.
  * npm/**/package.json             -- REWRITTEN with --npm. These drift silently: CD overwrites the
                                       version at publish time via `npm pkg set version=`, so a
                                       stale number in git is invisible until someone reads the file.
                                       At 0.0.11, npm/lib-q-types/package.json still said "0.0.2".
  * docs / README / *.md / *.sh     -- REPORTED ONLY, never rewritten. Most matches are HISTORY
                                       ("fixed in 0.0.10", a CHANGELOG heading, a compatibility
                                       statement) and bumping them rewrites the past. Some are live
                                       install snippets that must move. Telling them apart needs
                                       judgment, so this prints the candidates with file:line and
                                       leaves the edit to a human.

  reference/ is excluded: vendored upstream crates are versioned independently of this workspace.

THE TRAP THE REPORT MODE EXISTS FOR: at 0.0.11 two doc pins were CORRECT to leave at 0.0.10 --
lib-q-hqc/SECURITY.md and lib-q-types/src/hqc.rs both say `lib-q-types <= 0.0.10`, describing a
breaking change that ships IN 0.0.11. A blanket search-and-replace silently falsifies both.

Usage:
  python3 scripts/bump-workspace-version.py --to 0.0.12                  # dry run, infers --from
  python3 scripts/bump-workspace-version.py --to 0.0.12 --apply --npm
  python3 scripts/bump-workspace-version.py --to 0.0.12 --apply --npm --report-docs
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"reference", "target", ".git", "scratchpad", "node_modules", "pkg"}
DOC_SUFFIXES = {".md", ".sh", ".yml", ".yaml", ".rs", ".ps1", ".toml", ".json", ".mjs", ".ts"}


def skipped(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts)


def workspace_version() -> str | None:
    """Read `version` from the root Cargo.toml's [workspace.package] block."""
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    block = re.search(r"^\[workspace\.package\](.*?)(?=^\[)", text, re.S | re.M)
    if not block:
        return None
    m = re.search(r'^version\s*=\s*"([^"]+)"', block.group(1), re.M)
    return m.group(1) if m else None


def bump_manifests(old: str, new: str, apply: bool) -> tuple[int, int]:
    pat = re.compile(r'(version\s*=\s*")' + re.escape(old) + r'(")')
    files = hits = 0
    for man in sorted(ROOT.rglob("Cargo.toml")):
        if skipped(man):
            continue
        text = man.read_text(encoding="utf-8")
        new_text, n = pat.subn(r"\g<1>" + new + r"\g<2>", text)
        if not n:
            continue
        files += 1
        hits += n
        print(f"  {n:4d}  {man.relative_to(ROOT).as_posix()}")
        if apply:
            man.write_text(new_text, encoding="utf-8")
    return files, hits


def bump_npm(old: str, new: str, apply: bool) -> int:
    """Bump the top-level "version" of each npm/**/package.json.

    Matches ANY current value, not just `old`: these drift out of step with the workspace precisely
    because nothing reads them, so requiring them to already be at `old` would skip the stale ones
    that most need fixing. Each pre-existing value is printed so a surprise is visible.
    """
    pat = re.compile(r'^(\s*"version"\s*:\s*")([^"]+)(")', re.M)
    changed = 0
    for pkg in sorted((ROOT / "npm").rglob("package.json")):
        if skipped(pkg):
            continue
        text = pkg.read_text(encoding="utf-8")
        m = pat.search(text)
        if not m or m.group(2) == new:
            continue
        note = "" if m.group(2) == old else f"   <-- NOT at {old}; was adrift"
        print(f"  {m.group(2):>10} -> {new}  {pkg.relative_to(ROOT).as_posix()}{note}")
        changed += 1
        if apply:
            pkg.write_text(pat.sub(r"\g<1>" + new + r"\g<3>", text, count=1), encoding="utf-8")
    return changed


def report_docs(old: str) -> int:
    """Print every remaining mention of `old` outside manifests. NEVER rewrites."""
    found = 0
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in DOC_SUFFIXES or skipped(path):
            continue
        if path.name in ("Cargo.toml", "Cargo.lock"):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, 1):
            if old in line:
                print(f"  {path.relative_to(ROOT).as_posix()}:{i}: {line.strip()[:110]}")
                found += 1
    return found


def residual_manifests(old: str) -> list[str]:
    out = []
    for man in sorted(ROOT.rglob("Cargo.toml")):
        if skipped(man):
            continue
        for i, line in enumerate(man.read_text(encoding="utf-8").splitlines(), 1):
            if old in line:
                out.append(f"{man.relative_to(ROOT).as_posix()}:{i}: {line.strip()}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Bump workspace version pins.")
    ap.add_argument("--to", required=True, help="new version, e.g. 0.0.12")
    ap.add_argument("--from", dest="frm", help="current version (default: [workspace.package] version)")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    ap.add_argument("--npm", action="store_true", help="also bump npm/**/package.json")
    ap.add_argument("--report-docs", action="store_true",
                    help="list remaining mentions outside manifests for MANUAL review")
    args = ap.parse_args()

    old = args.frm or workspace_version()
    if not old:
        print("could not determine the current version; pass --from", file=sys.stderr)
        return 1
    if old == args.to:
        print(f"--from and --to are both {old}; nothing to do", file=sys.stderr)
        return 1

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"{mode}: {old} -> {args.to}\n\nCargo.toml pins:")
    files, hits = bump_manifests(old, args.to, args.apply)
    print(f"  = {hits} pin(s) across {files} manifest(s)")

    if args.npm:
        print("\nnpm package.json versions:")
        n = bump_npm(old, args.to, args.apply)
        print(f"  = {n} package(s)")

    # Residual check. Only meaningful after --apply; a dry run has of course changed nothing.
    if args.apply:
        left = residual_manifests(old)
        if left:
            print(f"\nRESIDUAL {old} still in manifests ({len(left)}) -- these were NOT the "
                  f"`version = \"...\"` form and need a look:")
            for entry in left:
                print("  " + entry)
        else:
            print(f"\nNo residual {old} in workspace manifests.")

    if args.report_docs:
        print(f"\nMentions of {old} OUTSIDE manifests -- REVIEW BY HAND, do not blanket-replace.")
        print("A live install snippet must move; a CHANGELOG entry, a 'fixed in' note or a")
        print("compatibility statement like 'lib-q-types <= 0.0.10' must NOT.")
        found = report_docs(old)
        print(f"  = {found} line(s) to triage")

    if not args.apply:
        print("\n(dry run -- re-run with --apply to write)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
