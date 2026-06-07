#!/usr/bin/env python3
"""Remove workspace dev-dependency lines that are not on crates.io yet at publish time."""
from __future__ import annotations

import pathlib
import re
import sys

# Dev-only workspace crates published in later CD tiers (see .github/workflows/cd.yml).
STRIP_CRATES = frozenset(
    {
        "lib-q-sca-test",  # tier 4
        "lib-q-blind-pcs",  # tier 4b (parallel with lib-q-fhe)
    }
)

DEV_SECTION = re.compile(r"^\[.*dev-dependencies\]\s*$")


def strip_manifest(manifest: pathlib.Path, publishing_pkg: str) -> bool:
    if publishing_pkg in STRIP_CRATES:
        return False

    lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    out: list[str] = []
    in_dev = False
    changed = False

    for line in lines:
        if DEV_SECTION.match(line.strip()):
            in_dev = True
            out.append(line)
            continue
        if in_dev and line.startswith("["):
            in_dev = False
        if in_dev:
            stripped = line.lstrip()
            if any(stripped.startswith(f"{crate} ") for crate in STRIP_CRATES):
                changed = True
                continue
        out.append(line)

    if changed:
        manifest.write_text("".join(out), encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: strip-forward-dev-deps-for-publish.py <package> <manifest>",
            file=sys.stderr,
        )
        return 2

    pkg, manifest = sys.argv[1], pathlib.Path(sys.argv[2])
    if strip_manifest(manifest, pkg):
        print(f"stripped forward dev-deps from {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
