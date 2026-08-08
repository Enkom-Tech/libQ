#!/usr/bin/env python3
"""Fail when a published crate gains no coverage floor and nobody recorded why.

THE GAP THIS FREEZES
--------------------
Coverage in this repo is gated by NAME, not by membership of the workspace:

  * `.github/workflows/pr.yml` builds `ALL_CRATES` from four hardcoded lists, walks it for
    the first crate the PR touched, and runs coverage for that ONE crate against a
    per-crate threshold (default 70).
  * `.github/workflows/coverage.yml` walks its own CORE/CRYPTO/UTIL lists on a schedule.

A crate whose name is in none of those lists is never measured against any floor. Nothing
reports this: the "Test Coverage" workflow goes green either way, because a crate it does
not know about cannot lower a number it does not compute. OBSERVED 2026-08-08: 45 names
are gated, and 31 published crates are outside all of them -- among them lib-q-saturnin,
lib-q-hqc, lib-q-slh-dsa, lib-q-mayo and lib-q-zk-encryption-proof.

WHY THIS GUARD RATCHETS INSTEAD OF DEMANDING A FLOOR FOR EVERYTHING
--------------------------------------------------------------------
Adding all 31 to the gated lists is not a free edit. The per-crate coverage step already
runs ~65 minutes for 18 crates under debug tarpaulin, and several of the absentees are
absent for a stated reason -- coverage.yml records that the heavy lattice crates
(lib-q-dkg, lib-q-threshold-raccoon, lib-q-threshold-kem-lattice, lib-q-blind-token) have
keygen far too slow to instrument. Silently tripling the job's runtime is a worse outcome
than the gap.

So this does not fix the gap; it stops it growing invisibly. Every published crate must
either be gated somewhere or appear in scripts/coverage-floor-exemptions.txt with a reason.
A new published crate fails until someone decides which it is. An exemption for a crate
that has since been gated also fails, so the file cannot rot.

WHAT "GATED" MEANS HERE, AND WHAT THIS DOES NOT CHECK
-------------------------------------------------------
Gated means the crate's name appears in a `*_CRATES="..."` list or as an explicit
`--crate <name>` argument in a workflow. That is how the workflows themselves decide
scope, so it is the same predicate rather than a re-derivation of one.

It is a NAME check and deliberately nothing more. It does not check that the threshold is
meaningful, that the crate's tests are good, or that the gated run actually executes -- a
crate gated at `--threshold 0` counts as gated here while enforcing nothing. Those are
separate questions; conflating them into this guard would make its verdict mean something
fuzzier than it says. Related, and also not checked: pr.yml `break`s at the first affected
crate, so a PR touching two gated crates only measures one.

Usage:
    python3 ci_guard_coverage_floors.py [REPO_ROOT]
    python3 ci_guard_coverage_floors.py --self-test
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

EXEMPTIONS_NAME = "coverage-floor-exemptions.txt"

CRATE_LIST_RE = re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*CRATES\s*=\s*"([^"]*)"', re.M)
CRATE_ARG_RE = re.compile(r'--crate\s+"?([A-Za-z0-9_-]+)"?')
# pr.yml selects the crate to measure into $AFFECTED, and its fallback branches assign a
# name directly rather than reading one out of a list:
#     AFFECTED="lib-q"        (workspace root or the umbrella crate changed)
#     AFFECTED="lib-q-core"   (nothing else identified)
# Both are genuine gates -- the crate is measured against the case statement's threshold --
# so a guard that only reads the lists reports them as unprotected. It did, on the first
# run here, naming lib-q as ungated when a root-file change measures it at 70.
AFFECTED_RE = re.compile(r'AFFECTED\s*=\s*"([A-Za-z0-9_-]+)"')
PUBLISH_FALSE_RE = re.compile(r'^\s*publish\s*=\s*false', re.M)


def gated_names(workflows_dir: Path) -> set[str]:
    """Crate names any workflow measures coverage for."""
    names: set[str] = set()
    for workflow in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
        text = workflow.read_text(encoding="utf-8", errors="replace")
        for match in CRATE_LIST_RE.finditer(text):
            names.update(match.group(1).split())
        for match in CRATE_ARG_RE.finditer(text):
            names.add(match.group(1))
        for match in AFFECTED_RE.finditer(text):
            names.add(match.group(1))
    # Shell expansions like `--crate "$crate"` are captured by the list branch already.
    return {n for n in names if n.startswith("lib-q") and "$" not in n}


def published_crates(root: Path) -> dict[str, Path]:
    """Workspace members without `publish = false`, mapped to their manifest."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout
    result: dict[str, Path] = {}
    for package in json.loads(out)["packages"]:
        manifest = Path(package["manifest_path"])
        text = manifest.read_text(encoding="utf-8", errors="replace")
        if PUBLISH_FALSE_RE.search(text):
            continue
        result[package["name"]] = manifest
    return result


def parse_exemptions(path: Path) -> tuple[dict[str, str], list[str]]:
    entries: dict[str, str] = {}
    errors: list[str] = []
    if not path.exists():
        return entries, [f"exemptions file not found: {path}"]
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 2 or not parts[0] or not parts[1]:
            errors.append(f"{path.name}:{lineno}: expected `<crate> | <reason>`, got: {line}")
            continue
        entries[parts[0]] = parts[1]
    return entries, errors


def evaluate(published: set[str], gated: set[str], exempt: set[str]):
    """Returns (ungated_and_unrecorded, stale_exemptions)."""
    ungated = published - gated
    return sorted(ungated - exempt), sorted(exempt & gated)


def run(root: Path, exemptions_path: Path) -> int:
    published = published_crates(root)
    gated = gated_names(root / ".github" / "workflows")
    exempt, errors = parse_exemptions(exemptions_path)

    for err in errors:
        print(f"  FAIL: {err}")

    unrecorded, stale = evaluate(set(published), gated, set(exempt))

    for name in unrecorded:
        print(f"  FAIL: {name} is published but has no coverage floor in any workflow.")
        print("        Either add it to a *_CRATES list (mind the job's runtime budget), or")
        print(f"        record it in {EXEMPTIONS_NAME} as:  {name} | <why not>")

    for name in stale:
        print(f"  FAIL: {EXEMPTIONS_NAME} exempts {name}, which is now gated. Remove the line.")

    ungated_total = len(set(published) - gated)
    print(
        f"  {len(published)} published crates, {len(gated)} gated names, "
        f"{ungated_total} without a floor ({len(exempt)} recorded, {len(unrecorded)} unrecorded)."
    )
    return 1 if (errors or unrecorded or stale) else 0


def self_test() -> int:
    """Prove each verdict fires. Load-bearing constructs:

      new-unrecorded  a published crate in no list and no exemption must FAIL
      stale-exempt    an exemption for a now-gated crate must FAIL
      gated-by-list   a crate named in a *_CRATES list must NOT fire
      gated-by-arg    a crate named via `--crate <name>` must NOT fire
      gated-by-affected  a crate assigned to $AFFECTED must NOT fire
      recorded        an exempted, ungated crate must NOT fire
      malformed line  an exemptions line without a reason must FAIL
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "a.yml").write_text(
            'jobs:\n  x:\n    steps:\n      - run: |\n'
            '          CORE_CRATES="lib-q-gated-by-list lib-q-was-exempt"\n'
            '          bash scripts/run-coverage.sh --crate lib-q-gated-by-arg --threshold 70\n'
            '          bash scripts/run-coverage.sh --crate "$crate" --threshold 70\n'
            '          AFFECTED="lib-q-gated-by-affected"\n',
            encoding="utf-8",
        )
        exemptions = root / EXEMPTIONS_NAME
        exemptions.write_text(
            "# fixture\n"
            "lib-q-recorded | fixture: too slow to instrument\n"
            "lib-q-was-exempt | fixture: this one is gated now, so this line is stale\n"
            "lib-q-broken-line\n",
            encoding="utf-8",
        )

        gated = gated_names(workflows)
        exempt, errors = parse_exemptions(exemptions)
        published = {
            "lib-q-gated-by-list", "lib-q-gated-by-arg", "lib-q-gated-by-affected",
            "lib-q-was-exempt", "lib-q-recorded", "lib-q-new-unrecorded",
        }
        unrecorded, stale = evaluate(published, gated, set(exempt))

        problems = []
        if "$crate" in gated or any("$" in g for g in gated):
            problems.append(f"shell expansions must not be treated as crate names: {sorted(gated)}")
        if gated != {"lib-q-gated-by-list", "lib-q-was-exempt", "lib-q-gated-by-arg",
                     "lib-q-gated-by-affected"}:
            problems.append(f"gated-set mismatch: {sorted(gated)}")
        if unrecorded != ["lib-q-new-unrecorded"]:
            problems.append(f"unrecorded mismatch: {unrecorded}")
        if stale != ["lib-q-was-exempt"]:
            problems.append(f"stale mismatch: {stale}")
        if not errors:
            problems.append("a malformed exemptions line must be reported")

        if problems:
            print("SELF-TEST FAILED -- the coverage-floor guard is not detecting what it claims:")
            for p in problems:
                print(f"  - {p}")
            return 1
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    root = (Path(argv[1]) if len(argv) > 1 else Path.cwd()).resolve()
    return run(root, Path(__file__).resolve().parent / EXEMPTIONS_NAME)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
