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

import re
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
# coverage.yml's `extended-coverage` job carries its crate lists in a build matrix rather
# than a shell variable:
#     - shard: aead-and-primitives
#       crates: "lib-q-saturnin lib-q-rocca-s ..."
# and then loops `--crate "$crate"`, which is a shell expansion this guard deliberately
# ignores. Without this pattern all 23 crates that job gates would read as ungated.
MATRIX_CRATES_RE = re.compile(r'^\s*crates\s*:\s*"([^"]*)"', re.M)
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
        for match in MATRIX_CRATES_RE.finditer(text):
            names.update(match.group(1).split())
    # Shell expansions like `--crate "$crate"` are captured by the list branch already.
    return {n for n in names if n.startswith("lib-q") and "$" not in n}


def workspace_members(root: Path) -> list[Path]:
    """Member directories from the root manifest's `[workspace] members` array.

    Parsed rather than obtained from `cargo metadata` ON PURPOSE. This guard runs in
    ci.yml's core-validation, which has no Setup Rust step -- it is a job of static checks
    that never needs a toolchain. Invoking cargo there would make rust-toolchain.toml's
    pinned nightly-2026-07-24 (plus four cross targets) download on a job that currently
    needs none of it, to answer a question that is written down in a TOML array.
    """
    text = (root / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
    match = re.search(r'^\s*members\s*=\s*\[(.*?)\]', text, re.S | re.M)
    if not match:
        return []
    members: list[Path] = []
    for entry in re.findall(r'"([^"]+)"', match.group(1)):
        if "*" in entry:
            # Globs are legal in members; expand so a future one is not silently dropped.
            members.extend(p for p in sorted(root.glob(entry)) if (p / "Cargo.toml").exists())
        else:
            members.append(root / entry)

    # A path dependency nested inside a member is pulled into the workspace by cargo even
    # though it is never named in `members`. That is not an edge case here: the five
    # lib-q-fn-dsa/fn-dsa-* crates are all published and all arrive this way, and an
    # earlier version of this function missed every one of them (72 crates found against
    # cargo metadata's 77). Walk each member for nested manifests.
    nested: list[Path] = []
    for member in members:
        if not member.is_dir():
            continue
        for manifest in sorted(member.rglob("Cargo.toml")):
            if manifest.parent == member:
                continue
            if "target" in manifest.relative_to(member).parts:
                continue
            nested.append(manifest.parent)

    seen = set()
    ordered = []
    for path in members + nested:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            ordered.append(path)
    return ordered


def published_crates(root: Path) -> dict[str, Path]:
    """Workspace members without `publish = false`, mapped to their manifest."""
    result: dict[str, Path] = {}
    for member in workspace_members(root):
        manifest = member / "Cargo.toml"
        if not manifest.exists():
            continue
        text = manifest.read_text(encoding="utf-8", errors="replace")
        if PUBLISH_FALSE_RE.search(text):
            continue
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M)
        if name:
            result[name.group(1)] = manifest
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


PR_THRESH_RE = re.compile(r'^\s*(lib-q[\w-]*)\)\s*echo "coverage-threshold=(\d+)"', re.M)
COV_THRESH_RE = re.compile(r'^\s*(lib-q[\w-]*)\)\s*THRESH=(\d+)', re.M)


def threshold_drift(workflows: Path) -> list[str]:
    """The same crate gated in two workflows must carry the same floor in both.

    coverage.yml's extended-coverage job and pr.yml's per-crate `case` are two hand-written
    copies of one set of measurements. Nothing but this check stops them drifting, and the
    drift is silent in the direction that matters: lower the pr.yml number and PRs stop
    catching a regression that the slower scheduled job would still catch days later.

    A crate the matrix gates but pr.yml does not name is also reported. pr.yml falls through
    to `*) 70`, which for the several crates measured below 70 is not a lenient default --
    it fails every PR that touches them.
    """
    pr_path = workflows / "pr.yml"
    cov_path = workflows / "coverage.yml"
    if not pr_path.exists() or not cov_path.exists():
        return []
    pr_text = pr_path.read_text(encoding="utf-8", errors="replace")
    cov_text = cov_path.read_text(encoding="utf-8", errors="replace")

    pr_thresholds = {m.group(1): int(m.group(2)) for m in PR_THRESH_RE.finditer(pr_text)}
    cov_thresholds = {m.group(1): int(m.group(2)) for m in COV_THRESH_RE.finditer(cov_text)}

    matrix_crates: list[str] = []
    for match in MATRIX_CRATES_RE.finditer(cov_text):
        matrix_crates.extend(match.group(1).split())

    problems = []
    for crate in sorted(set(matrix_crates)):
        in_cov = cov_thresholds.get(crate)
        in_pr = pr_thresholds.get(crate)
        if in_cov is None:
            problems.append(
                f"coverage.yml gates {crate} in its matrix but sets no THRESH for it"
            )
        if in_pr is None:
            problems.append(
                f"{crate} is gated in coverage.yml but has no pr.yml threshold; it would "
                f"fall through to the `*)` default of 70"
            )
        elif in_cov is not None and in_pr != in_cov:
            problems.append(
                f"{crate} floor differs: pr.yml={in_pr}%, coverage.yml={in_cov}%"
            )
    return problems


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

    drift = threshold_drift(root / ".github" / "workflows")
    for problem in drift:
        print(f"  FAIL: {problem}")

    ungated_total = len(set(published) - gated)
    print(
        f"  {len(published)} published crates, {len(gated)} gated names, "
        f"{ungated_total} without a floor ({len(exempt)} recorded, {len(unrecorded)} unrecorded)."
    )
    return 1 if (errors or unrecorded or stale or drift) else 0


def self_test() -> int:
    """Prove each verdict fires. Load-bearing constructs:

      new-unrecorded  a published crate in no list and no exemption must FAIL
      stale-exempt    an exemption for a now-gated crate must FAIL
      gated-by-list   a crate named in a *_CRATES list must NOT fire
      gated-by-arg    a crate named via `--crate <name>` must NOT fire
      gated-by-affected  a crate assigned to $AFFECTED must NOT fire
      gated-by-matrix    crates in a build-matrix `crates:` key must NOT fire
      recorded        an exempted, ungated crate must NOT fire
      malformed line  an exemptions line without a reason must FAIL
      drift           pr.yml and coverage.yml floors must agree, and a matrix-gated crate
                      must appear in both (see threshold_drift)
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
            '          AFFECTED="lib-q-gated-by-affected"\n'
            '    strategy:\n'
            '      matrix:\n'
            '        include:\n'
            '          - shard: one\n'
            '            crates: "lib-q-gated-by-matrix lib-q-also-by-matrix"\n',
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
            "lib-q-gated-by-matrix", "lib-q-also-by-matrix",
            "lib-q-was-exempt", "lib-q-recorded", "lib-q-new-unrecorded",
        }
        unrecorded, stale = evaluate(published, gated, set(exempt))

        problems = []
        if "$crate" in gated or any("$" in g for g in gated):
            problems.append(f"shell expansions must not be treated as crate names: {sorted(gated)}")
        if gated != {"lib-q-gated-by-list", "lib-q-was-exempt", "lib-q-gated-by-arg",
                     "lib-q-gated-by-affected", "lib-q-gated-by-matrix",
                     "lib-q-also-by-matrix"}:
            problems.append(f"gated-set mismatch: {sorted(gated)}")
        if unrecorded != ["lib-q-new-unrecorded"]:
            problems.append(f"unrecorded mismatch: {unrecorded}")
        if stale != ["lib-q-was-exempt"]:
            problems.append(f"stale mismatch: {stale}")
        if not errors:
            problems.append("a malformed exemptions line must be reported")

        # --- threshold_drift: three fixtures, each must be caught -------------------
        drift_dir = root / ".github" / "workflows"
        drift_dir.mkdir(parents=True, exist_ok=True)
        (drift_dir / "coverage.yml").write_text(
            "jobs:\n"
            "  x:\n"
            "    strategy:\n"
            "      matrix:\n"
            "        include:\n"
            "          - shard: s\n"
            '            crates: "lib-q-agree lib-q-differs lib-q-missing-in-pr lib-q-no-cov-thresh"\n'
            "    steps:\n"
            "      - run: |\n"
            '          case "$crate" in\n'
            "            lib-q-agree) THRESH=80 ;;\n"
            "            lib-q-differs) THRESH=80 ;;\n"
            "            lib-q-missing-in-pr) THRESH=50 ;;\n"
            "          esac\n",
            encoding="utf-8",
        )
        (drift_dir / "pr.yml").write_text(
            "jobs:\n"
            "  y:\n"
            "    steps:\n"
            "      - run: |\n"
            '          case "$AFFECTED" in\n'
            '            lib-q-agree) echo "coverage-threshold=80" >> $GITHUB_OUTPUT ;;\n'
            '            lib-q-differs) echo "coverage-threshold=61" >> $GITHUB_OUTPUT ;;\n'
            '            lib-q-no-cov-thresh) echo "coverage-threshold=10" >> $GITHUB_OUTPUT ;;\n'
            "          esac\n",
            encoding="utf-8",
        )
        found = threshold_drift(drift_dir)
        joined = " | ".join(found)
        if "lib-q-agree" in joined:
            problems.append("a crate whose floors AGREE must not be reported as drift")
        if "lib-q-differs" not in joined:
            problems.append("a differing floor (pr 61 vs coverage 80) must be reported")
        if "lib-q-missing-in-pr" not in joined:
            problems.append("a matrix-gated crate absent from pr.yml must be reported")
        if "lib-q-no-cov-thresh" not in joined:
            problems.append("a matrix-gated crate with no coverage.yml THRESH must be reported")

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
