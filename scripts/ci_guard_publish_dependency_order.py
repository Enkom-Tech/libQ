#!/usr/bin/env python3
"""Guard: cd.yml's publish tiers must satisfy the workspace dependency graph.

WHY THIS EXISTS
---------------
`cargo publish` resolves every VERSIONED dependency against the crates.io index at package time.
If crate A declares `B = "0.0.10"` and B has not been published yet, packaging A fails outright:

    error: failed to prepare local package for uploading
    Caused by:
      failed to select a version for the requirement `lib-q-stark-challenger = "^0.0.10"`
      candidate versions found which didn't match: 0.0.9

That is not hypothetical. It happened on the v0.0.10 release (CD run 30883399439): 51 crates were
published, then tier 7 failed on exactly that error, tiers 8-17 and every npm/wasm package were
skipped, and the release was left half-shipped. **crates.io versions are immutable**, so a partial
release cannot be rolled back -- only completed by a follow-up fix.

`ci-guard-publish-order.sh` did NOT catch it, and was never meant to: that guard checks the publish
list's MEMBERSHIP and BUILD PARAMETERS against cd.yml (does every crate reach a tier, does the
PowerShell fallback list the same set). It says nothing about whether the tier ORDER is a valid
topological order of the dependency graph. It reported PASS on the broken tree minutes before the
tag was cut.

WHAT COUNTS AS FATAL, AND WHY IT IS NOT "EVERY DEPENDENCY"
----------------------------------------------------------
Three kinds behave differently at package time, and treating them alike produces either false
negatives (missing the real bug) or false positives (blocking valid trees):

  * normal / build  -- versioned ones ARE resolved. A later tier is FATAL.
  * dev             -- tolerated. cargo does not resolve dev-dependencies when packaging.
                       OBSERVED on the same run: lib-q-hqc carries `lib-q-sca-test = "^0.0.10"` as
                       a dev-dependency, lib-q-sca-test publishes in a LATER tier, and lib-q-hqc
                       published successfully. Five such pairs exist in this workspace today;
                       flagging them would make the guard cry wolf and get ignored.
  * path-only       -- always safe. A dependency with a `path` and no `version` is STRIPPED from
                       the published manifest, so it imposes no ordering at all. This is the
                       standard escape hatch for a dev-dependency cycle (lib-q-stark-commit
                       dev-depends on lib-q-stark-merkle, which depends on lib-q-stark-commit).

SAME-TIER IS ALSO AN ERROR. Entries inside one `strategy.matrix` run in PARALLEL, so a dependency
between two packages in the same tier is a race, not an ordering -- it may pass and then fail on a
rerun. The v0.0.10 tree had `lib-q-stark-dft` and `lib-q-stark-commit` in one matrix while commit
depended on dft.

AUTHORITY: cd.yml, not the PowerShell fallback. cd.yml is what actually runs on a tag; the
PowerShell script is an operator fallback whose agreement with cd.yml is a separate guard's job.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CD = ROOT / ".github" / "workflows" / "cd.yml"

# Dependency kinds cargo resolves against the registry when packaging. `dev` is deliberately
# absent -- see the module docstring for the observation that establishes it.
FATAL_KINDS = {"normal", "build"}


def publish_tiers() -> dict[str, int]:
    """Map package name -> tier index, in cd.yml job order.

    Packages in the SAME job share a tier index, because matrix entries run in parallel.
    """
    text = CD.read_text(encoding="utf-8")
    job_re = re.compile(r"^  (publish-rust-[a-z0-9-]+):\s*$", re.M)
    matrix_pkg_re = re.compile(r'package:\s*"([^"]+)"')
    plain_pkg_re = re.compile(r"^\s+package:\s+([a-z0-9-]+)\s*$", re.M)

    order: dict[str, int] = {}
    tier = 0
    jobs = list(job_re.finditer(text))
    for i, m in enumerate(jobs):
        end = jobs[i + 1].start() if i + 1 < len(jobs) else len(text)
        body = text[m.end():end]
        pkgs = matrix_pkg_re.findall(body) or plain_pkg_re.findall(body)
        if not pkgs:
            continue
        tier += 1
        for p in pkgs:
            order.setdefault(p, tier)
    return order


def workspace_deps():
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    members = {p["name"] for p in meta["packages"]}
    return meta["packages"], members


def main() -> int:
    order = publish_tiers()
    packages, members = workspace_deps()

    later, same_tier, untiered = [], [], []
    for pkg in packages:
        name = pkg["name"]
        if name not in order:
            continue  # not published (publish = false, or excluded); membership is another guard
        for dep in pkg.get("dependencies", []):
            dn = dep["name"]
            if dn not in members or dn == name:
                continue
            if (dep.get("kind") or "normal") not in FATAL_KINDS:
                continue
            if (dep.get("req") or "*") == "*":
                continue  # path-only: stripped from the published manifest
            if dn not in order:
                untiered.append((name, dn, dep.get("req")))
            elif order[dn] > order[name]:
                later.append((name, order[name], dn, order[dn], dep.get("req")))
            elif order[dn] == order[name]:
                same_tier.append((name, dn, order[name]))

    print(f"ci-guard-publish-dependency-order: {len(order)} package(s) across "
          f"{max(order.values()) if order else 0} tier(s) in cd.yml")

    bad = False
    if later:
        bad = True
        print("\nFATAL: a versioned dependency publishes AFTER its dependent. `cargo publish`")
        print("       resolves these against crates.io and will fail mid-release:")
        for n, no, d, do, req in sorted(later, key=lambda v: v[1]):
            print(f"  tier {no:>2}  {n:<34} needs  {d:<34} (tier {do:>2})  {req}")
    if same_tier:
        bad = True
        print("\nFATAL: dependency inside a single tier. Matrix entries run in PARALLEL, so this")
        print("       is a race that may pass once and fail on rerun:")
        for n, d, t in sorted(same_tier):
            print(f"  tier {t:>2}  {n:<34} needs  {d:<34} (same tier)")
    if untiered:
        bad = True
        print("\nFATAL: versioned dependency on a workspace crate with no publish tier:")
        for n, d, req in sorted(untiered):
            print(f"  {n:<34} needs  {d:<34} {req}")

    if bad:
        print("\nFix by moving the dependency to an earlier tier, or -- if the ordering is not")
        print("satisfiable at any position -- by dropping the `version` so the dep is path-only")
        print("(dev-dependencies only), or by removing the dependency. Publishing with")
        print("--no-verify is NOT a workaround: crates.io versions are immutable.")
        return 1

    print("ci-guard-publish-dependency-order: OK (no fatal ordering violations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
