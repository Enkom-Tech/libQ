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


def parse_jobs() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Parse cd.yml into (job -> packages it publishes, job -> its `needs:` list).

    ORDER COMES FROM `needs:`, NOT FROM POSITION IN THE FILE. This is the whole point of the
    rewrite: GitHub Actions runs jobs CONCURRENTLY unless a `needs:` edge orders them, so a job's
    line number says nothing about when it runs. The previous implementation assigned tier indices
    with `enumerate()` over jobs in file order and compared those indices -- a model of an ordering
    that does not exist. It reported "OK (no fatal ordering violations)" on the v0.0.11 tree and
    the release then died exactly where it said there was no problem (see the FATAL text below).

    All top-level jobs are parsed, not just `publish-rust-*`, so the ancestor closure can traverse
    through non-publishing jobs (e.g. pre-release-validation).
    """
    text = CD.read_text(encoding="utf-8")
    job_re = re.compile(r"^  ([a-z0-9][a-z0-9-]*):\s*$", re.M)
    matrix_pkg_re = re.compile(r'package:\s*"([^"]+)"')
    plain_pkg_re = re.compile(r"^\s+package:\s+([a-z0-9-]+)\s*$", re.M)
    # Every `needs:` in this file is the inline-list form (`needs: [a, b]`); the single-scalar
    # form is accepted too. If a block/dash form is ever introduced this regex silently returns no
    # edges for that job, which would make the guard MORE strict (an absent edge is a violation),
    # not less -- it cannot go quiet in the unsafe direction.
    needs_re = re.compile(r"^\s+needs:\s*(?:\[([^\]]*)\]|([a-z0-9][a-z0-9-]*))\s*$", re.M)

    packages: dict[str, list[str]] = {}
    needs: dict[str, list[str]] = {}
    jobs = list(job_re.finditer(text))
    for i, m in enumerate(jobs):
        jid = m.group(1)
        end = jobs[i + 1].start() if i + 1 < len(jobs) else len(text)
        body = text[m.end():end]
        packages[jid] = matrix_pkg_re.findall(body) or plain_pkg_re.findall(body)
        nm = needs_re.search(body)
        if nm:
            raw = nm.group(1) if nm.group(1) is not None else nm.group(2)
            needs[jid] = [d.strip() for d in raw.split(",") if d.strip()]
        else:
            needs[jid] = []
    return packages, needs


def publish_jobs(packages: dict[str, list[str]]) -> dict[str, str]:
    """Map package name -> the job that publishes it (first wins, as before)."""
    owner: dict[str, str] = {}
    for jid, pkgs in packages.items():
        for p in pkgs:
            owner.setdefault(p, jid)
    return owner


def ancestor_closure(needs: dict[str, list[str]]) -> dict[str, set[str]]:
    """job -> every job that is guaranteed to COMPLETE before it starts."""
    memo: dict[str, set[str]] = {}
    visiting: set[str] = set()

    def walk(jid: str) -> set[str]:
        if jid in memo:
            return memo[jid]
        if jid in visiting:
            return set()  # cycle: Actions rejects these, do not hang on one
        visiting.add(jid)
        acc: set[str] = set()
        for d in needs.get(jid, []):
            acc.add(d)
            acc |= walk(d)
        visiting.discard(jid)
        memo[jid] = acc
        return acc

    return {jid: walk(jid) for jid in needs}


def workspace_deps():
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    members = {p["name"] for p in meta["packages"]}
    return meta["packages"], members


def main() -> int:
    job_packages, job_needs = parse_jobs()
    owner = publish_jobs(job_packages)
    ancestors = ancestor_closure(job_needs)
    packages, members = workspace_deps()

    no_edge, same_job, untiered = [], [], []
    for pkg in packages:
        name = pkg["name"]
        if name not in owner:
            continue  # not published (publish = false, or excluded); membership is another guard
        ja = owner[name]
        anc = ancestors.get(ja, set())
        for dep in pkg.get("dependencies", []):
            dn = dep["name"]
            if dn not in members or dn == name:
                continue
            if (dep.get("kind") or "normal") not in FATAL_KINDS:
                continue
            if (dep.get("req") or "*") == "*":
                continue  # path-only: stripped from the published manifest
            if dn not in owner:
                untiered.append((name, dn, dep.get("req")))
                continue
            jb = owner[dn]
            if jb == ja:
                same_job.append((name, dn, ja))
            elif jb not in anc:
                no_edge.append((name, ja, dn, jb, dep.get("req")))

    print(f"ci-guard-publish-dependency-order: {len(owner)} package(s) across "
          f"{sum(1 for j, p in job_packages.items() if p)} publishing job(s) in cd.yml; "
          "ordering derived from `needs:`")

    bad = False
    if no_edge:
        bad = True
        print("\nFATAL: a versioned dependency is NOT ordered before its dependent. There is no")
        print("       `needs:` path from the dependent's job to the dependency's job, so Actions")
        print("       may run them CONCURRENTLY -- `cargo publish` then resolves the dep against")
        print("       crates.io and fails mid-release. This is what killed v0.0.11:")
        for n, ja, d, jb, req in sorted(no_edge):
            print(f"  {n:<28} [{ja}]")
            print(f"      needs {d:<24} [{jb}]  {req}")
    if same_job:
        bad = True
        print("\nFATAL: dependency inside a single job. Matrix entries run in PARALLEL, so this")
        print("       is a race that may pass once and fail on rerun:")
        for n, d, j in sorted(same_job):
            print(f"  {n:<34} needs  {d:<34} (same job: {j})")
    if untiered:
        bad = True
        print("\nFATAL: versioned dependency on a workspace crate with no publish job:")
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
