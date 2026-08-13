#!/usr/bin/env python3
"""Guard: a publishable cdylib crate must LINK with bare default features on the host.

WHY THIS EXISTS
---------------
The v0.0.11 release published 35 crates and then died at tier 3:

    error: unwinding panics are not supported without std
    error: could not compile `lib-q-core` (lib) due to 1 previous error
    error: failed to verify package tarball

`lib-q-kem` declares `crate-type = ["cdylib", "rlib"]`. A native cdylib needs a panic runtime.
That cycle tightened its dependency to `lib-q-core = { default-features = false }` while its own
`default` was `[]`, so a bare-default host build put `lib-q-core` in `no_std` and the cdylib could
not link. Fixed with `default = ["std"]`.

**Every CI job was green.** `cargo publish --verify` builds the crate with BARE DEFAULT FEATURES ON
THE HOST, and CI never builds that combination -- it builds `--all-features`, `std,all-algorithms`,
and `--no-default-features` cross-compiled to `thumbv7em-none-eabi`. None of those is the failing
one. `--all-features` structurally cannot see it (it turns `std` on). So the defect reached a tag
with nothing red, and crates.io versions are immutable: a partial release can only be completed.

TWO MODES, BECAUSE THE CHEAP CHECK AND THE TRUE CHECK ARE DIFFERENT QUESTIONS
-----------------------------------------------------------------------------
The static shape (cdylib + default does not reach `std`) is NECESSARY but NOT SUFFICIENT. OBSERVED:
`lib-q-blind-pcs` has exactly that shape and publishes clean -- nothing in its bare-default graph
forces a `no_std` core. Failing on the shape alone would be a false positive on a crate that works.

  * `--static` (default) -- stdlib-only, one `cargo metadata` call, no build, no network. Flags any
    publishable cdylib crate whose default features do not reach its own `std` feature AND which is
    not in KNOWN_LINKABLE below. Cheap enough for every PR. A NEW crate of this shape fails here
    until someone builds it and records the evidence in the allowlist.

  * `--build` -- the true predicate: actually runs `cargo build -p <crate> --lib` (bare default
    features) for every statically-flagged crate, allowlisted or not, and requires exit 0. This is
    what stops the allowlist from rotting: an entry that stops linking goes red here. Belongs on the
    release path, before anything is published.

Using a plain `cargo build` rather than `cargo publish --dry-run` is deliberate and verified: it
reproduces the identical failure without needing dependencies to exist on crates.io yet, so it can
run BEFORE the release instead of during it. OBSERVED on 2026-08-13 at commit 8788981, by reverting
`lib-q-kem`'s `default = ["std"]` back to `default = []` on the real tree:

    $ cargo build -p lib-q-kem --lib          # mutated
    error: unwinding panics are not supported without std
    error: could not compile `lib-q-core` (lib) due to 1 previous error
    MUTATED_BUILD_EXIT=101
    $ cargo build -p lib-q-kem --lib          # restored
    EXIT=0

Usage:
  python3 scripts/ci_guard_cdylib_default_link.py            # --static (every PR)
  python3 scripts/ci_guard_cdylib_default_link.py --build    # release path: really build suspects
  python3 scripts/ci_guard_cdylib_default_link.py --self-test
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Publishable cdylib crates whose default features do NOT reach `std`, and which have nonetheless
# been OBSERVED to link with bare default features on the host. Each entry is a claim backed by a
# real build; `--build` mode re-proves every one of them on the release path, so a stale entry
# cannot stay green. Do NOT add a crate here without running the build and recording the date.
#
#   lib-q-blind-pcs  -- `cargo publish -p lib-q-blind-pcs --dry-run` exit 0 (2026-08-12)
#   lib-q-hpke       -- `cargo publish -p lib-q-hpke --dry-run`      exit 0 (2026-08-13)
#   lib-q-stark      -- `cargo publish -p lib-q-stark --dry-run`     exit 0 (2026-08-13)
#
# lib-q-hpke and lib-q-stark were the two crates card t_103554a6 recorded as UNVERIFIED against this
# failure class: at the time their dry-runs died earlier, on dependencies not yet published at
# 0.0.11, so the panic-runtime question could not be reached. Both were cleared once 0.0.11 was live.
KNOWN_LINKABLE = {
    "lib-q-blind-pcs",
    "lib-q-hpke",
    "lib-q-stark",
}


def default_reaches_std(features: dict[str, list[str]]) -> bool:
    """Does the `default` feature set transitively enable this crate's own `std` feature?

    Walks the crate's own feature graph only. A `dep/std` entry (e.g. `lib-q-core/std`) does NOT
    count: it turns std on for a DEPENDENCY, which is not the same as this crate being built with
    std, and it is precisely the distinction lib-q-kem got wrong. Cycle-safe via `seen`.
    """
    seen: set[str] = set()
    stack = list(features.get("default", []))
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        if f == "std":
            return True
        if "/" in f:  # dependency feature, not one of ours
            continue
        stack.extend(features.get(f, []))
    return False


def is_publishable(pkg: dict) -> bool:
    """`publish` is None when unrestricted, and a (possibly empty) list when restricted.

    An empty list means `publish = false` -- never uploaded, so `cargo publish --verify` never
    builds it and it cannot break a release. wasm-browser-demo is the one such cdylib here.
    """
    return pkg.get("publish") is None


def is_cdylib(pkg: dict) -> bool:
    return any("cdylib" in (t.get("crate_types") or []) for t in pkg.get("targets", []))


def classify(packages: list[dict]) -> tuple[list[str], list[str], list[str]]:
    """-> (flagged, allowlisted, safe): publishable cdylib crates split by default-feature shape.

    `flagged`     - default does not reach std, NOT allowlisted -> --static fails on these.
    `allowlisted` - same shape, but a recorded build says they link -> --build re-proves them.
    `safe`        - default reaches std, so a panic runtime is present by construction.
    """
    flagged, allowlisted, safe = [], [], []
    for pkg in packages:
        if not is_cdylib(pkg) or not is_publishable(pkg):
            continue
        name = pkg["name"]
        if default_reaches_std(pkg.get("features") or {}):
            safe.append(name)
        elif name in KNOWN_LINKABLE:
            allowlisted.append(name)
        else:
            flagged.append(name)
    return sorted(flagged), sorted(allowlisted), sorted(safe)


def load_packages() -> list[dict]:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return json.loads(out)["packages"]


def build_bare_default(name: str) -> tuple[int, str]:
    """Run the true predicate. Returns (exit code, last few lines of output)."""
    r = subprocess.run(["cargo", "build", "-p", name, "--lib"],
                       cwd=ROOT, capture_output=True, text=True)
    tail = "\n".join((r.stderr or r.stdout).strip().splitlines()[-6:])
    return r.returncode, tail


# -------------------------------------------------------------------------------------------
# self-test / mutation battery
# -------------------------------------------------------------------------------------------

def _pkg(name, *, cdylib=True, publish=None, features=None):
    return {
        "name": name,
        "publish": publish,
        "features": features if features is not None else {"default": []},
        "targets": [{"crate_types": ["cdylib", "rlib"] if cdylib else ["rlib"]}],
    }


def self_test() -> int:
    """Prove the classifier can say BOTH words before any real verdict is trusted.

    A guard that has only ever been watched to pass is a claim, not a control -- every case below
    asserts a specific WRONG answer would be caught, not merely that the code runs.
    """
    problems, cases = 0, 0

    def check(label, cond):
        nonlocal problems, cases
        cases += 1
        if not cond:
            print(f"  MUTATION-CHECK FAIL ({label})")
            problems = 1

    # A: THE REAL INCIDENT SHAPE -- lib-q-kem as it was: cdylib, default = [] -> MUST flag.
    f, a, s = classify([_pkg("lib-q-kem", features={"default": [], "std": []})])
    check("A: cdylib with default=[] must be flagged", f == ["lib-q-kem"])

    # B: the fix -- default = ["std"] -> must NOT flag.
    f, a, s = classify([_pkg("lib-q-kem", features={"default": ["std"], "std": []})])
    check("B: default=['std'] must be safe", s == ["lib-q-kem"] and not f)

    # C: std reached TRANSITIVELY through another feature -> must NOT flag.
    f, a, s = classify([_pkg("c", features={"default": ["full"], "full": ["alloc", "std"], "std": []})])
    check("C: transitively-reached std must be safe", s == ["c"] and not f)

    # D: a DEPENDENCY's std (`lib-q-core/std`) is NOT this crate's std -> MUST still flag. This is
    # the exact confusion behind the incident; a classifier that accepts `dep/std` reports lib-q-kem
    # green while it cannot link.
    f, a, s = classify([_pkg("d", features={"default": ["lib-q-core/std"], "std": []})])
    check("D: a dependency's std must not count as ours", f == ["d"])

    # E: not a cdylib -> irrelevant, no panic-runtime requirement.
    f, a, s = classify([_pkg("e", cdylib=False, features={"default": []})])
    check("E: non-cdylib must be ignored", not f and not s and not a)

    # F: publish = false -> never built by `cargo publish --verify`, cannot break a release.
    f, a, s = classify([_pkg("wasm-browser-demo", publish=[], features={"default": []})])
    check("F: publish=false cdylib must be ignored", not f and not a)

    # G: allowlisted crate of the flagged shape -> allowlisted, not flagged (but --build re-proves).
    f, a, s = classify([_pkg("lib-q-hpke", features={"default": ["alloc"], "std": []})])
    check("G: allowlisted crate must not fail --static", a == ["lib-q-hpke"] and not f)

    # H: a feature cycle must terminate rather than hang.
    f, a, s = classify([_pkg("h", features={"default": ["x"], "x": ["y"], "y": ["x"]})])
    check("H: feature cycle must terminate and stay flagged", f == ["h"])

    # I: crate with NO `std` feature at all and default=[] -> flagged (cannot reach std).
    f, a, s = classify([_pkg("i", features={"default": []})])
    check("I: crate with no std feature must be flagged", f == ["i"])

    if problems:
        print("SELF-TEST FAILED -- the cdylib link guard is not classifying what it claims.")
        return 1
    print(f"ci-guard-cdylib-default-link: self-test OK ({cases} mutation cases passed)")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if "--self-test" in argv:
        return self_test()

    # Re-prove detection before trusting a clean result on the real tree: a broken guard and a
    # healthy workspace produce identical output otherwise.
    if self_test() != 0:
        return 1

    do_build = "--build" in argv
    flagged, allowlisted, safe = classify(load_packages())

    print(f"ci-guard-cdylib-default-link: {len(flagged) + len(allowlisted) + len(safe)} publishable "
          f"cdylib crate(s); {len(safe)} reach std by default, {len(allowlisted)} allowlisted, "
          f"{len(flagged)} flagged")

    if flagged:
        print("\nFATAL: publishable cdylib crate(s) whose DEFAULT features do not enable `std`:")
        for n in flagged:
            print(f"  {n}")
        print("\nA native cdylib needs a panic runtime. `cargo publish --verify` builds exactly this")
        print("combination -- bare default features on the host -- and CI does not, which is how")
        print("lib-q-kem reached a tag green and killed the v0.0.11 release at tier 3.")
        print("\nFix by setting `default = [\"std\"]` (what lib-q-core, lib-q-intrinsics and lib-q-kem")
        print("do). no_std consumers are unaffected: they depend with `default-features = false`.")
        print("If the crate genuinely links with bare defaults, run")
        print("`cargo build -p <crate> --lib`, confirm exit 0, and add it to KNOWN_LINKABLE with")
        print("the date -- `--build` mode re-proves that claim on every release.")
        return 1

    if not do_build:
        print("ci-guard-cdylib-default-link: OK (static shape check; run --build to link them)")
        return 0

    # --build: re-prove every allowlisted claim empirically.
    print(f"\n--build: linking {len(allowlisted)} allowlisted crate(s) with bare default features")
    failures = []
    for n in allowlisted:
        rc, tail = build_bare_default(n)
        print(f"  {n:<24} cargo build --lib -> exit {rc}")
        if rc != 0:
            failures.append((n, tail))

    if failures:
        print("\nFATAL: an allowlisted crate no longer links with bare default features. Its entry in")
        print("       KNOWN_LINKABLE is a stale claim, and `cargo publish --verify` will fail on it")
        print("       mid-release -- after earlier crates are already immutable on crates.io:")
        for n, tail in failures:
            print(f"\n  {n}:\n{tail}")
        return 1

    print("ci-guard-cdylib-default-link: OK (every flagged-shape crate links with bare defaults)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
