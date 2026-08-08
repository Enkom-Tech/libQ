#!/usr/bin/env python3
"""Find `cfg(feature = "X")` gates naming a feature the crate does not define.

Such a gate is ALWAYS FALSE, so whatever it guards compiles to nothing in every configuration --
the same defect class as `#[cfg(any())]`, which `scripts/ci-guard-no-disabled-test-modules.sh`
catches. That guard's own docstring names this spelling as its explicit blind spot:

    "A functionally-equivalent always-false gate spelled a different way (e.g. a custom
     cfg(feature = "never-enabled") that genuinely no Cargo.toml ever defines) is invisible to
     this guard."

This closes that gap. See scripts/ci-guard-nonexistent-feature-gates.sh for the wrapper and the
WHY THIS EXISTS narrative.

WHAT COUNTS AS DEFINED
----------------------
A feature is defined for a crate if it is a key of that crate's `[features]` table, or if it is
an implicit feature created by an optional dependency. Cargo creates the implicit feature only
when the optional dependency is NOT referenced as `dep:<name>` anywhere in `[features]`; we model
that rule rather than assuming every optional dep yields a feature.

`#[cfg(feature = "...")]` is always evaluated against the features of the crate being compiled.
There is no cfg spelling that tests another crate's feature -- `dep/feat` is `[features]` -value
syntax, not cfg syntax -- so no cross-crate resolution is needed or attempted here.

WHAT IS SCANNED
---------------
Every directory containing a `Cargo.toml` with a `[package]` table, excluding `target/` and
dotted directories. That is deliberately broader than the workspace member list: a dead gate in a
non-member crate is still dead code. Within each crate, every `.rs` file under `src/`, `tests/`,
`benches/`, `examples/`, plus `build.rs` -- all of which compile against that package's features.

An earlier scratch version of this probe globbed `lib-q-*/Cargo.toml` and scanned only `src/`.
OBSERVED 2026-08-08: that reached 70 of the 79 workspace members, silently skipping `lib-q`
itself (the primary published facade crate), the five nested `lib-q-fn-dsa/*` crates,
`lib-q-hqc/traits`, and both `examples/` crates.

WHAT IS NOT COVERED
-------------------
  * Feature names built by macro concatenation or otherwise not present as a string literal.
  * `#[cfg_attr(cond, attr)]`: only the first (condition) argument is scanned, so a `feature = `
    string appearing inside the *attribute* argument is ignored. That is the correct reading, but
    it means a genuinely-dead gate hidden there would be missed.
  * A feature that exists but is unreachable (defined, yet no dependency path ever enables it) is
    a different and much harder question; this guard only answers "is it defined at all".

ESCAPE HATCH
------------
An inline `// feature-gate-ok: <reason>` comment on the same line as the cfg token exempts it,
mirroring `ci-guard-vacuous-test-shapes.sh`'s `# vacuity-ok:`. It shows up in `git blame` and
needs no separate allowlist file that can fall out of sync with the tree.

Usage: python scripts/ci_guard_nonexistent_feature_gates.py [REPO_ROOT]
Exit 0 = nothing found, 1 = at least one always-false gate, 2 = usage/environment error.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - the wrapper probes for a usable interpreter
    print("ci-guard-nonexistent-feature-gates: needs Python 3.11+ for tomllib", file=sys.stderr)
    raise SystemExit(2)

# The leading identifier guard is what keeps `target_feature = "avx2"` -- a CPU feature, never
# declared in `[features]` -- from reporting as always-false. Without it, every SIMD gate in the
# STARK and Keccak crates is a false positive (40 measured on this tree); the fixture's
# `target_feature` control catches its removal.
#
# It is spelled `(?<![A-Za-z0-9_])` rather than the `(?<!target_)\b` an earlier draft used, but
# note that this is a readability change, NOT a bug fix: `\b` already fails to match inside
# `target_feature`, because `_` is a word character. Verified by mutation -- swapping the two
# forms leaves the self-test green, so the earlier lookbehind was redundant rather than wrong.
FEATURE_KV = re.compile(r'(?<![A-Za-z0-9_])feature\s*=\s*"([^"]*)"')

# Matches the spellings that can gate code: the attribute `#[cfg(`, the inner attribute `#![cfg(`,
# the conditional-compilation macro `cfg!(`, and the `cfg_attr` variants.
#
# The `!?` before the lookahead is load-bearing and was missing from the first draft: without it
# `cfg!(feature = "x")` never matches, because the `!` sits between the token and the paren. That
# omission cost two of the seven planted gates in the fixture -- the macro form in `src/lib.rs`
# and the one in `build.rs` -- both reported clean.
CFG_TOKEN = re.compile(r'(?<![A-Za-z0-9_])(#!?\[\s*)?(cfg_attr|cfg)\s*!?\s*(?=\()')

SCAN_DIRS = ("src", "tests", "benches", "examples")
EXEMPT = "feature-gate-ok:"

# Vendored upstream copies, not workspace members and not built by this repo. `cargo metadata
# --no-deps` lists 79 members and none of them live here. Their feature sets are upstream's
# business: OBSERVED that scanning `reference/` reports 42 hits in `blake2` alone (its nightly
# `simd`/`simd_opt`/`simd_asm` gates) plus one in `libcrux`, none of which this repo can fix or
# should block CI on.
EXCLUDE_PREFIXES = ("reference/",)


def crate_features(manifest_data: dict) -> set[str]:
    """The set of feature names `#[cfg(feature = "...")]` can legitimately name in this crate."""
    features = manifest_data.get("features") or {}
    names: set[str] = set(features)

    # Cargo suppresses the implicit feature for an optional dependency that is referenced as
    # `dep:<name>` from any feature value. Collect those first so we do not credit a feature that
    # does not actually exist.
    explicit_dep_refs: set[str] = set()
    for value in features.values():
        for entry in value or []:
            if isinstance(entry, str) and entry.startswith("dep:"):
                explicit_dep_refs.add(entry[len("dep:") :].split("?")[0].split("/")[0])

    def collect(table: dict) -> None:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for dep, spec in (table.get(section) or {}).items():
                if isinstance(spec, dict) and spec.get("optional"):
                    if dep not in explicit_dep_refs:
                        names.add(dep)

    collect(manifest_data)
    for target_table in (manifest_data.get("target") or {}).values():
        collect(target_table)

    return names


CHAR_LIT = re.compile(r"'(?:\\.|[^\\'])'")


def _strip_comments(text: str) -> str:
    """Blank out `//` and `/* */` comments, preserving length so offsets stay valid."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "'":
            # A char literal may contain a double quote (`'"'`); consuming it here keeps the
            # string scanner below in sync. A lifetime (`'a`) does not match and falls through.
            m = CHAR_LIT.match(text, i)
            if m:
                i = m.end()
                continue
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                else:
                    if text[i] != "\n":
                        out[i] = " "
                    i += 1
            continue
        i += 1
    return "".join(out)


def _balanced(text: str, open_idx: int) -> tuple[str, int]:
    """Return the contents of the parenthesis group starting at `open_idx`, and its end offset.

    String-literal aware, so a `)` inside a string does not close the group early. Spans newlines,
    which is the whole point: a multi-line `#[cfg(\\n  feature = "x"\\n)]` is one group.
    """
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i
        i += 1
    return text[open_idx + 1 :], n


def _first_argument(group: str) -> str:
    """The first top-level comma-separated argument -- `cfg_attr`'s condition."""
    depth = 0
    for i, c in enumerate(group):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            return group[:i]
    return group


def scan_file(path: pathlib.Path, defined: set[str], crate: str, root: pathlib.Path) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    text = _strip_comments(raw)
    findings: list[str] = []

    for match in CFG_TOKEN.finditer(text):
        open_idx = text.find("(", match.end())
        if open_idx == -1:
            continue
        group, _end = _balanced(text, open_idx)  # noqa: F841 - _end used for the exemption span
        if match.group(2) == "cfg_attr":
            group = _first_argument(group)

        names = FEATURE_KV.findall(group)
        if not names:
            continue

        lineno = text.count("\n", 0, match.start()) + 1
        # The exemption is read from the ORIGINAL text: _strip_comments blanks it out. For a
        # multi-line cfg the comment may sit on any line the group spans, so check them all.
        raw_lines = raw.splitlines()
        end_line = text.count("\n", 0, _end) + 1
        span = raw_lines[lineno - 1 : end_line]
        if any(EXEMPT in ln for ln in span):
            continue

        rel = path.relative_to(root).as_posix()
        for feat in names:
            if feat not in defined:
                findings.append(f"{rel}:{lineno}: feature {feat!r} is not defined by {crate}")
    return findings


def tracked_paths(root: pathlib.Path) -> set[str] | None:
    """Repo-relative posix paths git tracks, or None when `root` is not a git work tree.

    Restricting to tracked files is what keeps a developer's git-ignored `scratchpad/` (and the
    build `target/`) from being scanned. The None fallback is deliberate: the documented
    `[REPO_ROOT]` argument exists so a reviewer can point this guard at a synthetic fixture tree
    and watch it fail, and such a tree is not a git repository.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=120,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    paths = {p for p in out.decode("utf-8", "replace").split("\0") if p}
    return paths or None


def iter_crates(root: pathlib.Path, tracked: set[str] | None):
    for manifest in sorted(root.rglob("Cargo.toml")):
        rel = manifest.relative_to(root).as_posix()
        parts = manifest.relative_to(root).parts
        if any(p == "target" or p.startswith(".") for p in parts):
            continue
        if any(rel.startswith(pfx) for pfx in EXCLUDE_PREFIXES):
            continue
        if tracked is not None and rel not in tracked:
            continue
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            print(f"ci-guard-nonexistent-feature-gates: cannot read {manifest}: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if "package" not in data:
            continue  # virtual workspace manifest
        yield manifest, data


FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "nonexistent-feature-gates"


def self_test() -> int:
    """Re-prove that this guard can fail, against the committed adversarial fixture.

    Landing a guard green proves nothing -- the card contract's register rule is explicit that "a
    check you have not seen fail is not evidence". Verifying that once by hand at authoring time
    is weaker than it looks: the next refactor can silently kill detection and the guard goes
    green forever, which is precisely the failure mode this family of guards exists to prevent.
    So the proof runs in CI on every push, not once in a commit message.

    The fixture's manifests are named `Cargo.toml.fixture` so cargo never treats the tree as a
    package; they are renamed on the way into a temp directory. The temp copy is not a git work
    tree, which also exercises the `tracked_paths` -> None fallback.
    """
    if not FIXTURE_DIR.is_dir():
        print(f"self-test: fixture tree missing at {FIXTURE_DIR}", file=sys.stderr)
        return 2

    expected_path = FIXTURE_DIR / "EXPECTED.txt"
    if not expected_path.is_file():
        print(f"self-test: {expected_path} missing", file=sys.stderr)
        return 2
    expected = sorted(
        ln.strip()
        for ln in expected_path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    )

    with tempfile.TemporaryDirectory(prefix="ci-guard-fixture-") as tmp:
        dest = pathlib.Path(tmp) / "tree"
        shutil.copytree(FIXTURE_DIR, dest)
        (dest / "EXPECTED.txt").unlink(missing_ok=True)
        (dest / "README.md").unlink(missing_ok=True)
        for manifest in list(dest.rglob("Cargo.toml.fixture")):
            manifest.rename(manifest.with_name("Cargo.toml"))

        actual = sorted(collect_findings(dest)[0])

    if actual == expected:
        print(f"self-test: OK -- fixture reproduces all {len(expected)} planted gate(s) and no controls")
        return 0

    print("ci-guard-nonexistent-feature-gates: SELF-TEST FAILED", file=sys.stderr)
    for line in sorted(set(expected) - set(actual)):
        print(f"  MISSED (guard no longer detects this):  {line}", file=sys.stderr)
    for line in sorted(set(actual) - set(expected)):
        print(f"  UNEXPECTED (guard over-reports):        {line}", file=sys.stderr)
    print(
        "\nThe fixture is the guard's proof that it can fail. If you changed the fixture on\n"
        "purpose, update scripts/fixtures/nonexistent-feature-gates/EXPECTED.txt in the same\n"
        "commit. If you did not, detection has regressed -- fix the guard, not the expectations.",
        file=sys.stderr,
    )
    return 1


def collect_findings(root: pathlib.Path) -> tuple[list[str], int, int]:
    tracked = tracked_paths(root)
    crates = list(iter_crates(root, tracked))
    crate_dirs = {m.parent for m, _ in crates}

    def owner(path: pathlib.Path) -> pathlib.Path | None:
        """The nearest ancestor directory that is itself a crate root."""
        for parent in path.parents:
            if parent in crate_dirs:
                return parent
            if parent == root:
                break
        return None

    findings: list[str] = []
    crates_scanned = 0
    files_scanned = 0

    for manifest, data in crates:
        crate_dir = manifest.parent
        crate = data["package"].get("name", crate_dir.name)
        defined = crate_features(data)
        crates_scanned += 1

        targets = []
        for sub in SCAN_DIRS:
            d = crate_dir / sub
            if d.is_dir():
                targets.extend(sorted(d.rglob("*.rs")))
        build_rs = crate_dir / "build.rs"
        if build_rs.is_file():
            targets.append(build_rs)

        for rs in targets:
            # `examples/` at the repo root is itself a crate and contains another
            # (`examples/wasm-browser-demo`). A nested crate's sources are compiled against ITS
            # features, not this one's -- attributing them here would produce false positives.
            if owner(rs) != crate_dir:
                continue
            if tracked is not None and rs.relative_to(root).as_posix() not in tracked:
                continue
            files_scanned += 1
            findings.extend(scan_file(rs, defined, crate, root))

    return findings, crates_scanned, files_scanned


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--self-test":
        return self_test()

    root = pathlib.Path(argv[0] if argv else ".").resolve()
    if not root.is_dir():
        print(f"ci-guard-nonexistent-feature-gates: not a directory: {root}", file=sys.stderr)
        return 2

    findings, crates_scanned, files_scanned = collect_findings(root)

    print(f"scanned {crates_scanned} crates, {files_scanned} files")
    if findings:
        print(f"ci-guard-nonexistent-feature-gates: FAIL -- {len(findings)} always-false feature gate(s):")
        for f in findings:
            print(f"  {f}")
        return 1
    print("ci-guard-nonexistent-feature-gates: OK -- every gated feature is defined by its own crate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
