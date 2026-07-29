#!/usr/bin/env python3
"""Assert that the coverage gate measures what it claims to measure.

Driven by scripts/ci-guard-coverage-honesty.sh (see that file for the rationale).
Three independent checks; each fails CLOSED (an unparseable input is an error, not a pass).

  CHECK 1  no test-NAME filter may follow libtest's `--` separator in any tarpaulin command
  CHECK 2  the coverage-skip predicate may only skip explicitly allowlisted packages
  CHECK 3  no unmeasured nested cargo package may hide inside a coverage-gated crate

Standard library only: this runs in the ci.yml `core-validation` job, which has no pip step.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

failures: list[str] = []
notes: list[str] = []


def fail(check: str, message: str) -> None:
    failures.append(f"[{check}] {message}")


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        raise SystemExit(f"ci-guard-coverage-honesty: expected file is missing: {rel}")
    return p.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# CHECK 1 -- no test-name filters in tarpaulin commands
# ---------------------------------------------------------------------------
# Files that build or issue a `cargo tarpaulin` command line. Adding a new one and forgetting
# to list it here is the only way to evade this check, so keep the list next to the reason.
TARPAULIN_COMMAND_FILES = [
    "scripts/run-coverage.sh",              # coverage.yml per-crate gate + local parity
    "scripts/run-coverage.ps1",             # Windows twin of the above
    ".github/actions/rust-test/action.yml",  # the pr.yml test-coverage gate
    ".github/workflows/security-critical-coverage.yml",  # scheduled scoped gates
]

# libtest flags that legitimately follow `--`. These change SCHEDULING or OUTPUT, never which
# tests run. `--skip` is deliberately absent: it is a filter wearing a flag's clothes.
ALLOWED_LIBTEST_FLAG_PREFIXES = (
    "--test-threads",
    "--nocapture",
    "--show-output",
    "--color",
    "--format",
    "--logfile",
    "--quiet",
    "--exact",  # only meaningful with a name filter, which we reject anyway
    "-Z",
)
# Flags whose VALUE is a separate token, so the token after them is not a test name.
VALUE_TAKING = ("--test-threads", "--format", "--logfile", "--color", "-Z")


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued physical lines into logical ones, keeping the start line no."""
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.rstrip()
        if not buf:
            start = i
        if stripped.endswith(chr(92)):  # trailing backslash = shell line continuation
            buf += stripped[:-1] + " "
            continue
        out.append((start, buf + stripped))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


BASH_APPEND = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)="\$\{?\1\}?(.*)"\s*$')
PS_APPEND = re.compile(r'^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*"(.*)"\s*$')
SEPARATOR = re.compile(r'(?:^|\s)--(?:\s|$)')


def command_fragments(rel: str, text: str):
    """Yield (lineno, fragment) for every logical line that forms a tarpaulin command line."""
    for lineno, line in logical_lines(text):
        if "cargo tarpaulin" in line:
            yield lineno, line
            continue
        m = BASH_APPEND.match(line) or PS_APPEND.match(line)
        if m and "cmd" in m.group(1).lower():
            yield lineno, m.group(2)


def check_no_test_name_filters() -> None:
    for rel in TARPAULIN_COMMAND_FILES:
        text = read(rel)
        for lineno, frag in command_fragments(rel, text):
            m = SEPARATOR.search(frag)
            if not m:
                continue
            tail = frag[m.end():].strip()
            tokens = tail.split()
            prev = ""
            for tok in tokens:
                if tok.startswith("-"):
                    if not tok.startswith(ALLOWED_LIBTEST_FLAG_PREFIXES):
                        fail(
                            "CHECK 1",
                            f"{rel}:{lineno}: unrecognised flag {tok!r} after the libtest `--` "
                            "separator. If it is a scheduling/output flag, add it to "
                            "ALLOWED_LIBTEST_FLAG_PREFIXES with a one-line reason; if it selects "
                            "tests, it does not belong in a coverage command.",
                        )
                elif prev.split("=")[0] in VALUE_TAKING and "=" not in prev:
                    pass  # this token is the previous flag's value, not a test name
                else:
                    fail(
                        "CHECK 1",
                        f"{rel}:{lineno}: test-NAME filter {tok!r} follows the libtest `--` "
                        "separator. A name filter shrinks the numerator's test set while "
                        "--include-files leaves the denominator alone, so the resulting "
                        "percentage describes the filter, not the crate. Remove it; if the run "
                        "is too slow, cut wall time (release profile, job split), never the "
                        "measurement.",
                    )
                prev = tok
        notes.append(f"CHECK 1: scanned {rel}")


# ---------------------------------------------------------------------------
# CHECK 2 -- the coverage-skip predicate may only skip allowlisted packages
# ---------------------------------------------------------------------------
# A package listed here is NOT measured by the pr.yml test-coverage job. Every entry needs a
# reason and a statement of where its coverage is measured instead -- "skipped" must never mean
# "unmeasured and nobody noticed".
COVERAGE_SKIP_ALLOWLIST = {
    # #![no_std] rlib built with a panic=abort profile; tarpaulin's instrumented harness is
    # panic=unwind, so it cannot be measured through the rust-test action. Its coverage IS
    # gated -- by coverage.yml's per-crate step (threshold 65) via scripts/run-coverage.sh.
    "lib-q-keccak",
}

SKIP_STEP_ID = "coverage-skip"


def workspace_members() -> list[tuple[str, str]]:
    """[(relative member path, cargo package name)] from the root Cargo.toml `members` array."""
    toml = read("Cargo.toml")
    m = re.search(r"^members\s*=\s*\[(.*?)^\]", toml, re.DOTALL | re.MULTILINE)
    if not m:
        raise SystemExit("ci-guard-coverage-honesty: could not parse [workspace] members")
    paths = re.findall(r'"([^"]+)"', m.group(1))
    if len(paths) < 10:
        raise SystemExit(
            f"ci-guard-coverage-honesty: parsed only {len(paths)} workspace members; "
            "the manifest layout changed and this guard would under-check"
        )
    out = []
    for rel in paths:
        manifest = ROOT / rel / "Cargo.toml"
        if not manifest.is_file():
            raise SystemExit(f"ci-guard-coverage-honesty: member {rel} has no Cargo.toml")
        txt = manifest.read_text(encoding="utf-8", errors="replace")
        nm = re.search(r'^\s*name\s*=\s*"([^"]+)"', txt, re.MULTILINE)
        if not nm:
            raise SystemExit(f"ci-guard-coverage-honesty: member {rel} has no package name")
        out.append((rel, nm.group(1)))
    return out


def workspace_exclude() -> set[str]:
    toml = read("Cargo.toml")
    m = re.search(r"^exclude\s*=\s*\[(.*?)^\]", toml, re.DOTALL | re.MULTILINE)
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()


def extract_skip_step(rel: str) -> str:
    """Return the dedented `run:` body of the step whose `id:` is coverage-skip."""
    lines = read(rel).splitlines()
    idx = next(
        (i for i, l in enumerate(lines) if l.strip() == f"id: {SKIP_STEP_ID}"),
        None,
    )
    if idx is None:
        raise SystemExit(
            f"ci-guard-coverage-honesty: no step with `id: {SKIP_STEP_ID}` in {rel}. "
            "If the coverage-skip logic moved, point this guard at its new home -- do not "
            "delete the check."
        )
    run_idx = next(
        (i for i in range(idx, min(idx + 12, len(lines))) if lines[i].strip() == "run: |"),
        None,
    )
    if run_idx is None:
        raise SystemExit(f"ci-guard-coverage-honesty: step {SKIP_STEP_ID} has no `run: |` block")
    body_indent = None
    body: list[str] = []
    for l in lines[run_idx + 1:]:
        if not l.strip():
            body.append("")
            continue
        indent = len(l) - len(l.lstrip())
        if body_indent is None:
            body_indent = indent
        if indent < body_indent:
            break
        body.append(l[body_indent:])
    if not body:
        raise SystemExit(f"ci-guard-coverage-honesty: step {SKIP_STEP_ID} has an empty run block")
    return "\n".join(body)


def check_coverage_skip_allowlist() -> None:
    rel = ".github/actions/rust-test/action.yml"
    block = extract_skip_step(rel)

    # Run the SHIPPED predicate, not a re-implementation of it. Substitute the action inputs the
    # way pr.yml drives them: one package at a time, no features, no package list.
    prepared = (
        block.replace("${{ inputs.features }}", "")
        .replace("${{ inputs.package }}", '$1')
        .replace("${{ inputs.packages }}", "")
    )
    leftover = re.search(r"\$\{\{.*?\}\}", prepared)
    if leftover:
        raise SystemExit(
            "ci-guard-coverage-honesty: unhandled GitHub expression in the coverage-skip step: "
            f"{leftover.group(0)!r}. Teach this guard about it rather than skipping the check."
        )

    bash = shutil.which("bash")
    if bash is None:
        raise SystemExit("ci-guard-coverage-honesty: bash is required to evaluate the predicate")

    members = workspace_members()
    names = sorted({name for _, name in members})

    with tempfile.TemporaryDirectory() as td:
        out_path = pathlib.Path(td) / "gh_output"
        script_path = pathlib.Path(td) / "probe.sh"
        script = (
            "set -u\n"
            "_coverage_skip_step() {\n"
            + "\n".join("  " + l for l in prepared.splitlines())
            + "\n}\n"
            'for _p in "$@"; do\n'
            '  : > "$GITHUB_OUTPUT"\n'
            '  _coverage_skip_step "$_p"\n'
            '  if grep -q "^skip=true" "$GITHUB_OUTPUT"; then echo "SKIP $_p"; fi\n'
            "done\n"
        )
        script_path.write_text(script, encoding="utf-8")
        env = dict(os.environ, GITHUB_OUTPUT=str(out_path))
        proc = subprocess.run(
            [bash, str(script_path), *names],
            capture_output=True, text=True, env=env, cwd=str(ROOT),
        )
        if proc.returncode != 0:
            raise SystemExit(
                "ci-guard-coverage-honesty: could not evaluate the coverage-skip predicate:\n"
                + proc.stderr
            )
        skipped = {l.split(" ", 1)[1] for l in proc.stdout.splitlines() if l.startswith("SKIP ")}

    unexpected = sorted(skipped - COVERAGE_SKIP_ALLOWLIST)
    stale = sorted(COVERAGE_SKIP_ALLOWLIST - skipped)
    for pkg in unexpected:
        fail(
            "CHECK 2",
            f"package {pkg!r} is routed to the coverage-SKIP branch but is not in "
            "COVERAGE_SKIP_ALLOWLIST. A package whose coverage silently never runs is the most "
            "invisible gap there is. Either make the predicate exact so it stops matching this "
            "package, or add it to the allowlist WITH a reason and a statement of where its "
            "coverage is measured instead.",
        )
    for pkg in stale:
        fail(
            "CHECK 2",
            f"COVERAGE_SKIP_ALLOWLIST lists {pkg!r} but the predicate no longer skips it. "
            "Drop the stale entry so the allowlist keeps describing reality.",
        )
    notes.append(
        f"CHECK 2: evaluated the shipped predicate against {len(names)} workspace packages; "
        f"skipped = {sorted(skipped) or '[]'}"
    )


# ---------------------------------------------------------------------------
# CHECK 3 -- no unmeasured nested cargo package inside a coverage-gated crate
# ---------------------------------------------------------------------------
# `--include-files '<crate>/src/**'` cannot see source that lives in a nested cargo package.
# Anything listed here is KNOWN to be outside its parent's coverage denominator. An entry is a
# debt marker, not an approval: it must say how big the hole is and what closes it.
NESTED_PACKAGE_EXCEPTIONS: dict[str, set[str]] = {
    # lib-q-fn-dsa's gated percentage describes lib-q-fn-dsa/src/lib.rs (161 measurable lines)
    # ONLY. These five nested crates hold ~37k lines -- including fn-dsa-kgen/src/poly.rs, where
    # a portable-keygen livelock survived from 2026-05-17 to 2026-07-27 with no coverage signal.
    # They cannot simply be added to --include-files: they are NOT workspace members, so
    # `tarpaulin --packages lib-q-fn-dsa` never runs their own test suites. Widening the
    # denominator without also running those suites would crater the number and break the gate
    # blind. Closing this needs measure-then-gate: report-only tarpaulin rows for each nested
    # crate first, then floors set from what CI actually prints. Tracked as follow-up work; see
    # docs/coverage-scope.md ("FN-DSA nested crates").
    "lib-q-fn-dsa": {
        "lib-q-fn-dsa/fn-dsa",
        "lib-q-fn-dsa/fn-dsa-comm",
        "lib-q-fn-dsa/fn-dsa-kgen",
        "lib-q-fn-dsa/fn-dsa-sign",
        "lib-q-fn-dsa/fn-dsa-vrfy",
    },
}


def check_no_hidden_nested_packages() -> None:
    members = workspace_members()
    member_paths = {rel.replace(chr(92), "/").strip("./") for rel, _ in members}
    excluded = {e.replace(chr(92), "/").strip("./") for e in workspace_exclude()}

    for rel, _name in members:
        base = ROOT / rel
        if not base.is_dir():
            continue
        found: set[str] = set()
        for manifest in base.rglob("Cargo.toml"):
            nested = manifest.parent.relative_to(ROOT).as_posix()
            if nested == rel or "target" in nested.split("/"):
                continue
            if nested in member_paths or nested in excluded:
                continue  # separately measured, or deliberately outside the workspace
            if "[package]" not in manifest.read_text(encoding="utf-8", errors="replace"):
                continue
            found.add(nested)
        allowed = NESTED_PACKAGE_EXCEPTIONS.get(rel, set())
        for nested in sorted(found - allowed):
            fail(
                "CHECK 3",
                f"{nested} is a cargo package nested inside coverage-gated crate {rel}, but it is "
                f"neither a workspace member nor in [workspace].exclude. Coverage for {rel} is "
                f"scoped to '{rel}/src/**', so every line under {nested} is outside the "
                "denominator while still shipping in the crate. Either make it a workspace "
                "member with its own gate, or record it in NESTED_PACKAGE_EXCEPTIONS with the "
                "line count and the plan to close it.",
            )
        for nested in sorted(allowed - found):
            fail(
                "CHECK 3",
                f"NESTED_PACKAGE_EXCEPTIONS lists {nested} under {rel} but it no longer exists. "
                "Remove the stale entry.",
            )
    total_excepted = sum(len(v) for v in NESTED_PACKAGE_EXCEPTIONS.values())
    notes.append(
        f"CHECK 3: {len(members)} workspace members scanned; "
        f"{total_excepted} nested package(s) recorded as known-unmeasured"
    )


def main() -> int:
    check_no_test_name_filters()
    check_coverage_skip_allowlist()
    check_no_hidden_nested_packages()

    for n in notes:
        print(f"  ok  {n}")
    if failures:
        print("")
        print("ci-guard-coverage-honesty: FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ci-guard-coverage-honesty: coverage gate scope checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
