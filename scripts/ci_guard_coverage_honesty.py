#!/usr/bin/env python3
"""Assert that the coverage gate measures what it claims to measure.

Driven by scripts/ci-guard-coverage-honesty.sh (see that file for the rationale).
Four independent checks; each fails CLOSED (an unparseable input is an error, not a pass).

  CHECK 1  no test-NAME filter may follow libtest's `--` separator in any tarpaulin command
  CHECK 2  the coverage-skip predicate may only skip explicitly allowlisted packages
  CHECK 3  no unmeasured nested cargo package may hide inside a coverage-gated crate
  CHECK 4  the denominator may not be narrowed without an explicit, justified allowlist entry

Standard library only: this runs in the ci.yml `core-validation` job, which has no pip step.

A NOTE ON HOW THIS GUARD IS ITSELF GUARDED
------------------------------------------
The first version of this file was evaded four ways by an adversarial review, every one of them
a *shape* the guard did not model rather than an invariant it did not hold:

  * `CMD+=" -- keypair_generation ..."` -- the bash append regex only understood `CMD="$CMD ..."`.
  * a substring `$PACKAGES` arm -- the predicate probe only ever drove the `$PACKAGE` input.
  * a raw `cargo tarpaulin` in coverage.yml -- that file was not on the hardcoded scan list.
  * `--include-files '<crate>/src/lib.rs'` / `--exclude-files '<crate>/src/verify.rs'` -- the
    denominator was only guarded against nested packages, not against being narrowed directly.

So the checks below deliberately avoid enumerating shapes wherever an invariant will do:
files are DISCOVERED by content rather than listed, command text is reached by TAINT-TRACKING
every variable that flows into a tarpaulin command rather than by matching one append idiom,
and the shipped predicate is exercised across EVERY input the action accepts rather than one.
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
# Discovery -- which files can issue or build a `cargo tarpaulin` command line
# ---------------------------------------------------------------------------
# Discovered by WALKING the repo, not by a hardcoded list. A hardcoded list is exactly how
# .github/workflows/coverage.yml -- the workflow that actually runs the per-crate gate -- was
# missed: adding a raw filtered tarpaulin command there passed the guard untouched.
SCAN_SUFFIXES = (".sh", ".bash", ".ps1", ".psm1", ".yml", ".yaml", ".cmd", ".bat")
PRUNE_DIRS = {
    ".git", "target", "node_modules", "reference", ".venv", "venv",
    "dist", "build", "__pycache__", ".cargo", "coverage",
}

# This guard's own files describe the banned patterns in prose; scanning them would flag the
# documentation instead of the defect.
GUARD_SELF = {
    "scripts/ci-guard-coverage-honesty.sh",
    "scripts/ci_guard_coverage_honesty.py",
}

# Discovery must never come back empty because something moved. These files are known to
# participate in a tarpaulin command line today; if one stops being discovered, the guard errors
# and the editor has to point it at the new home instead of losing the check silently.
REQUIRED_TARPAULIN_FILES = {
    "scripts/run-coverage.sh",                            # coverage.yml per-crate gate + local parity
    "scripts/run-coverage.ps1",                           # Windows twin of the above
    "scripts/print-tarpaulin-include-args.sh",            # emits the --include-files denominator
    ".github/actions/rust-test/action.yml",               # the pr.yml test-coverage gate
    ".github/workflows/coverage.yml",                     # executes the per-crate gate
    ".github/workflows/security-critical-coverage.yml",   # scheduled scoped gates
}


def discover_tarpaulin_files() -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [
            d for d in dirnames
            if d not in PRUNE_DIRS and not d.startswith("coverage-") and not d.startswith(".")
        ]
        for name in filenames:
            if not name.endswith(SCAN_SUFFIXES):
                continue
            p = pathlib.Path(dirpath) / name
            rel = p.relative_to(ROOT).as_posix()
            if rel in GUARD_SELF:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "tarpaulin" in text:
                found.append(rel)
    # os.walk prunes dot-directories above, so .github must be walked explicitly.
    gh = ROOT / ".github"
    if gh.is_dir():
        for dirpath, dirnames, filenames in os.walk(gh):
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
            for name in filenames:
                if not name.endswith(SCAN_SUFFIXES):
                    continue
                p = pathlib.Path(dirpath) / name
                rel = p.relative_to(ROOT).as_posix()
                if rel in GUARD_SELF:
                    continue
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "tarpaulin" in text:
                    found.append(rel)
    found = sorted(set(found))
    missing = sorted(REQUIRED_TARPAULIN_FILES - set(found))
    if missing:
        raise SystemExit(
            "ci-guard-coverage-honesty: these files are known to build tarpaulin command lines "
            f"but were not discovered: {missing}. If one was renamed or moved, update "
            "REQUIRED_TARPAULIN_FILES -- do not delete the entry."
        )
    return found


# ---------------------------------------------------------------------------
# Lexing helpers shared by CHECK 1 and CHECK 4
# ---------------------------------------------------------------------------
def strip_comments(text: str) -> str:
    """Blank out `#` comments so prose describing a banned pattern is not read as the pattern.

    Deliberately conservative: a full-line comment is dropped, and a trailing comment only when
    everything before the `#` has balanced quotes. `$#` and `${var#glob}` are untouched because
    the `#` must be preceded by whitespace or start the line.
    """
    out: list[str] = []
    for raw in text.splitlines():
        if raw.lstrip().startswith("#"):
            out.append("")
            continue
        idx = 0
        while True:
            m = re.search(r"(?:(?<=\s)|^)#", raw[idx:])
            if not m:
                break
            pos = idx + m.start()
            head = raw[:pos]
            if head.count('"') % 2 == 0 and head.count("'") % 2 == 0:
                raw = head.rstrip()
                break
            idx = pos + 1
        out.append(raw)
    return "\n".join(out)


def normalize_ps_concat(line: str) -> str:
    """Fold PowerShell's `'a' + 'b'` literal concatenation into one literal.

    scripts/run-coverage.ps1 writes globs as `"lib-q-core/src/" + "*" + "\""` so the `*` never
    sits inside a literal. Without folding, every pattern in that file reads as truncated.
    """
    line = line.replace("[char]92", "'\\'")
    prev = None
    while prev != line:
        prev = line
        line = re.sub(r"'\s*\+\s*'", "", line)
        line = re.sub(r'"\s*\+\s*"', "", line)
    return line


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


def prepared_lines(rel: str) -> list[tuple[int, str]]:
    text = strip_comments(read(rel))
    if rel.endswith((".ps1", ".psm1")):
        text = "\n".join(normalize_ps_concat(l) for l in text.splitlines())
    return logical_lines(text)


# ---------------------------------------------------------------------------
# CHECK 1 -- no test-name filters in tarpaulin commands
# ---------------------------------------------------------------------------
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

TARPAULIN_INVOCATION = re.compile(r"cargo\s+(?:\+\S+\s+)?tarpaulin\b")
BASH_ASSIGN = re.compile(
    r"^\s*(?:local\s+|export\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_]\w*)\+?=(.*)$"
)
PS_ASSIGN = re.compile(
    r"^\s*\$(?:(?:env|script|global|local|private):)?([A-Za-z_]\w*)\s*\+?=\s*(.*)$"
)
VAR_REF = re.compile(r"\$\{?([A-Za-z_]\w*)")
SEPARATOR = re.compile(r"(?:^|\s)--(?:\s|$)")
# A shell control operator ends the command; anything past it is redirection or a pipeline,
# not a libtest argument.
SHELL_BREAK = re.compile(r"^(?:[|;&()<>]|\d+[<>])")


def command_fragments(rel: str) -> list[tuple[int, str]]:
    """Every logical line that contributes text to a tarpaulin command line, with its line no.

    Reached by taint, not by matching one append idiom: a variable assigned a `cargo tarpaulin`
    command is tainted, every later assignment or append to a tainted name is a fragment, and any
    variable INTERPOLATED into a tainted assignment is itself tainted (so `OUT_EXTRA+=" ... "`,
    which run-coverage.sh already uses, is covered even though its name says nothing about cmd).
    """
    assign = PS_ASSIGN if rel.endswith((".ps1", ".psm1")) else BASH_ASSIGN
    lines = prepared_lines(rel)

    tainted: set[str] = set()
    frags: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    def add(lineno: int, frag: str) -> None:
        key = (lineno, frag)
        if key not in seen:
            seen.add(key)
            frags.append((lineno, frag))

    for lineno, line in lines:
        if TARPAULIN_INVOCATION.search(line):
            add(lineno, line)
            m = assign.match(line)
            if m:
                tainted.add(m.group(1))

    changed = True
    while changed:
        changed = False
        for lineno, line in lines:
            m = assign.match(line)
            if not m or m.group(1) not in tainted:
                continue
            add(lineno, m.group(2))
            for ref in VAR_REF.findall(m.group(2)):
                if ref not in tainted:
                    tainted.add(ref)
                    changed = True
    return frags


def check_no_test_name_filters(files: list[str]) -> None:
    scanned_with_commands = 0
    for rel in files:
        frags = command_fragments(rel)
        if frags:
            scanned_with_commands += 1
        for lineno, frag in frags:
            m = SEPARATOR.search(frag)
            if not m:
                continue
            tail = frag[m.end():].strip()
            prev = ""
            for raw_tok in tail.split():
                if SHELL_BREAK.match(raw_tok):
                    break
                tok = raw_tok.strip("\"'")
                if not tok:
                    continue
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
    notes.append(
        f"CHECK 1: taint-scanned {len(files)} tarpaulin-related file(s); "
        f"{scanned_with_commands} build or issue a tarpaulin command line"
    )


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

# The predicate reads THREE action inputs, so driving it with one is not "running the real
# predicate" -- it is running one arm of it. Reverting only the `$PACKAGES` arm to a substring
# match passed the single-input probe untouched. Each shape below is a way the action is really
# called (ci.yml passes `packages:` at .github/workflows/ci.yml:273; pr.yml passes `package:`),
# plus the feature-suffixed list form the predicate explicitly claims to handle.
# The padding entries are deliberately NOT real package names: a real one that happened to be
# skipped would make every package look skipped under that shape.
SKIP_INPUT_SHAPES: list[tuple[str, object]] = [
    ("package=<pkg>", lambda p: ("", p, "")),
    ("packages=<pkg>", lambda p: ("", "", p)),
    ("packages=<pkg>@features", lambda p: ("", "", p + "@std,random")),
    ("packages=... <pkg> ...", lambda p: ("", "", f"zzz-pad-a {p} zzz-pad-b")),
    ("features=std,alloc package=<pkg>", lambda p: ("std,alloc", p, "")),
]


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

    # Run the SHIPPED predicate, not a re-implementation of it -- but drive every input it reads,
    # because a predicate is only as exercised as its least-driven arm.
    prepared = (
        block.replace("${{ inputs.features }}", "$1")
        .replace("${{ inputs.package }}", "$2")
        .replace("${{ inputs.packages }}", "$3")
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

    names = sorted({name for _, name in workspace_members()})

    cases: list[str] = []
    for label, shape in SKIP_INPUT_SHAPES:
        for name in names:
            feats, pkg, pkgs = shape(name)  # type: ignore[operator]
            for field in (label, feats, pkg, pkgs, name):
                if "|" in field or "\n" in field:
                    raise SystemExit(
                        "ci-guard-coverage-honesty: probe field contains the record separator: "
                        f"{field!r}"
                    )
            cases.append(f"{label}|{feats}|{pkg}|{pkgs}|{name}")

    with tempfile.TemporaryDirectory() as td:
        out_path = pathlib.Path(td) / "gh_output"
        script_path = pathlib.Path(td) / "probe.sh"
        script = (
            "set -u\n"
            "_coverage_skip_step() {\n"
            + "\n".join("  " + l for l in prepared.splitlines())
            + "\n}\n"
            "while IFS='|' read -r _label _feat _pkg _pkgs _name; do\n"
            '  [ -n "$_name" ] || continue\n'
            '  : > "$GITHUB_OUTPUT"\n'
            '  _coverage_skip_step "$_feat" "$_pkg" "$_pkgs"\n'
            '  if grep -q "^skip=true" "$GITHUB_OUTPUT"; then\n'
            '    printf "SKIP|%s|%s\\n" "$_name" "$_label"\n'
            "  fi\n"
            "done\n"
        )
        script_path.write_text(script, encoding="utf-8")
        env = dict(os.environ, GITHUB_OUTPUT=str(out_path))
        # Bytes, not text=True: universal-newline translation rewrites the probe's stdin on
        # Windows, so every record arrives with a trailing CR that ends up inside the last field.
        proc = subprocess.run(
            [bash, str(script_path)],
            input=("\n".join(cases) + "\n").encode("utf-8"),
            capture_output=True, env=env, cwd=str(ROOT),
        )
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        if proc.returncode != 0:
            raise SystemExit(
                "ci-guard-coverage-honesty: could not evaluate the coverage-skip predicate:\n"
                + stderr
            )
        skipped: dict[str, set[str]] = {}
        for line in stdout.replace("\r", "\n").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 3 or parts[0] != "SKIP":
                continue
            skipped.setdefault(parts[1], set()).add("|".join(parts[2:]))

    unexpected = sorted(set(skipped) - COVERAGE_SKIP_ALLOWLIST)
    stale = sorted(COVERAGE_SKIP_ALLOWLIST - set(skipped))
    for pkg in unexpected:
        shapes = ", ".join(sorted(skipped[pkg]))
        fail(
            "CHECK 2",
            f"package {pkg!r} is routed to the coverage-SKIP branch (input shape(s): {shapes}) "
            "but is not in COVERAGE_SKIP_ALLOWLIST. A package whose coverage silently never runs "
            "is the most invisible gap there is. Either make the predicate exact so it stops "
            "matching this package, or add it to the allowlist WITH a reason and a statement of "
            "where its coverage is measured instead.",
        )
    for pkg in stale:
        fail(
            "CHECK 2",
            f"COVERAGE_SKIP_ALLOWLIST lists {pkg!r} but the predicate no longer skips it under "
            "any input shape. Drop the stale entry so the allowlist keeps describing reality.",
        )
    notes.append(
        f"CHECK 2: evaluated the shipped predicate against {len(names)} workspace packages "
        f"x {len(SKIP_INPUT_SHAPES)} input shapes ({len(cases)} evaluations); "
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


# ---------------------------------------------------------------------------
# CHECK 4 -- the denominator may not be narrowed without an explicit entry
# ---------------------------------------------------------------------------
# CHECK 3 only catches source hidden in a NESTED package. The denominator can also be narrowed
# head-on, and both directions were demonstrated to slip past this guard:
#   (a) --include-files '<crate>/src/lib.rs'   instead of '<crate>/src/*' + '<crate>/src/**'
#   (b) --exclude-files '<crate>/src/verify.rs'
# (b) is the repository's own idiom -- ~15 legitimate excludes exist for SIMD/arch files that
# genuinely cannot execute on the runner -- so a blanket ban would be wrong and would get
# switched off. Instead both narrowings are allowed only from an explicit list, the way
# NESTED_PACKAGE_EXCEPTIONS already works: adding one costs a line and a reason.

PATTERN_FLAG = re.compile(r"--(include|exclude)-files[=\s]+(\S+)")
# The flag names also appear inside error strings ("missing --include-files for crate ..."), so a
# capture only counts as a pattern if it is shaped like one: a path separator, a glob, or a .rs
# tail. A token with none of those selects no files at all, so it cannot narrow a denominator.
PATTERN_SHAPE = re.compile(r"[/\\*]|\.rs$")

# An include pattern whose final path component is one of these covers a directory, not a file.
DIRECTORY_GLOB_TAILS = {"*", "**", "*.rs"}

# --include-files patterns that deliberately name individual FILES. Keyed by "<file>::<pattern>"
# so allowlisting a narrow include for one scoped workflow cannot license the same narrowing in
# the general per-crate gate.
NARROW_INCLUDE_ALLOWLIST = {
    # The security-critical workflow is a SCOPED gate by construction: docs/coverage-scope.md
    # defines its tier as exactly these files at a 95%-target floor, because the rest of each
    # crate's src/*.rs is feature-gated and not part of that tier's denominator. Narrow here is
    # the point; narrow in the whole-crate gate is the defect.
    ".github/workflows/security-critical-coverage.yml::lib-q-sig/src/lib.rs",
    ".github/workflows/security-critical-coverage.yml::lib-q-sig/src/ml_dsa.rs",
    ".github/workflows/security-critical-coverage.yml::lib-q-sig/src/provider.rs",
    ".github/workflows/security-critical-coverage.yml::lib-q-threshold-kem-lattice/src/lib.rs",
    ".github/workflows/security-critical-coverage.yml::lib-q-threshold-kem-lattice/src/kem.rs",
    ".github/workflows/security-critical-coverage.yml::lib-q-threshold-kem-lattice/src/threshold.rs",
}

# --exclude-files patterns that remove source from INSIDE a workspace member's own src/ tree.
# Each one shrinks the denominator of the crate being measured, so each needs a reason. The
# rationale prose lives next to the code that emits them (scripts/run-coverage.sh, the rust-test
# action, docs/coverage-scope.md); the one-liners here say which category an entry is in.
# Keyed by pattern alone, not by file: an exclude must be applied consistently across the bash
# script, its PowerShell twin and the action, and three entries per exclusion would be noise.
SRC_EXCLUDE_ALLOWLIST = {
    # std,rand coverage builds skip wasm, so these lines are never compiled into the instrumented
    # binary; excluding them keeps the coverage.yml denominator equal to the PR action's.
    "lib-q-core/src/wasm/*",
    # `#[target_feature]` / target_feature-cfg intrinsic bodies. On a runner without AVX-512/AVX2
    # the equivalence tests take the scalar fallback, so these read 0/N however good the tests are.
    "lib-q-keccak/src/advanced_simd.rs",
    "lib-q-keccak/src/x86.rs",
    "lib-q-keccak/src/x86_simd_avx512.rs",
    # `#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]`, so on an x86_64 runner it is
    # not merely untested -- it is not executable at all, and tarpaulin reports a flat 0/88.
    # Excluded only on non-aarch64 hosts (see the `uname -m` guard in run-coverage.sh), so an
    # aarch64 runner would measure NEON for real rather than silently skipping it.
    #
    # This became load-bearing when `simd` joined lib-q-rocca-s's default features so consumers
    # actually get the constant-time AES backend instead of a secret-indexed S-box table
    # (t_3d6e8d50). Those 88 dead-on-x86 lines took the crate 98.21% -> 78.43% and broke its floor.
    # The tests did not get worse; the denominator gained code this runner cannot reach.
    "lib-q-rocca-s/src/simd/neon.rs",
    # Built only under `feature = "simd256"`; the default gate builds the portable backend.
    # Measured instead by the non-gated `--ml-dsa-simd256` pass in coverage.yml.
    "lib-q-ml-dsa/src/simd/avx2.rs",
    "lib-q-ml-dsa/src/simd/avx2/*",
    "lib-q-ml-dsa/src/simd/avx2/**",
    "lib-q-ml-dsa/src/ml_dsa_generic/instantiations/avx2.rs",
    # Only one of these compiles per target architecture; the other cannot be executed at all.
    "lib-q-intrinsics/src/arm64.rs",
    "lib-q-intrinsics/src/avx2.rs",
    # Function bodies carrying `#[target_feature(enable = "avx2", enable = "pclmulqdq")]`, plus the
    # feature-gated wasm binding. NOTE the deliberately narrow scope: lib-q-hqc/src/simd/avx2/ is
    # gated on `#[cfg(target_arch = "x86_64")]` (simd/mod.rs:35), NOT on the `simd-avx2` feature, so
    # mod.rs / polynomial.rs / syndrome.rs / vector.rs ARE compiled in a default x86_64 build and
    # stay in the denominator. Only the two files whose bodies the runner cannot execute are listed.
    "lib-q-hqc/src/wasm.rs",
    "lib-q-hqc/src/simd/avx2/gf2x.rs",
    "lib-q-hqc/src/simd/avx2/gf2x_toom3.rs",
    # Packed backends gated on `target_feature` ("avx2"/"avx512f"/"neon") in lib.rs -- not merely
    # target_arch -- so a default build compiles only the `no_packing` scalar fallback. Measured at
    # 1244 of 2052 lines, which reports a genuine 77.9% as 30.7%. `no_packing/` is deliberately NOT
    # listed: it IS compiled by default and must stay in the denominator.
    "lib-q-stark-monty31/src/x86_64_avx2/*",
    "lib-q-stark-monty31/src/x86_64_avx2/**",
    "lib-q-stark-monty31/src/x86_64_avx512/*",
    "lib-q-stark-monty31/src/x86_64_avx512/**",
    "lib-q-stark-monty31/src/aarch64_neon/*",
    "lib-q-stark-monty31/src/aarch64_neon/**",
    # Experimental recursive-verifier internals, covered by dedicated long-running integration
    # suites rather than the default crate gate (see the comment in scripts/run-coverage.sh).
    "lib-q-zkp/src/aggregation.rs",
    "lib-q-zkp/src/air/stark_verifier.rs",
    "lib-q-zkp/src/air/fri_verifier.rs",
    "lib-q-zkp/src/air/commitment_verifier.rs",
    "lib-q-zkp/src/air/constraint_verifier.rs",
}


def normalize_pattern(raw: str) -> str:
    """Reduce a quoted/escaped glob as written in shell, YAML or PowerShell to a bare path glob."""
    s = raw.replace('\\"', '"').replace("\\'", "'")
    for _ in range(4):
        s = s.strip("\"'")
    s = re.sub(r"\\+", "/", s)   # any run of backslashes is a Windows path separator here
    s = re.sub(r"/+", "/", s)
    return s.strip("\"'")


def scope_patterns(files: list[str]):
    """Yield (rel, lineno, kind, normalized pattern) for every --include/--exclude-files flag."""
    for rel in files:
        for lineno, line in prepared_lines(rel):
            for kind, raw in PATTERN_FLAG.findall(line):
                pat = normalize_pattern(raw)
                if pat and PATTERN_SHAPE.search(pat):
                    yield rel, lineno, kind, pat


def check_denominator_scope(files: list[str]) -> None:
    member_paths = sorted(
        {rel.replace(chr(92), "/").strip("./") for rel, _ in workspace_members()}
    )
    seen_includes: set[str] = set()
    seen_excludes: set[str] = set()
    n_include = n_exclude = 0

    for rel, lineno, kind, pat in scope_patterns(files):
        if kind == "include":
            n_include += 1
            tail = pat.rstrip("/").split("/")[-1]
            if tail in DIRECTORY_GLOB_TAILS:
                continue
            key = f"{rel}::{pat}"
            seen_includes.add(key)
            if key not in NARROW_INCLUDE_ALLOWLIST:
                fail(
                    "CHECK 4",
                    f"{rel}:{lineno}: --include-files {pat!r} names a single file rather than a "
                    "directory glob, so the denominator is whatever that file happens to contain. "
                    "Narrowing the include set raises the percentage without a line of new test "
                    "code. A whole-crate gate must include '<crate>/src/*' and '<crate>/src/**'; "
                    f"if this is a deliberately scoped tier, add {key!r} to "
                    "NARROW_INCLUDE_ALLOWLIST with the reason and the tier it belongs to.",
                )
            continue

        n_exclude += 1
        if "$" in pat:
            seen_excludes.add(pat)
            if pat not in SRC_EXCLUDE_ALLOWLIST:
                fail(
                    "CHECK 4",
                    f"{rel}:{lineno}: --exclude-files {pat!r} is built from a variable, so what "
                    "it removes from the denominator cannot be read off the source. Write the "
                    "path literally and record it in SRC_EXCLUDE_ALLOWLIST with a reason.",
                )
            continue
        inside_src = any(pat.startswith(m + "/src/") or pat == m + "/src" for m in member_paths)
        if not inside_src:
            continue  # target/, benches/, examples/, or a whole sibling crate: not measured source
        seen_excludes.add(pat)
        if pat not in SRC_EXCLUDE_ALLOWLIST:
            fail(
                "CHECK 4",
                f"{rel}:{lineno}: --exclude-files {pat!r} removes source from inside a workspace "
                "member's own src/ tree, which shrinks the denominator of the crate being "
                "measured. That is legitimate only for code the runner cannot execute at all "
                "(SIMD/arch-gated bodies, a non-compiled cfg). If that is the case here, add "
                f"{pat!r} to SRC_EXCLUDE_ALLOWLIST with the reason; if it is code that simply "
                "lacks tests, write the tests instead.",
            )

    for key in sorted(NARROW_INCLUDE_ALLOWLIST - seen_includes):
        fail(
            "CHECK 4",
            f"NARROW_INCLUDE_ALLOWLIST lists {key!r} but no such --include-files remains. "
            "Drop the stale entry so the allowlist keeps describing reality.",
        )
    for pat in sorted(SRC_EXCLUDE_ALLOWLIST - seen_excludes):
        fail(
            "CHECK 4",
            f"SRC_EXCLUDE_ALLOWLIST lists {pat!r} but no such --exclude-files remains. "
            "Drop the stale entry so the allowlist keeps describing reality.",
        )
    notes.append(
        f"CHECK 4: {n_include} --include-files and {n_exclude} --exclude-files patterns read; "
        f"{len(NARROW_INCLUDE_ALLOWLIST)} scoped include(s) and {len(SRC_EXCLUDE_ALLOWLIST)} "
        "in-src exclude(s) allowlisted"
    )


def main() -> int:
    files = discover_tarpaulin_files()
    check_no_test_name_filters(files)
    check_coverage_skip_allowlist()
    check_no_hidden_nested_packages()
    check_denominator_scope(files)

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
