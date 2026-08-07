#!/usr/bin/env python3
r"""Implementation for scripts/ci-guard-vacuous-test-shapes.sh.

Scans `run:` shell blocks in every .github/**/*.yml file for the three call-site shapes proven in
this repository to make a `cargo test`/`cargo bench`/... step report green without doing what its
name claims (card t_9f13e8e5, t_9d1766f3, and the systemic zero-tests item):

  R1  `cargo test|nextest ... | <anything>` -- a pipe after the invocation destroys the
      `test result: ...` summary line the runtime vacuity guard (ci-guard-no-vacuous-tests.sh)
      parses, and under `set -e -o pipefail` (every composite action's default bash step), a
      trailing `|| true` after such a pipe additionally masks cargo's own failure.
  R2  `cargo test ...` with a positional test-name filter (before or after a libtest `--`) on a
      line that does not also invoke the runtime guard ($GUARD) -- the proven dead-name-filter
      class: test-fn-dsa's old `-- memory_safety` (matched 0 of 7 tests) and four filters in
      test-k12/action.yml (`test_k12_implementations` / `test_create_hash_by_name` do not exist
      anywhere in the repo; `test_length_encode` exists in a different crate than the step ran
      in). A filter wrapped in the runtime guard turns a dead filter into a hard CI failure at run
      time, so it is exempted here (the two checks are complementary, not redundant: this one
      catches a NEW unguarded call site at review time; the runtime guard catches a call site
      that is guarded but whose filter has gone dead).
  R3  `|| true` / `|| echo ...` directly after a `cargo test|bench|build|check|run` invocation --
      masks that command's own exit code (the t_1d516263 class).

An inline `# vacuity-ok: <reason>` comment on the same physical line exempts that line from every
rule (mirrors the runtime guard's `--allow "reason"`; shows up in `git blame`, no separate
allowlist file to drift out of sync).

WHAT THIS GUARD DOES NOT COVER
-------------------------------
  * It only looks at `run:` steps -- either a `run: |` / `run: >` block scalar (tracked by a plain
    indentation heuristic: a line starting a `run:` block-scalar key; every subsequent line
    indented further than that key belongs to the block; a line at or below that indentation ends
    it) or a one-line `run: <command>` value (plain or single/double-quoted). This is not a YAML
    parser -- it is deliberately narrow so that prose in `description:` fields (which also contain
    the literal text "cargo test" in several `description: >-` blocks in this repo, e.g.
    test-sha3/action.yml's `test-algorithms` input doc) is never scanned as if it were shell.
    A `run:` key spelled or indented in some other way this heuristic does not recognise would
    silently not be scanned -- this is a real, accepted gap, not a claim of YAML-parser
    correctness. A one-line `run:` value continued onto following, more-indented lines (a YAML
    multi-line plain scalar) is read as its first line only; not observed in this repo.
  * A `cargo test` whose stdout is REDIRECTED to a file (`> out.txt`) rather than piped hides the
    `test result:` summary from the runtime guard just as effectively as a pipe does, and is not
    flagged: `>` is a logical-line terminator here, not a finding. Accepted gap -- no such call
    site exists in .github/ today.
  * Line continuations (`... \` at end of physical line) are joined into one logical line before
    any rule runs, so a command split across lines is judged as a whole -- but only for a single
    level of `\` continuation; a continued line that is itself a YAML block-scalar boundary is not
    specially handled (not observed in this repo's actions today).
  * `${{ ... }}` GitHub Actions expressions are replaced with a single placeholder token before
    tokenizing (not evaluated). Without this, a quoted expression like `"${{ inputs.features }}"`
    splits on whitespace into `"${{`, `inputs.features`, `}}"` -- `--features` (a value-taking
    flag) only consumes the first of those three, leaving `inputs.features` and `}}"` to look like
    bare positional filters and firing an R2 false positive that has nothing to do with a test
    name. Only the token shape is fixed by this; a template that DOES resolve to a real filter
    value at runtime is invisible to a static scan either way (documented limitation, not new).
  * It is static text analysis, not a shell parser: exotic quoting, `$(...)` command substitution
    used to build part of a cargo invocation, or a filter assembled across a `for` loop variable
    are not modelled. Every call site this guard was written against is a single literal `run:`
    line or block, which is what every offending line found in this repo actually was.

Usage: python3 scripts/ci_guard_vacuous_test_shapes.py [REPO_ROOT]
"""

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")

# cargo-side flags that consume a following value when not written as --flag=value
VALUE_FLAGS = {
    "-p", "--package", "--features", "--test", "--bench", "--example", "--bin",
    "--profile", "--target", "--target-dir", "--manifest-path", "--exclude",
    "--jobs", "-j", "--color", "--message-format", "-Z",
}
# libtest (after `--`) flags that consume a value
LIBTEST_VALUE_FLAGS = {"--test-threads", "--skip", "--format", "--logfile", "--color", "-Z"}

TEMPLATE_RE = re.compile(r"\$\{\{.*?\}\}")
# `- run:` (the key as the FIRST key of a step list item) is the most common shape in GitHub
# Actions, and an earlier version of both patterns below anchored on `^\s*run:`, which cannot match
# it. That left the guard blind to every step written in list-item form: a planted
# `- run: cargo test -p lib-q-core zzz_no_such_test_name` was scanned, found nothing, and the guard
# printed OK. The optional `-\s+` prefix is what closes that. For the block-scalar case the whole
# `<indent>- ` prefix is captured, so len(group(1)) is the column of `run:` and the body-indent
# comparison below is unchanged.
RUN_KEY_RE = re.compile(r"^(\s*(?:-\s+)?)run:\s*[|>][+-]?\s*$")
# A one-line `run: <command>` step (plain or quoted scalar). These are NOT block scalars, so the
# block-scalar walker below never saw them -- and this repo has four of them invoking `cargo
# test`, two of which (ci.yml's two `-p lib-q-sca-test` SCA smoke steps) carry exactly the
# unguarded positional name filter this guard exists to catch. Scanning only `run: |` blocks
# meant the guard could print "OK -- no unguarded vacuous-capable cargo test shapes in .github/"
# with two live R2 call sites sitting in the tree, which is the same shape of false assurance the
# guard was written to remove.
RUN_INLINE_RE = re.compile(r"^\s*(?:-\s+)?run:\s*(?![|>][+-]?\s*$)(\S.*?)\s*$")


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def strip_scalar_quotes(s: str) -> str:
    """Strip one layer of surrounding YAML quotes from a single-line `run:` value."""
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def iter_run_block_lines(text: str):
    """Yield (lineno, logical_line) for every physical line inside a `run:` block scalar --
    plus the value of every one-line `run: <command>` step -- with `\\`-continuations joined
    into their logical line (reported at the first physical line's number)."""
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = RUN_KEY_RE.match(lines[i])
        if not m:
            inline = RUN_INLINE_RE.match(lines[i])
            if inline:
                yield i + 1, strip_scalar_quotes(inline.group(1))
            i += 1
            continue
        base_indent = len(m.group(1))
        i += 1
        while i < n:
            raw = lines[i]
            if raw.strip() == "":
                i += 1
                continue
            if indent_of(raw) <= base_indent:
                break
            # Join `\`-continuations.
            logical = raw
            start_lineno = i + 1
            while logical.rstrip().endswith("\\") and i + 1 < n:
                i += 1
                logical = logical.rstrip()[:-1] + " " + lines[i].strip()
            yield start_lineno, logical
            i += 1


def strip_templates(s: str) -> str:
    return TEMPLATE_RE.sub("TEMPLATE_VALUE", s)


def find_positional_filters(tail: str):
    """Tokenize the portion of a `cargo test`/`cargo nextest` line after the subcommand and
    return any bare positional arguments (candidate test-name filters)."""
    cmdtail = re.split(r"(?<!\|)\|(?!\|)|\|\||&&|;|>", tail)[0]
    tokens = cmdtail.split()
    positional = []
    seen_ddash = False
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok == "--":
            seen_ddash = True
            continue
        if tok.startswith("-"):
            base = tok.split("=", 1)[0]
            vf = LIBTEST_VALUE_FLAGS if seen_ddash else VALUE_FLAGS
            if base in vf and "=" not in tok:
                skip_next = True
            continue
        # Strip a single layer of matching quotes, then skip shell variable references
        # ($VAR, ${VAR}, "${ARR[@]}", ...): these resolve at runtime to something this static
        # scan cannot see (a package list, a feature-flag accumulator, etc, not necessarily a
        # test-name filter at all), same accepted-gap rationale as the `${{ }}` template case.
        unquoted = tok
        if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in "\"'":
            unquoted = unquoted[1:-1]
        if unquoted.startswith("$"):
            continue
        positional.append(tok)
    return positional


def scan_file(path: Path):
    findings = []
    text = path.read_text(encoding="utf-8")
    for lineno, raw_logical in iter_run_block_lines(text):
        line = strip_templates(raw_logical.strip())
        if not line or line.startswith("#"):
            continue
        if "vacuity-ok:" in line:
            continue
        # An `echo "..."` line is a print statement, not an invocation, even when its literal
        # string documents a `cargo test ...` command for a human to run manually (e.g.
        # rust-test/action.yml's "Full keygen KAT: cargo test -p lib-q-fn-dsa-kgen test_keygen
        # --release -- --test-threads=1" -- deliberately manual/--ignored, not a CI call site).
        if re.match(r"^echo\b", line):
            continue

        # A `VAR="cargo test ..."` (or `'...'`) shell-variable assignment is not itself an
        # invocation -- it is a string literal later invoked indirectly (typically via `eval`),
        # which this static scan cannot follow. Skip the initial assignment line entirely; the
        # `eval "$VAR"` line it feeds does not itself contain the literal text "cargo test" so it
        # was never going to match anyway (a real gap -- see the module docstring -- not one this
        # guard can close without a shell parser).
        if re.search(r"=[\"']\s*cargo (test|nextest|bench|build|check|run)\b", line):
            continue

        # Evaluate each `&&`/`;`-separated command of the logical line SEPARATELY. Judging the
        # whole line as one unit had two holes, both silent: `bash "$GUARD" -- cargo test -p a &&
        # cargo test -p b dead_filter` exempted the second (unguarded) invocation from R2 because
        # the string "$GUARD" appeared *somewhere* on the line, and a second `cargo test` on the
        # same line was never examined at all (only the first match's tail was, and that tail was
        # truncated at the `&&`). `||` is deliberately NOT a separator here -- R3 is precisely the
        # rule about what follows `||`.
        for seg in re.split(r"&&|;", line):
            seg = seg.strip()
            if not seg:
                continue
            is_cargo_test = bool(re.search(r"\bcargo (test|nextest)\b", seg))
            is_other_cargo = bool(re.search(r"\bcargo (bench|build|check|run)\b", seg))

            # R3: `|| true` / `|| echo` directly suffixing a cargo test/bench/build/check/run.
            if (is_cargo_test or is_other_cargo) and re.search(r"\|\|\s*(true|echo)\b", seg):
                findings.append(
                    (lineno, "R3 `|| true`/`|| echo` masks a cargo command's own failure")
                )

            if not is_cargo_test:
                continue

            m = re.search(r"\bcargo (test|nextest)\b(.*)$", seg)
            tail = m.group(2)

            # R1: a pipe (not `||`) anywhere after the invocation.
            if re.search(r"(?<!\|)\|(?!\|)", tail):
                findings.append(
                    (lineno, "R1 cargo test/nextest output piped; summary line not verifiable")
                )

            # R2: positional name filter, unguarded.
            if "$GUARD" in seg:
                continue
            positional = find_positional_filters(tail)
            if positional:
                findings.append((lineno, f"R2 unguarded name filter(s): {positional}"))

    return findings


def main():
    all_findings = []
    # Both extensions: GitHub accepts `.yaml` for workflows and composite actions just as it does
    # `.yml`. Every file in .github/ is `.yml` today, so scanning only that extension would have
    # been indistinguishable from a working guard right up until the first `.yaml` file landed.
    seen = set()
    paths = sorted(ROOT.glob(".github/**/*.yml")) + sorted(ROOT.glob(".github/**/*.yaml"))
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        rel = path.relative_to(ROOT).as_posix()
        for lineno, why in scan_file(path):
            all_findings.append((rel, lineno, why))

    if all_findings:
        for rel, lineno, why in all_findings:
            print(f"{rel}:{lineno}: {why}")
        print(f"ci-guard-vacuous-test-shapes: FAIL -- {len(all_findings)} vacuous-capable test shape(s) found")
        return 1
    print("ci-guard-vacuous-test-shapes: OK -- no unguarded vacuous-capable cargo test shapes in .github/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
