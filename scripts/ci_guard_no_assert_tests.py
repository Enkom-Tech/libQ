#!/usr/bin/env python3
r"""Implementation for scripts/ci-guard-no-assert-tests.sh.

Flags `#[test]` functions that have NO mechanism by which they can ever fail.

WHY THIS EXISTS
----------------
scripts/ci-guard-vacuous-test-shapes.sh and scripts/ci-guard-no-vacuous-tests.sh catch a test
STEP that reports green without running the tests it claims to. Neither looks at whether an
individual test function, once it DOES run, is capable of reporting anything other than "ok".
Found 2026-08 in lib-q-hqc/tests/kat_with_aes_drbg_test.rs (fixed at 766cb0c): all three
`#[test]` fns in that file could not fail, and one was a KEM round-trip doing

    if ss == decapsulated_ss { println!("(check mark) ...") } else { println!("(cross mark) ...") }

with no assertion at all -- so a decapsulation returning the WRONG shared secret printed a cross
mark to stdout and still reported `ok` to the harness and to CI. In a post-quantum crypto
library, silently.

WHAT COUNTS AS "CAN FAIL"
---------------------------
A `#[test]` fn's body (or its `-> Result<...>` signature) must contain at least one of:
  * `assert!` / `assert_eq!` / `assert_ne!` / `debug_assert!` / `debug_assert_eq!` /
    `debug_assert_ne!`
  * `panic!` / `unreachable!` / `todo!` / `unimplemented!`
  * `.unwrap(` / `.unwrap_err(` / `.expect(` / `.expect_err(`
  * `matches!(` (used as an assertion idiom: `assert!(matches!(...))` or a bare
    `matches!(...)` guarding a panic/return)
  * a `?` try-operator, PROVIDED the fn signature returns `Result<..>` (or `anyhow::Result`,
    `std::result::Result`, etc) -- a `?` on an `Option`-returning test fn also legitimately
    fails the test (harness treats a `None` return as failure), so `Option<` is accepted too
  * `#[should_panic]` on the same attribute stack

A test with NONE of these can only ever fail if some callee panics -- a real but rare and
easy-to-audit shape, which is why this guard flags it for a human decision (fix, delete, or
allowlist with a stated reason) rather than trying to chase the call graph.

WHAT THIS GUARD DOES NOT DO
------------------------------
  * It does not evaluate whether the assertions present are the RIGHT ones, or reachable (e.g.
    an `assert!` behind a `return` that always runs first is invisible to this text scan). That
    is a correctness review question, not a structural-shape question, mirroring the framing in
    docs/notes on "boolean-constrained is not bound": a structural presence check is necessary,
    not sufficient.
  * It is not a Rust parser. Brace/string/comment tracking is a best-effort tokenizer, not rustc.
    A test body containing a raw string or byte string with unbalanced braces inside it is the
    known edge case; none observed in this repo's test files at the time of writing.
  * Only functions carrying a bare `#[test]` attribute are in scope (the literal attribute this
    repo's test suites use). `#[tokio::test]` / `#[wasm_bindgen_test]` / other custom test
    attributes are out of scope -- a different harness, a different guard if it becomes a problem.

ALLOWLIST
----------
scripts/no-assert-test-exemptions.txt, same ratchet shape as coverage-floor-exemptions.txt:
`<path>:<fn_name> | <reason>`. An entry for a test that has since gained a real assertion (or
been deleted) is a stale exemption and this guard fails on it, so the file cannot rot upward.

Usage:
    python3 ci_guard_no_assert_tests.py [REPO_ROOT]
    python3 ci_guard_no_assert_tests.py --self-test
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

EXEMPTIONS_NAME = "no-assert-test-exemptions.txt"

TEST_ATTR_RE = re.compile(r"^\s*#\s*\[\s*test\s*\]\s*$")
SHOULD_PANIC_RE = re.compile(r"#\s*\[\s*should_panic\b")
ATTR_LINE_RE = re.compile(r"^\s*#\s*!?\[")
FN_SIG_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*(?:<[^{;]*?>)?\s*\("
)

FAIL_PATTERNS = [
    re.compile(r"\bassert(?:_eq|_ne)?!"),
    re.compile(r"\bdebug_assert(?:_eq|_ne)?!"),
    re.compile(r"\bpanic!"),
    re.compile(r"\bunreachable!"),
    re.compile(r"\btodo!"),
    re.compile(r"\bunimplemented!"),
    re.compile(r"\.unwrap(?:_err)?\("),
    re.compile(r"\.expect(?:_err)?\("),
    re.compile(r"\bmatches!\("),
]

RESULT_RETURN_RE = re.compile(r"->\s*(?:[\w:]+::)?(?:Result|Option)\s*<")


def strip_code(text: str) -> str:
    """Best-effort removal of string/char literal contents and comments, so brace-matching and
    the FAIL_PATTERNS scan aren't fooled by e.g. a string literal containing the word "panic!" or
    a stray brace inside a string. Not a full lexer -- raw strings (`r"..."`, `r#"..."#`) are
    approximated by treating `#` fences up to 3 deep, which covers every raw string in this repo
    at the time of writing.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(" " * (j - i))
            i = j
            continue
        if c == "r" and i + 1 < n and (text[i + 1] == '"' or text[i + 1] == "#"):
            m = re.match(r'r(#{0,3})"', text[i:])
            if m:
                hashes = m.group(1)
                start = i + m.end()
                end_token = '"' + hashes
                j = text.find(end_token, start)
                j = n if j == -1 else j + len(end_token)
                out.append(" " * (j - i))
                i = j
                continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            j = min(j + 1, n)
            out.append(" " * (j - i))
            i = j
            continue
        if c == "'" and i + 2 < n and text[i + 1] == "\\":
            j = text.find("'", i + 2)
            j = n if j == -1 else j + 1
            out.append(" " * (j - i))
            i = j
            continue
        if c == "'" and i + 2 < n and text[i + 2] == "'":
            out.append("   ")
            i += 3
            continue
        out.append(c)
        i += 1
    return "".join(out)


def find_matching_brace(clean: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(clean)
    while i < n:
        if clean[i] == "{":
            depth += 1
        elif clean[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1



ANY_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^;{}]*?>)?\s*\(")


MACRO_RULES_RE = re.compile(r"macro_rules!\s*[A-Za-z_][A-Za-z0-9_]*\s*\{")


def blank_macro_bodies(clean: str) -> str:
    """Blank out `macro_rules!` bodies, preserving newlines so line numbers stay correct.

    A `#[test]` inside a macro TEMPLATE is not a test -- the expansions are, and their names are
    built by token pasting (`fn [<$name _ $t:lower>]()`), which no static scan can resolve. Left
    in, `lib-q-slh-dsa/src/util.rs`'s `gen_test!` reported `fn <unknown>` and could neither be
    fixed nor sensibly exempted. Skipping the template is correct rather than convenient: the
    generated tests delegate to a real function, which is where any assertion belongs.
    """
    out = clean
    while True:
        m = MACRO_RULES_RE.search(out)
        if not m:
            return out
        open_idx = out.index("{", m.end() - 1)
        close_idx = find_matching_brace(out, open_idx)
        if close_idx <= open_idx:
            return out
        span = out[open_idx : close_idx + 1]
        blanked = "".join(c if c == "\n" else " " for c in span)
        out = out[:open_idx] + blanked + out[close_idx + 1 :]


def collect_fn_bodies(clean: str) -> dict:
    """Map every `fn name` in the file to its body text.

    Needed because a test that only calls a helper -- `check(a, b)` where `check` asserts -- has
    no failure mechanism of its OWN but absolutely can fail. Treating those as vacuous produced
    304 false positives on the first repo sweep, which would have meant an allowlist so large it
    stopped meaning anything. Only same-file helpers are resolved; a cross-module helper still
    needs an exemption line, which is the honest limit of a stdlib-only static check.
    """
    bodies = {}
    for m in ANY_FN_RE.finditer(clean):
        open_idx = clean.find("{", m.end() - 1)
        if open_idx == -1:
            continue
        close_idx = find_matching_brace(clean, open_idx)
        if close_idx <= open_idx:
            continue
        # A name can appear more than once (generic helpers in separate modules); keep the
        # longest body, which is the conservative choice -- it is the one most likely to assert.
        prev = bodies.get(m.group(1))
        body = clean[open_idx : close_idx + 1]
        if prev is None or len(body) > len(prev):
            bodies[m.group(1)] = body
    return bodies


def body_can_fail(body: str, bodies: dict, depth: int = 0, seen=None) -> bool:
    """True if `body`, or any same-file helper it transitively calls, can fail."""
    if any(p.search(body) for p in FAIL_PATTERNS):
        return True
    if depth >= 3:
        return False
    if seen is None:
        seen = set()
    for call in CALL_RE.finditer(body):
        name = call.group(1)
        if name in seen or name not in bodies:
            continue
        seen.add(name)
        if body_can_fail(bodies[name], bodies, depth + 1, seen):
            return True
    return False


def find_tests(text: str):
    """Yield (lineno, fn_name, can_fail: bool) for every bare `#[test]` fn in `text`."""
    clean = blank_macro_bodies(strip_code(text))
    lines = clean.splitlines(keepends=True)
    line_start_offsets = []
    off = 0
    for ln in lines:
        line_start_offsets.append(off)
        off += len(ln)

    def lineno_at(offset: int) -> int:
        lo, hi = 0, len(line_start_offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_start_offsets[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    fn_bodies = collect_fn_bodies(clean)
    results = []
    i = 0
    n = len(lines)
    while i < n:
        if TEST_ATTR_RE.match(lines[i]):
            test_lineno = i + 1
            # Walk forward through any other stacked attributes / comments (blank comment lines
            # were already blanked by strip_code but keep their newline) to find the fn signature
            # and collect whether #[should_panic] rides along with it.
            j = i + 1
            attr_block = [lines[i]]
            while j < n and (ATTR_LINE_RE.match(lines[j]) or lines[j].strip() == ""):
                attr_block.append(lines[j])
                j += 1
            has_should_panic = any(SHOULD_PANIC_RE.search(a) for a in attr_block)
            # Collect the signature: from line j up to the first '{' (signature may span
            # multiple lines for a multi-line where-clause or return type).
            sig_start_offset = line_start_offsets[j] if j < n else len(clean)
            brace_search_limit = min(len(clean), sig_start_offset + 4000)
            open_idx = clean.find("{", sig_start_offset, brace_search_limit)
            if open_idx == -1:
                i = j
                continue
            sig_text = clean[sig_start_offset:open_idx]
            m = FN_SIG_RE.search(sig_text) or FN_SIG_RE.search(
                clean[sig_start_offset : sig_start_offset + 2000]
            )
            fn_name = m.group(1) if m else "<unknown>"
            close_idx = find_matching_brace(clean, open_idx)
            body = clean[open_idx : close_idx + 1]

            can_fail = has_should_panic
            if not can_fail:
                can_fail = body_can_fail(body, fn_bodies)
            if not can_fail and RESULT_RETURN_RE.search(sig_text) and "?" in body:
                can_fail = True

            results.append((test_lineno, fn_name, can_fail))
            i = j
            continue
        i += 1
    return results


def load_exemptions(root: Path) -> set[str]:
    path = root / "scripts" / EXEMPTIONS_NAME
    if not path.exists():
        return set()
    out = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key = line.split("|", 1)[0].strip()
        if key:
            out.add(key)
    return out


def tracked_rs_files(root: Path):
    # Tracked AND untracked-but-not-ignored. Scanning only tracked files leaves a hole exactly
    # the width of "a new test file": it is invisible to this guard until the commit that adds
    # it, so the author's pre-commit run passes and CI fails afterwards. That happened with
    # lib-q-core/tests/wasm_smoke.rs at 6b73868 -- the guard was run, returned OK because the
    # file was still untracked, and only failed once committed. `--exclude-standard` keeps
    # .gitignore'd paths (scratchpad/, target/) out.
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    out += subprocess.run(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # scripts/fixtures/** holds deliberately-planted, deliberately-broken snippets used by OTHER
    # guards' self-tests (e.g. ci-guard-nonexistent-feature-gates's `planted_in_tests_dir`,
    # commented "PLANTED 5: under tests/, which a src/-only scanner never reaches"). They are not
    # real crate tests -- scanning them just reports another guard's intentionally-vacuous fixture
    # as if it were a defect in this repo's actual test suite.
    return [
        root / p
        for p in out.splitlines()
        if p and not p.startswith("scripts/fixtures/")
    ]


def scan_repo(root: Path):
    findings = []  # (key, path, lineno, fn_name)
    stale = []
    exemptions = load_exemptions(root)
    seen_keys = set()
    for path in tracked_rs_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, fn_name, can_fail in find_tests(text):
            key = f"{rel}:{fn_name}"
            if can_fail:
                continue
            seen_keys.add(key)
            if key in exemptions:
                continue
            findings.append((key, rel, lineno, fn_name))
    stale = sorted(exemptions - seen_keys)
    return findings, stale


def self_test() -> bool:
    problems = []

    vacuous = """
#[test]
fn round_trip_no_assert() {
    let a = 1;
    let b = 1;
    if a == b {
        println!("ok");
    } else {
        println!("fail");
    }
}
"""
    r = find_tests(vacuous)
    if len(r) != 1 or r[0][2] is not False:
        problems.append(f"a println-only test must be flagged as cannot-fail (got {r})")

    normal = """
#[test]
fn real_assert() {
    let a = 1;
    assert_eq!(a, 1);
}
"""
    r = find_tests(normal)
    if len(r) != 1 or r[0][2] is not True:
        problems.append(f"a test with assert_eq! must NOT be flagged (got {r})")

    should_panic = """
#[test]
#[should_panic]
fn expected_panic() {
    let v: Vec<i32> = Vec::new();
    let _ = v[0];
}
"""
    r = find_tests(should_panic)
    if len(r) != 1 or r[0][2] is not True:
        problems.append(f"a #[should_panic] test must NOT be flagged (got {r})")

    try_op = """
#[test]
fn returns_result() -> Result<(), String> {
    let a: Result<i32, String> = Ok(1);
    let v = a?;
    let _ = v;
    Ok(())
}
"""
    r = find_tests(try_op)
    if len(r) != 1 or r[0][2] is not True:
        problems.append(f"a `?`-returning Result test must NOT be flagged (got {r})")

    unwrap_case = """
#[test]
fn uses_unwrap() {
    let a: Option<i32> = Some(1);
    let v = a.unwrap();
    println!("{}", v);
}
"""
    r = find_tests(unwrap_case)
    if len(r) != 1 or r[0][2] is not True:
        problems.append(f"a test using .unwrap() must NOT be flagged (got {r})")

    string_trap = '''
#[test]
fn string_with_braces_and_panic_word() {
    let s = "this text says panic! but is just a string { }";
    let expected = "this text says panic! but is just a string { }";
    assert_eq!(s, expected);
}
'''
    r = find_tests(string_trap)
    if len(r) != 1 or r[0][2] is not True or r[0][1] != "string_with_braces_and_panic_word":
        problems.append(f"brace-in-string must not desync brace matching (got {r})")

    if problems:
        for p in problems:
            print(f"  - {p}")
        print("SELF-TEST FAILED -- the no-assert-test guard is not detecting what it claims.")
        return False
    return True


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        if self_test():
            print("ci_guard_no_assert_tests: self-test OK")
            return 0
        return 1

    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

    if not self_test():
        return 1

    findings, stale = scan_repo(root)

    rc = 0
    if stale:
        print(f"ci_guard_no_assert_tests: {len(stale)} stale exemption(s) in scripts/{EXEMPTIONS_NAME}"
              f" (test now fails, is gone, or is now assertion-capable -- remove the line):")
        for key in stale:
            print(f"  {key}")
        rc = 1

    if findings:
        print(f"ci_guard_no_assert_tests: {len(findings)} #[test] fn(s) with no failure mechanism:")
        for key, rel, lineno, fn_name in findings:
            print(f"  {rel}:{lineno}: fn {fn_name} -- no assert/panic/unwrap/expect/?/should_panic found")
        print(
            "  Fix by adding a real assertion, or if a callee-panic-only test is deliberate,"
            f" add '<path>:<fn_name> | <reason>' to scripts/{EXEMPTIONS_NAME}."
        )
        rc = 1

    if rc == 0:
        print("ci_guard_no_assert_tests: OK -- every #[test] fn scanned has a failure mechanism")
    return rc


if __name__ == "__main__":
    sys.exit(main())
