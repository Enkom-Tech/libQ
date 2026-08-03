#!/usr/bin/env python3
"""Assert that every hand-maintained restatement of the publish list still matches cd.yml.

Driven by scripts/ci-guard-publish-order.sh (see that file for the rationale).
Standard library only: this runs in the ci.yml `core-validation` job, which has no pip step.

  CHECK 1  scripts/publish-crates-io-ordered.ps1 `$packages` publishes exactly cd.yml's crates
  CHECK 2  ...in an order that respects cd.yml's `needs` DAG
  CHECK 3  scripts/publish-crates-io-ordered.ps1 `$nestedManifest` matches cd.yml's
           `working-directory:` overrides (the nested FN-DSA manifests)
  CHECK 4  scripts/publish-npm-ordered.sh publishes exactly cd.yml's npm packages, with the
           same crate dir, wasm-pack features and out-dir
  CHECK 5  the docs/npm-publish.md "Package list (CD order)" table lists exactly those packages
           and states the right total

Every check fails CLOSED: if a list cannot be located or parsed, that is an error, not a pass.
A guard that silently finds nothing to compare is indistinguishable from a guard that passes.

WHY ORDER IS CHECKED AS A DAG, NOT AS A SEQUENCE (CHECK 2)
----------------------------------------------------------
cd.yml runs matrix entries in PARALLEL, so it asserts no order between crates inside one job --
only `needs` between jobs constrains anything. Demanding that the fallback script reproduce one
particular linearization would encode an arbitrary choice as gospel and would forbid legitimate
local-only reordering (e.g. publishing lib-q-blind-pcs before lib-q-dkg, which share a tier-4b
matrix with no `needs` edge between them). So the rule is: for every pair where cd.yml makes job(A) a
transitive prerequisite of job(B), the script must publish A before B.
"""

from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cd_publish_manifest import CdParseError, extract  # noqa: E402

PS1 = "scripts/publish-crates-io-ordered.ps1"
NPM_SH = "scripts/publish-npm-ordered.sh"
NPM_DOC = "docs/npm-publish.md"

failures: list[str] = []


def fail(check: str, message: str) -> None:
    failures.append(f"[{check}] {message}")


def read(root: pathlib.Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        raise SystemExit(f"ci-guard-publish-order: expected file is missing: {rel}")
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Restatement parsers -- each raises (never returns empty) when it finds nothing
# ---------------------------------------------------------------------------


def _strip_ps1_comments(text: str, source: str) -> str:
    """Blank out PowerShell `# ...` line comments and `<# ... #>` block comments,
    leaving string literals -- and every other character -- exactly where they
    were (comment text is replaced with spaces, newlines are kept), so the
    `re.MULTILINE`/`re.DOTALL` anchors the callers use still line up.

    This is deliberately NOT `line.split('#')[0]`. PowerShell, like most
    languages, does not treat `#` as a comment when it is inside a string --
    `"lib-q-mac # not a comment"` is one 26-character string, not a crate name
    truncated at the space. A naive split-on-`#` would silently mis-parse that
    (and, worse, would fail to notice a REAL comment hiding a crate, which is
    the bug this function exists to fix). So this walks the text one character
    at a time and tracks whether it is inside a single-quoted string (`'...'`,
    self-escaped as `''`), a double-quoted string (`"..."`, escaped with a
    backtick or self-escaped as `""`), or a block comment -- `#` only starts a
    line comment, and `<#` only starts a block comment, when none of those
    apply. A tokenizer that tracks this one bit of state (in-string or not) is
    harder to get subtly wrong than any regex/strip trick operating on whole
    lines, because it can never misjudge a `#` by looking at the wrong side of
    a quote.

    Fails closed on here-strings (`@"` / `@'`): every restatement this scanner
    reads is a flat list of plain quoted scalars, so a here-string appearing
    here means a construct this scanner was not built to reason about has been
    introduced. Guessing at where it ends is exactly the kind of blind spot
    this guard exists to close, so this raises instead.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        two = text[i : i + 2]
        if two == "<#":
            end = text.find("#>", i + 2)
            if end == -1:
                raise SystemExit(f"ci-guard-publish-order: unterminated <# comment #> in {source}")
            out.append("".join(c if c == "\n" else " " for c in text[i : end + 2]))
            i = end + 2
            continue
        if two in ('@"', "@'"):
            raise SystemExit(
                f"ci-guard-publish-order: here-string ({two}...) in {source} is not modelled by "
                "this scanner -- rewrite the restatement using plain quoted entries"
            )
        ch = text[i]
        if ch in "\"'":
            quote = ch
            j = i + 1
            while j < n:
                if quote == '"' and text[j] == "`" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == quote:
                    if j + 1 < n and text[j + 1] == quote:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            else:
                raise SystemExit(f"ci-guard-publish-order: unterminated {quote}-quoted string in {source}")
            out.append(text[i:j])
            i = j
            continue
        if ch == "#":
            end = text.find("\n", i)
            if end == -1:
                end = n
            out.append(" " * (end - i))
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def ps1_packages(text: str) -> list[str]:
    scanned = _strip_ps1_comments(text, PS1)
    m = re.search(r"^\$packages\s*=\s*@\(\s*$(.*?)^\)\s*$", scanned, re.MULTILINE | re.DOTALL)
    if not m:
        raise SystemExit(f"ci-guard-publish-order: could not locate `$packages = @(...)` in {PS1}")
    names = re.findall(r'"([^"]+)"', m.group(1))
    if not names:
        raise SystemExit(f"ci-guard-publish-order: `$packages` in {PS1} parsed to zero entries")
    return names


def ps1_nested_manifests(text: str) -> dict[str, str]:
    scanned = _strip_ps1_comments(text, PS1)
    m = re.search(r"^\$nestedManifest\s*=\s*@\{\s*$(.*?)^\}\s*$", scanned, re.MULTILINE | re.DOTALL)
    if not m:
        raise SystemExit(f"ci-guard-publish-order: could not locate `$nestedManifest = @{{...}}` in {PS1}")
    pairs = re.findall(r'"([^"]+)"\s*=\s*"([^"]+)"', m.group(1))
    return dict(pairs)


def sh_npm_rows(text: str) -> list[dict[str, str]]:
    # NOT vulnerable to the .ps1 comment-blindness bug (verified, not assumed): the row table
    # lives inside `<<'EOF' ... EOF` -- a QUOTED bash heredoc. Quoting the delimiter disables
    # every bit of shell interpretation of the body, `#` included, so a `#`-prefixed row is not
    # a comment to bash either: the real script still reads it as a literal (malformed) data row
    # and fails loudly trying to build/publish it, and this parser (which never special-cases
    # `#`) sees the same row and reports it as a mismatch. Confirmed by mutation: prefixing a row
    # with `#` here makes `bash`'s own `mapfile` still count it (30 rows, not 29) and this
    # function's CHECK 4 fail on the corrupted working-directory -- neither reading is fooled.
    m = re.search(r"<<'EOF'.*?\n(.*?)\nEOF\n", text, re.DOTALL)
    if not m:
        raise SystemExit(f"ci-guard-publish-order: could not locate the PACKAGES heredoc in {NPM_SH}")
    rows = []
    for line in m.group(1).splitlines():
        if not line.strip() or "|" not in line:
            continue
        parts = (line.split("|") + [""] * 7)[:7]
        rows.append(
            {
                "working_directory": parts[0],
                "package": parts[1],
                "features": parts[4],
                "out_dir": parts[5],
                "types_only": parts[6],
            }
        )
    if not rows:
        raise SystemExit(f"ci-guard-publish-order: the PACKAGES heredoc in {NPM_SH} parsed to zero rows")
    return rows


def doc_npm_table(text: str) -> tuple[list[str], int | None]:
    # NOT vulnerable to the .ps1 comment-blindness bug (verified, not assumed): wrapping a row in
    # an HTML comment (`<!-- | ... | --> `) hides it from a rendered markdown VIEW, but this
    # function -- like every markdown renderer's source input -- reads the raw file text, and an
    # HTML comment does not remove or alter that text. Confirmed by mutation: wrapping the
    # `@lib-q/mac` row in `<!-- -->` left the guard's row count and output unchanged (still found,
    # still OK). There is no discrepancy between what this parser sees and what a renderer hides,
    # so there is nothing here for a `#`-style scanner fix to close.
    m = re.search(r"^## Package list \(CD order\)\s*$(.*?)^## ", text, re.MULTILINE | re.DOTALL)
    if not m:
        raise SystemExit(
            f"ci-guard-publish-order: could not locate the '## Package list (CD order)' section in {NPM_DOC}"
        )
    section = m.group(1)
    names = re.findall(r"^\|\s*`(@lib-q/[^`]+)`\s*\|", section, re.MULTILINE)
    if not names:
        raise SystemExit(f"ci-guard-publish-order: the {NPM_DOC} package table parsed to zero rows")
    total = re.search(r"\*\*Total:\s*(\d+)\s+packages\*\*", section)
    return names, int(total.group(1)) if total else None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_crate_membership(cd_crates: list[str], script: list[str]) -> None:
    missing = [c for c in cd_crates if c not in script]
    extra = [c for c in script if c not in cd_crates]
    if missing:
        fail(
            "CHECK 1",
            f"{PS1} would silently skip {len(missing)} crate(s) that cd.yml publishes: "
            + ", ".join(missing),
        )
    if extra:
        fail(
            "CHECK 1",
            f"{PS1} lists {len(extra)} crate(s) cd.yml does not publish: " + ", ".join(extra),
        )
    dupes = sorted({c for c in script if script.count(c) > 1})
    if dupes:
        fail("CHECK 1", f"{PS1} lists these crates more than once: " + ", ".join(dupes))


def check_crate_order(manifest: dict, script: list[str]) -> None:
    job_of = {c["package"]: c["job"] for c in manifest["crates"]}
    ancestors = {k: set(v) for k, v in manifest["ancestors"].items()}
    position = {name: i for i, name in enumerate(script)}
    reported = 0
    for later, later_pos in position.items():
        job_later = job_of.get(later)
        if job_later is None:
            continue
        for earlier, earlier_pos in position.items():
            job_earlier = job_of.get(earlier)
            if job_earlier is None or earlier_pos <= later_pos:
                continue
            if job_earlier in ancestors.get(job_later, ()):
                fail(
                    "CHECK 2",
                    f"{PS1} publishes {later} (#{later_pos}, cd.yml job {job_later}) before its "
                    f"cd.yml prerequisite {earlier} (#{earlier_pos}, job {job_earlier})",
                )
                reported += 1
                if reported >= 25:
                    fail("CHECK 2", "... further order violations suppressed")
                    return


def check_nested_manifests(manifest: dict, nested: dict[str, str]) -> None:
    expected = {
        c["package"]: f"{c['working_directory']}/Cargo.toml"
        for c in manifest["crates"]
        if c["working_directory"]
    }
    for pkg, path in expected.items():
        if pkg not in nested:
            fail(
                "CHECK 3",
                f"{PS1} `$nestedManifest` is missing {pkg} -> {path}; cd.yml publishes that crate "
                f"with an explicit `working-directory:`, so `cargo publish -p` from the repo root "
                f"would resolve the wrong manifest",
            )
        elif nested[pkg].replace("\\", "/") != path:
            fail("CHECK 3", f"{PS1} `$nestedManifest[{pkg}]` = {nested[pkg]!r}, cd.yml says {path!r}")
    for pkg in nested:
        if pkg not in expected:
            fail("CHECK 3", f"{PS1} `$nestedManifest` has {pkg}, which cd.yml publishes from the repo root")


def check_npm(manifest: dict, rows: list[dict[str, str]]) -> None:
    cd_by_name = {item["package"]: item for item in manifest["npm"]}
    row_names = [row["package"] for row in rows]
    sh_by_name = {row["package"]: row for row in rows}
    for name in cd_by_name:
        if name not in sh_by_name:
            fail("CHECK 4", f"{NPM_SH} would silently skip {name}, which cd.yml publishes")
    for name in sh_by_name:
        if name not in cd_by_name:
            fail("CHECK 4", f"{NPM_SH} lists {name}, which cd.yml does not publish")
    dupes = sorted({n for n in row_names if row_names.count(n) > 1})
    if dupes:
        fail("CHECK 4", f"{NPM_SH} lists these packages more than once: " + ", ".join(dupes))
    for name, item in cd_by_name.items():
        row = sh_by_name.get(name)
        if row is None:
            continue
        if row["working_directory"] != item["working_directory"]:
            fail(
                "CHECK 4",
                f"{NPM_SH} builds {name} from {row['working_directory']!r}; "
                f"cd.yml uses {item['working_directory']!r}",
            )
        if row["types_only"] == "1":
            # TypeScript-only package: no wasm-pack build, so features/out-dir do not apply.
            continue
        if row["features"] != (item["features"] or ""):
            fail(
                "CHECK 4",
                f"{NPM_SH} builds {name} with features {row['features']!r}; "
                f"cd.yml uses {(item['features'] or '')!r}",
            )
        if row["out_dir"] != (item["out_dir"] or ""):
            fail(
                "CHECK 4",
                f"{NPM_SH} builds {name} into out-dir {row['out_dir']!r}; "
                f"cd.yml uses {(item['out_dir'] or '')!r}",
            )


def check_doc(manifest: dict, names: list[str], total: int | None) -> None:
    cd_names = [item["package"] for item in manifest["npm"]]
    for name in cd_names:
        if name not in names:
            fail("CHECK 5", f"{NPM_DOC} package table is missing {name}, which cd.yml publishes")
    for name in names:
        if name not in cd_names:
            fail("CHECK 5", f"{NPM_DOC} package table lists {name}, which cd.yml does not publish")
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        fail("CHECK 5", f"{NPM_DOC} package table lists these packages more than once: " + ", ".join(dupes))
    if total is None:
        fail("CHECK 5", f"{NPM_DOC} no longer states a '**Total: N packages**' count")
    else:
        if total != len(cd_names):
            fail("CHECK 5", f"{NPM_DOC} claims {total} packages; cd.yml publishes {len(cd_names)}")
        # Compare against the number of rows actually parsed too, not just cd.yml's count: a
        # padding duplicate row (e.g. 31 rows for 30 distinct packages, still stated as "30")
        # would pass the membership and the above checks -- every cd.yml package is present, the
        # stated total matches cd.yml -- while the table itself has drifted from what it claims.
        if total != len(names):
            fail(
                "CHECK 5",
                f"{NPM_DOC} claims {total} packages but its table has {len(names)} rows "
                f"({len(set(names))} distinct)",
            )


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    try:
        manifest = extract(root)
    except CdParseError as exc:
        print(f"ci-guard-publish-order: cannot derive the publish manifest from cd.yml: {exc}", file=sys.stderr)
        return 1

    cd_crates = [c["package"] for c in manifest["crates"]]
    ps1_text = read(root, PS1)
    script_crates = ps1_packages(ps1_text)

    check_crate_membership(cd_crates, script_crates)
    check_crate_order(manifest, script_crates)
    check_nested_manifests(manifest, ps1_nested_manifests(ps1_text))
    check_npm(manifest, sh_npm_rows(read(root, NPM_SH)))
    doc_names, doc_total = doc_npm_table(read(root, NPM_DOC))
    check_doc(manifest, doc_names, doc_total)

    if failures:
        print("ERROR: a publish list has drifted from .github/workflows/cd.yml.", file=sys.stderr)
        print(
            "cd.yml is the authority. An out-of-date fallback script does not error -- it just "
            "publishes fewer crates and reports success.",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        for item in failures:
            print(f"  {item}", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "Regenerate the lists from cd.yml:\n"
            "  python3 scripts/cd_publish_manifest.py --format crates\n"
            "  python3 scripts/cd_publish_manifest.py --format npm",
            file=sys.stderr,
        )
        return 1

    print(
        f"publish-order guard: OK ({len(cd_crates)} crates, {len(manifest['npm'])} npm packages "
        f"in cd.yml; fallback scripts and docs/npm-publish.md agree)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
