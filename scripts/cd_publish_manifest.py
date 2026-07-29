#!/usr/bin/env python3
"""Derive the publish manifest (what ships, and in what order) from .github/workflows/cd.yml.

WHY THIS EXISTS
---------------
`.github/workflows/cd.yml` is the ONLY authority on which crates and npm packages libQ
publishes and in what order. Three other places restate that list by hand:

  * scripts/publish-crates-io-ordered.ps1  -- the operator's crates.io fallback
  * scripts/publish-npm-ordered.sh         -- the operator's npm fallback
  * docs/npm-publish.md                    -- the "Package list (CD order)" table

A hand-maintained restatement of a list that grows every release does not stay correct: at
0.0.10 the PowerShell fallback listed 65 of cd.yml's 80 crates. Nothing failed. An operator
who fell back to it would have shipped an incomplete release and been told "All 65 workspace
crates published." crates.io versions are immutable, so that ships wrong permanently.

This module is the single derivation point. scripts/ci_guard_publish_order.py diffs every
restatement against it on each pull request, and scripts/publish-readiness-pr.sh uses it
instead of its own regex over cd.yml.

WHY IT SHIPS ITS OWN YAML PARSER
--------------------------------
It runs in the ci.yml `core-validation` job, which has no pip step (same constraint as
scripts/ci_guard_coverage_honesty.py), and PyYAML is not a dependency of this repo -- no
script imports it today. So the parser below is stdlib-only and covers exactly the block-YAML
subset cd.yml uses. It FAILS CLOSED: anything it does not model (tabs, anchors/aliases, flow
mappings, merge keys) raises rather than being silently skipped, because a parser that
silently drops a job is the very failure mode this file exists to prevent.

It is also cross-checked: `--self-check` re-derives the manifest with PyYAML when PyYAML
happens to be importable (dev boxes) and errors if the two disagree. CI does not depend on
that, but a divergence introduced by a future cd.yml construct gets caught by anyone who runs
the guard locally.

WHAT THIS DOES *NOT* MODEL
--------------------------
  * `if:` conditions on publish jobs -- every crate-publish/npm-publish step is treated as
    unconditional. cd.yml has no conditional publish job today; one added later would be
    reported as always-publishing.
  * matrix `exclude:` / non-`include` matrix axes -- only `strategy.matrix.include` is
    expanded. A cartesian matrix over a `package:` axis would raise rather than be guessed at.
  * Ordering WITHIN a matrix job. cd.yml matrix entries run in parallel, so cd.yml asserts no
    order between them; only the `needs` DAG constrains order (see `ancestor_map`).

Usage:
  python3 scripts/cd_publish_manifest.py [--root DIR] --format {json,crates,npm}
  python3 scripts/cd_publish_manifest.py --self-check
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

CRATE_PUBLISH_ACTION = "./.github/actions/crate-publish"
NPM_PUBLISH_ACTION = "./.github/actions/npm-publish"

_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)")
_BLOCK_SCALAR = re.compile(r"^[|>][+-]?[0-9]*$")
_KEY_LINE = re.compile(r'^(?:"([^"]*)"|\'([^\']*)\'|([^:]+?))\s*:(?:\s+(.*?))?\s*$')


class CdParseError(RuntimeError):
    """cd.yml contains a construct this parser does not model. Always fatal."""


# ---------------------------------------------------------------------------
# Minimal block-YAML parser (stdlib only, fail-closed)
# ---------------------------------------------------------------------------


def _leading_indent(line: str) -> int:
    stripped = line.lstrip(" ")
    n = len(line) - len(stripped)
    if "\t" in line[:n]:
        raise CdParseError(f"tab in indentation: {line!r}")
    return n


def _strip_comment(line: str) -> str:
    """Drop a trailing `# ...` comment, honouring quoted scalars."""
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is not None:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                i += 1
                out.append(line[i])
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1] in " \t"):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _is_blank(line: str) -> bool:
    return _strip_comment(line).strip() == ""


def _next_significant(lines: list[str], i: int) -> int:
    while i < len(lines) and _is_blank(lines[i]):
        i += 1
    return i


def _scalar(raw: str) -> object:
    text = raw.strip()
    if text == "" or text == "~" or text == "null":
        return None
    if text[0] in "&*":
        raise CdParseError(f"YAML anchors/aliases are not modelled: {raw!r}")
    if text[0] == "{":
        raise CdParseError(f"flow mappings are not modelled: {raw!r}")
    if text[0] == "[":
        if not text.endswith("]"):
            raise CdParseError(f"multi-line flow sequence is not modelled: {raw!r}")
        return _flow_sequence(text[1:-1])
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        body = text[1:-1]
        if text[0] == '"':
            body = body.replace('\\"', '"').replace("\\\\", "\\")
        return body
    return text


def _flow_sequence(body: str) -> list[object]:
    items: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for ch in body:
        if quote is not None:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
        elif ch in "[{":
            depth += 1
            current.append(ch)
        elif ch in "]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            items.append("".join(current))
            current = []
        else:
            current.append(ch)
    if "".join(current).strip():
        items.append("".join(current))
    return [_scalar(item) for item in items]


def _consume_block_scalar(lines: list[str], i: int, key_indent: int) -> tuple[str, int]:
    body: list[str] = []
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            body.append("")
            i += 1
            continue
        if _leading_indent(line) <= key_indent:
            break
        body.append(line)
        i += 1
    return "\n".join(body), i


def _parse_node(lines: list[str], i: int, indent: int) -> tuple[object, int]:
    i = _next_significant(lines, i)
    if i >= len(lines) or _leading_indent(lines[i]) < indent:
        return None, i
    content = _strip_comment(lines[i]).strip()
    if content == "-" or content.startswith("- "):
        return _parse_sequence(lines, i, indent)
    return _parse_mapping(lines, i, indent)


def _parse_mapping(lines: list[str], i: int, indent: int) -> tuple[dict, int]:
    result: dict[str, object] = {}
    while True:
        i = _next_significant(lines, i)
        if i >= len(lines):
            return result, i
        line_indent = _leading_indent(lines[i])
        if line_indent < indent:
            return result, i
        if line_indent > indent:
            raise CdParseError(f"unexpected indent at line {i + 1}: {lines[i]!r}")
        content = _strip_comment(lines[i]).strip()
        if content.startswith("- "):
            return result, i
        if content.startswith("<<"):
            raise CdParseError(f"merge keys are not modelled: {lines[i]!r}")
        m = _KEY_LINE.match(content)
        if not m:
            raise CdParseError(f"unparsable mapping line {i + 1}: {lines[i]!r}")
        key = next(g for g in m.groups()[:3] if g is not None).strip()
        raw_value = m.group(4)
        i += 1
        if raw_value and _BLOCK_SCALAR.match(raw_value):
            value, i = _consume_block_scalar(lines, i, line_indent)
        elif raw_value:
            value = _scalar(raw_value)
        else:
            j = _next_significant(lines, i)
            if j < len(lines) and _leading_indent(lines[j]) > line_indent:
                value, i = _parse_node(lines, j, _leading_indent(lines[j]))
            else:
                value = None
        if key in result:
            raise CdParseError(f"duplicate key {key!r} at line {i}")
        result[key] = value


def _parse_sequence(lines: list[str], i: int, indent: int) -> tuple[list, int]:
    items: list[object] = []
    work = lines  # mutated in place for the "- key: value" continuation trick
    while True:
        i = _next_significant(work, i)
        if i >= len(work):
            return items, i
        line_indent = _leading_indent(work[i])
        if line_indent < indent:
            return items, i
        content = _strip_comment(work[i]).strip()
        if not (content == "-" or content.startswith("- ")):
            return items, i
        if line_indent != indent:
            raise CdParseError(f"ragged sequence indent at line {i + 1}: {work[i]!r}")
        stripped = _strip_comment(work[i])
        dash_col = len(stripped) - len(stripped.lstrip(" "))
        rest = stripped[dash_col + 1 :]
        if rest.strip() == "":
            i += 1
            j = _next_significant(work, i)
            if j < len(work) and _leading_indent(work[j]) > indent:
                value, i = _parse_node(work, j, _leading_indent(work[j]))
            else:
                value = None
            items.append(value)
            continue
        item_col = dash_col + 1 + (len(rest) - len(rest.lstrip(" ")))
        payload = " " * item_col + rest.lstrip(" ")
        if _KEY_LINE.match(payload.strip()):
            work[i] = payload
            value, i = _parse_mapping(work, i, item_col)
        else:
            value = _scalar(rest)
            i += 1
        items.append(value)


def parse_yaml(text: str) -> object:
    lines = text.replace("\r\n", "\n").split("\n")
    lines = [line for line in lines if line.strip() != "---"]
    value, _ = _parse_node(lines, 0, 0)
    return value


# ---------------------------------------------------------------------------
# Publish-manifest extraction
# ---------------------------------------------------------------------------


def _needs_of(jobs: dict, name: str) -> list[str]:
    needs = jobs[name].get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    for dep in needs:
        if dep not in jobs:
            raise CdParseError(f"job {name!r} needs unknown job {dep!r}")
    return list(needs)


def job_order(jobs: dict) -> list[str]:
    """Deterministic topological order: earliest ready job in file order wins."""
    remaining = list(jobs)
    done: set[str] = set()
    order: list[str] = []
    while remaining:
        for name in remaining:
            if all(dep in done for dep in _needs_of(jobs, name)):
                order.append(name)
                done.add(name)
                remaining.remove(name)
                break
        else:
            raise CdParseError(f"cycle in cd.yml job `needs`: {remaining}")
    return order


def ancestor_map(jobs: dict) -> dict[str, set[str]]:
    """job -> every job that must complete before it (transitive `needs` closure)."""
    cache: dict[str, set[str]] = {}

    def walk(name: str, seen: frozenset) -> set[str]:
        if name in cache:
            return cache[name]
        if name in seen:
            raise CdParseError(f"cycle in cd.yml job `needs` at {name!r}")
        acc: set[str] = set()
        for dep in _needs_of(jobs, name):
            acc.add(dep)
            acc |= walk(dep, seen | {name})
        cache[name] = acc
        return acc

    return {name: walk(name, frozenset()) for name in jobs}


def _matrix_include(job: dict, job_name: str) -> list[dict]:
    strategy = job.get("strategy") or {}
    matrix = strategy.get("matrix") or {}
    if not isinstance(matrix, dict):
        raise CdParseError(f"job {job_name!r}: unmodelled matrix shape")
    extra = set(matrix) - {"include", "fail-fast"}
    if extra:
        raise CdParseError(
            f"job {job_name!r}: only `strategy.matrix.include` is modelled, found axes {sorted(extra)}"
        )
    include = matrix.get("include") or []
    if not isinstance(include, list):
        raise CdParseError(f"job {job_name!r}: `matrix.include` is not a list")
    return include


def _resolve(value, entry: dict, job_name: str, field: str):
    """Resolve a `with:` value that may reference `matrix.<field>`."""
    if not isinstance(value, str):
        return value
    ref = _MATRIX_REF.search(value)
    if not ref:
        return value
    name = ref.group(1)
    if value.strip() != "${{ matrix.%s }}" % name:
        # e.g. `${{ matrix.out-dir || 'pkg' }}` -- honour the documented default only.
        fallback = re.search(r"\|\|\s*'([^']*)'\s*\}\}", value)
        resolved = entry.get(name)
        if resolved not in (None, ""):
            return resolved
        if fallback:
            return fallback.group(1)
        raise CdParseError(
            f"job {job_name!r}: cannot resolve {field}={value!r} for matrix entry {entry!r}"
        )
    if name not in entry:
        raise CdParseError(
            f"job {job_name!r}: matrix entry {entry!r} has no `{name}` for {field}"
        )
    return entry[name]


def extract(root: pathlib.Path, doc: dict | None = None) -> dict:
    """Return {"crates": [...], "npm": [...], "jobs": [...], "ancestors": {...}}."""
    if doc is None:
        cd_path = root / ".github" / "workflows" / "cd.yml"
        if not cd_path.is_file():
            raise CdParseError(f"missing {cd_path}")
        doc = parse_yaml(cd_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise CdParseError("cd.yml did not parse to a mapping")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise CdParseError("cd.yml has no `jobs:` mapping")

    order = job_order(jobs)
    ancestors = ancestor_map(jobs)
    crates: list[dict] = []
    npm: list[dict] = []

    for job_name in order:
        job = jobs[job_name]
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            raise CdParseError(f"job {job_name!r}: `steps` is not a list")
        include = None
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if uses not in (CRATE_PUBLISH_ACTION, NPM_PUBLISH_ACTION):
                continue
            with_ = step.get("with") or {}
            if not isinstance(with_, dict):
                raise CdParseError(f"job {job_name!r}: publish step has no `with:` mapping")
            key = "package" if uses == CRATE_PUBLISH_ACTION else "package-name"
            raw = with_.get(key)
            if not isinstance(raw, str) or not raw:
                raise CdParseError(f"job {job_name!r}: publish step is missing `{key}`")
            if _MATRIX_REF.search(raw):
                if include is None:
                    include = _matrix_include(job, job_name)
                if not include:
                    raise CdParseError(
                        f"job {job_name!r}: publish step reads `matrix.*` but the job has no matrix.include"
                    )
                entries = include
            else:
                entries = [{}]
            for entry in entries:
                if not isinstance(entry, dict):
                    raise CdParseError(f"job {job_name!r}: matrix entry is not a mapping")
                if uses == CRATE_PUBLISH_ACTION:
                    crates.append(
                        {
                            "package": _resolve(raw, entry, job_name, key),
                            "working_directory": _resolve(
                                with_.get("working-directory"), entry, job_name, "working-directory"
                            ),
                            "job": job_name,
                        }
                    )
                else:
                    # The npm-publish step's own `working-directory` is the *built package*
                    # dir (`${{ format('{0}/{1}', matrix.working-directory, ...) }}`); the
                    # crate root that the wasm build runs in is the matrix entry's
                    # `working-directory`. Take the crate root -- that is what the fallback
                    # script and the docs table restate.
                    npm.append(
                        {
                            "package": _resolve(raw, entry, job_name, key),
                            "working_directory": entry.get("working-directory")
                            if entry
                            else with_.get("working-directory"),
                            "features": entry.get("features") if entry else None,
                            "out_dir": entry.get("out-dir") if entry else None,
                            "job": job_name,
                        }
                    )

    if not crates:
        raise CdParseError("cd.yml yielded zero crate-publish steps -- refusing to report success")
    if not npm:
        raise CdParseError("cd.yml yielded zero npm-publish steps -- refusing to report success")

    for item in crates + npm:
        for field in ("package", "working_directory"):
            value = item.get(field)
            if isinstance(value, str) and "${{" in value:
                raise CdParseError(f"unresolved {field}={value!r} for {item['package']!r}")
    for item in npm:
        if not item["working_directory"]:
            raise CdParseError(f"npm package {item['package']!r} has no working-directory")
        # cd.yml defaults out-dir to `pkg` (`${{ matrix.out-dir || 'pkg' }}`); the TypeScript-only
        # package is published straight from its source dir and has no wasm-pack out-dir at all.
        if item["out_dir"] in (None, "") and item["job"] != "publish-npm-types":
            item["out_dir"] = "pkg"

    seen: set[str] = set()
    for item in crates:
        if item["package"] in seen:
            raise CdParseError(f"cd.yml publishes {item['package']!r} twice")
        seen.add(item["package"])

    return {"crates": crates, "npm": npm, "jobs": order, "ancestors": {k: sorted(v) for k, v in ancestors.items()}}


def crate_names(root: pathlib.Path) -> list[str]:
    return [c["package"] for c in extract(root)["crates"]]


# ---------------------------------------------------------------------------
# Self-check against PyYAML (only when PyYAML is importable)
# ---------------------------------------------------------------------------


def self_check(root: pathlib.Path) -> int:
    mine = extract(root)
    try:
        import yaml  # type: ignore
    except ImportError:
        print("self-check: PyYAML not importable; stdlib parser not cross-validated (OK)")
        return 0
    cd_path = root / ".github" / "workflows" / "cd.yml"
    theirs = extract(root, doc=yaml.safe_load(cd_path.read_text(encoding="utf-8")))
    diffs = []
    for field in ("crates", "npm", "jobs"):
        if mine[field] != theirs[field]:
            diffs.append(field)
    if diffs:
        print(f"self-check FAILED: stdlib parser disagrees with PyYAML on {diffs}", file=sys.stderr)
        for field in diffs:
            print(f"  stdlib: {json.dumps(mine[field], indent=2)}", file=sys.stderr)
            print(f"  pyyaml: {json.dumps(theirs[field], indent=2)}", file=sys.stderr)
        return 1
    print(
        f"self-check: stdlib parser == PyYAML "
        f"({len(mine['crates'])} crates, {len(mine['npm'])} npm packages, {len(mine['jobs'])} jobs)"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=None, help="repo root (default: this file's parent's parent)")
    ap.add_argument("--format", choices=("json", "crates", "npm", "jobs"), default="json")
    ap.add_argument("--self-check", action="store_true", help="cross-validate against PyYAML if present")
    args = ap.parse_args(argv)

    root = pathlib.Path(args.root) if args.root else pathlib.Path(__file__).resolve().parent.parent
    if args.self_check:
        return self_check(root)

    manifest = extract(root)
    if args.format == "json":
        print(json.dumps(manifest, indent=2))
    elif args.format == "crates":
        for item in manifest["crates"]:
            print(item["package"])
    elif args.format == "npm":
        for item in manifest["npm"]:
            print(
                "\t".join(
                    [
                        item["package"],
                        item["working_directory"] or "",
                        item["features"] or "",
                        item["out_dir"] or "",
                    ]
                )
            )
    else:
        for name in manifest["jobs"]:
            print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
