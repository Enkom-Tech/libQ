#!/usr/bin/env python3
"""Assert every committed KAT (Known-Answer-Test) vector file discloses where it came from.

Driven by scripts/ci-guard-kat-provenance.sh (see that file for the interpreter-probe rationale
and the card this guard responds to). Reads kats-manifest.toml at the repo root. Five checks;
each fails CLOSED (an unparseable or missing input is an error, not a pass):

  CHECK 1  discovery is non-vacuous: every registered [scan].roots directory exists and yields at
           least one matching file. A registered root that finds nothing is as suspicious as
           finding too much -- usually it means a path moved and the guard is silently checking
           an empty directory while the real files go unchecked.
  CHECK 2  manifest coverage, both directions: every discovered file has exactly one [[kat]]
           entry, and every [[kat]] entry names a file that still exists.
  CHECK 3  content hash: each entry's `sha256` matches the file's current SHA-256. This is what
           makes a silent regeneration of a "self-generated" pin -- or a silent edit of an
           "upstream" extract -- visible in code review instead of invisible.
  CHECK 4  naming: an entry whose `origin` is not "upstream" may not sit at a path or carry a
           filename containing "official", "nist", or "rfc" (case-insensitive, word-bounded).
           This is the rule the card exists to enforce: lib-q-hqc's `kats/official/` held nine
           KAT tests whose every response value was written by the code under test.
  CHECK 5  header/manifest cross-check: the file's own leading `#`-comment must say what its
           manifest `origin` says, so a file cannot be manifested as "self-generated" while its
           own header still calls itself authoritative (or the reverse). `origin = "upstream"`
           entries must also carry `upstream_url` and `upstream_sha256`.

           EXEMPTION (added 2026-08-06, card t_71d4f79a second pass): an `origin = "upstream"`
           entry whose manifest `sha256` equals its own `upstream_sha256` is exempt from the
           header-comment requirement. Vector files vendored byte-for-byte from a designers'/
           NIST's own distribution get their evidentiary value FROM being byte-identical to that
           distribution; splicing in a header comment would edit their bytes and falsify the very
           equality that is the evidence. The exemption cannot be reached by a non-upstream entry
           no matter what fields it also carries (e.g. a copied `upstream_sha256`), because it is
           lexically nested inside the `origin == "upstream"` branch in `check_headers` below --
           see that function's comment for the full reasoning and a pointer to the abuse-attempt
           test that exercises this. The exemption is ALSO refused (added in review, same day) for
           any path CHECK 4's naming ban would otherwise catch: without that refusal, an entry
           that simply lies `origin = "upstream"` at a `kats/official/`-shaped path skipped CHECK
           4's naming ban (which by design does not apply to declared-upstream entries) AND, via
           this exemption, CHECK 5's header requirement, with nothing but two copy-pasted hex
           strings -- reproduced and confirmed exploitable before this refusal was added. This
           does not make the exemption sound against an `origin = "upstream"` lie at a
           non-banned path; that residual trust-the-declared-origin gap is the same one this
           docstring already discloses and is not newly introduced or newly closed here.

WHAT THIS GUARD DOES NOT COVER
-------------------------------
  * Discovery is scoped to `[scan].roots` -- NOT the whole repository. Three roots are registered
    as of 2026-08-06: lib-q-hqc/kats, lib-q-saturnin/tests/fixtures, lib-q-mayo/tests/kats (the
    latter two investigated and added in the card's second pass -- see kats-manifest.toml's
    comment for how). Widening `roots` further without first doing that same per-file
    investigation would either fabricate an `origin` or immediately fail CI for an unrelated crate
    for the wrong reason; see kats-manifest.toml's own comment.
  * CHECK 4's naming regex is applied ONLY to paths that are already KAT-manifest entries (i.e.
    files matching [scan].extensions/filename_suffixes under a registered root) -- never to the
    whole repository. A repo-wide unscoped version of this check would flag `nist_kem_kat.rs`,
    `official_specification_verification_test.rs`, and the `nist-drbg` Cargo feature, none of
    which are KAT vector files; that would be a false-positive generator, not a fix.
  * It never inspects the DATA inside a vector file, only its bytes-as-a-whole (CHECK 3) and its
    header comment (CHECK 5). It cannot tell you whether a file's claimed origin is TRUE, only
    whether a claim is present, internally consistent, and not wearing a name it has not earned.
  * It is static: a repo walk, a small TOML read, a SHA-256 per file. No cargo, no network, no
    code-under-test execution -- detecting an actual VALUE divergence from a real reference
    implementation is a different job (`tests/nist_kem_kat.rs`, or a future upstream-conformance
    test).
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
MANIFEST_PATH = ROOT / "kats-manifest.toml"

failures: list[str] = []
notes: list[str] = []


def fail(check: str, message: str) -> None:
    failures.append(f"[{check}] {message}")


# ---------------------------------------------------------------------------
# Minimal TOML reader, used only if the interpreter lacks `tomllib` (3.11+).
# ---------------------------------------------------------------------------
# This manifest's own shape is deliberately narrow -- a `[scan]` table of string/string-array
# values, plus repeated `[[kat]]` tables of string values; no nesting, no multiline strings, no
# inline tables. That narrowness is what makes a ~50-line hand-rolled parser safe to fall back
# to here rather than adding a pip dependency to a job (`core-validation`) that has no pip step.
def _parse_toml_minimal(text: str) -> dict:
    doc: dict = {"kat": []}
    cur: dict | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[scan]":
            cur = doc.setdefault("scan", {})
            continue
        if line == "[[kat]]":
            cur = {}
            doc["kat"].append(cur)
            continue
        if line.startswith("["):
            raise SystemExit(
                f"ci-guard-kat-provenance: kats-manifest.toml:{lineno}: unsupported table header "
                f"{line!r} (fallback parser only understands [scan] and [[kat]] -- install a "
                "Python with stdlib tomllib, i.e. 3.11+, to lift this restriction)"
            )
        m = re.match(r"^([A-Za-z_][\w-]*)\s*=\s*(.+)$", line)
        if not m or cur is None:
            raise SystemExit(
                f"ci-guard-kat-provenance: kats-manifest.toml:{lineno}: could not parse: {raw!r}"
            )
        key, val = m.group(1), m.group(2).strip()
        if val.startswith("["):
            items = re.findall(r'"((?:[^"\\]|\\.)*)"', val)
            cur[key] = [i.replace('\\"', '"') for i in items]
        elif val.startswith('"'):
            mm = re.match(r'^"((?:[^"\\]|\\.)*)"', val)
            if not mm:
                raise SystemExit(
                    f"ci-guard-kat-provenance: kats-manifest.toml:{lineno}: unterminated string "
                    f"in: {raw!r}"
                )
            cur[key] = mm.group(1).replace('\\"', '"')
        else:
            raise SystemExit(
                f"ci-guard-kat-provenance: kats-manifest.toml:{lineno}: unsupported value "
                f"{val!r} (fallback parser only understands quoted strings and string arrays)"
            )
    return doc


def load_manifest() -> dict:
    if not MANIFEST_PATH.is_file():
        raise SystemExit(f"ci-guard-kat-provenance: manifest not found: {MANIFEST_PATH}")
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    try:
        import tomllib  # Python 3.11+, stdlib
    except ModuleNotFoundError:
        return _parse_toml_minimal(text)
    return tomllib.loads(text)


# ---------------------------------------------------------------------------
# CHECK 1 -- discovery
# ---------------------------------------------------------------------------
def discover(scan_cfg: dict) -> dict[str, pathlib.Path]:
    roots = scan_cfg.get("roots") or []
    extensions = {str(e).lower().lstrip(".") for e in (scan_cfg.get("extensions") or [])}
    suffixes = tuple(str(s).lower() for s in (scan_cfg.get("filename_suffixes") or []))
    if not roots:
        raise SystemExit("ci-guard-kat-provenance: kats-manifest.toml [scan].roots is empty")
    if not extensions and not suffixes:
        raise SystemExit(
            "ci-guard-kat-provenance: kats-manifest.toml [scan] has neither 'extensions' nor "
            "'filename_suffixes' -- discovery would match nothing by construction"
        )

    found: dict[str, pathlib.Path] = {}
    for root_rel in roots:
        root_abs = ROOT / root_rel
        if not root_abs.is_dir():
            fail(
                "CHECK 1",
                f"registered scan root {root_rel!r} does not exist (or is not a directory) -- "
                "did it move? Update kats-manifest.toml's [scan].roots.",
            )
            continue
        root_found = 0
        for dirpath, dirnames, filenames in os.walk(root_abs):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                lower = name.lower()
                ext = lower.rsplit(".", 1)[-1] if "." in lower else ""
                if ext in extensions or lower.endswith(suffixes):
                    p = pathlib.Path(dirpath) / name
                    rel = p.relative_to(ROOT).as_posix()
                    found[rel] = p
                    root_found += 1
        if root_found == 0:
            fail(
                "CHECK 1",
                f"registered scan root {root_rel!r} exists but contains ZERO files matching "
                "[scan].extensions/filename_suffixes. A root that finds nothing is "
                "indistinguishable from a guard that stopped looking -- either the root path is "
                "wrong or the vector files moved/were renamed to an unlisted extension.",
            )
    if not found:
        fail(
            "CHECK 1",
            "discovery found ZERO KAT vector files across ALL registered roots. A provenance "
            "guard with nothing to check is not passing, it is vacuous -- that is a failure, "
            "not 'nothing to do'.",
        )
    notes.append(
        f"CHECK 1: {len(found)} KAT vector file(s) discovered across {len(roots)} registered "
        f"root(s): {', '.join(roots)}"
    )
    return found


# ---------------------------------------------------------------------------
# CHECK 2 -- manifest coverage, both directions
# ---------------------------------------------------------------------------
def check_coverage(discovered: dict[str, pathlib.Path], entries: list[dict]) -> dict[str, dict]:
    by_path: dict[str, dict] = {}
    for i, e in enumerate(entries):
        path = e.get("path")
        if not path:
            fail("CHECK 2", f"kats-manifest.toml [[kat]] entry #{i} has no 'path'")
            continue
        if path in by_path:
            fail("CHECK 2", f"kats-manifest.toml has TWO [[kat]] entries for {path!r}")
            continue
        by_path[path] = e

    missing_from_manifest = sorted(set(discovered) - set(by_path))
    stale_in_manifest = sorted(set(by_path) - set(discovered))
    for rel in missing_from_manifest:
        fail(
            "CHECK 2",
            f"{rel} is a discovered KAT vector file with NO kats-manifest.toml entry. Every "
            "committed KAT file must declare its origin -- add a [[kat]] entry.",
        )
    for rel in stale_in_manifest:
        fail(
            "CHECK 2",
            f"kats-manifest.toml has a [[kat]] entry for {rel!r} but that file no longer "
            "exists. Remove the stale entry so the manifest keeps describing reality.",
        )
    notes.append(
        f"CHECK 2: {len(discovered)} discovered file(s), {len(by_path)} manifest entries, "
        f"{len(missing_from_manifest)} uncovered, {len(stale_in_manifest)} stale"
    )
    return by_path


# ---------------------------------------------------------------------------
# CHECK 3 -- content hash
# ---------------------------------------------------------------------------
def sha256_of(path: pathlib.Path) -> str:
    """SHA-256 of the file with CRLF line endings normalised to LF.

    KAT vectors are text. Hashing the raw bytes makes this check depend on the
    checkout's line-ending policy rather than on the content: a Windows clone with
    `core.autocrlf=true` holds CRLF while the repository blobs and every Linux CI
    checkout hold LF, so the same commit hashes two different ways and CHECK 3 fires
    on all files at once for a reason that has nothing to do with drift. That is
    exactly what happened when this guard first ran in CI.

    `.gitattributes` now pins these paths to `-text` so git stops rewriting them, but
    the normalisation stays: it makes the check correct by construction rather than
    contingent on every clone being configured right, and it still catches real
    change, since collapsing CRLF to LF alters nothing else about the bytes.
    """
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def check_hashes(by_path: dict[str, dict]) -> None:
    checked = 0
    for rel, e in sorted(by_path.items()):
        p = ROOT / rel
        if not p.is_file():
            continue  # already reported by CHECK 2
        expected = str(e.get("sha256", ""))
        if not expected:
            fail("CHECK 3", f"{rel}: manifest entry has no 'sha256'")
            continue
        actual = sha256_of(p)
        checked += 1
        if actual.lower() != expected.lower():
            fail(
                "CHECK 3",
                f"{rel}: content hash changed. manifest sha256={expected} actual={actual}. If "
                "this is a deliberate regeneration, update the manifest entry's sha256 as part "
                "of the SAME review that changed the file -- a hash left stale is exactly the "
                "silent-drift case this check exists to catch.",
            )
    notes.append(f"CHECK 3: {checked} file(s) hash-verified against the manifest")


# ---------------------------------------------------------------------------
# CHECK 4 -- naming ban (official / nist / rfc), non-upstream entries only
# ---------------------------------------------------------------------------
VALID_ORIGINS = {"upstream", "self-generated", "third-party"}
# Word-bounded: matches `kats/official/x.rsp` and `nist_kem_kat.rsp` but not `unofficial_notes` or
# a hypothetical `finest.rsp`. Deliberately scoped to manifested KAT-vector paths only (see the
# module docstring) so it never sees, and cannot false-positive on, unrelated repo files.
#
# NOTE on the boundary classes: under `(?i)`, `[^a-z]` excludes BOTH cases, so this regex alone
# treats a camelCase join as an interior position -- `OfficialVectors.rsp` and `NistKat.rsp` would
# slip through (found in review, 2026-08-05, observed passing end-to-end before this fix). The
# camel-segment check below closes that: the path is split into case-transition word segments
# ("OfficialVectors" -> "Official","Vectors") and each segment is compared whole. Residual,
# accepted gap: a banned word embedded inside a single SAME-case letter run ("OFFICIALKAT",
# "myofficial") is indistinguishable from legitimate substrings like "unofficial" without
# false-positives, so it stays out of scope -- as does any name evading discovery entirely
# (unlisted extension), which no naming check can see.
NAME_BAN = re.compile(r"(?i)(^|[^a-z])(official|nist|rfc)([^a-z]|$)")
CAMEL_SEGMENTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+")
BANNED_WORDS = {"official", "nist", "rfc"}


def name_is_banned(rel: str) -> bool:
    if NAME_BAN.search(rel):
        return True
    return any(seg.lower() in BANNED_WORDS for seg in CAMEL_SEGMENTS.findall(rel))


def check_naming(by_path: dict[str, dict]) -> None:
    checked = 0
    for rel, e in sorted(by_path.items()):
        origin = e.get("origin", "")
        if origin not in VALID_ORIGINS:
            fail("CHECK 4", f"{rel}: origin {origin!r} is not one of {sorted(VALID_ORIGINS)}")
            continue
        if origin == "upstream":
            continue
        checked += 1
        if name_is_banned(rel):
            fail(
                "CHECK 4",
                f"{rel}: origin={origin!r} but the path/filename contains a banned word "
                "('official'/'nist'/'rfc'). A self-generated or third-party vector file may not "
                "be named or placed as if it were the genuine upstream reference -- this is the "
                "exact defect card t_71d4f79a found in lib-q-hqc's former kats/official/.",
            )
    notes.append(f"CHECK 4: {checked} non-upstream entr(y/ies) checked against the naming ban")


# ---------------------------------------------------------------------------
# CHECK 5 -- header must agree with the manifest's origin
# ---------------------------------------------------------------------------
ORIGIN_HEADER_TOKEN = {
    "upstream": "upstream",
    "self-generated": "self-generated",
    "third-party": "third-party",
}
HEADER_LINES_SCANNED = 20


def check_headers(by_path: dict[str, dict]) -> None:
    checked = 0
    exempted = 0
    for rel, e in sorted(by_path.items()):
        origin = e.get("origin", "")
        token = ORIGIN_HEADER_TOKEN.get(origin)
        if token is None:
            continue  # invalid origin already reported by CHECK 4
        p = ROOT / rel
        if not p.is_file():
            continue  # already reported by CHECK 2

        if origin == "upstream":
            upstream_url = e.get("upstream_url")
            upstream_sha256 = e.get("upstream_sha256")
            if not upstream_url or not upstream_sha256:
                fail(
                    "CHECK 5",
                    f"{rel}: origin=upstream requires both 'upstream_url' and 'upstream_sha256' "
                    "in the manifest entry",
                )
                continue
            # EXEMPTION -- a file vendored byte-for-byte from upstream cannot ALSO carry a
            # header comment declaring that fact: adding one would edit its bytes and falsify
            # the very equality (recorded `sha256` == claimed `upstream_sha256`) that makes the
            # claim checkable in the first place. An entry that satisfies this equality already
            # carries STRONGER, machine-verified provenance than a free-text header comment ever
            # could: CHECK 3 re-derives `sha256` from the file's actual bytes on every run (so it
            # cannot silently drift), and `upstream_sha256` is a citable, reviewable claim tied to
            # `upstream_url` that any reader can independently re-fetch and re-hash.
            #
            # This branch is reachable ONLY when `origin == "upstream"` literally. It cannot be
            # reached by a "self-generated" or "third-party" entry regardless of what other
            # fields such an entry also carries (e.g. a copied `upstream_sha256` equal to its own
            # `sha256`, attempting to mimic this condition) -- for those origins `token` is
            # "self-generated" / "third-party", not "upstream", so control never enters this `if
            # origin == "upstream":` block at all and falls straight through to the ordinary
            # header check below, which still demands the matching token in the file's own
            # comment. See the sandbox test in the lane's verification notes (card t_71d4f79a)
            # that plants exactly this abuse attempt and confirms it still fails.
            #
            # SECOND GUARD (added in review, 2026-08-06): `origin` itself is a self-declared
            # manifest field this script cannot verify (no network, no ground truth -- see the
            # module docstring). `sha256 == upstream_sha256` alone is NOT independent evidence of
            # genuine upstream provenance: for a self-generated file, both fields are just "the
            # hash of my own file", copied twice by whoever writes the entry. Nothing before this
            # line stops a contributor from mislabelling a self-generated file `origin =
            # "upstream"` specifically to reach this branch. CHECK 4 already skips its
            # official/nist/rfc naming ban entirely for `origin == "upstream"` entries (by design,
            # so a genuinely-vendored file is free to keep an upstream-given name) -- which means
            # that BEFORE this guard, an entry claiming `origin = "upstream"` at a path containing
            # "official"/"nist"/"rfc" could reach this exemption and skip BOTH the naming ban and
            # the header requirement with nothing but two copy-pasted hex strings and a fabricated
            # `upstream_url`, landing exactly the failure mode card t_71d4f79a exists to prevent
            # (self-generated content at a `kats/official/`-shaped path, presented as
            # authoritative) -- reproduced and confirmed exploitable in review before this fix
            # (see the lane's progress notes for the exact reproduction). Refusing the exemption
            # whenever the path itself is still naming-banned closes that specific compounding: an
            # entry at such a path must fall through to the ordinary header check below and
            # physically say "upstream" in its own text, restoring the one text-based speed bump
            # that existed before this exemption was added. This does NOT make the exemption fully
            # sound for an `origin = "upstream"` lie at an innocuous (non-banned) path -- that
            # residual gap is the same "we trust the declared origin, CI has no network" limitation
            # already disclosed in this module's docstring, not something introduced or claimed
            # fixed here.
            recorded_sha256 = str(e.get("sha256", "")).strip().lower()
            claimed_upstream_sha256 = str(upstream_sha256).strip().lower()
            if (
                recorded_sha256
                and recorded_sha256 == claimed_upstream_sha256
                and not name_is_banned(rel)
            ):
                exempted += 1
                checked += 1
                continue

        try:
            head_lines: list[str] = []
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for _ in range(HEADER_LINES_SCANNED):
                    line = f.readline()
                    if not line:
                        break
                    head_lines.append(line)
        except OSError as exc:
            fail("CHECK 5", f"{rel}: could not read header: {exc}")
            continue
        header = "".join(line for line in head_lines if line.lstrip().startswith("#"))
        if token.lower() not in header.lower():
            fail(
                "CHECK 5",
                f"{rel}: manifest origin={origin!r} but no leading '#'-comment line in the "
                f"file's first {len(head_lines)} lines contains {token!r}. A reader of the raw "
                "file (not just the manifest) must be able to tell what it is from the file "
                "itself.",
            )
            continue
        checked += 1
    notes.append(
        f"CHECK 5: {checked} file header(s) cross-checked against their manifest origin "
        f"({exempted} exempted: origin=upstream with sha256 == upstream_sha256, i.e. byte-for-byte "
        "vendored files that would be falsified by adding a header comment)"
    )


def main() -> int:
    doc = load_manifest()
    scan_cfg = doc.get("scan", {}) or {}
    entries = doc.get("kat", []) or []

    discovered = discover(scan_cfg)
    by_path = check_coverage(discovered, entries)
    check_hashes(by_path)
    check_naming(by_path)
    check_headers(by_path)

    for n in notes:
        print(f"  ok  {n}")
    if failures:
        print("")
        print("ci-guard-kat-provenance: FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"kat-provenance guard: OK ({len(discovered)} files, {len(by_path)} manifest entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
