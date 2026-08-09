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
  CHECK 5  provenance statement ADJACENT TO THE FILE, cross-checked against the manifest. A reader
           who opens the raw vector file (or the directory it sits in) must be able to tell what it
           is without going to kats-manifest.toml. Two ways to satisfy this, and which one applies
           is decided by the FILE FORMAT, not by the committer:

             (a) `#`-comment-capable formats (`.rsp`/`.req`/`.kat`/`.txt`, and only if the file
                 carries no NUL byte in its first 8 KiB): the file's own leading `#`-comment must
                 contain the token its manifest `origin` maps to, so a file cannot be manifested as
                 "self-generated" while its own header still calls itself authoritative (or the
                 reverse).
             (b) every other format -- JSON, and any binary container (`.blb`, `.bin`, ...): these
                 have NO comment syntax at all, so rule (a) is not satisfiable by construction and
                 was, before 2026-08-07, an absolute bar on registering any such file. Those files
                 must instead be named by a `PROVENANCE.md` SIDECAR in their own directory (or the
                 nearest ancestor directory up to and including their registered scan root), in a
                 machine-checked line of the form

                     - `<path relative to that PROVENANCE.md>`: origin=<origin>; <description>

                 The declared origin must equal the manifest's, the description must clear a length
                 floor (>= 40 chars, which stops a one-word stub and NOTHING more -- no check here
                 can tell a real sentence from 41 characters of noise), and the sidecar is checked
                 in BOTH directions: a sidecar line naming something no REGISTERED KAT file
                 resolves to is a failure, exactly as a stale [[kat]] entry is in CHECK 2. A
                 sidecar may also document files that took route (a) -- documenting a whole
                 directory is the natural thing to write, and those lines are not stale -- but if
                 it does, their declared origin must still agree with the manifest.

           `origin = "upstream"` entries must also carry `upstream_url` and `upstream_sha256`.

           EXEMPTION (added 2026-08-06, card t_71d4f79a second pass; NARROWED 2026-08-07): an
           `origin = "upstream"` entry whose manifest `sha256` equals its own `upstream_sha256` is
           exempt from the (a) header-comment requirement. Vector files vendored byte-for-byte from
           a designers'/NIST's own distribution get their evidentiary value FROM being byte-
           identical to that distribution; splicing in a header comment would edit their bytes and
           falsify the very equality that is the evidence. The exemption cannot be reached by a
           non-upstream entry no matter what fields it also carries (e.g. a copied
           `upstream_sha256`), because it is lexically nested inside the `origin == "upstream"`
           branch in `check_headers` below -- see that function's comment for the full reasoning
           and a pointer to the abuse-attempt test that exercises this. The exemption is ALSO
           refused (added in review, 2026-08-06) for any path CHECK 4's naming ban would otherwise
           catch: without that refusal, an entry that simply lies `origin = "upstream"` at a
           `kats/official/`-shaped path skipped CHECK 4's naming ban (which by design does not
           apply to declared-upstream entries) AND, via this exemption, CHECK 5's header
           requirement, with nothing but two copy-pasted hex strings -- reproduced and confirmed
           exploitable before this refusal was added. And it is refused (2026-08-07) for every file
           that is not `#`-comment-capable: the exemption exists to avoid FALSIFYING a header a
           text file could otherwise carry, which is not a coherent reason to excuse a JSON or
           binary file that could never have carried one. Such files take route (b) instead, so
           there is now no format for which "no provenance statement anywhere near the file" is
           reachable.

           RESIDUAL -- read this before citing CHECK 5 as anti-forgery. What the 2026-08-07 pass
           closed is exactly one thing: "a registered vector file with NO provenance statement
           anywhere near it" is no longer reachable in any format. It did NOT close, and no route
           through this check closes, a committer who simply LIES about `origin`:

             * TEXT route (a): a `#`-comment-capable file at a naming-innocuous path that declares
               `origin = "upstream"` and copies its own hash into `upstream_sha256` reaches the
               exemption and passes with no header at all.
             * SIDECAR route (b): the identical lie on a JSON/binary file passes too. It costs the
               liar one extra fabricated markdown line, because the sidecar is committer-written
               free text that this script compares only against the committer-written manifest.
               MEASURED 2026-08-07 in review (verifier's harness, scenario v1): a fabricated JSON
               with `origin = "upstream"`, `sha256 == upstream_sha256`, a `https://example.invalid`
               URL and a matching sidecar line -> `kat-provenance guard: OK`, exit 0.

           So route (b) is NOT stronger than route (a) against a lie; both are "we trust the
           declared origin, CI has no network". Its value is different and narrower: a reader
           standing in the directory now finds a claim to check, and a file cannot be added or
           renamed without someone writing that claim down in the same diff. Closing the lie
           itself needs corroboration this script cannot produce -- a network re-fetch of
           `upstream_url`, or a second party attesting the hash -- not another local text file.

WHAT THIS GUARD DOES NOT COVER
-------------------------------
  * Discovery is scoped to `[scan].roots` -- NOT the whole repository. See kats-manifest.toml for
    the roots currently registered and how each was investigated before being added. Widening
    `roots` without first doing that same per-file investigation would either fabricate an `origin`
    or immediately fail CI for an unrelated crate for the wrong reason; see the manifest's comment.
  * `[scan].exclude` is an escape hatch and is treated as one. Each excluded path is an EXACT
    repo-relative path (no globs), must exist (a stale exclusion is a failure, so the list cannot
    rot into silently hiding a file that moved into its place), may not also be a `[[kat]]` entry,
    and is printed in this guard's own output on every run so it shows up in review. It exists for
    non-KAT files that happen to match a scanned extension (e.g. a `requirements.txt` sitting in a
    directory of vector files).
    MEASURED BLAST RADIUS (review, 2026-08-07, verifier scenario v9), stated plainly because the
    line above understates it: an excluded path is dropped from discovery BEFORE every other
    check, so one `exclude` entry hides a fabricated vector file at a `kats/official/`-shaped path
    completely -- CHECK 2, 3, 4 and 5 never see it, and the guard prints OK. That is the exact
    defect card t_71d4f79a exists to prevent, reachable in one line. Nothing in this script can
    distinguish that from the legitimate `requirements.txt` case, so the only control is human:
    treat ANY addition to `exclude` as a claim needing the same scrutiny as a fabricated `origin`,
    and check the excluded path against the printed list in the CI log.
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
def _strip_toml_comment(raw: str) -> str:
    """Drop a trailing `#` comment, but NOT a `#` inside a quoted string.

    A plain `raw.split("#", 1)[0]` -- what this did until 2026-08-07 -- truncates
    `generator = "... dilithium-py PR #1 @ cc1fd2ad ..."` mid-string and then reports the result
    as an unterminated string, i.e. the guard hard-fails on a perfectly legal manifest. Only on
    interpreters without stdlib `tomllib` (< 3.11), which is exactly where nobody would look.
    Observed failing on this manifest before the fix; see the lane notes on card t_71d4f79a.
    """
    out: list[str] = []
    in_string = False
    escaped = False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out)


def _parse_toml_minimal(text: str) -> dict:
    doc: dict = {"kat": []}
    cur: dict | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_toml_comment(raw).strip()
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
    # Exact repo-relative paths that discovery skips. Deliberately NOT globs: an exclusion has to
    # name the one file it is hiding, so the diff that adds one is unambiguous in review.
    excluded = [str(x).replace("\\", "/").strip() for x in (scan_cfg.get("exclude") or [])]
    for rel in excluded:
        if not (ROOT / rel).is_file():
            fail(
                "CHECK 1",
                f"kats-manifest.toml [scan].exclude names {rel!r}, which does not exist. A stale "
                "exclusion is how an exclusion list rots into hiding a file it was never reviewed "
                "for -- delete the entry, or fix the path.",
            )
    if not roots:
        raise SystemExit("ci-guard-kat-provenance: kats-manifest.toml [scan].roots is empty")
    if not extensions and not suffixes:
        raise SystemExit(
            "ci-guard-kat-provenance: kats-manifest.toml [scan] has neither 'extensions' nor "
            "'filename_suffixes' -- discovery would match nothing by construction"
        )

    excluded_set = set(excluded)
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
                    if rel in excluded_set:
                        continue
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
        + (
            f"; {len(excluded)} path(s) EXCLUDED by [scan].exclude: {', '.join(sorted(excluded))}"
            if excluded
            else "; no [scan].exclude entries"
        )
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
# Extensions whose files are opaque binary containers, not text. CRLF normalisation (below) must
# never apply to these: a `.blb`/`.bin` blobby container can legitimately contain the two-byte
# sequence `\r\n` as pure data (e.g. inside an encoded length or vector payload), and collapsing it
# to `\n` silently changes what is being hashed to something that no longer matches the bytes on
# disk. For a binary format there is no such thing as a "line ending" to normalise -- doing so
# means CHECK 3 can no longer detect corruption that happens to land next to such a byte pair, and
# the manifest ends up pinning a hash of a transformed file rather than the real one. Found
# 2026-08-09 via `sha3_384_kat.blb`, whose content contains a literal CRLF byte pair.
BINARY_EXTENSIONS = {"blb", "bin"}


def is_binary_ext(rel: str) -> bool:
    suffix = pathlib.PurePosixPath(rel).suffix.lstrip(".").lower()
    return suffix in BINARY_EXTENSIONS


def sha256_of(path: pathlib.Path, *, binary: bool = False) -> str:
    """SHA-256 of the file, normalising CRLF line endings to LF for text formats only.

    KAT vectors are mostly text. Hashing the raw bytes of a text file makes this check
    depend on the checkout's line-ending policy rather than on the content: a Windows
    clone with `core.autocrlf=true` holds CRLF while the repository blobs and every
    Linux CI checkout hold LF, so the same commit hashes two different ways and CHECK 3
    fires on all files at once for a reason that has nothing to do with drift. That is
    exactly what happened when this guard first ran in CI.

    `.gitattributes` now pins these paths to `-text` so git stops rewriting them, but
    the normalisation stays for text formats: it makes the check correct by
    construction rather than contingent on every clone being configured right, and it
    still catches real change, since collapsing CRLF to LF alters nothing else about
    the bytes.

    For binary containers (see `BINARY_EXTENSIONS`) normalisation is skipped entirely --
    there is no line-ending convention to correct for, and applying one anyway hashes a
    transformed copy of the file instead of what is actually on disk.
    """
    data = path.read_bytes()
    if not binary:
        data = data.replace(b"\r\n", b"\n")
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
        actual = sha256_of(p, binary=is_binary_ext(rel))
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
# CHECK 5 -- a provenance statement adjacent to the file, agreeing with the manifest
# ---------------------------------------------------------------------------
ORIGIN_HEADER_TOKEN = {
    "upstream": "upstream",
    "self-generated": "self-generated",
    "third-party": "third-party",
}
HEADER_LINES_SCANNED = 20

# Extensions whose file format treats a leading `#` line as a comment, i.e. the only formats in
# which the in-file header rule is satisfiable at all. Hardcoded rather than manifest-driven on
# purpose: making this list a manifest field would let a committer declare a JSON file
# "comment-capable" (which only makes the guard STRICTER -- it would then demand an impossible
# header) or, worse in the other direction, declare a `.rsp` file non-capable to swap a header it
# could perfectly well carry for a sidecar line. The format decides, not the committer.
#
# JSON is absent deliberately: the grammar has no comment production, so `#` on line 1 is a parse
# error, and a `_provenance` key would change the bytes and therefore the `sha256` this manifest
# pins. Binary containers (`.blb` blobby archives, `.bin`) likewise. Before 2026-08-07 that made a
# self-generated JSON/binary vector file IMPOSSIBLE to register -- CHECK 5 could never pass for it
# -- which is why ~31 KAT-shaped files in this repo sat outside the guard entirely.
COMMENT_CAPABLE_EXTENSIONS = {"rsp", "req", "kat", "txt"}
SIDECAR_NAME = "PROVENANCE.md"
# A NUL byte in the first chunk means the "text" extension is lying; treat the file as binary and
# route it to the sidecar rule rather than demanding a header it cannot carry. Fail-safe either
# way: both routes require a machine-checked provenance statement, so this is not a bypass.
BINARY_SNIFF_BYTES = 8192
# A description this short cannot say where a file came from, so a one-word stub cannot satisfy the
# sidecar. Chosen to be shorter than every real entry and longer than any plausible stub.
MIN_SIDECAR_DESCRIPTION = 40
SIDECAR_LINE = re.compile(
    r"^\s*[-*]\s+`([^`]+)`\s*:\s*origin\s*=\s*([A-Za-z][A-Za-z-]*)\s*;\s*(\S.*)$"
)

_sidecar_cache: dict[pathlib.Path, tuple[dict[str, tuple[str, str]], list[str]]] = {}


def is_comment_capable(path: pathlib.Path) -> bool:
    """True iff a leading `#`-comment line is a thing this file's format can carry."""
    name = path.name.lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext not in COMMENT_CAPABLE_EXTENSIONS:
        return False
    try:
        with path.open("rb") as f:
            head = f.read(BINARY_SNIFF_BYTES)
    except OSError:
        return False
    return b"\x00" not in head


def find_sidecar(rel: str, roots: list[str]) -> pathlib.Path | None:
    """Nearest PROVENANCE.md at or above the file's own directory, bounded by its scan root.

    Bounded on purpose: without a bound, a single PROVENANCE.md at the repository root would
    "cover" every vector file in the tree, which is the opposite of adjacent. The search stops at
    the deepest registered `[scan].roots` directory containing the file, so a sidecar is always in
    the same crate-local vector tree as the file it describes.
    """
    p = ROOT / rel
    containing = [
        r.rstrip("/")
        for r in roots
        if rel == r.rstrip("/") or rel.startswith(r.rstrip("/") + "/")
    ]
    bound = ROOT / max(containing, key=len) if containing else ROOT
    d = p.parent
    while True:
        candidate = d / SIDECAR_NAME
        if candidate.is_file():
            return candidate
        if d == bound or d == ROOT or d.parent == d:
            return None
        d = d.parent


def parse_sidecar(path: pathlib.Path) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Parse the strict `- \\`path\\`: origin=X; description` lines out of a sidecar.

    Lines that do not match are ignored, so a sidecar is free to be a readable Markdown document
    with prose, headings and tables around its machine-checked lines.
    """
    if path in _sidecar_cache:
        return _sidecar_cache[path]
    entries: dict[str, tuple[str, str]] = {}
    duplicates: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        fail("CHECK 5", f"{path.relative_to(ROOT).as_posix()}: could not read sidecar: {exc}")
        _sidecar_cache[path] = ({}, [])
        return _sidecar_cache[path]
    for raw in text.splitlines():
        m = SIDECAR_LINE.match(raw)
        if not m:
            continue
        key = m.group(1).strip().replace("\\", "/")
        while key.startswith("./"):
            key = key[2:]
        if key in entries:
            duplicates.append(key)
        entries[key] = (m.group(2).strip().lower(), m.group(3).strip())
    _sidecar_cache[path] = (entries, duplicates)
    return entries, duplicates


def check_headers(by_path: dict[str, dict], roots: list[str]) -> None:
    checked = 0
    exempted = 0
    via_sidecar = 0
    # sidecar -> every key that took the SIDECAR ROUTE through it, whether or not the entry passed.
    resolved_keys: dict[pathlib.Path, set[str]] = {}
    # sidecar -> {key: manifest origin} for EVERY registered file that exists and whose nearest
    # in-bounds sidecar is that one, INCLUDING files that take the header route. The two sets are
    # different and the difference is load-bearing (found in review 2026-08-07, scenario v5): the
    # both-directions check below used `resolved_keys`, so a PROVENANCE.md that also documented a
    # `.rsp`/`.txt` in its directory -- a file that is registered, exists, and legitimately takes
    # route (a) -- was reported as naming a file that "was deleted/renamed" or "is NOT registered
    # in kats-manifest.toml", both of which were false. Documenting a whole directory is the
    # obvious thing to write, and it is exactly what closing the route-(a) residual would require
    # in lib-q-saturnin / lib-q-mayo / lib-q-romulus, so that false positive sat directly across
    # the next step anyone would take here.
    documented: dict[pathlib.Path, dict[str, str]] = {}
    for rel, e in sorted(by_path.items()):
        p = ROOT / rel
        if not p.is_file():
            continue
        sc = find_sidecar(rel, roots)
        if sc is not None:
            documented.setdefault(sc, {})[p.relative_to(sc.parent).as_posix()] = e.get("origin", "")
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

        # ROUTE (b) -- formats that cannot carry a `#` header at all. Checked BEFORE the upstream
        # byte-identity exemption below, deliberately: that exemption's whole justification is
        # "adding the header would falsify the bytes that ARE the evidence", which says nothing
        # about a file that could never have carried a header in the first place. Letting such a
        # file take the exemption is how a fabricated JSON/binary vector with a copy-pasted hash
        # would end up with no provenance statement anywhere near it. It takes the sidecar instead.
        if not is_comment_capable(p):
            sidecar = find_sidecar(rel, roots)
            if sidecar is None:
                fail(
                    "CHECK 5",
                    f"{rel}: this file's format cannot carry a leading '#'-comment header (its "
                    f"extension is not one of {sorted(COMMENT_CAPABLE_EXTENSIONS)}, or its first "
                    f"{BINARY_SNIFF_BYTES} bytes contain a NUL), so it must be described by a "
                    f"{SIDECAR_NAME} sidecar in its own directory or an ancestor up to its "
                    "registered [scan].roots directory -- and no such file exists. Create one "
                    "containing a line of exactly this shape:\n"
                    f"        - `{p.name}`: origin={origin}; <where these bytes came from and how "
                    "that was verified>",
                )
                continue
            sidecar_rel = sidecar.relative_to(ROOT).as_posix()
            key = p.relative_to(sidecar.parent).as_posix()
            entries, duplicates = parse_sidecar(sidecar)
            resolved_keys.setdefault(sidecar, set()).add(key)
            if key in duplicates:
                fail(
                    "CHECK 5",
                    f"{rel}: {sidecar_rel} has MORE THAN ONE line for {key!r}. Two provenance "
                    "claims for one file is not a provenance claim -- keep exactly one.",
                )
                continue
            if key not in entries:
                fail(
                    "CHECK 5",
                    f"{rel}: {sidecar_rel} exists but does not name this file. It must carry a "
                    f"line `- \\`{key}\\`: origin={origin}; <description>`. A sidecar that covers "
                    "some of a directory's vector files and silently omits others is exactly the "
                    "gap this rule exists to close.",
                )
                continue
            declared_origin, description = entries[key]
            if declared_origin != origin:
                fail(
                    "CHECK 5",
                    f"{rel}: {sidecar_rel} declares origin={declared_origin!r} but "
                    f"kats-manifest.toml says origin={origin!r}. The two must agree -- a file may "
                    "not be one thing to the manifest and another to the reader standing next to "
                    "it.",
                )
                continue
            if len(description) < MIN_SIDECAR_DESCRIPTION:
                fail(
                    "CHECK 5",
                    f"{rel}: {sidecar_rel}'s description for {key!r} is {len(description)} "
                    f"characters ({description!r}); at least {MIN_SIDECAR_DESCRIPTION} are "
                    "required. The point of the sidecar is that a reader learns where the bytes "
                    "came from, which a stub does not tell them.",
                )
                continue
            via_sidecar += 1
            checked += 1
            continue

        if origin == "upstream":
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
            #
            # THIRD GUARD (added 2026-08-07): the exemption is now unreachable for any file that is
            # not `#`-comment-capable -- such files are diverted to the sidecar rule above before
            # control ever gets here. See that branch's comment.
            recorded_sha256 = str(e.get("sha256", "")).strip().lower()
            claimed_upstream_sha256 = str(e.get("upstream_sha256", "")).strip().lower()
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

    # Both directions, same rule CHECK 2 applies to the manifest: a sidecar line naming something
    # no REGISTERED, EXISTING KAT file resolves to is stale, and a stale provenance claim is a
    # claim about a file nobody can check. Only sidecars actually consumed above are examined, so
    # an unrelated PROVENANCE.md elsewhere in the tree is never parsed and never fails anything.
    for sidecar, keys in sorted(resolved_keys.items()):
        sidecar_rel = sidecar.relative_to(ROOT).as_posix()
        sidecar_entries, _ = parse_sidecar(sidecar)
        known = documented.get(sidecar, {})
        for orphan in sorted(set(sidecar_entries) - set(known) - keys):
            fail(
                "CHECK 5",
                f"{sidecar_rel}: names {orphan!r}, but no kats-manifest.toml entry resolves to "
                "that file through this sidecar. Either the file was deleted/renamed and this "
                "line is stale, or the file exists and is NOT registered in kats-manifest.toml -- "
                "both are the failure this check exists for. Remove the line, or register the "
                "file.",
            )
        # A line for a file that took the HEADER route is allowed (see `documented` above), but it
        # is still a provenance claim, so it may not contradict the manifest -- the same rule the
        # sidecar route applies, and the only rule applied to these extra lines (no description
        # floor: the sidecar is not the required provenance statement for a file that carries its
        # own header).
        for extra in sorted((set(sidecar_entries) & set(known)) - keys):
            declared_origin = sidecar_entries[extra][0]
            if declared_origin != known[extra]:
                fail(
                    "CHECK 5",
                    f"{sidecar_rel}: declares origin={declared_origin!r} for {extra!r}, but "
                    f"kats-manifest.toml says origin={known[extra]!r}. That file satisfies CHECK 5 "
                    "through its own header comment, so this line is optional -- but a provenance "
                    "claim that contradicts the manifest is worse than no claim. Fix it or delete "
                    "it.",
                )

    notes.append(
        f"CHECK 5: {checked} file(s) carry a provenance statement agreeing with their manifest "
        f"origin -- {checked - exempted - via_sidecar} via their own leading '#'-comment header, "
        f"{via_sidecar} via a {SIDECAR_NAME} sidecar (formats that cannot carry a '#' comment: "
        f"JSON, binary), {exempted} exempted (origin=upstream with sha256 == upstream_sha256, i.e. "
        "byte-for-byte vendored TEXT files that adding a header comment would falsify)"
    )


def main() -> int:
    doc = load_manifest()
    scan_cfg = doc.get("scan", {}) or {}
    entries = doc.get("kat", []) or []
    roots = [str(r) for r in (scan_cfg.get("roots") or [])]

    discovered = discover(scan_cfg)
    by_path = check_coverage(discovered, entries)
    for rel in [str(x).replace("\\", "/").strip() for x in (scan_cfg.get("exclude") or [])]:
        if rel in by_path:
            fail(
                "CHECK 2",
                f"{rel} is BOTH a [[kat]] entry and a [scan].exclude path. Excluding a file the "
                "manifest also claims to describe means the guard never hashes or header-checks "
                "it while the manifest still asserts a provenance for it -- pick one.",
            )
    check_hashes(by_path)
    check_naming(by_path)
    check_headers(by_path, roots)

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
