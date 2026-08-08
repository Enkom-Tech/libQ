#!/usr/bin/env python3
"""Ratchet the classical-cryptography surface of this post-quantum library.

WHAT THIS REPLACES
------------------
`scripts/security-check.sh` used to open with:

    grep -r "use.*aes\\|use.*sha256\\|use.*rsa\\|use.*ecdsa" src/ 2>/dev/null

and seven more checks in the same shape. Every one of them scanned a repo-root `src/`
directory that stopped existing when libQ split into `lib-q-*` crates. `grep` therefore
found nothing, `2>/dev/null` hid the reason, and the FAIL branch was unreachable: the
script could only ever PASS. It also printed a hardcoded summary of check marks that was
unrelated to what the checks found.

WHY THE ORIGINAL CHECK COULD NOT SIMPLY BE REPOINTED
-----------------------------------------------------
Its premise -- that this repo contains no classical cryptography -- is false, and a naive
repoint would have produced a gate that fails on correct code. OBSERVED: 21 tracked source
files import a classical primitive, and the great majority are required rather than
accidental:

  * FIPS 205 specifies SLH-DSA parameter sets built on SHA-2. Implementing SLH-DSA-SHA2
    means using SHA-2.
  * MAYO expands its matrices with AES-128-CTR, per its specification.
  * NIST's KAT harnesses are defined in terms of an AES-CTR-DRBG. Reproducing published
    vectors byte for byte means running that DRBG.
  * `lib-q-hash` deliberately exports SHA-2 wrappers for interoperability.

A gate banning all of it would be wrong. What is worth preventing is *new, unexamined*
classical crypto appearing -- so this is a ratchet over a reviewed allowlist rather than a
ban.

WHY IT RATCHETS ON MANIFESTS AND NOT ON IMPORTS
------------------------------------------------
A crate cannot use `sha2` without declaring it, so the dependency tables are the complete
and non-evadable surface; `use` lines are neither (a fully-qualified `sha2::Sha256::new()`
has no `use`, and a `use` inside a macro body may not look like one). 11 manifests declare
a classical dependency versus 21 files importing one, so the manifest view is also the
smaller thing to keep reviewed.

The scan is section-aware. `[dependencies]` and `[build-dependencies]` ship to users;
`[dev-dependencies]` exist only when running this repo's own tests. Both are ratcheted,
because a new one of either deserves a look, but they are recorded and reported
separately. That distinction is not cosmetic -- it is a real classification this file got
wrong on the first pass: a section-blind grep reported `lib-q-slh-dsa` as shipping `aes`
to users, when the declaration is in its `[dev-dependencies]`.

HOW IT FAILS
------------
  * A crate declares a classical dependency that the allowlist does not cover  -> FAIL
  * An allowlist entry no longer matches anything                              -> FAIL
  * An entry is recorded as TODO (accepted for now, not justified)             -> WARN

Stale entries fail deliberately. An allowlist that keeps entries for dependencies that
were removed is one that nobody is reading, and it silently grants permission to
re-introduce them later.

The workspace root manifest is skipped: `[workspace.dependencies]` only pins a version for
members that opt in with `workspace = true`, so it grants no usage by itself. Members that
opt in are caught on their own manifests, which is where the decision actually lives.

Usage:
    python3 security_check_classical_crypto.py [REPO_ROOT]
    python3 security_check_classical_crypto.py --self-test
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Crate names that indicate pre-quantum cryptography. Matched against the dependency KEY,
# so a rename (`aes_impl = { package = "aes" }`) is handled by the package-name check below
# rather than by this list.
CLASSICAL = {
    "aes", "aes-gcm", "aes-gcm-siv", "aes-siv",
    "sha1", "sha-1", "sha2", "sha-2",
    "md-5", "md5",
    "rsa", "ecdsa", "elliptic-curve",
    "p256", "p384", "p521", "k256",
    "ed25519", "ed25519-dalek", "ed25519-compact",
    "x25519-dalek", "curve25519-dalek",
    "secp256k1", "libsecp256k1",
    "des", "rc4", "blowfish",
}

SHIPPED_SECTIONS = ("dependencies", "build-dependencies")
DEV_SECTION = "dev-dependencies"

ALLOWLIST_NAME = "classical-crypto-allowlist.txt"
EXCLUDE_PREFIXES = ("reference/",)

SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
# `name = ...` at the start of a line. Dependency keys may be quoted.
DEP_RE = re.compile(r'^\s*"?([A-Za-z0-9_][A-Za-z0-9_.-]*)"?\s*=')
PACKAGE_RE = re.compile(r'package\s*=\s*"([^"]+)"')


def norm(name: str) -> str:
    """crates.io treats `-` and `_` as equivalent for lookup; compare on one spelling."""
    return name.replace("_", "-").lower()


CLASSICAL_NORM = {norm(c) for c in CLASSICAL}


def section_kind(header: str) -> str | None:
    """Classify a TOML table header as shipped / dev / irrelevant.

    Handles the target-specific forms too, e.g.
    `[target.'cfg(unix)'.dependencies]` and `[target.x86_64-.../dev-dependencies]`,
    which are ordinary dependency tables that a naive equality check would miss.
    """
    head = header.strip()
    if head.startswith("workspace."):
        # Root pins only; see the module docstring.
        return None
    tail = head.rsplit(".", 1)[-1]
    if tail == DEV_SECTION:
        return "dev"
    if tail in SHIPPED_SECTIONS:
        return "shipped"
    return None


def scan_manifest(path: Path) -> list[tuple[str, str]]:
    """Return [(dependency_name, "shipped"|"dev")] for classical deps declared in `path`."""
    found: list[tuple[str, str]] = []
    kind: str | None = None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return found

    for line in text.splitlines():
        header = SECTION_RE.match(line)
        if header:
            kind = section_kind(header.group(1))
            continue
        if kind is None:
            continue
        match = DEP_RE.match(line)
        if not match:
            continue
        key = match.group(1)
        # A renamed dependency declares its real crate via `package = "..."`; that is the
        # name that decides whether this is classical crypto, not the local alias.
        renamed = PACKAGE_RE.search(line)
        actual = renamed.group(1) if renamed else key
        if norm(actual) in CLASSICAL_NORM:
            found.append((norm(actual), kind))
    return found


def tracked_manifests(root: Path) -> list[Path]:
    """Every git-tracked Cargo.toml except vendored trees and the workspace root."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "Cargo.toml", "*/Cargo.toml", "**/Cargo.toml"],
            capture_output=True, text=True, check=True,
        ).stdout
        rels = sorted({line.strip() for line in out.splitlines() if line.strip()})
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Not a git tree (the self-test fixture). Fall back to a walk.
        rels = sorted(
            str(p.relative_to(root)).replace("\\", "/")
            for p in root.rglob("Cargo.toml")
            if "target" not in p.parts
        )

    manifests = []
    for rel in rels:
        if rel == "Cargo.toml":
            continue  # workspace root: pins only
        if any(rel.startswith(prefix) for prefix in EXCLUDE_PREFIXES):
            continue
        manifests.append(root / rel)
    return manifests


def parse_allowlist(path: Path) -> tuple[dict[tuple[str, str], tuple[str, str]], list[str]]:
    """Parse `crate | dep | STATUS | reason` lines. Returns (entries, errors)."""
    entries: dict[tuple[str, str], tuple[str, str]] = {}
    errors: list[str] = []
    if not path.exists():
        return entries, [f"allowlist not found: {path}"]

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4:
            errors.append(f"{path.name}:{lineno}: expected 4 fields, got {len(parts)}: {line}")
            continue
        crate, dep, status, reason = parts
        if status not in ("JUSTIFIED", "TODO"):
            errors.append(f"{path.name}:{lineno}: status must be JUSTIFIED or TODO, got {status!r}")
            continue
        if not reason:
            errors.append(f"{path.name}:{lineno}: reason is required")
            continue
        entries[(crate, norm(dep))] = (status, reason)
    return entries, errors


def collect(root: Path) -> dict[tuple[str, str], str]:
    """Map (crate_dir, dep) -> "shipped"|"dev" for every classical dep in the tree."""
    actual: dict[tuple[str, str], str] = {}
    for manifest in tracked_manifests(root):
        crate = manifest.parent.relative_to(root).as_posix()
        for dep, kind in scan_manifest(manifest):
            key = (crate, dep)
            # A dep in both tables ships; report the stronger classification.
            if actual.get(key) != "shipped":
                actual[key] = kind
    return actual


def run(root: Path, allowlist_path: Path) -> int:
    actual = collect(root)
    allowed, errors = parse_allowlist(allowlist_path)

    for err in errors:
        print(f"  FAIL: {err}")

    unexpected = sorted(k for k in actual if k not in allowed)
    stale = sorted(k for k in allowed if k not in actual)
    todos = sorted(k for k in actual if k in allowed and allowed[k][0] == "TODO")

    for crate, dep in unexpected:
        kind = actual[(crate, dep)]
        print(f"  FAIL: {crate} declares classical dependency '{dep}' ({kind}), not in {ALLOWLIST_NAME}.")
        print(f"        If it is required, add:  {crate} | {dep} | JUSTIFIED | <why it is unavoidable>")

    for crate, dep in stale:
        print(f"  FAIL: {ALLOWLIST_NAME} still allows '{dep}' for {crate}, which no longer declares it.")
        print("        Remove the line -- a stale entry silently re-permits the dependency later.")

    for crate, dep in todos:
        print(f"  WARN: {crate} -> {dep}: {allowed[(crate, dep)][1]}")

    failures = len(errors) + len(unexpected) + len(stale)
    shipped = sum(1 for v in actual.values() if v == "shipped")
    print(
        f"  {len(actual)} classical dependency declarations "
        f"({shipped} shipped, {len(actual) - shipped} dev-only) across "
        f"{len({c for c, _ in actual})} crates; {len(todos)} awaiting justification."
    )
    return 1 if failures else 0


SELF_TEST_ALLOWLIST = """\
# fixture allowlist
good-crate | sha2 | JUSTIFIED | fixture: a reviewed, required use
gone-crate | aes  | JUSTIFIED | fixture: this crate no longer declares it
"""

SELF_TEST_MANIFESTS = {
    "good-crate/Cargo.toml": """\
[package]
name = "good-crate"
[dependencies]
sha2 = { workspace = true }
""",
    "bad-crate/Cargo.toml": """\
[package]
name = "bad-crate"
[dependencies]
rsa = "0.9"
""",
    "dev-crate/Cargo.toml": """\
[package]
name = "dev-crate"
[dev-dependencies]
aes = "0.9"
""",
    "renamed-crate/Cargo.toml": """\
[package]
name = "renamed-crate"
[dependencies]
myhash = { package = "sha2", version = "0.11" }
""",
    "target-crate/Cargo.toml": """\
[package]
name = "target-crate"
[target.'cfg(unix)'.dependencies]
ecdsa = "0.16"
""",
    "clean-crate/Cargo.toml": """\
[package]
name = "clean-crate"
[dependencies]
lib-q-sha3 = { workspace = true }
""",
    # Workspace-root pins must NOT count as usage.
    "Cargo.toml": """\
[workspace]
members = ["good-crate"]
[workspace.dependencies]
sha2 = "0.11"
aes = "0.9"
""",
}


def self_test() -> int:
    """Prove the ratchet rejects input it should reject, before trusting a clean run.

    Every construct here is load-bearing:
      bad-crate      a new shipped classical dep must FAIL
      dev-crate      a new dev-only classical dep must FAIL, classified "dev"
      renamed-crate  `package = "sha2"` behind an alias must still be caught
      target-crate   `[target.'cfg(unix)'.dependencies]` is a real dependency table
      gone-crate     an allowlist entry matching nothing must FAIL as stale
      good-crate     a covered dep must NOT fire
      clean-crate    a crate with no classical dep must NOT fire
      root Cargo.toml  `[workspace.dependencies]` pins must NOT count as usage
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, content in SELF_TEST_MANIFESTS.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        allowlist = root / ALLOWLIST_NAME
        allowlist.write_text(SELF_TEST_ALLOWLIST, encoding="utf-8")

        actual = collect(root)
        allowed, errors = parse_allowlist(allowlist)
        unexpected = {k for k in actual if k not in allowed}
        stale = {k for k in allowed if k not in actual}

        problems = []
        if errors:
            problems.append(f"allowlist parse errors on a valid fixture: {errors}")
        expected_unexpected = {
            ("bad-crate", "rsa"),
            ("dev-crate", "aes"),
            ("renamed-crate", "sha2"),
            ("target-crate", "ecdsa"),
        }
        if unexpected != expected_unexpected:
            problems.append(
                f"unexpected-set mismatch: got {sorted(unexpected)}, want {sorted(expected_unexpected)}"
            )
        if stale != {("gone-crate", "aes")}:
            problems.append(f"stale-set mismatch: got {sorted(stale)}")
        if actual.get(("dev-crate", "aes")) != "dev":
            problems.append("dev-dependencies must be classified 'dev'")
        if actual.get(("good-crate", "sha2")) != "shipped":
            problems.append("[dependencies] must be classified 'shipped'")
        if any(crate == "clean-crate" for crate, _ in actual):
            problems.append("a crate with no classical dependency must not be reported")
        if any(crate == "." for crate, _ in actual):
            problems.append("[workspace.dependencies] pins must not count as usage")

        if problems:
            print("SELF-TEST FAILED -- the ratchet is not detecting what it claims:")
            for p in problems:
                print(f"  - {p}")
            return 1
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path.cwd()
    allowlist = Path(__file__).resolve().parent / ALLOWLIST_NAME
    return run(root, allowlist)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
