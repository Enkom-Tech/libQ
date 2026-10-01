#!/usr/bin/env python3
"""Guard: no internal work-tracker references or internal infrastructure details in the tree.

WHY THIS EXISTS
===============
This repository is published. Comments, docs and CI configuration used to cite identifiers from a
private work tracker, internal task numbers, private hosts and tools, and workstation paths. Readers
outside the project cannot resolve any of them. They were removed in one sweep; this guard stops
them coming back one commit at a time.

WHAT IT CHECKS (every tracked text file, and every tracked file name)
=====================================================================
  1. tracker identifiers (`ID_PATTERNS`): the two identifier shapes the private tracker issues, in
     any case, with a hyphen, dash, space or underscore separator, and when glued to a prefix such
     as `card_`.
  2. internal task numbers: "task #<n>".
  3. workstation paths: a Windows user-profile path (`C:\\Users\\<name>`, `C:/Users/<name>`,
     `/c/Users/<name>`, `/mnt/c/Users/<name>`, and the separator-less `C:Users<name>` a shell makes
     of a mangled path). Generic placeholders (`<user>`, `...`, `someone`, `%USERNAME%`, ...) pass.
  4. private-network addresses: an RFC 1918 IPv4 literal whose octets are all valid, or a
     loopback/localhost address with a port. A dotted number that follows a section reference
     ("NIST 10.2.1.2", "SP 800-90A 10.1.1.2", "section 10.1.2.3", "§10.1.2.3") is a section number,
     not an address, and a number with a fifth component ("10.2.1.3.1") never matches.
  5. internal host and tool names -- only when a key is configured (see KEYED NAME LIST).

KEYED NAME LIST
===============
The names in check 5 are not in this repository, in plain text or as plain hashes: a plain hash of
a short word is recovered by trying candidate words, so a published hash list is a published list.
Instead, CI supplies the environment variable `INTERNAL_REFS_KEY`:

    v1:<key as 64 hex chars>:<entry>,<entry>,...
    entry = <mode><HMAC-SHA256(key, token) as 64 hex chars>
    mode  = "i" (token is compared lower-cased) or "s" (exact spelling only, for a name that is also
            an ordinary upper-case abbreviation)

Every word of a line is tested, together with its dot-suffixes ("a.b.c" -> "b.c", "c") and its
hyphen/underscore n-grams ("a-b_c" -> "a-b", "b_c", "a", ...), so a name inside a longer label is
still found. Without the variable (for example on the public mirror's CI) check 5 is skipped with a
notice and checks 1-4 still run. A variable that is set but malformed fails the run.
`--make-key-entry` builds the value from names on stdin without writing them anywhere.

EXEMPTIONS
==========
Only check 4 can be exempted, because only an address can be a legitimate non-reference (a test
fixture, for example). Put `internal-refs: allow-address <reason>` on the line. Every exempted line
is printed on every run, and the run fails if their number exceeds the ceiling committed in
`scripts/internal-refs-exemptions-max.txt` (a ratchet, like the repo's other exemption files).
Tracker identifiers, task numbers, workstation paths and internal names cannot be exempted.

SELF-TEST
=========
The guard runs its self-test before every scan (`--self-test` runs it alone): planted defects of
every kind must be reported, clean lines must pass, the exemption must cover only addresses, and
the keyed-name check is exercised with a throwaway key and a canary token, both with and without a
key configured.

Usage:
  python scripts/ci_guard_internal_refs.py [REPO_ROOT]
  python scripts/ci_guard_internal_refs.py --self-test
  INTERNAL_REFS_KEY=... python scripts/ci_guard_internal_refs.py --make-key-entry < names.txt
"""

from __future__ import annotations

import hashlib
import hmac
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

KEY_ENV = "INTERNAL_REFS_KEY"
ALLOW_MARKER = "internal-refs: allow-address"
CEILING_FILE = "scripts/internal-refs-exemptions-max.txt"

_SEP = r"[\s\-\u2010-\u2015_]?"
ID_PATTERNS = [
    ("tracker identifier", re.compile(r"(?<![0-9A-Za-z])ENK" + _SEP + r"[0-9]{1,6}(?![0-9])", re.I)),
    ("tracker identifier", re.compile(r"(?<![0-9A-Za-z])t_[0-9a-f]{8}(?![0-9A-Za-z])", re.I)),
    ("internal task number", re.compile(r"\btask\s*#\s*[0-9]+", re.I)),
]

_PLACEHOLDERS = {
    "...", "user", "users", "username", "someone", "me", "you", "name", "public", "default",
    "all users", "%username%", "$env:username", "$user", "${user}", "runner", "runneradmin",
}
_PROFILE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]:|/[A-Za-z]|/mnt/[A-Za-z])[\\/]+Users[\\/]+([^\\/\s'\"`),;]+)", re.I
)
_PROFILE_MANGLED = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:Users(?=[A-Za-z0-9])", re.I)

_SECTION_CONTEXT = re.compile(r"(?:NIST|SP\s*800-\d+[A-Z]?|[Ss]ection|§)\s*$")
_IPV4 = re.compile(
    r"(?<![\w.])(10|192\.168|172\.(?:1[6-9]|2\d|3[01]))((?:\.\d{1,3}){2,3})(?![\w]|\.\d)"
)
_LOOPBACK = re.compile(r"\b(?:127\.0\.0\.1|localhost):\d{2,5}\b")

WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


# ---------------------------------------------------------------------------------------------
# keyed name list


class KeyConfigError(ValueError):
    pass


def parse_key(value: str | None):
    """Return (key_bytes, {digest_hex: mode}) or None when no key is configured."""
    if value is None or not value.strip():
        return None
    parts = value.strip().split(":", 2)
    if len(parts) != 3 or parts[0] != "v1":
        raise KeyConfigError(f"{KEY_ENV} must look like v1:<key hex>:<entries>")
    try:
        key = bytes.fromhex(parts[1])
    except ValueError as e:
        raise KeyConfigError(f"{KEY_ENV}: key is not hex") from e
    if len(key) < 32:
        raise KeyConfigError(f"{KEY_ENV}: key must be at least 32 bytes")
    entries = {}
    for raw in parts[2].split(","):
        raw = raw.strip()
        if not raw:
            continue
        mode, digest = raw[0], raw[1:].lower()
        if mode not in "is" or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise KeyConfigError(f"{KEY_ENV}: malformed entry {raw[:8]}...")
        entries[digest] = mode
    if not entries:
        raise KeyConfigError(f"{KEY_ENV}: no entries")
    return key, entries


def _mac(key: bytes, token: str) -> str:
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def _candidates(word: str) -> set[str]:
    word = word.strip("._-")
    out = {word}
    dots = word.split(".")
    for i in range(1, len(dots)):
        out.add(".".join(dots[i:]))
    for piece in list(out) + dots:
        parts = re.split(r"([-_])", piece)
        toks, seps = parts[0::2], parts[1::2]
        for i in range(len(toks)):
            acc = toks[i]
            out.add(acc)
            for j in range(i + 1, len(toks)):
                acc = acc + seps[j - 1] + toks[j]
                out.add(acc)
    return {c for c in out if c}


def name_hit(line: str, keyed) -> bool:
    if keyed is None:
        return False
    key, entries = keyed
    for m in WORD.finditer(line):
        for cand in _candidates(m.group(0)):
            if entries.get(_mac(key, cand)) == "s":
                return True
            if entries.get(_mac(key, cand.lower())) == "i":
                return True
    return False


# ---------------------------------------------------------------------------------------------
# line checks


def _address_hit(line: str) -> bool:
    for m in _IPV4.finditer(line):
        octets = (m.group(1) + m.group(2)).split(".")
        if len(octets) != 4 or any(int(o) > 255 for o in octets):
            continue
        if _SECTION_CONTEXT.search(line[: m.start()]):
            continue
        return True
    return bool(_LOOPBACK.search(line))


def _profile_hit(line: str) -> bool:
    for m in _PROFILE.finditer(line):
        name = m.group(1).strip().lower()
        if name in _PLACEHOLDERS or name.startswith("<") or name.startswith("$") or name.startswith("%"):
            continue
        return True
    return bool(_PROFILE_MANGLED.search(line))


def check_line(line: str, keyed) -> tuple[list[str], bool]:
    """Return (findings, exempted_address) for one line."""
    found = [label for label, rx in ID_PATTERNS if rx.search(line)]
    if _profile_hit(line):
        found.append("workstation user-profile path")
    if name_hit(line, keyed):
        found.append("internal host or tool name")
    exempted = False
    if _address_hit(line):
        marker = line.find(ALLOW_MARKER)
        if marker >= 0 and line[marker + len(ALLOW_MARKER):].strip():
            exempted = True
        else:
            found.append("private-network address")
    return found, exempted


def scan_text(text: str, keyed):
    findings, exempt = [], []
    for lineno, line in enumerate(text.splitlines(), 1):
        f, e = check_line(line, keyed)
        findings += [(lineno, label) for label in f]
        if e:
            exempt.append(lineno)
    return findings, exempt


def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [root / p for p in out.decode("utf-8").split("\0") if p]


def scan_tree(root: pathlib.Path, files, keyed):
    report, exempt = [], []
    for path in files:
        rel = path.relative_to(root).as_posix()
        name_findings, _ = check_line(rel, keyed)
        for label in name_findings:
            report.append(f"  FAIL: {rel}: file name: {label}")
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue  # binary
        findings, ex = scan_text(data.decode("utf-8", errors="replace"), keyed)
        report += [f"  FAIL: {rel}:{n}: {label}" for n, label in findings]
        exempt += [f"{rel}:{n}" for n in ex]
    return report, exempt


def read_ceiling(root: pathlib.Path) -> int:
    p = root / CEILING_FILE
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return int(line)
    raise ValueError(f"{CEILING_FILE} has no number")


# ---------------------------------------------------------------------------------------------
# self-test


def self_test() -> bool:
    ok = True

    def expect(cond: bool, msg: str):
        nonlocal ok
        if not cond:
            print(f"  - self-test: {msg}")
            ok = False

    canary = "internal-ref-guard-" + "canary"
    key = secrets.token_bytes(32)
    keyed_value = f"v1:{key.hex()}:i{_mac(key, canary)}"
    keyed = parse_key(keyed_value)

    planted = {
        "tracker identifier": "see " + "ENK" + "-1234 for details",
        "tracker identifier, lower case": "see " + "enk" + "-123.",
        "tracker identifier, space": "see " + "ENK" + " 123.",
        "tracker identifier, non-breaking hyphen": "see " + "ENK" + "\u2011" + "77",
        "hex identifier": "fixed in " + "t_" + "0123abcd" + ".",
        "hex identifier, upper case": "fixed in " + "t_" + "71D4F79A" + ".",
        "hex identifier after a prefix": "card_" + "t_" + "71d4f79a",
        "task number": "the assembly (" + "task" + " #26)",
        "user-profile path": "C:" + "\\Users\\" + "alice" + "\\src",
        "user-profile path, forward slashes": "/c/" + "Users/" + "alice/src",
        "mangled user-profile path": "arrives as `C:" + "Users" + "alice" + "scripts`",
        "private IPv4 address": "curl http://" + "10." + "9.8.7" + "/x",
        "private IPv4 address with port": "host " + "192.168." + "1.20:22",
        "loopback address with a port": "base = http://" + "127.0.0.1" + ":8080",
    }
    for what, line in planted.items():
        found, _ = check_line(line, None)
        expect(bool(found), f"planted {what} was NOT detected: {line!r}")

    clean = [
        "Instantiate the DRBG (NIST 10.2.1.3.1).",
        "CTR_DRBG update (NIST 10.2.1.2)",
        "Hash_DRBG instantiate (SP 800-90A 10.1.1.2).",
        "see section 10.1.2.3 and §10.2.1.1",
        "not an address: 10.300.1.1",
        "Long-term support (LTS) toolchain.",
        "a https://example.invalid fixture",
        "core.hooksPath C:/" + "Users/someone/old/.githooks",
        "it cannot open `C:/" + "Users/...`",
        "copy to C:\\" + "Users\\<user>\\AppData",
        "tasks #1 through #3 of the checklist",
        "ssh " + canary + " uptime",  # clean when no key is configured
    ]
    for line in clean:
        found, _ = check_line(line, None)
        expect(not found, f"clean line was flagged {found}: {line!r}")

    # Exemption covers addresses only, and only with a reason.
    addr = "fixture http://" + "10." + "1.2.3" + "/"
    f, e = check_line(addr + " " + ALLOW_MARKER + " test fixture", None)
    expect(not f and e, "an address with an allow-address reason should be exempted and counted")
    f, e = check_line(addr + " " + ALLOW_MARKER, None)
    expect(bool(f) and not e, "an allow-address marker without a reason must not exempt")
    f, e = check_line("see " + "ENK" + "-12 " + ALLOW_MARKER + " because", None)
    expect(bool(f), "a tracker identifier must not be exemptable")

    # Keyed names: detected with the key (inline and inside labels), not without it.
    for line in ("ssh " + canary + " uptime", "runner-" + canary.upper() + "-2",
                 "x_" + canary + "_y", "host." + canary + ".example"):
        f, _ = check_line(line, keyed)
        expect("internal host or tool name" in f, f"keyed canary not detected: {line!r}")
    f, _ = check_line("ssh " + canary, parse_key(f"v1:{secrets.token_hex(32)}:i{'0' * 64}"))
    expect(not f, "a different key must not match the canary")
    s_value = f"v1:{key.hex()}:s{_mac(key, 'Canary')}"
    expect(bool(check_line("the Canary host", parse_key(s_value))[0]), "exact-case entry not detected")
    expect(not check_line("the canary host", parse_key(s_value))[0], "exact-case entry matched other case")
    for bad in ("v2:00:i00", "v1:zz:i" + "0" * 64, f"v1:{key.hex()}:x" + "0" * 64, f"v1:{'00' * 8}:i" + "0" * 64):
        try:
            parse_key(bad)
            expect(False, f"malformed {KEY_ENV} accepted: {bad[:12]}...")
        except KeyConfigError:
            pass
    expect(parse_key("") is None and parse_key(None) is None, "an empty key must mean 'not configured'")

    # File-level path: planted file reported, clean file not, exemption listed.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "clean.md").write_text("\n".join(clean) + "\n", encoding="utf-8")
        (root / "bad.rs").write_text("// see " + "t_" + "0123abcd\n", encoding="utf-8")
        (root / "fixture.txt").write_text(addr + " " + ALLOW_MARKER + " fixture\n", encoding="utf-8")
        (root / ("notes-" + "ENK" + "-5.md")).write_text("ok\n", encoding="utf-8")
        files = sorted(root.iterdir())
        report, exempt = scan_tree(root, files, None)
        expect(any("bad.rs:1" in r for r in report), "a planted file was not reported")
        expect(any("file name" in r for r in report), "a file name with an identifier was not reported")
        expect(not any("clean.md" in r for r in report), "a clean file was reported")
        expect(exempt == ["fixture.txt:1"], f"exemption not listed as expected: {exempt}")
    return ok


# ---------------------------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--make-key-entry"]:
        keyed = parse_key(os.environ.get(KEY_ENV))
        if keyed is None:
            print(f"set {KEY_ENV}=v1:<key hex>:<existing entries or a placeholder> first", file=sys.stderr)
            return 1
        key, _ = keyed
        out = []
        for line in sys.stdin.read().splitlines():
            line = line.strip()
            if not line:
                continue
            mode, _, token = line.partition(" ") if line[:2] in ("i ", "s ") else ("i", "", line)
            out.append(mode + _mac(key, token.lower() if mode == "i" else token))
        print(",".join(out))
        return 0

    if not self_test():
        print("SELF-TEST FAILED -- the internal-reference guard is not detecting what it claims.")
        return 1
    if argv[1:2] == ["--self-test"]:
        print("ci-guard-internal-refs: self-test OK")
        return 0

    try:
        keyed = parse_key(os.environ.get(KEY_ENV))
    except KeyConfigError as e:
        print(f"ci-guard-internal-refs: {e}")
        return 1
    if keyed is None:
        print(f"ci-guard-internal-refs: notice: {KEY_ENV} is not set, so the internal-name check is "
              "skipped; all other checks run.")

    root = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
    )
    files = tracked_files(root)
    if not files:
        print("ci-guard-internal-refs: no tracked files found -- refusing to report a clean tree")
        return 1
    report, exempt = scan_tree(root, files, keyed)
    ceiling = read_ceiling(root)
    print(f"ci-guard-internal-refs: {len(exempt)} address exemption(s) (ceiling {ceiling}):")
    for e in exempt:
        print(f"  EXEMPT: {e}")
    rc = 0
    if len(exempt) > ceiling:
        print(f"ci-guard-internal-refs: {len(exempt)} exemptions exceed the ceiling of {ceiling} in "
              f"{CEILING_FILE}. Remove the address, or raise the ceiling in a reviewed change.")
        rc = 1
    if report:
        print("\n".join(report))
        print(f"ci-guard-internal-refs: {len(report)} internal reference(s) found. Describe what the "
              "reference was for in plain words instead; see this script's header.")
        rc = 1
    if rc == 0:
        print(f"ci-guard-internal-refs: OK -- {len(files)} tracked file(s), no internal references"
              + ("" if keyed else " (internal-name check skipped)"))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
