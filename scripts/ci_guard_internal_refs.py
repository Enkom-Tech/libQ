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
  5. internal product, host and tool names, from the committed keyed list and, when configured,
     the INTERNAL_REFS_KEY secret (see KEYED NAME LIST).

KEYED NAME LIST
===============
The names in check 5 are not in this repository in plain text. They come from two keyed lists in
the same format, and a token is reported when either list matches it:

  * `scripts/internal-refs-names.txt` (committed). Every non-comment line is a separate list and
    all of them are checked. Its key is published with it, so it keeps the
    names out of the text of the tree but does not make them secret: anyone can test a guessed
    word against it. It exists so that check 5 runs on every CI run, including pre-merge runs,
    which never receive secrets.
  * the environment variable `INTERNAL_REFS_KEY` (optional, a CI secret), for names that must not
    be guessable from the repository at all.

Both use this format:

    v3:<key as 64 hex chars>:<entry>,<entry>,...
    entry = <mode><SHA3-256(key || 0x00 || token) as 64 hex chars>

(`v2`, with entry = KMAC256(key, token, 256 bits, S="lib-q ci_guard_internal_refs v2"), is still
accepted. v3 exists because the pure-Python KMAC256 is too slow to run over the whole tree on every
CI run; SHA3-256 has no length extension, so a key-prefixed SHA3-256 is a sound keyed hash.)
    mode  = "i" (token is compared lower-cased) or "s" (exact spelling only, for a name that is also
            an ordinary upper-case abbreviation)

Every word of a line is tested, together with its dot-suffixes ("a.b.c" -> "b.c", "c") and its
hyphen/underscore n-grams ("a-b_c" -> "a-b", "b_c", "a", ...), so a name inside a longer label is
still found, however long the word is. Candidates longer than 40 characters, hex runs of 12 or more
characters and plain numbers are never tested (no listed name has those shapes), and
`--make-key-entry` refuses names of those shapes rather than emit an entry that can never match. The format is `v2` since the MAC moved from HMAC-SHA256 to KMAC256 (lib-Q ships no
SHA-2); a `v1` value fails the run with a request to regenerate it, rather than silently matching
nothing. Without the variable, check 5 uses the committed list alone. A variable or committed list
that is present but malformed fails the run. `--make-key-entry` builds entries from names on stdin
without writing the names anywhere; it uses `INTERNAL_REFS_KEY` if set, else the committed key.

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
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

KEY_ENV = "INTERNAL_REFS_KEY"
NAMES_FILE = "scripts/internal-refs-names.txt"
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
# KMAC256 (NIST SP 800-185), pure Python on Keccak-f[1600].
#
# lib-Q ships no SHA-2, so the keyed name list uses KMAC256 instead of HMAC-SHA256. hashlib has
# SHAKE but not cSHAKE/KMAC, so the permutation is implemented here. The self-test checks it
# against the three KMAC256 samples published by NIST (SP 800-185 examples, samples 4-6).

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M64 = (1 << 64) - 1


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                v = a[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M64 if r else v
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _M64) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def _left_encode(x: int) -> bytes:
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def _right_encode(x: int) -> bytes:
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big") + bytes([n])


def _encode_string(s: bytes) -> bytes:
    return _left_encode(len(s) * 8) + s


def _bytepad(x: bytes, w: int) -> bytes:
    z = _left_encode(w) + x
    return z + b"\x00" * ((-len(z)) % w)


def _cshake256(data: bytes, out_len: int, n: bytes, s: bytes) -> bytes:
    rate = 136
    msg = _bytepad(_encode_string(n) + _encode_string(s), rate) + data
    msg += b"\x04"  # cSHAKE domain bits 00, then pad10*1
    msg += b"\x00" * ((-len(msg)) % rate)
    msg = msg[:-1] + bytes([msg[-1] | 0x80])
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(a)
    out = b""
    while len(out) < out_len:
        out += b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(rate // 8))
        if len(out) < out_len:
            _keccak_f(a)
    return out[:out_len]


def kmac256(key: bytes, data: bytes, out_len: int, custom: bytes = b"") -> bytes:
    """KMAC256(K, X, L, S) per NIST SP 800-185 section 4.3, L = 8 * out_len bits."""
    x = _bytepad(_encode_string(key), 136) + data + _right_encode(out_len * 8)
    return _cshake256(x, out_len, b"KMAC", custom)


def _kmac_known_answers() -> list[str]:
    """NIST SP 800-185 KMAC256 samples 4-6; returns the samples that did NOT match."""
    key = bytes(range(0x40, 0x60))
    short = bytes(range(4))
    long_ = bytes(range(0xC8))
    tag = b"My Tagged Application"
    samples = [
        (4, short, tag, "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
                        "F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"),
        (5, long_, b"", "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691"
                        "589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"),
        (6, long_, tag, "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D9"
                        "70FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"),
    ]
    return [f"sample {n}" for n, data, custom, exp in samples
            if kmac256(key, data, 64, custom).hex().upper() != exp]


_MAC_CUSTOM = b"lib-q ci_guard_internal_refs v2"


# ---------------------------------------------------------------------------------------------
# keyed name list


class KeyConfigError(ValueError):
    pass


def parse_key(value: str | None):
    """Return (key_bytes, {digest_hex: mode}, version) or None when no key is configured."""
    if value is None or not value.strip():
        return None
    parts = value.strip().split(":", 2)
    if len(parts) == 3 and parts[0] == "v1":
        raise KeyConfigError(
            f"{KEY_ENV} is a v1 (HMAC-SHA256) value; the guard now uses KMAC256 (v2). Regenerate it: "
            f"set {KEY_ENV}=v2:<key hex>:<placeholder> and pipe the names into --make-key-entry"
        )
    if len(parts) != 3 or parts[0] not in ("v2", "v3"):
        raise KeyConfigError(f"{KEY_ENV} must look like v3:<key hex>:<entries> (or v2)")
    ver = int(parts[0][1])
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
    return key, entries, ver


_MAC_CACHE: dict[tuple[bytes, str, int], str] = {}
_MAX_NAME_LEN = 40
_NOT_A_NAME = re.compile(r"[0-9a-fA-F]{12,}|[0-9]+")


def _mac(key: bytes, token: str, ver: int = 3) -> str:
    """v3: SHA3-256(key || 0x00 || token). v2: KMAC256(key, token, 256 bits, S=_MAC_CUSTOM)."""
    hit = _MAC_CACHE.get((key, token, ver))
    if hit is None:
        if ver == 3:
            hit = hashlib.sha3_256(key + b"\x00" + token.encode("utf-8")).hexdigest()
        else:
            hit = kmac256(key, token.encode("utf-8"), 32, _MAC_CUSTOM).hex()
        _MAC_CACHE[(key, token, ver)] = hit
    return hit


def _could_be_name(token: str) -> bool:
    """Internal names are short words: skip long tokens, hex blobs and plain numbers unhashed."""
    return len(token) <= _MAX_NAME_LEN and not _NOT_A_NAME.fullmatch(token)


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
                if len(acc) > _MAX_NAME_LEN:
                    break  # only ever grows, and _could_be_name rejects it
                out.add(acc)
    return {c for c in out if c}


def name_hit(line: str, keyed) -> bool:
    if isinstance(keyed, list):
        return any(name_hit(line, k) for k in keyed)
    if keyed is None:
        return False
    key, entries, ver = keyed
    for m in WORD.finditer(line):
        for cand in _candidates(m.group(0)):
            if not _could_be_name(cand):
                continue
            if entries.get(_mac(key, cand, ver)) == "s":
                return True
            if entries.get(_mac(key, cand.lower(), ver)) == "i":
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
    bad_kmac = _kmac_known_answers()
    expect(not bad_kmac, f"KMAC256 does not match the NIST SP 800-185 samples: {bad_kmac}")
    key = secrets.token_bytes(32)
    keyed_value = f"v2:{key.hex()}:i{_mac(key, canary, 2)}"
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
    v3 = parse_key(f"v3:{key.hex()}:i{_mac(key, canary, 3)}")
    expect("internal host or tool name" in check_line("ssh " + canary, v3)[0], "v3 canary not detected")
    expect(not check_line("ssh " + canary, parse_key(f"v3:{secrets.token_hex(32)}:i{_mac(key, canary, 3)}"))[0],
           "a v3 entry matched under a different key")
    expect(_mac(key, canary, 2) != _mac(key, canary, 3), "v2 and v3 digests coincide")
    other = parse_key(f"v2:{secrets.token_hex(32)}:i{'0' * 64}")
    f, _ = check_line("ssh " + canary, [other, keyed])
    expect("internal host or tool name" in f, "a canary in the second of two keyed lists was not detected")
    f, _ = check_line("ssh " + canary, other)
    expect(not f, "a different key must not match the canary")
    s_value = f"v2:{key.hex()}:s{_mac(key, 'Canary', 2)}"
    expect(bool(check_line("the Canary host", parse_key(s_value))[0]), "exact-case entry not detected")
    expect(not check_line("the canary host", parse_key(s_value))[0], "exact-case entry matched other case")
    for bad in ("v3:00:i00", "v2:zz:i" + "0" * 64, f"v2:{key.hex()}:x" + "0" * 64, f"v2:{'00' * 8}:i" + "0" * 64,
                f"v1:{key.hex()}:i" + "0" * 64):
        try:
            parse_key(bad)
            expect(False, f"malformed {KEY_ENV} accepted: {bad[:12]}...")
        except KeyConfigError:
            pass
    expect(parse_key("") is None and parse_key(None) is None, "an empty key must mean 'not configured'")

    # Committed-style list file: every non-comment line is read, not only the first.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / NAMES_FILE).parent.mkdir(parents=True)
        (root / NAMES_FILE).write_text(
            "# comment\n"
            f"v3:{secrets.token_hex(32)}:i{'0' * 64}\n"
            f"v3:{key.hex()}:i{_mac(key, canary, 3)}\n",
            encoding="utf-8",
        )
        lists = read_names_file(root)
        expect(len(lists) == 2, f"read_names_file returned {len(lists)} list(s) for a two-line file")
        f, _ = check_line("ssh " + canary, lists)
        expect("internal host or tool name" in f,
               "a canary only in the second line of the list file was not detected")

    # A name at the end of a long hyphenated word is still found.
    long_word = "-".join(["segment"] * 25) + "-" + canary
    expect(len(long_word) > 160, "the long-word fixture is not longer than 160 characters")
    f, _ = check_line("label " + long_word, v3)
    expect("internal host or tool name" in f, "a canary at the end of a long hyphenated word was not detected")

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


def read_names_file(root: pathlib.Path) -> list:
    """The committed keyed lists: every non-comment, non-blank line of NAMES_FILE, each parsed."""
    path = root / NAMES_FILE
    if not path.is_file():
        raise KeyConfigError(f"{NAMES_FILE} is missing")
    lists = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lists.append(parse_key(line))
    if not lists:
        raise KeyConfigError(f"{NAMES_FILE} holds no entries")
    return lists


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--make-key-entry"]:
        keyed = parse_key(os.environ.get(KEY_ENV))
        if keyed is None:
            here = pathlib.Path(__file__).resolve().parent.parent
            try:
                keyed = read_names_file(here)[0]
            except KeyConfigError as e:
                print(f"set {KEY_ENV}=v2:<key hex>:<a placeholder entry> first ({e})", file=sys.stderr)
                return 1
        key, _, ver = keyed
        out = []
        for lineno, line in enumerate(sys.stdin.read().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            mode, _, token = line.partition(" ") if line[:2] in ("i ", "s ") else ("i", "", line)
            if not _could_be_name(token):
                print(f"--make-key-entry: warning: skipped input line {lineno}: the scan never tests a "
                      f"name over {_MAX_NAME_LEN} characters, a hex run of 12+ characters or a plain "
                      "number, so its entry could never match", file=sys.stderr)
                continue
            out.append(mode + _mac(key, token.lower() if mode == "i" else token, ver))
        print(",".join(out))
        return 0

    if not self_test():
        print("SELF-TEST FAILED -- the internal-reference guard is not detecting what it claims.")
        return 1
    if argv[1:2] == ["--self-test"]:
        print("ci-guard-internal-refs: self-test OK")
        return 0

    root = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
    )
    try:
        keyed = read_names_file(root)
        from_env = parse_key(os.environ.get(KEY_ENV))
    except KeyConfigError as e:
        print(f"ci-guard-internal-refs: {e}")
        return 1
    if from_env is None:
        print(f"ci-guard-internal-refs: notice: {KEY_ENV} is not set; the internal-name check uses "
              f"the committed list in {NAMES_FILE} only.")
    else:
        keyed.append(from_env)
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
        print(f"ci-guard-internal-refs: OK -- {len(files)} tracked file(s), no internal references")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
