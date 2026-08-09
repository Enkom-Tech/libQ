# Vendored upstream KAT vectors — TurboSHAKE (`lib-q-sha3`)

These four `.blb` files are **byte-for-byte copies** of RustCrypto's `turboshake` crate test data
(the crate was named `turbo-shake` before PR #843 renamed it), which is itself RFC 9861
("KangarooTwelve and TurboSHAKE", Section 5) test vectors packed into the
[`blobby`](https://crates.io/crates/blobby) 0.4 container format that crate's own test harness
reads.

## Why this directory exists (card t_71d4f79a / t_f0d676d1)

Before this pass, `lib-q-sha3/tests/data/turboshake{128,256}_{6,7}.blb` existed on disk but were
each **exactly one byte shorter** than RustCrypto's real files, so `blobby` could not decode them —
`tests/data/upstream/PROVENANCE.md` recorded this as "do not decode under `blobby` 0.4 and no test
references them", and `kats-manifest.toml`'s own `[scan]` comment separately flagged "9 [`.blb`
files sharing a name with RustCrypto/hashes and NONE matches its bytes, and that is unexplained."
Meanwhile `tests/turboshake.rs` carried only property tests, with a comment arguing that was "more
robust than hardcoded test vectors" — the wrong call for a standardized primitive, since a property
test cannot detect divergence from the standard. The four files here are the fix: real,
byte-exact-verified vectors, decoding and passing under `blobby` 0.4, wired into
`tests/turboshake_blobby_kats.rs`.

They live in their own subdirectory (not flat under `tests/data/`, unlike the sha3/cshake `.blb`
files next door) so that registering them in `kats-manifest.toml` does not implicitly pull the
other ~15 unregistered `.blb` files under `tests/data/` into `[scan]` scope — each of those needs
its own per-file provenance investigation before being swept in (see the manifest's own comment).

## Source and digests

Fetched live and hashed 2026-08-09 against a specific pinned commit (the crate is `0.1.0
UNRELEASED` — no tagged release exists yet — so a commit SHA is the citable pin, not a tag):

```sh
curl -O "https://raw.githubusercontent.com/RustCrypto/hashes/6327a61bc3116ba245097ff25a79b9450f583d03/turboshake/tests/data/<file>"
```

| file | vectors (decoded) | SHA-256 |
|---|---:|---|
| `turboshake128_6.blb` | 2 | `4ac164c7c0304e1910ed771bc6aac0481f626eed34544deaeb03eb9debd77365` |
| `turboshake128_7.blb` | 10 | `ee31dee95ee7d5ec6c4d304c3193806a1196dea7f26b3db3dfe12866ce772a61` |
| `turboshake256_6.blb` | 4 | `3045c29d7726656b17cb13cef257b6ec22f0749a7f2cfe1f0576b15cb4935624` |
| `turboshake256_7.blb` | 9 | `358249455ae45d148f6e9af3d3afa64974360366bffb6b64aa24280ca49337e5` |

Each hash was reproduced by fetching the file at the pinned commit above and running
`sha256sum` — matches this directory's committed bytes exactly (0 mismatches).

## Cross-check against RFC 9861 directly (not just against RustCrypto)

RFC 9861 §5 was fetched directly (`curl https://www.rfc-editor.org/rfc/rfc9861.txt`) and the
decoded contents of these `.blb` files (via a throwaway `#[test] fn dump_vectors_for_manual_
inspection` that printed every `(input, output)` pair, deleted after use — see git history of
`tests/turboshake_blobby_kats.rs` in this session) were checked against it. Most of the vectors in
these files are NOT the handful of illustrative examples RFC 9861 §5 spells out inline (those cover
only a few `(input, D)` combinations per function); they come from the same section's broader
KAT tradition (XKCP's own TurboSHAKE/KangarooTwelve test suite, which RFC 9861 cites as the
reference implementation) and are not independently re-derivable from the short excerpt quoted in
this document. One vector, however, IS one of RFC 9861's own inline examples and was matched
byte-for-byte against the fetched RFC text:

* `TurboSHAKE256(M=`FF`, D=`06`, 64)` (RFC 9861 §5): `73 8D 7B 4E 37 D1 8B 7F 22 AD 1B 53 13 E3 57
  E3 DD 7D 07 05 6A 26 A3 03 C4 33 FA 35 33 45 52 80 F4 F5 A7 D4 F7 00 EF B4 37 FE 6D 28 14 05 E0
  7B E3 2A 0A 97 2E 22 E6 3A DC 1B 09 0D AE FE 00 4B` — decoded verbatim as vector #1 of
  `turboshake256_6.blb` (`input=[ff]`, `truncate_output=0`).

Several other decoded vectors also match RFC 9861 §5's published **KT128/KT256** examples exactly
(e.g. `turboshake128_7.blb` vector #3, `output=1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51 3c 08
03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5`, is RFC 9861's published `KT128(M=`00`^0, C=`00`^0, 32)`
value) — expected, since KT128/256 are built by calling TurboSHAKE128/256 internally with D=`06`/
`07` on the tree's encoded final node, so a KT128/256 KAT decomposes into a TurboSHAKE D=6/7 KAT on
different literal bytes than the KT-level M/C the RFC quotes. The remaining vectors were not
individually hand-matched against the RFC excerpt; their provenance rests primarily on the
byte-for-byte identity against the live, commit-pinned RustCrypto source above, which is itself
downstream of the same XKCP reference suite RFC 9861 cites.

## Format

Flat sequence of blobs read in groups of four: `(input, input_pattern_length, output,
truncate_output)`. `input_pattern_length`, when non-empty, means the real input is RFC 9861's
`ptn(n)` pattern (`00 01 02 .. F9 FA` repeated and truncated to `n` bytes) rather than a literal
byte string — this keeps large patterned inputs out of the `.blb` file. `truncate_output` lets a
vector assert a *suffix* of a long XOF stream (RFC 9861 has "last 32 bytes of a 10032-byte output"
vectors) without storing the whole stream. See `tests/turboshake_blobby_kats.rs` for the decode
logic.

## Machine-checked sidecar lines

`scripts/ci_guard_kat_provenance.py` CHECK 5 reads the lines below (binary `.blb` containers cannot
carry a `#`-comment header, so this file is the sidecar route).

- `turboshake128_6.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes commit `6327a61bc3116ba245097ff25a79b9450f583d03` `turboshake/tests/data/turboshake128_6.blb`; 2 vectors
- `turboshake128_7.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes commit `6327a61bc3116ba245097ff25a79b9450f583d03` `turboshake/tests/data/turboshake128_7.blb`; 10 vectors, includes RFC 9861 §5's published `KT128(M=`00`^0, C=`00`^0, 32)` value verbatim (vector #3)
- `turboshake256_6.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes commit `6327a61bc3116ba245097ff25a79b9450f583d03` `turboshake/tests/data/turboshake256_6.blb`; 4 vectors, includes RFC 9861 §5's published `TurboSHAKE256(M=`FF`, D=`06`, 64)` value verbatim (vector #1), matched byte-for-byte against the RFC text fetched 2026-08-09
- `turboshake256_7.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes commit `6327a61bc3116ba245097ff25a79b9450f583d03` `turboshake/tests/data/turboshake256_7.blb`; 9 vectors

## What was in these paths before, and where it went

The old (broken, 1-byte-short) copies were backed up before being overwritten, at
`scratchpad/audit-triage/blb-backup/` in the session that made this fix (not committed — that
scratchpad is throwaway). No test ever read them (confirmed: `tests/turboshake.rs`, now deleted,
contained only property tests with no `include_bytes!`), so nothing regresses by their replacement.
