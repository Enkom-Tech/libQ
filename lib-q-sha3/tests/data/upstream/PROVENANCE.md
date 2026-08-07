# Vendored upstream KAT vectors — `lib-q-sha3`

These `.blb` files are **byte-for-byte copies** of RustCrypto's `sha3` crate test data. They are
not regenerated, converted, filtered or re-encoded here — self-generated "reference" vectors prove
only that an implementation agrees with itself, so the bytes are copied verbatim and the copy is
checkable with `sha256sum`.

Container format: [`blobby`](https://crates.io/crates/blobby) 0.4 (workspace pin). Each file is a
flat sequence of blobs read pairwise as `(input, expected_output)`. For the SHAKE files the
expected blob is 512 bytes, i.e. the XOF output length to squeeze.

## Source and digests

Fetch (reproduces these bytes exactly):

```sh
curl -O "https://raw.githubusercontent.com/RustCrypto/hashes/<tag>/sha3/tests/data/<file>"
```

| file | upstream tag | bytes | vectors | SHA-256 |
|---|---|---:|---:|---|
| `sha3_224_kat.blb` | `sha3-v0.12.0` | 40515 | 256 | `15c5c56e597990fcd42002bc9e00a779411a0930451c3141fa0f0bc5d23a122d` |
| `sha3_256_kat.blb` | `sha3-v0.12.0` | 41539 | 256 | `89571bf7ada95c79ca4832b219adcbaebe50cd0369011051a702888a2efa6175` |
| `sha3_384_kat.blb` | `sha3-v0.12.0` | 45585 | 255 | `77022fe9c6d4626b81daecb3eca8fd6937ac0b0a78f4abd31c6a26df9b9b88a5` |
| `sha3_512_kat.blb` | `sha3-v0.12.0` | 49920 | 255 | `8a919debbb6e573fe3578b03558ed5bd4e0c23179a33307f996511df6224bea7` |
| `shake128_kat.blb` | `sha3-v0.11.0` | 164675 | 256 | `875951365a5b1c5599013983e5cad8fb61b2c748960b7bb1cbb0df52188c458a` |
| `shake256_kat.blb` | `sha3-v0.11.0` | 164675 | 256 | `2e9b66b25a20b45aea5525a8e0f57812a77101794aa70c45bebfdfa5a523c777` |

The SHAKE files are taken from `sha3-v0.11.0` because upstream moved SHAKE out of the `sha3` crate
afterwards and deleted the data files; `sha3-v0.12.0` has no `shake*_kat.blb`. The four SHA-3 files
are byte-identical across `sha3-v0.11.0-rc.9`, `sha3-v0.11.0` and `sha3-v0.12.0`.

Upstream does not document where its own SHA-3/SHAKE vectors came from (its `tests/mod.rs` cites a
source only for the Keccak files). Rather than take them on faith, every vector was re-derived
independently before being vendored — see below.

## Independent cross-check (2026-08-07)

Each `(input, expected)` pair was recomputed with a Keccak-f[1600] implementation that shares no
code with lib-Q or with RustCrypto, and the reference itself was validated first:

* SHA-3 / SHAKE outputs were checked against OpenSSL via Python `hashlib`
  (`sha3_224/256/384/512`, `shake_128/256`) — 36 comparisons across message lengths
  0, 1, 3, 71, 72, 135, 136, 200, 1000 bytes, 0 mismatches;
* a negative control confirmed the comparison can fail (a Keccak-padded sponge does **not** equal
  `hashlib.sha3_256("")`), and flipping one nibble of a vendored vector was correctly reported as
  a mismatch.

Result over the vendored files — every vector agreed:

| file | vectors | agree | mismatch |
|---|---:|---:|---:|
| `sha3_224_kat.blb` | 256 | 256 | 0 |
| `sha3_256_kat.blb` | 256 | 256 | 0 |
| `sha3_384_kat.blb` | 255 | 255 | 0 |
| `sha3_512_kat.blb` | 255 | 255 | 0 |
| `shake128_kat.blb` | 256 | 256 | 0 |
| `shake256_kat.blb` | 256 | 256 | 0 |

## Machine-checked sidecar lines

`scripts/ci_guard_kat_provenance.py` CHECK 5 reads the lines below. A `.blb` is a binary container
and cannot carry a leading `#`-comment header, so this sidecar is the route by which these files
declare their provenance. Keep exactly one line per file; the guard checks it in both directions.

- `sha3_224_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/sha3_224_kat.blb`; 256 vectors, all independently recomputed against OpenSSL `hashlib.sha3_224` (0 mismatches, 2026-08-07)
- `sha3_256_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/sha3_256_kat.blb`; 256 vectors, all independently recomputed against OpenSSL `hashlib.sha3_256` (0 mismatches, 2026-08-07)
- `sha3_384_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/sha3_384_kat.blb`; 255 vectors, all independently recomputed against OpenSSL `hashlib.sha3_384` (0 mismatches, 2026-08-07)
- `sha3_512_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/sha3_512_kat.blb`; 255 vectors, all independently recomputed against OpenSSL `hashlib.sha3_512` (0 mismatches, 2026-08-07)
- `shake128_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.11.0` `sha3/tests/data/shake128_kat.blb` (deleted upstream after 0.11); 256 vectors of 512-byte XOF output, all recomputed against OpenSSL `hashlib.shake_128` (0 mismatches, 2026-08-07)
- `shake256_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.11.0` `sha3/tests/data/shake256_kat.blb` (deleted upstream after 0.11); 256 vectors of 512-byte XOF output, all recomputed against OpenSSL `hashlib.shake_256` (0 mismatches, 2026-08-07)

## Why `../*.blb` is still kept and run

The curated files one directory up hold exactly two vectors each — `("", H(""))` and
`("abc", H("abc"))`, the FIPS 202 worked examples. That is **deliberate, and it is not a subset of
the files here**: the upstream SHA3-384 and SHA3-512 files contain no empty-input vector at all
(their first input is `cc`), and no upstream file contains `"abc"`. Dropping the curated set would
lose coverage, so both sets run.

## Not covered here

`cshake128.blb`, `cshake256.blb`, `cshake*_bytepad_block_aligned.blb` and the `turboshake*.blb`
files in the parent directory are **not** from this upstream source and are out of scope for this
document. The `turboshake*.blb` files do not decode under `blobby` 0.4 and no test references
them; `sha3_224_kat_new.blb` decodes to the same two vectors as `sha3_224_kat.blb` and is also
referenced by no test.
