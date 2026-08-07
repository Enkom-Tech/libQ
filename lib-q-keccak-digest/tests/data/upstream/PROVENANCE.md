# Vendored upstream KAT vectors — `lib-q-keccak-digest`

These `.blb` files are **byte-for-byte copies** of RustCrypto's `sha3` crate test data. They are
not regenerated, converted or re-encoded here; the copy is checkable with `sha256sum`.

Container format: [`blobby`](https://crates.io/crates/blobby) 0.4 (workspace pin), read pairwise as
`(input, expected_output)`.

## Source and digests

```sh
curl -O "https://raw.githubusercontent.com/RustCrypto/hashes/sha3-v0.12.0/sha3/tests/data/<file>"
```

| file | bytes | vectors | SHA-256 |
|---|---:|---:|---|
| `keccak_224_kat.blb` | 32 | 1 | `27900b7a286f8c10b9864af580c1c0ba57497d40d04aeed0ae842b5016519efa` |
| `keccak_256_kat.blb` | 170 | 3 | `fcdf47d6eb63ea44a07290da6fe913fc0220c7747ec7fc9d20dc68453ca8d823` |
| `keccak_384_kat.blb` | 52 | 1 | `82fbc8c49b7ab763033dad0fa0766042e19df5f3d1987e3b203b678efa03ff4e` |
| `keccak_512_kat.blb` | 69 | 1 | `81066e66b59e94d912648ab10c67c9d617bf978b1af3379435c33dec5dd1ff68` |
| `keccak_256_full_kat.blb` | 3404 | 14 | `ca0277744e6fad742cedfa49f2704cc627571d4b38a6ba9a9f1016e6914eeab6` |

Upstream's `sha3/tests/mod.rs` attributes its Keccak vectors to
<https://github.com/kazcw/yellowsun/blob/test-keccak/src/lib.rs#L171>.

## Independent cross-check (2026-08-07)

Every pair was recomputed with a Keccak-f[1600] implementation sharing no code with lib-Q or
RustCrypto. That reference was validated first against OpenSSL (`hashlib`) on the SHA-3 padding
(36 comparisons, 0 mismatches) and reproduces the canonical original-padding values
`keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` and
`keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45`; a negative
control confirmed the comparison can fail.

| file | vectors | agree | mismatch |
|---|---:|---:|---:|
| `keccak_224_kat.blb` | 1 | 1 | 0 |
| `keccak_256_kat.blb` | 3 | 3 | 0 |
| `keccak_384_kat.blb` | 1 | 1 | 0 |
| `keccak_512_kat.blb` | 1 | 1 | 0 |
| `keccak_256_full_kat.blb` | 14 | 14 | 0 |

## Machine-checked sidecar lines

`scripts/ci_guard_kat_provenance.py` CHECK 5 reads the lines below. A `.blb` is a binary container
and cannot carry a leading `#`-comment header, so this sidecar is the route by which these files
declare their provenance. Keep exactly one line per file; the guard checks it in both directions.

- `keccak_224_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/keccak_224_kat.blb`; 1 vector, independently recomputed with a from-scratch Keccak-f[1600] reference (0 mismatches, 2026-08-07)
- `keccak_256_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/keccak_256_kat.blb`; 3 vectors, independently recomputed with a from-scratch Keccak-f[1600] reference (0 mismatches, 2026-08-07)
- `keccak_384_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/keccak_384_kat.blb`; 1 vector, independently recomputed with a from-scratch Keccak-f[1600] reference (0 mismatches, 2026-08-07)
- `keccak_512_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/keccak_512_kat.blb`; 1 vector, independently recomputed with a from-scratch Keccak-f[1600] reference (0 mismatches, 2026-08-07)
- `keccak_256_full_kat.blb`: origin=upstream; byte-for-byte copy of RustCrypto/hashes `sha3-v0.12.0` `sha3/tests/data/keccak_256_full_kat.blb`; 14 vectors of the full 200-byte state, independently recomputed with a from-scratch Keccak-f[1600] reference (0 mismatches, 2026-08-07)

## Why `../*.blb` is still kept and run

The curated files one directory up hold exactly two vectors each — `("", H(""))` and
`("abc", H("abc"))`. That is **deliberate, and not a subset of the files here**: no upstream file
contains `"abc"`, and `keccak_256_full_kat.blb` upstream contains no empty-input vector. Upstream's
Keccak-224/384/512 files in turn hold only the empty-input vector, which the curated files already
cover — they are vendored anyway so the full upstream set is present and hash-checkable in one
place.
