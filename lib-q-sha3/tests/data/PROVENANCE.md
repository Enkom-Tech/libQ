# Provenance — lib-q-sha3/tests/data/*.blb (curated, NOT the upstream/ or turboshake/ subdirs)

This document covers only the `.blb` files sitting directly in this directory (the "curated" set
referenced by `upstream/PROVENANCE.md`'s "Why `../*.blb` is still kept and run" section). The
`upstream/` and `turboshake/` subdirectories have their own PROVENANCE.md and are NOT covered
here.

Each curated `sha3_*_kat.blb` / `shake*_kat.blb` file holds exactly two vectors —
`("", H(""))` and `("abc", H("abc"))`, the FIPS 202 worked examples — encoded as a `blobby` 0.4
container. `upstream/PROVENANCE.md` explains why both the curated and the upstream sets are kept
(neither is a subset of the other). No external source is cited anywhere in this repo for these
specific curated files; they are treated as self-generated pending a better source. The `cshake*`
files are likewise self-generated cSHAKE/bytepad test containers with no cited external source.

DEAD VECTOR: `sha3_224_kat_new.blb` decodes to the same two vectors as `sha3_224_kat.blb` and is
referenced by NO test in `lib-q-sha3/tests/` (`grep -rl sha3_224_kat_new lib-q-sha3/tests/*.rs`
found zero files, 2026-08-09) — flagged, not deleted, per the card's "do not delete" instruction.

## Machine-checked sidecar lines

- `sha3_224_kat.blb`: origin=self-generated; FIPS 202 worked-example pair ("", H("")) and ("abc", H("abc")) in a blobby container, no external source cited
- `sha3_224_kat_new.blb`: origin=self-generated; decodes to the same two FIPS 202 vectors as sha3_224_kat.blb; referenced by no test in this crate as of 2026-08-09
- `sha3_256_kat.blb`: origin=self-generated; FIPS 202 worked-example pair ("", H("")) and ("abc", H("abc")) in a blobby container, no external source cited
- `sha3_384_kat.blb`: origin=self-generated; FIPS 202 worked-example pair ("", H("")) and ("abc", H("abc")) in a blobby container, no external source cited
- `sha3_512_kat.blb`: origin=self-generated; FIPS 202 worked-example pair ("", H("")) and ("abc", H("abc")) in a blobby container, no external source cited
- `shake128_kat.blb`: origin=self-generated; FIPS 202 worked-example pair ("", H("")) and ("abc", H("abc")) in a blobby container, no external source cited
- `shake256_kat.blb`: origin=self-generated; FIPS 202 worked-example pair ("", H("")) and ("abc", H("abc")) in a blobby container, no external source cited
- `cshake128.blb`: origin=self-generated; cSHAKE128 test vectors in a blobby container, no external source cited
- `cshake128_bytepad_block_aligned.blb`: origin=self-generated; cSHAKE128 bytepad-block-aligned edge-case vectors in a blobby container, no external source cited
- `cshake256.blb`: origin=self-generated; cSHAKE256 test vectors in a blobby container, no external source cited
- `cshake256_bytepad_block_aligned.blb`: origin=self-generated; cSHAKE256 bytepad-block-aligned edge-case vectors in a blobby container, no external source cited
