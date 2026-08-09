# Provenance — lib-q-keccak-digest/tests/data/*.blb (curated, NOT the upstream/ subdir)

This document covers only the `.blb` files sitting directly in this directory. The `upstream/`
subdirectory has its own PROVENANCE.md and is NOT covered here.

Each curated file holds exactly two vectors — `("", H(""))` and `("abc", H("abc"))`, per
`upstream/PROVENANCE.md`'s "Why `../*.blb` is still kept and run" section (neither set is a subset
of the other). No external source is cited anywhere in this repo for these specific curated files;
treated as self-generated pending a better source.

## Machine-checked sidecar lines

- `keccak_224_kat.blb`: origin=self-generated; two-vector FIPS-202-style worked-example pair in a blobby container, no external source cited
- `keccak_256_kat.blb`: origin=self-generated; two-vector FIPS-202-style worked-example pair in a blobby container, no external source cited
- `keccak_384_kat.blb`: origin=self-generated; two-vector FIPS-202-style worked-example pair in a blobby container, no external source cited
- `keccak_512_kat.blb`: origin=self-generated; two-vector FIPS-202-style worked-example pair in a blobby container, no external source cited
- `keccak_256_full_kat.blb`: origin=self-generated; two-vector FIPS-202-style worked-example pair in a blobby container, no external source cited
