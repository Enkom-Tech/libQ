# Provenance — lib-q-duplex-aead/tests/data/

## turboshake_duplex_kat_v0.json

**Origin: self-generated.** Every value in this file, including every expected output, was written
by the code under test: `lib-q-duplex-aead/examples/dump_turboshake_duplex_kat.rs`, which calls
`lib_q_duplex_aead::turboshake::{encrypt, decrypt, init_state_prefix}`. The TurboSHAKE duplex AEAD
(GIP `aead_id = 17`) is a mode assembled in this repository; there is no upstream reference
implementation and no external vector set for it, so no `upstream` origin is possible.

It is a **regression pin, not conformance evidence**: `tests/turboshake_kat.rs` shows only that the
construction still emits the bytes it emitted when the file was frozen. Its one external anchor is
the test `init_call_equals_lib_q_sha3_turboshake256`, which checks the initialization call against
lib-q-sha3's TurboSHAKE256 (itself pinned to the RFC 9861 vectors under `lib-q-sha3/tests/data`).

An independent from-scratch Python check of these vectors exists, but it is not in this repository
and is not public, so a reader of this repository cannot re-run it and it is not claimed here. If it
is vendored, this entry can move to `origin = "independent-implementation"`.

### Re-generating and comparing

The generator is deterministic (fixed keys, nonces and inputs, no RNG). From the repository root,
with the pinned toolchain in `rust-toolchain.toml` (rustc 1.99.1), workspace version 0.0.12:

```sh
cargo run -q -p lib-q-duplex-aead --example dump_turboshake_duplex_kat > /tmp/turboshake_duplex_kat_v0.json
cmp /tmp/turboshake_duplex_kat_v0.json lib-q-duplex-aead/tests/data/turboshake_duplex_kat_v0.json
python3 scripts/ci_guard_kat_provenance.py
```

`cmp` prints nothing when the bytes match; the provenance guard re-checks the pinned SHA3-256 in
`kats-manifest.toml`.

## Machine-checked sidecar lines

- `turboshake_duplex_kat_v0.json`: origin=self-generated; regression pin of the TurboSHAKE duplex AEAD (aead_id 17) written by this crate's own examples/dump_turboshake_duplex_kat.rs, not conformance evidence
