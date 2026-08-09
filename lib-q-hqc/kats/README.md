# HQC known-answer test vectors

**`kats/regression-pins/`** — NIST `.req` seeds and **self-generated** `.rsp` responses (this
crate's own keygen/encaps/decaps output, not NIST or official HQC reference data) for the current
Oct 2024 parameter set.

See [`regression-pins/PROVENANCE.md`](regression-pins/PROVENANCE.md) for source, the known
divergence from the official HQC v5.0.0 reference, and SHA-256 pins.

`tests/nist_kem_kat.rs` gates on this tree only. Passing that test proves this crate's output has
not regressed since the pin was committed; it does **not** prove conformance with the official HQC
reference implementation.

**`kats/reference-intermediates/`** — genuine **upstream** vectors: verbatim
`intermediates_values` files from the official HQC reference at
<https://gitlab.com/pqc-hqc/hqc> tag v5.0.0 (`f46e542`, 2025-08-22). Consumed by
[`tests/reference_intermediates_kat.rs`](../tests/reference_intermediates_kat.rs), which is real
external conformance evidence. See
[`reference-intermediates/PROVENANCE.md`](reference-intermediates/PROVENANCE.md) for digests, the
build recipe that reproduces them from upstream C source, and the exact scope.

Status, in one line each:

* HQC-128 keygen + encaps + decaps: **byte-exact with upstream**.
* HQC-192/256 keygen: **RED** (`OMEGA` is 103/134 vs upstream 100/131) — `#[ignore]`d with the
  first differing byte recorded.
* Upstream `PQCkemKAT_*.rsp` KEM-boundary rows: **not comparable as-is**, because
  `HqcKem::keygen_with_seed` uses `seed48[0..32]` as `seed_kem` while upstream derives
  `seed_kem = SHAKE256(seed48 || 0x00)[0..32]`. Supplied the correctly derived `seed_kem`, this
  crate reproduces upstream `.rsp` public keys byte-for-byte at HQC-128.

To refresh the self-generated `.rsp` files from `.req` (maintainer only; does not fetch or check
anything external):

```bash
cargo test -p lib-q-hqc --release --features "alloc,hqc,random" \
  --test nist_kem_kat regenerate_regression_pin_rsp_files -- --ignored
```
