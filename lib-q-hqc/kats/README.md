# HQC known-answer test vectors

**`kats/regression-pins/`** — NIST `.req` seeds and **self-generated** `.rsp` responses (this
crate's own keygen/encaps/decaps output, not NIST or official HQC reference data) for the current
Oct 2024 parameter set.

See [`regression-pins/PROVENANCE.md`](regression-pins/PROVENANCE.md) for source, the known
divergence from the official HQC v5.0.0 reference, and SHA-256 pins.

CI and `tests/nist_kem_kat.rs` gate on this tree only. Passing that test proves this crate's
output has not regressed since the pin was committed; it does **not** prove conformance with the
official HQC reference implementation. A genuine upstream comparison exists locally
(`reference/hqc/kats/ref/`, untracked, not run in CI) and currently shows a divergence — see
`regression-pins/PROVENANCE.md`.

To refresh the self-generated `.rsp` files from `.req` (maintainer only; does not fetch or check
anything external):

```bash
cargo test -p lib-q-hqc --release --features "alloc,hqc,random" \
  --test nist_kem_kat regenerate_regression_pin_rsp_files -- --ignored
```
