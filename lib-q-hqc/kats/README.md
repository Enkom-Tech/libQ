# HQC known-answer test vectors

**`kats/official/`** — NIST `.req` seeds and `.rsp` responses for the current Oct 2024 parameter set.

See [`official/PROVENANCE.md`](official/PROVENANCE.md) for source, revision, and SHA-256 pins.

CI and `tests/nist_kem_kat.rs` gate on this tree only.

To refresh `.rsp` files from `.req` (maintainer only):

```bash
cargo test -p lib-q-hqc --release --features "alloc,hqc,random" \
  --test nist_kem_kat regenerate_official_kat_rsp_files -- --ignored
```
