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
* HQC-192/256 keygen: **byte-exact with upstream** (fixed 2026-08-09, card t_71d4f79a — `OMEGA`/
  `OMEGA_R` were 103/115/134 vs upstream 100/114/131; corrected).
* Upstream `PQCkemKAT_*.rsp` KEM-boundary rows: **not comparable as-is**, because
  `HqcKem::keygen_with_seed` uses `seed48[0..32]` as `seed_kem` while upstream derives
  `seed_kem = SHAKE256(seed48 || 0x00)[0..32]`. Supplied the correctly derived `seed_kem`, this
  crate reproduces upstream `.rsp` public keys byte-for-byte at HQC-128.

## Do not use `reference/` as an oracle

There may be a `reference/hqc/` tree on your machine. It is a **local checkout, git-ignored**
(`.gitignore:236 /reference`), at **whatever revision happened to be fetched**. It is not
authoritative and must never be used to decide whether this crate is correct.

This is not hypothetical. On 2026-08-10 an agent compared against
`reference/hqc/kats/ref/hqc-*/intermediates_values`, concluded the fixed-weight sampler had three
bugs, "fixed" them, regenerated the pins to match, and pushed a wire-breaking change to a
published crate. The implementation had been byte-exact all along. The local checkout was a
**later revision than the pinned v5.0.0 target**: its dumps have identical file sizes and
different contents from `reference-intermediates/`. Reverted at `910c644` / `57a39cb` / `614bdfd`;
see card `t_62273504` (closed PREMISE-WRONG).

The authoritative vectors are the ones vendored **in this directory**, with sha256 digests
recorded in the repo-root `kats-manifest.toml` and enforced by
`scripts/ci_guard_kat_provenance.py`. If you need a different upstream revision, vendor it here
with its digests and say so; do not point a test at `reference/`.

Two things that would have caught that mistake in one command each, worth doing in this order
before concluding this crate is non-conformant:

```bash
# 1. An external oracle already exists. Run it FIRST. If it is green, your premise is wrong.
cargo test -p lib-q-hqc --features "alloc,hqc,random" --test reference_intermediates_kat

# 2. Read the count. A bare `cargo test -p lib-q-hqc` runs NEITHER this suite nor nist_kem_kat:
#    both are `[[test]]` entries with `required-features`, and `hqc` is not a default feature,
#    so without the features they compile to nothing and the run still prints "ok".
```

To refresh the self-generated `.rsp` files from `.req` (maintainer only; does not fetch or check
anything external):

```bash
cargo test -p lib-q-hqc --release --features "alloc,hqc,random" \
  --test nist_kem_kat regenerate_regression_pin_rsp_files -- --ignored
```
