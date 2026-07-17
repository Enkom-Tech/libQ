# lib-q-blind-token (PROVISIONAL)

`lib-q-blind-token` provides a post-quantum **unlinkable** blind token (the Privacy-Pass primitive
slot) for libQ.

- Construction: an **unlinkable lattice blind token** (keyed-verification anonymous-credential
  style, Agrawal et al. CCS'22). The issuer holds a Micciancio–Peikert **gadget trapdoor** for a
  matrix `A` and issues a **GPV preimage** credential `x` on a hidden attribute `a_tok`
  (`A·x = d·a_tok + d0`). Redemption is a **fresh, re-randomized zero-knowledge proof of
  possession** (Lyubashevsky FS-with-aborts) — so redemptions are unlinkable to issuances and to
  each other. Explicitly **not** the forbidden classical 2HashDH VOPRF or RSA blind signature.
- Operations: `blind` → `blind_sign` → `unblind` (→ credential) → `redeem` (→ token bytes) →
  `verify`. The redeemable token is a ZK proof; its bytes vary per redemption by design.
- Parameterization: `issuer_key_id` selects the issuer key; `(issuer_key_id, epoch)` is the
  anonymity-set label.
- Wire format (`blind-token` v1, profile 2): `[ver=1][profile=2] framed(w_commit) framed(z)`,
  budget-gated. Profile 2 is the `q ≈ 2^51` / 7-bytes-per-coefficient parameterization (128-bit
  quantum); it is wire-incompatible with the retired profile-1 (`q ≈ 2^48`) tokens.
- The API is **std-gated** (the Gaussian samplers need `f64`).

## Status & security caveat

This crate is **PROVISIONAL** and **research-grade**. The construction and its statistical
properties are implemented and validated (exact GPV preimages, spherical/trapdoor-hiding sampler,
zero-knowledge / unlinkability experiment — see the test suite). It uses a **self-contained ring**
(`N = 1024`, `q ≈ 2^51`) whose parameters were **selected against a BKZ core-SVP cost model** to
reach ≈143-bit classical / ≈130-bit quantum Module-SIS (binding / one-more-unforgeability, BKZ-491),
`τ = 16` (≈128-bit knowledge soundness), with the trapdoor hidden **statistically** (`m̄ = 18`, no
Module-LWE assumption). This is the profile-2 raise from the earlier `q ≈ 2^48` instance (≈131-bit
classical / ≈119-bit quantum), which cleared classical but sat under a 128-bit **quantum** floor.
Consequence: keys/tokens are large (public key ≈ 483 KB, token ≈ 497 KB — up from ≈396/≈408 KB). The
security level is a cost-model **estimate**, not a proof, but it is **cross-checked against the
`malb/lattice-estimator`** (SageMath), which independently returns BKZ blocksize `b = 491` → 143-bit
classical / 130-bit quantum, matching the hand derivation to <1 bit; the quantum core-SVP margin
clears 128-bit (≈130-bit, ~2 bits of headroom). The small-width, secret-bearing samplers (trapdoor,
attribute, gadget coset, perturbation rounding) are now **isochronous** (constant-time in the secret
center/output) via `lattice::gaussian_ct` (reverse-CDT base + branchless `BerExp`, HPRR/Falcon
style); residual `f64`/FFT micro-architectural timing is not audited (see §7). See
`dev/conformance/integration/lib-q-blind-token/LIBQ_API.md` §3/§7 for the full derivation and caveat
list. Not load-bearing; for integration / protocol testing only.

## Validation

The hard cryptographic core is checked by hard assertions and statistical validators:

- `lattice::gadget` — exact gadget decomposition and `g·z ≡ u` coset sampling.
- `lattice::trapdoor` — exact identity `A·[R;I] = G`, exact preimages `A·x = u`, and the
  spherical-covariance test (`preimage_covariance_is_spherical`, `--ignored` / release).
- `lattice::scheme` — redeem/verify correctness, freshness, and the `unlinkability_experiment`
  (`--ignored` / release).

```bash
# correctness tests — run in release: keygen does heavy f64 + millions of RNG draws, so an
# unoptimized (debug) build takes minutes per keygen. CI runs this crate under `release-ci`.
cargo test --release -p lib-q-blind-token
# statistical validators (spherical sampler, unlinkability experiment, Gaussian moments)
cargo test --release -p lib-q-blind-token -- --ignored
```

## KAT export

Schema: `blind-token-kat-v2` (profile-2 / `q ≈ 2^51` parameterization)

```bash
cargo test -p lib-q-blind-token kat_regenerate_vectors -- --ignored
```

Output: `tests/vectors/blind-token-v2.json` (a sample redeemed token; bytes are RNG-seeded since
tokens are re-randomized proofs).
