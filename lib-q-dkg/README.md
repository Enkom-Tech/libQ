# lib-q-dkg (PROVISIONAL)

`lib-q-dkg` provides a dealerless distributed key generation (DKG) via a **binding** lattice
verifiable secret sharing (VSS) scheme for libQ.

- Construction style: Gennaro-style dealerless DKG; every party runs a VSS as dealer.
- Commitments: **BDLOP / Baum-style** commitments (message in the clear, statistically binding) over
  a self-contained ring \(R_q = \mathbb{Z}_q[X]/(X^{1024}+1)\), `q ≈ 2^48`.
- Soundness: the no-dealer check combines the homomorphic opening `commit(f(j)) == Σ_i jⁱ·Cᵢ` with a
  **Fiat–Shamir proof of correct sharing** that binds the share *value* — defeating the adaptive-
  dealer kernel-injection attack `f(j) + κ` (`A·κ ≡ 0`) that a bare-Ajtai commitment admits. There is
  **no `(n, t)` regime restriction**. Complaints are publicly verifiable from the commitments alone.
- Secret: the group key is **never reconstructed**; final shares are sums of qualified sub-shares;
  the verification-key set is the homomorphic sum of qualified commitments.
- Resharing is **binding-verifiable** and preserves the group secret (the group-key commitment is
  re-randomized).
- Output: `SigningShare` / `VerificationKeySet` / `KeygenSharesOutput` mirror the shapes of
  `lib-q-threshold-sig` (`share_bytes` carry `R_q`/`Z_q` encodings).
- Wire format (`dkg` v1): `[ver=1][profile=1] …` length-prefixed, budget-gated.

## Profile

`DkgProfileV1`: `id = 1`, `max_parties = 16`. Commitment geometry (`lattice::bdlop`):
`MU = 6`, `KAPPA = 9`, challenge weight `τ = 22`. Statistically binding (≈7.0-bit GH margin,
~2⁻⁶⁴⁵⁰⁰ failure); Module-LWE hiding **186-bit classical / 169-bit quantum core-SVP** (β = 636 from
malb's lattice-estimator — the gate; `KAPPA` was 8 but the estimator gave only 98-bit quantum there,
so it was raised to 9. See `lib-q-threshold-raccoon/SECURITY_ANALYSIS.md` §6).

## Validation

Tests carry per-share Fiat–Shamir proofs (Gaussian masking over `N = 1024`) — run them in
**release** (debug is far too slow; CI runs this crate only under `release-ci`):

```bash
cargo test -p lib-q-dkg --release
```

## KAT export

Schema: `dkg-kat-v1`

```bash
cargo test -p lib-q-dkg --release kat_regenerate_vectors -- --ignored
```

Output: `tests/vectors/dkg-v1.json`

## WASM

The `wasm` feature exposes a minimal JS surface (`@lib-q/dkg`): `dkgSetup`, `dkgKeygen(parties,
threshold)`, and `dkgDecodeRound1(bytes)`. Build/test:

```bash
cargo build -p lib-q-dkg --features wasm --target wasm32-unknown-unknown
wasm-pack test --node -- --features wasm,std,random --test wasm_smoke   # in lib-q-dkg/
```

## Fuzzing

`cargo-fuzz` harnesses for the untrusted wire decoders live in `fuzz/`:

```bash
cargo +nightly fuzz run dkg_round1_decode      # in lib-q-dkg/
cargo +nightly fuzz run dkg_complaint_decode
```

## Status

This crate is **PROVISIONAL** and intended for controlled evaluation. Lattice threshold VSS is
nascent; see `dev/conformance/integration/lib-q-dkg/LIBQ_API.md` for the scheme choice, the binding
argument, and the assumptions surfaced for RED-zone review. It is a pre-standard implementation
intended for integration and protocol testing, not final production standardization.
