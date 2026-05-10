# Design: `lib-q-prf`

## Role

`lib-q-prf` isolates **large-prime field** arithmetic and PRF semantics from the ML-DSA module ring \(R_q=\mathbb{Z}_q[X]/(X^{256}+1)\) in [`lib-q-ring`](../lib-q-ring/). DualRing-PRF-style protocols need \(\mathbb{F}_p\) with \(|p|\approx 2^{256}\)–\(2^{512}\); that domain is implemented here with `crypto_bigint::modular::FixedMontyForm` and `MontyParams<U256>` / `MontyParams<U512>` (constructed via `MontyParams::new_vartime` from the odd pilot moduli in [`params.rs`](src/params.rs)).

## Parameters

Two **pilot** profiles ship as constants in [`src/params.rs`](src/params.rs):

- **256-bit wire (`U256`):** 255-bit safe prime \(p=2q+1\), \(q\) prime.
- **512-bit wire (`U512`):** 511-bit safe prime.

Each modulus documents **provenance** (OpenSSL `prime -generate -safe`, SymPy `isprime` cross-check, bit length, big-endian hex). CI loads [`tests/reference_vectors.txt`](tests/reference_vectors.txt), including `SHA256_P*_LE` digests of the little-endian modulus encodings, so accidental edits to `p` are detected.

**Gold exponent:** for these safe primes, \(p-1=2q\) with odd \(q\), so the pilot sets \(g=q=(p-1)/2\), an odd divisor of \(p-1\) suitable for the power-residue construction.

## Legendre PRF caveat (extension fields)

Recent analysis shows **degree-1 Legendre PRFs over extension fields \(\mathbb{F}_{p^r}\)** are not fit for purpose under standard passive/active models; higher-degree variants are required there. This crate evaluates the **prime field** \(\mathbb{F}_p\) only, which is outside that attack class. Any future extension-field parameterisation would need a separate security review.

## Constant-time posture

- Secret-dependent work uses `FixedMontyForm` / `crypto_bigint::CtEq` for field steps; Legendre symbol mapping into \(\{-1,0,1\}\) bridges `crypto_bigint::Choice` into `subtle::Choice` for `ConditionallySelectable` on `i8`.
- Modular exponentiation may leak **exponent bit length** through timing (documented upstream); exponents used here are derived from public parameters \((p-1)/2\) or public challenge-derived inputs in composed protocols.

## References

- DualRing-PRF (QROM ring signatures using PRF linkage) — composed in [`lib-q-ring-sig`](../lib-q-ring-sig/) behind `dualring-prf`.
- Gold / power-residue OPRF literature (e.g. VOLE-based two-party evaluation) is relevant for **oblivious** evaluation, not implemented here.
