# lib-q-lattice-zkp

Research-facing crate boundary for **module-lattice** anonymous-credential machinery (BLNS-style constructions). The STARK stack in `lib-q-zkp` is intentionally not reused here: algebraic lattice relations are not economically expressed as bitwise AIR constraints.

## Intended cryptographic core

1. **Ajtai-style commitment** over a module ring: `Com(m; r) = A·r + m (mod q)` with public module-SIS matrix `A`.
2. **Sigma protocols** for linear relations in the NTT domain (openings, norm bounds compatible with ML-DSA coefficient geometry).
3. **Challenge distribution** aligned with FIPS 204 ternary challenges for cross-protocol composition.
4. **Amortisation** interface for batched credential shows (BLNS aggregation layer).

## Status

The crate ships a `no_std`+`alloc` core: Ajtai commitment over the [`lib-q-ring`](../lib-q-ring) workspace crate (Rust package name `lib_q_ring`), ML-DSA–compatible sparse challenges, Fiat–Shamir opening proofs, linear and infinity-norm verification hooks, and a BLNS-style batch transcript plus `aggregate_proofs`. **Blind issuance** (`blind::BlindIssuance`) includes a pilot issuer-keyed transcript (`BlindIssuerKeypair`, `BlindSignature`); **anonymous tokens** (`token`); **commitment and witness nullifier** openings (`sigma/uniqueness`); **hierarchical and private Merkle membership** pilots (`sigma/hierarchical`); all build on the same CRS. Unit tests live in `src/lib.rs`; optional fuzzing is under [`fuzz/`](fuzz/README.md).

For protocol-level notes (parameters, proof goals, amortisation order), see [`DESIGN.md`](DESIGN.md).
