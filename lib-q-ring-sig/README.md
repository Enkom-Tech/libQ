# lib-q-ring-sig

Federation-style **ring openings** over a shared Ajtai commitment reference string (CRS) from [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/). Each issuer holds an opening witness; a “ring signature” is a standard Schnorr-style opening proof whose Fiat–Shamir transcript binds the ordered list of member commitments and an application message.

## Scope

- **Implemented**: `sign_federation_message`, `verify_federation_opening`, linear-scan verification `verify_federation_opening_scan`, [`sign_dualring_lb`](src/dualring_lb.rs) / [`verify_dualring_lb`](src/dualring_lb.rs), and [`credential`](src/credential.rs) binding of attribute openings to DualRing-LB–style proofs (legacy federation-only path: `federation-opening` feature).
- **Optional (`pilot-insecure-prf-transcript` feature)**: laboratory Fiat–Shamir transcript over Legendre and Gold PRFs from [`lib-q-prf`](../lib-q-prf/). **Not** a ring signature: the verifier model includes every member’s PRF secrets in the ring vector. See [`pilot_insecure_prf_transcript`](src/pilot_insecure_prf_transcript.rs) and [DESIGN.md](DESIGN.md#prf-laboratory-transcript-pilot-insecure-prf-transcript).
- **Paper note**: The CCS 2021 construction uses a mod-3 challenge group; this stack uses ML-DSA–style sparse-ball challenges for the hashed aggregate `c = H(ctx ‖ R)` only (see [`dualring_lb`](src/dualring_lb.rs) module docs).

## Dependencies

- `lib-q-lattice-zkp` — commitments, opening proofs, `leaf_hash`.
- `lib-q-sha3` — ring digest.
- `lib-q-ring` — field/module types re-exported through lattice ZKP.
- `lib-q-prf` (optional) — large-field Legendre / Gold PRFs when `pilot-insecure-prf-transcript` is enabled.

## Algorithm registry

`Algorithm::LatticeRingSignature` and `Algorithm::LatticeDualRingLb` in [`lib-q-types`](../lib-q-types/) label protocol identifiers for policy and documentation; they are not `lib-q-core` KEM/signature providers.
