# lib-q-ring-sig

Federation-style **ring openings** over a shared Ajtai commitment reference string (CRS) from [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/). Each issuer holds an opening witness; a “ring signature” is a standard Schnorr-style opening proof whose Fiat–Shamir transcript binds the ordered list of member commitments and an application message.

## Scope

- **Implemented**: `sign_federation_message`, `verify_federation_opening`, linear-scan verification `verify_federation_opening_scan`, [`sign_dualring_lb`](src/dualring_lb.rs) / [`verify_dualring_lb`](src/dualring_lb.rs), and [`credential`](src/credential.rs) binding of attribute openings to DualRing-LB–style proofs (legacy federation-only path: `federation-opening` feature).
- **Optional (`dualring-prf` feature)**: experimental **DualRing-PRF** pilot transcript using Legendre and Gold PRFs from [`lib-q-prf`](../lib-q-prf/). See [`dualring_prf`](src/dualring_prf.rs) and [DESIGN.md](DESIGN.md#dualring-prf-optional-dualring-prf).
- **Paper gap**: The CCS 2021 **aggregated** DualRing-LB verification equation (single linked check) is not implemented; the shipped pilot is timing-hardened federation openings. See [DESIGN.md](DESIGN.md).

## Dependencies

- `lib-q-lattice-zkp` — commitments, opening proofs, `leaf_hash`.
- `lib-q-sha3` — ring digest.
- `lib-q-ring` — field/module types re-exported through lattice ZKP.
- `lib-q-prf` (optional) — large-field Legendre / Gold PRFs when `dualring-prf` is enabled.

## Algorithm registry

`Algorithm::LatticeRingSignature` and `Algorithm::LatticeDualRingLb` in [`lib-q-types`](../lib-q-types/) label protocol identifiers for policy and documentation; they are not `lib-q-core` KEM/signature providers.
