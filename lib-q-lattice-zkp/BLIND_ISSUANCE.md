# Lattice blind issuance (wire v0)

This document specifies blind issuance for BLNS-style credentials on top of Ajtai commitments and QROM Fiat–Shamir opening proofs in this crate. Shared-CRS pilot issuance is **non-conformant** on wire v0.

## Security goals

- **Blindness**: The issuer learns no function of the user’s token descriptor beyond what is implied by a single public commitment `Com_blinded` under the issuer matrix `A_issuer`.
- **One-more unforgeability (v0)**: Forging a valid attestation without the issuer opening reduces to **Module-SIS / opening soundness** on `A_issuer` in the QROM (committed-first-message Fiat–Shamir).

## Issuer-keyed model (v0)

v0 uses **issuer-keyed** commitments (shared-CRS pilot retired). Each issuer publishes:

| Field | Semantics |
|-------|-----------|
| `issuer_matrix_seed` | 32-byte seed expanding `A_issuer` |
| `issuer_params_digest` | `SHAKE256("lattice-zkp/issuer-params/v0" ‖ seed ‖ profile_id)` on wire kind `0x08` |
| Issuer secret | `AjtaiOpening` under `A_issuer` |
| Issuer public | `commit(A_issuer, sk)` |

[`BlindIssuerKeypair::sample_issuer_keyed`](src/blind.rs) samples the issuer opening under [`IssuerCommitmentParams`](src/blind.rs).

### Fiat–Shamir binding

Issuer attestations absorb:

- `BLIND_ISSUER_FS_LABEL` = `blind-issuer-v1`
- blinded commitment wire bytes
- issuer public commitment wire bytes (message path)
- [`blind_message_digest`](src/blind.rs) = `SHAKE256("lattice-zkp/blind-msg/v1" ‖ len ‖ message)`

### Blindness

User blinding randomness is uniform and independent. The issuer sees only `Com_blinded = commit(user + blind)` under `A_issuer`, which is computationally indistinguishable from a random commitment image under Module-LWE hiding for suitable parameters.

### Wire kind `0x08`

[`encode_blind_issuance_v0`](src/wire/v0.rs) body prefix:

`issuer_params_digest (32) ‖ blinded_commitment_digest (32) ‖ issuer_com ‖ opening_proof`

[`blinded_commitment_digest`](src/blind.rs) = `SHAKE256("lattice-zkp/blinded-com/v0" ‖ commitment_wire)`.

## Implemented API (`src/blind.rs`)

- [`IssuerCommitmentParams`](src/blind.rs) — issuer matrix family
- [`BlindIssuance`](src/blind.rs) — `request` / `issuer_sign` / `issuer_sign_message` / `finalize` / `verify` / `verify_message`
- [`BlindSignature`](src/blind.rs) on [`UnblindedBlindSignature`](src/blind.rs)

## Prover secret hygiene

See [`DESIGN.md`](DESIGN.md) §11 and [`src/sigma/secrets.rs`](src/sigma/secrets.rs). [`BlindUserState`](src/blind.rs) scrubs blind/user openings on drop unless consumed by [`BlindIssuance::finalize`](src/blind.rs).
