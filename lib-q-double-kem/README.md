# lib-q-double-kem (PROVISIONAL)

`lib-q-double-kem` provides a provisional MAUL v1 profile for combining two ML-KEM-768
encapsulation lanes into a single upgraded shared secret.

## Status

- **Provisional research profile** for Hint-MLWE style wire-constrained transport.
- The API and wire layout can evolve before standardization.

## Wire profile

- Baseline size for two ML-KEM-768 ciphertexts: `2176` bytes (`2 x 1088`).
- MAUL v1 target wire budget: `1260` bytes.
- Fixed wire split:
  - `hint`: `172` bytes
  - `body`: `1088` bytes

## Core API

- `MaulProfileV1`
- `double_encap`
- `double_decap`
- `ck_fo_upgrade`

## Shared secret derivation

The final shared secret is derived as:

`ss = KDF(ss_a || ss_b)`

with a domain-separated SHA3-256 based KDF.

## Security notes

- This profile is intended for controlled environments and deterministic testability.
- Production integrations must review threat model fit, replay constraints, and profile governance.
