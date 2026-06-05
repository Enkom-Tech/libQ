# lib-q-threshold-kem (PROVISIONAL)

`lib-q-threshold-kem` is a provisional threshold KEM construction for libQ.

- Group encapsulation uses **ML-KEM-768**.
- Secret sharing uses byte-wise **Shamir shares over GF(256)**.
- Partial decapsulation shares are bound to ciphertext and verifier commitments.
- Wire format is `threshold_kem_wire_v1`:
  `[ver=1][profile=1][ct_len u32 LE][ct][share_count u16 LE][shares]`.

## Profile

This crate exposes `ThresholdKemProfileV1` with:

- `id = 1`
- `max_threshold = 32`
- `parameter_set_digest = SHA3-256("amber-tkem-revised-v1-T32-k128")`

## Security and status

This crate is **PROVISIONAL** and intended for controlled evaluation and interoperability testing.

## Parameter provenance

The profile canonical blob is pinned in code and hashed with SHA3-256.
Reference standard for the KEM building block:

- FIPS 203 (ML-KEM): [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)
