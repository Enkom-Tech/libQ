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

## Proof size table

Measured from `tests/vectors/manifest.json` (KAT seed, T=32/n=64 encap path):

| Scenario | Bytes | Budget | Pass |
|----------|------:|-------:|:----:|
| ML-KEM-768 ciphertext (`ct`) | 1088 | 30720 | yes |
| Full wire (`threshold_kem_wire_v1`) | ≤30720 | 30720 | yes |

Hard ciphertext ceiling: `WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES = 30720`.

Pinned parameter digest (SHA3-256): `eb79c0f7804722e368351a9c5756dcafcae3ed2d46bc4c77dbc565b31877736c`.

## KAT export

Schema: `threshold-kem-kat-v1`

```bash
cargo test -p lib-q-threshold-kem kat_regenerate_vectors -- --ignored
```

Output: `tests/vectors/threshold-kem-v1.json`

## Security and status

This crate is **PROVISIONAL** and intended for controlled evaluation and interoperability testing.

## Parameter provenance

The profile canonical blob is pinned in code and hashed with SHA3-256.
Reference standard for the KEM building block:

- FIPS 203 (ML-KEM): [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)
