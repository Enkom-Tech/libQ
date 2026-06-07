# lib-q-double-kem (PROVISIONAL)

`lib-q-double-kem` provides a provisional MAUL v1 profile for combining two ML-KEM-768
encapsulation lanes into a single upgraded shared secret.

## Status

- **Provisional research profile** for Hint-MLWE style wire-constrained transport.
- The API and wire layout can evolve before standardization.

## Proof size table

Measured from `tests/vectors/manifest.json` (KAT seed, MAUL v1 encap path):

| Scenario | Bytes | Budget | Pass |
|----------|------:|-------:|:----:|
| Baseline (2× ML-KEM-768) | 2176 | — | — |
| MAUL v1 wire (`double_kem` encap) | 1260 | 1260 | yes |
| Size savings vs baseline | 42.1% | ≥40% | yes |

Fixed wire split: `hint` 172 B + `body` 1088 B = 1260 B.

## KAT export

Schema: `double-kem-kat-v1`

```bash
cargo test -p lib-q-double-kem kat_regenerate_vectors -- --ignored
```

Output: `tests/vectors/double-kem-v1.json`

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
