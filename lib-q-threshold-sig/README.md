# lib-q-threshold-sig (PROVISIONAL)

`lib-q-threshold-sig` provides a provisional threshold signature flow for libQ.

- Construction style: hash-based, FROST-like threshold Schnorr flow.
- Hash/XOF: `SHAKE256` from `lib-q-sha3`.
- Secret sharing: byte-wise Shamir shares over `GF(256)`.
- Wire format: `threshold_sig_wire_v1`  
  `[ver=1][profile=1][sig_len u16 LE][sig][meta_len u16 LE][meta]`.

## Profile

The crate exposes `ThresholdSigProfileV1`:

- `id = 1`
- `max_parties = 64`

## Proof size table

Measured from `tests/vectors/manifest.json` (KAT seed, profile v1, 3-of-5 sign path):

| Scenario | Bytes | Budget | Pass |
|----------|------:|-------:|:----:|
| Aggregated wire (`threshold_sig_wire_v1`) | 270 | 11264 | yes |
| Profile v1 envelope lane | 270 | 8192 | yes |

Hard wire ceiling: `WIRE_BUDGET_THRESHOLD_SIG_BYTES = 11264`. Profile v1 envelope: `PROFILE_ENVELOPE_BUDGET_BYTES = 8192`.

## KAT export

Schema: `threshold-sig-kat-v1`

```bash
cargo test -p lib-q-threshold-sig kat_regenerate_vectors -- --ignored
```

Output: `tests/vectors/threshold-sig-pop-v1.json`

## Status

This crate is **PROVISIONAL** and intended for controlled evaluation.
It is a pre-standard implementation intended for integration and protocol testing, not final production standardization.
