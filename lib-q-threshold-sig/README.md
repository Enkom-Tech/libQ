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

## Status

This crate is **PROVISIONAL** and intended for controlled evaluation.
It is a pre-standard implementation intended for integration and protocol testing, not final production standardization.
