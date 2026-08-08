# lib-q-blind-pcs

> **EXPERIMENTAL_NON_NIST:** This crate is a provisional demo and is **not** a
> NIST-standardized blind polynomial commitment system. Do not use in production.

`lib-q-blind-pcs` exposes a tiny hash-based blind commitment API intended for
demo and integration wiring:

- `blind_commit`
- `blind_open`
- `verify`

## Wire-format break

The commitment hash is now SHA3-256, replacing SHA-256 (`sha2`). Commitments produced by
0.0.6–0.0.10 do not verify under this code, and there is no compatibility flag —
regenerate any stored commitments. `verify` also compares in constant time now.

## Feature flag

- `default = []`
- enable with `--features blind-pcs`
