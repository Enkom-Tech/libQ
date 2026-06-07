# lib-q-blind-pcs

> **EXPERIMENTAL_NON_NIST:** This crate is a provisional demo and is **not** a
> NIST-standardized blind polynomial commitment system. Do not use in production.

`lib-q-blind-pcs` exposes a tiny hash-based blind commitment API intended for
demo and integration wiring:

- `blind_commit`
- `blind_open`
- `verify`

## Feature flag

- `default = []`
- enable with `--features blind-pcs`
