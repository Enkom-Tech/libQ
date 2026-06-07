# lib-q-fhe

> **EXPERIMENTAL_NON_NIST:** This crate is a demo-only toy construction and is **not**
> a NIST-standardized FHE primitive. Do not use it for production security.

`lib-q-fhe` provides a minimal lattice-style toy FHE flow over `i32` coefficients
modulo `q` with an intentionally small API:

- `fhe_keygen`
- `encrypt`
- `eval`
- `decrypt`

## Feature flag

- `default = []`
- enable with `--features fhe`

## Scope

This crate is intentionally educational and provisional. It is meant to support
internal demos and test wiring for feature-gated advanced primitives.
