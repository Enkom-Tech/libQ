# lib-q-ring

Portable negacyclic ring arithmetic for `R_q = Z_q[X]/(X^256 + 1)` with `q = 8_380_417` (FIPS 204 ML-DSA field). Shared by [**lib-q-ml-dsa**](../lib-q-ml-dsa), [**lib-q-lattice-zkp**](../lib-q-lattice-zkp), and related crates.

## Contents

- Montgomery / Barrett reduction and ML-DSA NTT (forward + inverse with Montgomery scaling)
- Polynomial types `Poly` / `NttPoly`, module vectors and matrices
- SHAKE128 matrix expansion (ExpandA-style) and FIPS 204 `SampleInBall` (SHAKE256)

## Features

- `default`: `alloc`
- `alloc`: enables `lib-q-sha3/alloc` for XOF buffering helpers

## Security

This crate is **research-grade** infrastructure: parameter sets and protocol security are not asserted here.
