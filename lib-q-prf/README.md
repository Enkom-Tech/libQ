# lib-q-prf

Legendre and Gold (power-residue) pseudorandom functions over prime fields \(\mathbb{F}_p\), using **safe-prime** pilot moduli and constant-time arithmetic via [`crypto_bigint`](https://github.com/RustCrypto/crypto-bigint) (`modular::FixedMontyForm` with `MontyParams<U256>` / `MontyParams<U512>`).

## Scope

- **Legendre PRF:** \(L_K(x)=\left(\frac{x+K}{p}\right)\) with explicit [`PrfError::ZeroInput`](src/error.rs) when \(x+K\equiv 0 \pmod p\).
- **Gold PRF:** \(\mathrm{Gold}_k(x)=(k+x)^g \bmod p\) with pilot \(g=(p-1)/2\) for safe primes \(p=2q+1\).
- **Key derivation:** domain-separated `SHAKE256` expansion into \([1,p)\) (see [`shake.rs`](src/shake.rs)).

This crate does **not** implement full anonymous ring signatures; [`lib-q-ring-sig`](../lib-q-ring-sig/) may compose these PRFs behind the `pilot-insecure-prf-transcript` feature for **non-shipping** transcript experiments (see that crate’s module docs).

## Features

| Feature | Purpose |
| ------- | ------- |
| `alloc` (default) | Enables `lib-q-sha3/alloc` for XOF buffering. |
| `std` | Pass-through to `alloc`. |

`crypto-bigint/alloc` is intentionally **not** enabled: field elements use fixed-width `U256` / `U512` only.

## Tests and KATs

- [`tests/reference_vectors.txt`](tests/reference_vectors.txt) — hex KATs; regenerate with [`scripts/gen_prf_kat.py`](../scripts/gen_prf_kat.py) (requires SymPy).
- SHA-256 fingerprints of modulus encodings catch typos in `params.rs`.

## Documentation

See [DESIGN.md](DESIGN.md) for assumptions, extension-field caveats, and safe-prime provenance.
