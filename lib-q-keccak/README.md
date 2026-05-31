# lib-Q Keccak: Quantum-Resistant Cryptographic Sponge Function

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache 2.0 Licensed][license-image]
![Rust Version][rustc-image]

Pure Rust implementation of the [Keccak Sponge Function][1] including the keccak-f
and keccak-p variants for the lib-Q post-quantum cryptography library.

[Documentation][docs-link]

## About

This crate implements the core Keccak sponge function, a foundational building block
for post-quantum cryptographic primitives. Keccak was designed by Guido Bertoni,
Joan Daemen, Michaël Peeters, and Gilles Van Assche, and forms the basis of the
SHA-3 cryptographic hash algorithms standardized in FIPS 202.

For high-level SHA-3 hash functions and SHAKE XOFs, see the [`lib-q-sha3`] crate,
which is built on this crate.

See the [lib-Q workspace README](https://github.com/Enkom-Tech/libQ/blob/main/README.md) for how Keccak/SHA-3 crates connect to ML-DSA (`lib-q-ring`, `lib-q-sha3`).

## Features

- **no_std compatible**: Works in embedded and WebAssembly environments
- **Optimized implementations**: Platform-specific optimizations for ARM64 and x86_64
- **SIMD support**: Parallel processing with portable SIMD (nightly)
- **Multi-threading**: Concurrent state processing for high-performance applications
- **WebAssembly**: Full WASM support with JavaScript interop via wasm-bindgen
- **Quantum-resistant**: Part of the lib-Q post-quantum cryptography suite

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
lib-q-keccak = "0.0.5"
```

### Basic Example

```rust
use lib_q_keccak::f1600;

let mut state = [0u64; 25];
f1600(&mut state);
```

### With Features

```toml
[dependencies]
lib-q-keccak = { version = "0.0.5", features = ["simd", "multithreading"] }
```

## Feature Flags

- `std` (default): Enable standard library support
- `asm` (default): Use optimized assembly when available
- `alloc`: Enable allocator support for no_std environments
- `simd`: Enable SIMD parallel processing (requires nightly)
- `multithreading`: Enable multi-threaded processing
- `wasm`: WebAssembly support with JS interop
- `wasm_getrandom`: WASM random number generation support
- `arm64_sha3`: ARM64 SHA3 hardware acceleration (native builds only)

## Minimum Supported Rust Version

Rust **1.89** or higher.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
http://www.apache.org/licenses/LICENSE-2.0).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be licensed as above, without any
additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/lib-q-keccak.svg
[crate-link]: https://crates.io/crates/lib-q-keccak
[docs-image]: https://docs.rs/lib-q-keccak/badge.svg
[docs-link]: https://docs.rs/lib-q-keccak/
[build-image]: https://github.com/Enkom-Tech/libQ/workflows/CI/badge.svg
[build-link]: https://github.com/Enkom-Tech/libQ/actions
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.89+-blue.svg

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Sponge_function
[`lib-q-sha3`]: https://github.com/Enkom-Tech/libQ/tree/main/lib-q-sha3
