# lib-q-k12

A pure Rust implementation of **KangarooTwelve** per [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html): **KT128** (TurboSHAKE128) and **KT256** (TurboSHAKE256) extendable-output functions, with domain separation via an optional customization string.

## Overview

KangarooTwelve applies a Sakura tree mode on top of TurboSHAKE. This crate exposes the two standard instances as **`Kt128`** and **`Kt256`**, matching the names and test vectors in RFC 9861.

- **KT128** — 128-bit collision strength (typical 32-byte default digest context).
- **KT256** — 256-bit collision strength (typical 64-byte default in high-security profiles).

## Features

- **Pure Rust**: No unsafe code
- **no_std**: Embedded-friendly (`#![no_std]`; works on `thumb*` and `wasm32-unknown-unknown`)
- **Streaming**: `Update` for incremental input
- **XOF**: Arbitrary output length via `ExtendableOutput` / `XofReader`
- **KATs**: Vectors from RFC 9861 Appendix A

### `no_std`, `alloc`, and WASM

- **Default** enables `alloc` (needed for `finalize_boxed` and similar helpers from `digest`).
- For **`core` only**, use `default-features = false` and `finalize_xof` / `finalize_xof_into` with a fixed-size buffer instead of `finalize_boxed`.
- CI runs `cargo check` for this crate on `wasm32-unknown-unknown` and `thumbv7em-none-eabi` with and without default features.

Integrated into [`lib-q-hash`](../lib-q-hash) for KangarooTwelve; see the [workspace README](../README.md) for the full dependency graph.

## Usage

### Basic hashing (KT128)

```rust
use lib_q_k12::{Kt128, digest::{ExtendableOutput, Update}};

let mut hasher = Kt128::default();
hasher.update(b"Hello, world!");
let result = hasher.finalize_boxed(32);
```

### With customization

```rust
use lib_q_k12::Kt128;
use lib_q_k12::digest::{ExtendableOutput, Update};

let customization = b"MyApplication";
let mut hasher = Kt128::new(customization);
hasher.update(b"Some data to hash");
let result = hasher.finalize_boxed(64);
```

### Streaming

```rust
use lib_q_k12::{Kt128, digest::{ExtendableOutput, Update}};

let mut hasher = Kt128::default();
hasher.update(b"First chunk");
hasher.update(b"Second chunk");
let result = hasher.finalize_boxed(32);
```

### XOF reader

```rust
use lib_q_k12::{Kt128, digest::{ExtendableOutput, Update, XofReader}};

let mut hasher = Kt128::default();
hasher.update(b"Input data");
let mut reader = hasher.finalize_xof();
let mut output = [0u8; 1000];
reader.read(&mut output);
```

### KT256

```rust
use lib_q_k12::{Kt256, digest::{ExtendableOutput, Update}};

let mut hasher = Kt256::default();
hasher.update(b"message");
let out = hasher.finalize_boxed(64);
```

## API reference

| Type | Role |
|------|------|
| `Kt128` / `Kt128Reader` | KangarooTwelve with TurboSHAKE128 (`AlgorithmName`: `"KT128"`) |
| `Kt256` / `Kt256Reader` | KangarooTwelve with TurboSHAKE256 (`AlgorithmName`: `"KT256"`) |

Main methods: `new`, `default`, `update`, `finalize_boxed`, `finalize_xof`, `reset` (see `digest` traits).

## Performance

Tree chunk size is 8192 bytes. Throughput depends on input length and CPU; see `cargo bench -p lib-q-k12`.

## Security

- **Collision strength**: `U16` bytes (128-bit) for `Kt128`, `U32` bytes (256-bit) for `Kt256` — see RFC 9861 §7.7–7.8.
- Use **KT256** when the application profile requires 256-bit collision security.

## Testing

```bash
cargo test -p lib-q-k12
```

## Standards

- [RFC 9861 — KangarooTwelve and TurboSHAKE](https://www.rfc-editor.org/rfc/rfc9861.html)
- [Keccak / KangarooTwelve (original)](https://keccak.team/kangarootwelve.html)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE-APACHE](LICENSE-APACHE) for details.

## Contributing

Run `cargo test -p lib-q-k12` and follow project rustfmt/Clippy settings. See [TESTING.md](TESTING.md).
