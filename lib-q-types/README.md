# lib-q-types

Shared **algorithm identifiers** and **classification types** for the lib-Q workspace. This crate is the lowest dependency layer so implementation crates (`lib-q-aead`, and others) can depend on stable IDs without pulling in `lib-q-core`.

## Contents

- `Algorithm` — discriminant for all supported algorithms
- `AlgorithmCategory` — KEM, signature, hash, AEAD
- `SecurityLevel` — coarse security tier metadata

## `no_std`

The crate is `#![no_std]` and does **not** require `alloc`. It is suitable for bare-metal and other constrained targets.

Verification on your machine:

```bash
cargo check -p lib-q-types
cargo check -p lib-q-types --features serde --target thumbv7em-none-eabihf
```

## Features

| Feature   | Purpose |
|-----------|---------|
| *(none)*  | Types only, `no_std`. |
| `serde`   | `Serialize` / `Deserialize` for `Algorithm`, `AlgorithmCategory`, and `SecurityLevel`. |
| `wasm`    | `wasm_bindgen` exports for the same types; enables `serde` (required for the generated JS interop). Use when this crate is part of a `wasm32-unknown-unknown` build that exposes these enums to JavaScript. |

For WebAssembly builds:

```bash
cargo check -p lib-q-types --features wasm --target wasm32-unknown-unknown
```

Downstream crates that enable WASM on `lib-q-core` typically enable `lib-q-types/wasm` in lockstep so algorithm enums stay consistent across the FFI boundary.

## Relationship to `lib-q-core`

`lib-q-core` re-exports `Algorithm`, `AlgorithmCategory`, and `SecurityLevel` from this crate. Richer error types and context APIs remain in `lib-q-core` for now; a future pass may move a minimal shared error surface here if it stays free of heavy dependencies.
