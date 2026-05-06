# lib-Q Examples

This directory contains examples demonstrating the usage of lib-Q post-quantum cryptography library. For the module-lattice ZKP research crate, see [`lib-q-lattice-zkp/README.md`](../lib-q-lattice-zkp/README.md) (not covered by these examples).

## WebAssembly (`wasm-pack`)

The standalone crate [`wasm-browser-demo/`](wasm-browser-demo/) builds a minimal ML-DSA-44 `cdylib` for browsers. See its [README](wasm-browser-demo/README.md) and the workspace guide [docs/wasm-compilation.md](../docs/wasm-compilation.md).

## ML-DSA Examples

### Running ML-DSA Examples

When building from the workspace root, use `-p lib-q-examples`. The package depends on `lib-q-ml-dsa` and `lib-q-sig` with ML-DSA enabled, enables `ml-dsa` / `slh-dsa` on the umbrella `lib-q` crate, and **defaults** to the `cb-kem` feature (pass `--no-default-features` if you want to omit CB-KEM and `lib-q`’s CB-KEM wiring).

```bash
# From workspace root (libQ/)
cargo run -p lib-q-examples --example ml_dsa_working_no_std
cargo run -p lib-q-examples --example ml_dsa_full_integration_test
cargo run -p lib-q-examples --example ml_dsa_no_std_example
cargo run -p lib-q-examples --example ml_dsa_no_std_trait_test
cargo run -p lib-q-examples --example ml_dsa_integration_test
```

### Example Descriptions

#### `ml_dsa_full_integration_test.rs`
Comprehensive integration test demonstrating:
- High-level API with automatic randomness generation (std environment)
- Low-level API with external randomness provision (no_std compatible)
- ML-DSA-65 variant testing

#### `ml_dsa_no_std_example.rs`
Simple example showing ML-DSA usage in no_std environments:
- Keypair generation with external randomness
- Message signing with external randomness
- Signature verification
- Demonstrates rejection of invalid signatures

#### `ml_dsa_no_std_trait_test.rs`
Exercises `lib-q-sig`’s ML-DSA wrapper with the `Signature` trait from `lib-q-core` **in this package’s default configuration** (`lib-q-sig` built with `std`):
- `generate_keypair` / `sign` / `verify` using automatic RNG
- `generate_keypair_with_randomness` / `sign_with_randomness` (the path to use on **no_std** when the trait’s RNG helpers are unavailable)

#### `ml_dsa_working_no_std.rs`
Working example using lib_q_ml_dsa directly:
- Demonstrates all ML-DSA variants (44, 65, 87)
- Shows proper no_std usage patterns

#### `ml_dsa_integration_test.rs`
Integration test using the main `libq` crate (with `ml-dsa` / `slh-dsa` features on the examples’ `lib-q` dependency):
- Confirms ML-DSA entries in the algorithm registry
- Uses `SignatureContext::with_default_provider()` so the core stub returns `NotImplemented` for `generate_keypair` (real signing lives in `lib-q-sig`)

### Features

- **ML-DSA-44**: Level 1 security (128-bit)
- **ML-DSA-65**: Level 3 security (192-bit) 
- **ML-DSA-87**: Level 4 security (256-bit)

### Key Sizes (ML-DSA-65)
- **Public key size**: 1952 bytes
- **Secret key size**: 4032 bytes  
- **Signature size**: 3309 bytes

### Security Notes

⚠️ **Important**: The examples use deterministic randomness (all zeros) for demonstration purposes. In production, always use cryptographically secure random sources.

## Other Examples

### Hash Example

```bash
cargo run -p lib-q-examples --example hash_example
```

Demonstrates cSHAKE128/cSHAKE256 (and a `HashContext` / SHAKE256 path where applicable).

### CB-KEM examples

```bash
cargo run -p lib-q-examples --example cb_kem_example
cargo run -p lib-q-examples --example cb_kem_simple_example
cargo run -p lib-q-examples --example cb_kem_production_example
cargo run -p lib-q-examples --example cb_kem_testing_example
```

### Keccak permutation smoke test

Runs `lib_q_keccak::f1600` on the documented zero-state vector (same check as the `lib-q-keccak` crate docs).

```bash
cargo run -p lib-q-examples --example keccak_no_std_test
```

### Signature algorithms in the registry

The umbrella registry lists ML-DSA, FN-DSA, and SLH-DSA variants among signature algorithms; runtime signing still uses `lib-q-sig` (or `libq::LibQSignatureProvider` with the right `lib-q` features), not the core stub provider.
