# lib-q-zkp fuzz targets

This directory is a **standalone** crate (excluded from the workspace root) for use with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Setup

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Purpose |
|--------|---------|
| `zkp_verify_bytes` | Deserialize arbitrary bytes as `postcard` STARK `Proof<DefaultConfig>`; if valid, run `StarkVerifier::verify` (should return `Err` on junk). |
| `zkp_prove_arithmetic` | Bounded `ArithmeticAir` trace generation and `StarkProver::prove` from short fuzz input. |

## Example

```bash
cd lib-q-zkp/fuzz
cargo +nightly fuzz run zkp_verify_bytes -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run zkp_prove_arithmetic -- -max_total_time=120 -timeout=30
```

On Windows, use the same commands from a shell where nightly and `cargo-fuzz` are available; linking uses the fuzzer runtime provided by `cargo-fuzz`.
