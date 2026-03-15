# lib-q-plonky

Entry point for the full Plonky3-derived STARK stack in lib-Q.

## Components

Each component is fully implemented; enable via crate features (see [Cargo.toml](Cargo.toml)):

| Feature | Crate | Description |
|---------|-------|-------------|
| `uni-stark` | lib-q-plonky-uni-stark | Univariate STARK (prover, verifier, preprocessed columns) |
| `batch-stark` | lib-q-plonky-batch-stark | Batch STARK (prove_batch, verify_batch, multiple AIRs, shared LogUp) |
| `keccak-air` | lib-q-plonky-keccak-air | Keccak AIR |
| `lookup` | lib-q-plonky-lookup | Lookup arguments |
| `multilinear-util` | lib-q-plonky-multilinear-util | Multilinear utilities |

Use the `full` feature to enable all of the above.

## Usage

Add to `Cargo.toml`:

```toml
lib-q-plonky = { path = "..", features = ["full"] }
# or specific features, e.g. ["uni-stark", "batch-stark"]
```

All components are built on the lib-q-stark-* primitives (NIST, SHAKE256).

## Architecture

For the overall ZKP/STARK/Plonky architecture and when to use which stack, see [docs/zkp-implementation.md](../docs/zkp-implementation.md) (section "Library layout and implementation status").
