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
# From another workspace member, use a path dependency:
lib-q-plonky = { path = "../lib-q-plonky", features = ["full"] }
# or crates.io once published:
# lib-q-plonky = { version = "0.0.5", features = ["full"] }
```

All components are built on the `lib-q-stark-*` primitives (SHAKE256-oriented pipeline).

## Architecture

For the overall ZKP/STARK/Plonky architecture, when to use **`lib-q-zkp`**, and how this differs from [**lib-q-lattice-zkp**](../lib-q-lattice-zkp), see [docs/zkp-implementation.md](../docs/zkp-implementation.md) (section "Library layout and implementation status").
