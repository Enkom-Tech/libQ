# lib-q-zkp

High-level **zero-knowledge proof** API for lib-Q, built on the in-tree **zk-STARK** stack (`lib-q-stark` and related crates). Optional integration with the **Plonky**-derived crates is available behind features (see `Cargo.toml`).

## Where to read more

- [**docs/zkp-implementation.md**](../docs/zkp-implementation.md) — layout of `lib-q-zkp`, `lib-q-stark*`, `lib-q-plonky`, and how they differ from the research [**lib-q-lattice-zkp**](../lib-q-lattice-zkp) path.
- [**lib-q-plonky**](../lib-q-plonky) — batch STARK, Keccak AIR, lookups, etc.

## WASM

CI checks this crate for `wasm32-unknown-unknown` with the appropriate feature set; it is a normal Rust library (not the primary `wasm-pack` npm artifact).

## License

Apache-2.0 — see [LICENSE](../LICENSE).
