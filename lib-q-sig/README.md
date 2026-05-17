# lib-q-sig

Post-quantum **signature façade** for lib-Q: optional integrations with ML-DSA, SLH-DSA, and FN-DSA behind feature flags. Exposes a `cdylib` + `rlib` crate for native and WASM bundles.

## Algorithms (feature-gated)

| Feature | Backend crate | Notes |
|--------|----------------|-------|
| `ml-dsa` | `lib-q-ml-dsa` | FIPS 204; ring layer in `lib-q-ring`. |
| `slh-dsa` | `lib-q-slh-dsa` | FIPS 205; caller-supplied RNG for `no_std`-friendly tests. |
| `slh-dsa-std` | above + `lib-q-random` | Implicit OS-backed RNG when APIs allow `None`. |
| `slh-dsa-wasm` | above + WASM deps | Browser/JS-oriented builds. |
| `fn-dsa` | `lib-q-fn-dsa` | FIPS 206. |

Default features: `alloc`, `ml-dsa`, `std`.

## Related crates

- [**lib-q-ml-dsa**](../lib-q-ml-dsa) — direct ML-DSA API and `hardened` mode.
- [**lib-q-core**](../lib-q-core) — `SignatureContext`, `LibQCryptoProvider`, algorithm IDs.
- [**lib-q**](../lib-q) — umbrella re-exports.

## Testing

```bash
cargo test -p lib-q-sig --features ml-dsa
cargo test -p lib-q-sig --features slh-dsa
cargo test -p lib-q-sig --features slh-dsa-std
```

See the workspace [README.md](../README.md) for full context.

## License

Apache-2.0 — see [LICENSE](../LICENSE).
