# Building libQ for WebAssembly

This document describes how to compile and ship libQ crates for `wasm32-unknown-unknown` (browser and bundler targets) and related constraints.

## Prerequisites

- Rust toolchain matching the workspace `rust-version` in the root [Cargo.toml](../Cargo.toml).
- Target: `rustup target add wasm32-unknown-unknown`.
- Optional (for npm / JS bindings): [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

## Randomness (`getrandom`)

On `wasm32-unknown-unknown`, `getrandom` must use the JavaScript backend (`wasm_js`). The repository configures this in two complementary ways:

1. **`.cargo/config.toml`** — `rustflags` for `wasm32-unknown-unknown` include `--cfg getrandom_backend="wasm_js"`.
2. **Crate manifests** — several crates add a `[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]` edge on `getrandom` with `features = ["wasm_js"]` so feature unification cannot drop the backend when hardened RNG paths are enabled.

For CI parity, you can also export:

```bash
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'
```

Use `-C panic=abort` for release `wasm-pack` / `cdylib` builds to reduce binary size. **Do not** add `panic=abort` globally if you need `cargo test --target wasm32-unknown-unknown` with the default unwind test runtime for mixed `cdylib` + test crates (see comments in the root `Cargo.toml` profiles).

## Compilation modes

### Library only (`rlib`)

For inclusion in another Rust WASM project:

```bash
cargo check -p lib-q-core --target wasm32-unknown-unknown --no-default-features --features "alloc,wasm"
```

Exact feature sets vary by crate; prefer each crate’s `Cargo.toml` `[features]` table and README.

### `wasm-pack` (browser)

From a crate that declares `crate-type` including `cdylib` and enables `wasm-bindgen` (e.g. `lib-q`, `lib-q-core` with `wasm`):

```bash
cd lib-q
wasm-pack build --target web --features wasm
```

### `wasm-pack` (Node.js)

```bash
wasm-pack build --target nodejs --features wasm
```

## Feature flags

**Typical WASM-friendly flags**

- `alloc` — heap allocation without full host `std` where applicable.
- `wasm` / `wasm_js` / `wasm_getrandom` — per-crate names for JS interop and `getrandom` wiring.

**Incompatible with `wasm32-unknown-unknown`**

- **`parallel` on STARK / Plonky graphs** — `lib-q-stark-rayon` and `lib-q-stark-util` emit `compile_error!` when `parallel` is enabled on WASM.
- **`parallelhash` on `lib-q-hash`** — same pattern; use serial ParallelHash builds in the browser.

## Workspace compile gate

CI runs a workspace-level check (excluding the examples umbrella crate and the host-only SCA harness):

```bash
cargo check --workspace --exclude lib-q-examples --exclude lib-q-sca-test --target wasm32-unknown-unknown
```

## Crate-specific notes

| Crate / area | Note |
|--------------|------|
| `lib-q-stark*` / `lib-q-plonky*` | Default builds use serial `lib-q-stark-rayon` shims; do not enable `parallel` on WASM. |
| `lib-q-keccak` | Dependents should use `default-features = false` unless they explicitly need `std` / host threading from Keccak. |
| `lib-q-sca-test` | Host-oriented timing harness; excluded from the WASM workspace gate. |

## Browser baseline

Documented baselines (not a substitute for your own QA matrix):

| Environment | Minimum | Notes |
|-------------|---------|--------|
| Chromium / Chrome | 120 | `WebAssembly` + `crypto.getRandomValues`. |
| Firefox | 115 | Same. |
| Safari | 16.4 | Same. |
| Node.js LTS | 18 | Prefer `wasm-pack` `nodejs` target; WASI uses different `getrandom` wiring (`wasm32-wasi`). |

## Binary size (advisory)

The script [scripts/wasm-size-check.sh](../scripts/wasm-size-check.sh) runs `wasm-pack` on selected crates and compares output size to a threshold. Treat thresholds as advisory until tuned per release.

## API documentation (WASM target)

```bash
RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps --target wasm32-unknown-unknown -p lib-q-core --features wasm
```

Repeat `-p` for other crates as needed. Hosting target-specific docs is optional and usually done via CI artifacts or Pages.

For repository-hosted WASM docs, see the GitHub Actions workflow [`.github/workflows/wasm-docs-pages.yml`](../.github/workflows/wasm-docs-pages.yml), which builds `wasm32-unknown-unknown` docs and deploys them to GitHub Pages from `main`.
