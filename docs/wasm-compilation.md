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

### Dev-dependencies and `wasm-pack test`

`wasm-pack test` (and `cargo build --tests --target wasm32-unknown-unknown`) compile **dev-dependencies**. **`proptest`** pulls `rand` 0.9 → **`getrandom` 0.3** without `wasm_js`, which fails under the `getrandom_backend="wasm_js"` cfg. **`criterion`** pulls **`wait-timeout`**, which does not compile for `wasm32-unknown-unknown`. Crates that do not need those tools in WASM test builds should list them only under:

```toml
[target.'cfg(not(target_arch = "wasm32"))'.dev-dependencies]
```

Bench-only crates (e.g. `fips204` next to `criterion` in `lib-q-ml-dsa`) belong in the same host-only block.

## Compilation modes

### As a Rust dependency (no `wasm-pack`)

Use `cargo check` / `cargo build` when pulling these crates into another Rust WASM binary; you do not need `cdylib` in your own crate unless you ship npm glue. Published `@lib-q/*` crates include `cdylib` for `wasm-pack`.

```bash
cargo check -p lib-q-core --target wasm32-unknown-unknown --no-default-features --features "alloc,wasm"
```

Exact feature sets vary by crate; prefer each crate’s `Cargo.toml` `[features]` table and README.

### `@lib-q/ml-kem`

[`lib-q-ml-kem`](../lib-q-ml-kem/) exposes ML-KEM `wasm-bindgen` entry points behind `--features wasm` (`ml_kem_generate_keypair`, `ml_kem_encapsulate`, `ml_kem_decapsulate`). Its manifest declares `crate-type = ["cdylib", "rlib"]` because current `wasm-pack` validates that entry for `wasm32-unknown-unknown` (the older `build.rs`-only `rustc-crate-type` hint is not sufficient).

The `wasm` feature enables `zeroize` in that crate: decapsulation keys and shared secrets live in `Zeroizing` buffers on the Rust side, and secret-returning getters plus `ml_kem_decapsulate` hand off copies as `Uint8Array`. Applications should still clear sensitive material in JavaScript after use (`Uint8Array.prototype.fill`, or equivalent), because erasure on the JS heap is outside Rust’s control.

```bash
cd lib-q-ml-kem
wasm-pack build --target web --release -- --features wasm
```

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

## WASM size gate

After the workspace check, CI runs `scripts/wasm-size-check.sh`, which performs `wasm-pack build --release` for selected `cdylib` crates and **fails the job** if the produced `.wasm` exceeds per-crate kilobyte budgets. Adjust budgets in that script when adding algorithms or changing `wasm-opt` settings.

## Supply chain (SBOM)

Release builds attach a CycloneDX JSON bill of materials for the `lib-q` crate resolved for `wasm32-unknown-unknown` with the same feature set used for `@lib-q/core` (see `scripts/generate-wasm-sbom.sh` and `docs/wasm-sbom.md`).

## `std` + WASM footguns

If you enable `std` on a crate while targeting `wasm32-unknown-unknown`, avoid unconditional `std::thread::sleep` and `std::fs` in library code; use `#[cfg(not(target_arch = "wasm32"))]` or stubs so bundlers do not pull in unsupported APIs.

## Crate-specific notes

| Crate / area | Note |
|--------------|------|
| `lib-q-stark*` / `lib-q-plonky*` | Default builds use serial `lib-q-stark-rayon` shims; do not enable `parallel` on WASM. |
| `lib-q-keccak` | Dependents should use `default-features = false` unless they explicitly need `std` / host threading from Keccak. |
| `lib-q-ml-kem` | `Cargo.toml` lists `cdylib` + `rlib` for `wasm-pack`. Host `no_std` consumers link the `rlib` only; enable feature `std` when you need a host `cdylib` link (workspace scripts use `--no-default-features --features std` for that check). |
| `lib-q-sca-test` | Host-oriented timing harness; excluded from the WASM workspace gate. |

## Browser baseline

Documented baselines (not a substitute for your own QA matrix):

| Environment | Minimum | Notes |
|-------------|---------|--------|
| Chromium / Chrome | 120 | `WebAssembly` + `crypto.getRandomValues`. |
| Firefox | 115 | Same. |
| Safari | 16.4 | Same. |
| Node.js LTS | 18 | Prefer `wasm-pack` `nodejs` target; WASI uses different `getrandom` wiring (`wasm32-wasi`). |

## API documentation (WASM target)

```bash
RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps --target wasm32-unknown-unknown -p lib-q-core --features wasm
```

Repeat `-p` for other crates as needed. Hosting target-specific docs is optional and usually done via CI artifacts or Pages.

For repository-hosted WASM docs, see the GitHub Actions workflow [`.github/workflows/wasm-docs-pages.yml`](../.github/workflows/wasm-docs-pages.yml), which builds `wasm32-unknown-unknown` docs and deploys them to GitHub Pages from `main`.
