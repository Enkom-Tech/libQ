# wasm-browser-demo

Minimal **ML-DSA-44** example built with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) for browser or Node integration.

## Build

From this directory:

```bash
rustup target add wasm32-unknown-unknown
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'
wasm-pack build --target web --release
```

Open `index.html` via a local static server (browsers block `file://` ES modules for WASM in many configurations):

```bash
npx serve .
```

## API

- `wasm_smoke_ml_dsa_sign_verify()` — deterministic sign/verify smoke test; returns `true` or a JS error string.

See [docs/wasm-compilation.md](../../docs/wasm-compilation.md) for workspace-wide WASM guidance.
