# WebAssembly security model for libQ

This document describes security properties and operational constraints when using libQ crates compiled to `wasm32-unknown-unknown` and distributed as JavaScript modules (`wasm-bindgen` / npm `@lib-q/*` packages).

## Threat model

- **Host trust**: The JavaScript environment (browser or Node.js) is assumed to control the embedding page, extensions, and debugging tools. Anything passed to or returned from JavaScript is exposed to that environment.
- **WASM linear memory**: Rust allocations live in a single growable memory object. The runtime does not guarantee scrubbing of freed pages. libQ uses `zeroize` for selected intermediate buffers at the JS boundary; this reduces but does not eliminate the risk of sensitive data lingering in memory.
- **Secrets on the JS heap**: APIs that return JSON or hex strings containing keys, shared secrets, or HPKE key schedule material place those values in the JS heap, where they are not zeroizable and may be copied by the garbage collector. Prefer the HPKE **opaque handle** exports (`hpkeSetupSenderHandle`, `hpkeSenderSealByHandle`, `hpkeSetupReceiverHandle`, `hpkeReceiverOpenByHandle`, `hpkeDropHandle`) so operational keying state remains in WASM until explicitly dropped.

## Constant-time and JIT compilation

Rust code in libQ is written with constant-time discipline where required for native targets. **WebAssembly engines apply optimization passes** (inlining, strength reduction, vectorization) that can alter timing behavior relative to native builds. In particular:

- Table-driven logic (e.g. small S-box or lookup-style constructions) may not retain the same timing profile as on `x86_64` or `aarch64`.
- ML-KEM-style polynomial arithmetic and SHA-3 / SHAKE sponges are generally less sensitive to these effects than table-heavy symmetric designs, but **no formal constant-time guarantee is offered for WASM**.

For high-assurance deployments, perform security-critical operations on a hardened native service and reserve the WASM surface for integration, verification, or non-timing-critical paths as appropriate.

## Randomness

On `wasm32-unknown-unknown`, `getrandom` must use the JavaScript backend (`wasm_js`). The workspace documents `RUSTFLAGS` / `.cargo/config.toml` configuration in [wasm-compilation.md](./wasm-compilation.md). Failure to set the backend typically surfaces as runtime errors when first drawing random bytes, not as compile-time failures.

## Content Security Policy (CSP)

Example policy fragment for Chromium-oriented hosts (adapt to your threat model):

```http
Content-Security-Policy: script-src 'self' 'wasm-unsafe-eval'; connect-src 'self';
```

Firefox and older Chrome builds may require different `script-src` allowances; see MDN and your browser matrix.

## Subresource Integrity (SRI)

Published `@lib-q/*` packages that ship `.wasm` files include `integrity-manifest.json` with **SHA-384** digests in `integrity="<algo>-<base64>"` form. Use the **relative path keys** in that JSON when pinning CDN responses (separate entries for `web/` vs `nodejs/` trees when both targets are published).

## Structured errors

WASM entry points return failures as `JsValue` objects:

Objects look like `{ "code": string, "codeNumeric": number, "message": string }`.

`code` is a stable string category; `codeNumeric` is the FNV-1a 32-bit digest of the UTF-8 `code` bytes for numeric `switch` handling in TypeScript. Plain string errors are not used for new bindings.

## Related documentation

- [wasm-compilation.md](./wasm-compilation.md) — toolchains, features, `getrandom`, and CI gates.
- [npm-packages.md](./npm-packages.md) — scoped packages and build pipeline overview.
