# @lib-q/types

Shared TypeScript interfaces for JavaScript values returned by `@lib-q/*` WebAssembly builds. Individual packages ship their own `*.d.ts` from `wasm-bindgen`; this package documents the **semantic JSON / object shapes** so applications can type results without `as unknown as`.

See [wasm-security-model](https://github.com/Enkom-Tech/libQ/blob/main/docs/wasm-security-model.md) for WASM memory, CSP (`script-src` / `wasm-eval`), and timing expectations.

## Install

```bash
npm install @lib-q/types
```

Use as a dev dependency if you only need typings.

## Usage

```typescript
import type { HpkeSealResult, LibQWasmError } from "@lib-q/types";

declare function hpkeSeal(...args: unknown[]): HpkeSealResult | LibQWasmError;
```

Errors from recent bindings are plain objects `{ code: string; message: string }` (see `LibQWasmError`), not `Error` subclasses.
