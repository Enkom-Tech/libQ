# Security policy

## Scope

This policy applies to the lib-Q workspace (`lib-q` and related crates published from this repository). The project targets post-quantum key encapsulation, signatures, SHA-3–family primitives, Saturnin-based symmetric constructions, HPKE, and a STARK-based zero-knowledge stack. It is **pre-production**: absence of a published advisory does not imply suitability for high-assurance deployment without your own review and testing.

## Supported versions

Security-sensitive fixes are applied on the main development branch and backported when practical to recent `0.0.x` releases. Use the latest tag or commit you can verify.

| Channel / version | Support |
| ----------------- | ------- |
| `main`            | Yes     |
| `0.0.x` releases  | Yes     |

For contributor expectations (review checklist, dependency hygiene), see [CONTRIBUTING.md](CONTRIBUTING.md#security-review-process).

## Reporting a vulnerability

### Preferred: private disclosure

Use [GitHub private vulnerability reporting](https://github.com/Enkom-Tech/libQ/security/advisories) for issues that could compromise confidentiality, integrity, or availability of callers.

You may also email **github@enkom.dev** if GitHub is unavailable. Include:

- A concise description and affected component (crate, feature flag, or API surface).
- Steps or a minimal reproducer.
- Assessment of impact (best effort is fine).
- Optional proof-of-concept and preferred disclosure timeline.
- Contact details for follow-up questions.

### Public discussion

For general hardening ideas or non-sensitive questions, open a regular issue without exploit details, or contact maintainers directly.

## Security properties and limits

lib-Q intentionally avoids classical public-key schemes (RSA, ECC, etc.) and non–SHA-3 hash families in its cryptographic design. **Actual security** still depends on correct integration:

1. **Key management** — generation, storage, rotation, and destruction of long-term and ephemeral keys.
2. **Entropy** — quality of randomness for key generation and nonces (platform and `getrandom` configuration matter, especially on WASM).
3. **Side channels** — implementation is written with timing and cache awareness; we do not claim completed independent side-channel evaluation for all targets.
4. **Correct use** — calling the right API with the right parameter set, domain separation, and protocol context.

## Implementation practices

- **Constant-time intent** on sensitive paths; validation via tooling and review is ongoing.
- **Zeroization** of sensitive buffers where types and APIs permit.
- **Input validation** on public entry points.
- **`unsafe`** restricted to narrow, reviewed cases (e.g. SIMD or FFI boundaries), not sprinkled through cryptographic logic.
- **Automation** — CI includes builds, tests, `cargo audit`, and NIST-oriented validation utilities; see [.github/workflows/security.yml](.github/workflows/security.yml) and the scripts referenced from [README.md](README.md).

## Audit status

There has been **no published third-party security audit** of the full workspace. Plan for external review before relying on this code in adversarial environments.

## Disclosure process

We aim to:

- Acknowledge receipt of credible reports quickly (typically within one business day).
- Share status updates while a fix is developed and released.
- Coordinate publication of advisories with the reporter when reasonable.
- Credit discoverers in advisories with their consent.

## Security updates

Fixes are delivered through:

- Patch releases on the `0.0.x` line when applicable.
- GitHub Security Advisories and release notes.

Subscribe to repository notifications or advisories if you depend on published crates.

### Published `pkg/` API vs current `wasm-bindgen` surface

Checked-in or older `pkg/` artifacts may expose a monolithic `LibQ` type with `sig_verify`. The maintained bindings are **`WasmSignatureContext`** (via `create_signature_context` in the `lib-q` WASM module), which copies `Uint8Array` inputs into Rust (`to_vec()`) for verification—callers should not rely on long-lived borrows of JavaScript memory inside WASM.

**Semver / migration:** regenerate bindings with `wasm-pack` from this repository and migrate from legacy `LibQ.sig_verify` to `create_signature_context()` + `WasmSignatureContext.verify`, passing canonical algorithm strings such as `ml-dsa-65` or aliases accepted by the parser (e.g. `mldsa65`, case-insensitive hyphenated forms).

## Contact

- **Email:** [github@enkom.dev](mailto:github@enkom.dev)
- **Repository:** [Enkom-Tech/libQ](https://github.com/Enkom-Tech/libQ)
