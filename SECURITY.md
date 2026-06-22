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

### WebAssembly deployment surface

When libQ is compiled for `wasm32-unknown-unknown` and executed in a browser or JS runtime:

- **Entropy** — Key generation and signing RNGs depend on `getrandom`’s `wasm_js` path (ultimately `crypto.getRandomValues` in typical browsers). Misconfigured bundlers, missing cfg flags, or blocked Web Crypto break randomness, not “degraded performance.”
- **Memory** — Linear memory is sandboxed by the host; secrets still live in JS-visible memory unless you isolate workers and avoid leaking handles to the host.
- **Side channels** — Coarse timers and different JIT pipelines change the side-channel landscape relative to native code. Existing constant-time discipline in the Rust sources remains necessary but is **not** sufficient to claim parity with server-side hardening without target-specific evaluation.
- **Supply chain** — `wasm-bindgen`, `js-sys`, and `web-sys` are part of the trusted computing base for JS interop builds. Pin versions and run `cargo audit` on the same lockfile you ship.

Threaded acceleration (`rayon` / `parallel` features in the STARK stack and `parallelhash` in `lib-q-hash`) is **rejected at compile time** on WASM; use serial feature sets.


### `lib-q-lattice-zkp` (wire v0)

[`lib-q-lattice-zkp`](lib-q-lattice-zkp/) ships a **frozen wire v0** profile with compact encodings, exportable KATs, and CI byte-budget gates. Suitable for downstream integration; not a substitute for independent audit or side-channel certification:

- Opening Fiat–Shamir uses a committed-first-message transform with **QROM** claims (see below).
- Blind issuance v0 is **issuer-keyed** via [`IssuerCommitmentParams`](lib-q-lattice-zkp/src/blind.rs); shared-CRS blind pilot is non-conformant.
- PVTN wire v0 hides Merkle path index and clearance level on the wire (verifier-side search); see `lib-q-lattice-zkp/DESIGN.md` §4.1.
- Default builds: prover rejection branches are not constant-time; enable `hardened` for CT-oriented prover paths.

### Random Oracle Model vs Quantum Random Oracle Model

Components using the **Fiat–Shamir transform** for non-interactive proofs (`lib-q-lattice-zkp` sigma opening proofs with `fs_w_digest`, and `lib-q-ring-sig` DualRing-LB–oriented pilot ring verification) state security as follows:

- **`lib-q-lattice-zkp` opening / PVTN / blind attestation paths:** committed-first-message Fiat–Shamir (`QROM_FS_W_DIGEST_DOMAIN`); analyzed in the **Quantum Random Oracle Model (QROM)** for the transform in ADR 058 / `lattice-fs-security-model-v0`.
- **`lib-q-ring-sig` DualRing-LB pilot:** security proofs remain in the **Random Oracle Model (ROM)**, not QROM, until a uniform upgrade lands.

- Classical adversaries must treat the hash function (SHAKE256) as a black box, which is standard for Fiat–Shamir.
- A quantum adversary with oracle access to the hash function could apply Simon's or Grover's algorithm to extract information beyond the classical proof bounds.

**Impact assessment:** QROM analysis applies to `lib-q-lattice-zkp` opening paths via the committed-first-message transform. `lib-q-ring-sig` DualRing-LB remains ROM-only until upgraded. Exploiting QROM gaps requires a cryptographically relevant quantum adversary with structured oracle access.

**Alternatives considered:** The optional `pilot-insecure-prf-transcript` feature on [`lib-q-ring-sig`](lib-q-ring-sig/) composes [`lib-q-prf`](lib-q-prf/) Legendre and Gold (power-residue) PRFs into a Fiat–Shamir transcript for **laboratory wiring tests only**. That path is **not** a ring signature: the verifier consumes **raw PRF secret key encodings** for every listed member, so anyone who sees the ring vector can evaluate the PRFs and synthesize valid-looking transcripts. It trades the Module-LWE/SIS opening model for algebraic \(\mathbb{F}_p\) PRF assumptions without delivering issuer hiding or unforgeability in that form. For federation rings of modest size, the ROM-only opening-based path may still be preferable when a single Module-SIS/LWE assumption family is desired.

**Upgrade path:** Both constructions are pre-production. QROM-secure lattice ring signatures with comparable engineering cost remain future work; callers exploring PRF-in-FS transcript patterns can evaluate `pilot-insecure-prf-transcript` under its documented limits (see [`lib-q-ring-sig/DESIGN.md`](lib-q-ring-sig/DESIGN.md) and [`lib-q-prf/DESIGN.md`](lib-q-prf/DESIGN.md)).

## Implementation practices

- **Constant-time intent** on sensitive paths; validation via tooling and review is ongoing.
- **Zeroization** of sensitive buffers where types and APIs permit.
- **Input validation** on public entry points.
- **`unsafe`** restricted to narrow, reviewed cases (e.g. SIMD or FFI boundaries), not sprinkled through cryptographic logic.
- **Automation** — CI includes builds, tests, `cargo audit`, and NIST-oriented validation utilities; see [.github/workflows/security.yml](.github/workflows/security.yml) and the scripts referenced from [README.md](README.md).
- **Hardened builds** — `lib-q-ml-kem`, `lib-q-ml-dsa`, and `lib-q-lattice-zkp` expose a `hardened` feature with CI timing smoke tests; see [docs/hardened-attestation.md](docs/hardened-attestation.md). This is not independent side-channel certification.

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
