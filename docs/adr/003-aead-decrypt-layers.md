# ADR 003: AEAD decrypt layers (Result vs semantic outcome)

## Status

Accepted.

## Context

Authenticated decryption in lib-Q exposes success versus failure through Rust’s `Result` type (`lib-q-core::traits::Aead::decrypt` and HPKE `open`). That boundary is appropriate for most callers and for dynamic dispatch (`dyn AeadOperations`, WASM shims), but it does not, by itself, prevent remote observers from correlating wall-clock time or branch behavior with verification outcome. Some integrators additionally want a **semantic** API that never returns successful plaintext in the same `Result::Ok` arm as a “verification failed” condition, so failure modes are expressed as a dedicated outcome variant instead of mixing them with operational errors.

## Decision

We define three **documentation and API layers** (not runtime stack levels):

| Layer | Role | Shipping stance |
|-------|------|-----------------|
| **A** | `Aead::decrypt` → `Result<Vec<u8>, Error>` | Canonical default ABI; stable; used by contexts, providers, and WASM where applicable. |
| **B** | `AeadDecryptSemantic::decrypt_semantic` → `Result<DecryptSemanticOutcome>` (lib-q-core `Result` alias = `Err(Error)` vs `Ok(outcome)`) | First-class in `lib-q-core`; `Ok(AuthenticationFailed)` encodes failed integrity **after** the decrypt/verify schedule defined for the algorithm; **no** plaintext bytes in that arm. Operational failures (key/nonce/size/config) remain `Err`. |
| **C** | Application policy: fixed latency, scheduling isolation, remote timing | **Not** a crypto API in core; documented in security materials; Layer B does **not** replace Layer C. |

### Error vs outcome (Layer B convention)

- **Pre-decrypt validation** (wrong key length, wrong nonce length, message too long, unsupported AD, ciphertext shorter than the algorithm’s tag length): **`Err(Error::…)`** (or HPKE’s `Err(HpkeError::…)` after mapping). Ciphertext strictly shorter than the tag is reported as **`Error::InvalidCiphertextSize`** (see `Error::aead_ciphertext_shorter_than_tag` in `lib-q-core`), not as tag verification failure.
- **Cryptographic path executed; integrity check failed** (e.g. tag mismatch after full Saturnin CTR decrypt and constant-time compare): **`Ok(DecryptSemanticOutcome::AuthenticationFailed)`**.
- **Cryptographic path executed; integrity OK**: **`Ok(DecryptSemanticOutcome::Success(Zeroizing<Vec<u8>>))`**.

Implementations must keep **one shared decrypt core** per algorithm (no duplicated CTR/tag loops for Layer A vs B). Layer A maps semantic success to `Ok` and semantic authentication failure to `Err` using the algorithm’s historical variant (see inventory below).

### Layer A error variant after integrity failure (post–Phase 2)

| Construction | `Aead::decrypt` on failed tag / binding |
|--------------|----------------------------------------|
| `lib_q_saturnin::SaturninAead`, `lib_q_saturnin::SaturninShortAead` | `Error::VerificationFailed` after full decrypt/verify schedule; ciphertext shorter than tag → `Error::InvalidCiphertextSize` |
| `lib_q_aead::Shake256Aead` | `Error::AuthenticationFailed` (existing tests / string `"Tag verification failed"`) after decrypt schedule; ciphertext shorter than tag → `Error::InvalidCiphertextSize` |
| `lib_q_duplex_aead::DuplexSpongeAead`, `lib_q_tweak_aead::TweakAead` | `Error::VerificationFailed` (`operation: "AEAD tag verification"`) after decrypt schedule; ciphertext shorter than tag → `Error::InvalidCiphertextSize` |
| `lib_q_romulus::{RomulusNAead, RomulusMAead}` (facade) | `Error::VerificationFailed` after decrypt schedule; ciphertext shorter than tag → `Error::InvalidCiphertextSize` |

Layer B always uses `Ok(DecryptSemanticOutcome::AuthenticationFailed)` for the same cryptographic condition regardless of the Layer A `Err` variant name.

### HPKE

- `SaturninAeadImpl::decrypt_semantic` exposes the same `DecryptSemanticOutcome` mapping as core, with HPKE errors for validation failures.
- `Shake256AeadImpl::decrypt_semantic` mirrors Saturnin: concrete `lib_q_aead::Shake256Aead` (no `dyn` indirection).
- `Aead::open` remains `Result`-first and is implemented as a thin wrapper over the semantic path for Saturnin and SHAKE256 so auth mapping stays consistent.
- **`AeadProvider` / `PostQuantumProvider`**: unchanged `open`/`Result` surface; semantic decrypt is **opt-in** for callers holding concrete HPKE AEAD impl types or registry leaf types. Duplex HPKE (`HpkeAead::DuplexSpongeAead`) uses the same `Box<dyn Aead>` provider path: use concrete `lib_q_aead::DuplexSpongeAead` or `lib_q_duplex_aead::DuplexSpongeAead` for `decrypt_semantic`.

### Saturnin-Short

Short mode uses a **single-block** integrity story (no separate tag; nonce binding and padding over one decrypted block). It implements the same Layer B trait and conventions so callers can use one semantic pattern for full and Short where both are enabled.

### Phase 2 inventory (`AeadDecryptSemantic`)

| Algorithm / type | Layer B (`decrypt_semantic`) | HPKE note |
|------------------|------------------------------|-----------|
| Saturnin full + Short (`lib-q-saturnin`) | Yes | `SaturninAeadImpl` forwards semantic |
| SHAKE256 (`lib-q-aead::Shake256Aead`) | Yes | `Shake256AeadImpl` forwards semantic |
| Duplex sponge (`lib-q-duplex-aead`, `lib-q-aead::DuplexSpongeAead`) | Yes | Provider `Box<dyn Aead>` only; use concrete type for semantic |
| Tweak CTR (`lib-q-tweak-aead`, `lib-q-aead::TweakAead`) | Yes | Same as duplex for provider usage |
| Romulus N / M (`lib-q-romulus` facades + `lib-q-aead` wrappers) | Yes | N/A (not a separate HPKE module) |

**Registry / mocks:** `MockAead` in `lib-q-aead` tests implements Layer A (`Aead`) + metadata only; it does **not** implement `AeadDecryptSemantic` (documented limitation for test doubles). `AeadWithMetadata::supports_semantic_decrypt` is overridden to return `false` for those stubs even when the backing `AeadMetadata` row is `true` for the real algorithm.

**Discoverability:** `AeadMetadata::supports_semantic_decrypt` documents whether the canonical shipped types for that algorithm implement Layer B; `AeadWithMetadata::supports_semantic_decrypt` defaults to that flag so `dyn AeadWithMetadata` callers can branch without importing algorithm-specific types.

## Consequences

- Positive: Clear split between transport/FFI-friendly `Result` APIs and opt-in semantic outcomes; Saturnin, SHAKE256, duplex/tweak, Romulus, and HPKE concrete AEAD types stay internally consistent where implemented.
- Negative: Two decrypt entry points per algorithm; callers must choose deliberately. WASM and `dyn AeadOperations` stay Layer A unless extended later.
- Versioning: Phase 2 adds `AeadDecryptSemantic` impls on existing public types without changing `Aead::decrypt` contracts; workspace crate versions are **0.0.2** until a first coordinated publish bump.

## Non-goals

- Layer B does **not** claim mitigation of **remote** timing against verification outcome; that remains Layer C and deployment policy.
- No public helpers that collapse secret-bearing state to `bool` without documenting timing implications (callers should `match` on `DecryptSemanticOutcome`).
