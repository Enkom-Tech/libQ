# Security

## Constant-time requirements

Full AEAD (`aead.rs`) tag verification uses constant-time comparison (`lib_q_core::Utils::constant_time_compare`). No secret-dependent branches or short-circuit comparisons on tags or keys in that path. The `constant_time` test binary exercises tag accept/reject behavior for full AEAD and Short. **Layer B:** use `lib_q_core::AeadDecryptSemantic::decrypt_semantic` on `SaturninAead` (or `SaturninShortAead` when the `aead-short` feature is enabled) for a semantic outcome without plaintext on authentication failure; `lib_q_core::Aead::decrypt` remains the default `Result` mapping. See workspace ADR `docs/adr/003-aead-decrypt-layers.md`.

### Saturnin-Short (spec Section 2.3)

Short mode is a single 32-byte block: there is no separate authentication tag. Validity is established by constant-time nonce binding and padding validation over the decrypted block, then fixed-layout assembly of a candidate plaintext buffer. The public decrypt API maps that result to `Ok` or `Err(VerificationFailed)` only after the symmetric inverse and parsing work complete—the same structural pattern as full Saturnin AEAD (full symmetric decrypt work before returning plaintext versus authentication failure at the API boundary). `AeadDecryptSemantic::decrypt_semantic` is implemented for Short as well. Remote timing analyses should assume verification can influence control flow at that API boundary; callers with stricter separation requirements must mediate timing above this layer.

### Saturnin-QCB (`qcb` feature)

Saturnin-QCB (`qcb.rs`) is the one-pass AEAD from "An Update on Saturnin", built on the Saturnin
tweakable block cipher `SaturninTbc` (`tbc.rs`): `TBC_d(K,T)(M) = Saturnin16^d_{K⊕T}(M)`. Tag
verification uses the constant-time `lib_q_core::Utils::constant_time_compare`, and the full
ciphertext body is decrypted before the authentication outcome is mapped to `Ok` vs
`Err(VerificationFailed)` (Layer A) / `AuthenticationFailed` (Layer B), matching the contract of
the other Saturnin AEAD paths.

**Mode definition.** The update note describes only the TBC and the encryption path (its Figure 1
is captioned "Saturnin-QCB, *encryption*" and shows neither the tag nor the associated data). The
complete mode is **Algorithm 1** of the QCB paper (Bhaumik, Bonnetain, Chailloux, Leurent,
Naya-Plasencia, Schrottenloher and Seurin, *QCB: Efficient Quantum-secure Authenticated
Encryption*, ASIACRYPT 2021; full version IACR ePrint 2020/1304), whose *Instantiation with
Saturnin* paragraph fixes the five domain separators used here: **9** full message block, **10**
final padded message block, **11** full associated-data block, **12** final padded
associated-data block, **13** tag/checksum. `tests/qcb_spec.rs` checks `SaturninQcb::encrypt`
against an independent transcription of Algorithm 1 over a 63-case length sweep.

Every tweak carries the nonce, associated data included. The paper requires this explicitly
(Section 5, *Avoiding Quantum Attacks*: "It is important to include the IV in the tweak when
processing the AD. Otherwise, there is a quantum forgery attack based on Deutsch's algorithm.").
Releases up to and including 0.0.8 zeroed the nonce in the AD tweak, which additionally allowed a
purely classical cross-nonce associated-data-relabelling forgery under nonce reuse; both are
closed, and the change is a **wire break** — no 0.0.8 QCB ciphertext decrypts under the current
code.

**Interpretation caveat — read before relying on byte compatibility.** **No official QCB
known-answer test vectors exist.** One detail remains an explicit local choice: the paper says
only that "the IV and the block number are simply concatenated" into the 256-bit tweak, and this
module splits that 128/128 (`N ‖ 0·8 ‖ block_index_be`), whereas the paper's stated limits (IVs of
at most 160 bits, up to 2^95 blocks) are simultaneously tight only under a 160/96 split. For the
16-byte nonce this mode fixes, the two splits coincide: right-zero-padding the IV to 160 bits
(Algorithm 1 line 1) and writing a big-endian index into the low 96 bits yields
`N ‖ 0·4 ‖ be96(i)`, byte-identical to `N ‖ 0·8 ‖ be64(i)` for every `i < 2^64`. They diverge only
for an implementation that *left*-pads the IV or orders the index little-endian. Byte
compatibility with a third-party Saturnin-QCB is therefore **likely but unproven**. If/when the
designers publish QCB KATs, they must be pinned and any divergence reconciled before this mode is
treated as a standard.

## KAT validation

Implementation is validated against the reference KAT vectors (AEAD, hash, block cipher) in `tests/kat_tests.rs`. KATs are the authoritative correctness check.

Saturnin-QCB has no published designer KATs (see above); it is instead pinned to **derived
self-consistency vectors** (`qcb::tests::pinned_kat_vectors`) plus round-trip, tamper-detection,
nonce/AD-binding, and block-independence (parallelism) tests. These lock byte-level behavior so
the construction cannot drift silently, but they do **not** establish agreement with an external
reference.

## Implementation notes

The reference, KAT-validated code path is the scalar implementation (`core`, `bs32_core`).

The SIMD features (`simd`, `simd-avx2`, `simd-neon`) provide optimized paths with runtime capability detection. These optimized paths are required to remain output-equivalent to the scalar reference path and are treated as separate review scope.

## SIMD security review checklist

Before accepting SIMD changes as production-ready:

1. Run all KAT tests on scalar and SIMD feature sets and verify byte-for-byte parity.
2. Run equivalence tests (`simd_equivalence`) across randomized vectors and edge-length inputs.
3. Confirm no secret-dependent branches are introduced in S-box/MDS/round logic.
4. Confirm no secret-dependent memory access patterns are introduced (table lookups indexed by secret data are forbidden in SIMD code paths).
5. Review each `unsafe` block in SIMD modules for documented invariants (feature gating, pointer validity, load/store bounds).
6. Re-run constant-time tests for AEAD tag verification and any modified comparison code.

## Constant-time observations for current SIMD path

- SIMD kernels are implemented with fixed-latency bitwise/arithmetic and lane-shift operations.
- Runtime dispatch branches only on CPU capabilities, not on key/plaintext/ciphertext content.
- AEAD tag verification remains in `lib_q_core::Utils::constant_time_compare`.

## No formal audit

This implementation has not undergone a formal third-party security audit. Use in production should consider your threat model (e.g. exposure to timing or other side-channel adversaries) and applicable certification or compliance requirements.

## Vulnerability reporting

Report vulnerabilities per the main [lib-Q SECURITY](../SECURITY.md) or the project contact.
