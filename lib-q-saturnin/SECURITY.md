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

**Interpretation caveat — we may be one byte wrong, and it is the tweak.** **No official QCB
known-answer test vectors exist** (the round-2 NIST-LWC package ships ctr-cascade, short and hash,
and no QCB). The paper says only that "the IV and the block number are simply concatenated" into
the 256-bit tweak, and Algorithm 1 line 1 says only "Pad the initialization vector if necessary" —
no padding direction, no field widths, no endianness stated anywhere in the document.

This module builds `N ‖ 0·8 ‖ block_index_be`, i.e. **byte 16 = `0x00`**. Reading the padding as
the Saturnin submission's `10*` rule instead gives a 161-bit IV field and a 95-bit index, i.e.
**byte 16 = `0x80`** — a one-byte difference on every TBC call of every message. **That second
reading is better supported than the one implemented here.** The Saturnin submission states `10*`
as the general rule for padding any sub-256-bit value into a 256-bit block, covering "our proposed
modes", and works this exact shape byte by byte: a 128-bit nonce gives "the 16 bytes of the nonce,
followed by a byte of value `0x80` … followed by one byte of value `0x01`".

An earlier version of this note said the paper's limits "are simultaneously tight only under a
160/96 split". **That is backwards** — a 96-bit index field addresses 2^96, leaving the stated 2^95
bound slack by a factor of two. Both numbers are exactly tight under 161/95. The paper's own
TRAX-QCB accounting ("3 bits … for domain separation, 80 bits of IV and 45 bits of block numbering
… at most 2^45 − 1 blocks") shows fields summing exactly to the tweak width; here 160 + 95 = 255
leaves one bit unaccounted for, and the `10*` pad bit is exactly it.

Byte compatibility with a paper-conformant Saturnin-QCB is therefore **unlikely, not "likely but
unproven"** — and in any case unreachable, because this mode emits the CTX tag `T'` rather than
Algorithm 1's `T`. There is no security consequence (byte 16 is constant either way, and the tweak
is XORed into the key, so the readings differ by a fixed key offset). The consequence is for
hardware: silicon that bakes in `0x00` cannot be corrected if the designers confirm `0x80`.
Decision: card `t_5d1460b7`. Question to the designers: card `t_7123c738`. If/when they publish
QCB KATs, pin them and reconcile before treating this mode as a standard.

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
