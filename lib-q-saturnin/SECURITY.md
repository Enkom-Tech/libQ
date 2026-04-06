# Security

## Constant-time requirements

Tag verification in AEAD decrypt uses constant-time comparison (`lib_q_core::Utils::constant_time_compare`). No secret-dependent branches or short-circuit comparisons on tags or keys in the public API. The `constant_time` test binary verifies this usage.

## KAT validation

Implementation is validated against the reference KAT vectors (AEAD, hash, block cipher) in `tests/kat_tests.rs`. KATs are the authoritative correctness check.

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
