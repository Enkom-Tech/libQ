# Security

## Constant-time requirements

Tag verification in AEAD decrypt uses constant-time comparison (`lib_q_core::Utils::constant_time_compare`). No secret-dependent branches or short-circuit comparisons on tags or keys in the public API. The `constant_time` test binary verifies this usage.

## KAT validation

Implementation is validated against the reference KAT vectors (AEAD, hash, block cipher) in `tests/kat_tests.rs`. KATs are the authoritative correctness check.

## Implementation notes

The reference, KAT-validated code path is the scalar implementation (`core`, `bs32_core`). Optional features `simd`, `lookup-tables`, `parallel`, and `assembly` currently delegate to that scalar implementation; they are performance hooks, not separate auditable paths.

## No formal audit

This implementation has not undergone a formal third-party security audit. Use in production should consider your threat model (e.g. exposure to timing or other side-channel adversaries) and applicable certification or compliance requirements.

## Vulnerability reporting

Report vulnerabilities per the main [lib-Q SECURITY](../SECURITY.md) or the project contact.
