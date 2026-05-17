---
name: Security report
about: Report a security vulnerability in lib-Q
title: '[SECURITY] '
labels: ['security', 'confidential']
---

**Prefer private disclosure for sensitive issues.**  
Use [GitHub Security Advisories](https://github.com/Enkom-Tech/libQ/security/advisories/new) so the report stays private until a fix is ready. This template is for coordinated disclosure; opening a public issue makes the report visible to everyone.

---

## Vulnerability type

- [ ] Cryptographic weakness (e.g. key recovery, forgery)
- [ ] Side-channel or timing attack
- [ ] Memory safety (use-after-free, leak of sensitive data)
- [ ] Information disclosure
- [ ] Denial of service
- [ ] Other (describe below)

## Severity

- [ ] Critical — exploitable, serious impact; immediate fix
- [ ] High — fix within days
- [ ] Medium — fix within a release cycle
- [ ] Low — fix when practical

## Affected components

- [ ] KEM (e.g. ML-KEM, HQC, CB-KEM)
- [ ] Signatures (e.g. ML-DSA, FN-DSA, SLH-DSA)
- [ ] Hash (SHA-3, SHAKE, K12, etc.)
- [ ] AEAD / symmetric
- [ ] ZKP
- [ ] RNG
- [ ] WASM bindings or build
- [ ] Other (specify)

## Description

Clear description of the vulnerability and how it violates security assumptions.

## Impact

- What can an attacker do?
- What data or systems are at risk?
- Under what conditions is it exploitable?

## Proof of concept

```rust
// Minimal PoC that demonstrates the issue. Do not include weaponized exploit code.
// Prefer assertions or outputs that show the vulnerability.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Steps that trigger the vulnerability
    Ok(())
}
```

## Steps to reproduce

1. Crate(s) and features used
2. Build/test command or code path
3. Inputs or configuration that trigger the issue
4. Observed vs expected (e.g. invalid ciphertext accepted, timing difference, etc.)

## Environment

| Field   | Value |
|--------|--------|
| OS     | |
| Rust   | |
| lib-Q  | version |
| Target | |
| Features | |

## Suggested mitigation

If you have ideas for a fix or hardening (e.g. constant-time, validation), describe them here.

## Disclosure

- [ ] I will follow responsible disclosure and not disclose publicly before a fix is available
- [ ] I have not included harmful or weaponized code in this report

## Contact (optional)

- Email or preferred contact for follow-up
- PGP key fingerprint if you use encrypted communication
