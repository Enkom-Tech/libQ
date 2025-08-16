---
name: Security report
about: Report a security vulnerability in libQ
title: '[SECURITY] '
labels: ['security', 'confidential']
assignees: ['libq/security-team']

---

**Security Vulnerability Report**

**IMPORTANT**: This issue will be kept confidential until the vulnerability is resolved.

**Vulnerability Type**
- [ ] Cryptographic weakness
- [ ] Side-channel attack
- [ ] Memory safety issue
- [ ] Information disclosure
- [ ] Denial of service
- [ ] Timing attack
- [ ] Other (please specify)

**Severity**
- [ ] Critical (immediate fix required)
- [ ] High (fix within 24 hours)
- [ ] Medium (fix within 1 week)
- [ ] Low (fix within 1 month)

**Affected Components**
- [ ] Key Encapsulation Mechanisms (KEMs)
- [ ] Digital Signatures
- [ ] Hash Functions
- [ ] Authenticated Encryption (AEAD)
- [ ] Zero-Knowledge Proofs (ZKPs)
- [ ] Random Number Generation
- [ ] Memory Management
- [ ] WASM Implementation
- [ ] Other (please specify)

**Description**
A clear and concise description of the vulnerability.

**Impact Assessment**
Describe the potential impact of this vulnerability:
- What can an attacker do?
- What data is at risk?
- What systems are affected?

**Proof of Concept**
```rust
// If possible, provide a proof of concept
// DO NOT include actual attack code that could be harmful
use libq::{init, Kem};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    // Describe the vulnerability here
    Ok(())
}
```

**Steps to Reproduce**
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See vulnerability

**Expected Behavior**
What should happen in a secure implementation.

**Actual Behavior**
What actually happens that makes this a vulnerability.

**Environment**
 - OS: [e.g. Ubuntu 22.04, Windows 11, macOS 13]
 - Rust version: [e.g. 1.70.0]
 - libQ version: [e.g. 0.1.0]
 - Target: [e.g. x86_64-unknown-linux-gnu, wasm32-unknown-unknown]
 - Features: [e.g. "all-algorithms", "wasm"]

**Additional Context**
Add any other context about the vulnerability here.

**Mitigation**
If you have suggestions for how to fix this vulnerability, please describe them.

**Disclosure Timeline**
- [ ] I agree to responsible disclosure
- [ ] I will not publicly disclose this vulnerability until it's fixed
- [ ] I understand this will be kept confidential

**Contact Information**
- Name: [Optional]
- Email: [Optional]
- PGP Key: [Optional]

**Checklist**
- [ ] I have verified this is a real vulnerability
- [ ] I have provided sufficient details for reproduction
- [ ] I have assessed the severity appropriately
- [ ] I have not included any harmful code
- [ ] I agree to responsible disclosure practices
