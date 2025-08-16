---
name: Bug report
about: Create a report to help us improve libQ
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ['libq/maintainers']

---

**Describe the bug**
A clear and concise description of what the bug is.

**Security Impact**
- [ ] No security impact
- [ ] Potential security vulnerability
- [ ] Confirmed security vulnerability
- [ ] Information disclosure
- [ ] Denial of service
- [ ] Cryptographic weakness

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Actual behavior**
A clear and concise description of what actually happened.

**Environment:**
 - OS: [e.g. Ubuntu 22.04, Windows 11, macOS 13]
 - Rust version: [e.g. 1.70.0]
 - libQ version: [e.g. 0.1.0]
 - Target: [e.g. x86_64-unknown-linux-gnu, wasm32-unknown-unknown]
 - Features: [e.g. "all-algorithms", "wasm"]

**Additional context**
Add any other context about the problem here.

**Cryptographic Context**
- [ ] This bug affects cryptographic operations
- [ ] This bug affects key generation
- [ ] This bug affects signature verification
- [ ] This bug affects encryption/decryption
- [ ] This bug affects hash functions
- [ ] This bug affects random number generation

**Reproducible Example**
```rust
// Please provide a minimal example that reproduces the bug
use libq::{init, Kem};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    // Your example here
    Ok(())
}
```

**Stack Trace**
```
// If applicable, paste the stack trace here
```

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Checklist**
- [ ] I have searched existing issues for duplicates
- [ ] I have provided a minimal reproducible example
- [ ] I have included all relevant environment information
- [ ] I have assessed the security impact
- [ ] I have not included any sensitive information in this report
