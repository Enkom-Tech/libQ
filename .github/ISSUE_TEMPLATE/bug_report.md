---
name: Bug report
about: Report a bug in lib-Q (Rust post-quantum crypto library)
title: '[BUG] '
labels: ['bug', 'needs-triage']
---

## Summary

One-line description of the bug.

## Security impact

- [ ] No security impact
- [ ] Possible security impact (needs review)
- [ ] Confirmed security impact — file via [Security report](https://github.com/Enkom-Tech/libQ/security/advisories/new) or this template with details

## Steps to reproduce

1. Crate and features: e.g. `lib-q-ml-kem` with `std`
2. Toolchain: e.g. `stable`, target if non-default
3. Minimal code or command that triggers the bug (or reference the example below)
4. What you observe (panic, wrong result, hang, etc.)

## Expected vs actual

- **Expected:** What correct behavior would be.
- **Actual:** What happens instead.

## Environment

| Field   | Value |
|--------|--------|
| OS     | e.g. Ubuntu 22.04, Windows 11, macOS 14 |
| Rust   | `rustc --version` |
| lib-Q  | version from Cargo.lock or crate |
| Target | e.g. x86_64-unknown-linux-gnu, wasm32-unknown-unknown |
| Features | e.g. `std`, `ml-kem`, `all-algorithms` |

## Minimal reproducible example

```rust
// Minimal code that reproduces the bug. Use the crate you're reporting against.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: lib_q_core::init()?;
    // Your code here
    Ok(())
}
```

If the bug is in build, tests, or a specific API, replace with the smallest snippet that still reproduces it.

## Cryptographic context (if applicable)

- [ ] Affects cryptographic correctness (key gen, encrypt/decrypt, sign/verify, hash)
- [ ] Affects RNG or randomness usage
- [ ] Affects constant-time or side-channel sensitivity
- [ ] No cryptographic impact

## Additional context

Logs, stack traces, or links to code paths if known. No secrets or keys.

## Checklist

- [ ] I searched existing issues for duplicates
- [ ] I provided a minimal reproducible example and environment details
- [ ] I assessed security impact; no sensitive material in the report
