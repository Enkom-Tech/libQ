# ML-DSA Security Audit Checklist

## Cryptographic Correctness

- [ ] All NIST FIPS 204 test vectors pass (keygen, siggen, sigver)
- [ ] ACVP test vectors pass for all parameter sets
- [ ] SIMD and portable implementations produce identical outputs
- [ ] Deterministic: same seed always produces same output
- [ ] Rejection sampling correctly implements FIPS 204 bounds
- [ ] Message representative derivation matches FIPS 204 Algorithm 2
- [ ] Signature encoding/decoding is bijective

## Entropy and Randomness

- [ ] All entropy sources properly validated
- [ ] RNG integration uses lib-q-random correctly
- [ ] No direct SHAKE usage bypassing RNG in hardened mode
- [ ] Entropy quality tests pass (non-duplicate, distribution)
- [ ] NIST DRBG mode works for KAT compatibility

## Side-Channel Resistance (Hardened Mode)

- [ ] Sensitive data zeroized after use (when zeroize feature enabled)
- [ ] Constant-time operations where possible (when constant-time enabled)
- [ ] No timing variations based on secret values
- [ ] No branching on secret data in critical paths

## Memory Safety

- [ ] No unsafe code with undefined behavior
- [ ] All array accesses bounds-checked
- [ ] No use-after-free or double-free issues
- [ ] Proper handling of uninitialized memory

## API Security

- [ ] Public API prevents misuse
- [ ] Clear separation between signing and verification keys
- [ ] Signature verification rejects invalid signatures
- [ ] No key recovery from signatures

## Implementation Quality

- [ ] All lints pass (cargo clippy)
- [ ] No compiler warnings
- [ ] Code coverage >80% for critical paths
- [ ] Documentation complete and accurate

## External Validation Requirements

### Timing Analysis
- [ ] Use Dudect or similar for constant-time validation
- [ ] Verify no timing variations based on secret values
- [ ] Test on multiple platforms and architectures

### Side-Channel Testing
- [ ] Power analysis on target hardware
- [ ] Electromagnetic emanation testing
- [ ] Cache timing analysis

### Fuzzing
- [ ] AFL++ or libFuzzer on parsing and signature verification
- [ ] Test with malformed inputs
- [ ] Test with edge case values

### Code Review
- [ ] External cryptographic expert review
- [ ] Security-focused code review
- [ ] Architecture review

### NIST Submission
- [ ] Submit for ACVP validation if seeking certification
- [ ] Pass all NIST test vectors
- [ ] Meet FIPS 204 compliance requirements

## Release Readiness Criteria

Before declaring implementation-complete:

1. All 30+ test suites passing (SIGGEN, mode tests, determinism, NIST comparison)
2. NIST FIPS 204 KAT vectors pass for all parameter sets
3. SIMD-portable byte-for-byte equivalence verified
4. Security audit checklist 100% complete
5. Documentation reviewed and published
6. CI pipeline passing on all platforms
7. External code review completed
8. No high-severity issues in cargo audit

## Automated Checks

The following automated checks are available:

```bash
# Run security audit script
./scripts/security_audit.sh

# Run specific security tests
cargo test --package lib-q-ml-dsa --features "hardened-mode,zeroize,constant-time" --test hardened_mode_tests

# Run compliance tests
cargo test --package lib-q-ml-dsa --features "fips-mode,acvp" --test fips_mode_tests

# Run determinism tests
cargo test --package lib-q-ml-dsa --features "simd256,random,acvp" --test determinism

# Run NIST comparison tests
cargo test --package lib-q-ml-dsa --features "fips-mode,acvp" --test nist_comparison
```
