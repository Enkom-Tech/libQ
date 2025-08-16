## Description
Brief description of changes made in this PR.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security enhancement
- [ ] Refactoring (no functional changes)

## Security Impact Assessment
- [ ] No security impact
- [ ] Improves security
- [ ] Potential security risk (explain below)
- [ ] Addresses security vulnerability

**If potential security risk, explain:**
<!-- Describe any potential security implications -->

## Cryptographic Validation
- [ ] No changes to cryptographic algorithms
- [ ] Only uses NIST-approved post-quantum algorithms
- [ ] Only uses SHA-3 family hash functions
- [ ] All operations are constant-time
- [ ] Proper memory zeroization implemented
- [ ] Input validation is comprehensive
- [ ] Error handling is secure
- [ ] No classical cryptographic algorithms introduced

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Property-based tests added/updated
- [ ] Constant-time tests added/updated
- [ ] WASM tests pass
- [ ] Cross-platform tests pass
- [ ] Performance benchmarks updated
- [ ] Security tests added/updated

## Documentation
- [ ] API documentation updated
- [ ] README examples updated
- [ ] Security considerations documented
- [ ] Breaking changes documented
- [ ] Migration guide provided (if breaking change)

## Code Quality
- [ ] Code follows Rust style guidelines
- [ ] `cargo fmt` run
- [ ] `cargo clippy` passes with no warnings
- [ ] No unsafe code added (or thoroughly justified)
- [ ] Error handling is comprehensive
- [ ] Logging is appropriate (no sensitive data)

## Performance
- [ ] No performance regression
- [ ] Performance benchmarks added/updated
- [ ] Memory usage optimized
- [ ] WASM performance acceptable

## Checklist
- [ ] I have read and followed the [Contributing Guidelines](CONTRIBUTING.md)
- [ ] I have tested my changes thoroughly
- [ ] I have ensured all tests pass
- [ ] I have updated documentation as needed
- [ ] I have considered the security implications
- [ ] I have not introduced any classical cryptographic algorithms
- [ ] I have verified constant-time properties where applicable
- [ ] I have properly zeroized sensitive memory
- [ ] I have validated all inputs
- [ ] I have handled errors securely

## Breaking Changes
<!-- If this is a breaking change, describe what breaks and how to migrate -->

## Related Issues
<!-- Link to any related issues -->
Closes #(issue number)

## Additional Notes
<!-- Any additional information that reviewers should know -->

## Security Review Checklist for Reviewers
- [ ] No classical cryptographic algorithms introduced
- [ ] Only SHA-3 family hash functions used
- [ ] All cryptographic operations are constant-time
- [ ] Memory is properly zeroized
- [ ] Input validation is comprehensive
- [ ] Error handling is secure
- [ ] No unsafe code (or thoroughly justified)
- [ ] No side-channel vulnerabilities introduced
- [ ] No information disclosure vulnerabilities
- [ ] Proper use of random number generation
