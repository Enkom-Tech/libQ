# Test Coverage Requirements

lib-Q maintains strict test coverage requirements as a NIST-approved quantum-resistant cryptographic library:

- **80% line coverage** for all core cryptographic functionality
- **95% line coverage** for security-critical code paths
- **100% branch coverage** for security-critical code paths
- **Comprehensive test vectors** for all cryptographic algorithms

## Running Coverage Tests

### Windows

```powershell
# Run coverage for a specific crate
.\scripts\run-coverage.ps1 -Crate "lib-q-sponge"

# Run coverage with custom threshold
.\scripts\run-coverage.ps1 -LineThreshold 90

# Include reference implementations in coverage calculation
.\scripts\run-coverage.ps1 -NoReference:$false
```

### Linux/macOS

```bash
# Run coverage for a specific crate
./scripts/run-coverage.sh --crate lib-q-sponge

# Run coverage with custom threshold
./scripts/run-coverage.sh --threshold 90

# Include reference implementations in coverage calculation
./scripts/run-coverage.sh --with-reference
```

## Coverage Strategy

To achieve and maintain 95% test coverage:

1. **Focus on core functionality**: Prioritize testing core cryptographic operations
2. **Use Known Answer Tests (KATs)**: Validate against published test vectors
3. **Test edge cases**: Ensure error handling and boundary conditions are covered
4. **Property-based testing**: Verify cryptographic properties using randomized inputs
5. **Exclude reference implementations**: Coverage calculations should focus on our implementation

## CI Integration

The continuous integration pipeline enforces the 95% coverage threshold:

- Pull requests must maintain at least 95% test coverage
- Coverage reports are automatically generated and uploaded as artifacts
- Failed coverage checks will block PR merges

## Coverage Exclusions

Some code may be legitimately excluded from coverage requirements:

- Debug-only code paths
- Platform-specific optimizations that can't be tested in CI
- Panic handlers in no_std environments

To exclude code from coverage, use the following annotation:

```rust
#[cfg(not(tarpaulin_include))]
fn excluded_function() {
    // This function won't count against coverage
}
```