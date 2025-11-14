# ML-DSA Interoperability Guide

## Wire-Format Compatibility Guarantee

The lib-q-ml-dsa implementation guarantees wire-format compatibility across all operational modes:

- Compliance Mode (no `random` feature)
- Production Mode (`random` feature enabled)
- Hardened Mode (`hardened-mode`, `zeroize`, `constant-time`)

### Guarantee

Systems running different modes can interoperate because:

1. All modes use identical FIPS 204 SHAKE-based operations
2. Key serialization format is mode-independent
3. Signature format is mode-independent
4. Verification logic is mode-independent

### Current Behavior (as of v0.0.2)

All modes produce **byte-for-byte identical outputs** given the same inputs:
- Same seed → Same keys
- Same signing inputs → Same signature
- Verification works across all mode combinations

### Testing

Run interoperability tests:

```bash
# Verify compliance mode
cargo test --package lib-q-ml-dsa --no-default-features \
  --features "std,mldsa44" --test interoperability_tests

# Verify production mode
cargo test --package lib-q-ml-dsa \
  --features "random,mldsa44" --test interoperability_tests

# Verify wire format stability
cargo test --package lib-q-ml-dsa --test wire_format_tests
```

### Regression Protection

The test suite includes saved test vectors (`tests/test_vectors/interop_vectors.json`) that lock in the current wire format. Any changes that break compatibility will fail these tests.

## Future Changes

If internal RNG usage changes in future versions (e.g., hardened mode generates randomness internally), the public API will ensure wire-format compatibility is maintained.
