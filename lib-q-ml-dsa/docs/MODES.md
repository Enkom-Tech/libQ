# ML-DSA Operating Modes

This document describes the different operating modes available in the ML-DSA implementation, each designed for specific use cases and security requirements.

## Overview

The ML-DSA implementation supports two distinct operating modes:

1. **FIPS Mode** (`fips-mode` feature) - For NIST FIPS 204 compliance
2. **Hardened Mode** (`hardened` feature) - For enhanced security deployments

## FIPS Mode (`fips-mode` feature)

### When to Use

- Seeking NIST FIPS 204 certification
- Interoperability with other FIPS-compliant implementations required
- Minimal overhead needed
- Operating in controlled/trusted environment
- Compliance with government or regulatory requirements

### Characteristics

- **Direct SHAKE128/256 usage** per FIPS 204 specification
- **No additional RNG abstraction overhead**
- **Bit-for-bit compatible** with NIST reference implementation
- **Validated against ACVP test vectors**
- **Minimal memory footprint**
- **Maximum performance** for compliance scenarios

### Implementation Details

FIPS mode uses the exact algorithms specified in FIPS 204:
- Direct SHAKE128/256 calls for internal randomness
- Standard polynomial operations without additional security measures
- Minimal abstraction layers for maximum compatibility

### Usage

```toml
[dependencies]
lib-q-ml-dsa = { version = "0.0.2", features = ["fips-mode", "mldsa44"] }
```

## Hardened Mode (`hardened` feature)

### When to Use

- Operating in adversarial environment
- Defense-in-depth security required
- Side-channel resistance needed
- Memory safety critical
- High-security deployments
- Zero-trust environments

### Characteristics

- **RNG abstraction** via lib-q-random
- **Automatic zeroization** of sensitive material
- **Constant-time operations** where possible
- **Enhanced entropy validation**
- **Memory protection** against side-channel attacks
- **Suitable for high-security deployments**

### Implementation Details

Hardened mode includes additional security measures:
- All randomness goes through `MLDsaRng` abstraction
- Automatic zeroization of sensitive buffers using `zeroize` crate
- Constant-time operations using `subtle` crate
- Enhanced entropy quality validation
- Protection against timing attacks

**NIST signature KATs (`tests/nistkats.rs`):** with feature `hardened`, the signing key is still wired
through the dual-share control-flow, but the secondary share is currently the **zero** ring element so
intermediate values match the reference implementation and **byte-for-byte KAT hashes hold**. SHAKE256
material is still squeezed for that staged share to keep the absorb/squeeze pattern amenable to
timing analysis; replacing the zero share with a real time-domain split is future masked-`skDecode`
work.

**`Decompose` / `MakeHint`:** the portable path uses `subtle`-based comparisons for the high-`r₁`
branches implicated by GHSA-hcp2-x6j4-29j7, and hint application routes through the constant-time
`use_one_hint` implementation. Polynomials fed to `make_hint` are the combined (`·_a` + `·_b`) values
from the signing loop; arithmetic masking of `w0` itself is not claimed—only branch/data-path
hardening at the SIMD decomposition and hint primitives.

### Usage

```toml
[dependencies]
lib-q-ml-dsa = { version = "0.0.2", features = ["hardened", "mldsa44"] }
```

## Feature Dependencies

### FIPS Mode Dependencies

```toml
fips-mode = []  # No additional dependencies
```

### Hardened Mode Dependencies

```toml
# Atomic gate (do not enable piecemeal):
hardened = ["random", "zeroize", "dep:subtle", "dep:getrandom"]
zeroize = ["dep:zeroize"]
```

## Migration Guide

### Switching from FIPS to Hardened Mode

1. **Update Cargo.toml**:
   ```toml
   # Before
   features = ["fips-mode", "mldsa44"]
   
   # After
   features = ["hardened", "mldsa44"]
   ```

2. **API remains identical** - no code changes required
3. **Performance impact** - hardened mode has slightly higher overhead
4. **Security improvement** - enhanced protection against side-channel attacks

### Switching from Hardened to FIPS Mode

1. **Update Cargo.toml**:
   ```toml
   # Before
   features = ["hardened", "mldsa44"]
   
   # After
   features = ["fips-mode", "mldsa44"]
   ```

2. **API remains identical** - no code changes required
3. **Performance improvement** - reduced overhead
4. **Compliance focus** - strict adherence to FIPS 204

## Security Considerations

### FIPS Mode Security

- **Compliance-focused**: Optimized for NIST certification
- **Standard algorithms**: Uses FIPS 204 specified methods
- **Minimal attack surface**: Fewer abstraction layers
- **Performance-optimized**: Maximum speed for compliance scenarios

### Hardened Mode Security

- **Defense-in-depth**: Multiple layers of security
- **Side-channel resistant**: Constant-time operations
- **Memory-safe**: Automatic zeroization
- **Entropy-validated**: Enhanced randomness quality checks
- **Audit-friendly**: Clear separation of security concerns

## Performance Comparison

| Aspect | FIPS Mode | Hardened Mode |
|--------|-----------|---------------|
| **Speed** | Maximum | Slightly reduced |
| **Memory** | Minimal | Additional buffers |
| **Security** | Standard | Enhanced |
| **Compliance** | NIST FIPS 204 | NIST + Additional |
| **Use Case** | Certification | Production Security |

## Testing

### FIPS Mode Testing

```bash
# Test FIPS compliance
cargo test --features "fips-mode,mldsa44,mldsa65,mldsa87"

# Test against NIST vectors
cargo test --features "fips-mode,acvp" --test acvp
```

### Hardened Mode Testing

```bash
# Test hardened security features
cargo test --features "hardened,mldsa44,mldsa65,mldsa87"

# Test entropy quality
cargo test --features "hardened,random" --test entropy_quality

# Test determinism
cargo test --features "hardened,random,acvp" --test determinism
```

## Best Practices

### For FIPS Mode

1. **Use for compliance** scenarios where NIST certification is required
2. **Validate against ACVP** test vectors regularly
3. **Monitor for updates** to FIPS 204 specification
4. **Document compliance** status clearly

### For Hardened Mode

1. **Use for production** deployments in adversarial environments
2. **Regular security audits** of the implementation
3. **Monitor entropy sources** for quality and availability
4. **Test side-channel resistance** in target environment

## Troubleshooting

### Common Issues

1. **Feature conflicts**: Ensure only one mode is enabled at a time
2. **Dependency issues**: Check that all required dependencies are available
3. **Performance concerns**: Choose appropriate mode for use case
4. **Compliance questions**: Verify mode selection meets requirements

### Getting Help

- Check test outputs for specific error messages
- Review feature documentation for requirements
- Consult security team for mode selection guidance
- Validate against NIST test vectors for compliance issues

## Interoperability Between Modes

All ML-DSA modes are **fully interoperable**:

- Keys generated in compliance mode work with signatures from hardened mode
- Signatures created in production mode verify in compliance mode
- Wire formats are identical across all modes

See [INTEROPERABILITY.md](INTEROPERABILITY.md) for details and testing procedures.
