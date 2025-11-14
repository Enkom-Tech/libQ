# ML-DSA Operating Modes

This document describes the different operating modes available in the ML-DSA implementation, each designed for specific use cases and security requirements.

## Overview

The ML-DSA implementation supports two distinct operating modes:

1. **FIPS Mode** (`fips-mode` feature) - For NIST FIPS 204 compliance
2. **Hardened Mode** (`hardened-mode` feature) - For enhanced security deployments

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

## Hardened Mode (`hardened-mode` feature)

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

### Usage

```toml
[dependencies]
lib-q-ml-dsa = { version = "0.0.2", features = ["hardened-mode", "mldsa44"] }
```

## Feature Dependencies

### FIPS Mode Dependencies

```toml
fips-mode = []  # No additional dependencies
```

### Hardened Mode Dependencies

```toml
hardened-mode = ["random", "zeroize", "constant-time"]
zeroize = ["dep:zeroize"]        # Automatic memory clearing
constant-time = ["dep:subtle"]   # Constant-time operations
```

## Migration Guide

### Switching from FIPS to Hardened Mode

1. **Update Cargo.toml**:
   ```toml
   # Before
   features = ["fips-mode", "mldsa44"]
   
   # After
   features = ["hardened-mode", "mldsa44"]
   ```

2. **API remains identical** - no code changes required
3. **Performance impact** - hardened mode has slightly higher overhead
4. **Security improvement** - enhanced protection against side-channel attacks

### Switching from Hardened to FIPS Mode

1. **Update Cargo.toml**:
   ```toml
   # Before
   features = ["hardened-mode", "mldsa44"]
   
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
cargo test --features "hardened-mode,mldsa44,mldsa65,mldsa87"

# Test entropy quality
cargo test --features "hardened-mode,random" --test entropy_quality

# Test determinism
cargo test --features "hardened-mode,random,acvp" --test determinism
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
