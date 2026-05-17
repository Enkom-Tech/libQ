# FN-DSA no_std Guide

This guide explains how to use FN-DSA in no_std environments, such as embedded systems, bare-metal applications, and constrained environments.

## Overview

FN-DSA is fully compatible with no_std environments, providing post-quantum digital signatures without requiring the standard library. The implementation includes:

- **Custom RNG**: Fallback RNG implementation for environments without standard library
- **Memory management**: Uses `alloc` crate for dynamic allocation
- **Error handling**: no_std-compatible error types
- **Performance**: Optimized for embedded and constrained environments

## Features

### Security Levels
- **Level 1 (128-bit security)**: n=512, suitable for most embedded applications
- **Level 5 (256-bit security)**: n=1024, for high-security embedded applications

### Key Sizes
| Security Level | Sign Key | Verify Key | Signature |
|----------------|----------|------------|-----------|
| Level 1        | 1281 bytes | 897 bytes | 666 bytes |
| Level 5        | 2305 bytes | 1793 bytes | 1280 bytes |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-q-fn-dsa = { version = "0.0.2", default-features = false, features = ["no_std", "alloc"] }
```

## Basic Usage

### 1. Create an FN-DSA Instance

```rust
use lib_q_fn_dsa::FnDsa512;

let fn_dsa = FnDsa512::new();
```

### 2. Generate a Keypair

```rust
let keypair = fn_dsa.generate_keypair()?;
```

### 3. Sign a Message

```rust
let message = b"Hello, no_std!";
let signature = fn_dsa.sign(&keypair.secret_key, message)?;
```

### 4. Verify a Signature

```rust
let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
```

## no_std-Specific Considerations

### Random Number Generation

FN-DSA includes a fallback RNG implementation for no_std environments:

```rust
// Automatically handled by the library
// Uses a simple counter-based approach (NOT cryptographically secure)
// In production, replace with proper hardware RNG
```

**⚠️ Important**: The default no_std RNG is NOT cryptographically secure and should be replaced with a proper hardware RNG in production environments.

### Memory Management

The library uses the `alloc` crate for dynamic allocation:

```rust
// Requires alloc feature
// Keys and signatures are allocated on the heap
// Memory is automatically freed when objects go out of scope
```

### Error Handling

no_std-compatible error handling:

```rust
use lib_q_core::Error;

match fn_dsa.generate_keypair() {
    Ok(keypair) => {
        // Success
    }
    Err(Error::KeyGenerationFailed) => {
        // Handle key generation failure
    }
    Err(e) => {
        // Handle other errors
    }
}
```

## Advanced Usage

### Custom RNG Implementation

For production use, implement a proper hardware RNG:

```rust
use rand_core::{CryptoRng, RngCore};

struct HardwareRng {
    // Your hardware RNG implementation
}

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        // Read from hardware RNG
        // Must be cryptographically secure
        unsafe {
            // Example: read from hardware register
            core::ptr::read_volatile(0x4000_0000 as *const u32)
        }
    }
    
    fn next_u64(&mut self) -> u64 {
        let upper = self.next_u32() as u64;
        let lower = self.next_u32() as u64;
        (upper << 32) | lower
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let bytes = self.next_u32().to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HardwareRng {}
```

### Key Serialization

```rust
// Convert keys to bytes for storage/transmission
let public_key_bytes = keypair.public_key.as_bytes();
let secret_key_bytes = keypair.secret_key.as_bytes();

// Reconstruct keys from bytes
let public_key = SigPublicKey::from_bytes(public_key_bytes)?;
let secret_key = SigSecretKey::from_bytes(secret_key_bytes)?;
```

### Hex Encoding (for embedded systems)

```rust
use lib_q_fn_dsa::examples::no_std_example::nostd_utils;

// Convert to hex for embedded systems
let public_key_hex = nostd_utils::bytes_to_hex(public_key_bytes);
let signature_hex = nostd_utils::bytes_to_hex(&signature);

// Convert from hex
let public_key_bytes = nostd_utils::hex_to_bytes(&public_key_hex)?;
```

## Performance Considerations

### Embedded System Performance

- **Key Generation**: ~100-500ms (depending on hardware)
- **Signing**: ~50-200ms
- **Verification**: ~30-100ms

### Memory Usage

- **Code Size**: ~50KB (Flash)
- **RAM Usage**: ~4KB (excluding keys)
- **Stack Usage**: ~2KB (peak during operations)

### Optimization Tips

1. **Use Level 1**: Unless you need Level 5 security, use Level 1 for better performance
2. **Minimize allocations**: Reuse buffers when possible
3. **Optimize for your target**: Consider using `no_avx2` feature for non-x86 targets
4. **Use static allocation**: Consider using static buffers for keys in embedded systems

## Security Best Practices

### Key Management

```rust
// Store keys in secure storage (secure elements, TPM, etc.)
// Never log or expose secret keys
// Implement proper key zeroization
// Use hardware security modules when available
```

### Random Number Generation

```rust
// Replace default RNG with hardware RNG
// Ensure sufficient entropy
// Consider multiple entropy sources
// Implement entropy health checks
```

### Side-Channel Resistance

```rust
// The library implements constant-time operations
// Ensure your hardware RNG is side-channel resistant
// Consider power analysis resistance
// Implement proper timing attack countermeasures
```

## Embedded System Integration

### ARM Cortex-M

```rust
// For ARM Cortex-M microcontrollers
use cortex_m::peripheral;

struct CortexMRng {
    rng: peripheral::RNG,
}

impl RngCore for CortexMRng {
    fn next_u32(&mut self) -> u32 {
        // Read from ARM Cortex-M RNG peripheral
        self.rng.dr.read().bits()
    }
    
    // ... implement other methods
}
```

### RISC-V

```rust
// For RISC-V systems
struct RiscVRng {
    // Your RISC-V RNG implementation
}

impl RngCore for RiscVRng {
    fn next_u32(&mut self) -> u32 {
        // Read from RISC-V RNG implementation
        // This depends on your specific hardware
    }
    
    // ... implement other methods
}
```

### Custom Hardware

```rust
// For custom hardware with RNG
struct CustomHardwareRng {
    base_address: usize,
}

impl RngCore for CustomHardwareRng {
    fn next_u32(&mut self) -> u32 {
        unsafe {
            // Read from your custom hardware RNG
            core::ptr::read_volatile((self.base_address + 0x00) as *const u32)
        }
    }
    
    // ... implement other methods
}
```

## Memory Management

### Static Allocation

For systems with limited heap, consider static allocation:

```rust
use core::mem::MaybeUninit;

// Static buffers for keys
static mut PUBLIC_KEY_BUFFER: MaybeUninit<[u8; 897]> = MaybeUninit::uninit();
static mut SECRET_KEY_BUFFER: MaybeUninit<[u8; 1281]> = MaybeUninit::uninit();

fn generate_static_keypair() -> Result<(), Error> {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;
    
    unsafe {
        PUBLIC_KEY_BUFFER.write(keypair.public_key.as_bytes().try_into().unwrap());
        SECRET_KEY_BUFFER.write(keypair.secret_key.as_bytes().try_into().unwrap());
    }
    
    Ok(())
}
```

### Heap Management

For systems with heap:

```rust
// The library automatically manages heap allocation
// Keys and signatures are allocated as needed
// Memory is freed when objects go out of scope
```

## Error Handling

### Custom Error Types

```rust
use lib_q_core::Error;

#[derive(Debug)]
pub enum EmbeddedError {
    FnDsa(Error),
    HardwareRng,
    MemoryAllocation,
    InvalidInput,
}

impl From<Error> for EmbeddedError {
    fn from(error: Error) -> Self {
        EmbeddedError::FnDsa(error)
    }
}
```

### Error Recovery

```rust
fn robust_key_generation() -> Result<SigKeypair, EmbeddedError> {
    let fn_dsa = FnDsa512::new();
    
    // Try multiple times if needed
    for _ in 0..3 {
        match fn_dsa.generate_keypair() {
            Ok(keypair) => return Ok(keypair),
            Err(Error::KeyGenerationFailed) => {
                // Wait and retry
                // Implement your delay mechanism
                continue;
            }
            Err(e) => return Err(EmbeddedError::from(e)),
        }
    }
    
    Err(EmbeddedError::HardwareRng)
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair().unwrap();
        
        // Test key sizes
        let (sign_size, vrfy_size, _) = fn_dsa.get_key_sizes();
        assert_eq!(keypair.secret_key.as_bytes().len(), sign_size);
        assert_eq!(keypair.public_key.as_bytes().len(), vrfy_size);
    }
    
    #[test]
    fn test_sign_verify() {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair().unwrap();
        
        let message = b"Test message";
        let signature = fn_dsa.sign(&keypair.secret_key, message).unwrap();
        let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature).unwrap();
        
        assert!(is_valid);
    }
}
```

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_full_workflow() {
        let fn_dsa = FnDsa512::new();
        
        // Generate keypair
        let keypair = fn_dsa.generate_keypair().unwrap();
        
        // Sign multiple messages
        let messages = [b"Message 1", b"Message 2", b"Message 3"];
        let mut signatures = Vec::new();
        
        for message in &messages {
            let signature = fn_dsa.sign(&keypair.secret_key, message).unwrap();
            signatures.push(signature);
        }
        
        // Verify all signatures
        for (message, signature) in messages.iter().zip(signatures.iter()) {
            let is_valid = fn_dsa.verify(&keypair.public_key, message, signature).unwrap();
            assert!(is_valid);
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **RNG not available**: Implement proper hardware RNG
2. **Memory errors**: Check heap size and allocation limits
3. **Performance issues**: Consider using `no_avx2` feature for non-x86 targets
4. **Build errors**: Ensure proper feature flags are set

### Debug Mode

```rust
// Enable debug logging (development only)
#[cfg(debug_assertions)]
// Implement your debug logging mechanism
```

### Error Handling

```rust
use lib_q_core::Error;

fn handle_error(error: Error) -> &'static str {
    match error {
        Error::InvalidKeySize { .. } => "Key size mismatch",
        Error::VerificationFailed => "Signature verification failed",
        Error::KeyGenerationFailed => "Key generation failed",
        _ => "Unknown error occurred",
    }
}
```

## Examples

See the `examples/no_std_example.rs` file for a complete working example.

## Further Reading

- [Rust Embedded Book](https://docs.rust-embedded.org/book/)
- [no_std Rust](https://docs.rust-embedded.org/book/intro/no-std.html)
- [FN-DSA Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.206.pdf)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Embedded Security Best Practices](https://www.nist.gov/publications/guidelines-evaluating-side-channel-attack-resistance-embedded-systems)
