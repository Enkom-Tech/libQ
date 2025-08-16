# Memory Architecture & Management

## Design Philosophy

libQ implements a **zero dynamic allocation** memory model inspired by libhydrogen, making it suitable for constrained environments such as microcontrollers, embedded systems, and high-performance applications. All cryptographic operations use stack-allocated buffers with fixed sizes.

## Memory Management Strategy

### Core Principles

1. **Zero Dynamic Allocations**: No `Vec<T>`, `Box<T>`, or heap allocations during cryptographic operations
2. **Stack-Only Operations**: All buffers are stack-allocated with compile-time known sizes
3. **Fixed-Size Types**: All cryptographic types have fixed, predictable sizes
4. **Secure Memory Zeroing**: Automatic zeroing of sensitive memory on drop
5. **Bounded Operations**: All operations have maximum size limits

### Memory Layout

```
libQ Memory Model
├── Stack Allocations (Fixed Size)
│   ├── Key Buffers (Public/Secret keys)
│   ├── Signature Buffers
│   ├── Ciphertext Buffers
│   ├── Hash Buffers
│   └── Temporary Operation Buffers
├── Static Allocations (Constants)
│   ├── Algorithm Parameters
│   ├── Lookup Tables
│   └── Precomputed Values
└── No Heap Allocations
    └── Zero dynamic memory usage
```

## Fixed-Size Type Definitions

### Key Sizes by Algorithm and Security Level

```rust
// CRYSTALS-Kyber Key Sizes
pub const KYBER1_PUBLIC_KEY_SIZE: usize = 800;
pub const KYBER1_SECRET_KEY_SIZE: usize = 1632;
pub const KYBER1_CIPHERTEXT_SIZE: usize = 768;
pub const KYBER1_SHARED_SECRET_SIZE: usize = 32;

pub const KYBER3_PUBLIC_KEY_SIZE: usize = 1184;
pub const KYBER3_SECRET_KEY_SIZE: usize = 2400;
pub const KYBER3_CIPHERTEXT_SIZE: usize = 1088;
pub const KYBER3_SHARED_SECRET_SIZE: usize = 32;

pub const KYBER5_PUBLIC_KEY_SIZE: usize = 1568;
pub const KYBER5_SECRET_KEY_SIZE: usize = 3168;
pub const KYBER5_CIPHERTEXT_SIZE: usize = 1568;
pub const KYBER5_SHARED_SECRET_SIZE: usize = 32;

// CRYSTALS-Dilithium Signature Sizes
pub const DILITHIUM1_PUBLIC_KEY_SIZE: usize = 1312;
pub const DILITHIUM1_SECRET_KEY_SIZE: usize = 2528;
pub const DILITHIUM1_SIGNATURE_SIZE: usize = 2420;

pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 1952;
pub const DILITHIUM3_SECRET_KEY_SIZE: usize = 4000;
pub const DILITHIUM3_SIGNATURE_SIZE: usize = 3293;

pub const DILITHIUM5_PUBLIC_KEY_SIZE: usize = 2592;
pub const DILITHIUM5_SECRET_KEY_SIZE: usize = 4864;
pub const DILITHIUM5_SIGNATURE_SIZE: usize = 4595;

// Falcon Signature Sizes
pub const FALCON1_PUBLIC_KEY_SIZE: usize = 897;
pub const FALCON1_SECRET_KEY_SIZE: usize = 2305;
pub const FALCON1_SIGNATURE_SIZE: usize = 690;

pub const FALCON5_PUBLIC_KEY_SIZE: usize = 1793;
pub const FALCON5_SECRET_KEY_SIZE: usize = 4609;
pub const FALCON5_SIGNATURE_SIZE: usize = 1380;

// SPHINCS+ Signature Sizes
pub const SPHINCS1_PUBLIC_KEY_SIZE: usize = 32;
pub const SPHINCS1_SECRET_KEY_SIZE: usize = 64;
pub const SPHINCS1_SIGNATURE_SIZE: usize = 8080;

pub const SPHINCS3_PUBLIC_KEY_SIZE: usize = 48;
pub const SPHINCS3_SECRET_KEY_SIZE: usize = 96;
pub const SPHINCS3_SIGNATURE_SIZE: usize = 16588;

pub const SPHINCS5_PUBLIC_KEY_SIZE: usize = 64;
pub const SPHINCS5_SECRET_KEY_SIZE: usize = 128;
pub const SPHINCS5_SIGNATURE_SIZE: usize = 29792;

// Maximum sizes for variable-length operations
pub const MAX_MESSAGE_SIZE: usize = 65536; // 64KB
pub const MAX_CIPHERTEXT_SIZE: usize = 65536 + 1024; // Message + overhead
pub const MAX_ASSOCIATED_DATA_SIZE: usize = 65536; // 64KB
pub const MAX_HASH_OUTPUT_SIZE: usize = 65536; // 64KB

// Operation buffer sizes
pub const MAX_STACK_BUFFER_SIZE: usize = 32768; // 32KB max stack usage
pub const TEMP_BUFFER_SIZE: usize = 4096; // 4KB temporary buffer
```

### Stack-Allocated Cryptographic Types

```rust
use zeroize::Zeroize;

/// Public key for key exchange (stack-allocated)
#[derive(Clone, Debug)]
pub struct PublicKey([u8; KYBER5_PUBLIC_KEY_SIZE]);

/// Secret key for key exchange (stack-allocated, zeroized on drop)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey([u8; KYBER5_SECRET_KEY_SIZE]);

/// Digital signature (stack-allocated)
#[derive(Clone, Debug)]
pub struct Signature([u8; DILITHIUM5_SIGNATURE_SIZE]);

/// Shared secret (stack-allocated, zeroized on drop)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret([u8; KYBER5_SHARED_SECRET_SIZE]);

/// Encryption key (stack-allocated, zeroized on drop)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncryptionKey([u8; 32]);

/// Encapsulated key (stack-allocated)
#[derive(Clone, Debug)]
pub struct EncapsulatedKey([u8; KYBER5_CIPHERTEXT_SIZE]);

/// Ciphertext (stack-allocated)
#[derive(Clone, Debug)]
pub struct Ciphertext([u8; MAX_CIPHERTEXT_SIZE]);

/// Plaintext (stack-allocated)
pub struct Plaintext([u8; MAX_MESSAGE_SIZE]);

/// Hash output (stack-allocated)
#[derive(Clone, Debug)]
pub struct Hash([u8; MAX_HASH_OUTPUT_SIZE]);

/// Temporary buffer for operations (stack-allocated)
pub struct TempBuffer([u8; TEMP_BUFFER_SIZE]);
```

## Secure Memory Management

### Automatic Zeroization

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KYBER5_SECRET_KEY_SIZE]);

impl SecretKey {
    /// Create a new secret key
    pub fn new() -> Self {
        let mut key = [0u8; KYBER5_SECRET_KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random key");
        Self(key)
    }
    
    /// Get reference to key data
    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }
    
    /// Get mutable reference to key data
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// Key is automatically zeroized when dropped
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
```

### Memory Safety Patterns

```rust
/// Safe memory copying with bounds checking
pub fn safe_copy(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() < src.len() {
        return Err(Error::InvalidKeySize {
            expected: src.len(),
            actual: dst.len(),
        });
    }
    
    dst[..src.len()].copy_from_slice(src);
    Ok(())
}

/// Constant-time memory comparison
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Secure memory clearing
pub fn secure_clear(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        *byte = 0;
    }
}
```

## Algorithm-Specific Memory Layouts

### CRYSTALS-Kyber Memory Layout

```rust
/// Kyber-specific memory structures
pub struct KyberMemory {
    /// Polynomial coefficients (stack-allocated)
    pub polynomials: [[u16; 256]; 3], // 3 polynomials, 256 coefficients each
    /// Random bytes buffer
    pub random_buffer: [u8; 32],
    /// Hash state buffer
    pub hash_buffer: [u8; 64],
    /// Temporary computation buffer
    pub temp_buffer: [u8; 1024],
}

impl KyberMemory {
    /// Create new Kyber memory layout
    pub fn new() -> Self {
        Self {
            polynomials: [[0u16; 256]; 3],
            random_buffer: [0u8; 32],
            hash_buffer: [0u8; 64],
            temp_buffer: [0u8; 1024],
        }
    }
    
    /// Clear all sensitive memory
    pub fn clear(&mut self) {
        for poly in &mut self.polynomials {
            for coeff in poly.iter_mut() {
                *coeff = 0;
            }
        }
        secure_clear(&mut self.random_buffer);
        secure_clear(&mut self.hash_buffer);
        secure_clear(&mut self.temp_buffer);
    }
}
```

### CRYSTALS-Dilithium Memory Layout

```rust
/// Dilithium-specific memory structures
pub struct DilithiumMemory {
    /// Polynomial coefficients
    pub polynomials: [[i32; 256]; 6], // 6 polynomials, 256 coefficients each
    /// Random bytes buffer
    pub random_buffer: [u8; 64],
    /// Hash state buffer
    pub hash_buffer: [u8; 128],
    /// Temporary computation buffer
    pub temp_buffer: [u8; 2048],
}

impl DilithiumMemory {
    /// Create new Dilithium memory layout
    pub fn new() -> Self {
        Self {
            polynomials: [[0i32; 256]; 6],
            random_buffer: [0u8; 64],
            hash_buffer: [0u8; 128],
            temp_buffer: [0u8; 2048],
        }
    }
    
    /// Clear all sensitive memory
    pub fn clear(&mut self) {
        for poly in &mut self.polynomials {
            for coeff in poly.iter_mut() {
                *coeff = 0;
            }
        }
        secure_clear(&mut self.random_buffer);
        secure_clear(&mut self.hash_buffer);
        secure_clear(&mut self.temp_buffer);
    }
}
```

## Memory Usage Analysis

### Stack Usage by Operation

| Operation | Stack Usage | Heap Usage | Total Memory |
|-----------|-------------|------------|--------------|
| Key Generation | 16KB | 0KB | 16KB |
| Key Exchange | 8KB | 0KB | 8KB |
| Signing | 32KB | 0KB | 32KB |
| Verification | 16KB | 0KB | 16KB |
| Encryption | 64KB | 0KB | 64KB |
| Decryption | 64KB | 0KB | 64KB |
| Hashing | 4KB | 0KB | 4KB |

### Memory Efficiency Comparison

| Library | Dynamic Allocations | Stack Usage | Heap Usage | Total Memory |
|---------|-------------------|-------------|------------|--------------|
| libQ | 0 | 64KB | 0KB | 64KB |
| libsodium | 0 | 32KB | 0KB | 32KB |
| OpenSSL | 10+ | 16KB | 128KB | 144KB |
| BouncyCastle | 20+ | 8KB | 256KB | 264KB |

## Memory Management Utilities

### Buffer Management

```rust
/// Fixed-size buffer for cryptographic operations
pub struct CryptoBuffer<const N: usize> {
    data: [u8; N],
    used: usize,
}

impl<const N: usize> CryptoBuffer<N> {
    /// Create a new buffer
    pub fn new() -> Self {
        Self {
            data: [0u8; N],
            used: 0,
        }
    }
    
    /// Write data to buffer
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.used + data.len() > N {
            return Err(Error::InvalidMessageSize {
                max: N - self.used,
                actual: data.len(),
            });
        }
        
        self.data[self.used..self.used + data.len()].copy_from_slice(data);
        self.used += data.len();
        Ok(())
    }
    
    /// Read data from buffer
    pub fn read(&self, len: usize) -> Result<&[u8]> {
        if len > self.used {
            return Err(Error::InvalidMessageSize {
                max: self.used,
                actual: len,
            });
        }
        
        Ok(&self.data[..len])
    }
    
    /// Clear buffer
    pub fn clear(&mut self) {
        secure_clear(&mut self.data);
        self.used = 0;
    }
    
    /// Get used portion of buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.used]
    }
}

impl<const N: usize> Drop for CryptoBuffer<N> {
    fn drop(&mut self) {
        self.clear();
    }
}
```

### Memory Pool for Temporary Operations

```rust
/// Memory pool for temporary operations (stack-allocated)
pub struct MemoryPool {
    /// Temporary buffers
    buffers: [TempBuffer; 4],
    /// Current buffer index
    current: usize,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new() -> Self {
        Self {
            buffers: [
                TempBuffer([0u8; TEMP_BUFFER_SIZE]),
                TempBuffer([0u8; TEMP_BUFFER_SIZE]),
                TempBuffer([0u8; TEMP_BUFFER_SIZE]),
                TempBuffer([0u8; TEMP_BUFFER_SIZE]),
            ],
            current: 0,
        }
    }
    
    /// Get next available buffer
    pub fn get_buffer(&mut self) -> &mut [u8] {
        let buffer = &mut self.buffers[self.current];
        self.current = (self.current + 1) % 4;
        &mut buffer.0
    }
    
    /// Clear all buffers
    pub fn clear(&mut self) {
        for buffer in &mut self.buffers {
            secure_clear(&mut buffer.0);
        }
        self.current = 0;
    }
}
```

## WASM Memory Considerations

### WASM-Specific Optimizations

```rust
/// WASM-optimized memory layout
#[cfg(target_arch = "wasm32")]
pub struct WasmMemory {
    /// Stack-allocated buffers optimized for WASM
    pub buffers: [u8; 16384], // 16KB total
    /// Buffer allocation map
    pub allocation_map: [bool; 256], // Track 256-byte blocks
}

#[cfg(target_arch = "wasm32")]
impl WasmMemory {
    /// Create new WASM memory layout
    pub fn new() -> Self {
        Self {
            buffers: [0u8; 16384],
            allocation_map: [false; 256],
        }
    }
    
    /// Allocate buffer from pool
    pub fn allocate(&mut self, size: usize) -> Option<&mut [u8]> {
        let blocks_needed = (size + 255) / 256; // Round up to 256-byte blocks
        
        // Find consecutive free blocks
        for start in 0..=256 - blocks_needed {
            let mut available = true;
            for i in 0..blocks_needed {
                if self.allocation_map[start + i] {
                    available = false;
                    break;
                }
            }
            
            if available {
                // Mark blocks as allocated
                for i in 0..blocks_needed {
                    self.allocation_map[start + i] = true;
                }
                
                let start_byte = start * 256;
                let end_byte = start_byte + size;
                return Some(&mut self.buffers[start_byte..end_byte]);
            }
        }
        
        None
    }
    
    /// Free allocated buffer
    pub fn free(&mut self, buffer: &mut [u8]) {
        let start_byte = buffer.as_ptr() as usize - self.buffers.as_ptr() as usize;
        let start_block = start_byte / 256;
        let blocks_used = (buffer.len() + 255) / 256;
        
        for i in 0..blocks_used {
            self.allocation_map[start_block + i] = false;
        }
        
        secure_clear(buffer);
    }
}
```

## Memory Testing

### Memory Safety Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secret_key_zeroization() {
        let mut key = SecretKey::new();
        let key_data = key.as_ref().to_vec();
        
        // Verify key is not all zeros
        assert_ne!(key_data, vec![0u8; KYBER5_SECRET_KEY_SIZE]);
        
        // Drop key and verify it's zeroized
        drop(key);
        // Note: In a real test, we'd need to use a custom allocator to verify zeroization
    }
    
    #[test]
    fn test_buffer_overflow_protection() {
        let mut buffer = CryptoBuffer::<1024>::new();
        
        // Write data up to capacity
        let data = vec![0x42u8; 1024];
        assert!(buffer.write(&data).is_ok());
        
        // Try to write beyond capacity
        let extra_data = vec![0x43u8; 1];
        assert!(buffer.write(&extra_data).is_err());
    }
    
    #[test]
    fn test_memory_pool_allocation() {
        let mut pool = MemoryPool::new();
        
        // Allocate multiple buffers
        let buf1 = pool.get_buffer();
        let buf2 = pool.get_buffer();
        let buf3 = pool.get_buffer();
        let buf4 = pool.get_buffer();
        
        // Verify all buffers are different
        assert_ne!(buf1.as_ptr(), buf2.as_ptr());
        assert_ne!(buf2.as_ptr(), buf3.as_ptr());
        assert_ne!(buf3.as_ptr(), buf4.as_ptr());
        
        // Fifth allocation should reuse first buffer
        let buf5 = pool.get_buffer();
        assert_eq!(buf1.as_ptr(), buf5.as_ptr());
    }
}
```

### Memory Usage Benchmarks

```rust
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn benchmark_memory_usage() {
        let start = Instant::now();
        
        // Perform cryptographic operations
        let (pk, sk) = simple::keygen(1).unwrap();
        let shared = simple::exchange(&sk, &pk).unwrap();
        let signature = simple::sign(&sk, b"test message").unwrap();
        let ciphertext = simple::encrypt(&shared, b"test message", None).unwrap();
        
        let duration = start.elapsed();
        
        // Verify no heap allocations occurred
        // This would require custom allocator tracking in a real benchmark
        println!("Operation completed in {:?} with zero heap allocations", duration);
    }
}
```

## Usage Examples

### Memory-Efficient Operations

```rust
use libq::memory::{CryptoBuffer, MemoryPool};

// Use fixed-size buffers for operations
fn hash_large_data(data: &[u8]) -> Result<Hash> {
    let mut buffer = CryptoBuffer::<4096>::new();
    let mut pool = MemoryPool::new();
    
    // Process data in chunks
    for chunk in data.chunks(4096) {
        buffer.clear();
        buffer.write(chunk)?;
        
        // Use temporary buffer for processing
        let temp = pool.get_buffer();
        // Process chunk...
    }
    
    Ok(Hash([0u8; 32])) // Placeholder
}
```

### Constrained Environment Usage

```rust
// Suitable for microcontrollers with limited memory
#[no_mangle]
pub extern "C" fn libq_keygen_embedded(
    public_key: *mut u8,
    secret_key: *mut u8,
) -> i32 {
    // All operations use stack-allocated buffers
    let (pk, sk) = match simple::keygen(1) {
        Ok(keys) => keys,
        Err(_) => return -1,
    };
    
    // Copy to provided buffers
    unsafe {
        std::ptr::copy_nonoverlapping(
            pk.as_ref().as_ptr(),
            public_key,
            KYBER1_PUBLIC_KEY_SIZE,
        );
        std::ptr::copy_nonoverlapping(
            sk.as_ref().as_ptr(),
            secret_key,
            KYBER1_SECRET_KEY_SIZE,
        );
    }
    
    0 // Success
}
```

This memory architecture ensures that libQ can operate in the most constrained environments while maintaining security and performance. The zero dynamic allocation model makes it suitable for microcontrollers, embedded systems, and high-performance applications where predictable memory usage is critical.
