# FN-DSA WebAssembly (WASM) Guide

This guide explains how to use FN-DSA in WebAssembly environments, particularly for browser-based applications.

## Overview

FN-DSA is fully compatible with WebAssembly, providing post-quantum digital signatures in browser environments. The implementation includes:

- **Browser-compatible RNG**: Uses `getrandom` with `wasm_js` backend
- **Memory management**: Efficient allocation for WASM constraints
- **Error handling**: WASM-friendly error types and messages
- **Performance**: Optimized for browser execution

## Features

### Security Levels
- **Level 1 (128-bit security)**: n=512, suitable for most web applications
- **Level 5 (256-bit security)**: n=1024, for high-security web applications

### Key Sizes
| Security Level | Sign Key | Verify Key | Signature |
|----------------|----------|------------|-----------|
| Level 1        | 1281 bytes | 897 bytes | 666 bytes |
| Level 5        | 2305 bytes | 1793 bytes | 1280 bytes |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-q-fn-dsa = { version = "0.0.2", features = ["wasm"] }
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
let message = b"Hello, WASM!";
let signature = fn_dsa.sign(&keypair.secret_key, message)?;
```

### 4. Verify a Signature

```rust
let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
```

## WASM-Specific Considerations

### Random Number Generation

FN-DSA uses `getrandom` with the `wasm_js` backend for secure random number generation in browsers:

```rust
// Automatically handled by the library
// Uses crypto.getRandomValues() in the browser
```

### Memory Management

The library is designed to work efficiently within WASM memory constraints:

```rust
// Keys are automatically managed
// Signatures are created with minimal allocations
// Memory is automatically freed when objects go out of scope
```

### Error Handling

WASM-compatible error handling:

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

### Custom RNG (if needed)

```rust
use rand_core::{CryptoRng, RngCore};

struct CustomWasmRng;

impl RngCore for CustomWasmRng {
    fn next_u32(&mut self) -> u32 {
        // Your custom RNG implementation
        // Must be cryptographically secure
    }
    
    fn next_u64(&mut self) -> u64 {
        // Your custom RNG implementation
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Your custom RNG implementation
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CustomWasmRng {}
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

### Hex Encoding (for web APIs)

```rust
use lib_q_fn_dsa::examples::wasm_example::wasm_utils;

// Convert to hex for web APIs
let public_key_hex = wasm_utils::bytes_to_hex(public_key_bytes);
let signature_hex = wasm_utils::bytes_to_hex(&signature);

// Convert from hex
let public_key_bytes = wasm_utils::hex_to_bytes(&public_key_hex)?;
```

## Performance Considerations

### Browser Performance

- **Key Generation**: ~200-500ms (depending on browser and hardware)
- **Signing**: ~100-300ms
- **Verification**: ~50-150ms

### Memory Usage

- **Code Size**: ~50KB (compressed)
- **Runtime Memory**: ~4KB (excluding keys)
- **Peak Stack Usage**: ~2KB

### Optimization Tips

1. **Reuse instances**: Create FN-DSA instances once and reuse them
2. **Batch operations**: Process multiple signatures together when possible
3. **Use Level 1**: Unless you need Level 5 security, use Level 1 for better performance
4. **Minimize allocations**: Reuse buffers when possible

## Security Best Practices

### Key Management

```rust
// Store keys securely (use Web Crypto API or secure storage)
// Never log or expose secret keys
// Use HTTPS for all communications
```

### Random Number Generation

```rust
// The library automatically uses secure RNG
// Ensure your browser supports crypto.getRandomValues()
// Consider additional entropy sources for high-security applications
```

### Signature Verification

```rust
// Always verify signatures on the server side
// Use constant-time comparison when possible
// Implement proper error handling
```

## Browser Compatibility

### Supported Browsers

- **Chrome**: 57+
- **Firefox**: 52+
- **Safari**: 11+
- **Edge**: 16+

### Required Features

- WebAssembly support
- `crypto.getRandomValues()` API
- ES6 modules (for modern bundlers)

## Integration Examples

### With Web Workers

```rust
// In your web worker
use lib_q_fn_dsa::FnDsa512;

let fn_dsa = FnDsa512::new();
let keypair = fn_dsa.generate_keypair()?;

// Send result back to main thread
post_message(keypair);
```

### With Service Workers

```rust
// In your service worker
use lib_q_fn_dsa::FnDsa512;

self.addEventListener('message', |event| {
    let fn_dsa = FnDsa512::new();
    let signature = fn_dsa.sign(&secret_key, &event.data)?;
    
    // Send signature back
    self.post_message(signature);
});
```

### With Web APIs

```rust
// Convert to/from JavaScript
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()
        .map_err(|e| JsValue::from_str(&format!("Error: {:?}", e)))?;
    
    // Convert to JavaScript object
    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"publicKey".into(), &keypair.public_key.as_bytes().into())?;
    js_sys::Reflect::set(&result, &"secretKey".into(), &keypair.secret_key.as_bytes().into())?;
    
    Ok(result.into())
}
```

## Troubleshooting

### Common Issues

1. **RNG not available**: Ensure `crypto.getRandomValues()` is supported
2. **Memory errors**: Check WASM memory limits
3. **Performance issues**: Consider using Web Workers for heavy operations
4. **Build errors**: Ensure proper feature flags are set

### Debug Mode

```rust
// Enable debug logging (development only)
#[cfg(debug_assertions)]
console_log::init_with_level(log::Level::Debug);
```

### Error Handling

```rust
use lib_q_core::Error;

fn handle_error(error: Error) -> String {
    match error {
        Error::InvalidKeySize { expected, actual } => {
            format!("Key size mismatch: expected {}, got {}", expected, actual)
        }
        Error::VerificationFailed => "Signature verification failed".to_string(),
        _ => "Unknown error occurred".to_string(),
    }
}
```

## Examples

See the `examples/wasm_example.rs` file for a complete working example.

## Further Reading

- [WebAssembly Documentation](https://webassembly.org/)
- [Rust WASM Book](https://rustwasm.github.io/docs/book/)
- [FN-DSA Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.206.pdf)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
