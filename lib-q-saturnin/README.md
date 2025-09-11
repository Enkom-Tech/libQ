# lib-q-saturnin

Post-quantum symmetric algorithm suite implementation for lib-Q.

Saturnin is a lightweight post-quantum symmetric algorithm suite designed for IoT and constrained devices, providing authenticated encryption, block cipher, hashing, and stream cipher modes with superior post-quantum security.

## Features

- **Post-quantum security**: Designed to resist quantum attacks
- **Lightweight**: Optimized for constrained devices and IoT
- **Multiple modes**: AEAD, block cipher, hash, and stream cipher
- **Memory safe**: Built in Rust with zero-cost abstractions
- **No-std support**: Works in embedded environments

## Algorithm Modes

### Authenticated Encryption (AEAD)
- **Saturnin-AEAD**: Authenticated encryption with associated data
- **Key size**: 256 bits
- **Nonce size**: 128 bits
- **Tag size**: 128 bits

### Block Cipher
- **Saturnin-256**: 256-bit block cipher
- **Key size**: 256 bits
- **Block size**: 256 bits

### Hash Function
- **Saturnin-Hash**: Cryptographic hash function
- **Output size**: 256 bits

### Stream Cipher
- **Saturnin-Stream**: Stream cipher mode
- **Key size**: 256 bits

## Usage

### AEAD Mode
```rust
use lib_q_saturnin::SaturninAead;
use lib_q_core::{AeadKey, Nonce};

let aead = SaturninAead::new();
let key = AeadKey::new(vec![0u8; 32]);
let nonce = Nonce::new(vec![0u8; 16]);
let plaintext = b"secret message";
let aad = b"associated data";

let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(aad))?;
let decrypted = aead.decrypt(&key, &nonce, &ciphertext, Some(aad))?;
```

### Block Cipher Mode
```rust
use lib_q_saturnin::SaturninBlockCipher;

let cipher = SaturninBlockCipher::new();
let key = vec![0u8; 32];
let block = vec![0u8; 32];

let encrypted = cipher.encrypt_block(&key, &block)?;
let decrypted = cipher.decrypt_block(&key, &encrypted)?;
```

## Features

- `default`: AEAD mode
- `aead`: Authenticated encryption mode
- `block-cipher`: Block cipher mode
- `hash`: Hash function mode
- `stream`: Stream cipher mode
- `zeroize`: Secure memory zeroization

## Security

This implementation follows lib-Q's security model:

- **Post-quantum only**: No classical algorithms
- **Constant-time operations**: All operations are constant-time
- **Secure memory**: Automatic secure memory zeroing
- **No side-channels**: Designed to prevent timing attacks

## Development Status

**Active Development** - Core implementation in progress

### Implemented
- ✅ Basic crate structure
- ✅ AEAD trait implementation
- ✅ Security validation framework

### In Progress
- 🔄 Saturnin-AEAD implementation
- 🔄 Saturnin block cipher implementation
- 🔄 Saturnin hash function implementation
- 🔄 Comprehensive test suite

### Planned
- 📋 Performance optimization
- 📋 SIMD acceleration
- 📋 Benchmarking suite
- 📋 Security audit

## License

See the main [lib-q license](../LICENSE).

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).
