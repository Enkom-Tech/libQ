//! Hash wrapper types that implement the lib-q-core Hash trait

use crate::{
    CShake128, CShake256, KangarooTwelve, Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224,
    Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};
use alloc::vec::Vec;
use digest::{CustomizedInit, Digest, ExtendableOutput, ExtendableOutputReset, Update, XofReader};
use lib_q_core::{Hash, Result};

/// Wrapper for cSHAKE128 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct CShake128Hash(CShake128);

/// Wrapper for cSHAKE256 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct CShake256Hash(CShake256);

/// Wrapper for SHAKE128 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Shake128Hash(Shake128);

/// Wrapper for SHAKE256 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Shake256Hash(Shake256);

/// Wrapper for SHA3-224 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Sha3_224Hash(Sha3_224);

/// Wrapper for SHA3-256 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Sha3_256Hash(Sha3_256);

/// Wrapper for SHA3-384 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Sha3_384Hash(Sha3_384);

/// Wrapper for SHA3-512 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Sha3_512Hash(Sha3_512);

/// Wrapper for KangarooTwelve that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct KangarooTwelveHash(KangarooTwelve<'static>);

/// Wrapper for Keccak-224 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Keccak224Hash(Keccak224);

/// Wrapper for Keccak-256 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Keccak256Hash(Keccak256);

/// Wrapper for Keccak-384 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Keccak384Hash(Keccak384);

/// Wrapper for Keccak-512 that implements lib-q-core Hash trait
#[derive(Debug, Clone)]
pub struct Keccak512Hash(Keccak512);

// Constructor implementations
impl CShake128Hash {
    /// Creates a new cSHAKE128 hash instance
    pub fn new() -> Self {
        Self(CShake128::default())
    }

    /// Creates a new cSHAKE128 hash instance with customization
    pub fn new_customized(customization: &[u8]) -> Self {
        Self(CShake128::new_customized(customization))
    }

    /// Creates a new cSHAKE128 hash instance with function name and customization
    pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
        Self(CShake128::new_with_function_name(
            function_name,
            customization,
        ))
    }
}

impl CShake256Hash {
    /// Creates a new cSHAKE256 hash instance
    pub fn new() -> Self {
        Self(CShake256::default())
    }

    /// Creates a new cSHAKE256 hash instance with customization
    pub fn new_customized(customization: &[u8]) -> Self {
        Self(CShake256::new_customized(customization))
    }

    /// Creates a new cSHAKE256 hash instance with function name and customization
    pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
        Self(CShake256::new_with_function_name(
            function_name,
            customization,
        ))
    }
}

impl Shake128Hash {
    /// Creates a new SHAKE128 hash instance
    pub fn new() -> Self {
        Self(Shake128::default())
    }
}

impl Shake256Hash {
    /// Creates a new SHAKE256 hash instance
    pub fn new() -> Self {
        Self(Shake256::default())
    }
}

// SHA-3 fixed-output constructor implementations
impl Sha3_224Hash {
    /// Creates a new SHA3-224 hash instance
    pub fn new() -> Self {
        Self(Sha3_224::default())
    }
}

impl Sha3_256Hash {
    /// Creates a new SHA3-256 hash instance
    pub fn new() -> Self {
        Self(Sha3_256::default())
    }
}

impl Sha3_384Hash {
    /// Creates a new SHA3-384 hash instance
    pub fn new() -> Self {
        Self(Sha3_384::default())
    }
}

impl Sha3_512Hash {
    /// Creates a new SHA3-512 hash instance
    pub fn new() -> Self {
        Self(Sha3_512::default())
    }
}

// Constructor implementations for new hash types
impl KangarooTwelveHash {
    /// Creates a new KangarooTwelve hash instance
    pub fn new() -> Self {
        Self(KangarooTwelve::new(b""))
    }

    /// Creates a new KangarooTwelve hash instance with customization
    pub fn new_customized(customization: &'static [u8]) -> Self {
        Self(KangarooTwelve::new(customization))
    }
}

impl Keccak224Hash {
    /// Creates a new Keccak-224 hash instance
    pub fn new() -> Self {
        Self(Keccak224::default())
    }
}

impl Keccak256Hash {
    /// Creates a new Keccak-256 hash instance
    pub fn new() -> Self {
        Self(Keccak256::default())
    }
}

impl Keccak384Hash {
    /// Creates a new Keccak-384 hash instance
    pub fn new() -> Self {
        Self(Keccak384::default())
    }
}

impl Keccak512Hash {
    /// Creates a new Keccak-512 hash instance
    pub fn new() -> Self {
        Self(Keccak512::default())
    }
}

// Implement lib_q_core::Hash trait for cSHAKE types
impl Hash for CShake128Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let mut output = [0u8; 16];
        hasher.finalize_xof_reset_into(&mut output);
        Ok(output.to_vec())
    }

    fn output_size(&self) -> usize {
        16
    }
}

impl Hash for CShake256Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let mut output = [0u8; 32];
        hasher.finalize_xof_reset_into(&mut output);
        Ok(output.to_vec())
    }

    fn output_size(&self) -> usize {
        32
    }
}

// Implement lib_q_core::Hash trait for SHAKE types
impl Hash for Shake128Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let mut output = [0u8; 16];
        hasher.finalize_xof_reset_into(&mut output);
        Ok(output.to_vec())
    }

    fn output_size(&self) -> usize {
        16
    }
}

impl Hash for Shake256Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let mut output = [0u8; 32];
        hasher.finalize_xof_reset_into(&mut output);
        Ok(output.to_vec())
    }

    fn output_size(&self) -> usize {
        32
    }
}

// Implement lib_q_core::Hash trait for SHA-3 fixed-output types
impl Hash for Sha3_224Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        28
    }
}

impl Hash for Sha3_256Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl Hash for Sha3_384Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        48
    }
}

impl Hash for Sha3_512Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        64
    }
}

// Implement lib_q_core::Hash trait for new hash types
impl Hash for KangarooTwelveHash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let mut output = [0u8; 32]; // Default output size
        let mut reader = hasher.finalize_xof();
        reader.read(&mut output);
        Ok(output.to_vec())
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl Hash for Keccak224Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        28
    }
}

impl Hash for Keccak256Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl Hash for Keccak384Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        48
    }
}

impl Hash for Keccak512Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = self.0.clone();
        Update::update(&mut hasher, data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    fn output_size(&self) -> usize {
        64
    }
}

// Default implementations
impl Default for CShake128Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CShake256Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Shake128Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Shake256Hash {
    fn default() -> Self {
        Self::new()
    }
}

// SHA-3 fixed-output default implementations
impl Default for Sha3_224Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_256Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_384Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_512Hash {
    fn default() -> Self {
        Self::new()
    }
}

// Default implementations for new hash types
impl Default for KangarooTwelveHash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Keccak224Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Keccak256Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Keccak384Hash {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Keccak512Hash {
    fn default() -> Self {
        Self::new()
    }
}
