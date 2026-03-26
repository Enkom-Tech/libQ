//! Pure Rust AES256-CTR-DRBG Implementation (NIST SP 800-90A)
//!
//! This module implements the CTR_DRBG deterministic random bit generator
//! using AES-256 in counter mode, as specified in NIST SP 800-90A.
//!
//! ## Purpose
//!
//! This is an alternative DRBG implementation for platforms where BearSSL
//! is not available. It is NIST SP 800-90A compliant but may not produce
//! identical output to the HQC reference implementation.
//!
//! For KAT compatibility, use the `bearssl-aes` feature instead.
//!
//! ## Security
//!
//! CTR_DRBG with AES-256 is a NIST-approved CSPRNG design that provides
//! cryptographically secure pseudorandom output when properly seeded.
//!
//! ## Usage
//!
//! ```rust
//! use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
//! use rand_core::Rng;
//!
//! let entropy = [0u8; 48]; // 48 bytes of entropy
//! let mut rng = Aes256CtrDrbg::instantiate(&entropy);
//!
//! let mut output = [0u8; 32];
//! rng.fill_bytes(&mut output);
//! ```

#[cfg(feature = "aes-drbg")]
use alloc::format;
#[cfg(feature = "aes-drbg")]
use alloc::string::String;

#[cfg(feature = "aes-drbg")]
use aes::Aes256;
#[cfg(feature = "aes-drbg")]
use aes::cipher::{
    BlockEncrypt,
    KeyInit,
    generic_array::GenericArray,
};
use rand_core::{
    TryCryptoRng,
    TryRng,
};

/// AES256-CTR-DRBG state structure
///
/// Implements the CTR_DRBG algorithm as specified in NIST SP 800-90A
/// using AES-256 in counter mode.
#[cfg(feature = "aes-drbg")]
#[derive(Debug, Clone)]
pub struct Aes256CtrDrbg {
    /// AES-256 key (32 bytes)
    key: [u8; 32],
    /// 128-bit counter value
    v: [u8; 16],
    /// Reseed counter
    reseed_counter: u64,
}

#[cfg(feature = "aes-drbg")]
impl Aes256CtrDrbg {
    /// Instantiate a new AES256-CTR-DRBG with the given entropy input
    ///
    /// # Arguments
    /// * `entropy_input` - 48 bytes of entropy input
    ///
    /// # Returns
    /// A new AES256-CTR-DRBG instance ready for generating random bytes
    pub fn instantiate(entropy_input: &[u8; 48]) -> Self {
        let mut key = [0u8; 32];
        let mut v = [0u8; 16];

        // Initial values: Key = 0x00...00, V = 0x00...00
        Self::ctr_drbg_update(Some(entropy_input), &mut key, &mut v);

        Self {
            key,
            v,
            reseed_counter: 1,
        }
    }

    /// AES-256-ECB encryption function
    ///
    /// # Arguments
    /// * `key` - 32-byte AES-256 key
    /// * `input` - 16-byte input block
    ///
    /// # Returns
    /// 16-byte encrypted output block
    pub fn aes256_ecb(key: &[u8; 32], input: &[u8; 16]) -> [u8; 16] {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(input);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    /// CTR_DRBG_Update function as specified in NIST SP 800-90A
    ///
    /// # Arguments
    /// * `provided_data` - Optional 48-byte provided data (None for generation update)
    /// * `key` - AES-256 key to update
    /// * `v` - Counter value to update
    fn ctr_drbg_update(provided_data: Option<&[u8; 48]>, key: &mut [u8; 32], v: &mut [u8; 16]) {
        let mut temp = [0u8; 48];

        // Generate 3 blocks using AES-256-ECB
        for i in 0..3 {
            // Increment V
            Self::increment_counter(v);
            // AES-256-ECB(Key, V) -> temp[i*16..(i+1)*16]
            let block = Self::aes256_ecb(key, v);
            temp[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }

        // XOR with provided_data if present
        if let Some(data) = provided_data {
            for i in 0..48 {
                temp[i] ^= data[i];
            }
        }

        // Update Key and V
        key.copy_from_slice(&temp[..32]);
        v.copy_from_slice(&temp[32..48]);
    }

    /// Increment the 128-bit counter value
    ///
    /// # Arguments
    /// * `v` - 16-byte counter to increment
    pub fn increment_counter(v: &mut [u8; 16]) {
        for i in (0..16).rev() {
            if v[i] == 0xFF {
                v[i] = 0x00;
            } else {
                v[i] += 1;
                break;
            }
        }
    }
}

#[cfg(feature = "aes-drbg")]
impl TryRng for Aes256CtrDrbg {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        // Generate all requested bytes first (matches reference randombytes behavior)
        let mut offset = 0;
        while offset < dest.len() {
            // Increment V
            Self::increment_counter(&mut self.v);

            // Generate block using AES-256-ECB
            let block = Self::aes256_ecb(&self.key, &self.v);

            // Copy to output
            let to_copy = core::cmp::min(16, dest.len() - offset);
            dest[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
            offset += to_copy;
        }

        // Update state after generating all bytes (matches reference behavior)
        Self::ctr_drbg_update(None, &mut self.key, &mut self.v);
        self.reseed_counter += 1;
        Ok(())
    }
}

#[cfg(feature = "aes-drbg")]
impl TryCryptoRng for Aes256CtrDrbg {}

#[cfg(feature = "aes-drbg")]
impl Aes256CtrDrbg {
    pub fn debug_state(&self) -> String {
        format!(
            "Key: {:02x?}\nV: {:02x?}\nReseed: {}",
            &self.key[..],
            &self.v[..],
            self.reseed_counter
        )
    }
}

/// Create AES256-CTR-DRBG RNG for KAT compatibility
#[cfg(feature = "aes-drbg")]
pub fn create_aes_ctr_drbg_rng(entropy: [u8; 48]) -> Aes256CtrDrbg {
    Aes256CtrDrbg::instantiate(&entropy)
}

// Placeholder implementation when aes-drbg feature is not enabled
#[cfg(not(feature = "aes-drbg"))]
pub struct Aes256CtrDrbg;

#[cfg(not(feature = "aes-drbg"))]
impl Aes256CtrDrbg {
    pub fn instantiate(_entropy_input: &[u8; 48]) -> Self {
        panic!("AES-CTR-DRBG requires the 'aes-drbg' feature to be enabled");
    }
}

#[cfg(not(feature = "aes-drbg"))]
impl TryRng for Aes256CtrDrbg {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("AES-CTR-DRBG requires the 'aes-drbg' feature to be enabled");
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("AES-CTR-DRBG requires the 'aes-drbg' feature to be enabled");
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
        panic!("AES-CTR-DRBG requires the 'aes-drbg' feature to be enabled");
    }
}

#[cfg(not(feature = "aes-drbg"))]
impl TryCryptoRng for Aes256CtrDrbg {}

#[cfg(not(feature = "aes-drbg"))]
pub fn create_aes_ctr_drbg_rng(_entropy: [u8; 48]) -> Aes256CtrDrbg {
    panic!("AES-CTR-DRBG requires the 'aes-drbg' feature to be enabled");
}
