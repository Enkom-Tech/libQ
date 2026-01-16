//! AES256-CTR-DRBG using BearSSL AES for exact KAT compatibility

#[cfg(feature = "bearssl-aes")]
use alloc::format;
#[cfg(feature = "bearssl-aes")]
use alloc::string::String;

#[cfg(feature = "bearssl-aes")]
use rand_core::{
    CryptoRng,
    RngCore,
};

#[cfg(feature = "bearssl-aes")]
use crate::bearssl_aes_pure::Aes256CtxPure;

/// AES256-CTR-DRBG using BearSSL AES primitive
#[cfg(feature = "bearssl-aes")]
pub struct BearSslAes256CtrDrbg {
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: u32,
}

#[cfg(feature = "bearssl-aes")]
impl BearSslAes256CtrDrbg {
    pub fn instantiate(entropy_input: &[u8; 48]) -> Self {
        let mut key = [0u8; 32];
        let mut v = [0u8; 16];

        // Initialize Key and V to zeros (NIST SP 800-90A requirement)
        // The entropy_input will be used as provided_data in the update
        // This matches the reference implementation's randombytes_init:
        // memset(DRBG_ctx.Key, 0x00, 32);
        // memset(DRBG_ctx.V, 0x00, 16);
        // AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);

        // Call ctr_drbg_update with entropy_input as provided_data
        Self::ctr_drbg_update(Some(entropy_input), &mut key, &mut v);

        Self {
            key,
            v,
            reseed_counter: 1,
        }
    }

    fn ctr_drbg_update(provided_data: Option<&[u8]>, key: &mut [u8; 32], v: &mut [u8; 16]) {
        let mut temp = [0u8; 48];

        // Generate 48 bytes using AES-256-ECB (3 blocks of 16 bytes)
        // This matches the reference implementation's AES256_CTR_DRBG_Update
        // Note: Reference creates a new AES context for each encryption call
        for i in 0..3 {
            Self::increment_counter(v);
            // Create new AES context for each encryption (matches reference: AES256_ECB creates new context each time)
            let aes_ctx = Aes256CtxPure::new(key);
            let encrypted = aes_ctx.encrypt_block(v);
            temp[i * 16..(i + 1) * 16].copy_from_slice(&encrypted);
        }

        // XOR with provided_data if present (matches reference: if (provided_data != NULL))
        if let Some(data) = provided_data {
            // Ensure we don't exceed temp bounds (should be 48 bytes)
            let len = core::cmp::min(48, data.len());
            for i in 0..len {
                temp[i] ^= data[i];
            }
        }

        // Update Key and V from temp (matches reference: memcpy(Key, temp, 32); memcpy(V, temp+32, 16))
        key.copy_from_slice(&temp[..32]);
        v.copy_from_slice(&temp[32..48]);
    }

    pub fn increment_counter(v: &mut [u8; 16]) {
        // Match reference implementation exactly:
        // for (int j=15; j>=0; j--) {
        //     if ( V[j] == 0xff )
        //         V[j] = 0x00;
        //     else {
        //         V[j]++;
        //         break;
        //     }
        // }
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

#[cfg(feature = "bearssl-aes")]
impl RngCore for BearSslAes256CtrDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        #[cfg(all(feature = "debug-drbg-state", feature = "std"))]
        {
            println!("=== fill_bytes START ===");
            println!("Requested {} bytes", dest.len());
            println!(
                "Initial state: Key: {:02x?} V: {:02x?} Reseed: {}",
                &self.key[..],
                &self.v[..],
                self.reseed_counter
            );
        }

        #[cfg(all(feature = "debug-drbg-state-defmt", not(feature = "std")))]
        {
            defmt::info!("=== fill_bytes START ===");
            defmt::info!("Requested {} bytes", dest.len());
            defmt::info!(
                "Initial state: Key: {:02x} V: {:02x} Reseed: {}",
                &self.key[..],
                &self.v[..],
                self.reseed_counter
            );
        }

        // Generate output bytes (matches reference: randombytes function)
        // Note: Reference creates a new AES context for each encryption call
        let mut offset = 0;
        while offset < dest.len() {
            Self::increment_counter(&mut self.v);
            // Create new AES context for each encryption (matches reference: AES256_ECB creates new context each time)
            let aes_ctx = Aes256CtxPure::new(&self.key);
            let block = aes_ctx.encrypt_block(&self.v);
            let to_copy = core::cmp::min(16, dest.len() - offset);
            dest[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
            offset += to_copy;
        }

        Self::ctr_drbg_update(None, &mut self.key, &mut self.v);
        self.reseed_counter += 1;

        #[cfg(all(feature = "debug-drbg-state", feature = "std"))]
        {
            println!(
                "State after update: Key: {:02x?} V: {:02x?} Reseed: {}",
                &self.key[..],
                &self.v[..],
                self.reseed_counter
            );
            println!("=== fill_bytes END ===");
        }

        #[cfg(all(feature = "debug-drbg-state-defmt", not(feature = "std")))]
        {
            defmt::info!(
                "State after update: Key: {:02x} V: {:02x} Reseed: {}",
                &self.key[..],
                &self.v[..],
                self.reseed_counter
            );
            defmt::info!("=== fill_bytes END ===");
        }
    }
}

#[cfg(feature = "bearssl-aes")]
impl CryptoRng for BearSslAes256CtrDrbg {}

#[cfg(feature = "bearssl-aes")]
impl BearSslAes256CtrDrbg {
    pub fn debug_state(&self) -> String {
        format!(
            "Key: {:02x?}\nV: {:02x?}\nReseed: {}",
            &self.key[..],
            &self.v[..],
            self.reseed_counter
        )
    }
}
