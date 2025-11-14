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

        key.copy_from_slice(&entropy_input[..32]);
        v.copy_from_slice(&entropy_input[32..48]);

        Self::ctr_drbg_update(None, &mut key, &mut v);

        Self {
            key,
            v,
            reseed_counter: 1,
        }
    }

    fn ctr_drbg_update(provided_data: Option<&[u8]>, key: &mut [u8; 32], v: &mut [u8; 16]) {
        let mut temp = [0u8; 48];
        let aes_ctx = Aes256CtxPure::new(key);

        for i in 0..3 {
            Self::increment_counter(v);
            let encrypted = aes_ctx.encrypt_block(v);
            temp[i * 16..(i + 1) * 16].copy_from_slice(&encrypted);
        }

        if let Some(data) = provided_data {
            for i in 0..data.len() {
                temp[i] ^= data[i];
            }
        }

        key.copy_from_slice(&temp[..32]);
        v.copy_from_slice(&temp[32..48]);
    }

    pub fn increment_counter(v: &mut [u8; 16]) {
        for i in (0..16).rev() {
            v[i] = v[i].wrapping_add(1);
            if v[i] != 0 {
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

        let aes_ctx = Aes256CtxPure::new(&self.key);
        let mut offset = 0;
        while offset < dest.len() {
            Self::increment_counter(&mut self.v);
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
