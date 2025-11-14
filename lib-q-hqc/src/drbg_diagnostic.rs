//! Dual-mode DRBG diagnostic wrapper for interoperability testing
//!
//! This module provides a wrapper that simultaneously generates output from both
//! DRBG implementations and logs differences for debugging.

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use alloc::format;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use alloc::string::String;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use alloc::vec::Vec;

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use rand_core::{
    CryptoRng,
    RngCore,
};

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use crate::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use crate::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;

/// Dual-mode DRBG wrapper that generates from both implementations and logs differences
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
pub struct DualModeDrbg {
    primary: BearSslAes256CtrDrbg,
    secondary: Aes256CtrDrbg,
    generation_count: usize,
    log_buffer: Vec<String>,
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
impl DualModeDrbg {
    pub fn new(primary: BearSslAes256CtrDrbg, secondary: Aes256CtrDrbg) -> Self {
        Self {
            primary,
            secondary,
            generation_count: 0,
            log_buffer: Vec::new(),
        }
    }

    pub fn get_logs(&self) -> &[String] {
        &self.log_buffer
    }

    pub fn clear_logs(&mut self) {
        self.log_buffer.clear();
    }

    fn log_comparison(&mut self, primary_output: &[u8], secondary_output: &[u8]) {
        let matches = primary_output == secondary_output;
        let log_entry = format!(
            "Generation #{}: {} bytes - Match: {} | BearSSL: {:02x?}... | Rust: {:02x?}...",
            self.generation_count,
            primary_output.len(),
            matches,
            &primary_output[..core::cmp::min(8, primary_output.len())],
            &secondary_output[..core::cmp::min(8, secondary_output.len())]
        );
        self.log_buffer.push(log_entry);
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
impl RngCore for DualModeDrbg {
    fn next_u32(&mut self) -> u32 {
        self.generation_count += 1;
        let primary_val = self.primary.next_u32();
        let secondary_val = self.secondary.next_u32();

        if primary_val != secondary_val {
            let log = format!(
                "Generation #{} (u32): BearSSL={:08x}, Rust={:08x}",
                self.generation_count, primary_val, secondary_val
            );
            self.log_buffer.push(log);
        }

        primary_val
    }

    fn next_u64(&mut self) -> u64 {
        self.generation_count += 1;
        let primary_val = self.primary.next_u64();
        let secondary_val = self.secondary.next_u64();

        if primary_val != secondary_val {
            let log = format!(
                "Generation #{} (u64): BearSSL={:016x}, Rust={:016x}",
                self.generation_count, primary_val, secondary_val
            );
            self.log_buffer.push(log);
        }

        primary_val
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.generation_count += 1;

        // Generate from primary
        self.primary.fill_bytes(dest);
        let primary_output = dest.to_vec();

        // Generate from secondary
        let mut secondary_output = vec![0u8; dest.len()];
        self.secondary.fill_bytes(&mut secondary_output);

        // Log comparison
        self.log_comparison(&primary_output, &secondary_output);
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
impl CryptoRng for DualModeDrbg {}
