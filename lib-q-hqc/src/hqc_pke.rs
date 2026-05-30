//! HQC Public Key Encryption (PKE) Implementation
//!
//! This module implements the HQC PKE layer as specified in the reference implementation.
//! The PKE layer provides the core encryption/decryption functionality.

#![cfg_attr(feature = "simd-avx2", allow(unsafe_code))]

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::concatenated_code::{
    ConcatenatedCode,
    ConcatenatedCodeError,
};
use crate::internal::shake256::Shake256Xof;
use crate::params_correct::HqcParams;

/// HQC PKE implementation
pub struct HqcPke<P: HqcParams> {
    concatenated_code: ConcatenatedCode<P>,
}

impl<P: HqcParams> HqcPke<P> {
    /// Create a new HQC PKE instance
    pub fn new() -> Result<Self, HqcPkeError> {
        let concatenated_code = ConcatenatedCode::new().map_err(HqcPkeError::CodeError)?;

        Ok(Self { concatenated_code })
    }

    /// Get a reference to the concatenated code instance
    pub fn concatenated_code(&self) -> &ConcatenatedCode<P> {
        &self.concatenated_code
    }

    /// XOF get bytes matching reference xof_get_bytes behavior
    ///
    /// The reference xof_get_bytes has special handling for non-8-byte-aligned sizes:
    ///
    /// 1. Squeeze (output_size - remainder) bytes directly
    /// 2. Squeeze 8 more bytes into tmp buffer
    /// 3. Copy only 'remainder' bytes from tmp to output
    ///
    /// This ensures consistent XOF state advancement across implementations.
    fn xof_get_bytes(xof: &mut Shake256Xof, output: &mut [u8]) -> Result<(), HqcPkeError> {
        let output_size = output.len();
        let bsize = 8usize;
        let remainder = output_size % bsize;

        if remainder == 0 {
            // Output size is 8-byte aligned - simple case
            xof.squeeze(output).map_err(|_| HqcPkeError::HashError)?;
        } else {
            // Output size is NOT 8-byte aligned - match reference behavior
            let aligned_size = output_size - remainder;

            // Squeeze aligned portion directly
            if aligned_size > 0 {
                xof.squeeze(&mut output[..aligned_size])
                    .map_err(|_| HqcPkeError::HashError)?;
            }

            // Squeeze 8 more bytes into tmp (reference behavior!)
            let mut tmp = [0u8; 8];
            xof.squeeze(&mut tmp).map_err(|_| HqcPkeError::HashError)?;

            // Copy only first 'remainder' bytes from tmp
            output[aligned_size..].copy_from_slice(&tmp[..remainder]);
        }

        Ok(())
    }

    /// Generate a key pair for HQC PKE with a random seed
    ///
    /// Returns (public_key, secret_key) where:
    /// - public_key: (h, s) where h is the circulant matrix and s = y*h + x
    /// - secret_key: (seed_dk) where seed_dk is used to derive y
    pub fn keygen<R: rand_core::CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(HqcPkePublicKey<P>, HqcPkeSecretKey<P>), HqcPkeError> {
        let mut seed = [0u8; 32]; // SEED_BYTES
        rng.fill_bytes(&mut seed);
        self.keygen_with_seed(&seed)
    }

    /// Generate a key pair for HQC PKE with a given seed
    ///
    /// Returns (public_key, secret_key) where:
    /// - public_key: (h, s) wire format with s = y*h + x
    /// - secret_key: (seed_dk) where seed_dk is used to derive y
    ///
    /// This implementation matches the reference implementation KAT generation flow:
    /// - Takes entropy seed (48 bytes for KAT compatibility)
    /// - Derives seed_kem using SHAKE-256 PRNG (domain=0)
    /// - Derives seed_pke from seed_kem using XOF (SHAKE-256 with domain=1)
    /// - Uses hash_i (SHA3-512 with domain=2) on seed_pke to derive keypair seeds
    /// - Produces seed_dk (32 bytes) and seed_ek (32 bytes)
    /// Generate a key pair from an already-derived PKE seed (`seed_pke`).
    ///
    /// This matches `HQC-PKE.Keygen(seedPKE)` in the 2025 specification after
    /// `seedPKE` has been obtained from the KEM XOF (`seedKEM` → XOF).
    pub fn keygen_from_seed_pke(
        &self,
        seed_pke: &[u8; 32],
    ) -> Result<(HqcPkePublicKey<P>, HqcPkeSecretKey<P>), HqcPkeError> {
        self.keygen_from_derived_seeds(seed_pke)
    }

    pub fn keygen_with_seed(
        &self,
        seed: &[u8],
    ) -> Result<(HqcPkePublicKey<P>, HqcPkeSecretKey<P>), HqcPkeError> {
        // Step 1: Derive seed_kem from entropy using PRNG (SHAKE-256 with domain=0)
        // This matches the reference implementation prng_init/prng_get_bytes exactly:
        //   shake256_inc_absorb(&shake256_prng_ctx, entropy_input, enlen);
        //   shake256_inc_absorb(&shake256_prng_ctx, personalization_string, perlen); // empty
        //   shake256_inc_absorb(&shake256_prng_ctx, &domain, 1);
        //   shake256_inc_finalize(&shake256_prng_ctx);
        let mut prng_ctx = Shake256Xof::new();
        prng_ctx.absorb(seed).map_err(|_| HqcPkeError::HashError)?;
        prng_ctx.absorb(&[]).map_err(|_| HqcPkeError::HashError)?; // empty personalization string
        const HQC_PRNG_DOMAIN: u8 = 0;
        prng_ctx
            .absorb(&[HQC_PRNG_DOMAIN])
            .map_err(|_| HqcPkeError::HashError)?;
        prng_ctx
            .finalize_absorb()
            .map_err(|_| HqcPkeError::HashError)?;
        let mut seed_kem = [0u8; 32];
        prng_ctx
            .squeeze(&mut seed_kem)
            .map_err(|_| HqcPkeError::HashError)?;

        // Step 2: Derive seed_pke from seed_kem using XOF (SHAKE-256 with domain=1)
        // This matches the reference implementation in kem.c:
        //   xof_init(&ctx_kem, seed_kem, SEED_BYTES);
        //   xof_get_bytes(&ctx_kem, seed_pke, SEED_BYTES);
        let mut xof_ctx = Shake256Xof::new();
        xof_ctx
            .init_with_domain(&seed_kem, 1) // HQC_XOF_DOMAIN = 1
            .map_err(|_| HqcPkeError::HashError)?;
        let mut seed_pke = [0u8; 32];
        xof_ctx
            .squeeze(&mut seed_pke)
            .map_err(|_| HqcPkeError::HashError)?;

        self.keygen_from_derived_seeds(&seed_pke)
    }

    fn keygen_from_derived_seeds(
        &self,
        seed_pke: &[u8; 32],
    ) -> Result<(HqcPkePublicKey<P>, HqcPkeSecretKey<P>), HqcPkeError> {
        // Step 3: Derive keypair seeds using hash_i (SHA3-512 with domain=2)
        // This matches the reference implementation in hqc.c:
        //   hash_i(keypair_seed, seed);  // seed is seed_pke
        let mut keypair_seed = [0u8; 64];
        self.hash_i(&mut keypair_seed, seed_pke);

        // Split the 64-byte hash output into seed_dk and seed_ek
        let mut seed_dk = [0u8; 32];
        let mut seed_ek = [0u8; 32];
        seed_dk.copy_from_slice(&keypair_seed[..32]);
        seed_ek.copy_from_slice(&keypair_seed[32..64]);

        // Generate decryption key components using seed_dk
        let mut dk_xof = Shake256Xof::new();
        dk_xof
            .init_with_domain(&seed_dk, 1)
            .map_err(|_| HqcPkeError::HashError)?;

        let mut y: Vec<u64> = vec![0u64; P::VEC_N_SIZE_64];
        let mut x: Vec<u64> = vec![0u64; P::VEC_N_SIZE_64];

        self.vect_sample_fixed_weight1(&mut dk_xof, &mut y, P::OMEGA)?;
        self.vect_sample_fixed_weight1(&mut dk_xof, &mut x, P::OMEGA)?;

        // Generate encryption key components using seed_ek
        let mut ek_xof = Shake256Xof::new();
        ek_xof
            .init_with_domain(&seed_ek, 1)
            .map_err(|_| HqcPkeError::HashError)?;

        let mut h: Vec<u64> = vec![0u64; P::VEC_N_SIZE_64];
        self.vect_set_random(&mut ek_xof, &mut h)?;

        // Compute s = y*h + x
        let mut s: Vec<u64> = vec![0u64; P::VEC_N_SIZE_64];
        self.vect_mul(&mut s, &y, &h)?;
        let s_copy = s.clone();
        self.vect_add(&mut s, &x, &s_copy, P::VEC_N_SIZE_64)?;

        // NIST / reference `ek_kem` wire format: seed_ek (32) ‖ serialized s.
        let s_len = P::PUBLIC_KEY_BYTES - 32;
        let mut public_key_data: Vec<u8> = vec![0u8; P::PUBLIC_KEY_BYTES];
        public_key_data[..32].copy_from_slice(&seed_ek);
        self.vect_to_bytes(&s, &mut public_key_data[32..32 + s_len])?;

        // Create secret key (seed_dk)
        let secret_key_data = seed_dk;

        Ok((
            HqcPkePublicKey::new(public_key_data),
            HqcPkeSecretKey::new(secret_key_data),
        ))
    }

    /// Encrypt a message using HQC PKE
    pub fn encrypt(
        &self,
        public_key: &HqcPkePublicKey<P>,
        message: &[u64],
        theta: &[u8],
    ) -> Result<HqcPkeCiphertext<P>, HqcPkeError> {
        let mut theta_xof = Shake256Xof::new();
        theta_xof
            .init_with_domain(theta, 1)
            .map_err(|_| HqcPkeError::HashError)?;

        // Retrieve h and s from public key
        let (h, s) = public_key.parse()?;

        // Generate random vectors
        let mut r1 = vec![0u64; P::VEC_N_SIZE_64];
        let mut r2 = vec![0u64; P::VEC_N_SIZE_64];
        let mut e = vec![0u64; P::VEC_N_SIZE_64];

        self.vect_sample_fixed_weight2(&mut theta_xof, &mut r2, P::OMEGA_R)?;
        self.vect_sample_fixed_weight2(&mut theta_xof, &mut e, P::OMEGA_E)?;
        self.vect_sample_fixed_weight2(&mut theta_xof, &mut r1, P::OMEGA_R)?;

        // Compute u = r1 + r2*h
        let mut u = { vec![0u64; P::VEC_N_SIZE_64] };
        self.vect_mul(&mut u, &r2, &h)?;
        let u_copy = u.clone();
        self.vect_add(&mut u, &r1, &u_copy, P::VEC_N_SIZE_64)?;

        // Compute v = C.encode(m) (work directly with u64 arrays)
        let mut v = vec![0u64; P::VEC_N1N2_SIZE_64];

        // Encode message directly to u64 array using concatenated code
        self.concatenated_code.code_encode(&mut v, message)?;

        // Compute v = C.encode(m) + Truncate(s*r2 + e)
        let mut tmp = vec![0u64; P::VEC_N_SIZE_64];
        self.vect_mul(&mut tmp, &r2, &s)?;
        let tmp_copy = tmp.clone();
        self.vect_add(&mut tmp, &e, &tmp_copy, P::VEC_N_SIZE_64)?;
        self.vect_truncate(&mut tmp);

        // Do vector addition in the field (add to first VEC_N1N2_SIZE_64 words)
        let v_copy = v.clone();
        self.vect_add(&mut v, &v_copy, &tmp, P::VEC_N1N2_SIZE_64)?;

        // Create ciphertext
        let mut ciphertext_data = { vec![0u8; P::CIPHERTEXT_BYTES] };
        self.vect_to_bytes(&u, &mut ciphertext_data[..P::VEC_N_SIZE_BYTES])?;
        self.vect_to_bytes(
            &v,
            &mut ciphertext_data[P::VEC_N_SIZE_BYTES..P::VEC_N_SIZE_BYTES + P::VEC_N1N2_SIZE_BYTES],
        )?;

        Ok(HqcPkeCiphertext::new(ciphertext_data))
    }

    /// Decrypt a ciphertext using HQC PKE
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        &self,
        secret_key: &HqcPkeSecretKey<P>,
        ciphertext: &HqcPkeCiphertext<P>,
    ) -> Result<Vec<u64>, HqcPkeError> {
        // Parse secret key to get y
        let y = secret_key.parse(self)?;

        // Parse ciphertext to get u and v (both as u64 arrays)
        let (u, v_bytes) = ciphertext.parse()?;

        // Convert v from bytes to u64 array
        let mut v = { vec![0u64; P::VEC_N1N2_SIZE_64] };
        self.bytes_to_vect(&v_bytes, &mut v)?;

        // Compute u*y
        let mut tmp1 = { vec![0u64; P::VEC_N_SIZE_64] };
        self.vect_mul(&mut tmp1, &y, &u)?;

        // Truncate(u*y)
        self.vect_truncate(&mut tmp1);

        // Compute v - Truncate(u*y) (work directly with u64 arrays)
        let v_copy = v.clone();
        self.vect_add(&mut v, &v_copy, &tmp1, P::VEC_N1N2_SIZE_64)?;

        // Decode directly from u64 array using concatenated code
        let mut message = { vec![0u64; P::K.div_ceil(8)] };
        self.concatenated_code.code_decode(&mut message, &v)?;

        Ok(message)
    }

    /// Convert bytes to u64 array
    pub fn bytes_to_u64_array(&self, bytes: &[u8], length: usize) -> Vec<u64> {
        let mut result = Vec::new();
        let num_u64_values = length.div_ceil(8); // Round up to get number of u64 values needed
        for i in 0..num_u64_values {
            let start = i * 8;
            if start < bytes.len() {
                let mut array = [0u8; 8];
                let end = (start + 8).min(bytes.len());
                array[..end - start].copy_from_slice(&bytes[start..end]);
                result.push(u64::from_le_bytes(array));
            }
        }
        result
    }

    /// Convert u64 array to bytes
    pub fn u64_array_to_bytes(&self, array: &[u64], length: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let num_u64_values = length.div_ceil(8); // Round up to get number of u64 values needed
        for (i, &value) in array.iter().enumerate().take(num_u64_values) {
            let bytes = value.to_le_bytes();
            let start = i * 8;
            if start < length {
                let end = (start + 8).min(length);
                result.extend_from_slice(&bytes[..end - start]);
            }
        }
        result
    }

    /// Public wrapper for polynomial multiplication (for testing)
    pub fn test_vect_mul(
        &self,
        output: &mut [u64],
        a: &[u64],
        b: &[u64],
    ) -> Result<(), HqcPkeError> {
        self.vect_mul(output, a, b)
    }

    /// Test vector addition
    pub fn test_vect_add(
        &self,
        output: &mut [u64],
        a: &[u64],
        b: &[u64],
        len: usize,
    ) -> Result<(), HqcPkeError> {
        self.vect_add(output, a, b, len)
    }

    /// Test vector truncation
    pub fn test_vect_truncate(&self, output: &mut [u64], input: &[u64]) {
        // Copy input to output first (handle different lengths)
        let copy_len = output.len().min(input.len());
        output[..copy_len].copy_from_slice(&input[..copy_len]);
        // Zero out remaining elements
        for item in output.iter_mut().skip(copy_len) {
            *item = 0;
        }
        // Then truncate in place
        self.vect_truncate(output)
    }

    /// Test Hamming weight calculation
    pub fn test_vect_hamming_weight(&self, v: &[u64]) -> usize {
        v.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Test vector to hex formatting for diagnostics (no_std compatible)
    pub fn test_vect_to_hex(&self, v: &[u64], count: usize) -> String {
        let actual_count = count.min(v.len());
        let hex_parts: Vec<String> = v[..actual_count]
            .iter()
            .map(|w| alloc::format!("{:016x}", w))
            .collect();
        alloc::format!("[{}, ...]", hex_parts.join(", "))
    }

    /// Test method for bytes_to_vect (for debugging)
    pub fn test_bytes_to_vect(&self, input: &[u8], output: &mut [u64]) -> Result<(), HqcPkeError> {
        self.bytes_to_vect(input, output)
    }

    /// Test method for vect_to_bytes (for debugging)
    pub fn test_vect_to_bytes(&self, input: &[u64], output: &mut [u8]) -> Result<(), HqcPkeError> {
        self.vect_to_bytes(input, output)
    }

    /// Test method for vect_sample_fixed_weight2 (for debugging)
    pub fn test_vect_sample_fixed_weight2(
        &self,
        xof: &mut Shake256Xof,
        output: &mut [u64],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        self.vect_sample_fixed_weight2(xof, output, weight)
    }

    /// Test method for vect_sample_fixed_weight1 (for debugging)
    pub fn test_vect_sample_fixed_weight1(
        &self,
        xof: &mut Shake256Xof,
        output: &mut [u64],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        self.vect_sample_fixed_weight1(xof, output, weight)
    }

    /// Test method for vect_generate_random_support1 (for debugging)
    pub fn test_vect_generate_random_support1(
        &self,
        xof: &mut Shake256Xof,
        support: &mut [u32],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        self.vect_generate_random_support1(xof, support, weight)
    }

    /// Test method for vect_write_support_to_vector (for debugging)
    pub fn test_vect_write_support_to_vector(
        &self,
        output: &mut [u64],
        support: &[u32],
        weight: usize,
    ) {
        self.vect_write_support_to_vector(output, support, weight)
    }

    /// Test method for hash_i (for debugging)
    pub fn test_hash_i(&self, output: &mut [u8], input: &[u8]) {
        self.hash_i(output, input)
    }

    /// Test code encode
    pub fn test_code_encode(&self, output: &mut [u64], message: &[u64]) -> Result<(), HqcPkeError> {
        self.concatenated_code
            .code_encode(output, message)
            .map_err(HqcPkeError::CodeError)
    }

    /// Test code decode
    pub fn test_code_decode(&self, output: &mut [u64], input: &[u64]) -> Result<(), HqcPkeError> {
        self.concatenated_code
            .code_decode(output, input)
            .map_err(HqcPkeError::CodeError)
    }

    // Helper functions

    /// Hash function hash_i (SHA3-512 with domain separation)
    /// I(str) = SHA3-512(str || I_DOMAIN_SEPARATOR)
    /// Used to derive (seedPKE.dk, seedPKE.ek) from seedPKE
    pub fn hash_i(&self, output: &mut [u8], input: &[u8]) {
        use lib_q_sha3::{
            Digest,
            Sha3_512,
        };

        const I_DOMAIN_SEPARATOR: u8 = 2; // HQC_I_FCT_DOMAIN = 2 (2025 specification)

        let mut hasher = Sha3_512::new();
        // Only absorb SEED_BYTES (32 bytes) from the input, as per reference implementation
        let seed_bytes = core::cmp::min(input.len(), 32);
        hasher.update(&input[..seed_bytes]);
        hasher.update([I_DOMAIN_SEPARATOR]);
        let result = hasher.finalize();
        output.copy_from_slice(&result);
    }

    /// Sample fixed weight vector (method 1)
    pub fn vect_sample_fixed_weight1(
        &self,
        xof: &mut Shake256Xof,
        output: &mut [u64],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        // Implementation based on reference vector.c
        // Clear output
        for item in &mut *output {
            *item = 0;
        }

        let mut support = vec![0u32; weight];
        self.vect_generate_random_support1(xof, &mut support, weight)?;
        self.vect_write_support_to_vector(output, &support, weight);

        Ok(())
    }

    /// Generate random support set (method 1)
    pub fn vect_generate_random_support1(
        &self,
        xof: &mut Shake256Xof,
        support: &mut [u32],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        let random_bytes_size = 3 * weight;
        let mut rand_bytes = vec![0u8; random_bytes_size];
        let mut i = 0;
        let mut j = random_bytes_size;

        while i < weight {
            loop {
                if j == random_bytes_size {
                    // Use xof_get_bytes to match reference XOF consumption behavior
                    Self::xof_get_bytes(xof, &mut rand_bytes)?;
                    j = 0;
                }

                support[i] = ((rand_bytes[j] as u32) << 16) |
                    ((rand_bytes[j + 1] as u32) << 8) |
                    (rand_bytes[j + 2] as u32);
                j += 3;

                if support[i] < P::UTILS_REJECTION_THRESHOLD {
                    break;
                }
            }

            support[i] = self.barrett_reduce(support[i]);

            let mut inc = 1;
            for k in 0..i {
                if support[k] == support[i] {
                    inc = 0;
                }
            }
            i += inc;
        }

        Ok(())
    }

    /// Generate random support set (method 2) - for encryption vectors
    pub fn vect_generate_random_support2(
        &self,
        xof: &mut Shake256Xof,
        support: &mut [u32],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        // Implementation based on reference vector.c vect_generate_random_support2
        let mut rand_u32 = vec![0u32; weight];

        // Get random bytes from XOF using reference-compatible behavior
        let mut bytes = vec![0u8; weight * 4];
        Self::xof_get_bytes(xof, &mut bytes)?;

        // Convert bytes to u32 array (little-endian)
        for (i, item) in rand_u32.iter_mut().enumerate() {
            let start = i * 4;
            let end = start + 4;
            let mut u32_bytes = [0u8; 4];
            u32_bytes.copy_from_slice(&bytes[start..end]);
            *item = u32::from_le_bytes(u32_bytes);
        }

        // Generate support using the method 2 algorithm
        for i in 0..weight {
            let buff = rand_u32[i] as u64;
            support[i] = i as u32 + ((buff * (P::N as u64 - i as u64)) >> 32) as u32;
        }

        // Handle collisions using the reference algorithm
        for i in (0..weight - 1).rev() {
            let mut found = 0u32;

            for j in (i + 1)..weight {
                if support[j] == support[i] {
                    found = 1;
                }
            }

            let mask = if found != 0 {
                0xFFFFFFFFu32
            } else {
                0x00000000u32
            };
            support[i] = (mask & (i as u32)) ^ (!mask & support[i]);
        }

        Ok(())
    }

    /// Barrett reduction modulo PARAM_N
    pub fn barrett_reduce(&self, x: u32) -> u32 {
        let q = ((x as u64) * P::N_MU) >> 32;
        let mut r = x - (q * P::N as u64) as u32;

        // Constant-time final reduction (matches reference)
        let reduce_flag = ((r.wrapping_sub(P::N as u32)) >> 31) ^ 1;
        let mask = (-(reduce_flag as i32)) as u32;
        r -= mask & (P::N as u32);

        r
    }

    /// Write support to vector
    pub fn vect_write_support_to_vector(&self, v: &mut [u64], support: &[u32], weight: usize) {
        // Precompute index_tab and bit_tab like reference
        let mut index_tab = vec![0u32; weight];
        let mut bit_tab = vec![0u64; weight];

        for i in 0..weight {
            index_tab[i] = support[i] >> 6;
            let pos = support[i] & 0x3F;
            bit_tab[i] = 1u64 << pos;
        }

        // Constant-time vector write (matches reference)
        for (i, val) in v.iter_mut().enumerate() {
            let mut temp_val = 0u64;
            for j in 0..weight {
                let tmp = i.wrapping_sub(index_tab[j] as usize);
                // Constant-time check if tmp == 0
                let val1 = 1u32 ^ ((tmp as u32 | tmp.wrapping_neg() as u32) >> 31);
                let mask = (-(val1 as i64)) as u64;
                temp_val |= bit_tab[j] & mask;
            }
            *val |= temp_val; // Use |= not = (accumulate, don't replace)
        }
    }

    /// Sample fixed weight vector (method 2)
    pub fn vect_sample_fixed_weight2(
        &self,
        xof: &mut Shake256Xof,
        output: &mut [u64],
        weight: usize,
    ) -> Result<(), HqcPkeError> {
        // Implementation based on reference vector.c
        // Clear output
        for item in &mut *output {
            *item = 0;
        }

        let mut support = vec![0u32; weight];
        self.vect_generate_random_support2(xof, &mut support, weight)?;
        self.vect_write_support_to_vector(output, &support, weight);

        Ok(())
    }

    /// Set random vector
    /// Matches reference xof_get_bytes behavior which handles non-8-byte-aligned sizes specially
    pub fn vect_set_random(
        &self,
        xof: &mut Shake256Xof,
        output: &mut [u64],
    ) -> Result<(), HqcPkeError> {
        // Match reference: xof_get_bytes(ctx, (uint8_t *)v, VEC_N_SIZE_BYTES);
        // The reference uses VEC_N_SIZE_BYTES, not output.len() * 8!
        // For HQC-128: VEC_N_SIZE_BYTES = 2209, not 277 * 8 = 2216
        let output_size = P::VEC_N_SIZE_BYTES;

        // Reference xof_get_bytes has special handling for non-8-byte-aligned sizes:
        // 1. Squeeze (output_size - remainder) bytes directly
        // 2. Squeeze 8 more bytes into tmp buffer
        // 3. Copy only 'remainder' bytes from tmp
        // This ensures the XOF state is advanced consistently
        let bsize = 8usize;
        let remainder = output_size % bsize;

        // Clear output first
        for item in output.iter_mut() {
            *item = 0;
        }

        if remainder == 0 {
            // Output size is 8-byte aligned - simple case
            let mut bytes = vec![0u8; output_size];
            xof.squeeze(&mut bytes)
                .map_err(|_| HqcPkeError::HashError)?;

            for (i, item) in output.iter_mut().enumerate() {
                let start = i * 8;
                if start + 8 <= bytes.len() {
                    let mut u64_bytes = [0u8; 8];
                    u64_bytes.copy_from_slice(&bytes[start..start + 8]);
                    *item = u64::from_le_bytes(u64_bytes);
                }
            }
        } else {
            // Output size is NOT 8-byte aligned - match reference xof_get_bytes behavior
            // Squeeze the aligned portion
            let aligned_size = output_size - remainder;
            let mut aligned_bytes = vec![0u8; aligned_size];
            xof.squeeze(&mut aligned_bytes)
                .map_err(|_| HqcPkeError::HashError)?;

            // Squeeze 8 more bytes into tmp (reference behavior!)
            let mut tmp = [0u8; 8];
            xof.squeeze(&mut tmp).map_err(|_| HqcPkeError::HashError)?;

            // Convert aligned portion to u64s
            let full_words = aligned_size / 8;
            for (i, chunk) in aligned_bytes.chunks_exact(8).enumerate().take(full_words) {
                let mut u64_bytes = [0u8; 8];
                u64_bytes.copy_from_slice(chunk);
                output[i] = u64::from_le_bytes(u64_bytes);
            }

            // Handle the last partial word using tmp (only first 'remainder' bytes)
            if full_words < output.len() {
                let mut last_bytes = [0u8; 8];
                last_bytes[..remainder].copy_from_slice(&tmp[..remainder]);
                output[full_words] = u64::from_le_bytes(last_bytes);
            }
        }

        // Apply bitmask to last word (reference: v[VEC_N_SIZE_64 - 1] &= BITMASK(PARAM_N, 64))
        if !output.is_empty() {
            let last_word_idx = output.len() - 1;
            if P::N % 64 != 0 {
                let bitmask = (1u64 << (P::N % 64)) - 1;
                output[last_word_idx] &= bitmask;
            }
        }

        Ok(())
    }

    /// Vector multiplication in GF(2)[x]/(x^n - 1)
    fn vect_mul(&self, output: &mut [u64], a: &[u64], b: &[u64]) -> Result<(), HqcPkeError> {
        if output.len() != P::VEC_N_SIZE_64 {
            return Err(HqcPkeError::InvalidKey);
        }

        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64", feature = "alloc"))]
        {
            if crate::simd::runtime::has_avx2() {
                return crate::simd::avx2::gf2x::avx2_vect_mul_mod_xnm1::<P>(output, a, b);
            }
        }

        schoolbook_vect_mul_mod_xnm1(output, a, b, P::VEC_N_SIZE_64, P::N)
    }

    /// Vector addition in GF(2)
    fn vect_add(
        &self,
        output: &mut [u64],
        a: &[u64],
        b: &[u64],
        len: usize,
    ) -> Result<(), HqcPkeError> {
        #[cfg(feature = "simd-avx2")]
        {
            // Check if AVX2 is available at runtime
            if crate::simd::runtime::has_avx2() {
                // Use Avx2 ZST directly via trait
                use crate::simd::{
                    Avx2,
                    PolynomialOps,
                };

                let a_bytes =
                    unsafe { core::slice::from_raw_parts(a.as_ptr() as *const u8, len * 8) };
                let b_bytes =
                    unsafe { core::slice::from_raw_parts(b.as_ptr() as *const u8, len * 8) };
                let output_bytes = unsafe {
                    core::slice::from_raw_parts_mut(output.as_mut_ptr() as *mut u8, len * 8)
                };

                Avx2::vect_add(output_bytes, a_bytes, b_bytes);
                return Ok(());
            }
        }

        // Fallback to portable implementation
        for i in 0..len {
            if i < output.len() && i < a.len() && i < b.len() {
                output[i] = a[i] ^ b[i];
            }
        }
        Ok(())
    }

    /// Vector truncation
    fn vect_truncate(&self, output: &mut [u64]) {
        // Truncate to N1N2 bits (exactly matching reference)
        let orig_words = output.len();
        let new_full_words = P::N1N2 / 64;
        let remaining_bits = P::N1N2 % 64;

        // Mask the last word if there's a partial word
        if remaining_bits > 0 {
            let mask = (1u64 << remaining_bits) - 1;
            if new_full_words < output.len() {
                output[new_full_words] &= mask;
            }
            // Zero out all subsequent words up to the original length
            for i in (new_full_words + 1)..orig_words {
                if i < output.len() {
                    output[i] = 0;
                }
            }
        } else {
            // No remaining bits, zero out all words from new_full_words onwards
            for i in new_full_words..orig_words {
                if i < output.len() {
                    output[i] = 0;
                }
            }
        }
    }

    /// Convert vector to bytes (matches reference hqc_store8)
    /// Writes exactly output.len() bytes from the input u64 array
    fn vect_to_bytes(&self, input: &[u64], output: &mut [u8]) -> Result<(), HqcPkeError> {
        let full_words = output.len() / 8;
        let remainder = output.len() % 8;

        // Write full 8-byte words
        for i in 0..full_words {
            if i >= input.len() {
                break;
            }
            let start = i * 8;
            output[start..start + 8].copy_from_slice(&input[i].to_le_bytes());
        }

        // Write remaining partial bytes from the last word
        if remainder > 0 && full_words < input.len() {
            let start = full_words * 8;
            let word_bytes = input[full_words].to_le_bytes();
            output[start..start + remainder].copy_from_slice(&word_bytes[..remainder]);
        }

        Ok(())
    }

    /// Convert bytes to vector
    fn bytes_to_vect(&self, input: &[u8], output: &mut [u64]) -> Result<(), HqcPkeError> {
        for (i, chunk) in input.chunks(8).enumerate() {
            if i >= output.len() {
                break;
            }
            let mut bytes = [0u8; 8];
            for (j, &byte) in chunk.iter().enumerate() {
                if j < 8 {
                    bytes[j] = byte;
                }
            }
            output[i] = u64::from_le_bytes(bytes);
        }
        Ok(())
    }
}

/// HQC PKE Public Key
#[derive(Debug, Clone, PartialEq)]
pub struct HqcPkePublicKey<P: HqcParams> {
    pub data: Vec<u8>,
    _params: core::marker::PhantomData<P>,
}

impl<P: HqcParams> HqcPkePublicKey<P> {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            _params: core::marker::PhantomData,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn parse(&self) -> Result<(Vec<u64>, Vec<u64>), HqcPkeError> {
        if self.data.len() != P::PUBLIC_KEY_BYTES {
            return Err(HqcPkeError::InvalidKey);
        }

        if self.data.len() < 32 {
            return Err(HqcPkeError::InvalidKey);
        }

        let mut seed_ek = [0u8; 32];
        seed_ek.copy_from_slice(&self.data[..32]);
        let s_len = P::PUBLIC_KEY_BYTES - 32;
        let pke = HqcPke::<P>::new().map_err(|_| HqcPkeError::HashError)?;

        let mut ek_xof = Shake256Xof::new();
        ek_xof
            .init_with_domain(&seed_ek, 1)
            .map_err(|_| HqcPkeError::HashError)?;
        let mut h = vec![0u64; P::VEC_N_SIZE_64];
        pke.vect_set_random(&mut ek_xof, &mut h)?;

        let mut s = vec![0u64; P::VEC_N_SIZE_64];
        pke.bytes_to_vect(&self.data[32..32 + s_len], &mut s)?;

        Ok((h, s))
    }
}

/// HQC PKE Secret Key
#[derive(Debug, Clone, PartialEq)]
pub struct HqcPkeSecretKey<P: HqcParams> {
    pub data: [u8; 32], // SEED_BYTES
    _params: core::marker::PhantomData<P>,
}

impl<P: HqcParams> HqcPkeSecretKey<P> {
    pub fn new(data: [u8; 32]) -> Self {
        Self {
            data,
            _params: core::marker::PhantomData,
        }
    }

    pub fn parse(&self, pke: &HqcPke<P>) -> Result<Vec<u64>, HqcPkeError> {
        let mut y = { vec![0u64; P::VEC_N_SIZE_64] };

        let mut dk_xof = Shake256Xof::new();
        dk_xof
            .init_with_domain(&self.data, 1)
            .map_err(|_| HqcPkeError::HashError)?;

        // Generate y and x in the same order as key generation
        pke.vect_sample_fixed_weight1(&mut dk_xof, &mut y, P::OMEGA)?;
        let mut temp = { vec![0u64; P::VEC_N_SIZE_64] };
        pke.vect_sample_fixed_weight1(&mut dk_xof, &mut temp, P::OMEGA)?;

        Ok(y)
    }
}

/// HQC PKE Ciphertext
#[derive(Debug, Clone, PartialEq)]
pub struct HqcPkeCiphertext<P: HqcParams> {
    pub data: Vec<u8>,
    _params: core::marker::PhantomData<P>,
}

impl<P: HqcParams> HqcPkeCiphertext<P> {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            _params: core::marker::PhantomData,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..P::CIPHERTEXT_BYTES]
    }

    #[cfg(feature = "alloc")]
    pub fn parse(&self) -> Result<(Vec<u64>, Vec<u8>), HqcPkeError> {
        let u_bytes = &self.data[..P::VEC_N_SIZE_BYTES];
        let v_bytes = &self.data[P::VEC_N_SIZE_BYTES..P::VEC_N_SIZE_BYTES + P::VEC_N1N2_SIZE_BYTES];

        let mut u = { vec![0u64; P::VEC_N_SIZE_64] };
        for (i, chunk) in u_bytes.chunks(8).enumerate() {
            if i >= u.len() {
                break;
            }
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            u[i] = u64::from_le_bytes(bytes);
        }

        Ok((u, v_bytes.to_vec()))
    }
}

/// HQC PKE error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HqcPkeError {
    CodeError(ConcatenatedCodeError),
    HashError,
    InvalidKey,
    InvalidCiphertext,
    DecryptionFailed,
}

impl fmt::Display for HqcPkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HqcPkeError::CodeError(e) => write!(f, "Code error: {}", e),
            HqcPkeError::HashError => write!(f, "Hash error"),
            HqcPkeError::InvalidKey => write!(f, "Invalid key"),
            HqcPkeError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            HqcPkeError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl From<ConcatenatedCodeError> for HqcPkeError {
    fn from(error: ConcatenatedCodeError) -> Self {
        HqcPkeError::CodeError(error)
    }
}

/// Schoolbook product in GF(2)[x]/(x^n - 1) matching the reference `gf2x` path.
///
/// `n_bits` is the HQC parameter `N`; `vec_n_words` is `ceil(n_bits / 64)`.
/// Used by [`HqcPke::vect_mul`] and exposed for regression tests against SIMD paths.
#[doc(hidden)]
pub fn schoolbook_vect_mul_mod_xnm1(
    output: &mut [u64],
    a: &[u64],
    b: &[u64],
    vec_n_words: usize,
    n_bits: usize,
) -> Result<(), HqcPkeError> {
    debug_assert!(
        !n_bits.is_multiple_of(64),
        "schoolbook_vect_mul_mod_xnm1: N multiple of 64 not supported by this reduction"
    );
    if output.len() != vec_n_words || a.len() < vec_n_words || b.len() < vec_n_words {
        return Err(HqcPkeError::InvalidKey);
    }

    let mut unreduced = vec![0u64; 2 * vec_n_words];
    let mask_n = n_bits & 0x3F;

    for (i, &ai) in a.iter().enumerate().take(vec_n_words) {
        for bit in 0..64 {
            let mask = if (ai >> bit) & 1 == 1 { !0u64 } else { 0u64 };
            let base = i;
            let sh = bit;
            let inv = 64 - sh;

            if sh == 0 {
                for j in 0..vec_n_words {
                    unreduced[base + j] ^= b[j] & mask;
                }
            } else {
                for j in 0..vec_n_words {
                    unreduced[base + j] ^= (b[j] << sh) & mask;
                    unreduced[base + j + 1] ^= (b[j] >> inv) & mask;
                }
            }
        }
    }

    for i in 0..vec_n_words {
        let r = unreduced[i + vec_n_words - 1] >> mask_n;
        let carry = unreduced[i + vec_n_words] << (64 - mask_n);
        output[i] = unreduced[i] ^ r ^ carry;
    }

    output[vec_n_words - 1] &= (1u64 << mask_n) - 1;
    Ok(())
}
