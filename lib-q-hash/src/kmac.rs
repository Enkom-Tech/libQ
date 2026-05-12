//! KMAC (KECCAK Message Authentication Code) implementation
//!
//! This module provides KMAC128 and KMAC256 implementations as specified in SP800-185.
//! KMAC is a PRF and keyed hash function based on cSHAKE.
//!
//! # Security note
//!
//! KMAC initialization absorbs `bytepad(encode_string(K), rate)` directly into the sponge
//! without heap-backed temporary buffers containing key material. This reduces key exposure
//! in freed/reallocated heap regions and aligns with audit expectations for secret handling.
//!
//! For MAC equality checks, use [`Kmac128::verify`](Kmac128::verify) /
//! [`Kmac256::verify`](Kmac256::verify) instead of comparing `finalize` output with `==`,
//! which is not constant-time.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use digest::block_api::{
    AlgorithmName,
    Block,
    BlockSizeUser,
    BufferKindUser,
    Eager,
    UpdateCore,
};
use digest::common::hazmat::{
    DeserializeStateError,
    SerializableState,
    SerializedState,
};
use digest::consts::{
    U16,
    U32,
    U136,
    U168,
    U400,
};
use digest::{
    CollisionResistance,
    ExtendableOutput,
    HashMarker,
    Reset,
    Update,
    XofReader,
};
use subtle::{
    Choice,
    ConstantTimeEq,
};
use zeroize::Zeroize;

use crate::cshake::{
    CShake128,
    CShake128Reader,
    CShake256,
    CShake256Reader,
};
use crate::utils::{
    left_encode,
    right_encode,
};

/// KMAC128 implementation
#[derive(Clone)]
pub struct Kmac128 {
    inner: CShake128,
}

/// KMAC256 implementation
#[derive(Clone)]
pub struct Kmac256 {
    inner: CShake256,
}

/// KMAC128 XOF reader
#[derive(Clone)]
pub struct Kmac128Reader {
    inner: CShake128Reader,
}

/// KMAC256 XOF reader
#[derive(Clone)]
pub struct Kmac256Reader {
    inner: CShake256Reader,
}

macro_rules! impl_kmac {
    (
        $name:ident, $inner_type:ident, $reader_name:ident, $inner_reader_type:ident, $rate:ident, $rate_expr:expr, $alg_name:expr
    ) => {
        impl $name {
            /// Creates a new KMAC instance with the given key and customization string
            pub fn new(key: &[u8], custom: &[u8]) -> Self {
                let mut kmac = Self {
                    inner: $inner_type::new_with_function_name(b"KMAC", custom),
                };
                kmac.init(key, $rate_expr);
                kmac
            }

            fn init(&mut self, key: &[u8], rate: usize) {
                // Stream bytepad(encode_string(K), rate) directly into the
                // sponge so key material never lands in heap-allocated
                // temporaries.
                let mut enc_buf = [0u8; 9];
                let mut total = 0usize;

                // bytepad outer: left_encode(rate)
                let le = left_encode(rate as u64, &mut enc_buf);
                Update::update(&mut self.inner, le);
                total += le.len();

                // encode_string(K) = left_encode(len(K)*8) || K
                let le = left_encode((key.len() * 8) as u64, &mut enc_buf);
                Update::update(&mut self.inner, le);
                total += le.len();

                Update::update(&mut self.inner, key);
                total += key.len();

                // Zero-pad to a multiple of `rate` with stack memory.
                let padding = (rate - (total % rate)) % rate;
                if padding > 0 {
                    const ZEROS: [u8; 168] = [0u8; 168];
                    Update::update(&mut self.inner, &ZEROS[..padding]);
                }
            }

            /// Update with data
            pub fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.inner, data);
            }

            /// Finalize with specified output length
            pub fn finalize(mut self, output: &mut [u8]) {
                self.with_bitlength((output.len() * 8) as u64);
                ExtendableOutput::finalize_xof_into(self.inner, output);
            }

            /// Finalize and compare the MAC to `expected` in constant time.
            ///
            /// The MAC output length is `expected.len()` (same encoding as [`Self::finalize`]
            /// with an output buffer of that length). The computed MAC is zeroized before
            /// returning.
            ///
            /// Combine or inspect the result with `subtle` APIs before branching on validity if
            /// control-flow timing is a concern.
            pub fn verify(mut self, expected: &[u8]) -> Choice {
                let mut mac = vec![0u8; expected.len()];
                self.with_bitlength((mac.len() * 8) as u64);
                ExtendableOutput::finalize_xof_into(self.inner, &mut mac);
                let ok = mac.ct_eq(expected);
                mac.zeroize();
                ok
            }

            /// Finalize with specified output length and return as Vec
            pub fn finalize_with_length(mut self, output_len: usize) -> Vec<u8> {
                let mut output = vec![0u8; output_len];
                self.with_bitlength((output_len * 8) as u64);
                ExtendableOutput::finalize_xof_into(self.inner, &mut output);
                output
            }

            /// Get XOF reader for variable-length output
            pub fn xof(mut self) -> $reader_name {
                self.with_bitlength(0);
                $reader_name {
                    inner: ExtendableOutput::finalize_xof(self.inner),
                }
            }

            fn with_bitlength(&mut self, bitlength: u64) {
                let mut enc_buf = [0u8; 9];
                let length_encoded = right_encode(bitlength, &mut enc_buf);
                Update::update(&mut self.inner, length_encoded);
            }
        }

        // Digest trait implementations
        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl HashMarker for $name {}

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.inner, data);
            }
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.inner.update(block);
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.inner.reset();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name {}

        // Implement Default trait
        impl Default for $name {
            fn default() -> Self {
                Self::new(b"", b"")
            }
        }

        // Implement XofReader for the reader type
        impl XofReader for $reader_name {
            fn read(&mut self, buf: &mut [u8]) {
                self.inner.read(buf);
            }
        }

        impl fmt::Debug for $reader_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($reader_name), " { ... }"))
            }
        }
    };
}

impl_kmac!(
    Kmac128,
    CShake128,
    Kmac128Reader,
    CShake128Reader,
    U168,
    168usize,
    "KMAC128"
);
impl_kmac!(
    Kmac256,
    CShake256,
    Kmac256Reader,
    CShake256Reader,
    U136,
    136usize,
    "KMAC256"
);

impl CollisionResistance for Kmac128 {
    type CollisionResistance = U16;
}

impl CollisionResistance for Kmac256 {
    type CollisionResistance = U32;
}

// Add SerializableState for KMAC types
impl SerializableState for Kmac128 {
    type SerializedStateSize = U400;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let inner = CShake128::deserialize(serialized_state)?;
        Ok(Self { inner })
    }
}

impl SerializableState for Kmac256 {
    type SerializedStateSize = U400;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let inner = CShake256::deserialize(serialized_state)?;
        Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    fn nist_kmac_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (idx, b) in key.iter_mut().enumerate() {
            *b = 0x40 + (idx as u8);
        }
        key
    }

    fn nist_kmac_short_data() -> [u8; 4] {
        [0x00, 0x01, 0x02, 0x03]
    }

    fn nist_kmac_long_data() -> Vec<u8> {
        (0x00..=0xC7).collect()
    }

    fn kmac128_reference(key: &[u8], custom: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
        let mut inner = CShake128::new_with_function_name(b"KMAC", custom);
        let mut enc_buf = [0u8; 9];
        let mut total = 0usize;

        let le = left_encode(168, &mut enc_buf);
        inner.update(le);
        total += le.len();

        let le = left_encode((key.len() * 8) as u64, &mut enc_buf);
        inner.update(le);
        total += le.len();

        inner.update(key);
        total += key.len();

        let padding = (168 - (total % 168)) % 168;
        if padding > 0 {
            const ZEROS: [u8; 168] = [0u8; 168];
            inner.update(&ZEROS[..padding]);
        }

        inner.update(data);
        inner.update(right_encode((out_len * 8) as u64, &mut enc_buf));

        let mut out = vec![0u8; out_len];
        inner.finalize_xof_into(&mut out);
        out
    }

    fn kmac256_reference(key: &[u8], custom: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
        let mut inner = CShake256::new_with_function_name(b"KMAC", custom);
        let mut enc_buf = [0u8; 9];
        let mut total = 0usize;

        let le = left_encode(136, &mut enc_buf);
        inner.update(le);
        total += le.len();

        let le = left_encode((key.len() * 8) as u64, &mut enc_buf);
        inner.update(le);
        total += le.len();

        inner.update(key);
        total += key.len();

        let padding = (136 - (total % 136)) % 136;
        if padding > 0 {
            const ZEROS: [u8; 136] = [0u8; 136];
            inner.update(&ZEROS[..padding]);
        }

        inner.update(data);
        inner.update(right_encode((out_len * 8) as u64, &mut enc_buf));

        let mut out = vec![0u8; out_len];
        inner.finalize_xof_into(&mut out);
        out
    }

    #[test]
    fn test_kmac128_basic() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        let mut output = [0u8; 32];
        kmac.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_kmac256_basic() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac256::new(key, custom);
        kmac.update(data);

        let mut output = [0u8; 64];
        kmac.finalize(&mut output);
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_kmac_xof() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        let mut reader = kmac.xof();
        let mut output = [0u8; 100];
        reader.read(&mut output);
        assert_ne!(output, [0u8; 100]);
    }

    #[test]
    fn test_kmac_different_keys() {
        let custom = b"custom";
        let data = b"test data";

        let mut kmac1 = Kmac128::new(b"key1", custom);
        kmac1.update(data);
        let mut output1 = [0u8; 32];
        kmac1.finalize(&mut output1);

        let mut kmac2 = Kmac128::new(b"key2", custom);
        kmac2.update(data);
        let mut output2 = [0u8; 32];
        kmac2.finalize(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_kmac_different_customs() {
        let key = b"key";
        let data = b"test data";

        let mut kmac1 = Kmac128::new(key, b"custom1");
        kmac1.update(data);
        let mut output1 = [0u8; 32];
        kmac1.finalize(&mut output1);

        let mut kmac2 = Kmac128::new(key, b"custom2");
        kmac2.update(data);
        let mut output2 = [0u8; 32];
        kmac2.finalize(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_kmac_reset() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        // Reset and test again
        kmac.reset();
        kmac.update(data);

        let mut output = [0u8; 32];
        kmac.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_kmac_default() {
        let kmac = Kmac128::default();
        let data = b"test data";

        let mut hasher = kmac;
        hasher.update(data);
        let result = hasher.finalize_with_length(32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_kmac_serialization() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        // Serialize the state
        let serialized = kmac.serialize();

        // Deserialize and continue
        let mut kmac2 = Kmac128::deserialize(&serialized).unwrap();
        kmac2.update(b"more data");

        let mut output = [0u8; 32];
        kmac2.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_kmac128_matches_reference_construction() {
        let key = b"auditor-sensitive-key-material";
        let custom = b"lib-q kmac reference";
        let data = b"input message for kmac128";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);
        let mut got = [0u8; 32];
        kmac.finalize(&mut got);

        let expected = kmac128_reference(key, custom, data, 32);
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_kmac256_matches_reference_construction() {
        let key = b"auditor-sensitive-key-material";
        let custom = b"lib-q kmac reference";
        let data = b"input message for kmac256";

        let mut kmac = Kmac256::new(key, custom);
        kmac.update(data);
        let mut got = [0u8; 64];
        kmac.finalize(&mut got);

        let expected = kmac256_reference(key, custom, data, 64);
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_kmac128_nist_sample_1() {
        let key = nist_kmac_key();
        let data = nist_kmac_short_data();
        let custom = b"";
        let expected = hex!(
            "E5780B0D3EA6F7D3A429C5706AA43A00
             FADBD7D49628839E3187243F456EE14E"
        );

        let mut kmac = Kmac128::new(&key, custom);
        kmac.update(&data);
        let mut out = [0u8; 32];
        kmac.finalize(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_kmac128_nist_sample_2() {
        let key = nist_kmac_key();
        let data = nist_kmac_short_data();
        let custom = b"My Tagged Application";
        let expected = hex!(
            "3B1FBA963CD8B0B59E8C1A6D71888B71
             43651AF8BA0A7070C0979E2811324AA5"
        );

        let mut kmac = Kmac128::new(&key, custom);
        kmac.update(&data);
        let mut out = [0u8; 32];
        kmac.finalize(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_kmac128_nist_sample_3() {
        let key = nist_kmac_key();
        let data = nist_kmac_long_data();
        let custom = b"My Tagged Application";
        let expected = hex!(
            "1F5B4E6CCA02209E0DCB5CA635B89A15
             E271ECC760071DFD805FAA38F9729230"
        );

        let mut kmac = Kmac128::new(&key, custom);
        kmac.update(&data);
        let mut out = [0u8; 32];
        kmac.finalize(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_kmac256_nist_sample_4() {
        let key = nist_kmac_key();
        let data = nist_kmac_short_data();
        let custom = b"My Tagged Application";
        let expected = hex!(
            "20C570C31346F703C9AC36C61C03CB64
             C3970D0CFC787E9B79599D273A68D2F7
             F69D4CC3DE9D104A351689F27CF6F595
             1F0103F33F4F24871024D9C27773A8DD"
        );

        let mut kmac = Kmac256::new(&key, custom);
        kmac.update(&data);
        let mut out = [0u8; 64];
        kmac.finalize(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_kmac256_nist_sample_5() {
        let key = nist_kmac_key();
        let data = nist_kmac_long_data();
        let custom = b"";
        let expected = hex!(
            "75358CF39E41494E949707927CEE0AF2
             0A3FF553904C86B08F21CC414BCFD691
             589D27CF5E15369CBBFF8B9A4C2EB178
             00855D0235FF635DA82533EC6B759B69"
        );

        let mut kmac = Kmac256::new(&key, custom);
        kmac.update(&data);
        let mut out = [0u8; 64];
        kmac.finalize(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_kmac256_nist_sample_6() {
        let key = nist_kmac_key();
        let data = nist_kmac_long_data();
        let custom = b"My Tagged Application";
        let expected = hex!(
            "B58618F71F92E1D56C1B8C55DDD7CD18
             8B97B4CA4D99831EB2699A837DA2E4D9
             70FBACFDE50033AEA585F1A2708510C3
             2D07880801BD182898FE476876FC8965"
        );

        let mut kmac = Kmac256::new(&key, custom);
        kmac.update(&data);
        let mut out = [0u8; 64];
        kmac.finalize(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_kmac128_verify_matches_finalize() {
        let key = nist_kmac_key();
        let data = nist_kmac_short_data();
        let custom = b"My Tagged Application";
        let expected = hex!(
            "3B1FBA963CD8B0B59E8C1A6D71888B71
             43651AF8BA0A7070C0979E2811324AA5"
        );

        let mut kmac = Kmac128::new(&key, custom);
        kmac.update(&data);
        let mut finalized = [0u8; 32];
        kmac.finalize(&mut finalized);
        assert_eq!(finalized.as_slice(), expected.as_slice());

        let mut kmac2 = Kmac128::new(&key, custom);
        kmac2.update(&data);
        assert!(bool::from(kmac2.verify(&expected)));

        let mut wrong = expected;
        wrong[0] ^= 0x01;
        let mut kmac3 = Kmac128::new(&key, custom);
        kmac3.update(&data);
        assert!(!bool::from(kmac3.verify(&wrong)));
    }

    #[test]
    fn test_kmac256_verify_nist() {
        let key = nist_kmac_key();
        let data = nist_kmac_short_data();
        let custom = b"My Tagged Application";
        let expected = hex!(
            "20C570C31346F703C9AC36C61C03CB64
             C3970D0CFC787E9B79599D273A68D2F7
             F69D4CC3DE9D104A351689F27CF6F595
             1F0103F33F4F24871024D9C27773A8DD"
        );

        let mut kmac = Kmac256::new(&key, custom);
        kmac.update(&data);
        assert!(bool::from(kmac.verify(&expected)));

        let mut wrong = expected;
        wrong[31] ^= 0x80;
        let mut kmac2 = Kmac256::new(&key, custom);
        kmac2.update(&data);
        assert!(!bool::from(kmac2.verify(&wrong)));
    }
}
