#![no_std]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]
// Allow clippy warnings in SIMD code - these are performance-critical implementations
// where the warnings don't apply to the specific use case
#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::let_and_return,
    clippy::identity_op,
    clippy::erasing_op
)]

#[cfg(feature = "std")]
extern crate std;

mod arithmetic;
pub mod constants;
mod encoding;
#[cfg(feature = "hardened")]
mod hardened;
mod hash_functions;
mod helper;
mod matrix;
mod ml_dsa_generic;
mod ntt;
mod polynomial;
mod pre_hash;
pub mod rng;
mod sample;
mod samplex4;
mod sha3_shim;
mod simd;

#[cfg(hax)]
mod specs;

pub mod types;

// Re-export hash functions for derive_message_representative
pub use pre_hash::DomainSeparationContext;
// Public interface
pub use types::*;

pub use crate::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};

#[cfg(feature = "mldsa44")]
pub mod ml_dsa_44;

#[cfg(feature = "mldsa65")]
pub mod ml_dsa_65;

#[cfg(feature = "mldsa87")]
pub mod ml_dsa_87;

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod constants_line_coverage {
    use crate::constants::{
        self,
        BYTES_FOR_VERIFICATION_KEY_HASH,
        COEFFICIENTS_IN_RING_ELEMENT,
        CONTEXT_MAX_LEN,
        Eta,
        FIELD_MODULUS,
        FIELD_MODULUS_MINUS_ONE_BIT_LENGTH,
        GAMMA2_V95_232,
        GAMMA2_V261_888,
        KEY_GENERATION_RANDOMNESS_SIZE,
        MASK_SEED_SIZE,
        MESSAGE_REPRESENTATIVE_SIZE,
        REJECTION_SAMPLE_BOUND_SIGN,
        RING_ELEMENT_OF_T0S_SIZE,
        RING_ELEMENT_OF_T1S_SIZE,
        SEED_FOR_A_SIZE,
        SEED_FOR_ERROR_VECTORS_SIZE,
        SEED_FOR_SIGNING_SIZE,
        SIGNING_RANDOMNESS_SIZE,
        beta,
        commitment_ring_element_size,
        commitment_vector_size,
        error_ring_element_size,
        gamma1_ring_element_size,
        signature_size,
        signing_key_size,
        verification_key_size,
    };

    #[test]
    fn public_and_root_constants_are_sane() {
        assert_eq!(FIELD_MODULUS, 8_380_417);
        assert_eq!(COEFFICIENTS_IN_RING_ELEMENT, 256);
        assert_eq!(FIELD_MODULUS_MINUS_ONE_BIT_LENGTH, 23);
        assert_eq!(KEY_GENERATION_RANDOMNESS_SIZE, 32);
        assert_eq!(SIGNING_RANDOMNESS_SIZE, 32);
        assert_eq!(CONTEXT_MAX_LEN, 255);
        assert!(RING_ELEMENT_OF_T0S_SIZE > 0);
        assert!(RING_ELEMENT_OF_T1S_SIZE > 0);
        assert_eq!(SEED_FOR_A_SIZE, 32);
        assert_eq!(SEED_FOR_ERROR_VECTORS_SIZE, 64);
        assert_eq!(BYTES_FOR_VERIFICATION_KEY_HASH, 64);
        assert_eq!(SEED_FOR_SIGNING_SIZE, 32);
        assert_eq!(MESSAGE_REPRESENTATIVE_SIZE, 64);
        assert_eq!(MASK_SEED_SIZE, 64);
        assert_eq!(REJECTION_SAMPLE_BOUND_SIGN, 814);
        let _ = GAMMA2_V261_888;
        let _ = GAMMA2_V95_232;
    }

    #[test]
    fn beta_and_size_helpers_execute() {
        assert_eq!(beta(39, Eta::Two), 78);
        assert_eq!(beta(49, Eta::Four), 196);
        assert_eq!(error_ring_element_size(3), 96);
        assert_eq!(error_ring_element_size(4), 128);
        assert_eq!(gamma1_ring_element_size(18), 576);
        assert_eq!(commitment_ring_element_size(6), 192);
        assert_eq!(commitment_vector_size(6, 4), 768);
        let sk = signing_key_size(4, 4, error_ring_element_size(3));
        assert!(sk > SEED_FOR_A_SIZE);
        let vk = verification_key_size(4);
        assert!(vk > 0);
        let sig = signature_size(4, 4, 80, 32, 18);
        assert!(sig > 32);
    }

    #[cfg(feature = "mldsa44")]
    #[test]
    fn mldsa44_parameter_block_is_linked() {
        use constants::ml_dsa_44;
        assert_eq!(ml_dsa_44::ROWS_IN_A, 4);
        let _ = ml_dsa_44::SIGNING_KEY_SIZE;
        let _ = ml_dsa_44::VERIFICATION_KEY_SIZE;
        let _ = ml_dsa_44::SIGNATURE_SIZE;
        let _: ml_dsa_44::MLDSA44KeyPair;
    }

    #[cfg(feature = "mldsa65")]
    #[test]
    fn mldsa65_parameter_block_is_linked() {
        use constants::ml_dsa_65;
        assert_eq!(ml_dsa_65::ROWS_IN_A, 6);
        let _ = ml_dsa_65::SIGNING_KEY_SIZE;
        let _: ml_dsa_65::MLDSA65VerificationKey;
    }

    #[cfg(feature = "mldsa87")]
    #[test]
    fn mldsa87_parameter_block_is_linked() {
        use constants::ml_dsa_87;
        assert_eq!(ml_dsa_87::ROWS_IN_A, 8);
        let _ = ml_dsa_87::SIGNING_KEY_SIZE;
        let _: ml_dsa_87::MLDSA87Signature;
    }
}
