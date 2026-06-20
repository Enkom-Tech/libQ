use super::*;

macro_rules! parameter_set {
    ($parameter_module:ident, $feature:literal) => {
        #[cfg(feature = $feature)]
        pub mod $parameter_module {
            #[cfg(all(feature = "simd256", target_arch = "x86_64", feature = $feature))]
            use super::instantiations::avx2::$parameter_module::{
                generate_key_pair as generate_key_pair_avx2,
                sign as sign_avx2,
                sign_pre_hashed_shake128 as sign_pre_hashed_shake128_avx2,
                verify as verify_avx2,
                verify_pre_hashed_shake128 as verify_pre_hashed_shake128_avx2,
            };
            #[cfg(all(feature = "simd256", target_arch = "x86_64", feature = "acvp", feature = $feature))]
            use super::instantiations::avx2::$parameter_module::{
                sign_internal as sign_internal_avx2,
                verify_internal as verify_internal_avx2,
            };
            #[cfg(all(feature = "simd128", target_arch = "aarch64", feature = $feature))]
            use super::instantiations::neon::$parameter_module::{
                generate_key_pair as generate_key_pair_neon,
                sign as sign_neon,
                sign_pre_hashed_shake128 as sign_pre_hashed_shake128_neon,
                verify as verify_neon,
                verify_pre_hashed_shake128 as verify_pre_hashed_shake128_neon,
            };
            #[cfg(all(feature = "simd128", target_arch = "aarch64", feature = "acvp", feature = $feature))]
            use super::instantiations::neon::$parameter_module::{
                sign_internal as sign_internal_neon,
                verify_internal as verify_internal_neon,
            };
            // No fallback imports needed - architecture-specific checks in functions
            // ensure correct implementation is called at runtime
            use super::*;
            use crate::ml_dsa_generic::$parameter_module::{
                SIGNATURE_SIZE,
                SIGNING_KEY_SIZE,
                VERIFICATION_KEY_SIZE,
            };

            #[allow(dead_code)]
            pub(crate) fn generate_key_pair(
                randomness: [u8; KEY_GENERATION_RANDOMNESS_SIZE],
                signing_key: &mut [u8; SIGNING_KEY_SIZE],
                verification_key: &mut [u8; VERIFICATION_KEY_SIZE],
            ) {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return generate_key_pair_avx2(randomness, signing_key, verification_key);
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return generate_key_pair_neon(randomness, signing_key, verification_key);
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::generate_key_pair(
                    randomness,
                    signing_key,
                    verification_key,
                );
            }

            #[cfg(feature = "acvp")]
            pub(crate) fn sign_internal(
                signing_key: &[u8; SIGNING_KEY_SIZE],
                message: &[u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
            ) -> Result<MLDSASignature<{ SIGNATURE_SIZE }>, SigningError> {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return sign_internal_avx2(signing_key, message, randomness);
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return sign_internal_neon(signing_key, message, randomness);
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::sign_internal(
                    signing_key,
                    message,
                    randomness,
                )
            }

            #[allow(dead_code)]
            pub(crate) fn sign(
                signing_key: &[u8; SIGNING_KEY_SIZE],
                message: &[u8],
                context: &[u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
            ) -> Result<MLDSASignature<{ SIGNATURE_SIZE }>, SigningError> {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return sign_avx2(signing_key, message, context, randomness);
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return sign_neon(signing_key, message, context, randomness);
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::sign(
                    signing_key,
                    message,
                    context,
                    randomness,
                )
            }

            #[allow(dead_code)]
            pub(crate) fn sign_pre_hashed_shake128(
                signing_key: &[u8; SIGNING_KEY_SIZE],
                message: &[u8],
                context: &[u8],
                pre_hash_buffer: &mut [u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
            ) -> Result<MLDSASignature<{ SIGNATURE_SIZE }>, SigningError> {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return sign_pre_hashed_shake128_avx2(
                        signing_key,
                        message,
                        context,
                        pre_hash_buffer,
                        randomness,
                    );
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return sign_pre_hashed_shake128_neon(
                        signing_key,
                        message,
                        context,
                        pre_hash_buffer,
                        randomness,
                    );
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::sign_pre_hashed_shake128(
                    signing_key,
                    message,
                    context,
                    pre_hash_buffer,
                    randomness,
                )
            }

            #[cfg(feature = "acvp")]
            pub(crate) fn verify_internal(
                verification_key_serialized: &[u8; VERIFICATION_KEY_SIZE],
                message: &[u8],
                signature_serialized: &[u8; SIGNATURE_SIZE],
            ) -> Result<(), VerificationError> {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return verify_internal_avx2(
                        verification_key_serialized,
                        message,
                        signature_serialized,
                    );
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return verify_internal_neon(
                        verification_key_serialized,
                        message,
                        signature_serialized,
                    );
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::verify_internal(
                    verification_key_serialized,
                    message,
                    signature_serialized,
                )
            }

            #[allow(dead_code)]
            pub(crate) fn verify(
                verification_key_serialized: &[u8; VERIFICATION_KEY_SIZE],
                message: &[u8],
                context: &[u8],
                signature_serialized: &[u8; SIGNATURE_SIZE],
            ) -> Result<(), VerificationError> {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return verify_avx2(
                        verification_key_serialized,
                        message,
                        context,
                        signature_serialized,
                    );
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return verify_neon(
                        verification_key_serialized,
                        message,
                        context,
                        signature_serialized,
                    );
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::verify(
                    verification_key_serialized,
                    message,
                    context,
                    signature_serialized,
                )
            }

            #[allow(dead_code)]
            pub(crate) fn verify_pre_hashed_shake128(
                verification_key_serialized: &[u8; VERIFICATION_KEY_SIZE],
                message: &[u8],
                context: &[u8],
                pre_hash_buffer: &mut [u8],
                signature_serialized: &[u8; SIGNATURE_SIZE],
            ) -> Result<(), VerificationError> {
                // Check simd256 first (AVX2 on x86_64)
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if lib_q_platform::simd256_support() {
                    return verify_pre_hashed_shake128_avx2(
                        verification_key_serialized,
                        message,
                        context,
                        pre_hash_buffer,
                        signature_serialized,
                    );
                }

                // Check simd128 only on aarch64 (NEON on ARM)
                #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
                if lib_q_platform::simd128_support() {
                    return verify_pre_hashed_shake128_neon(
                        verification_key_serialized,
                        message,
                        context,
                        pre_hash_buffer,
                        signature_serialized,
                    );
                }

                // Fall back to portable
                super::instantiations::portable::$parameter_module::verify_pre_hashed_shake128(
                    verification_key_serialized,
                    message,
                    context,
                    pre_hash_buffer,
                    signature_serialized,
                )
            }
        }
    };
}

parameter_set!(ml_dsa_44, "mldsa44");
parameter_set!(ml_dsa_65, "mldsa65");
parameter_set!(ml_dsa_87, "mldsa87");
