#[cfg(feature = "random")]
use lib_q_ml_dsa::{
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
};
#[cfg(feature = "random")]
use lib_q_random::LibQRng;
#[cfg(feature = "random")]
use rand_core::RngCore;

#[cfg(feature = "random")]
fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = LibQRng::new_secure().expect("Failed to create secure RNG");
    let mut seed = [0; L];
    rng.fill_bytes(&mut seed);
    seed
}
#[cfg(feature = "random")]
fn random_message() -> Vec<u8> {
    let mut rng = LibQRng::new_secure().expect("Failed to create secure RNG");

    // Limit message size to 4KB to avoid exceeding RNG entropy limits
    // Original code could generate up to 65KB which exceeds the per-call limit
    let mut length = [0u8; 2];
    rng.fill_bytes(&mut length);
    let length = ((length[1] as u16) << 8) | length[0] as u16;
    let length = length.min(4096); // Cap at 4KB

    let mut message = vec![0u8; length as usize];
    rng.fill_bytes(&mut message);

    message
}

#[cfg(feature = "random")]
fn modify_signing_key<const SIGNING_KEY_SIZE: usize>(signing_key: &mut [u8; SIGNING_KEY_SIZE]) {
    let mut rng = LibQRng::new_secure().expect("Failed to create secure RNG");
    let mut option_bytes = [0u8; 1];
    rng.fill_bytes(&mut option_bytes);
    let option = option_bytes[0] % 2;

    let position = match option {
        // Change the seed used for generating A
        0 => {
            let mut pos_bytes = [0u8; 1];
            rng.fill_bytes(&mut pos_bytes);
            (pos_bytes[0] % 32) as usize
        }

        // Change the verification key hash
        1 => {
            let mut pos_bytes = [0u8; 1];
            rng.fill_bytes(&mut pos_bytes);
            (64 + (pos_bytes[0] % 64)) as usize
        }

        // TODO: Changing s1, s2, and t0 could still result in valid
        // signatures. Look into this further.
        _ => unreachable!(),
    };

    let random_byte = {
        let byte = random_array::<1>()[0];

        if byte == 0 { byte + 1 } else { byte }
    };

    signing_key[position] ^= random_byte;
}

#[cfg(feature = "random")]
macro_rules! impl_consistency_test {
    ($name:ident, $key_gen:expr, $sign:expr, $verify:expr) => {
        #[test]
        fn $name() {
            let key_generation_seed = random_array();
            let signing_randomness = random_array();

            let message = random_message();

            let key_pair = $key_gen(key_generation_seed);

            let signature = $sign(&key_pair.signing_key, &message, b"", signing_randomness)
                .expect("Rejection sampling failure probability is < 2⁻¹²⁸");

            $verify(&key_pair.verification_key, &message, b"", &signature)
                .expect("Verification should pass since the signature was honestly generated");
        }
    };
}

#[cfg(feature = "random")]
macro_rules! impl_modified_signing_key_test {
    ($name:ident, $key_gen:expr, $signing_key_size: expr, $sign:expr, $verify:expr) => {
        #[test]
        fn $name() {
            let key_generation_seed = random_array();
            let signing_randomness = random_array();

            let message = random_message();

            let mut key_pair = $key_gen(key_generation_seed);

            modify_signing_key::<{ $signing_key_size }>(key_pair.signing_key.as_ref_mut());

            let signature = $sign(&key_pair.signing_key, &message, b"", signing_randomness)
                .expect("Rejection sampling failure probability is < 2⁻¹²⁸");

            assert!($verify(&key_pair.verification_key, &message, b"", &signature).is_err());
        }
    };
}

// 44

#[cfg(feature = "random")]
impl_consistency_test!(
    consistency_44,
    ml_dsa_44::generate_key_pair,
    ml_dsa_44::sign,
    ml_dsa_44::verify
);

#[cfg(feature = "random")]
impl_modified_signing_key_test!(
    modified_signing_key_44,
    ml_dsa_44::generate_key_pair,
    ml_dsa_44::MLDSA44SigningKey::len(),
    ml_dsa_44::sign,
    ml_dsa_44::verify
);

#[cfg(feature = "random")]
impl_consistency_test!(
    consistency_44_portable,
    ml_dsa_44::portable::generate_key_pair,
    ml_dsa_44::portable::sign,
    ml_dsa_44::portable::verify
);

#[cfg(feature = "random")]
impl_modified_signing_key_test!(
    modified_signing_key_44_portable,
    ml_dsa_44::portable::generate_key_pair,
    ml_dsa_44::MLDSA44SigningKey::len(),
    ml_dsa_44::portable::sign,
    ml_dsa_44::portable::verify
);

#[cfg(all(feature = "simd128", feature = "random"))]
impl_consistency_test!(
    consistency_44_simd128,
    ml_dsa_44::neon::generate_key_pair,
    ml_dsa_44::neon::sign,
    ml_dsa_44::neon::verify
);

#[cfg(all(feature = "simd128", feature = "random"))]
impl_modified_signing_key_test!(
    modified_signing_key_44_simd128,
    ml_dsa_44::neon::generate_key_pair,
    ml_dsa_44::MLDSA44SigningKey::len(),
    ml_dsa_44::neon::sign,
    ml_dsa_44::neon::verify
);

#[cfg(all(feature = "simd256", feature = "random"))]
impl_consistency_test!(
    consistency_44_simd256,
    ml_dsa_44::avx2::generate_key_pair,
    ml_dsa_44::avx2::sign,
    ml_dsa_44::avx2::verify
);

#[cfg(all(feature = "simd256", feature = "random"))]
impl_modified_signing_key_test!(
    modified_signing_key_44_simd256,
    ml_dsa_44::avx2::generate_key_pair,
    ml_dsa_44::MLDSA44SigningKey::len(),
    ml_dsa_44::avx2::sign,
    ml_dsa_44::avx2::verify
);

// 65

#[cfg(feature = "random")]
impl_consistency_test!(
    consistency_65,
    ml_dsa_65::generate_key_pair,
    ml_dsa_65::sign,
    ml_dsa_65::verify
);

#[cfg(feature = "random")]
impl_modified_signing_key_test!(
    modified_signing_key_65,
    ml_dsa_65::generate_key_pair,
    ml_dsa_65::MLDSA65SigningKey::len(),
    ml_dsa_65::sign,
    ml_dsa_65::verify
);

// 87

#[cfg(feature = "random")]
impl_consistency_test!(
    consistency_87,
    ml_dsa_87::generate_key_pair,
    ml_dsa_87::sign,
    ml_dsa_87::verify
);

#[cfg(feature = "random")]
impl_modified_signing_key_test!(
    modified_signing_key_87,
    ml_dsa_87::generate_key_pair,
    ml_dsa_87::MLDSA87SigningKey::len(),
    ml_dsa_87::sign,
    ml_dsa_87::verify
);
