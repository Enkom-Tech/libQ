//! FIPS 204 Algorithm 8 (ML-DSA.Verify_internal): the verifier must reject when
//! `||z||_inf >= gamma1 - beta`.
//!
//! A decoded signer response always lies in `[-gamma1 + 1, gamma1]` (BitUnpack of
//! `gamma1 - z` over `1 + log2(gamma1)` bits), so a bound of `2 * gamma1 - beta` can never fire
//! and the norm check becomes dead code. These tests take a valid signature, overwrite one
//! coefficient of `z` with a value at or above `gamma1 - beta`, and require that verification
//! fails with `SignerResponseExceedsBoundError` specifically. The commitment-hash comparison would
//! also reject these signatures, so a different error means the norm check did not fire.
//!
//! The parameters below are taken from FIPS 204 Table 1 rather than from the crate, so the
//! test does not share a constant with the code it is checking.

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::{
    VerificationError,
    Zeroizing,
};

/// FIPS 204 Table 1 values needed to locate and bound `z` inside an encoded signature.
struct Params {
    /// `lambda / 4`: length in bytes of the commitment hash `c~` that precedes `z`.
    c_tilde_bytes: usize,
    /// `l`: number of polynomials in `z`.
    l: usize,
    /// `log2(gamma1)`.
    gamma1_exponent: u32,
    /// `beta = tau * eta`.
    beta: i32,
}

impl Params {
    fn gamma1(&self) -> i32 {
        1 << self.gamma1_exponent
    }

    /// Bits per packed `z` coefficient.
    fn coeff_bits(&self) -> usize {
        self.gamma1_exponent as usize + 1
    }
}

#[cfg(feature = "mldsa44")]
const P44: Params = Params {
    c_tilde_bytes: 32,
    l: 4,
    gamma1_exponent: 17,
    beta: 39 * 2,
};
#[cfg(feature = "mldsa65")]
const P65: Params = Params {
    c_tilde_bytes: 48,
    l: 5,
    gamma1_exponent: 19,
    beta: 49 * 4,
};
#[cfg(feature = "mldsa87")]
const P87: Params = Params {
    c_tilde_bytes: 64,
    l: 7,
    gamma1_exponent: 19,
    beta: 60 * 2,
};

fn kg_seed(b: u8) -> [u8; KEY_GENERATION_RANDOMNESS_SIZE] {
    let mut s = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    s[0] = b;
    s[31] = b.wrapping_mul(13);
    s
}

fn sig_seed(b: u8) -> [u8; SIGNING_RANDOMNESS_SIZE] {
    let mut s = [0u8; SIGNING_RANDOMNESS_SIZE];
    s[0] = b;
    s[31] = b.wrapping_add(29);
    s
}

/// Coefficient index (into the flattened `z`, polynomial-major) to overwrite. Spread across the
/// first, a middle and the last polynomial so every SIMD lane group is not the same one.
fn target_coefficients(p: &Params) -> [usize; 3] {
    [0, 256 + 77, (p.l - 1) * 256 + 255]
}

/// Values of a `z` coefficient that FIPS 204 requires the verifier to reject on norm alone.
fn out_of_bound_values(p: &Params) -> [i32; 5] {
    let g = p.gamma1();
    [
        g - p.beta, // exactly at the bound: rejected because the test is `>=`
        g - p.beta + 1,
        g - 1,
        g,             // largest positive value BitUnpack can produce
        -(g - p.beta), // negative side, at the bound
    ]
}

/// Overwrite coefficient `index` of the packed `z` with `value`.
///
/// `z` is BitPack(`z`, gamma1 - 1, gamma1): each coefficient is stored as `gamma1 - z` in
/// `coeff_bits` bits, little-endian, immediately after `c~`.
fn set_z_coefficient(sig: &mut [u8], p: &Params, index: usize, value: i32) {
    let packed = (p.gamma1() - value) as u32;
    let bits = p.coeff_bits();
    assert!(
        packed < (1 << bits),
        "value not representable in the z encoding"
    );
    let base_bit = p.c_tilde_bytes * 8 + index * bits;
    for b in 0..bits {
        let bit = base_bit + b;
        let mask = 1u8 << (bit % 8);
        if (packed >> b) & 1 == 1 {
            sig[bit / 8] |= mask;
        } else {
            sig[bit / 8] &= !mask;
        }
    }
}

fn describe(r: &Result<(), VerificationError>) -> String {
    format!("{r:?}")
}

fn assert_bound_error(r: Result<(), VerificationError>, what: &str) {
    assert!(
        matches!(r, Err(VerificationError::SignerResponseExceedsBoundError)),
        "{what}: expected SignerResponseExceedsBoundError, got {}",
        describe(&r)
    );
}

fn assert_not_bound_error(r: Result<(), VerificationError>, what: &str) {
    assert!(
        r.is_err(),
        "{what}: tampered signature unexpectedly verified"
    );
    assert!(
        !matches!(r, Err(VerificationError::SignerResponseExceedsBoundError)),
        "{what}: z just inside the bound must not be rejected on norm, got {}",
        describe(&r)
    );
}

/// Runs the bound checks for one parameter set through every public verify entry point.
macro_rules! bound_test {
    ($name:ident, $module:ident, $params:expr, $seed:expr) => {
        #[test]
        fn $name() {
            let p = &$params;
            let msg = b"signer response bound";
            let ctx = b"fips204-alg8";
            let kp = $module::generate_key_pair_from_seed(&Zeroizing::new(kg_seed($seed)));
            let good = $module::sign(&kp.signing_key, msg, ctx, sig_seed($seed)).expect("sign");
            let good_ph =
                $module::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, sig_seed($seed))
                    .expect("sign pre-hashed");

            // Positive control: the untouched signatures verify through every entry point.
            assert!($module::verify(&kp.verification_key, msg, ctx, &good).is_ok());
            assert!($module::portable::verify(&kp.verification_key, msg, ctx, &good).is_ok());
            assert!(
                $module::verify_pre_hashed_shake128(&kp.verification_key, msg, ctx, &good_ph)
                    .is_ok()
            );

            let verify_all = |bytes: &[u8], bytes_ph: &[u8], expect_bound: bool, what: String| {
                let sig = $module::Signature::new(bytes.try_into().unwrap());
                let sig_ph = $module::Signature::new(bytes_ph.try_into().unwrap());
                let check = if expect_bound {
                    assert_bound_error
                } else {
                    assert_not_bound_error
                };
                check(
                    $module::verify(&kp.verification_key, msg, ctx, &sig),
                    &format!("{what} [verify]"),
                );
                check(
                    $module::portable::verify(&kp.verification_key, msg, ctx, &sig),
                    &format!("{what} [portable::verify]"),
                );
                #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
                if avx2_available() {
                    check(
                        $module::avx2::verify(&kp.verification_key, msg, ctx, &sig),
                        &format!("{what} [avx2::verify]"),
                    );
                }
                check(
                    $module::verify_pre_hashed_shake128(&kp.verification_key, msg, ctx, &sig_ph),
                    &format!("{what} [verify_pre_hashed_shake128]"),
                );
            };

            for index in target_coefficients(p) {
                for value in out_of_bound_values(p) {
                    let mut bytes = *good.as_ref();
                    let mut bytes_ph = *good_ph.as_ref();
                    set_z_coefficient(&mut bytes, p, index, value);
                    set_z_coefficient(&mut bytes_ph, p, index, value);
                    verify_all(&bytes, &bytes_ph, true, format!("z[{index}] = {value}"));
                }

                // Just inside the bound: the norm check must pass, and the signature must still
                // be rejected (by the commitment hash), so the bound is exact, not over-strict.
                for value in [p.gamma1() - p.beta - 1, -(p.gamma1() - p.beta - 1)] {
                    let mut bytes = *good.as_ref();
                    let mut bytes_ph = *good_ph.as_ref();
                    set_z_coefficient(&mut bytes, p, index, value);
                    set_z_coefficient(&mut bytes_ph, p, index, value);
                    if bytes == *good.as_ref() || bytes_ph == *good_ph.as_ref() {
                        // Vanishingly unlikely: the honest coefficient already had this value.
                        continue;
                    }
                    verify_all(&bytes, &bytes_ph, false, format!("z[{index}] = {value}"));
                }
            }
        }
    };
}

#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
fn avx2_available() -> bool {
    std::is_x86_feature_detected!("avx2")
}

/// Each parameter-set module plus a uniform `Signature` alias, so one macro body covers all three.
mod aliases {
    #[cfg(feature = "mldsa44")]
    pub mod ml_dsa_44 {
        pub use lib_q_ml_dsa::ml_dsa_44::*;
        pub type Signature = MLDSA44Signature;
    }
    #[cfg(feature = "mldsa65")]
    pub mod ml_dsa_65 {
        pub use lib_q_ml_dsa::ml_dsa_65::*;
        pub type Signature = MLDSA65Signature;
    }
    #[cfg(feature = "mldsa87")]
    pub mod ml_dsa_87 {
        pub use lib_q_ml_dsa::ml_dsa_87::*;
        pub type Signature = MLDSA87Signature;
    }
}

#[cfg(feature = "mldsa44")]
use aliases::ml_dsa_44;
#[cfg(feature = "mldsa65")]
use aliases::ml_dsa_65;
#[cfg(feature = "mldsa87")]
use aliases::ml_dsa_87;

#[cfg(feature = "mldsa44")]
bound_test!(
    ml_dsa_44_rejects_z_at_or_above_gamma1_minus_beta,
    ml_dsa_44,
    P44,
    0x44
);
#[cfg(feature = "mldsa65")]
bound_test!(
    ml_dsa_65_rejects_z_at_or_above_gamma1_minus_beta,
    ml_dsa_65,
    P65,
    0x65
);
#[cfg(feature = "mldsa87")]
bound_test!(
    ml_dsa_87_rejects_z_at_or_above_gamma1_minus_beta,
    ml_dsa_87,
    P87,
    0x87
);
