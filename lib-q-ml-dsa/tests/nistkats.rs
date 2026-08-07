//! Cross-implementation KATs for ML-DSA against `dilithium-py`.
//!
//! PROVENANCE -- read this before trusting these vectors (card t_71d4f79a, 2026-08-07). The data
//! files loaded here are NOT NIST vectors and never were, and they are not generated here either:
//! all six are byte-for-byte identical to `github.com/cryspen/libcrux` at commit `5c3fc214`, under
//! `libcrux-ml-dsa/tests/kats/`, as is the `tests/kats/dilithium.py` that produced them. They were
//! named `nistkats-*.json` until 2026-08-07, which asserted a provenance they do not have.
//!
//! `dilithium.py` descends from <https://github.com/GiacomoPope/dilithium-py> PR #1, which is
//! genuinely third-party -- but its FIPS-204-final modifications were written by libcrux, and this
//! crate is a `libcrux-ml-dsa` derivative, so for those algorithm details the cross-check is
//! same-author rather than independent. Two further measured limits: the vendored `verify` raises
//! `NameError` and has never executed, so these vectors cover keygen and sign only; and the
//! pre-hashed set shares `src/pre_hash.rs`'s 256-byte SHAKE-128 choice, so it cannot falsify it.
//!
//! The genuine NIST conformance data for this crate lives in `tests/kats/acvp-1_1_0_36/` and is
//! exercised by `tests/acvp.rs`. Full provenance, machine-checked by
//! `scripts/ci_guard_kat_provenance.py`, is in `tests/kats/PROVENANCE.md` and `kats-manifest.toml`.
//!
//! This test target keeps its `nistkats` file name for now ONLY because renaming it would break
//! `lib-q-ml-dsa/scripts/security_audit.sh` (which CI runs on push) and three `--test nistkats`
//! call sites; see card t_71d4f79a for the proposed follow-up.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MlDsaNISTKAT {
    #[serde(with = "hex::serde")]
    key_generation_seed: [u8; 32],

    #[serde(with = "hex::serde")]
    sha3_256_hash_of_verification_key: [u8; 32],

    #[serde(with = "hex::serde")]
    sha3_256_hash_of_signing_key: [u8; 32],

    // The length of the message in each KAT is 33 * (i + 1), where i is the
    // 0-indexed KAT counter.
    message: String,

    #[serde(with = "hex::serde")]
    signing_randomness: [u8; 32],

    #[serde(with = "hex::serde")]
    sha3_256_hash_of_signature: [u8; 32],
}

macro_rules! impl_nist_known_answer_tests {
    ($name:ident, $name_pre_hashed:ident, $parameter_set:literal, $key_gen:expr, $sign:expr, $verify:expr, $sign_pre_hashed:expr, $verify_pre_hashed:expr) => {
        #[test]
        fn $name() {
            let katfile_path = Path::new("tests")
                .join("kats")
                .join(format!("dilithium-py-kats-{}.json", $parameter_set));
            let katfile = File::open(katfile_path).expect("Could not open KAT file.");
            let reader = BufReader::new(katfile);

            let nist_kats: Vec<MlDsaNISTKAT> =
                serde_json::from_reader(reader).expect("Could not deserialize KAT file.");

            for kat in nist_kats {
                let key_pair = $key_gen(kat.key_generation_seed);

                let verification_key_hash =
                    lib_q_sha3::sha3_256(key_pair.verification_key.as_ref());
                assert_eq!(
                    verification_key_hash, kat.sha3_256_hash_of_verification_key,
                    "verification_key_hash != kat.sha3_256_hash_of_verification_key"
                );

                let signing_key_hash = lib_q_sha3::sha3_256(key_pair.signing_key.as_ref());
                assert_eq!(
                    signing_key_hash, kat.sha3_256_hash_of_signing_key,
                    "signing_key_hash != kat.sha3_256_hash_of_signing_key"
                );

                let message = hex::decode(kat.message).expect("Hex-decoding the message failed.");

                let signature = $sign(&key_pair.signing_key, &message, b"", kat.signing_randomness)
                    .expect("Rejection sampling failure probability is < 2⁻¹²⁸");

                let signature_hash = lib_q_sha3::sha3_256(signature.as_ref());
                assert_eq!(
                    signature_hash, kat.sha3_256_hash_of_signature,
                    "signature_hash != kat.sha3_256_hash_of_signature"
                );

                $verify(&key_pair.verification_key, &message, b"", &signature)
                    .expect("Verification should pass since the signature was honestly generated");
            }
        }

        #[test]
        fn $name_pre_hashed() {
            let katfile_path = Path::new("tests").join("kats").join(format!(
                "dilithium-py-kats-pre-hashed-{}.json",
                $parameter_set
            ));
            let katfile = File::open(katfile_path).expect("Could not open KAT file.");
            let reader = BufReader::new(katfile);

            let nist_kats: Vec<MlDsaNISTKAT> =
                serde_json::from_reader(reader).expect("Could not deserialize KAT file.");

            for kat in nist_kats {
                let key_pair = $key_gen(kat.key_generation_seed);

                let verification_key_hash =
                    lib_q_sha3::sha3_256(key_pair.verification_key.as_ref());
                assert_eq!(
                    verification_key_hash, kat.sha3_256_hash_of_verification_key,
                    "verification_key_hash != kat.sha3_256_hash_of_verification_key"
                );

                let signing_key_hash = lib_q_sha3::sha3_256(key_pair.signing_key.as_ref());
                assert_eq!(
                    signing_key_hash, kat.sha3_256_hash_of_signing_key,
                    "signing_key_hash != kat.sha3_256_hash_of_signing_key"
                );

                let message = hex::decode(kat.message).expect("Hex-decoding the message failed.");

                let signature =
                    $sign_pre_hashed(&key_pair.signing_key, &message, b"", kat.signing_randomness)
                        .expect("Rejection sampling failure probability is < 2⁻¹²⁸");

                let signature_hash = lib_q_sha3::sha3_256(signature.as_ref());
                assert_eq!(
                    signature_hash, kat.sha3_256_hash_of_signature,
                    "signature_hash != kat.sha3_256_hash_of_signature"
                );

                $verify_pre_hashed(&key_pair.verification_key, &message, b"", &signature)
                    .expect("Verification should pass since the signature was honestly generated");
            }
        }
    };
}

// 44

#[cfg(feature = "mldsa44")]
impl_nist_known_answer_tests!(
    nist_known_answer_tests_44,
    nist_known_answer_tests_pre_hashed_44,
    44,
    lib_q_ml_dsa::ml_dsa_44::generate_key_pair,
    lib_q_ml_dsa::ml_dsa_44::sign,
    lib_q_ml_dsa::ml_dsa_44::verify,
    lib_q_ml_dsa::ml_dsa_44::sign_pre_hashed_shake128,
    lib_q_ml_dsa::ml_dsa_44::verify_pre_hashed_shake128
);

#[cfg(feature = "mldsa44")]
impl_nist_known_answer_tests!(
    nist_known_answer_tests_44_portable,
    nist_known_answer_tests_pre_hashed_44_portable,
    44,
    lib_q_ml_dsa::ml_dsa_44::portable::generate_key_pair,
    lib_q_ml_dsa::ml_dsa_44::portable::sign,
    lib_q_ml_dsa::ml_dsa_44::portable::verify,
    lib_q_ml_dsa::ml_dsa_44::sign_pre_hashed_shake128,
    lib_q_ml_dsa::ml_dsa_44::verify_pre_hashed_shake128
);

#[cfg(all(feature = "simd128", feature = "mldsa44"))]
impl_nist_known_answer_tests!(
    nist_known_answer_tests_44_simd128,
    nist_known_answer_tests_pre_hashed_44_simd128,
    44,
    lib_q_ml_dsa::ml_dsa_44::neon::generate_key_pair,
    lib_q_ml_dsa::ml_dsa_44::neon::sign,
    lib_q_ml_dsa::ml_dsa_44::neon::verify,
    lib_q_ml_dsa::ml_dsa_44::sign_pre_hashed_shake128,
    lib_q_ml_dsa::ml_dsa_44::verify_pre_hashed_shake128
);

#[cfg(all(feature = "simd256", feature = "mldsa44"))]
impl_nist_known_answer_tests!(
    nist_known_answer_tests_44_simd256,
    nist_known_answer_tests_pre_hashed_44_simd256,
    44,
    lib_q_ml_dsa::ml_dsa_44::avx2::generate_key_pair,
    lib_q_ml_dsa::ml_dsa_44::avx2::sign,
    lib_q_ml_dsa::ml_dsa_44::avx2::verify,
    lib_q_ml_dsa::ml_dsa_44::sign_pre_hashed_shake128,
    lib_q_ml_dsa::ml_dsa_44::verify_pre_hashed_shake128
);

// 65
#[cfg(feature = "mldsa65")]
impl_nist_known_answer_tests!(
    nist_known_answer_tests_65,
    nist_known_answer_tests_pre_hashed_65,
    65,
    lib_q_ml_dsa::ml_dsa_65::generate_key_pair,
    lib_q_ml_dsa::ml_dsa_65::sign,
    lib_q_ml_dsa::ml_dsa_65::verify,
    lib_q_ml_dsa::ml_dsa_65::sign_pre_hashed_shake128,
    lib_q_ml_dsa::ml_dsa_65::verify_pre_hashed_shake128
);

// 87
#[cfg(feature = "mldsa87")]
impl_nist_known_answer_tests!(
    nist_known_answer_tests_87,
    nist_known_answer_tests_pre_hashed_87,
    87,
    lib_q_ml_dsa::ml_dsa_87::generate_key_pair,
    lib_q_ml_dsa::ml_dsa_87::sign,
    lib_q_ml_dsa::ml_dsa_87::verify,
    lib_q_ml_dsa::ml_dsa_87::sign_pre_hashed_shake128,
    lib_q_ml_dsa::ml_dsa_87::verify_pre_hashed_shake128
);
