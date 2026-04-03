#![allow(non_snake_case)]
#![cfg(feature = "alloc")]

use lib_q_slh_dsa::*;
use serde::Deserialize;

const KEYGEN_KAT_JSON: &str = include_str!("acvp/SLH-DSA-sigGen-FIPS205/internalProjection.json");

#[derive(Deserialize, Debug)]
#[serde(transparent)]
struct HexString {
    #[serde(with = "hex::serde")]
    data: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct TestCase {
    sk: HexString,
    message: HexString,
    signature: HexString,
    additionalRandomness: Option<HexString>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    parameterSet: String,
    tests: Vec<TestCase>,
}

#[derive(Deserialize, Debug)]
struct TestFile {
    testGroups: Vec<TestGroup>,
}

macro_rules! parameter_case {
    ($param:ident, $test_case:expr) => {{
        let sk = SigningKey::<$param>::try_from($test_case.sk.data.as_slice()).unwrap();
        let opt_rand = $test_case
            .additionalRandomness
            .as_ref()
            .map(|x| x.data.as_slice());
        let sig = sk.slh_sign_internal(&[$test_case.message.data.as_slice()], opt_rand);
        assert_eq!(sig.to_vec(), $test_case.signature.data);
    }};
}

fn run_sign_cvp_all() {
    let test_file: TestFile = serde_json::from_str(KEYGEN_KAT_JSON).unwrap();
    for test_group in test_file.testGroups {
        let p = test_group.parameterSet;
        for test_case in test_group.tests {
            match p.as_str() {
                Shake128f::NAME => parameter_case!(Shake128f, test_case),
                Shake128s::NAME => parameter_case!(Shake128s, test_case),
                Shake192f::NAME => parameter_case!(Shake192f, test_case),
                Shake192s::NAME => parameter_case!(Shake192s, test_case),
                Shake256f::NAME => parameter_case!(Shake256f, test_case),
                Shake256s::NAME => parameter_case!(Shake256s, test_case),
                Sha2_128f::NAME => parameter_case!(Sha2_128f, test_case),
                Sha2_128s::NAME => parameter_case!(Sha2_128s, test_case),
                Sha2_192f::NAME => parameter_case!(Sha2_192f, test_case),
                Sha2_192s::NAME => parameter_case!(Sha2_192s, test_case),
                Sha2_256f::NAME => parameter_case!(Sha2_256f, test_case),
                Sha2_256s::NAME => parameter_case!(Sha2_256s, test_case),
                _ => panic!("Unknown parameter set: {}", p),
            }
        }
    }
}

/// Deserialize the bundled ACVP sigGen JSON (multi‑MiB) and check expected group/case counts.
#[test]
fn test_sign_cvp_payload_parses() {
    let test_file: TestFile = serde_json::from_str(KEYGEN_KAT_JSON).unwrap();
    assert_eq!(test_file.testGroups.len(), 10);
    let n: usize = test_file.testGroups.iter().map(|g| g.tests.len()).sum();
    assert_eq!(n, 88);
}

/// Full ACVP sigGen signing (~88 cases, including 64KiB messages and SLH-DSA-*s) is far too slow
/// for routine debug `cargo test` (often many minutes). CI runs this in release with `--ignored`.
///
/// Local: `cargo test -p lib-q-slh-dsa --test acvp_sig test_sign_cvp --release -- --ignored --test-threads=1`
#[test]
#[ignore = "slow: full ACVP sigGen (run with --release -- --ignored)"]
fn test_sign_cvp() {
    run_sign_cvp_all();
}
