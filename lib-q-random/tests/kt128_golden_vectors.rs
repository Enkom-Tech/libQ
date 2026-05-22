//! Golden vectors for KT128 deterministic RNG (`tests/data/kt128_det_rng_v1.json`).
//!
//! Native-only: dev-dependencies (`serde`, `hex`) are not linked for `wasm32-unknown-unknown`.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hex::FromHex;
use lib_q_random::{
    KT128_DET_GOLDEN_U64_SEED_64,
    KT128_DET_GOLDEN_ZERO_SEED_64,
    new_deterministic_rng,
    new_deterministic_rng_from_u64,
};
use rand_core::Rng;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    version: u32,
    domain: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    seed_hex: Option<String>,
    seed_u64: Option<String>,
    output_hex: String,
}

#[test]
fn kt128_det_rng_v1_json_matches_live_output() {
    let raw = include_str!("data/kt128_det_rng_v1.json");
    let file: VectorFile = serde_json::from_str(raw).expect("parse golden JSON");
    assert_eq!(file.version, 1);
    assert_eq!(file.domain, "libQ-DET-RNG-v1");

    for vector in &file.vectors {
        let expected =
            <Vec<u8>>::from_hex(&vector.output_hex).expect("output_hex must be valid hex");
        let mut got = vec![0u8; expected.len()];

        if let Some(seed_hex) = &vector.seed_hex {
            let seed_bytes = <Vec<u8>>::from_hex(seed_hex).expect("seed_hex");
            assert_eq!(seed_bytes.len(), 32, "{}", vector.name);
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let mut rng = new_deterministic_rng(seed);
            rng.fill_bytes(&mut got);
        } else if let Some(seed_u64_hex) = &vector.seed_u64 {
            let seed = u64::from_str_radix(seed_u64_hex, 16).expect("seed_u64 hex");
            let mut rng = new_deterministic_rng_from_u64(seed);
            rng.fill_bytes(&mut got);
        } else {
            panic!("vector {} must have seed_hex or seed_u64", vector.name);
        }

        assert_eq!(got, expected, "vector {}", vector.name);
    }
}

#[test]
fn kt128_det_rng_v1_json_matches_public_constants() {
    let raw = include_str!("data/kt128_det_rng_v1.json");
    let file: VectorFile = serde_json::from_str(raw).unwrap();

    for vector in &file.vectors {
        let expected = <Vec<u8>>::from_hex(&vector.output_hex).unwrap();
        match vector.name.as_str() {
            "zero_seed_64" => assert_eq!(expected.as_slice(), KT128_DET_GOLDEN_ZERO_SEED_64),
            "u64_seed_0123456789abcdef_64" => {
                assert_eq!(expected.as_slice(), KT128_DET_GOLDEN_U64_SEED_64)
            }
            other => panic!("unexpected vector name: {other}"),
        }
    }
}
