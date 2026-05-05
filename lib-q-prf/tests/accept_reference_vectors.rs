//! KAT acceptance against `reference_vectors.txt` and SHA-256 fingerprints of moduli.

use crypto_bigint::U256;
use lib_q_prf::{
    GoldKey256,
    GoldKey512,
    GoldPrfParams256,
    GoldPrfParams512,
    LegendreKey256,
    LegendreKey512,
    LegendrePrfParams256,
    LegendrePrfParams512,
    PrfError,
    gold_prf_u256,
    gold_prf_u512,
    legendre_prf_u256,
    legendre_prf_u512,
    u256_from_le_bytes,
    u512_from_le_bytes,
};
use sha2::{
    Digest,
    Sha256,
};

fn line_value<'a>(text: &'a str, key: &str) -> &'a str {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(key) &&
            let Some(v) = rest.strip_prefix('=')
        {
            return v.trim();
        }
    }
    panic!("missing key {key}");
}

#[test]
fn sha256_of_moduli_matches_reference() {
    let raw = include_str!("reference_vectors.txt");
    let leg256 = LegendrePrfParams256::pilot();
    let leg512 = LegendrePrfParams512::pilot();
    let h256 = hex::encode(Sha256::digest(leg256.p.to_le_bytes()));
    let h512 = hex::encode(Sha256::digest(leg512.p.to_le_bytes()));
    assert_eq!(h256, line_value(raw, "SHA256_P256_LE"));
    assert_eq!(h512, line_value(raw, "SHA256_P512_LE"));
}

#[test]
fn kat_legendre_gold_256() {
    let raw = include_str!("reference_vectors.txt");
    let params_l = LegendrePrfParams256::pilot();
    let params_g = GoldPrfParams256::pilot();
    let mut kb = [0u8; 32];
    hex::decode_to_slice(line_value(raw, "KAT_256_K_LE"), &mut kb).expect("hex k");
    let mut xb = [0u8; 32];
    hex::decode_to_slice(line_value(raw, "KAT_256_X_LE"), &mut xb).expect("hex x");
    let k = u256_from_le_bytes(&kb);
    let x = u256_from_le_bytes(&xb);
    let leg_key = LegendreKey256::from_uint(k, &params_l).expect("leg key");
    let gold_key = GoldKey256::from_uint(k, &params_g).expect("gold key");
    let leg = legendre_prf_u256(&leg_key, &x, &params_l).expect("leg");
    let leg_exp: i8 = line_value(raw, "KAT_256_LEGENDRE").parse().expect("parse");
    assert_eq!(leg, leg_exp);
    let gout = gold_prf_u256(&gold_key, &x, &params_g).expect("gold");
    let mut gold_exp = [0u8; 32];
    hex::decode_to_slice(line_value(raw, "KAT_256_GOLD_LE"), &mut gold_exp).expect("gold hex");
    assert_eq!(gout, gold_exp);
}

#[test]
fn kat_legendre_gold_512() {
    let raw = include_str!("reference_vectors.txt");
    let params_l = LegendrePrfParams512::pilot();
    let params_g = GoldPrfParams512::pilot();
    let mut kb = [0u8; 64];
    hex::decode_to_slice(line_value(raw, "KAT_512_K_LE"), &mut kb).expect("hex k");
    let mut xb = [0u8; 64];
    hex::decode_to_slice(line_value(raw, "KAT_512_X_LE"), &mut xb).expect("hex x");
    let k = u512_from_le_bytes(&kb);
    let x = u512_from_le_bytes(&xb);
    let leg_key = LegendreKey512::from_uint(k, &params_l).expect("leg key");
    let gold_key = GoldKey512::from_uint(k, &params_g).expect("gold key");
    let leg = legendre_prf_u512(&leg_key, &x, &params_l).expect("leg");
    let leg_exp: i8 = line_value(raw, "KAT_512_LEGENDRE").parse().expect("parse");
    assert_eq!(leg, leg_exp);
    let gout = gold_prf_u512(&gold_key, &x, &params_g).expect("gold");
    let mut gold_exp = [0u8; 64];
    hex::decode_to_slice(line_value(raw, "KAT_512_GOLD_LE"), &mut gold_exp).expect("gold hex");
    assert_eq!(gout, gold_exp);
}

#[test]
fn legendre_zero_input_errors() {
    let params = LegendrePrfParams256::pilot();
    let k = params.p.wrapping_sub(&U256::ONE);
    let key = LegendreKey256::from_uint(k, &params).expect("key");
    let x = U256::ONE;
    let r = legendre_prf_u256(&key, &x, &params);
    assert_eq!(r, Err(PrfError::ZeroInput));
}
