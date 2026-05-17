#![no_main]

use lib_q_prf::{
    GoldKey256,
    GoldPrfParams256,
    gold_prf_u256,
    u256_from_le_bytes,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let params = GoldPrfParams256::pilot();
    let mut kb = [0u8; 32];
    kb.copy_from_slice(&data[..32]);
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&data[32..64]);
    let Ok(key) = GoldKey256::from_uint(u256_from_le_bytes(&kb), &params) else {
        return;
    };
    let x = u256_from_le_bytes(&xb);
    let _ = gold_prf_u256(&key, &x, &params);
});
