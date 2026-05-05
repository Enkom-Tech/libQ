#![no_main]

use lib_q_prf::{
    LegendreKey256,
    LegendrePrfParams256,
    u256_from_le_bytes,
};
use lib_q_ring_sig::{
    DualRingPrfMemberPublic256,
    DualRingPrfSignature256,
    verify_dualring_prf_u256,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 32 + 32 + 32 + 1 + 32 + 32 {
        return;
    }
    let leg_p = LegendrePrfParams256::pilot();
    let mut off = 0usize;
    let mut kb0 = [0u8; 32];
    kb0.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let mut gb0 = [0u8; 32];
    gb0.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let mut kb1 = [0u8; 32];
    kb1.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let mut gb1 = [0u8; 32];
    gb1.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let idx = (data[off] as usize) % 2;
    off += 1;
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let legendre_out = data.get(off).copied().unwrap_or(0) as i8;
    off += 1;
    if off + 32 > data.len() {
        return;
    }
    let mut gold_out = [0u8; 32];
    gold_out.copy_from_slice(&data[off..off + 32]);

    if LegendreKey256::from_uint(u256_from_le_bytes(&kb0), &leg_p).is_err() {
        return;
    }
    if LegendreKey256::from_uint(u256_from_le_bytes(&kb1), &leg_p).is_err() {
        return;
    }

    let ring = vec![
        DualRingPrfMemberPublic256 {
            legendre_key_le: kb0,
            gold_key_le: gb0,
        },
        DualRingPrfMemberPublic256 {
            legendre_key_le: kb1,
            gold_key_le: gb1,
        },
    ];

    let sig = DualRingPrfSignature256 {
        commitment,
        challenge,
        legendre_out,
        gold_out,
    };

    let msg = &data[off + 32..];
    let _ = verify_dualring_prf_u256(&ring, idx, msg, &sig);
});
