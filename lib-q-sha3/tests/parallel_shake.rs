//! The batched FIPS-202 SHAKE must equal four independent scalar instances, byte for byte.

use digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_sha3::parallel::{
    shake128_x4,
    shake256_x4,
};
use lib_q_sha3::{
    Shake128,
    Shake256,
};

fn seeded(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xFF) as u8
        })
        .collect()
}

fn scalar_shake128(msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Shake128::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; out_len];
    r.read(&mut out);
    out
}

fn scalar_shake256(msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; out_len];
    r.read(&mut out);
    out
}

fn check_128(in_len: usize, out_len: usize) {
    let m = [
        seeded(1, in_len),
        seeded(2, in_len),
        seeded(0xDEAD_BEEF, in_len),
        seeded(0xFEED_FACE, in_len),
    ];
    let mut got = [
        vec![0u8; out_len],
        vec![0u8; out_len],
        vec![0u8; out_len],
        vec![0u8; out_len],
    ];
    {
        let [a, b, c, d] = &mut got;
        shake128_x4(
            [&m[0], &m[1], &m[2], &m[3]],
            [
                a.as_mut_slice(),
                b.as_mut_slice(),
                c.as_mut_slice(),
                d.as_mut_slice(),
            ],
        );
    }
    for lane in 0..4 {
        let want = scalar_shake128(&m[lane], out_len);
        assert_eq!(
            got[lane], want,
            "SHAKE128 lane {lane} mismatch (in_len={in_len}, out_len={out_len})"
        );
    }
}

fn check_256(in_len: usize, out_len: usize) {
    let m = [
        seeded(11, in_len),
        seeded(22, in_len),
        seeded(0x1234_5678, in_len),
        seeded(0x0BAD_F00D, in_len),
    ];
    let mut got = [
        vec![0u8; out_len],
        vec![0u8; out_len],
        vec![0u8; out_len],
        vec![0u8; out_len],
    ];
    {
        let [a, b, c, d] = &mut got;
        shake256_x4(
            [&m[0], &m[1], &m[2], &m[3]],
            [
                a.as_mut_slice(),
                b.as_mut_slice(),
                c.as_mut_slice(),
                d.as_mut_slice(),
            ],
        );
    }
    for lane in 0..4 {
        let want = scalar_shake256(&m[lane], out_len);
        assert_eq!(
            got[lane], want,
            "SHAKE256 lane {lane} mismatch (in_len={in_len}, out_len={out_len})"
        );
    }
}

#[test]
fn shake128_x4_matches_scalar_across_sizes() {
    // Empty, sub-rate, exactly one rate (168), rate+1, multi-block. Small sizes mirror SLH-DSA's
    // single-block `f`/`prf` inputs (pk_seed + adrs + m ≈ 54 bytes for the L1 sets).
    for &in_len in &[0usize, 1, 22, 54, 167, 168, 169, 336, 337, 1000] {
        for &out_len in &[1usize, 16, 32, 168, 169, 400] {
            check_128(in_len, out_len);
        }
    }
}

#[test]
fn shake256_x4_matches_scalar_across_sizes() {
    // SHAKE256 rate is 136. SLH-DSA SHAKE suites use SHAKE256 for every component hash.
    for &in_len in &[0usize, 1, 54, 135, 136, 137, 272, 1000] {
        for &out_len in &[1usize, 16, 32, 64, 136, 137, 400] {
            check_256(in_len, out_len);
        }
    }
}
