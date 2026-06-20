//! The batched TurboSHAKE must equal four independent scalar instances, byte for byte.

use digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_sha3::parallel::{
    turbo_shake128_x4,
    turbo_shake256_x4,
};
use lib_q_sha3::{
    TurboShake128,
    TurboShake256,
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

fn scalar_ts128(ds: u8, msg: &[u8], out_len: usize) -> Vec<u8> {
    // const generic DS must be a literal; this test fixes it to the K12 leaf byte 0x0B.
    assert_eq!(ds, 0x0B);
    let mut h = TurboShake128::<0x0B>::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; out_len];
    r.read(&mut out);
    out
}

fn scalar_ts256(ds: u8, msg: &[u8], out_len: usize) -> Vec<u8> {
    assert_eq!(ds, 0x0B);
    let mut h = TurboShake256::<0x0B>::default();
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
        turbo_shake128_x4(
            0x0B,
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
        let want = scalar_ts128(0x0B, &m[lane], out_len);
        assert_eq!(
            got[lane], want,
            "TS128 lane {lane} mismatch (in_len={in_len}, out_len={out_len})"
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
        turbo_shake256_x4(
            0x0B,
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
        let want = scalar_ts256(0x0B, &m[lane], out_len);
        assert_eq!(
            got[lane], want,
            "TS256 lane {lane} mismatch (in_len={in_len}, out_len={out_len})"
        );
    }
}

#[test]
fn ts128_x4_matches_scalar_across_sizes() {
    // Empty, sub-rate, exactly one rate (168), rate+1, multi-block, exact K12 leaf (8192).
    for &in_len in &[0usize, 1, 167, 168, 169, 336, 337, 1000, 8192] {
        for &out_len in &[1usize, 32, 168, 169, 400] {
            check_128(in_len, out_len);
        }
    }
}

#[test]
fn ts256_x4_matches_scalar_across_sizes() {
    // TurboSHAKE256 rate is 136.
    for &in_len in &[0usize, 1, 135, 136, 137, 272, 1000, 8192] {
        for &out_len in &[1usize, 64, 136, 137, 400] {
            check_256(in_len, out_len);
        }
    }
}
