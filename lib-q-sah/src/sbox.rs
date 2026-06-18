//! S-box for S-A-H-256: the AES S-box, computed constant-time.
//!
//! The S-A-H S-box *function* is the AES S-box (differential uniformity 4,
//! linearity 16). The freeze-gate requires the production path to be
//! **bitsliceable and constant-time** — no secret-indexed table lookup. We
//! therefore compute the AES S-box with the Boyar–Peralta combinational circuit
//! (eprint 2011/332, Figs 5/7/8: top linear → shared non-linear → bottom
//! linear), evaluated over `u64` lanes so a single pass substitutes all 64
//! state bytes at once. Control flow and memory access are data-independent.
//!
//! `SBOX` (the 256-byte table) is kept ONLY as a test reference / oracle and is
//! never read on the hot path. Equivalence is asserted exhaustively in the unit
//! tests, cross-checked in Python (`sah-research/scripts/bitslice_sbox_check.py`)
//! and bound to the Zig harness via the KAT vectors.

/// AES S-box table. **Reference/oracle only** (test builds): the production path
/// uses the constant-time bitsliced circuit (`layer_bitsliced`). A table lookup
/// indexed by secret data is not constant-time and must not run on the hot path.
#[cfg(test)]
pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// Transpose the 8x8 bit matrix packed in a `u64` (byte `j` = row `j`, bit `b`
/// = column `b`). Self-inverse. Standard SWAR delta-swap (Hacker's Delight).
#[inline(always)]
pub(crate) fn transpose8(mut x: u64) -> u64 {
    let mut t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x = x ^ t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x = x ^ t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x = x ^ t ^ (t << 28);
    x
}

/// Boyar–Peralta forward AES S-box circuit over `u64` lanes. Each bit position
/// is an independent S-box evaluation. `u[0]` is the MSB input plane; the
/// returned array's index 0 is the MSB output plane.
#[inline(always)]
fn bp_vec(u: [u64; 8]) -> [u64; 8] {
    let (u0, u1, u2, u3, u4, u5, u6, u7) = (u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7]);

    // Top linear transform (Fig. 5).
    let t1 = u0 ^ u3;
    let t2 = u0 ^ u5;
    let t3 = u0 ^ u6;
    let t4 = u3 ^ u5;
    let t5 = u4 ^ u6;
    let t6 = t1 ^ t5;
    let t7 = u1 ^ u2;
    let t8 = u7 ^ t6;
    let t9 = u7 ^ t7;
    let t10 = t6 ^ t7;
    let t11 = u1 ^ u5;
    let t12 = u2 ^ u5;
    let t13 = t3 ^ t4;
    let t14 = t6 ^ t11;
    let t15 = t5 ^ t11;
    let t16 = t5 ^ t12;
    let t17 = t9 ^ t16;
    let t18 = u3 ^ u7;
    let t19 = t7 ^ t18;
    let t20 = t1 ^ t19;
    let t21 = u6 ^ u7;
    let t22 = t7 ^ t21;
    let t23 = t2 ^ t22;
    let t24 = t2 ^ t10;
    let t25 = t20 ^ t17;
    let t26 = t3 ^ t16;
    let t27 = t1 ^ t12;
    let d = u7; // forward direction

    // Shared non-linear component (Fig. 7).
    let m1 = t13 & t6;
    let m2 = t23 & t8;
    let m3 = t14 ^ m1;
    let m4 = t19 & d;
    let m5 = m4 ^ m1;
    let m6 = t3 & t16;
    let m7 = t22 & t9;
    let m8 = t26 ^ m6;
    let m9 = t20 & t17;
    let m10 = m9 ^ m6;
    let m11 = t1 & t15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let m14 = t2 & t10;
    let m15 = m14 ^ m11;
    let m16 = m3 ^ m2;
    let m17 = m5 ^ t24;
    let m18 = m8 ^ m7;
    let m19 = m10 ^ m15;
    let m20 = m16 ^ m13;
    let m21 = m17 ^ m15;
    let m22 = m18 ^ m13;
    let m23 = m19 ^ t25;
    let m24 = m22 ^ m23;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m27 = m20 ^ m21;
    let m28 = m23 ^ m25;
    let m29 = m28 & m27;
    let m30 = m26 & m24;
    let m31 = m20 & m23;
    let m32 = m27 & m31;
    let m33 = m27 ^ m25;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m36 = m24 ^ m25;
    let m37 = m21 ^ m29;
    let m38 = m32 ^ m33;
    let m39 = m23 ^ m30;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m42 = m37 ^ m39;
    let m43 = m37 ^ m38;
    let m44 = m39 ^ m40;
    let m45 = m42 ^ m41;
    let m46 = m44 & t6;
    let m47 = m40 & t8;
    let m48 = m39 & d;
    let m49 = m43 & t16;
    let m50 = m38 & t9;
    let m51 = m37 & t17;
    let m52 = m42 & t15;
    let m53 = m45 & t27;
    let m54 = m41 & t10;
    let m55 = m44 & t13;
    let m56 = m40 & t23;
    let m57 = m39 & t19;
    let m58 = m43 & t3;
    let m59 = m38 & t22;
    let m60 = m37 & t20;
    let m61 = m42 & t1;
    let m62 = m45 & t4;
    let m63 = m41 & t2;

    // Bottom linear transform (Fig. 8). XNOR ('#') lines are negated.
    let l0 = m61 ^ m62;
    let l1 = m50 ^ m56;
    let l2 = m46 ^ m48;
    let l3 = m47 ^ m55;
    let l4 = m54 ^ m58;
    let l5 = m49 ^ m61;
    let l6 = m62 ^ l5;
    let l7 = m46 ^ l3;
    let l8 = m51 ^ m59;
    let l9 = m52 ^ m53;
    let l10 = m53 ^ l4;
    let l11 = m60 ^ l2;
    let l12 = m48 ^ m51;
    let l13 = m50 ^ l0;
    let l14 = m52 ^ m61;
    let l15 = m55 ^ l1;
    let l16 = m56 ^ l0;
    let l17 = m57 ^ l1;
    let l18 = m58 ^ l8;
    let l19 = m63 ^ l4;
    let l20 = l0 ^ l1;
    let l21 = l1 ^ l7;
    let l22 = l3 ^ l12;
    let l23 = l18 ^ l2;
    let l24 = l15 ^ l9;
    let l25 = l6 ^ l10;
    let l26 = l7 ^ l9;
    let l27 = l8 ^ l10;
    let l28 = l11 ^ l14;
    let l29 = l11 ^ l17;

    [
        l6 ^ l24,     // S0
        !(l16 ^ l26), // S1 (XNOR)
        !(l19 ^ l28), // S2 (XNOR)
        l6 ^ l21,     // S3
        l20 ^ l22,    // S4
        l25 ^ l29,    // S5
        !(l13 ^ l27), // S6 (XNOR)
        !(l6 ^ l23),  // S7 (XNOR)
    ]
}

/// Constant-time bitsliced AES S-box applied to every byte of the 8-word state.
/// Production path: no table lookup, data-independent control flow.
// The loop indices double as bit-shift amounts (`8 * i`, `8 * p`) in these transpose/scatter
// steps, so range loops express the bit-plane layout most clearly; an iterator rewrite would
// obscure the bitslicing without removing the index arithmetic.
#[allow(clippy::needless_range_loop)]
#[inline]
pub(crate) fn layer_bitsliced(s: &mut [u64; 8]) {
    // Orthogonalize: build 8 bit-planes over all 64 state bytes.
    let mut t = [0u64; 8];
    for i in 0..8 {
        t[i] = transpose8(s[i]);
    }
    let mut reg = [0u64; 8];
    for i in 0..8 {
        for p in 0..8 {
            let byte = (t[i] >> (8 * p)) & 0xFF;
            reg[p] |= byte << (8 * i);
        }
    }
    // u[k] is the MSB-first plane (U0 = bit 7).
    let mut u = [0u64; 8];
    for k in 0..8 {
        u[k] = reg[7 - k];
    }
    let out = bp_vec(u);
    // Scatter back: output plane for bit p is out[7 - p].
    let mut regp = [0u64; 8];
    for p in 0..8 {
        regp[p] = out[7 - p];
    }
    let mut tp = [0u64; 8];
    for i in 0..8 {
        for p in 0..8 {
            let byte = (regp[p] >> (8 * i)) & 0xFF;
            tp[i] |= byte << (8 * p);
        }
    }
    for i in 0..8 {
        s[i] = transpose8(tp[i]);
    }
}

/// Reference table-lookup S-box layer. **NOT constant-time** — test oracle only.
#[cfg(test)]
pub(crate) fn layer_table(s: &mut [u64; 8]) {
    for w in s.iter_mut() {
        let b = w.to_le_bytes();
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = SBOX[b[i] as usize];
        }
        *w = u64::from_le_bytes(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitsliced_matches_table_layer() {
        // deterministic LCG for reproducibility without external deps
        let mut x: u64 = 0x5A48_2A2A_2A2A_2A2A;
        let mut next = || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            x
        };
        for _ in 0..8192 {
            let mut a = [0u64; 8];
            for w in a.iter_mut() {
                *w = next();
            }
            let mut b = a;
            layer_bitsliced(&mut a);
            layer_table(&mut b);
            assert_eq!(a, b);
        }
        for e in [
            [0u64; 8],
            [u64::MAX; 8],
            [0x0102_0304_0506_0708u64; 8],
            [0, 1, 2, 3, 4, 5, 6, 7],
            [0xFFu64; 8],
        ] {
            let mut a = e;
            let mut b = e;
            layer_bitsliced(&mut a);
            layer_table(&mut b);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn bitsliced_reproduces_aes_sbox_all_256() {
        for byte in 0u16..256 {
            let b = byte as u8;
            let word = (b as u64).wrapping_mul(0x0101_0101_0101_0101);
            let mut s = [word; 8];
            layer_bitsliced(&mut s);
            let expected = (SBOX[b as usize] as u64).wrapping_mul(0x0101_0101_0101_0101);
            for w in s {
                assert_eq!(w, expected, "input byte {b:#04x}");
            }
        }
    }

    #[test]
    fn transpose8_self_inverse() {
        let mut x: u64 = 0xDEAD_BEEF_CAFE_1234;
        for _ in 0..1000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            assert_eq!(x, transpose8(transpose8(x)));
        }
    }
}
