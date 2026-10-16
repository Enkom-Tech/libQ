//! Portable, constant-time AES round (bitsliced SubBytes).
//!
//! SubBytes is the Boyar-Peralta depth-16 Boolean circuit for the AES S-box
//! ("A depth-16 circuit for the AES S-box", Boyar and Peralta, 2011), the same
//! circuit used by constant-time software AES implementations such as BearSSL's
//! `aes_ct`. It is evaluated over eight bit planes, where plane `b` holds bit `b`
//! of every input byte. One evaluation processes up to eight blocks (128 bytes)
//! held in `u128` planes, so [`AesBlock::round_n`] batches the independent rounds of
//! an AEGIS-256 or HiAE update into a single circuit evaluation.
//!
//! Every step uses only fixed-index loads and stores, shifts by constants, and
//! bitwise operations: no table lookups, no secret-dependent branches, and no
//! secret-dependent addresses. ShiftRows is a fixed permutation and MixColumns
//! uses a mask-based `xtime`.

use super::AesBlock;

/// Portable 128-bit block (AES column-major byte order, as `AESENC` uses).
#[derive(Clone, Copy, Debug)]
pub struct Soft(pub [u8; 16]);

impl AesBlock for Soft {
    const BITSLICED: bool = true;

    #[inline(always)]
    unsafe fn load(b: &[u8; 16]) -> Self {
        Soft(*b)
    }

    #[inline(always)]
    unsafe fn store(self) -> [u8; 16] {
        self.0
    }

    #[inline(always)]
    unsafe fn zero() -> Self {
        Soft([0u8; 16])
    }

    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        let mut r = [0u8; 16];
        for (i, b) in r.iter_mut().enumerate() {
            *b = self.0[i] ^ o.0[i];
        }
        Soft(r)
    }

    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        let mut r = [0u8; 16];
        for (i, b) in r.iter_mut().enumerate() {
            *b = self.0[i] & o.0[i];
        }
        Soft(r)
    }

    #[inline(always)]
    unsafe fn round(self, rk: Self) -> Self {
        let [out] = rounds([self.0], [rk.0]);
        Soft(out)
    }

    #[inline(always)]
    unsafe fn round_n<const N: usize>(x: [Self; N], rk: [Self; N]) -> [Self; N] {
        let out = rounds(x.map(|b| b.0), rk.map(|b| b.0));
        out.map(Soft)
    }
}

/// `N` independent AES rounds (`N <= 8`), sharing one S-box circuit evaluation.
#[inline]
pub fn rounds<const N: usize>(x: [[u8; 16]; N], rk: [[u8; 16]; N]) -> [[u8; 16]; N] {
    const {
        assert!(
            N >= 1 && N <= 8,
            "the bitsliced S-box holds at most 8 blocks"
        )
    };

    // Pack: plane b, bit (16*blk + j) = bit b of byte j of block blk.
    let mut q = [0u128; 8];
    for (blk, bytes) in x.iter().enumerate() {
        for (j, &byte) in bytes.iter().enumerate() {
            let pos = 16 * blk + j;
            for (b, plane) in q.iter_mut().enumerate() {
                *plane |= u128::from((byte >> b) & 1) << pos;
            }
        }
    }

    sbox_planes(&mut q);

    let mut out = [[0u8; 16]; N];
    for (blk, block_out) in out.iter_mut().enumerate() {
        // Unpack SubBytes output for this block.
        let mut sb = [0u8; 16];
        for (j, byte) in sb.iter_mut().enumerate() {
            let pos = 16 * blk + j;
            let mut v = 0u8;
            for (b, plane) in q.iter().enumerate() {
                v |= (((plane >> pos) & 1) as u8) << b;
            }
            *byte = v;
        }
        *block_out = shift_rows_mix_columns_add(&sb, &rk[blk]);
    }
    out
}

/// GF(2^8) multiplication by x, branch-free.
#[inline(always)]
fn xtime(x: u8) -> u8 {
    let mask = 0u8.wrapping_sub(x >> 7);
    (x << 1) ^ (mask & 0x1B)
}

/// `MixColumns(ShiftRows(sb)) ^ rk`, column-major byte order.
#[inline(always)]
fn shift_rows_mix_columns_add(sb: &[u8; 16], rk: &[u8; 16]) -> [u8; 16] {
    // ShiftRows: out[r + 4c] = in[r + 4((c + r) mod 4)].
    let mut t = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            t[r + 4 * c] = sb[r + 4 * ((c + r) & 3)];
        }
    }
    let mut out = [0u8; 16];
    for c in 0..4 {
        let a0 = t[4 * c];
        let a1 = t[4 * c + 1];
        let a2 = t[4 * c + 2];
        let a3 = t[4 * c + 3];
        out[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3 ^ rk[4 * c];
        out[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3 ^ rk[4 * c + 1];
        out[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3) ^ rk[4 * c + 2];
        out[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3) ^ rk[4 * c + 3];
    }
    out
}

/// The AES S-box applied to every byte lane of the eight bit planes.
///
/// `q[0]` holds the least significant bit of each byte and `q[7]` the most
/// significant. Boyar-Peralta: linear top and bottom layers around a 32-AND
/// nonlinear core.
#[inline(always)]
#[allow(clippy::many_single_char_names)]
fn sbox_planes(q: &mut [u128; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Nonlinear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 forward S-box, used here only as a test oracle.
    const SBOX: [u8; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ];

    #[test]
    fn circuit_matches_fips197_sbox_for_all_256_inputs() {
        // 256 inputs = two full batches of 8 blocks.
        for batch in 0..2usize {
            let mut q = [0u128; 8];
            for pos in 0..128usize {
                let byte = (batch * 128 + pos) as u8;
                for (b, plane) in q.iter_mut().enumerate() {
                    *plane |= u128::from((byte >> b) & 1) << pos;
                }
            }
            sbox_planes(&mut q);
            for pos in 0..128usize {
                let mut v = 0u8;
                for (b, plane) in q.iter().enumerate() {
                    v |= (((plane >> pos) & 1) as u8) << b;
                }
                let input = batch * 128 + pos;
                assert_eq!(v, SBOX[input], "S-box mismatch at input {input:#04x}");
            }
        }
    }

    #[test]
    fn rfc10032_aesround_vector() {
        // RFC 10032 Appendix A.1.
        let input: [u8; 16] = core::array::from_fn(|i| i as u8);
        let rk: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
        let [out] = rounds([input], [rk]);
        assert_eq!(
            out,
            [
                0x7A, 0x7B, 0x4E, 0x56, 0x38, 0x78, 0x25, 0x46, 0xA8, 0xC0, 0x47, 0x7A, 0x3B, 0x81,
                0x3F, 0x43
            ]
        );
    }

    #[test]
    fn batched_rounds_equal_single_rounds() {
        let x: [[u8; 16]; 6] =
            core::array::from_fn(|b| core::array::from_fn(|i| (b * 37 + i * 11) as u8));
        let k: [[u8; 16]; 6] =
            core::array::from_fn(|b| core::array::from_fn(|i| (b * 5 + i * 29 + 3) as u8));
        let batched = rounds(x, k);
        for i in 0..6 {
            let [single] = rounds([x[i]], [k[i]]);
            assert_eq!(batched[i], single);
        }
    }
}
