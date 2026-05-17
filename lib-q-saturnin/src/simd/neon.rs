//! NEON kernels for Saturnin helpers.

use alloc::vec;
use alloc::vec::Vec;
use core::arch::aarch64::{
    uint8x16_t,
    uint32x4_t,
    vandq_u32,
    vdupq_n_u32,
    veorq_u8,
    veorq_u32,
    vgetq_lane_u32,
    vld1q_u8,
    vorrq_u32,
    vshlq_n_u32,
    vshrq_n_u32,
    vst1q_u8,
};

use lib_q_core::{
    Error,
    Result,
};

/// NEON XOR for one 32-byte block.
///
/// # Safety
///
/// Caller must ensure NEON is available on the executing CPU before calling.
/// Input and output pointers must be valid for 32-byte reads/writes.
#[target_feature(enable = "neon")]
pub unsafe fn xor_blocks_32(a: &[u8; 32], b: &[u8; 32], result: &mut [u8; 32]) {
    // SAFETY: pointers are valid for 16-byte loads and NEON is enabled.
    let a0: uint8x16_t = unsafe { vld1q_u8(a.as_ptr()) };
    // SAFETY: pointers are valid for 16-byte loads and NEON is enabled.
    let a1: uint8x16_t = unsafe { vld1q_u8(a.as_ptr().add(16)) };
    // SAFETY: pointers are valid for 16-byte loads and NEON is enabled.
    let b0: uint8x16_t = unsafe { vld1q_u8(b.as_ptr()) };
    // SAFETY: pointers are valid for 16-byte loads and NEON is enabled.
    let b1: uint8x16_t = unsafe { vld1q_u8(b.as_ptr().add(16)) };

    let r0 = veorq_u8(a0, b0);
    let r1 = veorq_u8(a1, b1);

    // SAFETY: pointers are valid for 16-byte stores and NEON is enabled.
    unsafe {
        vst1q_u8(result.as_mut_ptr(), r0);
        vst1q_u8(result.as_mut_ptr().add(16), r1);
    }
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn v_xor(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    veorq_u32(a, b)
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn v_and(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    vandq_u32(a, b)
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn v_or(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    vorrq_u32(a, b)
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn v_set1(v: u32) -> uint32x4_t {
    vdupq_n_u32(v)
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn v_rol16(x: uint32x4_t) -> uint32x4_t {
    let l = vshlq_n_u32(x, 16);
    let r = vshrq_n_u32(x, 16);
    vorrq_u32(l, r)
}

#[target_feature(enable = "neon")]
unsafe fn apply_sbox(q: &mut [uint32x4_t; 8]) {
    let mut a = q[0];
    let mut b = q[1];
    let mut c = q[2];
    let mut d = q[3];
    a = unsafe { v_xor(a, v_and(b, c)) };
    b = unsafe { v_xor(b, v_or(a, d)) };
    d = unsafe { v_xor(d, v_or(b, c)) };
    c = unsafe { v_xor(c, v_and(b, d)) };
    b = unsafe { v_xor(b, v_or(a, c)) };
    a = unsafe { v_xor(a, v_or(b, d)) };
    q[0] = b;
    q[1] = c;
    q[2] = d;
    q[3] = a;

    let mut a = q[4];
    let mut b = q[5];
    let mut c = q[6];
    let mut d = q[7];
    a = unsafe { v_xor(a, v_and(b, c)) };
    b = unsafe { v_xor(b, v_or(a, d)) };
    d = unsafe { v_xor(d, v_or(b, c)) };
    c = unsafe { v_xor(c, v_and(b, d)) };
    b = unsafe { v_xor(b, v_or(a, c)) };
    a = unsafe { v_xor(a, v_or(b, d)) };
    q[4] = d;
    q[5] = b;
    q[6] = a;
    q[7] = c;
}

#[target_feature(enable = "neon")]
unsafe fn mul_column_4_7(q: &mut [uint32x4_t; 8]) {
    let tmp = q[4];
    q[4] = q[5];
    q[5] = q[6];
    q[6] = q[7];
    q[7] = unsafe { v_xor(tmp, q[4]) };
}

#[target_feature(enable = "neon")]
unsafe fn mul_column_0_3(q: &mut [uint32x4_t; 8]) {
    let tmp = q[0];
    q[0] = q[1];
    q[1] = q[2];
    q[2] = q[3];
    q[3] = unsafe { v_xor(tmp, q[0]) };
}

#[target_feature(enable = "neon")]
unsafe fn apply_mds(q: &mut [uint32x4_t; 8]) {
    q[0] = unsafe { v_xor(q[0], q[4]) };
    q[1] = unsafe { v_xor(q[1], q[5]) };
    q[2] = unsafe { v_xor(q[2], q[6]) };
    q[3] = unsafe { v_xor(q[3], q[7]) };

    unsafe { mul_column_4_7(q) };

    q[4] = unsafe { v_xor(q[4], v_rol16(q[0])) };
    q[5] = unsafe { v_xor(q[5], v_rol16(q[1])) };
    q[6] = unsafe { v_xor(q[6], v_rol16(q[2])) };
    q[7] = unsafe { v_xor(q[7], v_rol16(q[3])) };

    unsafe { mul_column_0_3(q) };
    unsafe { mul_column_0_3(q) };

    q[0] = unsafe { v_xor(q[0], q[4]) };
    q[1] = unsafe { v_xor(q[1], q[5]) };
    q[2] = unsafe { v_xor(q[2], q[6]) };
    q[3] = unsafe { v_xor(q[3], q[7]) };

    q[4] = unsafe { v_xor(q[4], v_rol16(q[0])) };
    q[5] = unsafe { v_xor(q[5], v_rol16(q[1])) };
    q[6] = unsafe { v_xor(q[6], v_rol16(q[2])) };
    q[7] = unsafe { v_xor(q[7], v_rol16(q[3])) };
}

#[target_feature(enable = "neon")]
unsafe fn apply_shift_rows_slice(q: &mut [uint32x4_t; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m3333 = unsafe { v_set1(0x3333_0000) };
    let m7777_low = unsafe { v_set1(0x0000_7777) };
    let m1111_low = unsafe { v_set1(0x0000_1111) };
    let m1111_hi = unsafe { v_set1(0x1111_0000) };
    let m7777_hi = unsafe { v_set1(0x7777_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = vshlq_n_u32(unsafe { v_and(x, m3333) }, 2);
        let b = unsafe { v_and(vshrq_n_u32(x, 2), m3333) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().skip(4).take(4) {
        let x = *qi;
        let a = vshlq_n_u32(unsafe { v_and(x, m7777_low) }, 1);
        let b = unsafe { v_and(vshrq_n_u32(x, 3), m1111_low) };
        let c = vshlq_n_u32(unsafe { v_and(x, m1111_hi) }, 3);
        let d = unsafe { v_and(vshrq_n_u32(x, 1), m7777_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

#[target_feature(enable = "neon")]
unsafe fn apply_shift_rows_slice_inv(q: &mut [uint32x4_t; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m3333 = unsafe { v_set1(0x3333_0000) };
    let m1111_low = unsafe { v_set1(0x0000_1111) };
    let m7777_low = unsafe { v_set1(0x0000_7777) };
    let m7777_hi = unsafe { v_set1(0x7777_0000) };
    let m1111_hi = unsafe { v_set1(0x1111_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = vshlq_n_u32(unsafe { v_and(x, m3333) }, 2);
        let b = unsafe { v_and(vshrq_n_u32(x, 2), m3333) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().skip(4).take(4) {
        let x = *qi;
        let a = vshlq_n_u32(unsafe { v_and(x, m1111_low) }, 3);
        let b = unsafe { v_and(vshrq_n_u32(x, 1), m7777_low) };
        let c = vshlq_n_u32(unsafe { v_and(x, m7777_hi) }, 1);
        let d = unsafe { v_and(vshrq_n_u32(x, 3), m1111_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

#[target_feature(enable = "neon")]
unsafe fn apply_shift_rows_sheet(q: &mut [uint32x4_t; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m00ff = unsafe { v_set1(0x00FF_0000) };
    let m0fff_low = unsafe { v_set1(0x0000_0FFF) };
    let m000f_low = unsafe { v_set1(0x0000_000F) };
    let m000f_hi = unsafe { v_set1(0x000F_0000) };
    let m0fff_hi = unsafe { v_set1(0x0FFF_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = vshlq_n_u32(unsafe { v_and(x, m00ff) }, 8);
        let b = unsafe { v_and(vshrq_n_u32(x, 8), m00ff) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().skip(4).take(4) {
        let x = *qi;
        let a = vshlq_n_u32(unsafe { v_and(x, m0fff_low) }, 4);
        let b = unsafe { v_and(vshrq_n_u32(x, 12), m000f_low) };
        let c = vshlq_n_u32(unsafe { v_and(x, m000f_hi) }, 12);
        let d = unsafe { v_and(vshrq_n_u32(x, 4), m0fff_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

#[target_feature(enable = "neon")]
unsafe fn apply_shift_rows_sheet_inv(q: &mut [uint32x4_t; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m00ff = unsafe { v_set1(0x00FF_0000) };
    let m000f_low = unsafe { v_set1(0x0000_000F) };
    let m0fff_low = unsafe { v_set1(0x0000_0FFF) };
    let m0fff_hi = unsafe { v_set1(0x0FFF_0000) };
    let m000f_hi = unsafe { v_set1(0x000F_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = vshlq_n_u32(unsafe { v_and(x, m00ff) }, 8);
        let b = unsafe { v_and(vshrq_n_u32(x, 8), m00ff) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().skip(4).take(4) {
        let x = *qi;
        let a = vshlq_n_u32(unsafe { v_and(x, m000f_low) }, 12);
        let b = unsafe { v_and(vshrq_n_u32(x, 4), m0fff_low) };
        let c = vshlq_n_u32(unsafe { v_and(x, m0fff_hi) }, 4);
        let d = unsafe { v_and(vshrq_n_u32(x, 12), m000f_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

fn round_constants(num_super_rounds: usize, domain: u8) -> Vec<u32> {
    if num_super_rounds == 16 {
        match domain {
            7 => {
                return vec![
                    0x3FBA180C, 0x563AB9AB, 0x125EA5EF, 0x859DA26C, 0xB8CF779B, 0x7D4DE793,
                    0x07EFB49F, 0x8D525306, 0x1E08E6AB, 0x41729F87, 0x8C4AEF0A, 0x4AA0C9A7,
                    0xD93A95EF, 0xBB00D2AF, 0xB62C5BF0, 0x386D94D8,
                ];
            }
            8 => {
                return vec![
                    0x3C9B19A7, 0xA9098694, 0x23F878DA, 0xA7B647D3, 0x74FC9D78, 0xEACAAE11,
                    0x2F31A677, 0x4CC8C054, 0x2F51CA05, 0x5268F195, 0x4F5B8A2B, 0xF614B4AC,
                    0xF1D95401, 0x764D2568, 0x6A493611, 0x8EEF9C3E,
                ];
            }
            _ => {}
        }
    }

    let mut out = Vec::with_capacity(num_super_rounds);
    let mut x0 = (domain as u32)
        .wrapping_add((num_super_rounds as u32) << 4)
        .wrapping_add(0xFE00);
    let mut x1 = x0;
    for _ in 0..num_super_rounds {
        for _ in 0..16 {
            x0 = (x0 << 1) ^ (0x2D & (!(x0 >> 15).wrapping_add(1)));
            x1 = (x1 << 1) ^ (0x53 & (!(x1 >> 15).wrapping_add(1)));
        }
        out.push((x1 << 16) | x0);
    }
    out
}

/// NEON single-block bs32 encrypt path.
///
/// # Safety
///
/// Caller must ensure NEON is available on the executing CPU before calling.
/// The `block` buffer must be a valid mutable 32-byte block.
#[target_feature(enable = "neon")]
pub unsafe fn encrypt_block_bs32(
    num_super_rounds: usize,
    domain: u8,
    key: &[u8; 32],
    block: &mut [u8; 32],
) -> Result<()> {
    if num_super_rounds > 31 {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Number of super-rounds must be <= 31",
        });
    }
    if domain > 15 {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Domain must be <= 15",
        });
    }

    let mut keybuf = [0u32; 16];
    for i in 0..8 {
        let w = (key[i << 1] as u32) |
            ((key[(i << 1) + 1] as u32) << 8) |
            ((key[(i << 1) + 16] as u32) << 16) |
            ((key[(i << 1) + 17] as u32) << 24);
        keybuf[i] = w;
        keybuf[i + 8] = ((w & 0x001F001F) << 11) | ((w >> 5) & 0x07FF07FF);
    }
    let rc = round_constants(num_super_rounds, domain);

    let words = [
        (block[0] as u32) |
            ((block[1] as u32) << 8) |
            ((block[16] as u32) << 16) |
            ((block[17] as u32) << 24),
        (block[2] as u32) |
            ((block[3] as u32) << 8) |
            ((block[18] as u32) << 16) |
            ((block[19] as u32) << 24),
        (block[4] as u32) |
            ((block[5] as u32) << 8) |
            ((block[20] as u32) << 16) |
            ((block[21] as u32) << 24),
        (block[6] as u32) |
            ((block[7] as u32) << 8) |
            ((block[22] as u32) << 16) |
            ((block[23] as u32) << 24),
        (block[8] as u32) |
            ((block[9] as u32) << 8) |
            ((block[24] as u32) << 16) |
            ((block[25] as u32) << 24),
        (block[10] as u32) |
            ((block[11] as u32) << 8) |
            ((block[26] as u32) << 16) |
            ((block[27] as u32) << 24),
        (block[12] as u32) |
            ((block[13] as u32) << 8) |
            ((block[28] as u32) << 16) |
            ((block[29] as u32) << 24),
        (block[14] as u32) |
            ((block[15] as u32) << 8) |
            ((block[30] as u32) << 16) |
            ((block[31] as u32) << 24),
    ];

    let mut q = [
        unsafe { v_set1(words[0]) },
        unsafe { v_set1(words[1]) },
        unsafe { v_set1(words[2]) },
        unsafe { v_set1(words[3]) },
        unsafe { v_set1(words[4]) },
        unsafe { v_set1(words[5]) },
        unsafe { v_set1(words[6]) },
        unsafe { v_set1(words[7]) },
    ];

    for i in 0..8 {
        q[i] = unsafe { v_xor(q[i], v_set1(keybuf[i])) };
    }

    for i in (0..num_super_rounds).step_by(2) {
        unsafe { apply_sbox(&mut q) };
        unsafe { apply_mds(&mut q) };

        unsafe { apply_sbox(&mut q) };
        unsafe { apply_shift_rows_slice(&mut q) };
        unsafe { apply_mds(&mut q) };
        unsafe { apply_shift_rows_slice_inv(&mut q) };
        q[0] = unsafe { v_xor(q[0], v_set1(rc[i])) };
        for j in 0..8 {
            q[j] = unsafe { v_xor(q[j], v_set1(keybuf[j + 8])) };
        }

        if i + 1 < num_super_rounds {
            unsafe { apply_sbox(&mut q) };
            unsafe { apply_mds(&mut q) };

            unsafe { apply_sbox(&mut q) };
            unsafe { apply_shift_rows_sheet(&mut q) };
            unsafe { apply_mds(&mut q) };
            unsafe { apply_shift_rows_sheet_inv(&mut q) };
            q[0] = unsafe { v_xor(q[0], v_set1(rc[i + 1])) };
            for j in 0..8 {
                q[j] = unsafe { v_xor(q[j], v_set1(keybuf[j])) };
            }
        }
    }

    let w0 = vgetq_lane_u32(q[0], 0);
    let w1 = vgetq_lane_u32(q[1], 0);
    let w2 = vgetq_lane_u32(q[2], 0);
    let w3 = vgetq_lane_u32(q[3], 0);
    let w4 = vgetq_lane_u32(q[4], 0);
    let w5 = vgetq_lane_u32(q[5], 0);
    let w6 = vgetq_lane_u32(q[6], 0);
    let w7 = vgetq_lane_u32(q[7], 0);

    block[0] = w0 as u8;
    block[1] = (w0 >> 8) as u8;
    block[16] = (w0 >> 16) as u8;
    block[17] = (w0 >> 24) as u8;
    block[2] = w1 as u8;
    block[3] = (w1 >> 8) as u8;
    block[18] = (w1 >> 16) as u8;
    block[19] = (w1 >> 24) as u8;
    block[4] = w2 as u8;
    block[5] = (w2 >> 8) as u8;
    block[20] = (w2 >> 16) as u8;
    block[21] = (w2 >> 24) as u8;
    block[6] = w3 as u8;
    block[7] = (w3 >> 8) as u8;
    block[22] = (w3 >> 16) as u8;
    block[23] = (w3 >> 24) as u8;
    block[8] = w4 as u8;
    block[9] = (w4 >> 8) as u8;
    block[24] = (w4 >> 16) as u8;
    block[25] = (w4 >> 24) as u8;
    block[10] = w5 as u8;
    block[11] = (w5 >> 8) as u8;
    block[26] = (w5 >> 16) as u8;
    block[27] = (w5 >> 24) as u8;
    block[12] = w6 as u8;
    block[13] = (w6 >> 8) as u8;
    block[28] = (w6 >> 16) as u8;
    block[29] = (w6 >> 24) as u8;
    block[14] = w7 as u8;
    block[15] = (w7 >> 8) as u8;
    block[30] = (w7 >> 16) as u8;
    block[31] = (w7 >> 24) as u8;

    Ok(())
}
