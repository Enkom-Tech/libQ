//! Toom–Cook 3 + Karatsuba + PCLMUL multiply from `reference/hqc/src/x86_64/common/hqc-*/gf2x.c`.
//!
//! Buffer sizes follow `PARAM_N_MULT` / `VEC_N_256_SIZE_64` on [`crate::params_correct::HqcParams`].

#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec;
use core::arch::x86_64::*;

/// Derived sizes for one parameter set (matches reference `gf2x.c` macros).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ToomDims {
    pub t_tm3r_3w_256: usize,
    pub t_tm3r_3w_64: usize,
}

impl ToomDims {
    #[inline]
    pub const fn from_param_n_mult(n_mult: usize) -> Self {
        let t_tm3r_3w = n_mult / 3;
        let t_tm3r_3w_256 = (t_tm3r_3w + 128) / (4 * 64);
        let t_tm3r_3w_64 = t_tm3r_3w_256 << 2;
        Self {
            t_tm3r_3w_256,
            t_tm3r_3w_64,
        }
    }

    #[inline]
    pub const fn t2(&self) -> usize {
        self.t_tm3r_3w_64 << 1
    }

    /// `6 * T_TM3R_3W_256 - 2` stores in `Out` (reference `toom_3_mult` final loop).
    #[inline]
    pub const fn out_m256i_len(&self) -> usize {
        6 * self.t_tm3r_3w_256 - 2
    }

    /// Inner Toom-3 chunk width in `__m256i` (reference `T_3W >> 8` per parameter set).
    ///
    /// Verified against the fast HQC AVX2 layout: HQC-128 uses 2048-bit (`8`), HQC-192
    /// uses 4096-bit (`16`), HQC-256 uses 8192-bit (`32`) elementary blocks; operands are
    /// zero-padded to `3 *` this width when `t_tm3r_3w_256` is below that (HQC-256: 78 → 96).
    #[inline]
    pub fn t3w_256(&self) -> usize {
        match self.t_tm3r_3w_256 {
            24 => 8,
            48 => 16,
            78 => 32,
            _ => panic!("unsupported T_TM3R_3W_256 for AVX2 Toom-3"),
        }
    }

    #[inline]
    pub fn karat3_in_m256i(&self) -> usize {
        3 * self.t3w_256()
    }

    #[inline]
    pub fn karat3_out_m256i(&self) -> usize {
        6 * self.t3w_256()
    }

    /// Slice length for `u0`…`v2`: at least `t_tm3r_3w_256`, padded to `karat3_in_m256i` when needed.
    #[inline]
    pub fn padded_tm3_slice_m256i(&self) -> usize {
        let t = self.t_tm3r_3w_256;
        let kin = self.karat3_in_m256i();
        t.max(kin)
    }

    /// `max(2 * t_tm3r_3w_256, karat3_out_m256i)` — buffers holding full `karat_mult3` outputs.
    #[inline]
    pub fn w_buf_m256i(&self) -> usize {
        let t2 = self.t_tm3r_3w_256 << 1;
        let ko = self.karat3_out_m256i();
        t2.max(ko)
    }

    #[inline]
    pub fn tmp_m256i(&self) -> usize {
        let t4 = self.t_tm3r_3w_256 * 4;
        let ko = self.karat3_out_m256i();
        t4.max(ko)
    }
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
pub(crate) unsafe fn karat_mult_1(c: *mut __m128i, a: *const __m128i, b: *const __m128i) {
    let z = _mm_setzero_si128();
    let mut d1 = [z; 2];
    let mut d0 = [z; 2];
    let mut d2 = [z; 2];

    let al = _mm_loadu_si128(a);
    let ah = _mm_loadu_si128(a.add(1));
    let bl = _mm_loadu_si128(b);
    let bh = _mm_loadu_si128(b.add(1));

    let mut dd0 = _mm_clmulepi64_si128(al, bl, 0);
    let mut dd2 = _mm_clmulepi64_si128(al, bl, 0x11);
    let mut aalpaah = _mm_xor_si128(al, _mm_shuffle_epi32(al, 0x4E));
    let mut bblpbbh = _mm_xor_si128(bl, _mm_shuffle_epi32(bl, 0x4E));
    let mut dd1 = _mm_xor_si128(
        _mm_xor_si128(dd0, dd2),
        _mm_clmulepi64_si128(aalpaah, bblpbbh, 0),
    );
    d0[0] = _mm_xor_si128(dd0, _mm_unpacklo_epi64(_mm_setzero_si128(), dd1));
    d0[1] = _mm_xor_si128(dd2, _mm_unpackhi_epi64(dd1, _mm_setzero_si128()));

    dd0 = _mm_clmulepi64_si128(ah, bh, 0);
    dd2 = _mm_clmulepi64_si128(ah, bh, 0x11);
    aalpaah = _mm_xor_si128(ah, _mm_shuffle_epi32(ah, 0x4E));
    bblpbbh = _mm_xor_si128(bh, _mm_shuffle_epi32(bh, 0x4E));
    dd1 = _mm_xor_si128(
        _mm_xor_si128(dd0, dd2),
        _mm_clmulepi64_si128(aalpaah, bblpbbh, 0),
    );
    d2[0] = _mm_xor_si128(dd0, _mm_unpacklo_epi64(_mm_setzero_si128(), dd1));
    d2[1] = _mm_xor_si128(dd2, _mm_unpackhi_epi64(dd1, _mm_setzero_si128()));

    let alpah = _mm_xor_si128(al, ah);
    let blpbh = _mm_xor_si128(bl, bh);
    dd0 = _mm_clmulepi64_si128(alpah, blpbh, 0);
    dd2 = _mm_clmulepi64_si128(alpah, blpbh, 0x11);
    aalpaah = _mm_xor_si128(alpah, _mm_shuffle_epi32(alpah, 0x4E));
    bblpbbh = _mm_xor_si128(blpbh, _mm_shuffle_epi32(blpbh, 0x4E));
    dd1 = _mm_xor_si128(
        _mm_xor_si128(dd0, dd2),
        _mm_clmulepi64_si128(aalpaah, bblpbbh, 0),
    );
    d1[0] = _mm_xor_si128(dd0, _mm_unpacklo_epi64(_mm_setzero_si128(), dd1));
    d1[1] = _mm_xor_si128(dd2, _mm_unpackhi_epi64(dd1, _mm_setzero_si128()));

    let middle = _mm_xor_si128(d0[1], d2[0]);
    c.write(d0[0]);
    c.add(1)
        .write(_mm_xor_si128(middle, _mm_xor_si128(d0[0], d1[0])));
    c.add(2)
        .write(_mm_xor_si128(middle, _mm_xor_si128(d1[1], d2[1])));
    c.add(3).write(d2[1]);
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_mult_2(c: *mut __m256i, a: *const __m256i, b: *const __m256i) {
    let z = _mm256_setzero_si256();
    let mut d0 = [z; 2];
    let mut d1 = [z; 2];
    let mut d2 = [z; 2];

    karat_mult_1(d0.as_mut_ptr().cast(), a.cast(), b.cast());
    karat_mult_1(
        d2.as_mut_ptr().cast(),
        a.cast::<__m128i>().add(2),
        b.cast::<__m128i>().add(2),
    );

    let saa = _mm256_xor_si256(a.read(), a.add(1).read());
    let sbb = _mm256_xor_si256(b.read(), b.add(1).read());
    karat_mult_1(
        d1.as_mut_ptr().cast(),
        (&saa as *const __m256i).cast(),
        (&sbb as *const __m256i).cast(),
    );

    let middle = _mm256_xor_si256(d0[1], d2[0]);
    c.write(d0[0]);
    c.add(1)
        .write(_mm256_xor_si256(middle, _mm256_xor_si256(d0[0], d1[0])));
    c.add(2)
        .write(_mm256_xor_si256(middle, _mm256_xor_si256(d1[1], d2[1])));
    c.add(3).write(d2[1]);
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_mult_4(c: *mut __m256i, a: *const __m256i, b: *const __m256i) {
    let z = _mm256_setzero_si256();
    let mut d0 = [z; 4];
    let mut d1 = [z; 4];
    let mut d2 = [z; 4];
    let mut saa = [z; 2];
    let mut sbb = [z; 2];

    karat_mult_2(d0.as_mut_ptr(), a, b);
    karat_mult_2(d2.as_mut_ptr(), a.add(2), b.add(2));

    saa[0] = _mm256_xor_si256(a.read(), a.add(2).read());
    sbb[0] = _mm256_xor_si256(b.read(), b.add(2).read());
    saa[1] = _mm256_xor_si256(a.add(1).read(), a.add(3).read());
    sbb[1] = _mm256_xor_si256(b.add(1).read(), b.add(3).read());

    karat_mult_2(d1.as_mut_ptr(), saa.as_ptr(), sbb.as_ptr());

    let middle0 = _mm256_xor_si256(d0[2], d2[0]);
    let middle1 = _mm256_xor_si256(d0[3], d2[1]);

    c.write(d0[0]);
    c.add(1).write(d0[1]);
    c.add(2)
        .write(_mm256_xor_si256(middle0, _mm256_xor_si256(d0[0], d1[0])));
    c.add(3)
        .write(_mm256_xor_si256(middle1, _mm256_xor_si256(d0[1], d1[1])));
    c.add(4)
        .write(_mm256_xor_si256(middle0, _mm256_xor_si256(d1[2], d2[2])));
    c.add(5)
        .write(_mm256_xor_si256(middle1, _mm256_xor_si256(d1[3], d2[3])));
    c.add(6).write(d2[2]);
    c.add(7).write(d2[3]);
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_mult_8(c: *mut __m256i, a: *const __m256i, b: *const __m256i) {
    let z = _mm256_setzero_si256();
    let mut d0 = [z; 8];
    let mut d1 = [z; 8];
    let mut d2 = [z; 8];
    let mut saa = [z; 4];
    let mut sbb = [z; 4];

    karat_mult_4(d0.as_mut_ptr(), a, b);
    karat_mult_4(d2.as_mut_ptr(), a.add(4), b.add(4));

    for i in 0..4 {
        saa[i] = _mm256_xor_si256(a.add(i).read(), a.add(i + 4).read());
        sbb[i] = _mm256_xor_si256(b.add(i).read(), b.add(i + 4).read());
    }

    karat_mult_4(d1.as_mut_ptr(), saa.as_ptr(), sbb.as_ptr());

    for i in 0..4 {
        let is = i + 4;
        let is2 = is + 4;
        let is3 = is2 + 4;
        let middle = _mm256_xor_si256(d0[is], d2[i]);
        c.add(i).write(d0[i]);
        c.add(is)
            .write(_mm256_xor_si256(middle, _mm256_xor_si256(d0[i], d1[i])));
        c.add(is2)
            .write(_mm256_xor_si256(middle, _mm256_xor_si256(d1[is], d2[is])));
        c.add(is3).write(d2[is]);
    }
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_mult_16(c: *mut __m256i, a: *const __m256i, b: *const __m256i) {
    let z = _mm256_setzero_si256();
    let mut d0 = [z; 16];
    let mut d1 = [z; 16];
    let mut d2 = [z; 16];
    let mut saa = [z; 8];
    let mut sbb = [z; 8];

    karat_mult_8(d0.as_mut_ptr(), a, b);
    karat_mult_8(d2.as_mut_ptr(), a.add(8), b.add(8));

    for i in 0..8 {
        saa[i] = _mm256_xor_si256(a.add(i).read(), a.add(i + 8).read());
        sbb[i] = _mm256_xor_si256(b.add(i).read(), b.add(i + 8).read());
    }

    karat_mult_8(d1.as_mut_ptr(), saa.as_ptr(), sbb.as_ptr());

    for i in 0..8 {
        let is = i + 8;
        let is2 = is + 8;
        let is3 = is2 + 8;
        let middle = _mm256_xor_si256(d0[is], d2[i]);
        c.add(i).write(d0[i]);
        c.add(is)
            .write(_mm256_xor_si256(middle, _mm256_xor_si256(d0[i], d1[i])));
        c.add(is2)
            .write(_mm256_xor_si256(middle, _mm256_xor_si256(d1[is], d2[is])));
        c.add(is3).write(d2[is]);
    }
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_mult_32(c: *mut __m256i, a: *const __m256i, b: *const __m256i) {
    let z = _mm256_setzero_si256();
    let mut d0 = [z; 32];
    let mut d1 = [z; 32];
    let mut d2 = [z; 32];
    let mut saa = [z; 16];
    let mut sbb = [z; 16];

    karat_mult_16(d0.as_mut_ptr(), a, b);
    karat_mult_16(d2.as_mut_ptr(), a.add(16), b.add(16));

    for i in 0..16 {
        saa[i] = _mm256_xor_si256(a.add(i).read(), a.add(i + 16).read());
        sbb[i] = _mm256_xor_si256(b.add(i).read(), b.add(i + 16).read());
    }

    karat_mult_16(d1.as_mut_ptr(), saa.as_ptr(), sbb.as_ptr());

    for i in 0..16 {
        let is = i + 16;
        let is2 = is + 16;
        let is3 = is2 + 16;
        let middle = _mm256_xor_si256(d0[is], d2[i]);
        c.add(i).write(d0[i]);
        c.add(is)
            .write(_mm256_xor_si256(middle, _mm256_xor_si256(d0[i], d1[i])));
        c.add(is2)
            .write(_mm256_xor_si256(middle, _mm256_xor_si256(d1[is], d2[is])));
        c.add(is3).write(d2[is]);
    }
}

#[inline]
#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_inner_mul(c: *mut __m256i, a: *const __m256i, b: *const __m256i, t3w: usize) {
    match t3w {
        8 => karat_mult_8(c, a, b),
        16 => karat_mult_16(c, a, b),
        32 => karat_mult_32(c, a, b),
        _ => unreachable!("karat_inner_mul: invalid t3w"),
    }
}

/// 3-way Toom on operands of length `3 * t3w` `__m256i` (each third is one chunk); writes `6 * t3w` words to `out`.
#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn karat_mult3_dyn(out: *mut __m256i, a: *mut __m256i, b: *mut __m256i, t3w: usize) {
    let t2w = t3w << 1;
    let t6w = t3w * 6;

    let mut aa01 = vec![_mm256_setzero_si256(); t3w];
    let mut bb01 = vec![_mm256_setzero_si256(); t3w];
    let mut aa02 = vec![_mm256_setzero_si256(); t3w];
    let mut bb02 = vec![_mm256_setzero_si256(); t3w];
    let mut aa12 = vec![_mm256_setzero_si256(); t3w];
    let mut bb12 = vec![_mm256_setzero_si256(); t3w];

    let mut d0 = vec![_mm256_setzero_si256(); t2w];
    let mut d1 = vec![_mm256_setzero_si256(); t2w];
    let mut d2 = vec![_mm256_setzero_si256(); t2w];
    let mut d3 = vec![_mm256_setzero_si256(); t2w];
    let mut d4 = vec![_mm256_setzero_si256(); t2w];
    let mut d5 = vec![_mm256_setzero_si256(); t2w];
    let mut ro256 = vec![_mm256_setzero_si256(); 3 * t2w];

    let a0 = a;
    let a1 = a.add(t3w);
    let a2 = a.add(t3w << 1);
    let b0 = b;
    let b1 = b.add(t3w);
    let b2 = b.add(t3w << 1);

    for i in 0..t3w {
        aa01[i] = _mm256_xor_si256(a0.add(i).read(), a1.add(i).read());
        bb01[i] = _mm256_xor_si256(b0.add(i).read(), b1.add(i).read());
        aa12[i] = _mm256_xor_si256(a2.add(i).read(), a1.add(i).read());
        bb12[i] = _mm256_xor_si256(b2.add(i).read(), b1.add(i).read());
        aa02[i] = _mm256_xor_si256(a0.add(i).read(), a2.add(i).read());
        bb02[i] = _mm256_xor_si256(b0.add(i).read(), b2.add(i).read());
    }

    karat_inner_mul(d0.as_mut_ptr(), a0, b0, t3w);
    karat_inner_mul(d1.as_mut_ptr(), a1, b1, t3w);
    karat_inner_mul(d2.as_mut_ptr(), a2, b2, t3w);
    karat_inner_mul(d3.as_mut_ptr(), aa01.as_ptr(), bb01.as_ptr(), t3w);
    karat_inner_mul(d4.as_mut_ptr(), aa02.as_ptr(), bb02.as_ptr(), t3w);
    karat_inner_mul(d5.as_mut_ptr(), aa12.as_ptr(), bb12.as_ptr(), t3w);

    for i in 0..t3w {
        let j = i + t3w;
        let mut middle0 = _mm256_xor_si256(_mm256_xor_si256(d0[i], d1[i]), d0[j]);
        ro256[i] = d0[i];
        ro256[j] = _mm256_xor_si256(d3[i], middle0);
        ro256[j + t3w] = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_xor_si256(_mm256_xor_si256(d4[i], d2[i]), d3[j]),
                d1[j],
            ),
            middle0,
        );
        middle0 = _mm256_xor_si256(_mm256_xor_si256(d1[j], d2[i]), d2[j]);
        ro256[j + (t3w << 1)] = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_xor_si256(_mm256_xor_si256(d5[i], d4[j]), d0[j]),
                d1[i],
            ),
            middle0,
        );
        ro256[i + (t3w << 2)] = _mm256_xor_si256(d5[j], middle0);
        ro256[j + (t3w << 2)] = d2[j];
    }

    for i in 0..t6w {
        out.add(i).write(ro256[i]);
    }
}

#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn divide_by_x_plus_one_256(out: *mut __m256i, inp: *const __m256i, size: i32) {
    let a = inp.cast::<u64>();
    let b = out.cast::<u64>();
    b.write(a.read());
    let n = 2 * ((size as usize) << 2);
    for i in 1..n {
        b.add(i).write(b.add(i - 1).read() ^ a.add(i).read());
    }
}

/// Reference `toom_3_mult`; `out` must have length ≥ `d.out_m256i_len()`.
#[target_feature(enable = "avx2", enable = "pclmulqdq")]
pub(crate) unsafe fn toom_3_mult(
    out: *mut __m256i,
    a256: *const __m256i,
    b256: *const __m256i,
    d: ToomDims,
) {
    let t = d.t_tm3r_3w_256;
    let t64 = d.t_tm3r_3w_64;
    let t2 = d.t2();
    let t3w = d.t3w_256();
    let karat_out = d.karat3_out_m256i();
    let tk = d.padded_tm3_slice_m256i();
    let tw = d.w_buf_m256i();
    let tmp_len = d.tmp_m256i();

    let mut u0 = vec![_mm256_setzero_si256(); tk];
    let mut v0 = vec![_mm256_setzero_si256(); tk];
    let mut u1 = vec![_mm256_setzero_si256(); tk];
    let mut v1 = vec![_mm256_setzero_si256(); tk];
    let mut u2 = vec![_mm256_setzero_si256(); tk];
    let mut v2 = vec![_mm256_setzero_si256(); tk];

    let a = a256.cast::<u64>();
    let b = b256.cast::<u64>();

    for i in 0..t - 1 {
        let i4 = i << 2;
        // C: `int32_t i42 = i4 - 2` then `A[i42 + T_TM3R_3W_64]` — signed index, not wrapping usize.
        let u1_off = (i4 as i64) - 2 + (t64 as i64);
        debug_assert!(u1_off >= 0);
        let u1_off = u1_off as usize;
        u0[i] = _mm256_loadu_si256((a.add(i4)).cast());
        v0[i] = _mm256_loadu_si256((b.add(i4)).cast());
        u1[i] = _mm256_loadu_si256((a.add(u1_off)).cast());
        v1[i] = _mm256_loadu_si256((b.add(u1_off)).cast());
        u2[i] = _mm256_loadu_si256((a.add(i4 + t2 - 4)).cast());
        v2[i] = _mm256_loadu_si256((b.add(i4 + t2 - 4)).cast());
    }

    let i = t - 1;
    let i4 = i << 2;
    let i41 = i4 + 1;
    // C: { A[i4], A[i41], 0, 0 } — lane0 = low u64
    u0[i] = _mm256_set_epi64x(0, 0, a.add(i41).read() as i64, a.add(i4).read() as i64);
    v0[i] = _mm256_set_epi64x(0, 0, b.add(i41).read() as i64, b.add(i4).read() as i64);
    u1[i] = _mm256_set_epi64x(
        0,
        0,
        a.add(i41 + t64 - 2).read() as i64,
        a.add(i4 + t64 - 2).read() as i64,
    );
    v1[i] = _mm256_set_epi64x(
        0,
        0,
        b.add(i41 + t64 - 2).read() as i64,
        b.add(i4 + t64 - 2).read() as i64,
    );
    u2[i] = _mm256_set_epi64x(
        0,
        0,
        a.add(i4 - 4 + t2).read() as i64,
        a.add(i4 - 3 + t2).read() as i64,
    );
    v2[i] = _mm256_set_epi64x(
        0,
        0,
        b.add(i4 - 4 + t2).read() as i64,
        b.add(i4 - 3 + t2).read() as i64,
    );

    let mut w0 = vec![_mm256_setzero_si256(); tw];
    let mut w1 = vec![_mm256_setzero_si256(); tw];
    let mut w2 = vec![_mm256_setzero_si256(); tw];
    let mut w3 = vec![_mm256_setzero_si256(); tw];
    let mut w4 = vec![_mm256_setzero_si256(); tw];
    let mut tmp = vec![_mm256_setzero_si256(); tmp_len];
    let mut ro256 = vec![_mm256_setzero_si256(); 6 * t];
    let zero = _mm256_setzero_si256();

    for i in 0..t {
        w3[i] = _mm256_xor_si256(_mm256_xor_si256(u0[i], u1[i]), u2[i]);
        w2[i] = _mm256_xor_si256(_mm256_xor_si256(v0[i], v1[i]), v2[i]);
    }

    karat_mult3_dyn(w1.as_mut_ptr(), w2.as_mut_ptr(), w3.as_mut_ptr(), t3w);

    let mut u1_64 = u1.as_ptr() as *const u64;
    let mut u2_64 = u2.as_ptr() as *const u64;
    let mut v1_64 = v1.as_ptr() as *const u64;
    let mut v2_64 = v2.as_ptr() as *const u64;

    // C: {0, U1[0], U1[1]^U2[0], U1[2]^U2[1]}
    w0[0] = _mm256_set_epi64x(
        (u1_64.add(2).read() ^ u2_64.add(1).read()) as i64,
        (u1_64.add(1).read() ^ u2_64.read()) as i64,
        u1_64.read() as i64,
        0,
    );
    w4[0] = _mm256_set_epi64x(
        (v1_64.add(2).read() ^ v2_64.add(1).read()) as i64,
        (v1_64.add(1).read() ^ v2_64.read()) as i64,
        v1_64.read() as i64,
        0,
    );

    u1_64 = u1_64.add(3);
    u2_64 = u2_64.add(2);
    v1_64 = v1_64.add(3);
    v2_64 = v2_64.add(2);

    for i in 0..t - 1 {
        let i4 = i << 2;
        let i1 = i + 1;
        w0[i1] = _mm256_xor_si256(
            _mm256_loadu_si256((u1_64.add(i4)).cast()),
            _mm256_loadu_si256((u2_64.add(i4)).cast()),
        );
        w4[i1] = _mm256_xor_si256(
            _mm256_loadu_si256((v1_64.add(i4)).cast()),
            _mm256_loadu_si256((v2_64.add(i4)).cast()),
        );
    }

    for i in 0..t {
        w3[i] = _mm256_xor_si256(w3[i], w0[i]);
        w2[i] = _mm256_xor_si256(w2[i], w4[i]);
    }
    for i in 0..t {
        w0[i] = _mm256_xor_si256(w0[i], u0[i]);
        w4[i] = _mm256_xor_si256(w4[i], v0[i]);
    }

    karat_mult3_dyn(tmp.as_mut_ptr(), w3.as_mut_ptr(), w2.as_mut_ptr(), t3w);
    for i in 0..karat_out {
        w3[i] = tmp[i];
    }

    karat_mult3_dyn(w2.as_mut_ptr(), w0.as_mut_ptr(), w4.as_mut_ptr(), t3w);
    karat_mult3_dyn(w4.as_mut_ptr(), u2.as_mut_ptr(), v2.as_mut_ptr(), t3w);
    karat_mult3_dyn(w0.as_mut_ptr(), u0.as_mut_ptr(), v0.as_mut_ptr(), t3w);

    for i in 0..karat_out {
        w3[i] = _mm256_xor_si256(w3[i], w2[i]);
    }
    for i in 0..karat_out {
        w1[i] = _mm256_xor_si256(w1[i], w0[i]);
    }

    let u1_w2 = (w2.as_ptr() as *const u64).add(1);
    let u2_w0 = (w0.as_ptr() as *const u64).add(1);
    for i in 0..(t << 1) {
        let i4 = i << 2;
        w2[i] = _mm256_xor_si256(
            _mm256_loadu_si256((u1_w2.add(i4)).cast()),
            _mm256_loadu_si256((u2_w0.add(i4)).cast()),
        );
    }

    let u1_w4 = w4.as_ptr() as *const u64;
    // C: `(__m256i){0,0,0,U1_64[0]}` — low u64 lane first; matches `_mm256_set_epi64x(U1,0,0,0)`.
    tmp[0] = _mm256_xor_si256(
        _mm256_xor_si256(_mm256_xor_si256(w2[0], w3[0]), w4[0]),
        _mm256_set_epi64x(u1_w4.read() as i64, 0, 0, 0),
    );
    let u1p = u1_w4.add(1);
    for i in 1..(t << 1) - 1 {
        let i4 = i << 2;
        tmp[i] = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_xor_si256(w2[i], w3[i]), w4[i]),
            _mm256_loadu_si256((u1p.add(i4 - 4)).cast()),
        );
    }

    divide_by_x_plus_one_256(w2.as_mut_ptr(), tmp.as_ptr(), t as i32);
    w2[(t << 1) - 1] = zero;

    let u1_w3 = (w3.as_ptr() as *const u64).add(1);
    let u2_w1 = (w1.as_ptr() as *const u64).add(1);
    for i in 0..(t << 1) - 1 {
        let i4 = i << 2;
        tmp[i] = _mm256_xor_si256(
            _mm256_loadu_si256((u1_w3.add(i4)).cast()),
            _mm256_loadu_si256((u2_w1.add(i4)).cast()),
        );
    }

    divide_by_x_plus_one_256(w3.as_mut_ptr(), tmp.as_ptr(), t as i32);
    w3[(t << 1) - 1] = zero;

    for i in 0..karat_out {
        w1[i] = _mm256_xor_si256(w1[i], _mm256_xor_si256(w2[i], w4[i]));
    }
    for i in 0..karat_out {
        w2[i] = _mm256_xor_si256(w2[i], w3[i]);
    }

    for i in 0..(t << 1) - 1 {
        ro256[i] = w0[i];
        ro256[i + 2 * t - 1] = w2[i];
        ro256[i + 4 * t - 2] = w4[i];
    }

    ro256[(t << 1) - 1] = _mm256_xor_si256(w0[(t << 1) - 1], w2[0]);
    ro256[(t << 2) - 2] = _mm256_xor_si256(w2[(t << 1) - 1], w4[0]);
    ro256[6 * t - 3] = w4[(t << 1) - 1];

    let u1_ro = (ro256.as_mut_ptr() as *mut u64).add(t * 4 - 2);
    let u2_ro = (ro256.as_mut_ptr() as *mut u64).add((3 * t - 1) * 4 - 2);

    for i in 0..(t << 1) {
        let i4 = i << 2;
        let aux = _mm256_xor_si256(_mm256_loadu_si256((u1_ro.add(i4)).cast()), w1[i]);
        _mm256_storeu_si256((u1_ro.add(i4)).cast(), aux);
        let aux2 = _mm256_xor_si256(_mm256_loadu_si256((u2_ro.add(i4)).cast()), w3[i]);
        _mm256_storeu_si256((u2_ro.add(i4)).cast(), aux2);
    }

    let nout = d.out_m256i_len();
    for i in 0..nout {
        out.add(i).write(ro256[i]);
    }
}

#[inline]
unsafe fn mm256_srli_epi64_var(v: __m256i, imm: u32) -> __m256i {
    let mut x = [0u64; 4];
    _mm256_storeu_si256(x.as_mut_ptr().cast(), v);
    for z in &mut x {
        *z >>= imm.min(63);
    }
    _mm256_loadu_si256(x.as_ptr().cast())
}

#[inline]
unsafe fn mm256_slli_epi64_var(v: __m256i, imm: u32) -> __m256i {
    let mut x = [0u64; 4];
    _mm256_storeu_si256(x.as_mut_ptr().cast(), v);
    for z in &mut x {
        *z <<= imm.min(63);
    }
    _mm256_loadu_si256(x.as_ptr().cast())
}

/// Reference `reduce` from `gf2x.c`: modular reduction mod \(x^{PARAM\_N}-1\), output `VEC_N_SIZE_BYTES` into `out`.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn reduce_avx2_to_u64(
    out: &mut [u64],
    prod_a: &[__m256i],
    scratch_m256: &mut [__m256i],
    param_n: usize,
    vec_n_size_bytes: usize,
) {
    const WORD: i32 = 64;
    let last64 = (param_n >> 6) as i32;
    let dec64 = (param_n & 0x3F) as i32;
    let d0 = WORD - dec64;
    let a = prod_a.as_ptr().cast::<u64>();
    let a_m256 = prod_a.as_ptr();

    for elt in scratch_m256.iter_mut() {
        *elt = _mm256_setzero_si256();
    }
    let tmp_u64 = scratch_m256.as_mut_ptr().cast::<u64>();

    let upper = ((param_n >> 5) as i32) - 4;
    let mut i = last64;
    while i < upper {
        let mut r256 = _mm256_loadu_si256((a.add(i as usize)).cast());
        r256 = mm256_srli_epi64_var(r256, dec64 as u32);
        let mut carry256 = _mm256_loadu_si256((a.add(i as usize + 1)).cast());
        carry256 = mm256_slli_epi64_var(carry256, d0 as u32);
        r256 = _mm256_xor_si256(r256, carry256);
        let i2 = ((i - last64) >> 2) as usize;
        let lhs = _mm256_loadu_si256(a_m256.add(i2));
        scratch_m256[i2] = _mm256_xor_si256(lhs, r256);
        i += 4;
    }

    let mut i = i - last64;
    while i < last64 + 1 {
        let ii = i as usize;
        let r = a.add(ii + last64 as usize).read() >> (dec64 as u32);
        let carry = a
            .add(ii + last64 as usize + 1)
            .read()
            .wrapping_shl(d0 as u32);
        tmp_u64.add(ii).write(a.add(ii).read() ^ r ^ carry);
        i += 1;
    }

    let mask = (1u64 << (param_n & 0x3F)) - 1;
    tmp_u64
        .add(last64 as usize)
        .write(tmp_u64.add(last64 as usize).read() & mask);

    core::ptr::copy_nonoverlapping(
        tmp_u64.cast::<u8>(),
        out.as_mut_ptr().cast::<u8>(),
        vec_n_size_bytes,
    );
}

#[cfg(test)]
mod toom_dims_tests {
    use super::ToomDims;
    use crate::params_correct::{
        Hqc1Params,
        Hqc3Params,
        Hqc5Params,
        HqcParams,
    };

    #[test]
    fn t3w_256_matches_reference_avx2_layout() {
        let d128 = ToomDims::from_param_n_mult(Hqc1Params::PARAM_N_MULT);
        assert_eq!(d128.t_tm3r_3w_256, 24);
        assert_eq!(d128.t3w_256(), 8);
        assert_eq!(d128.karat3_in_m256i(), 24);
        assert_eq!(d128.padded_tm3_slice_m256i(), 24);

        let d192 = ToomDims::from_param_n_mult(Hqc3Params::PARAM_N_MULT);
        assert_eq!(d192.t_tm3r_3w_256, 48);
        assert_eq!(d192.t3w_256(), 16);
        assert_eq!(d192.karat3_in_m256i(), 48);
        assert_eq!(d192.padded_tm3_slice_m256i(), 48);

        let d256 = ToomDims::from_param_n_mult(Hqc5Params::PARAM_N_MULT);
        assert_eq!(d256.t_tm3r_3w_256, 78);
        assert_eq!(d256.t3w_256(), 32);
        assert_eq!(d256.karat3_in_m256i(), 96);
        assert_eq!(d256.padded_tm3_slice_m256i(), 96);
        assert_eq!(d256.w_buf_m256i(), 192);
    }
}
