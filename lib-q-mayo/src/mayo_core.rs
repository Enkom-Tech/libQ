//! MAYO_2 keygen / sign / verify core. Faithful port of the round-2
//! reference implementation (`MAYO-C`: `mayo.c`, `arithmetic.c`,
//! `generic/generic_arithmetic.h`, `generic/echelon_form.h`) with
//! little-endian nibble/limb semantics on every platform.
//!
//! Constant-time posture: no lookup tables, no secret-dependent branches or
//! indices in signing. The only signing branch is on the public
//! "system solvable" predicate of the retry loop (same declassification as
//! the reference implementation).

use crate::SigningError;
use crate::expand::shake256;
use crate::gf16::{
    ct_64_is_greater_than,
    ct_compare_8,
    ct_compare_64,
    inverse_f,
    mul_f,
    mul_fx8,
};
use crate::mvec::{
    m_vec_add,
    m_vec_copy,
    m_vec_mul_add,
    m_vec_multiply_bins,
};
use crate::params::*;

pub(crate) const P_LIMBS: usize = P1_LIMBS + P2_LIMBS;
pub(crate) const EPK_LIMBS: usize = P1_LIMBS + P2_LIMBS + P3_LIMBS;

// ---------------------------------------------------------------------------
// nibble encoding
// ---------------------------------------------------------------------------

/// Unpack `out.len()` GF(16) nibbles from packed bytes (low nibble first).
pub(crate) fn decode(m: &[u8], out: &mut [u8]) {
    let n = out.len();
    for i in 0..n / 2 {
        out[2 * i] = m[i] & 0xF;
        out[2 * i + 1] = m[i] >> 4;
    }
    if n % 2 == 1 {
        out[n - 1] = m[n / 2] & 0xF;
    }
}

/// Pack `m.len()` GF(16) nibbles into bytes (low nibble first).
pub(crate) fn encode(m: &[u8], out: &mut [u8]) {
    let n = m.len();
    for i in 0..n / 2 {
        out[i] = m[2 * i] | (m[2 * i + 1] << 4);
    }
    if n % 2 == 1 {
        out[n / 2] = m[n - 1];
    }
}

// ---------------------------------------------------------------------------
// wiping
// ---------------------------------------------------------------------------

#[cfg(feature = "zeroize")]
pub(crate) fn wipe_bytes(buf: &mut [u8]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

#[cfg(feature = "zeroize")]
pub(crate) fn wipe_limbs(buf: &mut [u64]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

#[cfg(not(feature = "zeroize"))]
pub(crate) fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(not(feature = "zeroize"))]
pub(crate) fn wipe_limbs(buf: &mut [u64]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// matrix kernels over m-vectors (port of generic_arithmetic.h)
// ---------------------------------------------------------------------------

const L: usize = M_VEC_LIMBS;

/// acc += bs_mat (bs_rows x bs_cols, optionally upper triangular) * mat.
fn mul_add_m_upper_triangular_mat_x_mat(
    bs_mat: &[u64],
    mat: &[u8],
    acc: &mut [u64],
    bs_rows: usize,
    bs_cols: usize,
    mat_cols: usize,
    triangular: bool,
) {
    let mut entry = 0;
    for r in 0..bs_rows {
        let start = if triangular { r } else { 0 };
        for c in start..bs_cols {
            for k in 0..mat_cols {
                m_vec_mul_add(
                    &bs_mat[L * entry..],
                    mat[c * mat_cols + k],
                    &mut acc[L * (r * mat_cols + k)..],
                );
            }
            entry += 1;
        }
    }
}

/// acc += bs_mat (bs_rows x bs_cols, optionally upper triangular) * mat^T.
fn mul_add_m_upper_triangular_mat_x_mat_trans(
    bs_mat: &[u64],
    mat: &[u8],
    acc: &mut [u64],
    bs_rows: usize,
    bs_cols: usize,
    mat_rows: usize,
    triangular: bool,
) {
    let mut entry = 0;
    for r in 0..bs_rows {
        let start = if triangular { r } else { 0 };
        for c in start..bs_cols {
            for k in 0..mat_rows {
                m_vec_mul_add(
                    &bs_mat[L * entry..],
                    mat[k * bs_mat_cols_stride(bs_cols) + c],
                    &mut acc[L * (r * mat_rows + k)..],
                );
            }
            entry += 1;
        }
    }
}

#[inline(always)]
fn bs_mat_cols_stride(bs_cols: usize) -> usize {
    bs_cols
}

/// acc += mat^T * bs_mat.
fn mul_add_mat_trans_x_m_mat(
    mat: &[u8],
    bs_mat: &[u64],
    acc: &mut [u64],
    mat_rows: usize,
    mat_cols: usize,
    bs_mat_cols: usize,
) {
    for r in 0..mat_cols {
        for c in 0..mat_rows {
            for k in 0..bs_mat_cols {
                m_vec_mul_add(
                    &bs_mat[L * (c * bs_mat_cols + k)..],
                    mat[c * mat_cols + r],
                    &mut acc[L * (r * bs_mat_cols + k)..],
                );
            }
        }
    }
}

/// acc += mat * bs_mat.
fn mul_add_mat_x_m_mat(
    mat: &[u8],
    bs_mat: &[u64],
    acc: &mut [u64],
    mat_rows: usize,
    mat_cols: usize,
    bs_mat_cols: usize,
) {
    for r in 0..mat_rows {
        for c in 0..mat_cols {
            for k in 0..bs_mat_cols {
                m_vec_mul_add(
                    &bs_mat[L * (c * bs_mat_cols + k)..],
                    mat[r * mat_cols + c],
                    &mut acc[L * (r * bs_mat_cols + k)..],
                );
            }
        }
    }
}

/// Copy the upper-triangular half of an o x o matrix of m-vectors, folding in
/// the transposed lower half (`Upper` in the spec).
fn m_upper(input: &[u64], out: &mut [u64], size: usize) {
    let mut stored = 0;
    for r in 0..size {
        for c in r..size {
            m_vec_copy(&input[L * (r * size + c)..], &mut out[L * stored..]);
            if r != c {
                let (a, b) = split_in_out(input, out, L * (c * size + r), L * stored);
                m_vec_add(a, b);
            }
            stored += 1;
        }
    }
}

#[inline(always)]
fn split_in_out<'a>(
    input: &'a [u64],
    out: &'a mut [u64],
    in_off: usize,
    out_off: usize,
) -> (&'a [u64], &'a mut [u64]) {
    (&input[in_off..], &mut out[out_off..])
}

/// L = (P1 + P1^T) * O + P2, accumulated into `acc` (which starts as P2).
fn p1p1t_times_o(p1: &[u64], o: &[u8], acc: &mut [u64]) {
    let mut entry = 0;
    for r in 0..V {
        for c in r..V {
            if c == r {
                entry += 1;
                continue;
            }
            for k in 0..O {
                m_vec_mul_add(&p1[L * entry..], o[c * O + k], &mut acc[L * (r * O + k)..]);
                m_vec_mul_add(&p1[L * entry..], o[r * O + k], &mut acc[L * (c * O + k)..]);
            }
            entry += 1;
        }
    }
}

/// P3 = O^T * (P1*O + P2); `p2` is overwritten with P1*O + P2 in the process.
fn compute_p3(p1: &[u64], p2: &mut [u64], o: &[u8], p3: &mut [u64]) {
    mul_add_m_upper_triangular_mat_x_mat(p1, o, p2, V, V, O, true);
    mul_add_mat_trans_x_m_mat(o, p2, p3, V, O, O);
}

/// M = Vdec * L and VPV = Vdec * P1 * Vdec^T (signing).
fn compute_m_and_vpv(vdec: &[u8], l_mat: &[u64], p1: &[u64], vl: &mut [u64], vp1v: &mut [u64]) {
    mul_add_mat_x_m_mat(vdec, l_mat, vl, K, V, O);

    let mut pv = [0u64; V * K * L];
    mul_add_m_upper_triangular_mat_x_mat_trans(p1, vdec, &mut pv, V, V, K, true);
    mul_add_mat_x_m_mat(vdec, &pv, vp1v, K, V, K);
    wipe_limbs(&mut pv);
}

// ---------------------------------------------------------------------------
// compute_rhs / compute_A (port of mayo.c)
// ---------------------------------------------------------------------------

#[inline(always)]
fn xor_byte(limbs: &mut [u64], byte_idx: usize, val: u8) {
    limbs[byte_idx / 8] ^= (val as u64) << ((byte_idx % 8) * 8);
}

#[inline(always)]
fn get_byte(limbs: &[u64], byte_idx: usize) -> u8 {
    (limbs[byte_idx / 8] >> ((byte_idx % 8) * 8)) as u8
}

/// y = t - sum_{i<=j} E^{...} * vPv[i][j], the right-hand side of the linear
/// system. `vpv` holds k*k m-vectors. (`M % 16 == 0` for MAYO_2, so no tail
/// masking is needed.)
fn compute_rhs(vpv: &[u64], t: &[u8], y: &mut [u8]) {
    let top_pos = ((M - 1) % 16) * 4;
    let mut temp = [0u64; L];
    for i in (0..K).rev() {
        for j in i..K {
            // multiply accumulator by z (shift up one nibble) ...
            let top = ((temp[L - 1] >> top_pos) & 0xF) as u8;
            temp[L - 1] <<= 4;
            for k in (0..L - 1).rev() {
                temp[k + 1] ^= temp[k] >> 60;
                temp[k] <<= 4;
            }
            // ... and reduce mod f(z)
            for (jj, &f) in F_TAIL.iter().enumerate() {
                let val = mul_f(top, f);
                if jj % 2 == 0 {
                    xor_byte(&mut temp, jj / 2, val);
                } else {
                    xor_byte(&mut temp, jj / 2, val << 4);
                }
            }
            // add vPv[i][j] (+ vPv[j][i] if off-diagonal)
            let mirror = (i != j) as u64;
            for k in 0..L {
                temp[k] ^=
                    vpv[(i * K + j) * L + k] ^ (mirror.wrapping_neg() & vpv[(j * K + i) * L + k]);
            }
        }
    }

    for i in (0..M).step_by(2) {
        let b = get_byte(&temp, i / 2);
        y[i] = t[i] ^ (b & 0xF);
        y[i + 1] = t[i + 1] ^ (b >> 4);
    }
    wipe_limbs(&mut temp);
}

fn transpose_16x16_nibbles(m: &mut [u64]) {
    const EVEN_NIBBLES: u64 = 0x0F0F_0F0F_0F0F_0F0F;
    const EVEN_BYTES: u64 = 0x00FF_00FF_00FF_00FF;
    const EVEN_2BYTES: u64 = 0x0000_FFFF_0000_FFFF;
    const EVEN_HALF: u64 = 0x0000_0000_FFFF_FFFF;

    for i in (0..16).step_by(2) {
        let t = ((m[i] >> 4) ^ m[i + 1]) & EVEN_NIBBLES;
        m[i] ^= t << 4;
        m[i + 1] ^= t;
    }
    for i in (0..16).step_by(4) {
        let t0 = ((m[i] >> 8) ^ m[i + 2]) & EVEN_BYTES;
        let t1 = ((m[i + 1] >> 8) ^ m[i + 3]) & EVEN_BYTES;
        m[i] ^= t0 << 8;
        m[i + 1] ^= t1 << 8;
        m[i + 2] ^= t0;
        m[i + 3] ^= t1;
    }
    for i in 0..4 {
        let t0 = ((m[i] >> 16) ^ m[i + 4]) & EVEN_2BYTES;
        let t1 = ((m[i + 8] >> 16) ^ m[i + 12]) & EVEN_2BYTES;
        m[i] ^= t0 << 16;
        m[i + 8] ^= t1 << 16;
        m[i + 4] ^= t0;
        m[i + 12] ^= t1;
    }
    for i in 0..8 {
        let t = ((m[i] >> 32) ^ m[i + 8]) & EVEN_HALF;
        m[i] ^= t << 32;
        m[i + 8] ^= t;
    }
}

const A_WIDTH: usize = (O * K).div_ceil(16) * 16;
const M_OVER_8: usize = M.div_ceil(8);

/// Build the m x (k*o+1) linear system matrix A from the M_i matrices
/// (`vtl` holds k*o m-vectors). Writes the unpacked byte matrix to `a_out`
/// (row-major, `A_COLS` columns; the last column is left untouched).
fn compute_a(vtl: &[u64], a_out: &mut [u8]) {
    let mut a = [0u64; A_WIDTH * M_OVER_8];

    let mut bits_to_shift = 0usize;
    let mut words_to_shift = 0usize;
    for i in 0..K {
        for j in (i..K).rev() {
            let mj = &vtl[j * L * O..];
            for c in 0..O {
                for k in 0..L {
                    a[O * i + c + (k + words_to_shift) * A_WIDTH] ^= mj[k + c * L] << bits_to_shift;
                    if bits_to_shift > 0 {
                        a[O * i + c + (k + words_to_shift + 1) * A_WIDTH] ^=
                            mj[k + c * L] >> (64 - bits_to_shift);
                    }
                }
            }
            if i != j {
                let mi = &vtl[i * L * O..];
                for c in 0..O {
                    for k in 0..L {
                        a[O * j + c + (k + words_to_shift) * A_WIDTH] ^=
                            mi[k + c * L] << bits_to_shift;
                        if bits_to_shift > 0 {
                            a[O * j + c + (k + words_to_shift + 1) * A_WIDTH] ^=
                                mi[k + c * L] >> (64 - bits_to_shift);
                        }
                    }
                }
            }
            bits_to_shift += 4;
            if bits_to_shift == 64 {
                words_to_shift += 1;
                bits_to_shift = 0;
            }
        }
    }

    let used_rows = (M + (K + 1) * K / 2).div_ceil(16);
    for c in (0..A_WIDTH * used_rows).step_by(16) {
        transpose_16x16_nibbles(&mut a[c..c + 16]);
    }

    let mut tab = [0u8; F_TAIL.len() * 4];
    for (i, &f) in F_TAIL.iter().enumerate() {
        tab[4 * i] = mul_f(f, 1);
        tab[4 * i + 1] = mul_f(f, 2);
        tab[4 * i + 2] = mul_f(f, 4);
        tab[4 * i + 3] = mul_f(f, 8);
    }

    const LOW_BIT_IN_NIBBLE: u64 = 0x1111_1111_1111_1111;
    for c in (0..A_WIDTH).step_by(16) {
        for r in M..M + (K + 1) * K / 2 {
            let pos = (r / 16) * A_WIDTH + c + (r % 16);
            let t0 = a[pos] & LOW_BIT_IN_NIBBLE;
            let t1 = (a[pos] >> 1) & LOW_BIT_IN_NIBBLE;
            let t2 = (a[pos] >> 2) & LOW_BIT_IN_NIBBLE;
            let t3 = (a[pos] >> 3) & LOW_BIT_IN_NIBBLE;
            for t in 0..F_TAIL.len() {
                let rr = r + t - M;
                a[(rr / 16) * A_WIDTH + c + (rr % 16)] ^= t0.wrapping_mul(tab[4 * t] as u64) ^
                    t1.wrapping_mul(tab[4 * t + 1] as u64) ^
                    t2.wrapping_mul(tab[4 * t + 2] as u64) ^
                    t3.wrapping_mul(tab[4 * t + 3] as u64);
            }
        }
    }

    for r in (0..M).step_by(16) {
        for c in (0..A_COLS - 1).step_by(16) {
            for i in 0..core::cmp::min(16, M - r) {
                let word = a[(r / 16) * A_WIDTH + c + i].to_le_bytes();
                let len = core::cmp::min(16, A_COLS - 1 - c);
                decode(
                    &word,
                    &mut a_out[(r + i) * A_COLS + c..(r + i) * A_COLS + c + len],
                );
            }
        }
    }
    wipe_limbs(&mut a);
}

// ---------------------------------------------------------------------------
// constant-time echelon form + sample_solution (port of echelon_form.h /
// arithmetic.c)
// ---------------------------------------------------------------------------

const ROW_LEN: usize = A_COLS.div_ceil(16);

#[inline(always)]
fn ef_extract(row: &[u64], index: usize) -> u8 {
    ((row[index / 16] >> ((index % 16) * 4)) & 0xF) as u8
}

fn ef_pack_row(input: &[u8], out: &mut [u64]) {
    for limb in out.iter_mut() {
        *limb = 0;
    }
    for (j, &nib) in input.iter().enumerate() {
        out[j / 16] |= ((nib as u64) & 0xF) << ((j % 16) * 4);
    }
}

fn ef_unpack_row(input: &[u64], out: &mut [u8]) {
    for (j, o) in out.iter_mut().enumerate() {
        *o = ef_extract(input, j);
    }
}

/// `acc += a * input` over ROW_LEN limbs (nibble-sliced row).
#[inline(always)]
fn row_mul_add(input: &[u64], a: u8, acc: &mut [u64]) {
    let input: &[u64; ROW_LEN] = input[..ROW_LEN].try_into().unwrap();
    let acc: &mut [u64; ROW_LEN] = (&mut acc[..ROW_LEN]).try_into().unwrap();
    let tab = crate::gf16::mul_table(a);
    const LSB: u64 = 0x1111_1111_1111_1111;
    for i in 0..ROW_LEN {
        acc[i] ^= ((input[i] & LSB) * ((tab & 0xFF) as u64)) ^
            (((input[i] >> 1) & LSB) * (((tab >> 8) & 0xF) as u64)) ^
            (((input[i] >> 2) & LSB) * (((tab >> 16) & 0xF) as u64)) ^
            (((input[i] >> 3) & LSB) * (((tab >> 24) & 0xF) as u64));
    }
}

/// Constant-time row echelon form of the m x A_COLS byte matrix `a`
/// (ones on the first nonzero entry of each row). The pivot row index is
/// secret; the pivot column is public.
fn echelon_form(a: &mut [u8]) {
    let nrows = M as i32;
    let ncols = A_COLS;

    let mut packed = [0u64; ROW_LEN * M];
    for i in 0..M {
        let mut row = [0u64; ROW_LEN];
        ef_pack_row(&a[i * ncols..i * ncols + ncols], &mut row);
        packed[i * ROW_LEN..(i + 1) * ROW_LEN].copy_from_slice(&row);
    }

    let mut pivot_row: i32 = 0;
    for pivot_col in 0..ncols as i32 {
        let lower = core::cmp::max(0, pivot_col + nrows - ncols as i32);
        let upper = core::cmp::min(nrows - 1, pivot_col);

        let mut prow = [0u64; ROW_LEN];
        let mut prow_scaled = [0u64; ROW_LEN];

        // gather a pivot row in constant time
        let mut pivot: u8 = 0;
        let mut pivot_is_zero: u64 = u64::MAX;
        let mut row = lower;
        while row <= core::cmp::min(nrows - 1, upper + 32) {
            let is_pivot_row = !ct_compare_64(row, pivot_row);
            let below_pivot_row = ct_64_is_greater_than(row, pivot_row);
            for j in 0..ROW_LEN {
                prow[j] ^= (is_pivot_row | (below_pivot_row & pivot_is_zero)) &
                    packed[row as usize * ROW_LEN + j];
            }
            pivot = ef_extract(&prow, pivot_col as usize);
            pivot_is_zero = !ct_compare_64(pivot as i32, 0);
            row += 1;
        }

        // scale pivot row by pivot^-1
        row_mul_add(&prow, inverse_f(pivot), &mut prow_scaled);

        // conditionally write the scaled pivot row back
        for row in lower..=upper {
            let do_copy = !ct_compare_64(row, pivot_row) & !pivot_is_zero;
            let do_not_copy = !do_copy;
            for (col, &scaled) in prow_scaled.iter().enumerate() {
                let idx = row as usize * ROW_LEN + col;
                packed[idx] = (do_not_copy & packed[idx]).wrapping_add(do_copy & scaled);
            }
        }

        // eliminate entries below the pivot (masked: `pivot_row` is secret)
        for row in lower..nrows {
            let below_pivot = (ct_64_is_greater_than(row, pivot_row) & 0xF) as u8;
            let elt = ef_extract(&packed[row as usize * ROW_LEN..], pivot_col as usize);
            row_mul_add(
                &prow_scaled,
                below_pivot & elt,
                &mut packed[row as usize * ROW_LEN..(row as usize + 1) * ROW_LEN],
            );
        }

        pivot_row += ((!pivot_is_zero) & 1) as i32;
        wipe_limbs(&mut prow);
        wipe_limbs(&mut prow_scaled);
    }

    let mut temp = [0u8; ROW_LEN * 16];
    for i in 0..M {
        ef_unpack_row(&packed[i * ROW_LEN..(i + 1) * ROW_LEN], &mut temp);
        a[i * ncols..(i + 1) * ncols].copy_from_slice(&temp[..ncols]);
    }
    wipe_bytes(&mut temp);
    wipe_limbs(&mut packed);
}

/// Sample a solution x to Ax = y, with `r` (length k*o+1, last byte zero)
/// used as randomness. Returns `false` if A is not full rank (restart).
///
/// `a` is the m x A_COLS byte matrix (clobbered); `x` must be k*o+1 bytes
/// (the back-substitution search window may touch one entry past k*o, as in
/// the oversized buffer of the reference implementation); the solution is
/// the first k*o entries.
fn sample_solution(a: &mut [u8], y: &[u8], r: &[u8], x: &mut [u8]) -> bool {
    let ko = K * O;
    x[..ko].copy_from_slice(&r[..ko]);

    // Ar (last column of A cleared first, r's implicit last entry is 0)
    let mut ar = [0u8; M];
    for i in 0..M {
        a[ko + i * A_COLS] = 0;
    }
    for (i, ari) in ar.iter_mut().enumerate() {
        let mut acc = 0u8;
        for j in 0..A_COLS {
            acc ^= mul_f(a[i * A_COLS + j], r[j]);
        }
        *ari = acc;
    }

    // move y - Ar to the last column
    for i in 0..M {
        a[ko + i * A_COLS] = y[i] ^ ar[i];
    }

    echelon_form(a);

    // full rank <=> last row (excluding the y entry) is nonzero
    let mut full_rank = 0u8;
    for i in 0..A_COLS - 1 {
        full_rank |= a[(M - 1) * A_COLS + i];
    }
    if full_rank == 0 {
        wipe_bytes(&mut ar);
        return false;
    }

    // back substitution in constant time: the column of the first nonzero
    // entry in each row is secret
    for row in (0..M).rev() {
        let mut finished: u8 = 0;
        let col_upper_bound = core::cmp::min(row + 32 / (M - row), ko);
        for col in row..=col_upper_bound {
            let correct_column = ct_compare_8(a[row * A_COLS + col], 0) & !finished;
            let u = correct_column & a[row * A_COLS + A_COLS - 1];
            x[col] ^= u;

            for i in (0..row).step_by(8) {
                let mut tmp: u64 = 0;
                for b in 0..8 {
                    tmp ^= (a[(i + b) * A_COLS + col] as u64) << (8 * b);
                }
                tmp = mul_fx8(u, tmp);
                for b in 0..8 {
                    a[(i + b) * A_COLS + A_COLS - 1] ^= ((tmp >> (8 * b)) & 0xF) as u8;
                }
            }
            finished |= correct_column;
        }
    }
    wipe_bytes(&mut ar);
    true
}

// ---------------------------------------------------------------------------
// key expansion
// ---------------------------------------------------------------------------

/// AES-128-CTR keystream directly into little-endian u64 limbs.
fn expand_p1_p2(seed_pk: &[u8; PK_SEED_BYTES], p: &mut [u64]) {
    debug_assert!(p.len() >= P_LIMBS);
    let mut bytes = [0u8; 16];
    // (P1_BYTES + P2_BYTES) is a multiple of 16 for MAYO_2
    let mut ctr: u128 = 0;
    use aes::cipher::{
        BlockCipherEncrypt,
        KeyInit,
    };
    use aes::{
        Aes128,
        Block,
    };
    let cipher = Aes128::new_from_slice(seed_pk).expect("16-byte key");
    for chunk in p[..P_LIMBS].chunks_mut(2) {
        let mut block = Block::from(ctr.to_be_bytes());
        cipher.encrypt_block(&mut block);
        bytes.copy_from_slice(&block);
        chunk[0] = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        chunk[1] = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        ctr = ctr.wrapping_add(1);
    }
}

/// Expanded secret key: P1 || L limbs and the decoded oil matrix O.
pub(crate) struct ExpandedSk {
    /// P1 (upper-triangular) followed by L = (P1+P1^T)O + P2.
    pub p: [u64; P_LIMBS],
    /// v x o oil matrix, one GF(16) element per byte.
    pub o: [u8; V * O],
}

impl ExpandedSk {
    fn zeroed() -> Self {
        Self {
            p: [0u64; P_LIMBS],
            o: [0u8; V * O],
        }
    }
}

impl Drop for ExpandedSk {
    fn drop(&mut self) {
        wipe_limbs(&mut self.p);
        wipe_bytes(&mut self.o);
    }
}

pub(crate) fn expand_sk(seed_sk: &[u8; SK_SEED_BYTES], sk: &mut ExpandedSk) {
    let mut s = [0u8; PK_SEED_BYTES + O_BYTES];
    shake256(&[seed_sk], &mut s);

    decode(&s[PK_SEED_BYTES..], &mut sk.o);

    let seed_pk: [u8; PK_SEED_BYTES] = s[..PK_SEED_BYTES].try_into().unwrap();
    expand_p1_p2(&seed_pk, &mut sk.p);

    // L = (P1 + P1^T)*O + P2 computed in place over P2
    let (p1, p2) = sk.p.split_at_mut(P1_LIMBS);
    p1p1t_times_o(p1, &sk.o, p2);

    wipe_bytes(&mut s);
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

/// CompactKeyGen: derive the compact keypair from `seed_sk`.
pub(crate) fn keypair_compact(seed_sk: &[u8; SK_SEED_BYTES], cpk: &mut [u8; CPK_BYTES]) {
    let mut s = [0u8; PK_SEED_BYTES + O_BYTES];
    shake256(&[seed_sk], &mut s);

    let mut o = [0u8; V * O];
    decode(&s[PK_SEED_BYTES..], &mut o);

    let seed_pk: [u8; PK_SEED_BYTES] = s[..PK_SEED_BYTES].try_into().unwrap();
    let mut p = [0u64; P_LIMBS];
    expand_p1_p2(&seed_pk, &mut p);

    let mut p3 = [0u64; O * O * L];
    {
        let (p1, p2) = p.split_at_mut(P1_LIMBS);
        compute_p3(p1, p2, &o, &mut p3);
    }

    cpk[..PK_SEED_BYTES].copy_from_slice(&seed_pk);

    let mut p3_upper = [0u64; P3_LIMBS];
    m_upper(&p3, &mut p3_upper, O);
    for (i, limb) in p3_upper.iter().enumerate() {
        cpk[PK_SEED_BYTES + i * 8..PK_SEED_BYTES + (i + 1) * 8]
            .copy_from_slice(&limb.to_le_bytes());
    }

    wipe_bytes(&mut s);
    wipe_bytes(&mut o);
    wipe_limbs(&mut p);
    wipe_limbs(&mut p3);
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

/// Produce a signature over `message` using `seed_sk` and 24 bytes of
/// randomness `r_bytes` (the spec's randomizer R; all-zero gives the
/// deterministic mode, still hedged by `seed_sk`).
pub(crate) fn sign_signature(
    seed_sk: &[u8; SK_SEED_BYTES],
    message: &[u8],
    randomizer: &[u8; SALT_BYTES],
    sig: &mut [u8; SIG_BYTES],
) -> Result<(), SigningError> {
    let mut sk = ExpandedSk::zeroed();
    expand_sk(seed_sk, &mut sk);

    // tmp = digest || salt/R || seed_sk || ctr
    let mut tmp = [0u8; DIGEST_BYTES + SALT_BYTES + SK_SEED_BYTES + 1];
    shake256(&[message], &mut tmp[..DIGEST_BYTES]);
    tmp[DIGEST_BYTES..DIGEST_BYTES + SALT_BYTES].copy_from_slice(randomizer);
    tmp[DIGEST_BYTES + SALT_BYTES..DIGEST_BYTES + SALT_BYTES + SK_SEED_BYTES]
        .copy_from_slice(seed_sk);

    let mut salt = [0u8; SALT_BYTES];
    shake256(
        &[&tmp[..DIGEST_BYTES + SALT_BYTES + SK_SEED_BYTES]],
        &mut salt,
    );

    // t = H(digest || salt)
    tmp[DIGEST_BYTES..DIGEST_BYTES + SALT_BYTES].copy_from_slice(&salt);
    let mut tenc = [0u8; M_BYTES];
    shake256(&[&tmp[..DIGEST_BYTES + SALT_BYTES]], &mut tenc);
    let mut t = [0u8; M];
    decode(&tenc, &mut t);

    let (p1, l_mat) = sk.p.split_at(P1_LIMBS);

    let mut v = [0u8; K * V_BYTES + R_BYTES];
    let mut vdec = [0u8; K * V];
    let mut mtmp = [0u64; K * O * L];
    let mut vpv = [0u64; K * K * L];
    let mut a = [0u8; M * A_COLS];
    let mut y = [0u8; M];
    let mut r = [0u8; K * O + 1];
    let mut x = [0u8; K * O + 1];
    let mut sol_found = false;

    for ctr in 0..=255u8 {
        tmp[DIGEST_BYTES + SALT_BYTES + SK_SEED_BYTES] = ctr;
        shake256(&[&tmp], &mut v);

        for i in 0..K {
            decode(
                &v[i * V_BYTES..(i + 1) * V_BYTES],
                &mut vdec[i * V..(i + 1) * V],
            );
        }

        mtmp.fill(0);
        vpv.fill(0);
        a.fill(0);
        compute_m_and_vpv(&vdec, l_mat, p1, &mut mtmp, &mut vpv);
        compute_rhs(&vpv, &t, &mut y);
        compute_a(&mtmp, &mut a);

        for i in 0..M {
            a[(1 + i) * A_COLS - 1] = 0;
        }

        r[K * O] = 0;
        decode(&v[K * V_BYTES..K * V_BYTES + R_BYTES], &mut r[..K * O]);

        // restart-or-not is the only public branch (as in the reference)
        if sample_solution(&mut a, &y, &r, &mut x) {
            sol_found = true;
            break;
        }
    }

    let mut s = [0u8; K * N];
    if sol_found {
        let mut ox = [0u8; V];
        for i in 0..K {
            let vi = &vdec[i * V..(i + 1) * V];
            // Ox = O * x_i (O is v x o)
            for (row, oxr) in ox.iter_mut().enumerate() {
                let mut acc = 0u8;
                for col in 0..O {
                    acc ^= mul_f(sk.o[row * O + col], x[i * O + col]);
                }
                *oxr = acc;
            }
            for j in 0..V {
                s[i * N + j] = vi[j] ^ ox[j];
            }
            s[i * N + V..(i + 1) * N].copy_from_slice(&x[i * O..(i + 1) * O]);
        }
        encode(&s, &mut sig[..(K * N).div_ceil(2)]);
        sig[SIG_BYTES - SALT_BYTES..].copy_from_slice(&salt);
        wipe_bytes(&mut ox);
    }

    wipe_bytes(&mut v);
    wipe_bytes(&mut vdec);
    wipe_limbs(&mut mtmp);
    wipe_limbs(&mut vpv);
    wipe_bytes(&mut a);
    wipe_bytes(&mut y);
    wipe_bytes(&mut r);
    wipe_bytes(&mut x);
    wipe_bytes(&mut s);
    wipe_bytes(&mut tmp);

    if sol_found {
        Ok(())
    } else {
        Err(SigningError::RetryLimitExceeded)
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// P*S^T then S*(P*S^T), stack-efficient variant
/// (`mayo_generic_m_calculate_PS_SPS`). `sps` receives k*k m-vectors.
fn calculate_ps_sps(p1: &[u64], p2: &[u64], p3: &[u64], s: &[u8], sps: &mut [u64]) {
    let mut ps = [0u64; (N + K) * L];
    let mut accumulator = [0u64; 16 * L * N];

    for col in 0..K {
        accumulator.fill(0);
        let mut p1_used = 0;
        for row in 0..V {
            for j in row..V {
                m_vec_add(
                    &p1[p1_used * L..],
                    &mut accumulator[(row * 16 + s[col * N + j] as usize) * L..],
                );
                p1_used += 1;
            }
            for j in 0..O {
                m_vec_add(
                    &p2[(row * O + j) * L..],
                    &mut accumulator[(row * 16 + s[col * N + j + V] as usize) * L..],
                );
            }
        }

        let mut p3_used = 0;
        for row in V..N {
            for j in row..N {
                m_vec_add(
                    &p3[p3_used * L..],
                    &mut accumulator[(row * 16 + s[col * N + j] as usize) * L..],
                );
                p3_used += 1;
            }
        }

        for row in 0..N {
            let mut out = [0u64; L];
            m_vec_multiply_bins(
                &mut accumulator[row * 16 * L..(row * 16 + 16) * L],
                &mut out,
            );
            m_vec_copy(&out, &mut ps[(row + col) * L..]);
        }

        for row in 0..K {
            let mut bins = [0u64; 16 * L];
            for j in 0..N {
                m_vec_add(
                    &ps[(j + col) * L..],
                    &mut bins[s[row * N + j] as usize * L..],
                );
            }
            let mut out = [0u64; L];
            m_vec_multiply_bins(&mut bins, &mut out);
            m_vec_copy(&out, &mut sps[(row * K + col) * L..]);
        }
    }
}

/// Evaluate the public map at `s` and compare against `t`.
pub(crate) fn verify(cpk: &[u8; CPK_BYTES], message: &[u8], sig: &[u8; SIG_BYTES]) -> bool {
    // expand pk
    let mut pk = [0u64; EPK_LIMBS];
    let seed_pk: [u8; PK_SEED_BYTES] = cpk[..PK_SEED_BYTES].try_into().unwrap();
    expand_p1_p2(&seed_pk, &mut pk);
    for i in 0..P3_LIMBS {
        pk[P_LIMBS + i] = u64::from_le_bytes(
            cpk[PK_SEED_BYTES + i * 8..PK_SEED_BYTES + (i + 1) * 8]
                .try_into()
                .unwrap(),
        );
    }
    let (p1, rest) = pk.split_at(P1_LIMBS);
    let (p2, p3) = rest.split_at(P2_LIMBS);

    // t = H(H(m) || salt)
    let mut tmp = [0u8; DIGEST_BYTES + SALT_BYTES];
    shake256(&[message], &mut tmp[..DIGEST_BYTES]);
    tmp[DIGEST_BYTES..].copy_from_slice(&sig[SIG_BYTES - SALT_BYTES..]);
    let mut tenc = [0u8; M_BYTES];
    shake256(&[&tmp], &mut tenc);
    let mut t = [0u8; M];
    decode(&tenc, &mut t);

    // decode s and evaluate P
    let mut s = [0u8; K * N];
    decode(&sig[..(K * N).div_ceil(2)], &mut s);

    let mut sps = [0u64; K * K * L];
    calculate_ps_sps(p1, p2, p3, &s, &mut sps);

    let zero = [0u8; M];
    let mut y = [0u8; M];
    compute_rhs(&sps, &zero, &mut y);

    y == t
}
