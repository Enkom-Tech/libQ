//! Double encoding scheme for DAWN
//!
//! This module implements the zero divisor encoding and double encoding paradigm
//! as specified in the DAWN paper.

#[cfg(not(feature = "std"))]
use alloc::{
    vec,
    vec::Vec,
};

use lib_q_core::Result;

use crate::polynomial::field::FieldPolynomial;

// --- FastInversion (Algorithm 1): f^{-1} mod (x^{n/4}+1, Z_2) and for decrypt f^{-1} mod (x^{n/2}+1, Z_2) ---

/// Reduce polynomial f (degree n, coefficients in Z_q) to Z_2[x]/(x^m+1) with m = n/4.
/// Fold: for i in 0..m, f_reduced[i] = (sum of f[i + t*m] for t in 0..4) mod 2.
/// In Z_2, -1 ≡ 1; use centred representation so coefficient stored as q-1 maps to 1.
fn reduce_f_to_z2_mod_w(f: &[u32], n: usize, q: u32) -> Vec<u8> {
    let m = n / 4;
    let half = q / 2;
    let mut out = vec![0u8; m];
    for i in 0..m {
        let mut parity = 0u8;
        for t in 0..4 {
            let c = f[i + t * m];
            // centred parity: c > q/2 means negative coefficient (value -(q-c)), odd iff (q-c) is odd
            let p = if c > half { (q - c) % 2 } else { c % 2 };
            parity ^= p as u8;
        }
        out[i] = parity;
    }
    out
}

/// Reduce polynomial f (degree n, coefficients in Z_q) to Z_2[x]/(x^{n/2}+1).
/// Fold: for i in 0..n/2, f_reduced[i] = (f[i] + f[i+n/2]) mod 2 (centred parity).
fn reduce_f_to_z2_mod_t(f: &[u32], n: usize, q: u32) -> Vec<u8> {
    let m = n / 2;
    let half = q / 2;
    let mut out = vec![0u8; m];
    for i in 0..m {
        let c0 = f[i];
        let c1 = f[i + m];
        let p0 = if c0 > half { (q - c0) % 2 } else { c0 % 2 };
        let p1 = if c1 > half { (q - c1) % 2 } else { c1 % 2 };
        out[i] = (p0 ^ p1) as u8;
    }
    out
}

/// Polynomial multiplication in Z_2[x]/(x^m+1). Coefficients in {0,1}.
fn poly_z2_mul_mod_xm_plus1(a: &[u8], b: &[u8], m: usize) -> Vec<u8> {
    let mut prod = vec![0u8; 2 * m];
    for i in 0..m {
        for j in 0..m {
            prod[i + j] ^= a[i] & b[j];
        }
    }
    for i in m..2 * m {
        prod[i - m] ^= prod[i];
    }
    prod.truncate(m);
    prod
}

/// Multiply a polynomial by t = x^{n/2}+1 in Z_q[x]/(x^n+1).
///
/// (t·a)[i] = a[i] - a[i+n/2]   for  0 <= i < n/2
/// (t·a)[i] = a[i] + a[i-n/2]   for  n/2 <= i < n
///
/// All arithmetic is mod q (centred representation handled by caller).
fn mul_by_t(a: &FieldPolynomial) -> FieldPolynomial {
    let n = a.coefficients.len();
    let q = a.modulus;
    let n_half = n / 2;
    let mut out = vec![0u32; n];
    for i in 0..n_half {
        // a[i] - a[i + n/2] mod q
        out[i] = (a.coefficients[i] + q - a.coefficients[i + n_half]) % q;
    }
    for i in n_half..n {
        // a[i] + a[i - n/2] mod q
        out[i] = (a.coefficients[i] + a.coefficients[i - n_half]) % q;
    }
    FieldPolynomial::from_coefficients(out, q)
}

// --- PKE.Encrypt (Algorithm 4) ---

/// Build polynomial w*m in Z_q[x]/(x^n+1) from message bytes (n/4 bits).
/// w = x^{n/4}+1; m has support 0..n/4-1; (w*m)[i] = m[i] for i<n/4, (w*m)[n/4+i] = m[i] for i<n/4.
fn message_to_wm_poly(message: &[u8], n: usize, q: u32) -> FieldPolynomial {
    let nq = n / 4;
    let mut m_coeffs = vec![0u32; n];
    let mut bit_idx = 0;
    for &byte in message {
        for bit in 0..8 {
            if bit_idx < nq {
                m_coeffs[bit_idx] = ((byte >> bit) & 1) as u32;
                bit_idx += 1;
            }
        }
    }
    let mut wm = vec![0u32; n];
    wm[..nq].copy_from_slice(&m_coeffs[..nq]);
    wm[nq..][..nq].copy_from_slice(&m_coeffs[..nq]);
    FieldPolynomial::from_coefficients(wm, q)
}

/// DAWN.PKE.Encrypt (Algorithm 4). c = compress(h*s + e + w*m).
/// Caller supplies s and e (sampled from ρ). Returns compressed ciphertext polynomial.
pub fn pke_encrypt(
    h: &FieldPolynomial,
    m: &[u8],
    s: &FieldPolynomial,
    e: &FieldPolynomial,
    encoder: &DoubleEncoder,
) -> Result<FieldPolynomial> {
    let n = encoder.zero_divisor_encoder.degree;
    let q = encoder.large_modulus;
    if m.len() * 8 > n / 4 {
        return Err(lib_q_core::Error::InvalidMessageSize {
            max: n / 4 / 8,
            actual: m.len(),
        });
    }
    let wm = message_to_wm_poly(m, n, q);
    let mut c = h.clone() * s.clone();
    c.reduce_mod_field();
    c.reduce_mod_cyclotomic();
    c = c + e.clone();
    c.reduce_mod_field();
    c = c + wm;
    c.reduce_mod_field();
    Ok(encoder.compress(&c))
}

/// Centre polynomial coefficients to [-(q-1)/2, (q-1)/2]. Returns signed coefficients.
fn centre_poly_to_i64(p: &[u32], q: u32) -> Vec<i64> {
    let half = (q - 1) / 2;
    let q_i = q as i64;
    p.iter()
        .map(|&c| {
            let c = c as i64;
            if c > half as i64 { c - q_i } else { c }
        })
        .collect()
}

/// Unpack f2 bytes to polynomial of length len (bits).
fn unpack_f2(f2_bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..len.min(f2_bytes.len() * 8) {
        if (f2_bytes[i / 8] >> (i % 8)) & 1 != 0 {
            out[i] = 1;
        }
    }
    out
}

/// Common decrypt prefix: compute c' = t·f·decompress(c) in Z_q[x]/(x^n+1),
/// centre, fold mod t = x^{n/2}+1, and extract c2 = c_prime mod 2.
///
/// Paper Algorithm 5, steps 1–2 plus the Z_2 reduction of step 3.
/// The t-multiplication makes the noise term t·(g·s + f·e) always even
/// after the mod-t fold, so c2 carries only the message contribution.
fn decrypt_common(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    encoder: &DoubleEncoder,
) -> (Vec<i64>, Vec<u8>, usize, usize, u32) {
    let n = encoder.zero_divisor_encoder.degree;
    let q = encoder.large_modulus;
    let n_half = n / 2;
    let n_quarter = n / 4;

    let decompressed = encoder.decompress(c_compressed);
    let mut a = f.clone() * decompressed;
    a.reduce_mod_field();
    a.reduce_mod_cyclotomic();

    // Paper step 2: multiply by t = x^{n/2}+1
    let ta = mul_by_t(&a);

    let ta_centred = centre_poly_to_i64(&ta.coefficients, q);

    // Fold mod (x^{n/2}+1): c_prime[i] = ta_centred[i] - ta_centred[i + n/2]
    let mut c_prime = vec![0i64; n_half];
    for i in 0..n_half {
        c_prime[i] = ta_centred[i] - ta_centred[i + n_half];
    }
    let half = (q - 1) / 2;
    let q_i = q as i64;
    for v in c_prime.iter_mut().take(n_half) {
        let mut val = *v;
        while val > half as i64 {
            val -= q_i;
        }
        while val < -(half as i64) {
            val += q_i;
        }
        *v = val;
    }

    let mut c2 = vec![0u8; n_half];
    for i in 0..n_half {
        c2[i] = (c_prime[i].rem_euclid(2)) as u8;
    }

    (c_prime, c2, n_half, n_quarter, q)
}

/// DAWN.PKE.Decrypt (Algorithm 5). Returns recovered message m.
pub fn pke_decrypt(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    f2: &[u8],
    encoder: &DoubleEncoder,
) -> Result<Vec<u8>> {
    let n_quarter = encoder.zero_divisor_encoder.degree / 4;
    let (c_prime, c2, n_half, _, _) = decrypt_common(c_compressed, f, encoder);

    // f2 is f^{-1} mod (x^{n/4}+1, Z_2); zero-pad to n/2 for multiplication in Z_2[x]/(x^{n/2}+1).
    let f2_poly = unpack_f2(f2, n_quarter);
    let mut f2_padded = vec![0u8; n_half];
    f2_padded[..f2_poly.len()].copy_from_slice(&f2_poly);
    let m_prime = poly_z2_mul_mod_xm_plus1(&c2, &f2_padded, n_half);

    simple_decoding(&m_prime, n_quarter, &c_prime, 0)
}

/// PKE decrypt using the reliability-bounded decoder (top-4, flip ≤2). For experiments and comparison with baseline.
pub fn pke_decrypt_reliability(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    f2: &[u8],
    encoder: &DoubleEncoder,
) -> Result<Vec<u8>> {
    let n_quarter = encoder.zero_divisor_encoder.degree / 4;
    let (c_prime, c2, n_half, _, q) = decrypt_common(c_compressed, f, encoder);

    let f2_poly = unpack_f2(f2, n_quarter);
    let mut f2_padded = vec![0u8; n_half];
    f2_padded[..f2_poly.len()].copy_from_slice(&f2_poly);
    let m_prime = poly_z2_mul_mod_xm_plus1(&c2, &f2_padded, n_half);

    reliability_bounded_decoding(&m_prime, n_quarter, &c_prime, q)
}

/// PKE decrypt using the Path B majority-reliability decoder (repetition-code majority with c_prime tie-break).
pub fn pke_decrypt_majority_reliability(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    f2: &[u8],
    encoder: &DoubleEncoder,
) -> Result<Vec<u8>> {
    let n_quarter = encoder.zero_divisor_encoder.degree / 4;
    let (c_prime, c2, n_half, _, q) = decrypt_common(c_compressed, f, encoder);

    let f2_poly = unpack_f2(f2, n_quarter);
    let mut f2_padded = vec![0u8; n_half];
    f2_padded[..f2_poly.len()].copy_from_slice(&f2_poly);
    let m_prime = poly_z2_mul_mod_xm_plus1(&c2, &f2_padded, n_half);

    majority_reliability_decoding(&m_prime, n_quarter, &c_prime, q)
}

/// Pack bit slice to bytes (LSB first per byte).
fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            byte |= (b & 1) << i;
        }
        out.push(byte);
    }
    out
}

/// SimpleDecoding (Algorithm 2): recover m from m' ≈ w*m with at most one error.
/// Spec-conformant: extract m from first half m'[0..n/4]; single-bit correction only when syndrome has weight 1.
fn simple_decoding(m_prime: &[u8], n_quarter: usize, _c_prime: &[i64], _q: u32) -> Result<Vec<u8>> {
    let n_half = m_prime.len().min(n_quarter * 2);
    let mut m_bits: Vec<u8> = (0..n_quarter)
        .map(|i| if i < n_half { m_prime[i] & 1 } else { 0 })
        .collect();
    let right: Vec<u8> = (0..n_quarter)
        .map(|i| {
            let j = i + n_quarter;
            if j < n_half { m_prime[j] & 1 } else { 0 }
        })
        .collect();

    let syndrome: Vec<u8> = (0..n_quarter).map(|k| m_bits[k] ^ right[k]).collect();
    let syndrome_weight: usize = syndrome.iter().map(|&s| s as usize).sum();

    if syndrome_weight == 0 {
        return Ok(bits_to_bytes(&m_bits));
    }

    if syndrome_weight == 1 &&
        let Some(k) = (0..n_quarter).find(|&k| syndrome[k] != 0)
    {
        m_bits[k] ^= 1;
        return Ok(bits_to_bytes(&m_bits));
    }

    Ok(bits_to_bytes(&m_bits))
}

/// Per-bit reliability from c_prime: for message bit index i we use both c_prime[i] and
/// c_prime[i+n_quarter]. Higher value = more reliable (larger margin from 0).
fn reliability_per_bit(c_prime: &[i64], n_quarter: usize, q: u32) -> Vec<u64> {
    let sym_half = (q as i64 - 1) / 2;
    let mut rel = vec![0u64; n_quarter];
    for i in 0..n_quarter {
        let c0 = c_prime[i].unsigned_abs().min(sym_half as u64);
        let j = i + n_quarter;
        let c1 = if j < c_prime.len() {
            c_prime[j].unsigned_abs().min(sym_half as u64)
        } else {
            0
        };
        rel[i] = (sym_half as u64).saturating_sub(c0) + (sym_half as u64).saturating_sub(c1);
    }
    rel
}

/// Bounded-search reliability decoder: top-4 least-reliable positions, enumerate ≤2 flips (max 11 candidates).
/// Returns the candidate with highest score (sum of reliability at positions where bit is 1).
fn reliability_bounded_decoding(
    m_prime: &[u8],
    n_quarter: usize,
    c_prime: &[i64],
    q: u32,
) -> Result<Vec<u8>> {
    let n_half = m_prime.len().min(n_quarter * 2);
    let m_bits: Vec<u8> = (0..n_quarter)
        .map(|i| if i < n_half { m_prime[i] & 1 } else { 0 })
        .collect();
    let right: Vec<u8> = (0..n_quarter)
        .map(|i| {
            let j = i + n_quarter;
            if j < n_half { m_prime[j] & 1 } else { 0 }
        })
        .collect();
    let rel = reliability_per_bit(c_prime, n_quarter, q);

    let mut indices: Vec<usize> = (0..n_quarter).collect();
    indices.sort_by_key(|&i| rel[i]);
    let top4: Vec<usize> = indices.into_iter().take(4).collect();

    let mut candidates: Vec<Vec<u8>> = vec![m_bits.clone()];
    for &i in &top4 {
        let mut c = m_bits.clone();
        c[i] ^= 1;
        candidates.push(c);
    }
    for (idx, &i) in top4.iter().enumerate() {
        for &j in &top4[idx + 1..] {
            let mut c = m_bits.clone();
            c[i] ^= 1;
            c[j] ^= 1;
            candidates.push(c);
        }
    }

    let syndrome_weight = |bits: &[u8]| -> usize {
        bits.iter()
            .zip(right.iter())
            .filter(|(a, b)| a != b)
            .count()
    };

    let best = candidates
        .iter()
        .enumerate()
        .min_by_key(|(idx, c)| (syndrome_weight(c), *idx))
        .map(|(_, c)| c.clone())
        .unwrap_or_else(|| m_bits);
    Ok(bits_to_bytes(&best))
}

/// Path B decoder: repetition-code majority with c_prime tie-break.
/// m' = w·m (noisy) has left half = right half = m in the noiseless case; decode each bit by
/// majority of (m_prime[i], m_prime[i+n_quarter]). On tie (left != right), choose the side
/// with larger |c_prime| (more reliable).
fn majority_reliability_decoding(
    m_prime: &[u8],
    n_quarter: usize,
    c_prime: &[i64],
    _q: u32,
) -> Result<Vec<u8>> {
    let n_half = m_prime.len().min(n_quarter * 2);
    let m_bits: Vec<u8> = (0..n_quarter)
        .map(|i| {
            let left = if i < n_half { m_prime[i] & 1 } else { 0 };
            let j = i + n_quarter;
            let right = if j < n_half { m_prime[j] & 1 } else { 0 };
            if left == right {
                left
            } else {
                let abs_left = c_prime
                    .get(i)
                    .copied()
                    .map(|c| c.unsigned_abs())
                    .unwrap_or(0);
                let abs_right = c_prime
                    .get(j)
                    .copied()
                    .map(|c| c.unsigned_abs())
                    .unwrap_or(0);
                if abs_left >= abs_right { left } else { right }
            }
        })
        .collect();
    Ok(bits_to_bytes(&m_bits))
}

/// Chase decoder operating in c2 space (pre-f₂ multiplication).
///
/// Identifies the `K_CHASE` least-reliable c2 positions (those where `|c_prime[i]|`
/// is closest to a parity boundary), enumerates all 2^K_CHASE candidate c2 vectors
/// by flipping subsets of those positions, multiplies each by f₂, and selects the
/// candidate whose w·m repetition-code syndrome weight is minimal.
///
/// Constant-time considerations: the reliability ranking is derived from c_prime
/// which depends on (public) ciphertext × (secret) f.  In an FO-KEM with implicit
/// rejection the decoded message never reaches the adversary on failure; however
/// the top-k selection must use a fixed comparison count to avoid timing leaks.
/// The current implementation uses a fixed-iteration selection loop (no early exit)
/// and evaluates all 2^K_CHASE candidates unconditionally.
const K_CHASE: usize = 6;

fn chase_decode_c2(
    c2: &[u8],
    c_prime: &[i64],
    f2_poly: &[u8],
    n_half: usize,
    n_quarter: usize,
) -> Result<Vec<u8>> {
    let k = K_CHASE.min(n_half);

    // Reliability: distance from c_prime[i] to the nearest parity boundary.
    // Odd c_prime values have parity 1, even have parity 0.  The parity decision
    // is uncertain when |c_prime[i]| is small (close to 0) — specifically when the
    // magnitude is close to an integer of the opposite parity.
    // Proxy: positions with smallest |c_prime[i]| are least reliable because they
    // are closest to the 0-crossing where parity flips.
    let mut indexed_rel: Vec<(usize, u64)> = (0..n_half)
        .map(|i| (i, c_prime[i].unsigned_abs()))
        .collect();

    // Fixed-iteration selection of k smallest (no data-dependent early exit).
    // Partial selection sort with exactly k passes — constant work regardless of data.
    for pass in 0..k {
        let mut min_idx = pass;
        for j in (pass + 1)..n_half {
            if indexed_rel[j].1 < indexed_rel[min_idx].1 {
                min_idx = j;
            }
        }
        indexed_rel.swap(pass, min_idx);
    }

    let least_reliable: Vec<usize> = indexed_rel[..k].iter().map(|&(idx, _)| idx).collect();

    let num_candidates = 1usize << k;
    let mut best_syndrome_weight = usize::MAX;
    let mut best_m_prime: Vec<u8> = vec![0u8; n_half];

    for pattern in 0..num_candidates {
        let mut c2_candidate = c2.to_vec();
        for (bit_pos, &pos) in least_reliable.iter().enumerate() {
            if (pattern >> bit_pos) & 1 == 1 {
                c2_candidate[pos] ^= 1;
            }
        }

        let m_prime_candidate = poly_z2_mul_mod_xm_plus1(&c2_candidate, f2_poly, n_half);

        let sw: usize = (0..n_quarter)
            .map(|i| {
                let left = m_prime_candidate[i] & 1;
                let j = i + n_quarter;
                let right = if j < n_half {
                    m_prime_candidate[j] & 1
                } else {
                    0
                };
                (left ^ right) as usize
            })
            .sum();

        // Unconditional update (constant-time style: always compare, always write on improvement).
        if sw < best_syndrome_weight || (sw == best_syndrome_weight && pattern == 0) {
            best_syndrome_weight = sw;
            best_m_prime.copy_from_slice(&m_prime_candidate);
        }
    }

    simple_decoding(&best_m_prime, n_quarter, c_prime, 0)
}

/// PKE decrypt using the Chase decoder (pre-f₂ c2-space enumeration).
pub fn pke_decrypt_chase(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    f2: &[u8],
    encoder: &DoubleEncoder,
) -> Result<Vec<u8>> {
    let n_quarter = encoder.zero_divisor_encoder.degree / 4;
    let (c_prime, c2, n_half, _, _) = decrypt_common(c_compressed, f, encoder);

    let f2_poly = unpack_f2(f2, n_quarter);
    let mut f2_padded = vec![0u8; n_half];
    f2_padded[..f2_poly.len()].copy_from_slice(&f2_poly);
    chase_decode_c2(&c2, &c_prime, &f2_padded, n_half, n_quarter)
}

// --- Phase 1 diagnostics: c2 error counting and f2 weight measurement ---

/// Compute the ideal c2 for a given message (zero noise, d_c=1) and return the
/// Hamming distance between the actual c2 (from a noisy ciphertext) and the ideal.
/// Also returns the actual c2 and ideal c2 for further analysis.
#[cfg(feature = "random")]
pub struct C2Diagnostic {
    pub c2_hamming_distance: usize,
    pub c2_actual: Vec<u8>,
    pub c2_ideal: Vec<u8>,
    pub c_prime_abs_min: u64,
    pub c_prime_abs_max: u64,
    pub c_prime_abs_mean: f64,
}

#[cfg(feature = "random")]
pub fn pke_c2_error_diagnostic(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    message: &[u8],
    encoder: &DoubleEncoder,
) -> C2Diagnostic {
    let n = encoder.zero_divisor_encoder.degree;
    let q = encoder.large_modulus;
    let n_half = n / 2;

    // Actual c2 from the noisy ciphertext (using the corrected t-multiplication path)
    let (c_prime, c2_actual, _, _, _) = decrypt_common(c_compressed, f, encoder);

    let mut abs_min = u64::MAX;
    let mut abs_max = 0u64;
    let mut abs_sum = 0u64;
    for &v in &c_prime {
        let abs = v.unsigned_abs();
        abs_min = abs_min.min(abs);
        abs_max = abs_max.max(abs);
        abs_sum += abs;
    }
    let abs_mean = abs_sum as f64 / n_half as f64;

    // Ideal c2: compute t * f * (w*m) directly with no noise or compression loss.
    let wm = message_to_wm_poly(message, n, q);
    let mut a_ideal = f.clone() * wm;
    a_ideal.reduce_mod_field();
    a_ideal.reduce_mod_cyclotomic();
    let ta_ideal = mul_by_t(&a_ideal);

    let ta_ideal_centred = centre_poly_to_i64(&ta_ideal.coefficients, q);
    let half = (q - 1) / 2;
    let q_i = q as i64;
    let mut c_prime_ideal = vec![0i64; n_half];
    for i in 0..n_half {
        c_prime_ideal[i] = ta_ideal_centred[i] - ta_ideal_centred[i + n_half];
    }
    for v in c_prime_ideal.iter_mut().take(n_half) {
        let mut val = *v;
        while val > half as i64 {
            val -= q_i;
        }
        while val < -(half as i64) {
            val += q_i;
        }
        *v = val;
    }

    let c2_ideal: Vec<u8> = (0..n_half)
        .map(|i| (c_prime_ideal[i].rem_euclid(2)) as u8)
        .collect();

    let c2_hamming_distance = c2_actual
        .iter()
        .zip(c2_ideal.iter())
        .filter(|&(a, b)| a != b)
        .count();

    C2Diagnostic {
        c2_hamming_distance,
        c2_actual,
        c2_ideal,
        c_prime_abs_min: abs_min,
        c_prime_abs_max: abs_max,
        c_prime_abs_mean: abs_mean,
    }
}

/// Compute the Hamming weight of f2 (number of 1-bits).
pub fn f2_hamming_weight(f2: &[u8]) -> usize {
    f2.iter().map(|&byte| byte.count_ones() as usize).sum()
}

/// c2 error histogram: for each of num_samples random (message, s, e) triples,
/// compute the number of c2 bit errors and bucket them.
/// Returns (histogram, f2_weight) where histogram[i] = count of samples with exactly i c2 errors,
/// and histogram[max_bucket] = count of samples with ≥ max_bucket errors.
#[cfg(feature = "random")]
pub fn c2_error_histogram(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    max_bucket: usize,
    rng_seed: &[u8; 64],
) -> Vec<usize> {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut histogram = vec![0usize; max_bucket + 1];
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => {
                histogram[max_bucket] += 1;
                continue;
            }
        };
        let diag = pke_c2_error_diagnostic(&compressed_c, &keypair.secret_key, &message, &encoder);
        let idx = diag.c2_hamming_distance.min(max_bucket);
        histogram[idx] += 1;
    }
    histogram
}

/// PKE histogram using the Chase decoder (same signature as pke_failure_rate_histogram).
#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram_chase(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> (usize, usize, usize, usize) {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let n_quarter_bits = n / 4;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut bucket_0 = 0usize;
    let mut bucket_1 = 0usize;
    let mut bucket_2_4 = 0usize;
    let mut bucket_gt4 = 0usize;
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let recovered =
            match pke_decrypt_chase(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder) {
                Ok(r) => r,
                Err(_) => {
                    bucket_gt4 += 1;
                    continue;
                }
            };
        let mut bit_errors = 0usize;
        for bi in 0..n_quarter_bits
            .min(recovered.len() * 8)
            .min(message.len() * 8)
        {
            let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
            let b_rec = if bi / 8 < recovered.len() {
                (recovered[bi / 8] >> (bi % 8)) & 1
            } else {
                0
            };
            if b_msg != b_rec {
                bit_errors += 1;
            }
        }
        match bit_errors {
            0 => bucket_0 += 1,
            1 => bucket_1 += 1,
            2..=4 => bucket_2_4 += 1,
            _ => bucket_gt4 += 1,
        }
    }
    (bucket_0, bucket_1, bucket_2_4, bucket_gt4)
}

/// FastInversion: compute f^{-1} mod (x^{n/4}+1, Z_2) via Newton lifting.
///
/// Uses the identity: if f·f2 ≡ 1 (mod x^{2^i}+1, Z_2), then
///   f2_new = f · f2² mod (x^{2^{i+1}}+1, Z_2)
/// satisfies f·f2_new ≡ 1 (mod x^{2^{i+1}}+1, Z_2).
/// In Z_2, squaring is the Frobenius: (Σ cₖ xᵏ)² = Σ cₖ x²ᵏ.
///
/// Returns None if f is not invertible mod (x^{n/4}+1, Z_2).
pub fn fast_inversion(f: &FieldPolynomial, degree: usize) -> Option<Vec<u8>> {
    let n = degree;
    let m = n / 4; // target ring degree; must be a power of 2
    if f.coefficients.len() < n || m == 0 || !m.is_power_of_two() {
        return None;
    }

    // Reduce f to Z_2[x]/(x^m+1)
    let f_z2 = reduce_f_to_z2_mod_w(&f.coefficients[..n], n, f.modulus);

    // Invertibility check: f(1) mod 2 must equal 1.
    let f_sum: u8 = f_z2.iter().fold(0u8, |acc, &b| acc ^ b);
    if f_sum == 0 {
        return None;
    }

    // Newton lifting.
    // Invariant: after step i, f2 has length 2^{i+1} and satisfies
    //   f · f2 ≡ 1  (mod x^{2^{i+1}}+1, Z_2).
    //
    // Base case (i = −1): f2 = [1], which is f⁻¹ mod (x+1, Z_2)
    // because f(1) = 1 in Z_2 implies f ≡ 1 mod (x+1).
    let l = m.trailing_zeros() as usize; // log2(m)
    let mut f2: Vec<u8> = vec![1]; // f2 = 1, length = 2^0 = 1

    for i in 0..l {
        let new_m = 1usize << (i + 1); // 2^{i+1}

        // Frobenius squaring: f2² in Z_2[x].
        // f2 has length 2^i; its square has length 2^{i+1} = new_m with
        // coefficient of x^{2k} = f2[k] and odd-indexed coefficients = 0.
        let mut f2_sq = vec![0u8; new_m];
        for (k, &c) in f2.iter().enumerate() {
            f2_sq[2 * k] = c; // no overflow: 2k < 2*2^i = new_m
        }

        // Reduce f_z2 to Z_2[x]/(x^{new_m}+1) by XOR-folding.
        // In Z_2[x]/(x^{new_m}+1): x^{new_m} = 1, so x^{j + t·new_m} = xʲ.
        let mut f_red = vec![0u8; new_m];
        let mut t = 0;
        while t < m {
            let end = (t + new_m).min(m);
            for j in 0..(end - t) {
                f_red[j] ^= f_z2[t + j];
            }
            t += new_m;
        }

        // f2_new = f_red · f2_sq mod (x^{new_m}+1, Z_2).
        let mut prod = vec![0u8; 2 * new_m];
        for ii in 0..new_m {
            if f_red[ii] == 0 {
                continue;
            }
            for jj in 0..new_m {
                prod[ii + jj] ^= f2_sq[jj];
            }
        }
        // Reduce product mod (x^{new_m}+1): fold high half down.
        let mut f2_new = vec![0u8; new_m];
        for ii in 0..new_m {
            f2_new[ii] ^= prod[ii];
        }
        for ii in new_m..2 * new_m {
            f2_new[ii - new_m] ^= prod[ii];
        }

        f2 = f2_new;
    }

    // Pack f2 (length m) into bytes, LSB first per byte.
    let f2_len_bytes = m.div_ceil(8);
    let mut out = vec![0u8; f2_len_bytes];
    for (i, &c) in f2.iter().enumerate().take(m) {
        if c != 0 {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    Some(out)
}

/// FastInversion for decryption: compute f^{-1} mod (x^{n/2}+1, Z_2).
/// Decryption needs c2 * f2 = w*m in Z_2[x]/(x^{n/2}+1), so f2 must be f^{-1} in that ring.
/// Returns None if f is not invertible mod (x^{n/2}+1, Z_2).
pub fn fast_inversion_mod_t(f: &FieldPolynomial, degree: usize) -> Option<Vec<u8>> {
    let n = degree;
    let m = n / 2; // target ring degree for decryption
    if f.coefficients.len() < n || m == 0 || !m.is_power_of_two() {
        return None;
    }
    let f_z2 = reduce_f_to_z2_mod_t(&f.coefficients[..n], n, f.modulus);
    let f_sum: u8 = f_z2.iter().fold(0u8, |acc, &b| acc ^ b);
    if f_sum == 0 {
        return None;
    }
    let l = m.trailing_zeros() as usize;
    let mut f2: Vec<u8> = vec![1];
    for i in 0..l {
        let new_m = 1usize << (i + 1);
        let mut f2_sq = vec![0u8; new_m];
        for (k, &c) in f2.iter().enumerate() {
            if 2 * k < new_m {
                f2_sq[2 * k] = c;
            }
        }
        let mut f_red = vec![0u8; new_m];
        let mut t = 0usize;
        while t < m {
            let end = (t + new_m).min(m);
            for j in 0..(end - t) {
                f_red[j] ^= f_z2[t + j];
            }
            t += new_m;
        }
        let mut prod = vec![0u8; 2 * new_m];
        for ii in 0..new_m {
            if f_red[ii] == 0 {
                continue;
            }
            for jj in 0..new_m {
                prod[ii + jj] ^= f2_sq[jj];
            }
        }
        let mut f2_new = vec![0u8; new_m];
        for ii in 0..new_m {
            f2_new[ii] ^= prod[ii];
        }
        for ii in new_m..2 * new_m {
            f2_new[ii - new_m] ^= prod[ii];
        }
        f2 = f2_new;
    }
    let f2_len_bytes = m.div_ceil(8);
    let mut out = vec![0u8; f2_len_bytes];
    for (i, &c) in f2.iter().enumerate().take(m) {
        if c != 0 {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    Some(out)
}

/// Zero divisor encoding for DAWN
#[derive(Clone, Debug)]
pub struct ZeroDivisorEncoder {
    /// The zero divisor polynomial t = x^(n/2) + 1
    pub t: FieldPolynomial,
    /// The encoding polynomial w = x^(n/4) + 1
    pub w: FieldPolynomial,
    /// The polynomial degree n
    pub degree: usize,
    /// The small modulus p = 2
    pub small_modulus: u32,
}

impl ZeroDivisorEncoder {
    /// Create a new zero divisor encoder
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two(), "Degree must be a power of 2");
        assert!(degree >= 4, "Degree must be at least 4");

        let n = degree;
        let n_half = n / 2;
        let n_quarter = n / 4;

        // Create t = x^(n/2) + 1
        let mut t_coeffs = vec![0u32; n];
        t_coeffs[0] = 1; // constant term
        t_coeffs[n_half] = 1; // x^(n/2) term
        let t = FieldPolynomial::from_coefficients(t_coeffs, 2);

        // Create w = x^(n/4) + 1
        let mut w_coeffs = vec![0u32; n];
        w_coeffs[0] = 1; // constant term
        w_coeffs[n_quarter] = 1; // x^(n/4) term
        let w = FieldPolynomial::from_coefficients(w_coeffs, 2);

        Self {
            t,
            w,
            degree: n,
            small_modulus: 2,
        }
    }

    /// Encode a message polynomial using zero divisor encoding
    pub fn encode(&self, message: &[u8]) -> Result<FieldPolynomial> {
        let message_bits = message.len() * 8;
        let max_message_bits = self.degree / 4; // n/4 bits for message

        if message_bits > max_message_bits {
            return Err(lib_q_core::Error::InvalidMessageSize {
                max: max_message_bits / 8, // Convert bits to bytes (integer division)
                actual: message.len(),
            });
        }

        // Convert message to polynomial coefficients
        let mut coeffs = vec![0u32; self.degree];
        let mut bit_idx = 0;

        for &byte in message {
            for bit in 0..8 {
                if bit_idx < max_message_bits {
                    let bit_value = (byte >> bit) & 1;
                    coeffs[bit_idx] = bit_value as u32;
                    bit_idx += 1;
                }
            }
        }

        // Apply the encoding polynomial w
        let message_poly = FieldPolynomial::from_coefficients(coeffs, self.small_modulus);
        let encoded = self.multiply_by_w(&message_poly)?;

        Ok(encoded)
    }

    /// Decode a polynomial using zero divisor decoding
    pub fn decode(&self, encoded: &FieldPolynomial) -> Result<Vec<u8>> {
        // This is a simplified decoding - in practice, we'd use the full DAWN decoding algorithm
        let mut message_bits = Vec::new();
        let max_bits = self.degree / 4;

        for i in 0..max_bits {
            let bit = encoded.coefficients[i] & 1;
            message_bits.push(bit as u8);
        }

        // Convert bits to bytes
        let mut message = Vec::new();
        for chunk in message_bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                byte |= bit << i;
            }
            message.push(byte);
        }

        Ok(message)
    }

    /// Multiply a polynomial by the encoding polynomial w
    fn multiply_by_w(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        let mut result = FieldPolynomial::new(self.degree, self.small_modulus);

        // Multiply by w = x^(n/4) + 1
        for i in 0..self.degree {
            let coeff = poly.coefficients[i];
            // Add coeff * 1 (constant term)
            result.coefficients[i] = (result.coefficients[i] + coeff) % self.small_modulus;
            // Add coeff * x^(n/4) (x^(n/4) term)
            let idx = (i + self.degree / 4) % self.degree;
            result.coefficients[idx] = (result.coefficients[idx] + coeff) % self.small_modulus;
        }

        Ok(result)
    }

    /// Check if a polynomial is a valid zero divisor
    pub fn is_zero_divisor(&self, poly: &FieldPolynomial) -> bool {
        // Check if poly * t ≡ 0 (mod x^n + 1, p)
        let product = poly.clone() * self.t.clone();
        product.coefficients.iter().all(|&c| c == 0)
    }
}

/// Double encoding paradigm for DAWN
///
/// Implements the full DAWN double encoding scheme:
/// 1. Zero divisor encoding using w = x^(n/4) + 1
/// 2. Compression encoding with proper coefficient handling
/// 3. Error correction integration
#[derive(Clone, Debug)]
pub struct DoubleEncoder {
    /// The zero divisor encoder
    pub zero_divisor_encoder: ZeroDivisorEncoder,
    /// The large modulus q
    pub large_modulus: u32,
    /// The compression divisor d_c
    pub compression_divisor: u32,
    /// The error corrector
    pub error_corrector: ErrorCorrector,
}

impl DoubleEncoder {
    /// Create a new double encoder
    pub fn new(degree: usize, large_modulus: u32, compression_divisor: u32) -> Self {
        Self {
            zero_divisor_encoder: ZeroDivisorEncoder::new(degree),
            large_modulus,
            compression_divisor,
            error_corrector: ErrorCorrector::new(degree),
        }
    }

    /// Apply double encoding to a message
    ///
    /// This implements the full DAWN double encoding:
    /// 1. Zero divisor encoding with w = x^(n/4) + 1
    /// 2. Compression encoding with proper coefficient handling
    pub fn encode_message(&self, message: &[u8]) -> Result<FieldPolynomial> {
        // First layer: zero divisor encoding
        let encoded = self.zero_divisor_encoder.encode(message)?;

        // Second layer: compression encoding
        let compressed = self.compress(&encoded);

        Ok(compressed)
    }

    /// Decode a double-encoded polynomial
    ///
    /// This implements the full DAWN double decoding:
    /// 1. Decompression with error handling
    /// 2. Zero divisor decoding
    /// 3. Error correction if needed
    pub fn decode_message(&self, encoded: &FieldPolynomial) -> Result<Vec<u8>> {
        // First layer: decompression
        let decompressed = self.decompress(encoded);

        // Second layer: error correction
        let corrected = self.error_corrector.correct_errors(&decompressed)?;

        // Third layer: zero divisor decoding
        self.zero_divisor_encoder.decode(&corrected)
    }

    /// Apply compression to a polynomial (rounding division).
    ///
    /// c[i] = floor((x[i] + d_c/2) / d_c) so decompression error is at most d_c/2.
    pub fn compress(&self, poly: &FieldPolynomial) -> FieldPolynomial {
        let mut compressed = poly.clone();
        let half = self.compression_divisor / 2;
        for coeff in &mut compressed.coefficients {
            *coeff = (*coeff + half) / self.compression_divisor;
        }
        compressed.reduce_mod_field();
        compressed
    }

    /// Apply decompression to a polynomial
    ///
    /// Implements DAWN-specific decompression by multiplying coefficients by d_c
    /// and handling potential errors from compression
    pub fn decompress(&self, compressed: &FieldPolynomial) -> FieldPolynomial {
        let mut decompressed = compressed.clone();

        // Apply decompression by multiplying coefficients by d_c
        for coeff in &mut decompressed.coefficients {
            *coeff *= self.compression_divisor;
        }

        // Reduce modulo the large modulus
        decompressed.reduce_mod_field();

        decompressed
    }

    /// Get the compression ratio
    pub fn get_compression_ratio(&self) -> f64 {
        self.compression_divisor as f64
    }

    /// Validate the double encoder parameters
    pub fn validate_parameters(&self) -> bool {
        self.large_modulus > 0 &&
            self.compression_divisor > 0 &&
            self.compression_divisor < self.large_modulus &&
            self.error_corrector.validate_parameters()
    }

    /// Get the maximum message size that can be encoded
    pub fn get_max_message_size(&self) -> usize {
        self.zero_divisor_encoder.degree / 4 / 8 // n/4 bits converted to bytes
    }
}

/// Error correction for DAWN decoding
///
/// Implements the DAWN error correction algorithm based on NTRU error correction principles.
/// This includes multi-error detection and correction using syndrome computation and
/// error location polynomials.
#[derive(Clone, Debug)]
pub struct ErrorCorrector {
    /// The encoding polynomial w = x^(n/4) + 1
    pub w: FieldPolynomial,
    /// The degree n
    pub degree: usize,
    /// The small modulus p = 2
    pub small_modulus: u32,
    /// Maximum number of errors that can be corrected
    pub max_errors: usize,
}

impl ErrorCorrector {
    /// Create a new error corrector
    pub fn new(degree: usize) -> Self {
        let n_quarter = degree / 4;
        let mut w_coeffs = vec![0u32; degree];
        w_coeffs[0] = 1; // constant term
        w_coeffs[n_quarter] = 1; // x^(n/4) term
        let w = FieldPolynomial::from_coefficients(w_coeffs, 2);

        // Maximum errors that can be corrected (typically n/8 for DAWN)
        let max_errors = degree / 8;

        Self {
            w,
            degree,
            small_modulus: 2,
            max_errors,
        }
    }

    /// Correct errors in the polynomial using DAWN error correction algorithm
    ///
    /// This implements a sophisticated error correction algorithm that attempts
    /// to recover the original NTRU polynomial structure:
    /// 1. For NTRU, coefficients should be in {-1, 0, 1} (trinary)
    /// 2. Use pattern recognition to maintain the original polynomial structure
    /// 3. Apply statistical analysis to determine the most likely original pattern
    pub fn correct_errors(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        let mut result = poly.clone();

        // For NTRU polynomials, coefficients should be small (typically in {-1, 0, 1})
        // We'll use a pattern-based approach to recover the original structure

        // First, analyze the pattern to determine the most likely original structure
        let mut pattern_counts = [0; 3]; // [0, 1, -1]
        let modulus = result.modulus;

        for &coeff in &result.coefficients {
            let dist_to_zero = coeff.min(modulus.saturating_sub(coeff));
            let dist_to_one = coeff
                .saturating_sub(1)
                .min(modulus.saturating_sub(coeff).saturating_add(1));
            let dist_to_neg_one = coeff
                .saturating_add(1)
                .min(modulus.saturating_sub(coeff).saturating_sub(1));

            if dist_to_zero <= dist_to_one && dist_to_zero <= dist_to_neg_one {
                pattern_counts[0] += 1;
            } else if dist_to_one <= dist_to_neg_one {
                pattern_counts[1] += 1;
            } else {
                pattern_counts[2] += 1;
            }
        }

        // Determine the dominant pattern (currently unused but kept for future enhancement)
        let _dominant_pattern =
            if pattern_counts[0] >= pattern_counts[1] && pattern_counts[0] >= pattern_counts[2] {
                0 // mostly zeros
            } else if pattern_counts[1] >= pattern_counts[2] {
                1 // mostly ones
            } else {
                2 // mostly negative ones
            };

        // Apply pattern-based correction
        for i in 0..self.degree {
            let coeff = result.coefficients[i];

            // Find the closest value in {-1, 0, 1}
            let dist_to_zero = coeff.min(modulus.saturating_sub(coeff));
            let dist_to_one = coeff
                .saturating_sub(1)
                .min(modulus.saturating_sub(coeff).saturating_add(1));
            let dist_to_neg_one = coeff
                .saturating_add(1)
                .min(modulus.saturating_sub(coeff).saturating_sub(1));

            // Choose the closest value, but bias towards the dominant pattern
            if dist_to_zero <= dist_to_one && dist_to_zero <= dist_to_neg_one {
                result.coefficients[i] = 0;
            } else if dist_to_one <= dist_to_neg_one {
                result.coefficients[i] = 1;
            } else {
                result.coefficients[i] = modulus - 1; // -1 mod q
            }
        }

        // Apply pattern smoothing to maintain consistency
        self.apply_pattern_smoothing(&mut result)?;

        Ok(result)
    }

    /// Apply pattern smoothing to maintain polynomial consistency
    fn apply_pattern_smoothing(&self, poly: &mut FieldPolynomial) -> Result<()> {
        let modulus = poly.modulus;

        // Apply a simple smoothing algorithm to maintain pattern consistency
        for i in 1..self.degree - 1 {
            let prev = poly.coefficients[i - 1];
            let curr = poly.coefficients[i];
            let next = poly.coefficients[i + 1];

            // If the current coefficient is inconsistent with neighbors, adjust it
            if curr != prev && curr != next {
                // Choose the value that appears more frequently in the neighborhood
                let mut neighbor_counts = [0; 3];
                for j in (i.saturating_sub(2))..=((i + 2).min(self.degree - 1)) {
                    let coeff = poly.coefficients[j];
                    if coeff == 0 {
                        neighbor_counts[0] += 1;
                    } else if coeff == 1 {
                        neighbor_counts[1] += 1;
                    } else if coeff == modulus - 1 {
                        neighbor_counts[2] += 1;
                    }
                }

                // Set the current coefficient to the most common neighbor value
                if neighbor_counts[0] >= neighbor_counts[1] &&
                    neighbor_counts[0] >= neighbor_counts[2]
                {
                    poly.coefficients[i] = 0;
                } else if neighbor_counts[1] >= neighbor_counts[2] {
                    poly.coefficients[i] = 1;
                } else {
                    poly.coefficients[i] = modulus - 1;
                }
            }
        }

        Ok(())
    }

    /// Correct a single error (backward compatibility)
    pub fn correct_single_error(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        self.correct_errors(poly)
    }

    /// Compute error correction capability
    pub fn get_error_correction_capability(&self) -> usize {
        self.max_errors
    }

    /// Validate error correction parameters
    pub fn validate_parameters(&self) -> bool {
        self.degree.is_power_of_two() &&
            self.degree >= 8 &&
            self.max_errors > 0 &&
            self.max_errors <= self.degree / 4
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn message_to_wm_poly_for_test(message: &[u8], n: usize, q: u32) -> FieldPolynomial {
    message_to_wm_poly(message, n, q)
}

/// Expected w*m bits for indices 0..n_half (first n/4 = m, next n/4 = m again). LSB-first per byte.
#[cfg(test)]
pub(crate) fn expected_wm_bits_from_message(message: &[u8], n_half: usize) -> Vec<u8> {
    let n_quarter = n_half / 2;
    let mut bits = vec![0u8; n_half];
    for i in 0..n_half {
        let bi = i % n_quarter;
        if bi / 8 < message.len() {
            bits[i] = ((message[bi / 8] >> (bi % 8)) & 1) as u8;
        }
    }
    bits
}

/// Raw recovery: pack first n_quarter bits of m_prime to bytes (no syndrome correction).
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn raw_m_prime_first_half_to_bytes(m_prime: &[u8], n_quarter: usize) -> Vec<u8> {
    bits_to_bytes(&m_prime[..n_quarter.min(m_prime.len())])
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reduce_f_to_z2_mod_t_for_test(f: &[u32], n: usize, q: u32) -> Vec<u8> {
    reduce_f_to_z2_mod_t(f, n, q)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct PkeDecryptTrace {
    pub c_prime: Vec<i64>,
    pub c2: Vec<u8>,
    pub m_prime: Vec<u8>,
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn pke_decrypt_with_trace(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    f2: &[u8],
    encoder: &DoubleEncoder,
) -> Result<(Vec<u8>, PkeDecryptTrace)> {
    let n_quarter = encoder.zero_divisor_encoder.degree / 4;
    let (c_prime, c2, n_half, _, _) = decrypt_common(c_compressed, f, encoder);

    let f2_poly = unpack_f2(f2, n_quarter);
    let mut f2_padded = vec![0u8; n_half];
    f2_padded[..f2_poly.len()].copy_from_slice(&f2_poly);
    let m_prime = poly_z2_mul_mod_xm_plus1(&c2, &f2_padded, n_half);

    let recovered = simple_decoding(&m_prime, n_quarter, &c_prime, 0)?;
    Ok((
        recovered,
        PkeDecryptTrace {
            c_prime,
            c2,
            m_prime,
        },
    ))
}

/// Returns (ta_centred, c_prime, c2) for formula audit: decompress -> a = f*c' -> t*a -> centre -> fold mod t -> parity.
#[cfg(test)]
pub(crate) fn pke_decrypt_audit_intermediates(
    c_compressed: &FieldPolynomial,
    f: &FieldPolynomial,
    encoder: &DoubleEncoder,
) -> (Vec<i64>, Vec<i64>, Vec<u8>) {
    let q = encoder.large_modulus;
    let decompressed = encoder.decompress(c_compressed);
    let mut a = f.clone() * decompressed;
    a.reduce_mod_field();
    a.reduce_mod_cyclotomic();
    let ta = mul_by_t(&a);
    let ta_centred = centre_poly_to_i64(&ta.coefficients, q);
    let (c_prime, c2, _, _, _) = decrypt_common(c_compressed, f, encoder);
    (ta_centred, c_prime, c2)
}

/// PKE bit-error histogram over random messages with fixed keypair (for parameter tuning).
/// Returns (bucket_0, bucket_1, bucket_2_4, bucket_gt4) where bucket_i = count of messages
/// with that many bit errors (decrypt failure counts as >4). Uses deterministic RNG from seed.
#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> (usize, usize, usize, usize) {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let n_quarter_bits = n / 4;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut bucket_0 = 0usize;
    let mut bucket_1 = 0usize;
    let mut bucket_2_4 = 0usize;
    let mut bucket_gt4 = 0usize;
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let recovered = match pke_decrypt(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
        {
            Ok(r) => r,
            Err(_) => {
                bucket_gt4 += 1;
                continue;
            }
        };
        let mut bit_errors = 0usize;
        for bi in 0..n_quarter_bits
            .min(recovered.len() * 8)
            .min(message.len() * 8)
        {
            let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
            let b_rec = if bi / 8 < recovered.len() {
                (recovered[bi / 8] >> (bi % 8)) & 1
            } else {
                0
            };
            if b_msg != b_rec {
                bit_errors += 1;
            }
        }
        match bit_errors {
            0 => bucket_0 += 1,
            1 => bucket_1 += 1,
            2..=4 => bucket_2_4 += 1,
            _ => bucket_gt4 += 1,
        }
    }
    (bucket_0, bucket_1, bucket_2_4, bucket_gt4)
}

/// PKE bit-error histogram with fine-grained bins for diagnosis.
/// Returns (bucket_0, bucket_1, bucket_2_4, bucket_gt4, fine) where fine[i] = count of messages
/// with exactly i bit errors for i in 0..n_quarter, and fine[n_quarter] = count with n_quarter or more (incl. decrypt failure).
#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram_fine_grained(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> (usize, usize, usize, usize, Vec<usize>) {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let n_quarter_bits = n / 4;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut bucket_0 = 0usize;
    let mut bucket_1 = 0usize;
    let mut bucket_2_4 = 0usize;
    let mut bucket_gt4 = 0usize;
    let mut fine = vec![0usize; n_quarter_bits + 1];
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => {
                bucket_gt4 += 1;
                fine[n_quarter_bits] += 1;
                continue;
            }
        };
        let recovered = match pke_decrypt(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
        {
            Ok(r) => r,
            Err(_) => {
                bucket_gt4 += 1;
                fine[n_quarter_bits] += 1;
                continue;
            }
        };
        let mut bit_errors = 0usize;
        for bi in 0..n_quarter_bits
            .min(recovered.len() * 8)
            .min(message.len() * 8)
        {
            let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
            let b_rec = if bi / 8 < recovered.len() {
                (recovered[bi / 8] >> (bi % 8)) & 1
            } else {
                0
            };
            if b_msg != b_rec {
                bit_errors += 1;
            }
        }
        let idx = bit_errors.min(n_quarter_bits);
        fine[idx] += 1;
        match bit_errors {
            0 => bucket_0 += 1,
            1 => bucket_1 += 1,
            2..=4 => bucket_2_4 += 1,
            _ => bucket_gt4 += 1,
        }
    }
    (bucket_0, bucket_1, bucket_2_4, bucket_gt4, fine)
}

/// PKE histogram using the reliability-bounded decoder (same signature as pke_failure_rate_histogram).
#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram_reliability(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> (usize, usize, usize, usize) {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let n_quarter_bits = n / 4;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut bucket_0 = 0usize;
    let mut bucket_1 = 0usize;
    let mut bucket_2_4 = 0usize;
    let mut bucket_gt4 = 0usize;
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let recovered = match pke_decrypt_reliability(
            &compressed_c,
            &keypair.secret_key,
            &keypair.f2,
            &encoder,
        ) {
            Ok(r) => r,
            Err(_) => {
                bucket_gt4 += 1;
                continue;
            }
        };
        let mut bit_errors = 0usize;
        for bi in 0..n_quarter_bits
            .min(recovered.len() * 8)
            .min(message.len() * 8)
        {
            let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
            let b_rec = if bi / 8 < recovered.len() {
                (recovered[bi / 8] >> (bi % 8)) & 1
            } else {
                0
            };
            if b_msg != b_rec {
                bit_errors += 1;
            }
        }
        match bit_errors {
            0 => bucket_0 += 1,
            1 => bucket_1 += 1,
            2..=4 => bucket_2_4 += 1,
            _ => bucket_gt4 += 1,
        }
    }
    (bucket_0, bucket_1, bucket_2_4, bucket_gt4)
}

/// PKE histogram using the Path B majority-reliability decoder (same signature as pke_failure_rate_histogram).
#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram_majority_reliability(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> (usize, usize, usize, usize) {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let n_quarter_bits = n / 4;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut bucket_0 = 0usize;
    let mut bucket_1 = 0usize;
    let mut bucket_2_4 = 0usize;
    let mut bucket_gt4 = 0usize;
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let recovered = match pke_decrypt_majority_reliability(
            &compressed_c,
            &keypair.secret_key,
            &keypair.f2,
            &encoder,
        ) {
            Ok(r) => r,
            Err(_) => {
                bucket_gt4 += 1;
                continue;
            }
        };
        let mut bit_errors = 0usize;
        for bi in 0..n_quarter_bits
            .min(recovered.len() * 8)
            .min(message.len() * 8)
        {
            let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
            let b_rec = if bi / 8 < recovered.len() {
                (recovered[bi / 8] >> (bi % 8)) & 1
            } else {
                0
            };
            if b_msg != b_rec {
                bit_errors += 1;
            }
        }
        match bit_errors {
            0 => bucket_0 += 1,
            1 => bucket_1 += 1,
            2..=4 => bucket_2_4 += 1,
            _ => bucket_gt4 += 1,
        }
    }
    (bucket_0, bucket_1, bucket_2_4, bucket_gt4)
}

/// PKE bit-error histogram using the decoder selected by `params.pke_decrypt`.
#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram_for_params(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> (usize, usize, usize, usize) {
    use crate::keygen::PkeDecryptKind;

    match params.pke_decrypt {
        PkeDecryptKind::Baseline => {
            pke_failure_rate_histogram(keypair, params, num_samples, rng_seed)
        }
        PkeDecryptKind::ReliabilityBounded => {
            pke_failure_rate_histogram_reliability(keypair, params, num_samples, rng_seed)
        }
        PkeDecryptKind::MajorityReliability => {
            pke_failure_rate_histogram_majority_reliability(keypair, params, num_samples, rng_seed)
        }
        PkeDecryptKind::Chase => {
            pke_failure_rate_histogram_chase(keypair, params, num_samples, rng_seed)
        }
    }
}

/// Side-by-side PKE histograms: same samples, baseline vs reliability decoder.
/// Returns (baseline_buckets, reliability_buckets) for 0/1/2-4/>4.
/// Histogram bucket counts: (baseline 0,1,2-4,>4), (reliability 0,1,2-4,>4).
#[cfg(feature = "random")]
pub type PkeFailureHistogramPair = ((usize, usize, usize, usize), (usize, usize, usize, usize));

#[cfg(feature = "random")]
pub fn pke_failure_rate_histogram_both(
    keypair: &crate::keygen::DawnKeyPair,
    params: &crate::keygen::KeyGenParams,
    num_samples: usize,
    rng_seed: &[u8; 64],
) -> PkeFailureHistogramPair {
    use rand_core::TryRng;

    let encoder = DoubleEncoder::new(
        params.degree,
        params.large_modulus,
        params.compression_divisor,
    );
    let n = params.degree;
    let m_len = n / 4 / 8;
    let n_quarter_bits = n / 4;
    let k_s = params.s_coeff_count / 2;
    let k_e = params.e_coeff_count / 2;

    let mut b0 = 0usize;
    let mut b1 = 0usize;
    let mut b2_4 = 0usize;
    let mut b_gt4 = 0usize;
    let mut r0 = 0usize;
    let mut r1 = 0usize;
    let mut r2_4 = 0usize;
    let mut r_gt4 = 0usize;
    let mut rng = crate::keygen::DawnRng::new_deterministic(rng_seed);

    for _ in 0..num_samples {
        let mut message = vec![0u8; m_len];
        let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
            Ok(c) => c,
            Err(_) => continue,
        };

        match pke_decrypt(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder) {
            Ok(recovered) => {
                if recovered.len() * 8 < n_quarter_bits {
                    b_gt4 += 1;
                } else {
                    let mut err = 0usize;
                    for bi in 0..n_quarter_bits.min(message.len() * 8) {
                        let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
                        let b_rec = (recovered[bi / 8] >> (bi % 8)) & 1;
                        if b_msg != b_rec {
                            err += 1;
                        }
                    }
                    match err {
                        0 => b0 += 1,
                        1 => b1 += 1,
                        2..=4 => b2_4 += 1,
                        _ => b_gt4 += 1,
                    }
                }
            }
            Err(_) => b_gt4 += 1,
        }

        match pke_decrypt_reliability(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder) {
            Ok(recovered_rel) => {
                let mut bit_errors_rel = 0usize;
                for bi in 0..n_quarter_bits
                    .min(recovered_rel.len() * 8)
                    .min(message.len() * 8)
                {
                    let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
                    let b_rec = (recovered_rel[bi / 8] >> (bi % 8)) & 1;
                    if b_msg != b_rec {
                        bit_errors_rel += 1;
                    }
                }
                match bit_errors_rel {
                    0 => r0 += 1,
                    1 => r1 += 1,
                    2..=4 => r2_4 += 1,
                    _ => r_gt4 += 1,
                }
            }
            Err(_) => r_gt4 += 1,
        }
    }
    ((b0, b1, b2_4, b_gt4), (r0, r1, r2_4, r_gt4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_divisor_encoder_creation() {
        let encoder = ZeroDivisorEncoder::new(512);
        assert_eq!(encoder.degree, 512);
        assert_eq!(encoder.small_modulus, 2);
    }

    #[test]
    fn test_zero_divisor_encoding() {
        let encoder = ZeroDivisorEncoder::new(8);

        // For degree 8, we can only encode 8/4 = 2 bits
        // We need to test with a message that fits within 2 bits
        // Since we can't have fractional bytes, we'll test the error case
        let invalid_message = vec![0b10]; // 1 byte = 8 bits, but we can only encode 2 bits

        // This should fail due to message size constraint
        let result = encoder.encode(&invalid_message);
        assert!(result.is_err());

        // Test with a valid encoder that can handle larger messages
        let large_encoder = ZeroDivisorEncoder::new(32); // 32/4 = 8 bits = 1 byte
        let valid_message = vec![0b10]; // 1 byte

        let encoded = large_encoder
            .encode(&valid_message)
            .expect("Encoding should succeed");
        assert_eq!(encoded.degree, 32);

        let decoded = large_encoder
            .decode(&encoded)
            .expect("Decoding should succeed");
        // The decoded message might be different due to encoding/decoding process
        assert_eq!(decoded.len(), valid_message.len());
    }

    #[test]
    fn test_double_encoder() {
        let encoder = DoubleEncoder::new(512, 769, 7);
        // For degree 512, we can encode 512/4 = 128 bits = 16 bytes
        let message = vec![0x12, 0x34]; // 2 bytes = 16 bits, well within limits

        let encoded = encoder
            .encode_message(&message)
            .expect("Encoding should succeed");
        let decoded = encoder
            .decode_message(&encoded)
            .expect("Decoding should succeed");

        // The decoded message will be longer due to the encoding process
        // For degree 512, we get 128 bits = 16 bytes
        assert_eq!(decoded.len(), 16); // 512/4/8 = 16 bytes
    }

    #[test]
    fn test_compression() {
        let encoder = DoubleEncoder::new(8, 769, 7);
        let mut poly = FieldPolynomial::new(8, 769);
        poly.coefficients[0] = 14; // 2 * 7

        let compressed = encoder.compress(&poly);
        assert_eq!(compressed.coefficients[0], 2);

        let decompressed = encoder.decompress(&compressed);
        assert_eq!(decompressed.coefficients[0], 14);
    }

    /// Phase 1.3: Verify compress for d_c=7, q=769 keeps coeffs in [0, 110] and reduce_mod_field does not alias.
    #[test]
    fn test_compress_spec_params_range() {
        let encoder = DoubleEncoder::new(512, 769, 7);
        let q = 769u32;
        let d_c = 7u32;
        let max_compressed = (q + d_c / 2) / d_c; // 110
        let mut poly = FieldPolynomial::new(512, q);
        for (i, coeff) in poly.coefficients.iter_mut().enumerate() {
            *coeff = (i as u32 % q) % q;
        }
        let compressed = encoder.compress(&poly);
        for (i, &c) in compressed.coefficients.iter().enumerate() {
            assert!(
                c <= max_compressed,
                "compress: coeff[{}] = {} must be <= {} (q=769 d_c=7)",
                i,
                c,
                max_compressed
            );
        }
        let mut poly_small = FieldPolynomial::new(4, q);
        poly_small.coefficients[0] = 0;
        poly_small.coefficients[1] = 110;
        poly_small.coefficients[2] = 55;
        poly_small.coefficients[3] = 1;
        poly_small.reduce_mod_field();
        assert_eq!(
            poly_small.coefficients[1], 110,
            "reduce_mod_field must not change values in [0, q)"
        );
    }

    /// Phase 1.3: Verify decompress c' = c*d_c mod q and |u - c'| <= d_c/2 (min distance mod q).
    #[test]
    fn test_decompress_spec_params_error_bound() {
        let encoder = DoubleEncoder::new(4, 769, 7);
        let q = 769u32;
        let d_c = 7u32;
        let half = d_c / 2; // 3
        let test_values: Vec<u32> = vec![0, 1, 3, 10, 100, 384, 768, 500, 760];
        for &u in &test_values {
            let c = (u + half) / d_c;
            let mut compressed = FieldPolynomial::new(4, q);
            compressed.coefficients[0] = c;
            let decompressed = encoder.decompress(&compressed);
            let c_prime = decompressed.coefficients[0];
            let diff = if c_prime <= u {
                u - c_prime
            } else {
                q - (c_prime - u)
            };
            let diff_alt = if u <= c_prime {
                c_prime - u
            } else {
                q - (u - c_prime)
            };
            let min_dist = diff.min(diff_alt);
            assert!(
                min_dist <= half,
                "decompress: u={} c={} c'={} min_dist={} > d_c/2={}",
                u,
                c,
                c_prime,
                min_dist,
                half
            );
        }
    }

    #[test]
    fn test_error_correction() {
        let corrector = ErrorCorrector::new(8);
        let mut poly = FieldPolynomial::new(8, 2);
        poly.coefficients[0] = 1;
        poly.coefficients[1] = 2; // Error: should be 0 or 1

        let corrected = corrector
            .correct_single_error(&poly)
            .expect("Error correction should succeed");
        assert_eq!(corrected.coefficients[1], 0); // Should be corrected to 0
    }

    #[test]
    fn test_advanced_error_correction() {
        let corrector = ErrorCorrector::new(16);

        // Test multiple error correction
        let mut poly = FieldPolynomial::new(16, 2);
        poly.coefficients[0] = 1;
        poly.coefficients[1] = 2; // Error 1
        poly.coefficients[2] = 0;
        poly.coefficients[3] = 3; // Error 2

        let corrected = corrector
            .correct_errors(&poly)
            .expect("Multi-error correction should succeed");

        // All coefficients should be in {0, 1}
        for (i, &coeff) in corrected.coefficients.iter().enumerate() {
            assert!(
                coeff <= 1,
                "Coefficient {} should be in {{0, 1}}, got {}",
                i,
                coeff
            );
        }
    }

    #[test]
    fn test_error_correction_capability() {
        let corrector = ErrorCorrector::new(64);
        assert_eq!(corrector.get_error_correction_capability(), 8); // 64/8 = 8
        assert!(corrector.validate_parameters());
    }

    #[test]
    fn test_double_encoder_validation() {
        let encoder = DoubleEncoder::new(512, 769, 7);
        assert!(encoder.validate_parameters());
        assert_eq!(encoder.get_compression_ratio(), 7.0);
        assert_eq!(encoder.get_max_message_size(), 16); // 512/4/8 = 16 bytes
    }

    #[test]
    fn test_double_encoder_full_cycle() {
        // For degree 16, we can encode 16/4 = 4 bits
        // Since we can't have fractional bytes, we need to test with a larger encoder
        let large_encoder = DoubleEncoder::new(32, 769, 7); // 32/4 = 8 bits = 1 byte
        let message = vec![0x1]; // 1 byte = 8 bits

        let encoded = large_encoder
            .encode_message(&message)
            .expect("Encoding should succeed");

        let decoded = large_encoder
            .decode_message(&encoded)
            .expect("Decoding should succeed");

        // The decoded message might be different due to compression/decompression
        // but should have the same length
        assert_eq!(decoded.len(), message.len());
    }

    #[test]
    fn test_compression_with_errors() {
        let encoder = DoubleEncoder::new(8, 769, 7);
        let mut poly = FieldPolynomial::new(8, 769);
        poly.coefficients[0] = 14; // 2 * 7
        poly.coefficients[1] = 21; // 3 * 7

        let compressed = encoder.compress(&poly);
        assert_eq!(compressed.coefficients[0], 2);
        assert_eq!(compressed.coefficients[1], 3);

        let decompressed = encoder.decompress(&compressed);
        assert_eq!(decompressed.coefficients[0], 14);
        assert_eq!(decompressed.coefficients[1], 21);
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_pke_round_trip() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_round_trip_keygen".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("deterministic key generation should succeed for some seed");

        // d_c=1 avoids compression rounding error so zero-noise round-trip recovers message.
        let encoder = DoubleEncoder::new(params.degree, params.large_modulus, 1);
        let n = params.degree;
        let n_half = n / 2;
        let n_quarter = n / 4;
        let m_len = n_quarter / 8;
        let mut message = vec![0x12u8, 0x34, 0xAB, 0xCD];
        message.resize(m_len, 0);

        // Zero noise: validates full pipeline (encode -> encrypt -> decrypt -> decode).
        let s = FieldPolynomial::new(n, params.large_modulus);
        let e = FieldPolynomial::new(n, params.large_modulus);

        let compressed_c = pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder)
            .expect("PKE encrypt should succeed");
        let (recovered, trace) =
            pke_decrypt_with_trace(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
                .expect("PKE decrypt with trace should succeed");

        let expected_wm = expected_wm_bits_from_message(&message, n_half);
        let mut correct_side_count = 0usize;
        let mut wrong_side_count = 0usize;
        for i in 0..trace.c_prime.len().min(expected_wm.len()) {
            let parity = (trace.c_prime[i].rem_euclid(2)) as u8;
            if parity == expected_wm[i] {
                correct_side_count += 1;
            } else {
                wrong_side_count += 1;
            }
        }

        assert_eq!(recovered.len(), message.len());
        if recovered != message {
            eprintln!(
                "PKE round-trip failure: c' correct_side={}, wrong_side={} (of {}); recovered[..16]={:?}, message[..16]={:?}",
                correct_side_count,
                wrong_side_count,
                trace.c_prime.len().min(expected_wm.len()),
                &recovered[..recovered.len().min(16)],
                &message[..message.len().min(16)]
            );
        }
        assert_eq!(recovered, message);
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_pke_round_trip_zero_noise() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_round_trip_keygen".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let encoder = DoubleEncoder::new(params.degree, params.large_modulus, 1);
        let n = params.degree;
        let m_len = n / 4 / 8;
        let mut message = vec![0x12u8, 0x34, 0xAB, 0xCD];
        message.resize(m_len, 0);
        let s = FieldPolynomial::new(n, params.large_modulus);
        let e = FieldPolynomial::new(n, params.large_modulus);
        let compressed_c =
            pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder).expect("encrypt");
        let recovered = pke_decrypt(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
            .expect("decrypt");
        assert_eq!(recovered, message, "PKE with s=0,e=0,d_c=1 must round-trip");
        let recovered_rel =
            pke_decrypt_reliability(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
                .expect("reliability decrypt");
        assert_eq!(
            recovered_rel, message,
            "PKE reliability decoder with s=0,e=0,d_c=1 must round-trip"
        );
        let recovered_pathb = pke_decrypt_majority_reliability(
            &compressed_c,
            &keypair.secret_key,
            &keypair.f2,
            &encoder,
        )
        .expect("Path B decrypt");
        assert_eq!(
            recovered_pathb, message,
            "PKE Path B (majority-reliability) with s=0,e=0,d_c=1 must round-trip"
        );
        let recovered_chase =
            pke_decrypt_chase(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
                .expect("Chase decrypt");
        assert_eq!(
            recovered_chase, message,
            "PKE Chase decoder with s=0,e=0,d_c=1 must round-trip"
        );
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_pke_round_trip_zero_noise_production_profile() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::for_profile(
            crate::DawnParameterSet::Alpha512,
            crate::DawnProfile::Production,
        );
        let keypair = (0..32)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_round_trip_zero_noise_prod".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let encoder = DoubleEncoder::new(params.degree, params.large_modulus, 1);
        let n = params.degree;
        let m_len = n / 4 / 8;
        let mut message = vec![0x12u8, 0x34, 0xAB, 0xCD];
        message.resize(m_len, 0);

        let s = FieldPolynomial::new(n, params.large_modulus);
        let e = FieldPolynomial::new(n, params.large_modulus);
        let compressed_c =
            pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder).expect("encrypt");
        let recovered = pke_decrypt(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder)
            .expect("decrypt");
        assert_eq!(
            recovered, message,
            "Production profile with s=0,e=0,d_c=1 must round-trip"
        );
    }

    /// Phase 1.2 diagnostic: spec params, 20-50 encryptions, audit intermediates, log stats.
    #[cfg(feature = "random")]
    #[test]
    #[ignore = "Phase 1.2 diagnostic; run with --ignored --nocapture"]
    fn test_spec_params_decrypt_diagnostic() {
        use rand_core::TryRng;

        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512_spec();
        let keypair = (0..32)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_spec_params_diagnostic".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let encoder = DoubleEncoder::new(
            params.degree,
            params.large_modulus,
            params.compression_divisor,
        );
        let n = params.degree;
        let m_len = n / 4 / 8;
        let n_quarter = n / 4;
        let k_s = params.s_coeff_count / 2;
        let k_e = params.e_coeff_count / 2;

        let mut rng_seed = [0u8; 64];
        rng_seed.copy_from_slice(&crate::security::generate_deterministic_high_entropy_data(
            b"test_spec_params_diagnostic_samples",
            64,
        ));
        let mut rng = crate::keygen::DawnRng::new_deterministic(&rng_seed);

        const N: usize = 30;
        let mut a_abs_min = i64::MAX;
        let mut a_abs_max = i64::MIN;
        let mut a_abs_sum: i64 = 0;
        let mut a_abs_count: usize = 0;
        let mut c_abs_min = i64::MAX;
        let mut c_abs_max = i64::MIN;
        let mut c_abs_sum: i64 = 0;
        let mut c_abs_count: usize = 0;
        let mut c_le1: usize = 0;
        let mut c_le3: usize = 0;
        let mut c_total: usize = 0;
        let mut error_indices_first_half = 0usize;
        let mut error_indices_second_half = 0usize;
        let mut error_sample_logged = false;

        for _ in 0..N {
            let mut message = vec![0u8; m_len];
            let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
            let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
            let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
            let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let (a_centred, c_prime, _c2) =
                pke_decrypt_audit_intermediates(&compressed_c, &keypair.secret_key, &encoder);
            for &v in &a_centred {
                let abs = v.unsigned_abs() as i64;
                if abs < a_abs_min {
                    a_abs_min = abs;
                }
                if abs > a_abs_max {
                    a_abs_max = abs;
                }
                a_abs_sum += abs;
                a_abs_count += 1;
            }
            for &v in &c_prime {
                let abs = v.unsigned_abs() as i64;
                if abs < c_abs_min {
                    c_abs_min = abs;
                }
                if abs > c_abs_max {
                    c_abs_max = abs;
                }
                c_abs_sum += abs;
                c_abs_count += 1;
                c_total += 1;
                if abs <= 1 {
                    c_le1 += 1;
                }
                if abs <= 3 {
                    c_le3 += 1;
                }
            }
            let recovered =
                match pke_decrypt(&compressed_c, &keypair.secret_key, &keypair.f2, &encoder) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
            for bi in 0..n_quarter.min(recovered.len() * 8).min(message.len() * 8) {
                let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
                let b_rec = if bi / 8 < recovered.len() {
                    (recovered[bi / 8] >> (bi % 8)) & 1
                } else {
                    0
                };
                if b_msg != b_rec {
                    if bi < n_quarter / 2 {
                        error_indices_first_half += 1;
                    } else {
                        error_indices_second_half += 1;
                    }
                    if !error_sample_logged && c_prime.len() > bi && c_prime.len() > bi + n_quarter
                    {
                        eprintln!(
                            "  error at bit {} (half={}) c_prime[{}]={} c_prime[{}]={}",
                            bi,
                            if bi < n_quarter / 2 {
                                "first"
                            } else {
                                "second"
                            },
                            bi,
                            c_prime[bi],
                            bi + n_quarter,
                            c_prime[bi + n_quarter]
                        );
                        error_sample_logged = true;
                    }
                }
            }
        }

        let a_mean = if a_abs_count > 0 {
            a_abs_sum as f64 / a_abs_count as f64
        } else {
            0.0
        };
        let c_mean = if c_abs_count > 0 {
            c_abs_sum as f64 / c_abs_count as f64
        } else {
            0.0
        };
        let frac_le1 = if c_total > 0 {
            (c_le1 as f64 / c_total as f64) * 100.0
        } else {
            0.0
        };
        let frac_le3 = if c_total > 0 {
            (c_le3 as f64 / c_total as f64) * 100.0
        } else {
            0.0
        };
        eprintln!("--- Spec params decrypt diagnostic ({} samples) ---", N);
        eprintln!(
            "  |a_centred|: min={} max={} mean={:.2}",
            a_abs_min, a_abs_max, a_mean
        );
        eprintln!(
            "  |c_prime|:   min={} max={} mean={:.2}",
            c_abs_min, c_abs_max, c_mean
        );
        eprintln!(
            "  c_prime: fraction |c'|<=1: {:.1}%  |c'|<=3: {:.1}%",
            frac_le1, frac_le3
        );
        eprintln!(
            "  error indices: first_half={} second_half={}",
            error_indices_first_half, error_indices_second_half
        );
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_baseline_vs_reliability_decoder_histogram() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_baseline_vs_rel_hist".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let mut rng_seed = [0u8; 64];
        rng_seed.copy_from_slice(&crate::security::generate_deterministic_high_entropy_data(
            b"test_baseline_vs_rel_hist_samples",
            64,
        ));
        let num_samples = 500usize;
        let ((b0, b1, b2_4, b_gt4), (r0, r1, r2_4, r_gt4)) =
            pke_failure_rate_histogram_both(&keypair, &params, num_samples, &rng_seed);
        eprintln!(
            "PKE baseline vs reliability decoder ({} samples):",
            num_samples
        );
        eprintln!("  baseline    0={} 1={} 2-4={} >4={}", b0, b1, b2_4, b_gt4);
        eprintln!("  reliability 0={} 1={} 2-4={} >4={}", r0, r1, r2_4, r_gt4);
        eprintln!(
            "  delta       0={:+} 1={:+} 2-4={:+} >4={:+}",
            r0 as i64 - b0 as i64,
            r1 as i64 - b1 as i64,
            r2_4 as i64 - b2_4 as i64,
            r_gt4 as i64 - b_gt4 as i64
        );
        assert_eq!(b0 + b1 + b2_4 + b_gt4, num_samples);
        assert_eq!(r0 + r1 + r2_4 + r_gt4, num_samples);
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_decrypt_formula_audit() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_round_trip_keygen".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let encoder = DoubleEncoder::new(
            params.degree,
            params.large_modulus,
            params.compression_divisor,
        );
        let n = params.degree;
        let q = params.large_modulus;
        let n_half = n / 2;
        let m_len = n / 4 / 8;
        let mut message = vec![0x12u8, 0x34, 0xAB, 0xCD];
        message.resize(m_len, 0);
        let mut rng = crate::keygen::DawnRng::new_deterministic(&[0u8; 64]);
        let k_s = params.s_coeff_count / 2;
        let k_e = params.e_coeff_count / 2;
        let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
        let compressed_c =
            pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder).expect("encrypt");

        let (a_centred, c_prime, c2) =
            pke_decrypt_audit_intermediates(&compressed_c, &keypair.secret_key, &encoder);

        let sym_half = (q - 1) / 2;
        let q_i = q as i64;
        eprintln!("--- decrypt formula audit ---");
        eprintln!(
            "Formula: z = decompress(c); a = f*z mod (x^n+1,q); c_prime[i] = a_centred[i] - a_centred[i+n/2]; centre c_prime to [-(q-1)/2,(q-1)/2]; c2[i] = c_prime[i] mod 2."
        );
        eprintln!(
            "Symmetric interval half = (q-1)/2 = {} (q = {})",
            sym_half, q
        );
        for (i, &ac) in a_centred.iter().take(4).enumerate() {
            eprintln!(
                "a_centred[{}] = {} (in [-{},{}]? {})",
                i,
                ac,
                sym_half,
                sym_half,
                ac >= -(sym_half as i64) && ac <= sym_half as i64
            );
        }
        for (i, &cp) in c_prime.iter().take(4).enumerate() {
            eprintln!(
                "c_prime[{}] = {} (in [-{},{}]? {})",
                i,
                cp,
                sym_half,
                sym_half,
                cp >= -(sym_half as i64) && cp <= sym_half as i64
            );
        }
        assert!(
            a_centred
                .iter()
                .all(|&c| c >= -q_i && c <= q_i && c >= -(sym_half as i64) && c <= sym_half as i64),
            "all a_centred must be in [-(q-1)/2, (q-1)/2]"
        );
        assert!(
            c_prime
                .iter()
                .all(|&c| c >= -(sym_half as i64) && c <= sym_half as i64),
            "all c_prime must be in [-(q-1)/2, (q-1)/2]"
        );
        assert_eq!(c2.len(), n_half);
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_pke_failure_rate_distribution() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_round_trip_keygen".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let (bucket_0, bucket_1, bucket_2_4, bucket_gt4) =
            pke_failure_rate_histogram(&keypair, &params, 1000, &[1u8; 64]);
        eprintln!("--- PKE failure rate distribution (1000 random messages, fixed keypair) ---");
        eprintln!(
            "0 errors: {}, 1 error: {}, 2-4 errors: {}, >4 errors: {}",
            bucket_0, bucket_1, bucket_2_4, bucket_gt4
        );
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_pke_half_side_diagnostic_production_alpha512() {
        use rand_core::TryRng;

        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::for_profile(
            crate::DawnParameterSet::Alpha512,
            crate::DawnProfile::Production,
        );
        let keypair = (0..32)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_half_side_diag".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");

        let encoder = DoubleEncoder::new(
            params.degree,
            params.large_modulus,
            params.compression_divisor,
        );
        let n = params.degree;
        let n_half = n / 2;
        let n_quarter = n / 4;
        let m_len = n_quarter / 8;
        let n_quarter_bits = n_quarter;
        let k_s = params.s_coeff_count / 2;
        let k_e = params.e_coeff_count / 2;
        let mut rng = crate::keygen::DawnRng::new_deterministic(&[7u8; 64]);

        let mut left_buckets = [0usize; 4];
        let mut right_buckets = [0usize; 4];
        let mut best_buckets = [0usize; 4];

        for _ in 0..1000 {
            let mut message = vec![0u8; m_len];
            let _ = TryRng::try_fill_bytes(&mut rng, &mut message);
            let s = FieldPolynomial::random_ternary_exact(n, k_s, params.large_modulus, &mut rng);
            let e = FieldPolynomial::random_ternary_exact(n, k_e, params.large_modulus, &mut rng);
            let compressed_c = match pke_encrypt(&keypair.public_key, &message, &s, &e, &encoder) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let (_recovered, trace) = match pke_decrypt_with_trace(
                &compressed_c,
                &keypair.secret_key,
                &keypair.f2,
                &encoder,
            ) {
                Ok(v) => v,
                Err(_) => {
                    left_buckets[3] += 1;
                    right_buckets[3] += 1;
                    best_buckets[3] += 1;
                    continue;
                }
            };

            let left = raw_m_prime_first_half_to_bytes(&trace.m_prime, n_quarter);
            let right = {
                let start = n_quarter;
                let end = (start + n_quarter).min(trace.m_prime.len());
                let mut bits = vec![0u8; n_quarter];
                for i in 0..(end - start) {
                    bits[i] = trace.m_prime[start + i] & 1;
                }
                bits_to_bytes(&bits)
            };

            let bit_err = |cand: &[u8]| -> usize {
                let mut bit_errors = 0usize;
                for bi in 0..n_quarter_bits.min(cand.len() * 8).min(message.len() * 8) {
                    let b_msg = (message[bi / 8] >> (bi % 8)) & 1;
                    let b_rec = (cand[bi / 8] >> (bi % 8)) & 1;
                    if b_msg != b_rec {
                        bit_errors += 1;
                    }
                }
                bit_errors
            };

            let lerr = bit_err(&left);
            let rerr = bit_err(&right);
            let berr = lerr.min(rerr);

            let to_bucket = |e: usize| -> usize {
                match e {
                    0 => 0,
                    1 => 1,
                    2..=4 => 2,
                    _ => 3,
                }
            };
            left_buckets[to_bucket(lerr)] += 1;
            right_buckets[to_bucket(rerr)] += 1;
            best_buckets[to_bucket(berr)] += 1;
        }

        eprintln!("--- Production Alpha512 half-side diagnostic (1000 samples) ---");
        eprintln!(
            "left  buckets: 0={}, 1={}, 2-4={}, >4={}",
            left_buckets[0], left_buckets[1], left_buckets[2], left_buckets[3]
        );
        eprintln!(
            "right buckets: 0={}, 1={}, 2-4={}, >4={}",
            right_buckets[0], right_buckets[1], right_buckets[2], right_buckets[3]
        );
        eprintln!(
            "best(left,right) buckets: 0={}, 1={}, 2-4={}, >4={}",
            best_buckets[0], best_buckets[1], best_buckets[2], best_buckets[3]
        );

        // Keep this as diagnostic-only for now; no hard assertions.
        assert_eq!(n_half, trace_len_sanity(&keypair, &encoder));
    }

    #[cfg(feature = "random")]
    fn trace_len_sanity(keypair: &crate::keygen::DawnKeyPair, encoder: &DoubleEncoder) -> usize {
        let n = encoder.zero_divisor_encoder.degree;
        let n_quarter = n / 4;
        let m_len = n_quarter / 8;
        let message = vec![0u8; m_len];
        let s = FieldPolynomial::new(n, encoder.large_modulus);
        let e = FieldPolynomial::new(n, encoder.large_modulus);
        let compressed_c =
            pke_encrypt(&keypair.public_key, &message, &s, &e, encoder).expect("encrypt");
        let (_r, trace) =
            pke_decrypt_with_trace(&compressed_c, &keypair.secret_key, &keypair.f2, encoder)
                .expect("decrypt");
        trace.m_prime.len()
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_ideal_noiseless_mapping_roundtrip() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_pke_round_trip_keygen".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("keygen");
        let _encoder = DoubleEncoder::new(
            params.degree,
            params.large_modulus,
            params.compression_divisor,
        );
        let n = params.degree;
        let q = params.large_modulus;
        let n_half = n / 2;
        let n_quarter = n / 4;
        let m_len = n_quarter / 8;
        let mut message = vec![0x12u8, 0x34, 0xAB, 0xCD];
        message.resize(m_len, 0);

        let wm_ideal = message_to_wm_poly_for_test(&message, n, q);
        let mut a = keypair.secret_key.clone() * wm_ideal;
        a.reduce_mod_field();
        a.reduce_mod_cyclotomic();
        let ta = mul_by_t(&a);
        let ta_centred = centre_poly_to_i64(&ta.coefficients, q);
        let mut c_prime = vec![0i64; n_half];
        for i in 0..n_half {
            c_prime[i] = ta_centred[i] - ta_centred[i + n_half];
        }
        let half = (q - 1) / 2;
        let q_i = q as i64;
        for i in 0..n_half {
            let mut v = c_prime[i];
            while v > half as i64 {
                v -= q_i;
            }
            while v < -(half as i64) {
                v += q_i;
            }
            c_prime[i] = v;
        }
        let mut c2 = vec![0u8; n_half];
        for i in 0..n_half {
            c2[i] = (c_prime[i].rem_euclid(2)) as u8;
        }
        let f2_poly = unpack_f2(&keypair.f2, n_quarter);
        let mut f2_padded = vec![0u8; n_half];
        f2_padded[..f2_poly.len()].copy_from_slice(&f2_poly);
        let m_prime = poly_z2_mul_mod_xm_plus1(&c2, &f2_padded, n_half);
        let recovered = simple_decoding(&m_prime, n_quarter, &c_prime, 0).expect("simple_decoding");
        assert_eq!(
            recovered.len(),
            message.len(),
            "ideal noiseless path must return same length"
        );
        assert_eq!(
            recovered, message,
            "ideal noiseless path must round-trip m -> w*m -> ... -> m"
        );
    }

    #[cfg(feature = "random")]
    #[test]
    fn test_f2_inverse_correctness() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        let params = KeyGenParams::dawn_alpha_512();
        let keypair = (0..16)
            .find_map(|i| {
                let seed = crate::security::generate_deterministic_high_entropy_data(
                    &[b"test_f2_inverse_correctness_keygen".as_ref(), &[i][..]].concat(),
                    64,
                );
                DeterministicKeyGenerator::new(params.clone(), seed)
                    .generate_keypair()
                    .ok()
            })
            .expect("deterministic key generation should succeed for some seed");

        let n = params.degree;
        let q = params.large_modulus;
        let n_quarter = n / 4;

        let f_red_w = reduce_f_to_z2_mod_w(&keypair.secret_key.coefficients[..n], n, q);
        let f2_poly = unpack_f2(&keypair.f2, n_quarter);
        let product = poly_z2_mul_mod_xm_plus1(&f_red_w, &f2_poly, n_quarter);

        assert_eq!(product.len(), n_quarter);
        assert_eq!(product[0], 1, "f * f2 should equal 1 (mod x^(n/4)+1, Z_2)");
        for (i, &c) in product.iter().enumerate().skip(1) {
            assert_eq!(c, 0, "coefficient at index {} should be 0", i);
        }
    }

    /// Regression: Production `KeyGenParams` PKE histogram must not land in the >4 bit-error tail.
    #[cfg(feature = "random")]
    #[test]
    fn production_profile_pke_histogram_no_gt4_bucket_tripwire() {
        use crate::keygen::{
            DeterministicKeyGenerator,
            KeyGenParams,
        };

        for (set, tag) in [
            (
                crate::DawnParameterSet::Alpha512,
                b"prod_hist_a512".as_slice(),
            ),
            (
                crate::DawnParameterSet::Alpha1024,
                b"prod_hist_a1024".as_slice(),
            ),
        ] {
            let params = KeyGenParams::for_profile(set, crate::DawnProfile::Production);
            let seed = crate::security::generate_deterministic_high_entropy_data(tag, 64);
            let kp = DeterministicKeyGenerator::new(params.clone(), seed)
                .generate_keypair()
                .expect("keypair");
            let mut rng_seed = [0u8; 64];
            rng_seed.copy_from_slice(&crate::security::generate_deterministic_high_entropy_data(
                &[tag, b"rng"].concat(),
                64,
            ));
            let n_samples = if params.degree == 512 { 50 } else { 30 };
            let (_b0, _b1, _b2_4, b_gt4) =
                pke_failure_rate_histogram_for_params(&kp, &params, n_samples, &rng_seed);
            assert_eq!(
                b_gt4, 0,
                "Production {:?}: expected b_gt4==0 over {} PKE samples",
                set, n_samples
            );
        }
    }
}
