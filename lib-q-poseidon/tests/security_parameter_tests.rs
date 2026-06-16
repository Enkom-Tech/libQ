//! Security parameter tests for Poseidon
//!
//! Enforce at test time that Poseidon parameters meet the structural invariants
//! the crate targets (capacity/state-width relations, minimum round counts, MDS
//! invertibility, valid S-box exponent). NOTE: these checks do NOT prove a
//! specific bit-security level over the GF(p²) extension field; the round counts
//! are not independently verified for that field.

use lib_q_poseidon::{
    Poseidon128,
    Poseidon256,
    mds_matrix_5x5,
    round_constants_128,
    round_constants_256,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    PrimeCharacteristicRing,
    PrimeField32,
};
use lib_q_stark_mersenne31::Mersenne31;

type F = Complex<Mersenne31>;

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

#[test]
fn test_poseidon128_capacity_meets_128bit_security() {
    let p = Poseidon128::params();
    assert!(
        p.capacity >= 3,
        "3 elements × 62 bits = 186 >= 128; capacity must be >= 3"
    );
    assert_eq!(
        p.state_width,
        p.rate + p.capacity,
        "state_width must equal rate + capacity"
    );
    assert!(
        p.state_width >= 5,
        "state_width must be >= 5 for 128-bit security"
    );
}

#[test]
fn test_poseidon256_capacity_meets_256bit_security() {
    let p = Poseidon256::params();
    assert!(
        p.capacity >= 5,
        "5 elements × 62 bits = 310 >= 256; capacity must be >= 5"
    );
    assert!(
        p.state_width >= 7,
        "state_width must be >= 7 for 256-bit security"
    );
}

#[test]
fn test_poseidon128_full_round_count_algebraic_bound() {
    assert!(
        Poseidon128::params().full_rounds >= 6,
        "Poseidon paper requires R_F >= 6 for Groebner basis attack resistance"
    );
    assert!(
        Poseidon256::params().full_rounds >= 6,
        "Poseidon256 must also satisfy full_rounds >= 6"
    );
}

#[test]
fn test_poseidon128_partial_round_count_statistical_bound() {
    assert!(
        Poseidon128::params().partial_rounds >= 56,
        "From Poseidon paper Table 2, alpha=5, log2(p)=31: R_P >= 56"
    );
    assert!(
        Poseidon256::params().partial_rounds >= 56,
        "Poseidon256 must also satisfy partial_rounds >= 56"
    );
}

#[test]
fn test_sbox_alpha_is_valid_permutation_over_gf_p2() {
    // The S-box operates over the extension field GF(p^2) = Complex<Mersenne31>,
    // whose multiplicative group has order p^2 - 1 (NOT p - 1). x^5 is a
    // permutation of GF(p^2) iff gcd(5, p^2 - 1) == 1.
    let p = Mersenne31::ORDER_U32 as u64;
    let order_minus_1 = p * p - 1;
    let g = gcd(5, order_minus_1);
    assert_eq!(
        g, 1,
        "alpha=5 must be coprime to p^2 - 1 for x^5 to be a permutation over GF(p^2)"
    );
}

#[test]
fn test_round_constants_are_nonzero() {
    let rc128 = round_constants_128();
    assert!(
        rc128.iter().all(|c| *c != F::ZERO),
        "All Poseidon-128 round constants must be nonzero"
    );
    let rc256 = round_constants_256();
    assert!(
        rc256.iter().all(|c| *c != F::ZERO),
        "All Poseidon-256 round constants must be nonzero"
    );
}

#[test]
fn test_round_constants_no_consecutive_repeats() {
    let rc128 = round_constants_128();
    assert!(
        rc128.windows(2).all(|w| w[0] != w[1]),
        "No two consecutive Poseidon-128 round constants may be equal"
    );
    let rc256 = round_constants_256();
    assert!(
        rc256.windows(2).all(|w| w[0] != w[1]),
        "No two consecutive Poseidon-256 round constants may be equal"
    );
}

#[test]
fn test_round_constants_reproduced_from_shake256_seed() {
    use digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    use lib_q_sha3::Shake256;

    const P: u32 = (1 << 31) - 1;
    let seed = "Poseidon128_Mersenne31_v1_w5";
    let count = 10;

    let mut hasher = Shake256::default();
    hasher.update(seed.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut bytes = vec![0u8; count * 8];
    reader.read(&mut bytes);

    let rc = round_constants_128();
    for i in 0..count {
        let real_bytes = [
            bytes[i * 8],
            bytes[i * 8 + 1],
            bytes[i * 8 + 2],
            bytes[i * 8 + 3],
        ];
        let imag_bytes = [
            bytes[i * 8 + 4],
            bytes[i * 8 + 5],
            bytes[i * 8 + 6],
            bytes[i * 8 + 7],
        ];
        let real_u32 = u32::from_le_bytes(real_bytes) % P;
        let imag_u32 = u32::from_le_bytes(imag_bytes) % P;
        let expected = Complex::new_complex(Mersenne31::new(real_u32), Mersenne31::new(imag_u32));
        assert_eq!(
            rc[i], expected,
            "Round constant {} must match SHAKE256 derivation from seed (mod P)",
            i
        );
    }
}

/// Determinant of 3x3 matrix over F (Sarrus / cofactor)
fn det_3x3(m: &[Vec<F>]) -> F {
    assert_eq!(m.len(), 3);
    assert_eq!(m[0].len(), 3);
    let a = m[0][0];
    let b = m[0][1];
    let c = m[0][2];
    let d = m[1][0];
    let e = m[1][1];
    let f = m[1][2];
    let g = m[2][0];
    let h = m[2][1];
    let i = m[2][2];
    a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)
}

/// Determinant of 5x5 matrix via Laplace expansion along first row
fn det_5x5(m: &[Vec<F>]) -> F {
    assert_eq!(m.len(), 5);
    assert!(m.iter().all(|r| r.len() == 5));
    let mut acc = F::ZERO;
    for j in 0..5 {
        let sign = if j % 2 == 0 { 1i32 } else { -1i32 };
        let mut minor = vec![vec![F::ZERO; 4]; 4];
        for ri in 1..5 {
            let mut ci = 0;
            for (cj, &elem) in m[ri].iter().enumerate() {
                if cj == j {
                    continue;
                }
                minor[ri - 1][ci] = elem;
                ci += 1;
            }
        }
        let minor_det = det_4x4(&minor);
        if sign > 0 {
            acc += m[0][j] * minor_det;
        } else {
            acc -= m[0][j] * minor_det;
        }
    }
    acc
}

fn det_4x4(m: &[Vec<F>]) -> F {
    let mut acc = F::ZERO;
    for j in 0..4 {
        let sign = if j % 2 == 0 { 1i32 } else { -1i32 };
        let mut minor = vec![vec![F::ZERO; 3]; 3];
        for ri in 1..4 {
            let mut ci = 0;
            for (cj, &elem) in m[ri].iter().enumerate() {
                if cj == j {
                    continue;
                }
                minor[ri - 1][ci] = elem;
                ci += 1;
            }
        }
        let minor_det = det_3x3(&minor);
        if sign > 0 {
            acc += m[0][j] * minor_det;
        } else {
            acc -= m[0][j] * minor_det;
        }
    }
    acc
}

#[test]
fn test_mds_matrix_5x5_has_nonzero_determinant() {
    let mds = mds_matrix_5x5();
    let det = det_5x5(&mds);
    assert_ne!(det, F::ZERO, "5x5 MDS matrix must have nonzero determinant");
}

fn combinations_3(n: usize) -> Vec<[usize; 3]> {
    let mut out = Vec::new();
    for a in 0..n {
        for b in (a + 1)..n {
            for c in (b + 1)..n {
                out.push([a, b, c]);
            }
        }
    }
    out
}

#[test]
fn test_mds_matrix_5x5_all_3x3_submatrices_nonzero_determinant() {
    let mds = mds_matrix_5x5();
    for rows in combinations_3(5) {
        for cols in combinations_3(5) {
            let mut sub = vec![vec![F::ZERO; 3]; 3];
            for (i, &r) in rows.iter().enumerate() {
                for (j, &c) in cols.iter().enumerate() {
                    sub[i][j] = mds[r][c];
                }
            }
            let det = det_3x3(&sub);
            assert_ne!(
                det,
                F::ZERO,
                "Every 3x3 submatrix of MDS must have nonzero determinant"
            );
        }
    }
}
