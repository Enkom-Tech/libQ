//! MAYO_2 parameters (NIST additional-signatures round 2).
//!
//! Values match the round-2 specification and the authors' reference
//! implementation (`MAYO-C`, `include/mayo.h`). The whole crate is written
//! against these constants; other parameter sets (MAYO_1/3/5) would need
//! `M % 16 == 0` assumptions in `mvec`/`core` revisited (MAYO_2 is the only
//! set where `m` is a multiple of 16, which makes the packed representation
//! byte-exact with the wire encoding).

/// Number of variables `n`.
pub const N: usize = 81;
/// Dimension of the target space `m` (number of equations).
pub const M: usize = 64;
/// Number of oil variables `o`.
pub const O: usize = 17;
/// Number of vinegar variables `v = n - o`.
pub const V: usize = N - O;
/// Whipping parameter `k`.
pub const K: usize = 4;
/// Columns of the linear system `A`: `k*o + 1`.
pub const A_COLS: usize = K * O + 1;

/// `u64` limbs per m-vector: `ceil(m / 16)` (16 nibbles per limb).
pub const M_VEC_LIMBS: usize = M.div_ceil(16);

/// Bytes of an encoded m-vector (`m/2`).
pub const M_BYTES: usize = 32;
/// Bytes of the encoded oil matrix `O` (`v*o/2`).
pub const O_BYTES: usize = 544;
/// Bytes of one encoded vinegar vector (`v/2`).
pub const V_BYTES: usize = 32;
/// Bytes of the encoded `r` vector (`ceil(k*o/2)`).
pub const R_BYTES: usize = 34;
/// Bytes of the packed `P1` (upper-triangular v x v of m-vectors).
pub const P1_BYTES: usize = 66560;
/// Bytes of the packed `P2` (v x o of m-vectors).
pub const P2_BYTES: usize = 34816;
/// Bytes of the packed `P3` (upper-triangular o x o of m-vectors).
pub const P3_BYTES: usize = 4896;

/// Compact secret key size (the seed).
pub const CSK_BYTES: usize = 24;
/// Compact public key size (`pk_seed || P3`).
pub const CPK_BYTES: usize = 4912;
/// Signature size (`ceil(n*k/2) || salt`).
pub const SIG_BYTES: usize = 186;

/// Salt length.
pub const SALT_BYTES: usize = 24;
/// Message digest length.
pub const DIGEST_BYTES: usize = 32;
/// Public-key seed length.
pub const PK_SEED_BYTES: usize = 16;
/// Secret-key seed length.
pub const SK_SEED_BYTES: usize = 24;

/// `u64` limbs of `P1`: `v*(v+1)/2` m-vectors.
pub const P1_LIMBS: usize = V * (V + 1) / 2 * M_VEC_LIMBS;
/// `u64` limbs of `P2`: `v*o` m-vectors.
pub const P2_LIMBS: usize = V * O * M_VEC_LIMBS;
/// `u64` limbs of `P3`: `o*(o+1)/2` m-vectors.
pub const P3_LIMBS: usize = O * (O + 1) / 2 * M_VEC_LIMBS;

/// Tail coefficients of `f(z) = z^64 + x^3*z^3 + x*z^2 + x^3` over GF(16).
pub const F_TAIL: [u8; 4] = [8, 0, 2, 8];

const _: () = {
    assert!(P1_BYTES == P1_LIMBS * 8);
    assert!(P2_BYTES == P2_LIMBS * 8);
    assert!(P3_BYTES == P3_LIMBS * 8 - (M_VEC_LIMBS * 8 - M_BYTES) * O * (O + 1) / 2);
    assert!(CPK_BYTES == PK_SEED_BYTES + P3_BYTES);
    assert!(SIG_BYTES == (N * K).div_ceil(2) + SALT_BYTES);
    assert!(
        M.is_multiple_of(16),
        "core assumes m is a multiple of 16 (MAYO_2)"
    );
    assert!(O_BYTES == V * O / 2);
    assert!(R_BYTES == (K * O).div_ceil(2));
};
