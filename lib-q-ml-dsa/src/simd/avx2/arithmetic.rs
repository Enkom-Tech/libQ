use lib_q_intrinsics::*;

use crate::constants::{
    BITS_IN_LOWER_PART_OF_T,
    GAMMA2_V95_232,
    GAMMA2_V261_888,
    Gamma2,
};
use crate::simd::avx2::vector_type::Vec256;
use crate::simd::traits::{
    FIELD_MODULUS,
    INVERSE_OF_MODULUS_MOD_MONTGOMERY_R,
};

#[inline]
#[hax_lib::fstar::before(r#"open Spec.Intrinsics"#)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::requires(true)]
#[hax_lib::ensures(|result| fstar!(r#"
    forall i. if v (to_i32x8 $t i) < 0 
              then to_i32x8 $result i = to_i32x8 $t i +! $FIELD_MODULUS
              else to_i32x8 $result i = to_i32x8 $t i)) =
"#))]
#[allow(dead_code)]
fn to_unsigned_representatives_ret(t: &Vec256) -> Vec256 {
    hax_lib::fstar!("reveal_opaque_arithmetic_ops #i32_inttype)");

    let signs = mm256_srai_epi32::<31>(*t);
    let conditional_add_field_modulus = mm256_and_si256(signs, mm256_set1_epi32(FIELD_MODULUS));

    hax_lib::fstar!(r"logand_lemma $FIELD_MODULUS (mk_i32 0)");

    mm256_add_epi32(*t, conditional_add_field_modulus)
}

#[inline]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::requires(true)]
#[hax_lib::ensures(|_| fstar!(r#"
    forall i. if v (to_i32x8 $t i) < 0 
              then to_i32x8 tt_future i = to_i32x8 $t i +! $FIELD_MODULUS
              else to_i32x8 tt_future i = to_i32x8 $t i)) =
"#))]
#[allow(dead_code)]
fn to_unsigned_representatives(t: &mut Vec256) {
    *t = to_unsigned_representatives_ret(t);
}

#[inline]
pub(super) fn add(lhs: &mut Vec256, rhs: &Vec256) {
    *lhs = mm256_add_epi32(*lhs, *rhs);
}

#[inline]
pub(super) fn subtract(lhs: &mut Vec256, rhs: &Vec256) {
    *lhs = mm256_sub_epi32(*lhs, *rhs)
}

// Not using inline always here regresses performance significantly.
#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::ensures(|result| fstar!(r#"
    forall i. to_i32x8 ${result} i == 
              Spec.MLDSA.Math.mont_mul (to_i32x8 ${lhs} i) $constant
"#))]
pub(super) fn montgomery_multiply_by_constant(lhs: Vec256, constant: i32) -> Vec256 {
    hax_lib::fstar!("reveal_opaque (`%Spec.MLDSA.Math.mont_mul) (Spec.MLDSA.Math.mont_mul)");

    let rhs = mm256_set1_epi32(constant);
    let field_modulus = mm256_set1_epi32(FIELD_MODULUS);
    let inverse_of_modulus_mod_montgomery_r =
        mm256_set1_epi32(INVERSE_OF_MODULUS_MOD_MONTGOMERY_R as i32);

    let prod02 = mm256_mul_epi32(lhs, rhs);
    let prod13 = mm256_mul_epi32(
        mm256_shuffle_epi32::<0b11_11_01_01>(lhs),
        mm256_shuffle_epi32::<0b11_11_01_01>(rhs),
    );

    let k02 = mm256_mul_epi32(prod02, inverse_of_modulus_mod_montgomery_r);
    let k13 = mm256_mul_epi32(prod13, inverse_of_modulus_mod_montgomery_r);

    let c02 = mm256_mul_epi32(k02, field_modulus);
    let c13 = mm256_mul_epi32(k13, field_modulus);

    let res02 = mm256_sub_epi32(prod02, c02);
    let res13 = mm256_sub_epi32(prod13, c13);
    let res02_shifted = mm256_shuffle_epi32::<0b11_11_01_01>(res02);
    mm256_blend_epi32::<0b10101010>(res02_shifted, res13)
}

// Not using inline always here regresses performance significantly.
#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::requires(
    hax_lib::eq(field_modulus, mm256_set1_epi32(FIELD_MODULUS)).and(hax_lib::eq(
        inverse_of_modulus_mod_montgomery_r,
        mm256_set1_epi32(INVERSE_OF_MODULUS_MOD_MONTGOMERY_R as i32),
    ))
)]
#[hax_lib::ensures(|_| fstar!(r#"
    forall i. to_i32x8 ${lhs}_future i == 
              Spec.MLDSA.Math.mont_mul (to_i32x8 ${lhs} i) (to_i32x8 ${rhs} i)
"#))]
pub(super) fn montgomery_multiply_aux(
    field_modulus: Vec256,
    inverse_of_modulus_mod_montgomery_r: Vec256,
    lhs: &mut Vec256,
    rhs: &Vec256,
) {
    hax_lib::fstar!("reveal_opaque (`%Spec.MLDSA.Math.mont_mul) (Spec.MLDSA.Math.mont_mul)");

    let prod02 = mm256_mul_epi32(*lhs, *rhs);
    let prod13 = mm256_mul_epi32(
        mm256_shuffle_epi32::<0b11_11_01_01>(*lhs),
        mm256_shuffle_epi32::<0b11_11_01_01>(*rhs),
    );

    let k02 = mm256_mul_epi32(prod02, inverse_of_modulus_mod_montgomery_r);
    let k13 = mm256_mul_epi32(prod13, inverse_of_modulus_mod_montgomery_r);

    let c02 = mm256_mul_epi32(k02, field_modulus);
    let c13 = mm256_mul_epi32(k13, field_modulus);

    let res02 = mm256_sub_epi32(prod02, c02);
    let res13 = mm256_sub_epi32(prod13, c13);
    let res02_shifted = mm256_shuffle_epi32::<0b11_11_01_01>(res02);
    *lhs = mm256_blend_epi32::<0b10101010>(res02_shifted, res13);
}

#[inline(always)]
pub(super) fn montgomery_multiply(lhs: &mut Vec256, rhs: &Vec256) {
    let field_modulus = mm256_set1_epi32(FIELD_MODULUS);
    let inverse_of_modulus_mod_montgomery_r =
        mm256_set1_epi32(INVERSE_OF_MODULUS_MOD_MONTGOMERY_R as i32);
    montgomery_multiply_aux(field_modulus, inverse_of_modulus_mod_montgomery_r, lhs, rhs);
}

// Not using inline always here regresses performance significantly.
#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::requires(
    hax_lib::eq(inverse_of_modulus_mod_montgomery_r, mm256_set1_epi32(INVERSE_OF_MODULUS_MOD_MONTGOMERY_R as i32))
)]
#[hax_lib::ensures(|_| fstar!(r#"
    forall i. to_i32x8 ${simd_unit}_future i == 
              Spec.MLDSA.Math.mont_mul (to_i32x8 ${simd_unit} i) (2 ^! $SHIFT_BY)
"#))]
pub(super) fn shift_left_then_reduce<const SHIFT_BY: i32>(simd_unit: &mut Vec256) {
    hax_lib::fstar!("reveal_opaque (`%Spec.MLDSA.Math.mont_mul) (Spec.MLDSA.Math.mont_mul)");

    let inverse_of_modulus_mod_montgomery_r =
        mm256_set1_epi32(INVERSE_OF_MODULUS_MOD_MONTGOMERY_R as i32);

    let shifted = mm256_slli_epi32::<SHIFT_BY>(*simd_unit);
    let prod02 = mm256_mul_epi32(shifted, inverse_of_modulus_mod_montgomery_r);
    let prod13 = mm256_mul_epi32(
        mm256_shuffle_epi32::<0b11_11_01_01>(shifted),
        mm256_shuffle_epi32::<0b11_11_01_01>(inverse_of_modulus_mod_montgomery_r),
    );

    let field_modulus = mm256_set1_epi32(FIELD_MODULUS);
    let k02 = mm256_mul_epi32(prod02, inverse_of_modulus_mod_montgomery_r);
    let k13 = mm256_mul_epi32(prod13, inverse_of_modulus_mod_montgomery_r);

    let c02 = mm256_mul_epi32(k02, field_modulus);
    let c13 = mm256_mul_epi32(k13, field_modulus);

    let res02 = mm256_sub_epi32(shifted, c02);
    let res13 = mm256_sub_epi32(shifted, c13);
    let res02_shifted = mm256_shuffle_epi32::<0b11_11_01_01>(res02);
    *simd_unit = mm256_blend_epi32::<0b10101010>(res02_shifted, res13);
}

#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::fstar::options("--fuel 0 --ifuel 0 --z3rlimit 300")]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::requires(fstar!(r#"v $bound > 0 /\ 
    (forall i. Spec.Utils.is_i32b (v $FIELD_MODULUS - 1) (to_i32x8 ${simd_unit} i))"#))]
#[hax_lib::ensures(|result| fstar!(r#"
    $result == false <==> 
        (forall i. Spec.Utils.is_i32b (v $bound - 1) (to_i32x8 ${simd_unit} i))"#))]
pub(super) fn infinity_norm_exceeds(simd_unit: &Vec256, bound: i32) -> bool {
    hax_lib::fstar!("reveal_opaque_arithmetic_ops #i32_inttype)");

    let absolute_values = mm256_abs_epi32(*simd_unit);

    // We will test if |simd_unit| > bound - 1, because if this is the case then
    // it follows that |simd_unit| >= bound
    let bound = mm256_set1_epi32(bound - 1);

    let compare_with_bound = mm256_cmpgt_epi32(absolute_values, bound);

    // If every lane of |result| is 0, all coefficients are <= bound - 1
    let result = mm256_testz_si256(compare_with_bound, compare_with_bound);

    hax_lib::fstar!(r"logand_lemma_forall #i32_inttype");

    result != 1
}

// Not using inline always here regresses performance significantly.
#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::fstar::verification_status(lax)]
#[hax_lib::requires(fstar!(r#"(v $gamma2 == v $GAMMA2_V261_888 \/ v $gamma2 == v $GAMMA2_V95_232) /\
    (forall i. Spec.Utils.is_i32b (v $FIELD_MODULUS - 1) (to_i32x8 $r i))"#))]
#[hax_lib::ensures(|(r0,r1)| fstar!(r#"
    forall i.
    let (r0_s, r1_s) = Spec.MLDSA.Math.decompose_spec $gamma2 (to_i32x8 $r i) in
    to_i32x8 ${r0}_future i = r0_s /\ 
    to_i32x8 ${r1}_future i = r1_s"#))]
pub(super) fn decompose(gamma2: Gamma2, r: &Vec256, r0: &mut Vec256, r1: &mut Vec256) {
    hax_lib::fstar!("reveal_opaque (`%Spec.MLDSA.Math.decompose) (Spec.MLDSA.Math.decompose)");

    // Convert the signed representative to the standard unsigned one.
    // This is equivalent to: r = r + ((r >> 31) & FIELD_MODULUS)
    let signs = mm256_srai_epi32::<31>(*r);
    let r_unsigned = mm256_add_epi32(*r, mm256_and_si256(signs, mm256_set1_epi32(FIELD_MODULUS)));

    // Compute ⌈r / 128⌉
    let ceil_of_r_by_128 = mm256_add_epi32(r_unsigned, mm256_set1_epi32(127));
    let ceil_of_r_by_128 = mm256_srai_epi32::<7>(ceil_of_r_by_128);

    // Compute r1 based on gamma2
    let r1_result = match gamma2 {
        GAMMA2_V95_232 => {
            // We approximate 1 / 1488 as: ⌊2²⁴ / 1488⌋ / 2²⁴ = 11,275 / 2²⁴
            let result = mm256_mullo_epi32(ceil_of_r_by_128, mm256_set1_epi32(11_275));
            let result = mm256_add_epi32(result, mm256_set1_epi32(1 << 23));
            let result = mm256_srai_epi32::<24>(result);

            // For the corner-case a₁ = (q-1)/α = 44, we have to set a₁=0.
            let mask = mm256_cmpeq_epi32(result, mm256_set1_epi32(44));
            mm256_andnot_si256(mask, result)
        }
        GAMMA2_V261_888 => {
            // We approximate 1 / 4092 as: ⌊2²² / 4092⌋ / 2²² = 1025 / 2²²
            let result = mm256_mullo_epi32(ceil_of_r_by_128, mm256_set1_epi32(1025));
            let result = mm256_add_epi32(result, mm256_set1_epi32(1 << 21));
            let result = mm256_srai_epi32::<22>(result);

            // For the corner-case a₁ = (q-1)/α = 16, we have to set a₁=0.
            mm256_and_si256(result, mm256_set1_epi32(15))
        }
        _ => unreachable!(),
    };

    let alpha = gamma2 * 2;
    let mut r0_result = mm256_sub_epi32(
        r_unsigned,
        mm256_mullo_epi32(r1_result, mm256_set1_epi32(alpha)),
    );

    // In the corner-case, when we set a₁=0, we will incorrectly
    // have a₀ > (q-1)/2 and we'll need to subtract q. As we
    // return a₀ + q, that comes down to adding q if a₀ < (q-1)/2.
    let threshold = mm256_set1_epi32((FIELD_MODULUS - 1) / 2);
    let mask = mm256_cmpgt_epi32(r0_result, threshold);
    r0_result = mm256_sub_epi32(
        r0_result,
        mm256_and_si256(mask, mm256_set1_epi32(FIELD_MODULUS)),
    );

    *r0 = r0_result;
    *r1 = r1_result;
}

#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::fstar::verification_status(lax)]
#[hax_lib::fstar::verification_status(lax)]
pub(super) fn compute_hint(low: &Vec256, high: &Vec256, gamma2: i32, hint: &mut Vec256) -> usize {
    hax_lib::fstar!(
        "reveal_opaque (`%Spec.MLDSA.Math.compute_hint) (Spec.MLDSA.Math.compute_hint)"
    );

    let r = mm256_add_epi32(*low, *high);
    let ceil_of_r_by_128 = mm256_add_epi32(r, mm256_set1_epi32(127));
    let _r_shifted = mm256_srai_epi32::<7>(ceil_of_r_by_128);

    let minus_gamma2 = mm256_set1_epi32(-gamma2);
    let gamma2_vec = mm256_set1_epi32(gamma2);

    let low_within_bound = mm256_cmpgt_epi32(mm256_abs_epi32(*low), gamma2_vec);
    let low_equals_minus_gamma2 = mm256_cmpeq_epi32(*low, minus_gamma2);
    let low_equals_minus_gamma2_and_high_is_nonzero =
        mm256_sign_epi32(low_equals_minus_gamma2, *high);

    *hint = mm256_or_si256(
        low_within_bound,
        low_equals_minus_gamma2_and_high_is_nonzero,
    );

    let hints_mask = mm256_movemask_ps(mm256_castsi256_ps(*hint));
    *hint = mm256_and_si256(*hint, mm256_set1_epi32(0x1));

    hints_mask as usize
}

#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::fstar::verification_status(lax)]
#[hax_lib::fstar::verification_status(lax)]
pub(super) fn use_hint(gamma2: Gamma2, r: &Vec256, hint: &mut Vec256) {
    hax_lib::fstar!("reveal_opaque (`%Spec.MLDSA.Math.use_hint) (Spec.MLDSA.Math.use_hint)");

    let mut r0 = mm256_setzero_si256();
    let mut r1 = mm256_setzero_si256();
    decompose(gamma2, r, &mut r0, &mut r1);

    let all_zeros = mm256_setzero_si256();
    let _negate_hints = vec256_blendv_epi32(all_zeros, *hint, r0);

    let alpha = if gamma2 == GAMMA2_V261_888 { 261 } else { 95 };
    let r0_tmp = mm256_mullo_epi32(r1, mm256_set1_epi32(alpha));
    let r0_tmp = mm256_sub_epi32(*r, r0_tmp);
    let field_modulus_and_mask = mm256_set1_epi32(FIELD_MODULUS - 1);
    r0 = mm256_sub_epi32(r0_tmp, field_modulus_and_mask);

    let minus_gamma2 = mm256_set1_epi32(-gamma2);
    let gamma2_vec = mm256_set1_epi32(gamma2);

    let low_within_bound = mm256_cmpgt_epi32(mm256_abs_epi32(r0), gamma2_vec);
    let low_equals_minus_gamma2 = mm256_cmpeq_epi32(r0, minus_gamma2);
    let low_equals_minus_gamma2_and_high_is_nonzero = mm256_sign_epi32(low_equals_minus_gamma2, r1);

    *hint = mm256_or_si256(
        low_within_bound,
        low_equals_minus_gamma2_and_high_is_nonzero,
    );

    let r1_plus_hints = mm256_add_epi32(r1, *hint);
    let max_hint = if gamma2 == GAMMA2_V261_888 { 261 } else { 95 };
    let greater_than_or_equal_to_max = mm256_cmpge_epi32(r1_plus_hints, mm256_set1_epi32(max_hint));

    if gamma2 == GAMMA2_V261_888 {
        *hint = vec256_blendv_epi32(r1_plus_hints, all_zeros, greater_than_or_equal_to_max);
    } else {
        *hint = mm256_and_si256(r1_plus_hints, mm256_set1_epi32(15));
    }
}

#[inline(always)]
#[hax_lib::fstar::before(r#"[@@ "opaque_to_smt"]"#)]
#[hax_lib::ensures(|_| fstar!(r#"
    forall i. to_i32x8 ${r0}_future i == Spec.MLDSA.Math.power2round (to_i32x8 ${r0} i) /\
              to_i32x8 ${r1}_future i == Spec.MLDSA.Math.power2round_remainder (to_i32x8 ${r0} i)
"#))]
pub(super) fn power2round(r0: &mut Vec256, r1: &mut Vec256) {
    hax_lib::fstar!("reveal_opaque (`%Spec.MLDSA.Math.power2round) (Spec.MLDSA.Math.power2round)");

    // Convert the signed representative to the standard unsigned one.
    // This is equivalent to: t = t + ((t >> 31) & FIELD_MODULUS)
    let signs = mm256_srai_epi32::<31>(*r0);
    let t = mm256_add_epi32(*r0, mm256_and_si256(signs, mm256_set1_epi32(FIELD_MODULUS)));

    // t1 = ⌊(t - 1)/2^{BITS_IN_LOWER_PART_OF_T} + 1/2⌋
    let t1 = mm256_add_epi32(
        t,
        mm256_set1_epi32((1 << (BITS_IN_LOWER_PART_OF_T - 1)) - 1),
    );
    let t1 = mm256_srai_epi32::<{ BITS_IN_LOWER_PART_OF_T as i32 }>(t1);

    // t0 = t - (2^{BITS_IN_LOWER_PART_OF_T} * t1)
    let tmp = mm256_slli_epi32::<{ BITS_IN_LOWER_PART_OF_T as i32 }>(t1);
    *r0 = mm256_sub_epi32(t, tmp);
    *r1 = t1;
}
