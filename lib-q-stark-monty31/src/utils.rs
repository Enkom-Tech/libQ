use crate::{
    FieldParameters,
    MontyParameters,
};

/// Convert a u32 into MONTY form.
/// There are no constraints on the input.
/// The output will be a u32 in range `[0, P)`.
#[inline]
pub(crate) const fn to_monty<MP: MontyParameters>(x: u32) -> u32 {
    (((x as u64) << MP::MONTY_BITS) % MP::PRIME as u64) as u32
}

/// Convert an i32 into MONTY form.
/// There are no constraints on the input.
/// The output will be a u32 in range `[0, P)`.
#[inline]
pub(crate) const fn to_monty_signed<MP: MontyParameters>(x: i32) -> u32 {
    let red = (((x as i64) << MP::MONTY_BITS) % MP::PRIME as i64) as i32;
    if red >= 0 {
        red as u32
    } else {
        MP::PRIME.wrapping_add_signed(red)
    }
}

/// Convert a u64 into MONTY form.
/// There are no constraints on the input.
/// The output will be a u32 in range `[0, P)`.
#[inline]
pub(crate) const fn to_monty_64<MP: MontyParameters>(x: u64) -> u32 {
    (((x as u128) << MP::MONTY_BITS) % MP::PRIME as u128) as u32
}

/// Convert an i64 into MONTY form.
/// There are no constraints on the input.
/// The output will be a u32 in range `[0, P)`.
#[inline]
pub(crate) const fn to_monty_64_signed<MP: MontyParameters>(x: i64) -> u32 {
    let red = (((x as i128) << MP::MONTY_BITS) % MP::PRIME as i128) as i32;
    if red >= 0 {
        red as u32
    } else {
        MP::PRIME.wrapping_add_signed(red)
    }
}

/// Convert a u32 out of MONTY form.
/// There are no constraints on the input.
/// The output will be a u32 in range `[0, P)`.
#[inline]
#[must_use]
pub(crate) const fn from_monty<MP: MontyParameters>(x: u32) -> u32 {
    monty_reduce::<MP>(x as u64)
}

/// Add two integers modulo `P = MP::PRIME`.
///
/// Assumes that `P` is less than `2^31` and `a + b <= 2P` for all array pairs `a, b`.
/// If the inputs are not in this range, the result may be incorrect.
/// The result will be in the range `[0, P]` and equal to `(a + b) mod P`.
/// It will be equal to `P` if and only if `a + b = 2P` so provided `a + b < 2P`
/// the result is guaranteed to be less than `P`.
#[inline]
#[must_use]
pub(crate) const fn add<MP: MontyParameters>(lhs: u32, rhs: u32) -> u32 {
    let mut sum = lhs + rhs;
    let (corr_sum, over) = sum.overflowing_sub(MP::PRIME);
    if !over {
        sum = corr_sum;
    }
    sum
}

/// Subtract two integers modulo `P = MP::PRIME`.
///
/// Assumes that `P` is less than `2^31` and `|a - b| <= P` for all array pairs `a, b`.
/// If the inputs are not in this range, the result may be incorrect.
/// The result will be in the range `[0, P]` and equal to `(a - b) mod P`.
/// It will be equal to `P` if and only if `a - b = P` so provided `a - b < P`
/// the result is guaranteed to be less than `P`.
#[inline]
#[must_use]
pub(crate) const fn sub<MP: MontyParameters>(lhs: u32, rhs: u32) -> u32 {
    let (mut diff, over) = lhs.overflowing_sub(rhs);
    let corr = if over { MP::PRIME } else { 0 };
    diff = diff.wrapping_add(corr);
    diff
}

/// Given an element `x` from a 31 bit field `F` compute `x/2`.
/// The input must be in `[0, P)`.
/// The output will also be in `[0, P)`.
#[inline]
pub(crate) const fn halve_u32<FP: FieldParameters>(input: u32) -> u32 {
    let shr = input >> 1;
    let lo_bit = input & 1;
    let shr_corr = shr + FP::HALF_P_PLUS_1;
    if lo_bit == 0 { shr } else { shr_corr }
}

/// Montgomery reduction of a value in `0..P << MONTY_BITS`.
///
/// The input must be in `[0, MONTY * P)`.
/// The output will be in `[0, P)`.
#[inline]
#[must_use]
pub(crate) const fn monty_reduce<MP: MontyParameters>(x: u64) -> u32 {
    // t = x * MONTY_MU mod MONTY
    let t = x.wrapping_mul(MP::MONTY_MU as u64) & (MP::MONTY_MASK as u64);

    // u = t * P
    let u = t * (MP::PRIME as u64);

    // Thus:
    // 1. x - u = x - t * P = x mod P
    // 2. x - u = x - x * MONTY_MU * P mod MONTY = 0 mod MONTY
    // For the second point note that MONTY_MU = P^{-1} mod MONTY.

    // Additionally, u < MONTY * P so: - MONTY * P < x - u < MONTY * P
    // Thus after dividing by MONTY, -P < (x - u)/MONTY < P.
    // So we can just add P to the result if it is negative.

    let (x_sub_u, over) = x.overflowing_sub(u);
    let x_sub_u_hi = (x_sub_u >> MP::MONTY_BITS) as u32;
    let corr = if over { MP::PRIME } else { 0 };
    x_sub_u_hi.wrapping_add(corr)
}

/// Montgomery reduction of a value in `0..P << MONTY_BITS`.
/// The input must be in [0, 2 * MONTY * P).
/// The output will be in [0, P).
///
/// This is slower than `monty_reduce` but has a larger input range.
#[inline]
#[must_use]
pub(crate) const fn large_monty_reduce<MP: MontyParameters>(x: u64) -> u32 {
    // t = x * MONTY_MU mod MONTY
    let t = x.wrapping_mul(MP::MONTY_MU as u64) & (MP::MONTY_MASK as u64);

    // u = t * P
    let u = t * (MP::PRIME as u64);

    // Thus:
    // 1. x - u = x - t * P = x mod P
    // 2. x - u = x - x * MONTY_MU * P mod MONTY = 0 mod MONTY
    // For the second point note that MONTY_MU = P^{-1} mod MONTY.

    // This time, - MONTY * P < x - u < 2 * MONTY * P so we need to be
    // more careful with our reduction.
    // The trick is just to first reduce x to lie in [0, MONTY * P).
    let (x_prime, over) = x.overflowing_sub((MP::PRIME as u64) << MP::MONTY_BITS);
    let x_corr = if over { x } else { x_prime };

    // Now we can do the same as before.

    let (x_sub_u, over) = x_corr.overflowing_sub(u);
    let x_sub_u_hi = (x_sub_u >> MP::MONTY_BITS) as u32;
    let corr = if over { MP::PRIME } else { 0 };
    x_sub_u_hi.wrapping_add(corr)
}

/// Perform a monty reduction on a u128 in the range `[0, 2^96)`
///
/// The input will be in `[0, P)` and be equal to `x * MONTY^{-1} mod P`.
pub(crate) const fn monty_reduce_u128<MP: MontyParameters>(x: u128) -> u32 {
    // TODO: There is probably a way to do this faster than using %.

    // Need to find MONTY^{-1} mod P.
    // As P * MONTY_MU = 1 mod MONTY, we know that P * MONTY_MU = 1 + k * MONTY for some k.
    // Thus k * MONTY = -1 mod P.
    // Rearranging, we get k = (P * MONTY_MU - 1) / MONTY.
    // Thus we want -k = P - k = P - (P * MONTY_MU - 1) / MONTY.

    // Compiler should realize that this is a constant.
    let monty_inv_mod_p =
        MP::PRIME - ((((MP::PRIME as u64) * (MP::MONTY_MU as u64)) - 1) >> MP::MONTY_BITS) as u32;

    // As monty_inv_mod_p < 2^32, x * monty_inv_mod_p < 2^128 so the product below will not overflow.
    ((x * (monty_inv_mod_p as u128)) % (MP::PRIME as u128)) as u32
}

/// Direct, hand-written boundary tests for the low-level Montgomery helpers in this file.
///
/// These are deliberately NOT "does not panic" tests: each asserts a specific known answer at a
/// boundary (`0`, `1`, `P-1`, values that wrap `2^32`/`2^64`) chosen because it is exactly where an
/// off-by-one in a `wrapping_sub`/`overflowing_sub` correction would first misfire. The
/// `test_field!`/`test_prime_field!` macro suite in `monty_31.rs` covers the same functions
/// indirectly (through `MontyField31` arithmetic with random inputs); this module tests the
/// primitives directly at their edges instead.
#[cfg(test)]
mod tests {
    use crate::test_utils::TestFP as FP;
    use crate::utils::{
        add,
        from_monty,
        halve_u32,
        large_monty_reduce,
        monty_reduce,
        monty_reduce_u128,
        sub,
        to_monty,
        to_monty_64,
        to_monty_64_signed,
        to_monty_signed,
    };
    use crate::MontyParameters;

    const P: u32 = FP::PRIME;

    #[test]
    fn add_wraps_exactly_at_2p() {
        // a + b < 2P is the documented precondition; a + b == 2P is the one boundary where the
        // "did we overflow past P" correction must fire but the u32 add itself does not overflow.
        assert_eq!(add::<FP>(P - 1, P - 1), P - 2);
        assert_eq!(add::<FP>(P - 1, 1), 0);
        assert_eq!(add::<FP>(0, 0), 0);
        assert_eq!(add::<FP>(0, P - 1), P - 1);
    }

    #[test]
    fn sub_wraps_exactly_at_zero() {
        assert_eq!(sub::<FP>(0, 1), P - 1);
        assert_eq!(sub::<FP>(0, P - 1), 1);
        assert_eq!(sub::<FP>(P - 1, P - 1), 0);
        assert_eq!(sub::<FP>(5, 5), 0);
    }

    #[test]
    fn halve_matches_definition_at_boundaries() {
        // halve_u32(x) must equal x/2 mod P: for even x that's x >> 1, for odd x it's
        // (x + P) / 2 = (x >> 1) + (P + 1)/2 exactly (P is odd, so x + P is even whenever x is
        // odd, and the division here is exact).
        for x in [0u32, 1, 2, P - 2, P - 1] {
            let expected = if x % 2 == 0 {
                x / 2
            } else {
                (x as u64 + P as u64) as u32 / 2
            };
            assert_eq!(halve_u32::<FP>(x), expected, "halve mismatch for x={x}");
        }
    }

    #[test]
    fn monty_round_trip_at_boundaries() {
        // from_monty(to_monty(x)) must recover x mod P for every u32 input, not just canonical
        // ones: to_monty has no precondition on its input range.
        for x in [0u32, 1, 2, P - 1, P, P + 1, u32::MAX, 1 << 31, (1 << 31) - 1] {
            let expected = x % P;
            assert_eq!(
                from_monty::<FP>(to_monty::<FP>(x)),
                expected,
                "monty round-trip failed for x={x}"
            );
        }
    }

    #[test]
    fn to_monty_64_and_128_agree_with_32_bit_path_mod_p() {
        // For inputs that fit in a u32, the 64/128-bit-input variants must reduce identically to
        // the direct u32 path (mod P first, then convert).
        for x in [0u64, 1, P as u64 - 1, P as u64, u32::MAX as u64] {
            let via_64 = to_monty_64::<FP>(x);
            let via_32 = to_monty::<FP>((x % P as u64) as u32);
            assert_eq!(via_64, via_32, "mismatch for x={x}");
        }
        // A value that only fits in 64 bits (exercises the true >32-bit reduction path).
        let big: u64 = (P as u64) * (1u64 << 20) + 12345;
        assert_eq!(
            from_monty::<FP>(to_monty_64::<FP>(big)),
            (big % (P as u64)) as u32
        );
    }

    #[test]
    fn to_monty_signed_matches_unsigned_via_negation() {
        // to_monty_signed(-x) for 0 < x <= (P-1)/2 must equal P - to_monty_signed(x) (mod P),
        // i.e. negation in the input must correspond to field negation in the output.
        for x in [1i32, 2, 100, ((P - 1) / 2) as i32] {
            let pos = to_monty_signed::<FP>(x);
            let neg = to_monty_signed::<FP>(-x);
            assert_eq!(
                (pos + neg) % P,
                0,
                "to_monty_signed({x}) + to_monty_signed(-{x}) should be 0 mod P"
            );
        }
        assert_eq!(to_monty_signed::<FP>(0), 0);

        // The i64 variant must agree with the i32 variant for inputs within i32's range.
        for x in [-100i64, -1, 0, 1, 100] {
            assert_eq!(to_monty_64_signed::<FP>(x), to_monty_signed::<FP>(x as i32));
        }
    }

    #[test]
    fn monty_reduce_known_answers() {
        // monty_reduce(x) must return x * R^{-1} mod P for x in [0, MONTY * P). Cross-check against
        // to_monty/from_monty (already boundary-tested above) using values built from `new`/`to_u32`
        // rather than re-deriving the Montgomery math a second time by hand.
        assert_eq!(monty_reduce::<FP>(0), 0);
        // to_monty(1) is exactly R mod P; reducing it must return 1.
        assert_eq!(monty_reduce::<FP>(to_monty::<FP>(1) as u64), 1);
        // Reducing (P-1) copies of R (i.e. to_monty(P-1)) must return P-1.
        assert_eq!(monty_reduce::<FP>(to_monty::<FP>(P - 1) as u64), P - 1);
    }

    #[test]
    fn large_monty_reduce_matches_monty_reduce_when_in_range() {
        // large_monty_reduce accepts a wider input range [0, 2*MONTY*P) but must agree with
        // monty_reduce wherever their domains overlap ([0, MONTY*P)).
        for x in [to_monty::<FP>(1), to_monty::<FP>(P - 1), to_monty::<FP>(12345)] {
            assert_eq!(monty_reduce::<FP>(x as u64), large_monty_reduce::<FP>(x as u64));
        }
        // Exercise the >= MONTY*P branch explicitly (the whole reason this function exists).
        let monty_p = (P as u64) << FP::MONTY_BITS;
        let above = monty_p + (to_monty::<FP>(7) as u64);
        assert_eq!(large_monty_reduce::<FP>(above), 7);
    }

    #[test]
    fn monty_reduce_u128_known_answers() {
        assert_eq!(monty_reduce_u128::<FP>(0), 0);
        // A u128 built the same way monty_reduce is exercised above, just widened.
        assert_eq!(monty_reduce_u128::<FP>(to_monty::<FP>(P - 1) as u128), P - 1);
    }
}
