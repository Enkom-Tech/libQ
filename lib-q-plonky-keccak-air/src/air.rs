use core::array;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::PrimeCharacteristicRing;

use crate::columns::{
    KeccakColsRef,
    NUM_KECCAK_COLS,
};
use crate::constants::rc_value_bit;
use crate::round_flags::eval_round_flags;
use crate::{
    BITS_PER_LIMB,
    NUM_ROUNDS,
    NUM_ROUNDS_MIN_1,
    U64_LIMBS,
};

/// Assumes the field size is at least 16 bits.
#[derive(Debug)]
pub struct KeccakAir {}

impl<F> BaseAir<F> for KeccakAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }
}

impl<AB: AirBuilder> Air<AB> for KeccakAir {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        eval_round_flags(builder);

        let main = builder.main();
        let local = KeccakColsRef::from_row_slice(main.current_slice());
        let next = KeccakColsRef::from_row_slice(main.next_slice());

        let first_step = local.step_flags(0);
        let final_step = local.step_flags(NUM_ROUNDS_MIN_1);
        let not_final_step = AB::Expr::ONE - final_step;

        // If this is the first step, the input A must match the preimage.
        for y in 0..5 {
            for x in 0..5 {
                builder
                    .when(first_step)
                    .assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                        local.preimage(y, x, limb) - local.a(y, x, limb)
                    }));
            }
        }

        // If this is not the final step, the local and next preimages must match.
        for y in 0..5 {
            for x in 0..5 {
                builder
                    .when(not_final_step.clone())
                    .when_transition()
                    .assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                        local.preimage(y, x, limb) - next.preimage(y, x, limb)
                    }));
            }
        }

        builder.assert_bool(local.export());

        builder
            .when(not_final_step.clone())
            .assert_zero(local.export());

        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
        for x in 0..5 {
            builder.assert_bools::<64, _>(array::from_fn(|z| local.c(x, z)));
            builder.assert_zeros::<64, _>(array::from_fn(|z| {
                let xor = local.c(x, z).into().xor3(
                    &local.c((x + 4) % 5, z).into(),
                    &local.c((x + 1) % 5, (z + 63) % 64).into(),
                );
                local.c_prime(x, z) - xor
            }));
        }

        // Check that the input limbs are consistent with A' and D.
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z: usize| {
                    local
                        .a_prime(y, x, z)
                        .into()
                        .xor3(&local.c(x, z).into(), &local.c_prime(x, z).into())
                };

                builder.assert_bools::<64, _>(array::from_fn(|z| local.a_prime(y, x, z)));

                builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                    computed_limb - local.a(y, x, limb)
                }));
            }
        }

        // xor_{i=0}^4 A'[x, i, z] = C'[x, z]
        for x in 0..5 {
            let four = AB::Expr::TWO.double();
            builder.assert_zeros::<64, _>(array::from_fn(|z| {
                let sum: AB::Expr = (0..5).map(|y| local.a_prime(y, x, z).into()).sum();
                let diff = sum - local.c_prime(x, z);
                diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - four.clone())
            }));
        }

        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z| {
                    let andn = local
                        .b((x + 1) % 5, y, z)
                        .into()
                        .andn(&local.b((x + 2) % 5, y, z).into());
                    andn.xor(&local.b(x, y, z).into())
                };
                builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                    computed_limb - local.a_prime_prime(y, x, limb)
                }));
            }
        }

        // A'''[0, 0] = A''[0, 0] XOR RC
        builder.assert_bools::<64, _>(array::from_fn(|z| local.a_prime_prime_0_0_bits(z)));
        builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
            let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB..
                (limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::ZERO, |acc, z| {
                    acc.double() + local.a_prime_prime_0_0_bits(z)
                });
            computed_a_prime_prime_0_0_limb - local.a_prime_prime(0, 0, limb)
        }));

        let get_xored_bit = |i| {
            let mut rc_bit_i = AB::Expr::ZERO;
            for r in 0..NUM_ROUNDS {
                let this_round = local.step_flags(r);
                let this_round_constant = AB::Expr::from_bool(rc_value_bit(r, i) != 0);
                rc_bit_i += this_round * this_round_constant;
            }

            rc_bit_i.xor(&local.a_prime_prime_0_0_bits(i).into())
        };

        builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
            let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB..
                (limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_xored_bit(z));
            computed_a_prime_prime_prime_0_0_limb - local.a_prime_prime_prime_0_0_limbs(limb)
        }));

        // Enforce that this round's output equals the next round's input.
        for x in 0..5 {
            for y in 0..5 {
                builder
                    .when_transition()
                    .when(not_final_step.clone())
                    .assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                        local.a_prime_prime_prime(y, x, limb) - next.a(y, x, limb)
                    }));
            }
        }
    }
}
