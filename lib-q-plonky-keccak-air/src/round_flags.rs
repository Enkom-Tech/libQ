use core::array;

use lib_q_stark_air::{
    AirBuilder,
    WindowAccess,
};

use crate::columns::KeccakColsRef;
use crate::{
    NUM_ROUNDS,
    NUM_ROUNDS_MIN_1,
};

/// Evaluate and constrain round flags for each row of the Keccak AIR.
///
/// - Enforces that in the first row, `step_flags[0]` is 1, and all other flags are 0.
/// - Enforces that at each transition, the flags rotate forward (circular shift).
/// - Guarantees that exactly one round flag is active per row, following Keccak's round schedule.
#[inline]
pub(crate) fn eval_round_flags<AB: AirBuilder>(builder: &mut AB) {
    let main = builder.main();

    let local = KeccakColsRef::from_row_slice(main.current_slice());
    let next = KeccakColsRef::from_row_slice(main.next_slice());

    builder.when_first_row().assert_one(local.step_flags(0));
    builder
        .when_first_row()
        .assert_zeros::<NUM_ROUNDS_MIN_1, _>(array::from_fn(|i| local.step_flags(i + 1)));

    builder
        .when_transition()
        .assert_zeros::<NUM_ROUNDS, _>(array::from_fn(|i| {
            local.step_flags(i) - next.step_flags((i + 1) % NUM_ROUNDS)
        }));
}
