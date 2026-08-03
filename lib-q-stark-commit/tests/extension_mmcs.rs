//! Integration tests for `ExtensionMmcs` (see `src/adapters/extension_mmcs.rs`), using the real
//! Merkle-tree implementation (`lib-q-stark-merkle`) as the inner MMCS.
//!
//! Lives in `tests/` for the same reason `tests/mmcs.rs` does: `lib-q-stark-merkle` depends on
//! `lib-q-stark-commit`, so exercising it from an in-crate `#[cfg(test)]` module would link two
//! distinct compilations of `lib-q-stark-commit` into one test binary (see the comment at the top
//! of `tests/mmcs.rs` for the exact compile error this produces).

use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_commit::{
    BatchOpeningRef,
    ExtensionMmcs,
    Mmcs,
};
use lib_q_stark_field::extension::BinomialExtensionField;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Dimensions;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::MerkleTreeMmcs;
use lib_q_stark_shake128::Shake128Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};

type Val = BabyBear;
// The degree-4 binomial extension field, as used e.g. by `lib-q-stark-baby-bear`'s own
// `ext4_tests` module (`F_{p^4}`, the FRI challenge field for BabyBear).
type Challenge = BinomialExtensionField<Val, 4>;

type MyHash = SerializingHasher<Shake128Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake128Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

fn mmcs() -> ChallengeMmcs {
    let inner = ValMmcs::new(MyHash::new(Shake128Hash), MyCompress::new(Shake128Hash));
    ChallengeMmcs::new(inner)
}

fn matrix(height: usize, width: usize) -> RowMajorMatrix<Challenge> {
    RowMajorMatrix::new(
        (0..height * width)
            .map(|i| Challenge::from(Val::new(i as u32 + 1)))
            .collect(),
        width,
    )
}

/// `ExtensionMmcs` must round-trip: committing to a matrix of extension-field elements and then
/// opening/verifying every row must succeed, exactly as for the base-field `Mmcs`.
#[test]
fn honest_extension_opening_is_accepted_at_every_row() {
    let mmcs = mmcs();
    let height = 8;
    let width = 2;
    let (commitment, prover_data) = mmcs.commit_matrix(matrix(height, width));
    let dims = [Dimensions { width, height }];

    for index in 0..height {
        let opening = mmcs.open_batch(index, &prover_data);
        mmcs.verify_batch(&commitment, &dims, index, BatchOpeningRef::from(&opening))
            .unwrap_or_else(|e| panic!("honest extension opening at index {index} rejected: {e:?}"));
    }
}

/// Tampering an opened *extension-field* value must be rejected. `ExtensionMmcs::verify_batch`
/// flattens the (claimed) extension values back to base-field coordinates and defers to the inner
/// MMCS, so this also exercises `EF::flatten_to_base` being consistent with `EF::reconstitute_from_base`
/// on the honest path.
#[test]
fn tampered_extension_value_is_rejected() {
    let mmcs = mmcs();
    let height = 8;
    let width = 2;
    let (commitment, prover_data) = mmcs.commit_matrix(matrix(height, width));
    let dims = [Dimensions { width, height }];
    let index = 4;

    let mut tampered = mmcs.open_batch(index, &prover_data);
    tampered.opened_values[0][0] += Challenge::ONE;

    let result = mmcs.verify_batch(&commitment, &dims, index, BatchOpeningRef::from(&tampered));
    assert!(
        result.is_err(),
        "ExtensionMmcs::verify_batch accepted a tampered extension-field opened value"
    );
}
