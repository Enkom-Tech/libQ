//! Integration tests for the `Mmcs` trait, exercised against the real Merkle-tree implementation
//! (`lib-q-stark-merkle`).
//!
//! These live in `tests/` rather than `src/mmcs.rs`'s `#[cfg(test)]` module because
//! `lib-q-stark-merkle` itself depends on `lib-q-stark-commit` (it implements `Mmcs`): a `[dev-dependencies]`
//! cycle like that, if exercised from an in-crate `#[cfg(test)]` module, makes `cargo test` link
//! two distinct compilations of `lib-q-stark-commit` (one built with `--cfg test` for the unit-test
//! harness, one built plainly as `lib-q-stark-merkle`'s ordinary dependency) into the same test
//! binary, and the `Mmcs` trait from one is not the same type as the `Mmcs` trait from the other
//! ("multiple different versions of crate `lib_q_stark_commit` in the dependency graph" — confirmed
//! by actually hitting this compile error while writing these tests in-crate first). An integration
//! test in `tests/` only ever sees the one, plain build of the library, exactly like every other
//! downstream crate, so no duplication occurs.

use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_commit::{
    BatchOpeningRef,
    Mmcs,
};
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
type MyHash = SerializingHasher<Shake128Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake128Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;

fn mmcs() -> ValMmcs {
    ValMmcs::new(MyHash::new(Shake128Hash), MyCompress::new(Shake128Hash))
}

fn matrix(height: usize, width: usize) -> RowMajorMatrix<Val> {
    RowMajorMatrix::new(
        (0..height * width)
            .map(|i| Val::new(i as u32 + 1))
            .collect(),
        width,
    )
}

/// The prover's `open_batch`/verifier's `verify_batch` round trip must accept every honestly
/// produced opening, for every valid row index.
#[test]
fn honest_opening_is_accepted_at_every_row() {
    let mmcs = mmcs();
    let height = 8;
    let width = 3;
    let (commitment, prover_data) = mmcs.commit_matrix(matrix(height, width));
    let dims = [Dimensions { width, height }];

    for index in 0..height {
        let opening = mmcs.open_batch(index, &prover_data);
        mmcs.verify_batch(&commitment, &dims, index, BatchOpeningRef::from(&opening))
            .unwrap_or_else(|e| panic!("honest opening at index {index} rejected: {e:?}"));
    }
}

/// The single most important test in this task: a verifier that accepts a tampered opening is a
/// broken commitment scheme. Flipping one opened field element must make `verify_batch` return
/// `Err`, because the Merkle path was computed over the ORIGINAL value.
#[test]
fn tampered_opened_value_is_rejected() {
    let mmcs = mmcs();
    let height = 8;
    let width = 3;
    let (commitment, prover_data) = mmcs.commit_matrix(matrix(height, width));
    let dims = [Dimensions { width, height }];
    let index = 3;

    let mut tampered = mmcs.open_batch(index, &prover_data);
    tampered.opened_values[0][0] += Val::ONE;

    let result = mmcs.verify_batch(&commitment, &dims, index, BatchOpeningRef::from(&tampered));
    assert!(
        result.is_err(),
        "verify_batch accepted a batch opening whose leaf value was tampered with"
    );
}

/// Same idea, but tampering the Merkle proof (a sibling digest) instead of the leaf value: this
/// must also be rejected, since the recomputed root would no longer match the commitment.
#[test]
fn tampered_proof_sibling_is_rejected() {
    let mmcs = mmcs();
    let height = 8;
    let width = 3;
    let (commitment, prover_data) = mmcs.commit_matrix(matrix(height, width));
    let dims = [Dimensions { width, height }];
    let index = 5;

    let mut tampered = mmcs.open_batch(index, &prover_data);
    assert!(
        !tampered.opening_proof.is_empty(),
        "test setup: height 8 must produce a non-empty Merkle path"
    );
    tampered.opening_proof[0][0] ^= 0xFF;

    let result = mmcs.verify_batch(&commitment, &dims, index, BatchOpeningRef::from(&tampered));
    assert!(
        result.is_err(),
        "verify_batch accepted a batch opening with a tampered Merkle sibling"
    );
}

/// An opening honestly produced for index `i` must be rejected if the verifier is told it was
/// opened at a different index `j` — otherwise a malicious prover could equivocate about which row
/// a commitment covers.
#[test]
fn opening_replayed_at_the_wrong_index_is_rejected() {
    let mmcs = mmcs();
    let height = 8;
    let width = 3;
    let (commitment, prover_data) = mmcs.commit_matrix(matrix(height, width));
    let dims = [Dimensions { width, height }];

    let opening = mmcs.open_batch(2, &prover_data);
    let result = mmcs.verify_batch(&commitment, &dims, 6, BatchOpeningRef::from(&opening));
    assert!(
        result.is_err(),
        "verify_batch accepted an honest opening for index 2 when told it was index 6"
    );
}

/// `open_batch`/`verify_batch` on a *batch* of matrices with different heights: the trait's
/// documented index-reduction (`j = index >> (log2_ceil(max_height) - log2_ceil(height))`) must be
/// applied consistently between prover and verifier, and tampering the *smaller* matrix's opened
/// row must also be caught.
#[test]
fn mixed_height_batch_round_trips_and_rejects_tampering() {
    let mmcs = mmcs();
    let tall = matrix(8, 2);
    let short = matrix(2, 2);
    let dims = [
        Dimensions {
            width: 2,
            height: 8,
        },
        Dimensions {
            width: 2,
            height: 2,
        },
    ];
    let (commitment, prover_data) = mmcs.commit(vec![tall, short]);

    for index in 0..8 {
        let opening = mmcs.open_batch(index, &prover_data);
        assert_eq!(opening.opened_values.len(), 2);
        mmcs.verify_batch(&commitment, &dims, index, BatchOpeningRef::from(&opening))
            .unwrap_or_else(|e| {
                panic!("honest mixed-height opening at index {index} rejected: {e:?}")
            });
    }

    let mut tampered = mmcs.open_batch(0, &prover_data);
    tampered.opened_values[1][0] += Val::ONE; // tamper the *short* matrix's opened row
    let result = mmcs.verify_batch(&commitment, &dims, 0, BatchOpeningRef::from(&tampered));
    assert!(
        result.is_err(),
        "verify_batch accepted tampering in the shorter matrix of a mixed-height batch"
    );
}
