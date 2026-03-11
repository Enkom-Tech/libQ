//! LogUp integration test: permutation generation and constraint sanity.
//!
//! Minimal range-check style setup: main trace has a value column and a table column;
//! the lookup asserts that each value appears in the table (same table row = same value).

extern crate alloc;

use alloc::vec;
use core::ops::Neg;

use lib_q_plonky_lookup::debug_util::{
    LookupDebugInstance,
    check_lookups,
};
use lib_q_plonky_lookup::logup::LogUpGadget;
use lib_q_plonky_lookup::lookup_traits::LookupGadget;
use lib_q_plonky_lookup::{
    Direction,
    Kind,
    Lookup,
    LookupAir,
    LookupData,
    LookupEvaluator,
};
use lib_q_stark_air::symbolic::{
    BaseEntry,
    SymbolicExpression,
    SymbolicVariable,
};
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

type F = Mersenne31;
type EF = lib_q_stark_field::extension::Complex<Mersenne31>;

/// Minimal AIR with one local lookup: Receive(read, 1), Send(provide, mult).
/// Main trace columns: [read, provide, mult].
struct RangeCheckAir;

impl<Fld: lib_q_stark_field::Field> LookupAir<Fld> for RangeCheckAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        vec![0]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<Fld>> {
        let read =
            SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 0));
        let provide =
            SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 1));
        let mult =
            SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 2));
        let one = SymbolicExpression::from(Fld::ONE);
        let lookup = self.register_lookup(
            Kind::Local,
            &[
                (vec![read], one, Direction::Receive),
                (vec![provide], mult, Direction::Send),
            ],
        );
        vec![lookup]
    }
}

#[test]
fn logup_gadget_permutation_smoke() {
    let gadget = LogUpGadget::new();
    let height = 4;
    let main = RowMajorMatrix::new(
        vec![
            F::ZERO,
            F::ONE,
            F::new(2),
            F::new(3),
            F::ZERO,
            F::ONE,
            F::new(2),
            F::new(3),
        ],
        2,
    );
    let col0 = SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 0));
    let col1 = SymbolicExpression::from(SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 1));
    let one = SymbolicExpression::from(F::ONE);
    let lookup = Lookup::new(
        Kind::Local,
        vec![vec![col0], vec![col1]],
        vec![one.clone(), one.neg()],
        vec![0],
    );
    let lookups = vec![lookup];
    let mut lookup_data = vec![LookupData {
        name: alloc::string::String::new(),
        aux_idx: 0,
        expected_cumulated: EF::ZERO,
    }];
    let chal = EF::from(F::new(12345));
    let permutation_challenges = vec![chal; gadget.num_challenges() * lookups.len()];

    let perm = gadget.generate_permutation::<F, EF>(
        &main,
        &None,
        &[],
        &lookups,
        &mut lookup_data,
        &permutation_challenges,
    );
    assert_eq!(perm.height(), height);
    assert_eq!(perm.width(), gadget.num_aux_cols() * lookups.len());
}

#[test]
fn test_range_check_valid() {
    let mut air = RangeCheckAir;
    let lookups = air.get_lookups();
    let main_trace = RowMajorMatrix::new(
        vec![
            F::ZERO,
            F::ZERO,
            F::ONE,
            F::ONE,
            F::ONE,
            F::ONE,
            F::new(2),
            F::new(2),
            F::ONE,
            F::new(3),
            F::new(3),
            F::ONE,
        ],
        3,
    );
    let instance = LookupDebugInstance {
        main_trace: &main_trace,
        preprocessed_trace: &None,
        public_values: &[],
        lookups: &lookups,
        permutation_challenges: &[],
    };
    check_lookups(&[instance]);
}

#[test]
#[should_panic(expected = "Lookup mismatch")]
fn test_range_check_invalid() {
    let mut air = RangeCheckAir;
    let lookups = air.get_lookups();
    let main_trace = RowMajorMatrix::new(
        vec![
            F::ZERO,
            F::ZERO,
            F::ONE,
            F::ONE,
            F::ONE,
            F::ONE,
            F::new(256),
            F::new(255),
            F::ONE,
            F::new(3),
            F::new(3),
            F::ONE,
        ],
        3,
    );
    let instance = LookupDebugInstance {
        main_trace: &main_trace,
        preprocessed_trace: &None,
        public_values: &[],
        lookups: &lookups,
        permutation_challenges: &[],
    };
    check_lookups(&[instance]);
}
