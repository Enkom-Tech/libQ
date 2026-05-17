//! Known-answer tests for Poseidon.
//!
//! Regression guard against constant or parameter drift. Expected values were
//! generated from this implementation; replace with reference-derived values
//! when available (e.g. Python/Sage with same field and parameters).

use std::collections::BTreeSet;

use lib_q_poseidon::{
    Poseidon,
    Poseidon128,
    Poseidon256,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    PrimeCharacteristicRing,
    PrimeField32,
};
use lib_q_stark_mersenne31::Mersenne31;

type F = Complex<Mersenne31>;

fn m31(u: u32) -> Mersenne31 {
    Mersenne31::new(u)
}

// KAT expected values: first output element (real, imag) as canonical u32.
// Regenerated after % P round constants and rate-only 10*1 padding.
const KAT_ZEROS_128: (u32, u32) = (1659687304, 938438641);
const KAT_SEQ_128: (u32, u32) = (1984498265, 1835192369);
const KAT_MULTI_128: (u32, u32) = (1887303254, 1272265698);
const PERM_KAT_128: [(u32, u32); 5] = [
    (1256535900, 1878638418),
    (889451214, 854685520),
    (1479030052, 1491237636),
    (466803534, 2090751667),
    (1517770422, 1347436791),
];
const KAT_ZEROS_256: (u32, u32) = (284805478, 447069445);

fn to_f(pair: (u32, u32)) -> F {
    Complex::new_complex(m31(pair.0), m31(pair.1))
}

#[test]
fn test_poseidon128_kat_all_zeros_input() {
    let input = vec![F::ZERO, F::ZERO];
    let result = Poseidon128.hash(&input);
    let expected = to_f(KAT_ZEROS_128);
    assert_eq!(result[0], expected, "Poseidon128 zeros input KAT");
}

#[test]
fn test_poseidon128_kat_sequential_input() {
    let one = F::from(m31(1));
    let two = F::from(m31(2));
    let input = vec![one, two];
    let result = Poseidon128.hash(&input);
    assert_eq!(
        result[0],
        to_f(KAT_SEQ_128),
        "Poseidon128 sequential [1,2] KAT"
    );
}

#[test]
fn test_poseidon128_kat_multi_block_absorption() {
    let one = F::from(m31(1));
    let two = F::from(m31(2));
    let three = F::from(m31(3));
    let input = vec![one, two, three];
    let result = Poseidon128.hash(&input);
    assert_eq!(
        result[0],
        to_f(KAT_MULTI_128),
        "Poseidon128 multi-block [1,2,3] KAT"
    );
}

#[test]
fn test_poseidon128_permutation_kat_known_state() {
    let perm = Poseidon128::permutation();
    let state = vec![
        F::from(m31(1)),
        F::from(m31(2)),
        F::from(m31(3)),
        F::from(m31(4)),
        F::from(m31(5)),
    ];
    let out = perm.permute(state);
    for (i, &expected) in PERM_KAT_128.iter().enumerate() {
        assert_eq!(out[i], to_f(expected), "permutation KAT element {}", i);
    }
}

#[test]
fn test_poseidon256_kat_all_zeros_input() {
    let zeros = vec![F::ZERO, F::ZERO];
    let result = Poseidon256.hash(&zeros);
    assert_eq!(
        result[0],
        to_f(KAT_ZEROS_256),
        "Poseidon256 zeros input KAT"
    );
}

#[test]
fn test_poseidon_collision_resistance_50_random_inputs() {
    let mut outputs = BTreeSet::new();
    for i in 0..50u32 {
        let a = F::from(m31(i));
        let b = F::from(m31(i + 1));
        let out = Poseidon128.hash(&[a, b]);
        outputs.insert((
            out[0].real().as_canonical_u32(),
            out[0].imag().as_canonical_u32(),
        ));
    }
    assert_eq!(outputs.len(), 50, "no hash collisions across 50 samples");
}
