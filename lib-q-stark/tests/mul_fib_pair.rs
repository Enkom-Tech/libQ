use core::borrow::Borrow;

use lib_q_stark::{
    StarkConfig,
    prove_with_preprocessed,
    setup_preprocessed,
    verify_with_preprocessed,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_challenger::{
    ComplexFieldChallenger,
    Shake256Challenger32,
};
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::Field;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_fri::{
    TwoAdicFriPcs,
    create_test_fri_params,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::MerkleTreeMmcs;
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31ComplexRadix2Dit,
};
use lib_q_stark_rayon::prelude::*;
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};

pub struct MulFibPAir {
    num_rows: usize,
    /// Index to tamper with in preprocessed trace (None = no tampering)
    tamper_index: Option<usize>,
}

impl MulFibPAir {
    pub const fn new(num_rows: usize) -> Self {
        Self {
            num_rows,
            tamper_index: None,
        }
    }

    pub const fn with_tampered_preprocessed(num_rows: usize, tamper_index: usize) -> Self {
        Self {
            num_rows,
            tamper_index: Some(tamper_index),
        }
    }
}

impl<F: Field> BaseAir<F> for MulFibPAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(generate_preprocessed_trace::<F>(
            self.num_rows,
            self.tamper_index,
        ))
    }
}

impl<AB: AirBuilder> Air<AB> for MulFibPAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MulFibPairRow<AB::Var> = main.current_slice().borrow();
        let next: &MulFibPairRow<AB::Var> = main.next_slice().borrow();

        let preprocessed = builder.preprocessed();
        let prep: &PreprocessedRow<AB::Var> = preprocessed.current_slice().borrow();

        let local_a = local.a.clone();
        let local_b = local.b.clone();
        let next_a = next.a.clone();
        let next_b = next.b.clone();
        let prod_coeff = prep.prod_coeff.clone();
        let sum_coeff = prep.sum_coeff.clone();

        let mut when_transition = builder.when_transition();

        when_transition.assert_eq(local_b.clone(), next_a);

        let prod_term = prod_coeff * local_a.clone() * local_b.clone();
        let sum_term = sum_coeff * (local_a + local_b);
        when_transition.assert_eq(prod_term + sum_term, next_b);
    }
}

pub fn generate_trace_rows<F: Field>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_COLS), NUM_COLS);
    let preprocessed = generate_preprocessed_trace::<F>(n, None);

    // SAFETY: align_to_mut is safe when the slice is properly aligned and sized.
    // MulFibPairRow is a repr(C) struct that matches the memory layout of the trace values.
    // The trace width matches NUM_COLS which equals the size of MulFibPairRow.
    let (_, rows, _) = unsafe { trace.values.align_to_mut::<MulFibPairRow<F>>() };
    // SAFETY: Same as above - PreprocessedRow matches the preprocessed trace layout.
    let (_, prep_rows, _) = unsafe { preprocessed.values.align_to::<PreprocessedRow<F>>() };
    assert_eq!(rows.len(), n);

    rows[0] = MulFibPairRow::new(F::from_u64(a), F::from_u64(b));

    for i in 1..n {
        rows[i].a = rows[i - 1].b;
        rows[i].b = prep_rows[i - 1].prod_coeff * rows[i - 1].a * rows[i - 1].b +
            prep_rows[i - 1].sum_coeff * (rows[i - 1].a + rows[i - 1].b);
    }

    trace
}

pub fn generate_preprocessed_trace<F: Field>(
    n: usize,
    tamper_index: Option<usize>,
) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut preprocessed = RowMajorMatrix::new(
        F::zero_vec(n * NUM_PREPROCESSED_COLS),
        NUM_PREPROCESSED_COLS,
    );

    let (_, rows, _) = unsafe { preprocessed.values.align_to_mut::<PreprocessedRow<F>>() };
    assert_eq!(rows.len(), n);

    rows.iter_mut().enumerate().for_each(|(i, row)| {
        row.prod_coeff = F::from_u64((i % 2) as u64);
        row.sum_coeff = F::from_u64(((i + 1) % 6) as u64);
    });

    if let Some(idx) = tamper_index.filter(|&i| i < n) {
        rows[idx].prod_coeff += F::ONE;
    }

    preprocessed
}

const NUM_COLS: usize = 2;
const NUM_PREPROCESSED_COLS: usize = 2;

pub struct MulFibPairRow<F> {
    pub a: F,
    pub b: F,
}

impl<F> MulFibPairRow<F> {
    const fn new(a: F, b: F) -> Self {
        Self { a, b }
    }
}

impl<F> Borrow<MulFibPairRow<F>> for [F] {
    fn borrow(&self) -> &MulFibPairRow<F> {
        debug_assert_eq!(self.len(), NUM_COLS);
        // SAFETY: align_to is safe when the slice is properly aligned.
        // MulFibPairRow matches the memory layout of NUM_COLS field elements.
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MulFibPairRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

pub struct PreprocessedRow<F> {
    pub prod_coeff: F,
    pub sum_coeff: F,
}

impl<F> Borrow<PreprocessedRow<F>> for [F] {
    fn borrow(&self) -> &PreprocessedRow<F> {
        debug_assert_eq!(self.len(), NUM_PREPROCESSED_COLS);
        // SAFETY: PreprocessedRow matches the memory layout of NUM_PREPROCESSED_COLS field elements.
        let (prefix, shorts, suffix) = unsafe { self.align_to::<PreprocessedRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// Use Complex<Mersenne31> as base field (TWO_ADICITY = 32) for sufficient two-adicity
type Val = Complex<Mersenne31>;
// Use Complex<Mersenne31> directly as challenge field
type Challenge = Val;
// Quantum-safe SHAKE256-based Merkle tree setup
type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
// Use u8 as width type for byte-based hashing (quantum-safe)
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type BaseChallenger = Shake256Challenger32<Mersenne31>;
type Challenger = ComplexFieldChallenger<BaseChallenger>;
type Dft = Mersenne31ComplexRadix2Dit;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn setup_test_config() -> MyConfig {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash);
    let challenger = Challenger::new(base_challenger);
    MyConfig::new(pcs, challenger)
}

#[test]
fn test_mul_fib_pair() {
    let num_rows = 1024;
    let config = setup_test_config();
    let trace = generate_trace_rows::<Val>(1, 1, num_rows);

    let air = MulFibPAir::new(num_rows);
    let degree_bits = 10; // log2(1024)
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<MyConfig, _>(&config, &air, degree_bits).unwrap();

    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&preprocessed_prover_data));

    verify_with_preprocessed(&config, &air, &proof, &[], Some(&preprocessed_vk))
        .expect("verification failed");
}

#[test]
fn test_tampered_preprocessed_fails() {
    let num_rows = 1024;
    let config = setup_test_config();
    let trace = generate_trace_rows::<Val>(1, 1, num_rows);
    let air = MulFibPAir::new(num_rows);
    let degree_bits = 10; // log2(1024)

    // Prover uses the correct AIR for preprocessed setup.
    let (preprocessed_prover_data, _) =
        setup_preprocessed::<MyConfig, _>(&config, &air, degree_bits).unwrap();
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&preprocessed_prover_data));

    // Verifier uses a *tampered* AIR to derive the preprocessed commitment, which should
    // not match the one used in the proof.
    let tampered_air = MulFibPAir::with_tampered_preprocessed(num_rows, 3);
    let (_, tampered_preprocessed_vk) =
        setup_preprocessed::<MyConfig, _>(&config, &tampered_air, degree_bits).unwrap();

    let result = verify_with_preprocessed(
        &config,
        &tampered_air,
        &proof,
        &[],
        Some(&tampered_preprocessed_vk),
    );

    assert!(
        result.is_err(),
        "Verification should fail with tampered preprocessed columns"
    );
}
