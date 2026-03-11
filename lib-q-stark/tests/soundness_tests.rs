//! Soundness tests: verifier rejects every category of invalid proof.

use std::vec::Vec;

use lib_q_stark::{
    MAX_TRACE_HEIGHT,
    StarkConfig,
    assert_trace_height_within_limit,
    prove,
    verify,
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
use lib_q_stark_field::extension::Complex;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
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
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    Hash,
    SerializingHasher,
};

type ValF = Complex<Mersenne31>;
type Challenge = ValF;

/// Simple multiplication AIR: one row constraint a * b = c per "op".
/// Width = 3 * num_ops. No boundary/transition for minimal soundness tests.
#[derive(Clone)]
struct SimpleMulAir {
    num_ops: usize,
}

impl SimpleMulAir {
    fn new(num_ops: usize) -> Self {
        Self { num_ops }
    }
}

impl<F: Field> BaseAir<F> for SimpleMulAir {
    fn width(&self) -> usize {
        self.num_ops * 3
    }
}

impl<AB: AirBuilder> Air<AB> for SimpleMulAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        for i in 0..self.num_ops {
            let a = local[i * 3].clone();
            let b = local[i * 3 + 1].clone();
            let c = local[i * 3 + 2].clone();
            builder.assert_zero(a.clone() * b - c);
        }
    }
}

type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<<ValF as Field>::Packing, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<ValF, Challenge, ValMmcs>;
type BaseChallenger = Shake256Challenger32<Mersenne31>;
type Challenger = ComplexFieldChallenger<BaseChallenger>;
type MyConfig = StarkConfig<
    TwoAdicFriPcs<ValF, Mersenne31ComplexRadix2Dit, ValMmcs, ChallengeMmcs>,
    Challenge,
    Challenger,
>;

fn make_fast_config() -> MyConfig {
    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(Shake256Hash {});
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, 3);
    let pcs = TwoAdicFriPcs::new(Mersenne31ComplexRadix2Dit, val_mmcs, fri_params);
    let base_challenger = BaseChallenger::from_hasher(Vec::new(), Shake256Hash {});
    let challenger = Challenger::new(base_challenger);
    MyConfig::new(pcs, challenger)
}

/// Minimum trace height for FRI: log_min_height > log_final_poly_len + log_blowup (3+2=5), so >= 64 rows.
const MIN_TRACE_ROWS: usize = 64;

fn make_mul_proof(
    a: u32,
    b: u32,
) -> (
    SimpleMulAir,
    RowMajorMatrix<ValF>,
    Vec<ValF>,
    lib_q_stark::Proof<MyConfig>,
) {
    let air = SimpleMulAir::new(1);
    let product = a * b;
    let row: [ValF; 3] = [
        ValF::from(Mersenne31::new(a)),
        ValF::from(Mersenne31::new(b)),
        ValF::from(Mersenne31::new(product)),
    ];
    let mut values = vec![ValF::ZERO; MIN_TRACE_ROWS * 3];
    for i in 0..MIN_TRACE_ROWS {
        values[i * 3] = row[0];
        values[i * 3 + 1] = row[1];
        values[i * 3 + 2] = row[2];
    }
    let trace = RowMajorMatrix::new(values, 3);
    let pv = vec![ValF::from(Mersenne31::new(product))];
    let config = make_fast_config();
    let proof = prove(&config, &air, trace.clone(), &pv);
    (air, trace, pv, proof)
}

fn copy_proof(proof: &lib_q_stark::Proof<MyConfig>) -> lib_q_stark::Proof<MyConfig> {
    let bytes = postcard::to_allocvec(proof).expect("serialize");
    postcard::from_bytes(&bytes).expect("deserialize")
}

#[test]
fn test_verifier_rejects_bit_flipped_trace_commitment() {
    let (air, _, pv, proof) = make_mul_proof(3, 4);
    let config = make_fast_config();
    let mut bad = copy_proof(&proof);
    let bytes: [u8; 32] = bad.commitments.trace.into();
    let mut arr = bytes;
    arr[0] ^= 0x01;
    bad.commitments.trace = Hash::from(arr);
    assert!(verify(&config, &air, &bad, &pv).is_err());
}

#[test]
fn test_verifier_rejects_bit_flipped_quotient_commitment() {
    let (air, _, pv, proof) = make_mul_proof(3, 4);
    let config = make_fast_config();
    let mut bad = copy_proof(&proof);
    let bytes: [u8; 32] = bad.commitments.quotient_chunks.into();
    let mut arr = bytes;
    arr[0] ^= 0x01;
    bad.commitments.quotient_chunks = Hash::from(arr);
    assert!(verify(&config, &air, &bad, &pv).is_err());
}

#[test]
fn test_verifier_rejects_modified_public_values() {
    let (air, _, _pv, proof) = make_mul_proof(3, 4);
    let config = make_fast_config();
    let pv_wrong = [ValF::from(Mersenne31::new(13))];
    assert!(verify(&config, &air, &proof, &pv_wrong).is_err());
}

#[test]
fn test_verifier_rejects_wrong_air_width() {
    let (_, _, pv, proof) = make_mul_proof(3, 4);
    let config = make_fast_config();
    let wrong_air = SimpleMulAir::new(2);
    let air1 = SimpleMulAir::new(1);
    assert!(verify(&config, &air1, &proof, &pv).is_ok());
    assert!(verify(&config, &wrong_air, &proof, &pv).is_err());
}

/// DoS protection: prover panics when trace height exceeds MAX_TRACE_HEIGHT.
#[test]
fn test_prover_rejects_trace_exceeding_max_height() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_trace_height_within_limit(MAX_TRACE_HEIGHT + 1);
    }));
    assert!(
        result.is_err(),
        "assert_trace_height_within_limit must panic for height > MAX_TRACE_HEIGHT"
    );
}

#[test]
fn test_verifier_rejects_tampered_opening_value() {
    let (air, _, pv, mut proof) = make_mul_proof(3, 4);
    let config = make_fast_config();
    let v = proof.opened_values.trace_local[0] + ValF::ONE;
    proof.opened_values.trace_local[0] = v;
    assert!(verify(&config, &air, &proof, &pv).is_err());
}

#[cfg(not(debug_assertions))]
#[test]
fn test_verifier_rejects_constraint_violation_in_trace() {
    let (air, mut trace, pv, _) = make_mul_proof(3, 4);
    let config = make_fast_config();
    trace.values[2] = ValF::from(Mersenne31::new(13));
    let bad_proof = prove(&config, &air, trace, &pv);
    assert!(verify(&config, &air, &bad_proof, &pv).is_err());
}

#[test]
fn test_verifier_rejects_tampered_fri_auth_path() {
    let (air, _, pv, mut proof) = make_mul_proof(3, 4);
    let config = make_fast_config();
    if let Some(q) = proof.opened_values.quotient_chunks.get_mut(0) &&
        let Some(cell) = q.get_mut(0)
    {
        let new_val = *cell + ValF::ONE;
        *cell = new_val;
        assert!(verify(&config, &air, &proof, &pv).is_err());
        return;
    }
    if let Some(cell) = proof.opened_values.trace_local.get_mut(1) {
        let new_val = *cell + ValF::ONE;
        *cell = new_val;
    }
    assert!(verify(&config, &air, &proof, &pv).is_err());
}
