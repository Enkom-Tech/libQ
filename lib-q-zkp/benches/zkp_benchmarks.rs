//! Performance benchmarks for ZKP operations (Criterion; stable-compatible).

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    ArithmeticAir,
    HashPreimageAir,
    MerkleInclusionAir,
    PoseidonHashAir,
    RangeProofAir,
    TraceGenerator,
};

type TestField = Complex<Mersenne31>;

fn bench_arithmetic_air_trace_generation(c: &mut Criterion) {
    let air = ArithmeticAir::new(100).unwrap();
    let inputs: Vec<(TestField, TestField)> = (0..100)
        .map(|i| {
            (
                TestField::from(Mersenne31::new(i as u32)),
                TestField::from(Mersenne31::new((i + 1) as u32)),
            )
        })
        .collect();

    c.bench_function("arithmetic_air_trace_generation", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&inputs).unwrap();
        });
    });
}

fn bench_hash_preimage_air_trace_generation(c: &mut Criterion) {
    let air = HashPreimageAir::new();
    let preimage = b"test preimage data for benchmarking".to_vec();

    c.bench_function("hash_preimage_air_trace_generation", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&preimage).unwrap();
        });
    });
}

fn bench_poseidon_hash_air_trace_generation(c: &mut Criterion) {
    use lib_q_poseidon::PoseidonField;
    let air = PoseidonHashAir::new(32).unwrap();
    let preimage: Vec<PoseidonField> = (0..10)
        .map(|i| Complex::<Mersenne31>::from(Mersenne31::new(i as u32)))
        .collect();

    c.bench_function("poseidon_hash_air_trace_generation", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&preimage).unwrap();
        });
    });
}

fn bench_merkle_inclusion_air_trace_generation_depth_8(c: &mut Criterion) {
    use lib_q_zkp::air::{
        MerkleHash,
        MerkleProofInput,
    };
    let air = MerkleInclusionAir::new(8).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false; 8],
        siblings: (0..8)
            .map(|_| MerkleHash::from_bytes(&[0u8; 32]).unwrap())
            .collect(),
    };

    c.bench_function("merkle_inclusion_air_trace_depth_8", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&input).unwrap();
        });
    });
}

fn bench_merkle_inclusion_air_trace_generation_depth_32(c: &mut Criterion) {
    use lib_q_zkp::air::{
        MerkleHash,
        MerkleProofInput,
    };
    let air = MerkleInclusionAir::new(32).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false; 32],
        siblings: (0..32)
            .map(|_| MerkleHash::from_bytes(&[0u8; 32]).unwrap())
            .collect(),
    };

    c.bench_function("merkle_inclusion_air_trace_depth_32", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&input).unwrap();
        });
    });
}

fn bench_merkle_inclusion_air_trace_generation_depth_64(c: &mut Criterion) {
    use lib_q_zkp::air::{
        MerkleHash,
        MerkleProofInput,
    };
    let air = MerkleInclusionAir::new(64).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false; 64],
        siblings: (0..64)
            .map(|_| MerkleHash::from_bytes(&[0u8; 32]).unwrap())
            .collect(),
    };

    c.bench_function("merkle_inclusion_air_trace_depth_64", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&input).unwrap();
        });
    });
}

fn bench_range_proof_air_trace_generation(c: &mut Criterion) {
    let air = RangeProofAir::new(16).unwrap();
    let inputs = vec![TestField::ZERO];

    c.bench_function("range_proof_air_trace_generation", |b| {
        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&inputs).unwrap();
        });
    });
}

criterion_group!(
    zkp_benches,
    bench_arithmetic_air_trace_generation,
    bench_hash_preimage_air_trace_generation,
    bench_poseidon_hash_air_trace_generation,
    bench_merkle_inclusion_air_trace_generation_depth_8,
    bench_merkle_inclusion_air_trace_generation_depth_32,
    bench_merkle_inclusion_air_trace_generation_depth_64,
    bench_range_proof_air_trace_generation,
);
criterion_main!(zkp_benches);
