//! Performance benchmarks for ZKP operations

#![feature(test)]
extern crate test;

#[cfg(feature = "zkp")]
mod benches {
    extern crate alloc;

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
    use test::Bencher;

    type TestField = Complex<Mersenne31>;

    #[bench]
    fn bench_arithmetic_air_trace_generation(b: &mut Bencher) {
        let air = ArithmeticAir::new(100).unwrap();
        let inputs: alloc::vec::Vec<(TestField, TestField)> = (0..100)
            .map(|i| {
                (
                    TestField::from(Mersenne31::new(i as u32)),
                    TestField::from(Mersenne31::new((i + 1) as u32)),
                )
            })
            .collect();

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&inputs).unwrap();
        });
    }

    #[bench]
    fn bench_hash_preimage_air_trace_generation(b: &mut Bencher) {
        let air = HashPreimageAir::new();
        let preimage = b"test preimage data for benchmarking".to_vec();

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&preimage).unwrap();
        });
    }

    #[bench]
    fn bench_poseidon_hash_air_trace_generation(b: &mut Bencher) {
        use lib_q_poseidon::PoseidonField;
        let air = PoseidonHashAir::new(32).unwrap();
        let preimage: alloc::vec::Vec<PoseidonField> = (0..10)
            .map(|i| Complex::<Mersenne31>::from(Mersenne31::new(i as u32)))
            .collect();

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&preimage).unwrap();
        });
    }

    #[bench]
    fn bench_merkle_inclusion_air_trace_generation_depth_8(b: &mut Bencher) {
        use lib_q_zkp::air::{
            MerkleHash,
            MerkleProofInput,
        };
        let air = MerkleInclusionAir::new(8).unwrap();
        let input = MerkleProofInput {
            leaf: alloc::vec![1, 2, 3, 4],
            leaf_hash_direct: None,
            path_bits: alloc::vec![false; 8],
            siblings: (0..8)
                .map(|_| MerkleHash::from_bytes(&[0u8; 32]).unwrap())
                .collect(),
        };

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&input).unwrap();
        });
    }

    #[bench]
    fn bench_merkle_inclusion_air_trace_generation_depth_32(b: &mut Bencher) {
        use lib_q_zkp::air::{
            MerkleHash,
            MerkleProofInput,
        };
        let air = MerkleInclusionAir::new(32).unwrap();
        let input = MerkleProofInput {
            leaf: alloc::vec![1, 2, 3, 4],
            leaf_hash_direct: None,
            path_bits: alloc::vec![false; 32],
            siblings: (0..32)
                .map(|_| MerkleHash::from_bytes(&[0u8; 32]).unwrap())
                .collect(),
        };

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&input).unwrap();
        });
    }

    #[bench]
    fn bench_merkle_inclusion_air_trace_generation_depth_64(b: &mut Bencher) {
        use lib_q_zkp::air::{
            MerkleHash,
            MerkleProofInput,
        };
        let air = MerkleInclusionAir::new(64).unwrap();
        let input = MerkleProofInput {
            leaf: alloc::vec![1, 2, 3, 4],
            leaf_hash_direct: None,
            path_bits: alloc::vec![false; 64],
            siblings: (0..64)
                .map(|_| MerkleHash::from_bytes(&[0u8; 32]).unwrap())
                .collect(),
        };

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&input).unwrap();
        });
    }

    #[bench]
    fn bench_range_proof_air_trace_generation(b: &mut Bencher) {
        let air = RangeProofAir::new(16).unwrap();
        let inputs = alloc::vec![TestField::ZERO];

        b.iter(|| {
            let _trace: lib_q_stark_matrix::dense::RowMajorMatrix<TestField> =
                air.generate_trace(&inputs).unwrap();
        });
    }
}
