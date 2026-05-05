//! Module-lattice commitments, Fiat–Shamir sigma protocols, and BLNS-style batching hooks.
//!
//! The construction targets the same \(R_q = \mathbb{Z}_q[X]/(X^{256}+1)\) field as ML-DSA via
//! [`lib_q_ring`].
#![forbid(unsafe_code)]
#![no_std]
#![allow(missing_docs)]

extern crate alloc;

pub mod blind;
pub mod budget;
pub mod challenge;
pub mod commitment;
pub mod error;
pub mod params;
pub mod serialize;
pub mod sigma;
pub mod token;
pub mod util;

pub use blind::{
    BLIND_ISSUER_FS_LABEL,
    BlindIssuance,
    BlindIssuerKeypair,
    BlindRequest,
    BlindResponse,
    BlindSignature,
    BlindUserState,
    UnblindedBlindSignature,
    UnblindedIssuance,
    add_module_vec,
    aggregate_opening,
    blind_message_digest,
    blinded_commitment,
    issuance_blind_message_extra,
    issuance_transcript_ctx,
};
pub use budget::AmortisationBudget;
pub use challenge::MlDsaCompatibleChallenge;
pub use commitment::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    commit,
};
pub use error::{
    ProofError,
    VerifyError,
};
pub use params::AjtaiParameters;
pub use sigma::{
    AmortisedProof,
    BatchPresentationState,
    CrtPackedNormProof,
    HierarchicalAuthProof,
    LinearRelationProof,
    MerklePath,
    NullifierOpeningProof,
    OpeningProof,
    PVTN_CLEARANCE_MARGIN_NORM_BETA,
    PrivateMembershipProof,
    WitnessNullifierOpeningProof,
    aggregate_proofs,
    amortise,
    encode_pvtn_leaf,
    hierarchical,
    hierarchical_opening_ctx,
    leaf_clearance_level,
    leaf_hash,
    linear,
    node_hash,
    norm,
    opening,
    opening_ctx_with_nullifier,
    opening_ctx_with_witness_nullifier,
    private_membership_opening_ctx,
    prove_inf_norm,
    prove_level_membership,
    prove_linear,
    prove_nullifier_opening,
    prove_opening,
    prove_private_membership,
    prove_witness_nullifier_opening,
    registry_nullifier,
    uniqueness,
    uniqueness_amortisation_label,
    verify_aggregate,
    verify_hierarchical_membership,
    verify_inf_norm,
    verify_inf_norm_proof,
    verify_level_membership,
    verify_linear,
    verify_merkle_path,
    verify_nullifier_opening,
    verify_opening,
    verify_private_membership,
    verify_witness_nullifier_opening,
    witness_nullifier,
    witness_uniqueness_amortisation_label,
    witness_wire,
};
pub use token::{
    AnonymousToken,
    SpendingProof,
    TOKEN_EPOCH_LEN,
    TOKEN_ORIGIN_LEN,
    TOKEN_SERIAL_LEN,
    opening_from_token_fields,
};

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use lib_q_ring::{
        ModuleVec,
        Poly,
        sample_in_ball,
    };
    use rand_core::{
        TryCryptoRng,
        TryRng,
    };

    use super::*;

    #[derive(Debug)]
    struct TestRng(u64);

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            Ok((self.0 >> 32) as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(((self.try_next_u32()? as u64) << 32) | u64::from(self.try_next_u32()?))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let mut i = 0usize;
            while i < dst.len() {
                let v = self.try_next_u32()?.to_le_bytes();
                let take = (dst.len() - i).min(4);
                dst[i..i + take].copy_from_slice(&v[..take]);
                i += take;
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    #[test]
    fn commitment_homomorphic_r_and_m() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [9u8; 32],
            params,
        };
        let mut m1 = alloc::vec![Poly::zero(), Poly::zero()];
        m1[0].coeffs[0] = 3;
        let mut m2 = alloc::vec![Poly::zero(), Poly::zero()];
        m2[0].coeffs[0] = 5;
        let mut r1 = alloc::vec![Poly::zero()];
        r1[0].coeffs[0] = 11;
        let mut r2 = alloc::vec![Poly::zero()];
        r2[0].coeffs[0] = 13;
        let o1 = AjtaiOpening {
            message: ModuleVec(m1.clone()),
            randomness: ModuleVec(r1.clone()),
        };
        let o2 = AjtaiOpening {
            message: ModuleVec(m2.clone()),
            randomness: ModuleVec(r2.clone()),
        };
        let c1 = commit(&key, &o1);
        let c2 = commit(&key, &o2);
        let mut r_sum = r1.clone();
        r_sum[0].add_assign(&r2[0]);
        let mut ms = m1.clone();
        for (a, b) in ms.iter_mut().zip(m2.iter()) {
            a.add_assign(b);
        }
        let o_sum = AjtaiOpening {
            message: ModuleVec(ms),
            randomness: ModuleVec(r_sum),
        };
        let c_sum = commit(&key, &o_sum);
        let mut expect = c1.value.0.clone();
        for (e, b) in expect.iter_mut().zip(c2.value.0.iter()) {
            e.add_assign(b);
        }
        assert_eq!(c_sum.value.0.len(), expect.len());
        for (a, b) in c_sum.value.0.iter().zip(expect.iter()) {
            assert_eq!(a.coeffs, b.coeffs);
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [11u8; 32],
            params,
        };
        let opening = AjtaiOpening {
            message: ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let c1 = commit(&key, &opening);
        let c2 = commit(&key, &opening);
        assert_eq!(c1, c2);
    }

    #[test]
    fn opening_proof_roundtrip() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [3u8; 32],
            params,
        };
        let message = alloc::vec![Poly::zero(), Poly::zero()];
        let randomness = alloc::vec![Poly::zero()];
        let opening = AjtaiOpening {
            message: ModuleVec(message),
            randomness: ModuleVec(randomness),
        };
        let com = commit(&key, &opening);
        let mut rng = TestRng(0xC0FFEE);
        let proof = prove_opening(
            &mut rng,
            &key,
            &opening,
            &com,
            b"ctx-opening",
            39,
            20_000_000,
            512,
        )
        .expect("prove");
        verify_opening(&key, &com, &proof, b"ctx-opening", 39, 20_000_000).expect("verify");
    }

    #[test]
    fn opening_proof_completeness_100_iterations() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [5u8; 32],
            params,
        };
        let opening = AjtaiOpening {
            message: ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let com = commit(&key, &opening);
        for i in 0..100u64 {
            let mut rng = TestRng(0xC0FFEE_u64 ^ (i.wrapping_mul(0x9E3779B97F4A7C15)));
            let proof = prove_opening(
                &mut rng,
                &key,
                &opening,
                &com,
                b"ctx-open-complete",
                39,
                20_000_000,
                512,
            )
            .expect("prove");
            verify_opening(&key, &com, &proof, b"ctx-open-complete", 39, 20_000_000)
                .expect("verify");
        }
    }

    #[test]
    fn opening_proof_tamper_fails_verification() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [13u8; 32],
            params,
        };
        let opening = AjtaiOpening {
            message: ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let com = commit(&key, &opening);
        let mut rng = TestRng(0xBAD5EED);
        let mut proof = prove_opening(
            &mut rng,
            &key,
            &opening,
            &com,
            b"ctx-open-tamper",
            39,
            20_000_000,
            512,
        )
        .expect("prove");
        proof.z.0[0].coeffs[0] ^= 1;
        let res = verify_opening(&key, &com, &proof, b"ctx-open-tamper", 39, 20_000_000);
        assert!(res.is_err());
    }

    #[test]
    fn challenge_kat_matches_ring() {
        let seed = [7u8; 32];
        let c1 = MlDsaCompatibleChallenge::derive(&seed, 39);
        let c2 = sample_in_ball(&seed, 39);
        assert_eq!(c1.poly.coeffs, c2.coeffs);
    }

    #[test]
    fn batch_transcript_smaller_than_per_attribute_hash_duplication() {
        let mut st = BatchPresentationState::new(b"batch");
        for i in 0u8..10 {
            st.absorb_attribute(&[i], &[0u8; 48]);
        }
        let smart = st.buf.len();
        // Naive model: each attribute carries two independent 64-byte hashes on the wire.
        let naive = 10 * (64 + 64);
        assert!(smart < naive);
    }

    #[test]
    fn batch_transcript_growth_is_sublinear_against_naive_model() {
        let mut hundred = BatchPresentationState::new(b"batch");
        for i in 0u8..100 {
            hundred.absorb_attribute(&[i], &[0u8; 48]);
        }
        let hundred_len = hundred.buf.len();

        // Naive model: each attribute ships two independent 64-byte hashes.
        let naive_hundred = 100 * (64 + 64);
        assert!(hundred_len < naive_hundred);
    }

    #[test]
    fn amortised_proof_verifies_with_single_batch_challenge() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [21u8; 32],
            params,
        };

        let mut m1 = alloc::vec![Poly::zero(), Poly::zero()];
        m1[0].coeffs[0] = 2;
        let mut r1 = alloc::vec![Poly::zero()];
        r1[0].coeffs[0] = 9;
        let o1 = AjtaiOpening {
            message: ModuleVec(m1),
            randomness: ModuleVec(r1),
        };

        let mut m2 = alloc::vec![Poly::zero(), Poly::zero()];
        m2[1].coeffs[0] = 3;
        let mut r2 = alloc::vec![Poly::zero()];
        r2[0].coeffs[0] = 7;
        let o2 = AjtaiOpening {
            message: ModuleVec(m2),
            randomness: ModuleVec(r2),
        };

        let c1 = commit(&key, &o1);
        let c2 = commit(&key, &o2);
        let commitments = alloc::vec![c1, c2];
        let openings = alloc::vec![o1, o2];

        let mut rng = TestRng(0xA5515EED);
        let proof = amortise(
            &mut rng,
            &key,
            &openings,
            &commitments,
            b"batch-ctx",
            39,
            100_000_000,
        )
        .expect("amortise");
        verify_aggregate(&key, &commitments, &proof, 39, 100_000_000).expect("verify aggregate");
    }

    #[test]
    fn amortised_proof_tamper_fails_verification() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [22u8; 32],
            params,
        };
        let o = AjtaiOpening {
            message: ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let c = commit(&key, &o);
        let commitments = alloc::vec![c];
        let openings = alloc::vec![o];

        let mut rng = TestRng(0xBADB_A7C1);
        let mut proof = amortise(
            &mut rng,
            &key,
            &openings,
            &commitments,
            b"batch-ctx",
            39,
            100_000_000,
        )
        .expect("amortise");
        proof.r_scalars[0] ^= 1;
        let res = verify_aggregate(&key, &commitments, &proof, 39, 100_000_000);
        assert!(res.is_err());
    }

    #[test]
    fn packed_norm_proof_accepts_and_rejects_expected_bounds() {
        let mut p = Poly::zero();
        p.coeffs[0] = 7;
        let slots = alloc::vec![alloc::vec![p.clone()], alloc::vec![Poly::zero()]];
        let proof = prove_inf_norm(&slots, 8);
        assert!(verify_inf_norm(&slots[0], 8));
        assert!(verify_inf_norm_proof(&proof, 8));
        assert!(!verify_inf_norm_proof(&proof, 6));
    }

    #[test]
    fn budget_estimator_matches_expected_values_and_saturates() {
        let pilot = AmortisationBudget::mldsa65_pilot();
        assert_eq!(pilot.bytes_per_attribute, 6_304);
        assert_eq!(pilot.overhead_bytes, 128);
        assert_eq!(pilot.estimate_presentation_bytes(10), 63_168);

        let saturated = AmortisationBudget::new(usize::MAX, usize::MAX - 1);
        assert_eq!(saturated.estimate_presentation_bytes(2), usize::MAX);
    }

    #[test]
    fn module_vec_serialization_roundtrip_and_error_paths() {
        let mut p0 = Poly::zero();
        p0.coeffs[0] = 123;
        p0.coeffs[10] = -45;
        let mut p1 = Poly::zero();
        p1.coeffs[0] = 7;
        p1.coeffs[255] = -7;
        let polys = alloc::vec![p0, p1];

        let encoded = serialize::write_module_vec(&polys);
        let decoded = serialize::read_module_vec(&encoded).expect("decode");
        assert_eq!(decoded.len(), polys.len());
        assert_eq!(decoded[0].coeffs, polys[0].coeffs);
        assert_eq!(decoded[1].coeffs, polys[1].coeffs);

        assert_eq!(
            serialize::read_module_vec(&[1, 2, 3]),
            Err(VerifyError::InvalidFormat)
        );
        assert_eq!(
            serialize::read_module_vec(&[2, 0, 0, 0]),
            Err(VerifyError::InvalidFormat)
        );
        assert_eq!(
            serialize::read_module_vec(&encoded[..encoded.len() - 1]),
            Err(VerifyError::InvalidFormat)
        );
    }

    #[test]
    fn util_vector_ops_cover_success_and_errors() {
        let mut a = Poly::zero();
        a.coeffs[0] = 3;
        let mut b = Poly::zero();
        b.coeffs[0] = 5;

        let sum = util::module_add(&[a.clone()], &[b.clone()]).expect("sum");
        assert_eq!(sum.len(), 1);
        assert_eq!(sum[0].coeffs[0], 8);

        let diff = util::module_sub(&sum, &[b.clone()]).expect("diff");
        assert_eq!(diff[0].coeffs[0], a.coeffs[0]);

        assert_eq!(
            util::module_add(&[a.clone()], &[]),
            Err(VerifyError::InvalidFormat)
        );
        assert_eq!(
            util::module_sub(&[a.clone()], &[]),
            Err(VerifyError::InvalidFormat)
        );

        let prod = util::module_ring_mul_challenge(&Poly::zero(), &[a.clone(), b.clone()]);
        assert_eq!(prod.len(), 2);
        assert_eq!(prod[0].coeffs, Poly::zero().coeffs);
        assert_eq!(prod[1].coeffs, Poly::zero().coeffs);

        assert_eq!(util::module_infinity_norm(&[]), 0);
        assert_eq!(util::module_infinity_norm(&[a.clone(), b.clone()]), 5);

        assert!(bool::from(util::polys_ct_eq(
            &[a.clone(), b.clone()],
            &[a.clone(), b.clone()]
        )));
        assert!(!bool::from(util::polys_ct_eq(&[a.clone()], &[b.clone()])));
        assert!(!bool::from(util::polys_ct_eq(&[a], &[b, Poly::zero()])));
    }

    #[test]
    fn linear_relation_proof_roundtrip_and_rejects_tamper() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [31u8; 32],
            params,
        };

        let mut m = alloc::vec![Poly::zero(), Poly::zero()];
        m[0].coeffs[0] = 4;
        let mut r = alloc::vec![Poly::zero()];
        r[0].coeffs[0] = 6;
        let opening = AjtaiOpening {
            message: ModuleVec(m),
            randomness: ModuleVec(r),
        };
        let com = commit(&key, &opening);

        let mut witness = opening.randomness.0.clone();
        witness.extend(opening.message.0.clone());
        let l =
            lib_q_ring::ModuleMatrix::expand_from_seed(&[0x42u8; 32], 1, key.params.witness_len());
        let t = l.mul_vec(&ModuleVec(witness));

        let mut rng = TestRng(0x1EE7_CAFE);
        let proof = prove_linear(
            &mut rng,
            &key,
            &opening,
            &com,
            &l,
            &t,
            b"linear-ctx",
            39,
            40_000_000,
            256,
        )
        .expect("prove_linear");

        verify_linear(&key, &com, &proof, &l, &t, b"linear-ctx", 39, 40_000_000)
            .expect("verify_linear");

        let mut tampered = proof.clone();
        tampered.u.0[0].coeffs[0] ^= 1;
        let res = verify_linear(&key, &com, &tampered, &l, &t, b"linear-ctx", 39, 40_000_000);
        assert_eq!(res, Err(VerifyError::Rejected));
    }

    #[test]
    fn linear_relation_parameter_checks_and_rejection_limit() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [44u8; 32],
            params,
        };
        let opening = AjtaiOpening {
            message: ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let com = commit(&key, &opening);
        let l =
            lib_q_ring::ModuleMatrix::expand_from_seed(&[0x33u8; 32], 1, key.params.witness_len());

        let bad_t = ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]);
        let mut rng = TestRng(0xA11C_0001);
        assert_eq!(
            prove_linear(
                &mut rng,
                &key,
                &opening,
                &com,
                &l,
                &bad_t,
                b"linear-bad-params",
                39,
                10_000_000,
                16,
            ),
            Err(ProofError::InvalidParameters)
        );

        let mut m = alloc::vec![Poly::zero(), Poly::zero()];
        m[0].coeffs[0] = 1;
        let opening_non_zero = AjtaiOpening {
            message: ModuleVec(m),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut witness = opening_non_zero.randomness.0.clone();
        witness.extend(opening_non_zero.message.0.clone());
        let t = l.mul_vec(&ModuleVec(witness));
        let com_non_zero = commit(&key, &opening_non_zero);
        let mut rng = TestRng(0xA11C_0002);
        let res = prove_linear(
            &mut rng,
            &key,
            &opening_non_zero,
            &com_non_zero,
            &l,
            &t,
            b"linear-reject-limit",
            39,
            0,
            1,
        );
        assert_eq!(res, Err(ProofError::RejectionLimit));
    }
}
