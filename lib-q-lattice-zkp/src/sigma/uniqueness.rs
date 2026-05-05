//! Nullifier helpers for double-spend detection.
//!
//! ## Registry nullifier ([`registry_nullifier`])
//!
//! The digest `SHAKE256( wire(com) ‖ realm )` is deterministic for a fixed commitment
//! image and realm label. Anyone who knows `com` can compute it; it is appropriate for
//! commitment-keyed registries.
//!
//! ## Witness nullifier ([`witness_nullifier`])
//!
//! The digest `SHAKE256( domain ‖ wire(message) ‖ wire(randomness) ‖ realm )` depends only
//! on the secret opening witness (and realm), not on the commitment image. Two distinct
//! commitments under different CRS seeds that open the same witness polynomials share the
//! same witness nullifier—useful for cross-commitment linkability at the application layer.
//!
//! [`NullifierOpeningProof`] / [`WitnessNullifierOpeningProof`] bind the respective digest
//! into the Fiat–Shamir context of an opening proof so verifiers re-derive the same nullifier
//! during verification.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use crate::commitment::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
};
use crate::error::{
    ProofError,
    VerifyError,
};
use crate::serialize::write_module_vec;
use crate::sigma::amortise::BatchPresentationState;
use crate::sigma::opening::{
    OpeningProof,
    prove_opening,
    verify_opening,
};

const WITNESS_NULLIFIER_DOMAIN: &[u8] = b"lattice-zkp/witness-null/v1";

/// Serialize `(message ‖ randomness)` witness blocks for nullifier derivation.
#[must_use]
pub fn witness_wire(opening: &AjtaiOpening) -> Vec<u8> {
    let mut v = write_module_vec(&opening.message.0);
    v.extend_from_slice(&write_module_vec(&opening.randomness.0));
    v
}

/// Deterministic nullifier derived from the opening witness (message and randomness blocks).
#[must_use]
pub fn witness_nullifier(opening: &AjtaiOpening, realm: &[u8]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(WITNESS_NULLIFIER_DOMAIN);
    h.update(&witness_wire(opening));
    h.update(realm);
    let mut out = [0u8; 32];
    let mut reader = h.finalize_xof();
    XofReader::read(&mut reader, &mut out);
    out
}

/// Deterministic nullifier for a commitment under a realm / context label.
pub fn registry_nullifier(com: &AjtaiCommitment, realm: &[u8]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(&write_module_vec(&com.value.0));
    h.update(realm);
    let mut out = [0u8; 32];
    let mut reader = h.finalize_xof();
    XofReader::read(&mut reader, &mut out);
    out
}

/// Build Fiat–Shamir context bytes that bind an opening proof transcript to a nullifier.
pub fn opening_ctx_with_nullifier(base_ctx: &[u8], nullifier: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(base_ctx.len() + 1 + 32);
    v.extend_from_slice(base_ctx);
    v.push(0);
    v.extend_from_slice(nullifier);
    v
}

/// Build Fiat–Shamir context bytes that bind an opening proof transcript to a witness nullifier.
#[must_use]
pub fn opening_ctx_with_witness_nullifier(base_ctx: &[u8], nullifier: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(base_ctx.len() + 1 + 32);
    v.extend_from_slice(base_ctx);
    v.push(1);
    v.extend_from_slice(nullifier);
    v
}

/// Proof bundle tying an opening to [`registry_nullifier`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifierOpeningProof {
    pub nullifier: [u8; 32],
    pub opening: OpeningProof,
}

/// Proof bundle tying an opening to [`witness_nullifier`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessNullifierOpeningProof {
    pub nullifier: [u8; 32],
    pub opening: OpeningProof,
}

/// Prove knowledge of an opening for `com` with FS context that includes the realm nullifier.
#[allow(clippy::too_many_arguments)]
pub fn prove_nullifier_opening<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    opening: &AjtaiOpening,
    com: &AjtaiCommitment,
    base_ctx: &[u8],
    realm: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<NullifierOpeningProof, ProofError> {
    let nullifier = registry_nullifier(com, realm);
    let ctx = opening_ctx_with_nullifier(base_ctx, &nullifier);
    let opening_proof =
        prove_opening(rng, key, opening, com, &ctx, tau, z_inf_bound, max_attempts)?;
    Ok(NullifierOpeningProof {
        nullifier,
        opening: opening_proof,
    })
}

/// Verify [`prove_nullifier_opening`].
#[allow(clippy::too_many_arguments)]
pub fn verify_nullifier_opening(
    key: &AjtaiCommitmentKey,
    com: &AjtaiCommitment,
    realm: &[u8],
    base_ctx: &[u8],
    proof: &NullifierOpeningProof,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let expect = registry_nullifier(com, realm);
    if expect != proof.nullifier {
        return Err(VerifyError::Rejected);
    }
    let ctx = opening_ctx_with_nullifier(base_ctx, &proof.nullifier);
    verify_opening(key, com, &proof.opening, &ctx, tau, z_inf_bound)
}

/// Prove knowledge of an opening for `com` with FS context that includes the witness nullifier.
#[allow(clippy::too_many_arguments)]
pub fn prove_witness_nullifier_opening<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    opening: &AjtaiOpening,
    com: &AjtaiCommitment,
    base_ctx: &[u8],
    realm: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<WitnessNullifierOpeningProof, ProofError> {
    let nullifier = witness_nullifier(opening, realm);
    let ctx = opening_ctx_with_witness_nullifier(base_ctx, &nullifier);
    let opening_proof =
        prove_opening(rng, key, opening, com, &ctx, tau, z_inf_bound, max_attempts)?;
    Ok(WitnessNullifierOpeningProof {
        nullifier,
        opening: opening_proof,
    })
}

/// Verify [`prove_witness_nullifier_opening`].
///
/// When `witness` is [`Some`], checks `proof.nullifier == witness_nullifier(witness, realm)`.
/// When `witness` is [`None`], only the opening equation is checked (Fiat–Shamir binds the
/// carried `proof.nullifier` into the transcript; integrators that need equality to a secret
/// witness must supply [`Some`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_witness_nullifier_opening(
    key: &AjtaiCommitmentKey,
    com: &AjtaiCommitment,
    realm: &[u8],
    base_ctx: &[u8],
    proof: &WitnessNullifierOpeningProof,
    witness: Option<&AjtaiOpening>,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    if let Some(o) = witness {
        let expect = witness_nullifier(o, realm);
        if expect != proof.nullifier {
            return Err(VerifyError::Rejected);
        }
    }
    let ctx = opening_ctx_with_witness_nullifier(base_ctx, &proof.nullifier);
    verify_opening(key, com, &proof.opening, &ctx, tau, z_inf_bound)
}

/// Label bytes for [`crate::sigma::amortise::amortise`] that bind witness nullifiers for a batch.
#[must_use]
pub fn witness_uniqueness_amortisation_label(realm: &[u8], openings: &[AjtaiOpening]) -> Vec<u8> {
    let mut st = BatchPresentationState::new(b"lattice-zkp-witness-uniqueness-amort");
    st.buf.extend_from_slice(realm);
    for o in openings {
        let n = witness_nullifier(o, realm);
        st.buf.extend_from_slice(&n);
        st.buf.extend_from_slice(&witness_wire(o));
    }
    st.buf
}

/// Label bytes for [`crate::sigma::amortise::amortise`] that bind each commitment’s nullifier.
#[must_use]
pub fn uniqueness_amortisation_label(realm: &[u8], commitments: &[AjtaiCommitment]) -> Vec<u8> {
    let mut st = BatchPresentationState::new(b"lattice-zkp-uniqueness-amort");
    st.buf.extend_from_slice(realm);
    for c in commitments {
        let n = registry_nullifier(c, realm);
        st.buf.extend_from_slice(&n);
        st.buf.extend_from_slice(&write_module_vec(&c.value.0));
    }
    st.buf
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::commitment::{
        AjtaiCommitmentKey,
        AjtaiOpening,
        commit,
    };
    use crate::params::AjtaiParameters;
    use crate::sigma::amortise::{
        amortise,
        verify_aggregate,
    };

    #[derive(Debug)]
    struct TestRng(u64);

    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;

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

    impl rand_core::TryCryptoRng for TestRng {}

    #[test]
    fn nullifier_stable_for_same_commitment() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [1u8; 32],
            params,
        };
        let o = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let c = commit(&key, &o);
        let n1 = registry_nullifier(&c, b"realm-a");
        let n2 = registry_nullifier(&c, b"realm-a");
        assert_eq!(n1, n2);
        assert_ne!(
            registry_nullifier(&c, b"realm-a"),
            registry_nullifier(&c, b"realm-b")
        );
    }

    #[test]
    fn nullifier_opening_roundtrip() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [2u8; 32],
            params,
        };
        let o = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let c = commit(&key, &o);
        let mut rng = TestRng(0x5011_u64);
        let proof = prove_nullifier_opening(
            &mut rng, &key, &o, &c, b"ctx-n", b"realm-x", 39, 20_000_000, 512,
        )
        .expect("prove");
        verify_nullifier_opening(&key, &c, b"realm-x", b"ctx-n", &proof, 39, 20_000_000)
            .expect("verify");
    }

    #[test]
    fn uniqueness_label_amortises_with_openings() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [3u8; 32],
            params,
        };
        let o1 = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let c1 = commit(&key, &o1);
        let o2 = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let c2 = commit(&key, &o2);
        let commitments = alloc::vec![c1, c2];
        let openings = alloc::vec![o1, o2];
        let label = uniqueness_amortisation_label(b"realm-amort", &commitments);
        let mut ap = None;
        for attempt in 0u64..256 {
            let mut rng = TestRng(0xA11E_u64 ^ attempt);
            if let Ok(p) = amortise(
                &mut rng,
                &key,
                &openings,
                &commitments,
                &label,
                39,
                500_000_000,
            ) {
                ap = Some(p);
                break;
            }
        }
        let ap = ap.expect("amortise with retries");
        verify_aggregate(&key, &commitments, &ap, 39, 500_000_000).expect("verify batch");
    }

    #[test]
    fn witness_nullifier_same_for_different_commitment_keys_same_opening() {
        let params = AjtaiParameters::new(2, 1);
        let key1 = AjtaiCommitmentKey {
            seed: [0x11u8; 32],
            params: params.clone(),
        };
        let key2 = AjtaiCommitmentKey {
            seed: [0x22u8; 32],
            params,
        };
        let mut m0 = lib_q_ring::Poly::zero();
        m0.coeffs[0] = 3;
        let o = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![m0, lib_q_ring::Poly::zero()]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let c1 = commit(&key1, &o);
        let c2 = commit(&key2, &o);
        assert_ne!(
            c1, c2,
            "different CRS seeds must yield different commitments"
        );
        let n = witness_nullifier(&o, b"realm-w");
        assert_eq!(n, witness_nullifier(&o, b"realm-w"));
        assert_ne!(
            witness_nullifier(&o, b"realm-w"),
            witness_nullifier(&o, b"realm-x")
        );
    }

    #[test]
    fn witness_nullifier_opening_roundtrip() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [0x77u8; 32],
            params,
        };
        let o = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let c = commit(&key, &o);
        let mut rng = TestRng(0x5012_u64);
        let proof = prove_witness_nullifier_opening(
            &mut rng,
            &key,
            &o,
            &c,
            b"ctx-wn",
            b"realm-wn",
            39,
            20_000_000,
            512,
        )
        .expect("prove");
        verify_witness_nullifier_opening(
            &key,
            &c,
            b"realm-wn",
            b"ctx-wn",
            &proof,
            Some(&o),
            39,
            20_000_000,
        )
        .expect("verify");
    }
}
