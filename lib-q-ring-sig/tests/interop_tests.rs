//! Cross-module federation and credential checks.

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    prove_opening,
};
use lib_q_ring::{
    ModuleVec,
    Poly,
};
use lib_q_ring_sig::{
    CredentialPresentation,
    FederationRing,
    MemberIssuerKey,
    RingSigParams,
    attribute_message_digest,
    federation_digest,
    sign_dualring_lb,
    sign_federation_message,
    verify_credential_presentation,
    verify_dualring_lb,
    verify_federation_opening_scan,
};
use rand_chacha::{
    ChaCha8Rng,
    ChaCha20Rng,
};
use rand_core::SeedableRng;

#[inline]
fn interop_test_deterministic_seed32(tag: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&tag.to_le_bytes());
    s
}

fn crs() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: [0x5Au8; 32],
        params: AjtaiParameters::new(2, 1),
    }
}

#[test]
fn federation_scan_finds_signer() {
    let key = crs();
    let p = RingSigParams::mldsa65_pilot();
    let o0 = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let m1 = MemberIssuerKey::from_opening(&key, o0).expect("m0");
    let mut mvec = vec![Poly::zero(), Poly::zero()];
    mvec[0].coeffs[0] = 4;
    let o1 = AjtaiOpening {
        message: ModuleVec(mvec),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let m2 = MemberIssuerKey::from_opening(&key, o1).expect("m1");
    let ring_slice = [m1.commitment.clone(), m2.commitment.clone()];
    let digest = federation_digest(&ring_slice);
    assert_ne!(digest, [0u8; 32]);

    let mut rng = ChaCha8Rng::from_seed(interop_test_deterministic_seed32(0xC0DE_u64));
    let msg = b"policy-digest";
    let proof = sign_federation_message(
        &mut rng,
        &key,
        &m2.opening,
        &m2.commitment,
        &ring_slice,
        msg,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("sign");
    let idx = verify_federation_opening_scan(&key, &ring_slice, msg, &proof, p.tau, p.z_inf_bound)
        .expect("scan");
    assert_eq!(idx, 1);
}

#[test]
fn credential_presentation_roundtrip() {
    let key = crs();
    let p = RingSigParams::mldsa65_pilot();

    let attr_opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let attr_com = lib_q_lattice_zkp::commit(&key, &attr_opening);

    let mut rng = ChaCha8Rng::from_seed(interop_test_deterministic_seed32(0xF00D_u64));
    let attr_proof = prove_opening(
        &mut rng,
        &key,
        &attr_opening,
        &attr_com,
        b"attr-ctx",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("attr prove");

    let issuer_opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let issuer = MemberIssuerKey::from_opening(&key, issuer_opening).expect("issuer");

    let mut other = vec![Poly::zero(), Poly::zero()];
    other[0].coeffs[0] = 2;
    let other_opening = AjtaiOpening {
        message: ModuleVec(other),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let other_member = MemberIssuerKey::from_opening(&key, other_opening).expect("other");

    let ring = FederationRing {
        members: vec![other_member.commitment, issuer.commitment.clone()],
    };
    let msg = attribute_message_digest(&attr_com);
    let mut rng2 = ChaCha8Rng::from_seed(interop_test_deterministic_seed32(0xBEEF_u64));
    let fed_proof = sign_dualring_lb(
        &mut rng2,
        &key,
        &issuer.opening,
        &issuer.commitment,
        ring.as_slice(),
        &msg,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("dualring prove");

    let pres = CredentialPresentation {
        attribute_commitment: attr_com,
        attribute_opening_proof: attr_proof,
        ring_signature: fed_proof,
    };
    verify_credential_presentation(
        &key,
        ring.as_slice(),
        &pres,
        b"attr-ctx",
        p.tau,
        p.z_inf_bound,
    )
    .expect("credential ok");
}

#[test]
fn dualring_lb_verify_runs_full_ring() {
    let key = crs();
    let p = RingSigParams::mldsa65_pilot();
    let a = MemberIssuerKey::from_opening(
        &key,
        AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    )
    .expect("a");
    let mut m = vec![Poly::zero(), Poly::zero()];
    m[0].coeffs[0] = 4;
    let b = MemberIssuerKey::from_opening(
        &key,
        AjtaiOpening {
            message: ModuleVec(m),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    )
    .expect("b");
    let ring_slice = [a.commitment.clone(), b.commitment.clone()];
    let mut rng = ChaCha20Rng::from_seed([0xD1u8; 32]);
    let sig = sign_dualring_lb(
        &mut rng,
        &key,
        &b.opening,
        &b.commitment,
        &ring_slice,
        b"dr-msg",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("dualring sign");
    verify_dualring_lb(&key, &ring_slice, b"dr-msg", &sig, p.tau, p.z_inf_bound)
        .expect("dualring verify");
}
