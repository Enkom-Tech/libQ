//! Cross-crate smoke tests for privacy protocol building blocks (lattice ZKP, ring signatures).

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    AnonymousToken,
    BlindIssuance,
    BlindIssuerKeypair,
    BlindRequest,
    BlindSignature,
    MerklePath,
    ProofError,
    TOKEN_EPOCH_LEN,
    TOKEN_ORIGIN_LEN,
    TOKEN_SERIAL_LEN,
    UnblindedBlindSignature,
    amortise,
    commit,
    encode_pvtn_leaf,
    leaf_hash,
    node_hash,
    opening_ctx_with_nullifier,
    opening_from_token_fields,
    prove_level_membership,
    prove_nullifier_opening,
    prove_opening,
    prove_private_membership,
    prove_witness_nullifier_opening,
    registry_nullifier,
    uniqueness_amortisation_label,
    verify_aggregate,
    verify_level_membership,
    verify_nullifier_opening,
    verify_private_membership,
    verify_witness_nullifier_opening,
    witness_nullifier,
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
    sign_dualring_lb,
    sign_federation_message,
    verify_credential_presentation,
    verify_dualring_lb,
    verify_federation_opening,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[inline]
fn test_seed32(tag: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&tag.to_le_bytes());
    seed
}

fn pilot_crs() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: [0x71u8; 32],
        params: AjtaiParameters::new(2, 1),
    }
}

#[test]
fn blind_issuance_token_fields_and_nullifier_amortisation() {
    let key = pilot_crs();
    let p = RingSigParams::mldsa65_pilot();
    let user_opening = opening_from_token_fields(
        2,
        1,
        &[7u8; TOKEN_SERIAL_LEN],
        &[3u8; TOKEN_ORIGIN_LEN],
        &[1u8; TOKEN_EPOCH_LEN],
    )
    .expect("token opening layout");
    let mut rng = ChaCha20Rng::from_seed(test_seed32(0xB1A4_u64));
    let (_req, user_st) =
        BlindIssuance::request(&mut rng, &key, user_opening.clone()).expect("blind req");
    let issuer_opening = lib_q_lattice_zkp::sigma::opening::sample_random_opening(&mut rng, &key);
    let blind_req = BlindRequest {
        com_blinded: user_st.com_blinded.clone(),
    };
    let resp = BlindIssuance::issuer_sign(
        &mut rng,
        &key,
        &blind_req,
        &issuer_opening,
        b"integration-realm",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("issuer");
    let bundle = BlindIssuance::finalize(user_st, resp).expect("finalize");
    BlindIssuance::verify(&key, &bundle, b"integration-realm", p.tau, p.z_inf_bound)
        .expect("blind verify");

    let mut fs_rng = ChaCha20Rng::from_seed(test_seed32(0x50E4_u64));
    let token_proof = prove_opening(
        &mut fs_rng,
        &key,
        &bundle.token_opening,
        &bundle.com_blinded,
        b"token-spend",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("token proof");
    let token = AnonymousToken {
        commitment: bundle.com_blinded.clone(),
        serial: [7u8; TOKEN_SERIAL_LEN],
        origin: [3u8; TOKEN_ORIGIN_LEN],
        epoch_le: [1u8; TOKEN_EPOCH_LEN],
        opening_proof: token_proof,
    };
    token
        .verify_opening_only(&key, b"token-spend", p.tau, p.z_inf_bound)
        .expect("token opening");
    let spend = token.spend();
    spend
        .verify(
            &key,
            &token.commitment,
            b"token-spend",
            p.tau,
            p.z_inf_bound,
            &token.serial,
        )
        .expect("spend verify");

    let realm = b"sybil-realm";
    let n = registry_nullifier(&bundle.com_blinded, realm);
    let mut n_rng = ChaCha20Rng::from_seed(test_seed32(0xD06_u64));
    let np = prove_nullifier_opening(
        &mut n_rng,
        &key,
        &bundle.token_opening,
        &bundle.com_blinded,
        b"pop",
        realm,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("nullifier proof");
    verify_nullifier_opening(
        &key,
        &bundle.com_blinded,
        realm,
        b"pop",
        &np,
        p.tau,
        p.z_inf_bound,
    )
    .expect("nullifier verify");

    let ctx = opening_ctx_with_nullifier(b"pop", &n);
    assert!(!ctx.is_empty());

    let c2 = commit(
        &key,
        &AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    );
    let commitments = vec![bundle.com_blinded.clone(), c2];
    let o2 = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let openings = vec![bundle.token_opening.clone(), o2];
    let label = uniqueness_amortisation_label(realm, &commitments);
    let mut ap_opt: Result<lib_q_lattice_zkp::AmortisedProof, ProofError> =
        Err(ProofError::RejectionLimit);
    for attempt in 0u64..128 {
        let mut ar = ChaCha20Rng::from_seed(test_seed32(0xA_u64 ^ attempt));
        ap_opt = amortise(
            &mut ar,
            &key,
            &openings,
            &commitments,
            &label,
            p.tau,
            500_000_000,
        );
        if ap_opt.is_ok() {
            break;
        }
    }
    let ap = ap_opt.expect("amortise");
    verify_aggregate(&key, &commitments, &ap, p.tau, 500_000_000).expect("batch");
}

#[test]
fn federation_ring_opening_integration() {
    let key = pilot_crs();
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
    let ring = [a.commitment.clone(), b.commitment.clone()];
    let mut rng = ChaCha20Rng::seed_from_u64(0xE11E);
    let proof = sign_federation_message(
        &mut rng,
        &key,
        &b.opening,
        &b.commitment,
        &ring,
        b"fed-msg",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("sign");
    verify_federation_opening(&key, &ring, 1, b"fed-msg", &proof, p.tau, p.z_inf_bound)
        .expect("fed verify");
}

#[test]
fn credential_lifecycle_end_to_end() {
    // End-to-end flow: blind issuance produces a token commitment, the issuer
    // (a federation member) signs the token's attribute digest, and the verifier
    // accepts the resulting CredentialPresentation via DualRing-LB–style full-ring verify.
    let key = pilot_crs();
    let p = RingSigParams::mldsa65_pilot();

    let user_opening = opening_from_token_fields(
        2,
        1,
        &[7u8; TOKEN_SERIAL_LEN],
        &[3u8; TOKEN_ORIGIN_LEN],
        &[1u8; TOKEN_EPOCH_LEN],
    )
    .expect("token layout");
    let mut rng = ChaCha20Rng::from_seed(test_seed32(0xB1A4_u64));
    let (_req, user_st) =
        BlindIssuance::request(&mut rng, &key, user_opening).expect("blind request");
    let issuer_blind_opening =
        lib_q_lattice_zkp::sigma::opening::sample_random_opening(&mut rng, &key);
    let blind_req = BlindRequest {
        com_blinded: user_st.com_blinded.clone(),
    };
    let resp = BlindIssuance::issuer_sign(
        &mut rng,
        &key,
        &blind_req,
        &issuer_blind_opening,
        b"credential-realm",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("issuer blind sign");
    let bundle = BlindIssuance::finalize(user_st, resp).expect("finalize");
    BlindIssuance::verify(&key, &bundle, b"credential-realm", p.tau, p.z_inf_bound)
        .expect("blind bundle verify");

    // Holder proves opening for the blinded token commitment under the attribute context
    // so the verifier can check it without learning the secret token fields.
    let attr_fs_ctx: &[u8] = b"credential-attribute";
    let mut attr_rng = ChaCha20Rng::from_seed(test_seed32(0x50E4_u64));
    let attribute_opening_proof = prove_opening(
        &mut attr_rng,
        &key,
        &bundle.token_opening,
        &bundle.com_blinded,
        attr_fs_ctx,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("attribute opening proof");

    // Build a federation ring of two issuers; the second member signs the attribute digest.
    let other_issuer = MemberIssuerKey::from_opening(
        &key,
        AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    )
    .expect("other issuer");
    let mut signing_msg = vec![Poly::zero(), Poly::zero()];
    signing_msg[0].coeffs[0] = 9;
    let signing_issuer = MemberIssuerKey::from_opening(
        &key,
        AjtaiOpening {
            message: ModuleVec(signing_msg),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    )
    .expect("signing issuer");
    let ring = FederationRing {
        members: vec![
            other_issuer.commitment.clone(),
            signing_issuer.commitment.clone(),
        ],
    };

    let attr_digest = attribute_message_digest(&bundle.com_blinded);
    let mut fed_rng = ChaCha20Rng::from_seed([0x22; 32]);
    let ring_signature = sign_dualring_lb(
        &mut fed_rng,
        &key,
        &signing_issuer.opening,
        &signing_issuer.commitment,
        ring.as_slice(),
        &attr_digest,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("dualring-lb sign");

    // Sanity checks before bundling into a presentation.
    lib_q_lattice_zkp::verify_opening(
        &key,
        &bundle.com_blinded,
        &attribute_opening_proof,
        attr_fs_ctx,
        p.tau,
        p.z_inf_bound,
    )
    .expect("standalone attribute proof verifies");
    verify_dualring_lb(
        &key,
        ring.as_slice(),
        &attr_digest,
        &ring_signature,
        p.tau,
        p.z_inf_bound,
    )
    .expect("standalone dualring-lb proof verifies");

    let presentation = CredentialPresentation {
        attribute_commitment: bundle.com_blinded.clone(),
        attribute_opening_proof,
        ring_signature,
    };
    verify_credential_presentation(
        &key,
        ring.as_slice(),
        &presentation,
        attr_fs_ctx,
        p.tau,
        p.z_inf_bound,
    )
    .expect("credential presentation verify");
}

#[test]
fn token_double_spend_detection() {
    // Two SpendingProofs derived from the same token must carry the same serial so an
    // application-layer registry can reject the second use; both must also verify
    // independently against the token commitment under the spend context.
    let key = pilot_crs();
    let p = RingSigParams::mldsa65_pilot();
    let serial = [0x42u8; TOKEN_SERIAL_LEN];
    let origin = [0x07u8; TOKEN_ORIGIN_LEN];
    let epoch = [0x01u8; TOKEN_EPOCH_LEN];
    let opening = opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("layout");
    let com = commit(&key, &opening);
    let mut rng = ChaCha20Rng::from_seed(test_seed32(0xDEAD_BEEF_u64));
    let proof = prove_opening(
        &mut rng,
        &key,
        &opening,
        &com,
        b"token-spend-replay",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("token proof");
    let token = AnonymousToken {
        commitment: com,
        serial,
        origin,
        epoch_le: epoch,
        opening_proof: proof,
    };

    let first = token.spend();
    let second = token.spend();
    assert_eq!(
        first.serial, second.serial,
        "spending the same token twice must reuse the serial for replay detection"
    );
    assert_eq!(first.serial, serial);

    first
        .verify(
            &key,
            &token.commitment,
            b"token-spend-replay",
            p.tau,
            p.z_inf_bound,
            &serial,
        )
        .expect("first spend verifies");
    second
        .verify(
            &key,
            &token.commitment,
            b"token-spend-replay",
            p.tau,
            p.z_inf_bound,
            &serial,
        )
        .expect("second spend verifies (registry must reject by serial)");

    // A spending proof under a wrong expected serial must be rejected.
    let mut wrong = serial;
    wrong[0] ^= 0xFF;
    assert!(
        first
            .verify(
                &key,
                &token.commitment,
                b"token-spend-replay",
                p.tau,
                p.z_inf_bound,
                &wrong,
            )
            .is_err(),
        "verifier must reject spending proofs whose serial does not match the expected token serial"
    );
}

#[test]
fn hierarchical_auth_cross_crate() {
    // Build a 4-leaf Merkle tree, prove level membership for the second leaf, and
    // verify acceptance at clearance levels at or below the leaf's declared level
    // and rejection above it.
    let key = pilot_crs();
    let p = RingSigParams::mldsa65_pilot();

    let role = [0xA5u8; 16];
    let parent = [0u8; 32];
    let target_clearance: u32 = 5;
    let target_payload = encode_pvtn_leaf(target_clearance, &role, &parent);

    let leaf0 = leaf_hash(b"leaf-0");
    let leaf1 = leaf_hash(&target_payload);
    let leaf2 = leaf_hash(b"leaf-2");
    let leaf3 = leaf_hash(b"leaf-3");
    let n01 = node_hash(&leaf0, &leaf1);
    let n23 = node_hash(&leaf2, &leaf3);
    let root = node_hash(&n01, &n23);

    // Path for `target_payload` (leaf1): sibling at level 0 is leaf0 (target is right child),
    // sibling at level 1 is n23 (target is left child after first hash).
    let path = MerklePath {
        directions: vec![false, true],
        siblings: vec![leaf0, n23],
    };

    let credential_opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let credential_com = commit(&key, &credential_opening);
    let mut rng = ChaCha20Rng::from_seed(test_seed32(0xC1EA_C0DE_u64));
    let proof = prove_level_membership(
        &mut rng,
        &key,
        &credential_opening,
        &credential_com,
        target_payload,
        path,
        &root,
        target_clearance,
        b"pvt-cross-crate",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("prove level membership");

    verify_level_membership(
        &key,
        &proof,
        &root,
        target_clearance,
        b"pvt-cross-crate",
        p.tau,
        p.z_inf_bound,
    )
    .expect("verify at exact clearance");
    verify_level_membership(
        &key,
        &proof,
        &root,
        target_clearance - 1,
        b"pvt-cross-crate",
        p.tau,
        p.z_inf_bound,
    )
    .expect("verify at lower clearance requirement");
    assert!(
        verify_level_membership(
            &key,
            &proof,
            &root,
            target_clearance + 1,
            b"pvt-cross-crate",
            p.tau,
            p.z_inf_bound,
        )
        .is_err(),
        "verifier must reject when min_clearance exceeds the leaf level"
    );
}

#[test]
fn blind_signature_pilot_integration() {
    let key = pilot_crs();
    let p = RingSigParams::mldsa65_pilot();
    let user_opening = opening_from_token_fields(
        2,
        1,
        &[9u8; TOKEN_SERIAL_LEN],
        &[2u8; TOKEN_ORIGIN_LEN],
        &[3u8; TOKEN_EPOCH_LEN],
    )
    .expect("opening");
    let mut rng = ChaCha20Rng::from_seed(test_seed32(0xB10Cu64));
    let (req, user_st) = BlindIssuance::request(&mut rng, &key, user_opening).expect("request");
    let issuer = BlindIssuerKeypair::sample(&mut rng, &key);
    let (resp, digest) = BlindIssuance::issuer_sign_message(
        &mut rng,
        &key,
        &req,
        &issuer,
        b"integration-policy",
        b"blind-sig-ctx",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("issuer_sign_message");
    let bundle: UnblindedBlindSignature =
        BlindIssuance::finalize_message(user_st, resp, digest).expect("finalize_message");
    bundle
        .verify_blind_signature(&key, b"blind-sig-ctx", p.tau, p.z_inf_bound)
        .expect("BlindSignature::verify_blind_signature");
}

#[test]
fn witness_nullifier_same_witness_two_commitment_keys_integration() {
    let p = RingSigParams::mldsa65_pilot();
    let params = AjtaiParameters::new(2, 1);
    let key_a = AjtaiCommitmentKey {
        seed: [0x01u8; 32],
        params: params.clone(),
    };
    let key_b = AjtaiCommitmentKey {
        seed: [0x02u8; 32],
        params,
    };
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let opening = lib_q_lattice_zkp::sigma::opening::sample_random_opening(&mut rng, &key_a);
    let com_a = commit(&key_a, &opening);
    let com_b = commit(&key_b, &opening);
    let realm = b"witness-realm";
    assert_eq!(
        witness_nullifier(&opening, realm),
        witness_nullifier(&opening, realm)
    );
    assert_ne!(com_a, com_b);

    let mut pr = ChaCha20Rng::from_seed([0x51u8; 32]);
    let proof_a = prove_witness_nullifier_opening(
        &mut pr,
        &key_a,
        &opening,
        &com_a,
        b"pop",
        realm,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("prove a");
    verify_witness_nullifier_opening(
        &key_a,
        &com_a,
        realm,
        b"pop",
        &proof_a,
        Some(&opening),
        p.tau,
        p.z_inf_bound,
    )
    .expect("verify a");

    let mut pr2 = ChaCha20Rng::from_seed([0x52u8; 32]);
    let proof_b = prove_witness_nullifier_opening(
        &mut pr2,
        &key_b,
        &opening,
        &com_b,
        b"pop",
        realm,
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("prove b");
    verify_witness_nullifier_opening(
        &key_b,
        &com_b,
        realm,
        b"pop",
        &proof_b,
        Some(&opening),
        p.tau,
        p.z_inf_bound,
    )
    .expect("verify b");
    assert_eq!(proof_a.nullifier, proof_b.nullifier);
}

#[test]
fn dualring_lb_full_ring_verify_integration() {
    let key = pilot_crs();
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
    m[0].coeffs[0] = 6;
    let b = MemberIssuerKey::from_opening(
        &key,
        AjtaiOpening {
            message: ModuleVec(m),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    )
    .expect("b");
    let ring = [a.commitment.clone(), b.commitment.clone()];
    let mut rng = ChaCha20Rng::from_seed([0xC0; 32]);
    let sig = sign_dualring_lb(
        &mut rng,
        &key,
        &b.opening,
        &b.commitment,
        &ring,
        b"dualring-lb-it",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("sign dualring lb");
    verify_dualring_lb(&key, &ring, b"dualring-lb-it", &sig, p.tau, p.z_inf_bound)
        .expect("verify dualring lb");
}

#[test]
fn private_membership_pilot_integration() {
    let key = pilot_crs();
    let p = RingSigParams::mldsa65_pilot();
    let role = [0x5Au8; 16];
    let parent = [0u8; 32];
    let leaf_payload = encode_pvtn_leaf(8, &role, &parent);
    let l0 = leaf_hash(b"pm-leaf-0");
    let l1 = leaf_hash(&leaf_payload);
    let root = node_hash(&l0, &l1);
    let path = MerklePath {
        directions: vec![false],
        siblings: vec![l0],
    };
    let credential_opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let credential_com = commit(&key, &credential_opening);
    let mut rng = ChaCha20Rng::from_seed(test_seed32(0x51A1_C0DEu64));
    let proof = prove_private_membership(
        &mut rng,
        &key,
        &credential_opening,
        &credential_com,
        leaf_payload,
        path,
        &root,
        3,
        b"pm-integration",
        p.tau,
        p.z_inf_bound,
        p.max_prove_attempts,
    )
    .expect("prove private membership");
    verify_private_membership(
        &key,
        &proof,
        &root,
        3,
        b"pm-integration",
        p.tau,
        p.z_inf_bound,
    )
    .expect("verify private membership");
}

#[test]
fn ring_sig_params_nist_category_profiles_distinct() {
    let c1 = RingSigParams::nist_security_category_1();
    let c3 = RingSigParams::nist_security_category_3();
    let c5 = RingSigParams::nist_security_category_5();
    assert!(c1.tau < c3.tau && c3.tau < c5.tau);
    assert!(c1.z_inf_bound < c3.z_inf_bound && c3.z_inf_bound < c5.z_inf_bound);
}
