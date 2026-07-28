//! IP soundness tests: identity token, credential, and group membership proof
//! soundness with wrong keys, roots, or attributes.

#![cfg(feature = "zkp")]

use lib_q_zkp::air::MerkleHash;
use lib_q_zkp::api::MerklePath;
use lib_q_zkp::ip::auth::{
    prove_group_membership,
    verify_group_membership,
};
use lib_q_zkp::ip::credential::{
    IpCredential,
    compute_credential_commitment,
    prove_credential_attributes,
    verify_credential_proof,
};
use lib_q_zkp::ip::identity::{
    identity_token_from_secret,
    prove_it_ownership,
    verify_it_ownership,
};

/// Assert that a verifier *ran to a verdict* and rejected.
///
/// The previous form, `assert!(!verify(..).unwrap_or(false))`, also passes when the verifier
/// returns `Err` — so it could not distinguish "correctly rejected" from "blew up before
/// reaching a verdict". Requiring `Ok(false)` makes the negative test discriminating.
#[track_caller]
fn assert_rejected<E: core::fmt::Debug>(result: Result<bool, E>, what: &str) {
    match result {
        Ok(false) => {}
        Ok(true) => panic!("{what}: verifier accepted an invalid proof"),
        Err(e) => panic!("{what}: verifier failed to reach a verdict: {e:?}"),
    }
}

/// Assert that a verifier ran to a verdict and accepted.
#[track_caller]
fn assert_accepted<E: core::fmt::Debug>(result: Result<bool, E>, what: &str) {
    match result {
        Ok(true) => {}
        Ok(false) => panic!("{what}: verifier rejected a valid proof"),
        Err(e) => panic!("{what}: verifier failed to reach a verdict: {e:?}"),
    }
}

#[test]
fn test_it_ownership_correct_it_verifies() {
    let sk1 = vec![7u8];
    let it1 = identity_token_from_secret(&sk1);
    let proof = prove_it_ownership(&it1, &sk1).unwrap();
    assert_accepted(
        verify_it_ownership(&proof, &it1),
        "correct IT (from identity_token_from_secret)",
    );
}

#[test]
fn test_it_ownership_wrong_key_same_it_fails() {
    let correct_key = vec![7u8];
    let it = identity_token_from_secret(&correct_key);
    let wrong_key = b"different key".to_vec();
    let proof = prove_it_ownership(&it, &wrong_key).unwrap();
    assert_rejected(
        verify_it_ownership(&proof, &it),
        "proof with wrong key (same IT)",
    );
}

#[test]
fn test_it_ownership_wrong_it_fails() {
    let (proof, _it1) = {
        let sk1 = [1u8; 32];
        let it1 = identity_token_from_secret(&sk1);
        let proof = prove_it_ownership(&it1, &sk1.to_vec()).unwrap();
        (proof, it1)
    };
    let (_proof2, it2) = {
        let sk2 = [2u8; 32];
        let it2 = identity_token_from_secret(&sk2);
        let proof2 = prove_it_ownership(&it2, &sk2.to_vec()).unwrap();
        (proof2, it2)
    };
    assert_rejected(verify_it_ownership(&proof, &it2), "wrong IT");
}

#[test]
fn test_group_membership_wrong_root_fails() {
    let member_key = b"member-key".to_vec();
    let path = MerklePath {
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
        ],
    };
    let proof = prove_group_membership(&member_key, &[0u8; 32], &path).unwrap();
    let wrong_root = [0xFFu8; 32];
    assert_rejected(verify_group_membership(&proof, &wrong_root), "wrong root");
}

#[test]
fn test_group_membership_cross_tree_fails() {
    let path1 = MerklePath {
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[2u8; 32]).unwrap(),
        ],
    };
    let path2 = MerklePath {
        path_bits: vec![true, false],
        siblings: vec![
            MerkleHash::from_bytes(&[10u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[20u8; 32]).unwrap(),
        ],
    };
    let member1 = b"member-one".to_vec();
    let member2 = b"member-two".to_vec();
    let proof_t1 = prove_group_membership(&member1, &[0u8; 32], &path1).unwrap();
    let _proof_t2 = prove_group_membership(&member2, &[0u8; 32], &path2).unwrap();
    let root_t2 = [0x42u8; 32];
    assert_rejected(
        verify_group_membership(&proof_t1, &root_t2),
        "proof for tree 1 against root of tree 2",
    );
}

#[test]
fn test_credential_correct_disclosure_verifies() {
    let credential = IpCredential {
        attributes: vec![vec![100u8], vec![200u8], vec![44u8]],
    };
    let reveal_mask = vec![true, false, false];
    let proof = prove_credential_attributes(&credential, &reveal_mask).unwrap();
    let commitment = compute_credential_commitment(&credential.attributes).unwrap();
    let disclosed_val_100 = vec![vec![100u8]];
    assert_accepted(
        verify_credential_proof(&proof, &commitment, &disclosed_val_100),
        "correct commitment and disclosed value",
    );
}

#[test]
fn test_credential_wrong_disclosed_value_fails() {
    let credential = IpCredential {
        attributes: vec![vec![100u8], vec![200u8]],
    };
    let reveal_mask = vec![true, false];
    let proof = prove_credential_attributes(&credential, &reveal_mask).unwrap();
    // The commitment is the *correct* one, so the only thing wrong here is the disclosed
    // value. Passing an empty commitment (as this test used to) made the verifier bail out
    // on input validation before it ever looked at the disclosed value.
    let commitment = compute_credential_commitment(&credential.attributes).unwrap();
    let wrong_val_101 = vec![vec![101u8]];
    assert_rejected(
        verify_credential_proof(&proof, &commitment, &wrong_val_101),
        "wrong disclosed value under the correct commitment",
    );
}

#[test]
fn test_credential_proof_bytes_hide_undisclosed_attributes() {
    let credential = IpCredential {
        attributes: vec![vec![42u8], vec![0xABu8], vec![0xCDu8]],
    };
    let reveal_mask = vec![true, false, false];
    let proof = prove_credential_attributes(&credential, &reveal_mask).unwrap();
    let bytes = &proof.data;
    // Proof must not contain the raw undisclosed attribute bytes as a 4-byte pattern
    // (single bytes can appear in lengths/counts). Use rare 4-byte pattern.
    let hidden_ab = [0xABu8; 4];
    let hidden_cd = [0xCDu8; 4];
    assert!(
        !bytes.windows(4).any(|w| w == hidden_ab),
        "undisclosed attribute 0xAB must not appear as 4-byte run in proof"
    );
    assert!(
        !bytes.windows(4).any(|w| w == hidden_cd),
        "undisclosed attribute 0xCD must not appear as 4-byte run in proof"
    );
}
