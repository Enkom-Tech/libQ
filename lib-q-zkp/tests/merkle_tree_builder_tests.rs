//! Tests for Poseidon Merkle tree builder and prove/verify round-trip.

#![cfg(feature = "zkp")]
#![allow(clippy::needless_range_loop)]

use lib_q_zkp::air::MerkleHash;
use lib_q_zkp::api::{
    build_merkle_tree,
    merkle_path_from_tree,
    prove_membership_with_config,
    verify_membership_with_config,
    verify_membership_with_depth_and_config,
};
use lib_q_zkp::merkle::PoseidonMerkleTree;
use lib_q_zkp::stark::{
    default_config,
    fast_proof_config,
};

/// Assert that a verifier *ran to a verdict* and rejected.
///
/// `assert!(!verify(..).unwrap_or(false))` also passes when the verifier returns `Err`, so it
/// cannot distinguish "correctly rejected" from "blew up before reaching a verdict".
#[track_caller]
fn assert_rejected<E: core::fmt::Debug>(result: Result<bool, E>, what: &str) {
    match result {
        Ok(false) => {}
        Ok(true) => panic!("{what}: verifier accepted an invalid proof"),
        Err(e) => panic!("{what}: verifier failed to reach a verdict: {e:?}"),
    }
}

#[test]
fn test_build_tree_roundtrip_prove_verify() {
    let cfg = fast_proof_config();
    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1", b"leaf2", b"leaf3"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let root_bytes = tree.root_bytes();

    for (i, leaf) in leaves.iter().enumerate() {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership_with_config(leaf, &path, cfg.clone()).unwrap();
        assert!(
            verify_membership_with_config(&proof, &root_bytes, cfg.clone()).unwrap(),
            "leaf {} must verify against tree root",
            i
        );
        assert!(
            verify_membership_with_depth_and_config(&proof, &root_bytes, tree.depth(), cfg.clone())
                .unwrap(),
            "leaf {} must verify with explicit depth",
            i
        );
    }
}

#[test]
fn test_root_consistency_verify_path() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let root = tree.root();

    for (i, leaf) in leaves.iter().enumerate() {
        let (path_bits, siblings) = tree.path(i).unwrap();
        assert!(
            PoseidonMerkleTree::verify_path(&root, leaf, &path_bits, &siblings),
            "verify_path must succeed for leaf {}",
            i
        );
    }
}

#[test]
fn test_path_correctness_depth_and_siblings() {
    let leaves: Vec<&[u8]> = vec![b"x", b"y", b"z", b"w"];
    let tree = build_merkle_tree(&leaves).unwrap();

    assert_eq!(tree.depth(), 2);
    assert_eq!(tree.num_leaves(), 4);

    for i in 0..4 {
        let (path_bits, siblings) = tree.path(i).unwrap();
        assert_eq!(path_bits.len(), tree.depth());
        assert_eq!(siblings.len(), tree.depth());
    }
}

#[test]
fn test_wrong_root_rejected() {
    let cfg = default_config();
    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let path = merkle_path_from_tree(&tree, 0).unwrap();
    let proof = prove_membership_with_config(leaves[0], &path, cfg.clone()).unwrap();

    let wrong_root = [0xFFu8; 32];
    assert_rejected(
        verify_membership_with_config(&proof, &wrong_root, cfg),
        "wrong root",
    );
}

#[test]
fn test_tampered_leaf_different_root() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    let tree1 = build_merkle_tree(&leaves).unwrap();
    let tampered: Vec<&[u8]> = vec![b"a", b"b", b"X"];
    let tree2 = build_merkle_tree(&tampered).unwrap();
    assert_ne!(tree1.root_bytes(), tree2.root_bytes());
}

#[test]
fn test_cross_tree_rejected() {
    let cfg = default_config();
    let leaves_a: Vec<&[u8]> = vec![b"a0", b"a1"];
    let leaves_b: Vec<&[u8]> = vec![b"b0", b"b1"];
    let tree_a = build_merkle_tree(&leaves_a).unwrap();
    let tree_b = build_merkle_tree(&leaves_b).unwrap();

    let path_a = merkle_path_from_tree(&tree_a, 0).unwrap();
    let proof_a = prove_membership_with_config(leaves_a[0], &path_a, cfg.clone()).unwrap();

    assert_rejected(
        verify_membership_with_config(&proof_a, &tree_b.root_bytes(), cfg),
        "proof from tree A against tree B root",
    );
}

#[test]
fn test_single_leaf_depth_one() {
    let cfg = fast_proof_config();
    let leaves: Vec<&[u8]> = vec![b"only"];
    let tree = build_merkle_tree(&leaves).unwrap();
    assert_eq!(tree.depth(), 1);
    assert_eq!(tree.num_leaves(), 1);
    let (path_bits, siblings) = tree.path(0).unwrap();
    assert_eq!(path_bits.len(), 1);
    assert_eq!(siblings.len(), 1);

    let path = merkle_path_from_tree(&tree, 0).unwrap();
    let proof = prove_membership_with_config(leaves[0], &path, cfg.clone()).unwrap();
    assert!(verify_membership_with_config(&proof, &tree.root_bytes(), cfg).unwrap());
}

#[test]
fn test_two_leaves() {
    let cfg = fast_proof_config();
    let leaves: Vec<&[u8]> = vec![b"left", b"right"];
    let tree = build_merkle_tree(&leaves).unwrap();
    assert_eq!(tree.depth(), 1);
    assert_eq!(tree.num_leaves(), 2);
    for i in 0..2 {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership_with_config(leaves[i], &path, cfg.clone()).unwrap();
        assert!(verify_membership_with_config(&proof, &tree.root_bytes(), cfg.clone()).unwrap());
    }
}

#[test]
fn test_three_leaves_padded_to_four() {
    let cfg = fast_proof_config();
    let leaves: Vec<&[u8]> = vec![b"1", b"2", b"3"];
    let tree = build_merkle_tree(&leaves).unwrap();
    assert_eq!(tree.depth(), 2);
    assert_eq!(tree.num_leaves(), 3);

    for i in 0..3 {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership_with_config(leaves[i], &path, cfg.clone()).unwrap();
        assert!(verify_membership_with_config(&proof, &tree.root_bytes(), cfg.clone()).unwrap());
    }
}

#[test]
fn test_five_leaves_padded_to_eight() {
    let cfg = fast_proof_config();
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
    let tree = build_merkle_tree(&leaves).unwrap();
    assert_eq!(tree.depth(), 3);
    assert_eq!(tree.num_leaves(), 5);

    for i in 0..5 {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership_with_config(leaves[i], &path, cfg.clone()).unwrap();
        assert!(verify_membership_with_config(&proof, &tree.root_bytes(), cfg.clone()).unwrap());
    }
}

#[test]
fn test_path_out_of_bounds_rejected() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    let tree = build_merkle_tree(&leaves).unwrap();
    assert!(tree.path(3).is_err());
    assert!(tree.path(10).is_err());
    assert!(merkle_path_from_tree(&tree, 3).is_err());
}

#[test]
fn test_empty_leaves_rejected() {
    let leaves: Vec<&[u8]> = vec![];
    let result = build_merkle_tree(&leaves);
    assert!(result.is_err());
}

#[test]
fn test_verify_path_wrong_root_fails() {
    let leaves: Vec<&[u8]> = vec![b"x", b"y"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let (path_bits, siblings) = tree.path(0).unwrap();
    let wrong_root = MerkleHash::hash_data(b"wrong");
    assert!(!PoseidonMerkleTree::verify_path(
        &wrong_root,
        leaves[0],
        &path_bits,
        &siblings
    ));
}

#[test]
fn test_root_bytes_length() {
    let leaves: Vec<&[u8]> = vec![b"x"];
    let tree = build_merkle_tree(&leaves).unwrap();
    assert_eq!(tree.root_bytes().len(), 32);
}
