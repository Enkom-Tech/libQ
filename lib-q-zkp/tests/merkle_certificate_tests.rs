//! Merkle tree certificate tests: create, use, and security validation.
//!
//! Validates that Merkle tree certificates can be created (prove_membership)
//! and used (verify_membership / verify_membership_with_depth), and that
//! secure verification rejects wrong root, wrong depth, and cross-tree misuse.

#![cfg(feature = "zkp")]

use lib_q_zkp::api::{
    build_merkle_tree,
    merkle_path_from_tree,
    prove_membership,
    verify_membership,
    verify_membership_with_depth,
};

/// Create and use (happy path): build tree, issue certificate, verify with correct root and depth.
#[test]
fn test_merkle_certificate_create_and_verify() {
    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1", b"leaf2"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let root = tree.root_bytes();

    for (i, leaf) in leaves.iter().enumerate() {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership(leaf, &path).unwrap();

        assert!(
            verify_membership(&proof, &root).unwrap(),
            "certificate must verify with correct root for leaf {}",
            i
        );
        assert!(
            verify_membership_with_depth(&proof, &root, tree.depth()).unwrap(),
            "certificate must verify with correct root and depth for leaf {}",
            i
        );
    }
}

/// Security: verification with wrong root must reject (prevents binding to wrong tree).
#[test]
fn test_merkle_certificate_wrong_root_rejected() {
    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let path = merkle_path_from_tree(&tree, 0).unwrap();
    let proof = prove_membership(leaves[0], &path).unwrap();

    let wrong_root = [0xFFu8; 32];
    let result = verify_membership(&proof, &wrong_root);
    assert!(
        !result.unwrap_or(false),
        "certificate must not verify against wrong root"
    );
}

/// Security: verify_membership_with_depth with wrong depth must reject (depth confusion).
#[test]
fn test_merkle_certificate_wrong_depth_rejected() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let root = tree.root_bytes();
    let path = merkle_path_from_tree(&tree, 0).unwrap();
    let proof = prove_membership(leaves[0], &path).unwrap();

    let wrong_depth = tree.depth() + 1;
    let result = verify_membership_with_depth(&proof, &root, wrong_depth);
    assert!(
        !result.unwrap_or(false),
        "certificate must not verify with wrong tree depth"
    );
}

/// Security: proof issued for tree A must not verify against root of tree B (cross-tree).
#[test]
fn test_merkle_certificate_cross_tree_rejected() {
    let leaves_a: Vec<&[u8]> = vec![b"tree_a_0", b"tree_a_1"];
    let leaves_b: Vec<&[u8]> = vec![b"tree_b_0", b"tree_b_1"];
    let tree_a = build_merkle_tree(&leaves_a).unwrap();
    let tree_b = build_merkle_tree(&leaves_b).unwrap();
    let root_b = tree_b.root_bytes();

    let path_a = merkle_path_from_tree(&tree_a, 0).unwrap();
    let proof_a = prove_membership(leaves_a[0], &path_a).unwrap();

    let result = verify_membership(&proof_a, &root_b);
    assert!(
        !result.unwrap_or(false),
        "certificate for tree A must not verify against root of tree B"
    );
}

/// Multiple leaves: issue a certificate per leaf and verify each against the same root.
#[test]
fn test_merkle_certificate_multiple_leaves_same_root() {
    let leaves: Vec<&[u8]> = vec![b"l0", b"l1", b"l2", b"l3"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let root = tree.root_bytes();
    let depth = tree.depth();

    for (i, leaf) in leaves.iter().enumerate() {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership(leaf, &path).unwrap();
        assert!(
            verify_membership(&proof, &root).unwrap(),
            "leaf {} certificate must verify",
            i
        );
        assert!(
            verify_membership_with_depth(&proof, &root, depth).unwrap(),
            "leaf {} certificate must verify with explicit depth",
            i
        );
    }
}
