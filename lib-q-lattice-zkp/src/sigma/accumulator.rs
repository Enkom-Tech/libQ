//! SIS/Ajtai Merkle **accumulator** — the algebraic replacement for the SHAKE-Merkle tree, so that a
//! path can later be proven in zero knowledge (PVTN V2, audit #65 / ADR 095).
//!
//! See the design doc [`docs/pvtn-v2-unlinkable-membership.md`](../../docs/pvtn-v2-unlinkable-membership.md)
//! §5. This module implements **only the public, deterministic relation**: the SIS hash node/leaf
//! compression, the base-2 gadget `G`/`G^{-1}`, tree construction, and a *cleartext* membership check
//! (the analogue of [`super::hierarchical::verify_merkle_path`]). It is collision-resistant under
//! Module-SIS, sound at the functional level, and KAT-pinnable on its own.
//!
//! **It is NOT the zero-knowledge layer.** The ZK Stern membership argument that hides the leaf,
//! siblings, and position (design §6) is *not* implemented here — it is the cryptographer's
//! review-gated core. Nothing in this module makes a presentation unlinkable by itself.
//!
//! > **DRAFT — RED / param-pending.** `ACC_K_ACC` and the seed/domain layout below are a *functional*
//! > parameterisation chosen so the relation type-checks and round-trips in tests. The Module-SIS
//! > security parameters (`k_acc`, node bit-length, depth) MUST be pinned by a cryptographer for
//! > ≥128-bit collision resistance before any vectors or wire format are frozen (design §13).

extern crate alloc;

use alloc::vec::Vec;

use lib_q_ring::{
    ModuleMatrix,
    ModuleVec,
    Poly,
};
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::error::VerifyError;

/// Field modulus of `R_q = Z_q[X]/(X^256+1)` (mirrors `lib_q_ring` / `profile.rs::modulus`).
const Q: i64 = 8_380_417;
/// `ceil(log2 q) = 23` — gadget base-2 width (mirrors `profile::RQ_COEFF_PACK_BITS`).
const BITS: usize = 23;
/// Ring degree.
const N: usize = 256;

/// **DRAFT parameter** — SIS output rank `k_acc`. A node is a bit-vector of `k_acc * BITS` polynomials
/// (`k_acc * BITS * 256` bits). Security-pending (design §13); small here for fast functional tests.
pub const ACC_K_ACC: usize = 2;

/// Number of `Poly` slots in a node bit-vector / leaf preimage (`= k_acc * BITS`).
pub const ACC_NODE_LEN: usize = ACC_K_ACC * BITS;

const SEED_DOMAIN_A0: &[u8] = b"lattice-zkp/pvtn-acc/A0/v2";
const SEED_DOMAIN_A1: &[u8] = b"lattice-zkp/pvtn-acc/A1/v2";
const SEED_DOMAIN_ALEAF: &[u8] = b"lattice-zkp/pvtn-acc/Aleaf/v2";

/// A tree node (or leaf preimage): a length-`ACC_NODE_LEN` bit-vector. Every coefficient of every
/// `Poly` is `0` or `1`. The public root is an [`AccNode`]; interior nodes are part of the (future)
/// ZK witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccNode(pub ModuleVec);

/// Public accumulator parameters: the two compression matrices and the leaf matrix, expanded from a
/// base seed. `A0, A1, A_leaf : R_q^{k_acc × (k_acc·BITS)}` map a length-`ACC_NODE_LEN` bit-vector to
/// `k_acc` ring elements (design §5).
pub struct AccParams {
    a0: ModuleMatrix,
    a1: ModuleMatrix,
    a_leaf: ModuleMatrix,
}

fn derive_seed(base: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(domain);
    h.update(base);
    let mut out = [0u8; 32];
    let mut reader = h.finalize_xof();
    XofReader::read(&mut reader, &mut out);
    out
}

impl AccParams {
    /// Expand the accumulator matrices from a single 32-byte base seed (domain-separated per matrix).
    #[must_use]
    pub fn from_base_seed(base: &[u8; 32]) -> Self {
        let rows = ACC_K_ACC;
        let cols = ACC_NODE_LEN;
        Self {
            a0: ModuleMatrix::expand_from_seed(&derive_seed(base, SEED_DOMAIN_A0), rows, cols),
            a1: ModuleMatrix::expand_from_seed(&derive_seed(base, SEED_DOMAIN_A1), rows, cols),
            a_leaf: ModuleMatrix::expand_from_seed(&derive_seed(base, SEED_DOMAIN_ALEAF), rows, cols),
        }
    }
}

/// Gadget `G^{-1}`: decompose `v ∈ R_q^{k_acc}` (coeffs reduced to `[0, q)`) into its base-2 bits — a
/// length-`ACC_NODE_LEN` bit-vector. Slot `j*BITS + b` holds bit `b` of the `j`-th ring element's
/// coefficients. Inverse of [`recompose`].
#[must_use]
pub fn decompose(v: &ModuleVec) -> AccNode {
    let mut out: Vec<Poly> = Vec::with_capacity(v.0.len() * BITS);
    for vp in &v.0 {
        let mut norm = vp.clone();
        norm.normalize_mod_q_assign(); // coeffs now in [0, q), non-negative
        for b in 0..BITS {
            let mut bit_poly = Poly::zero();
            for c in 0..N {
                bit_poly.coeffs[c] = (norm.coeffs[c] >> b) & 1;
            }
            out.push(bit_poly);
        }
    }
    AccNode(ModuleVec(out))
}

/// Gadget `G`: recompose a length-`ACC_NODE_LEN` bit-vector back to `v ∈ R_q^{k_acc}`. Inverse of
/// [`decompose`] on well-formed (binary) inputs. `G · G^{-1}(v) = v` for `v` in `[0, q)`.
#[must_use]
pub fn recompose(node: &AccNode) -> ModuleVec {
    let k = node.0.0.len() / BITS;
    let mut out: Vec<Poly> = Vec::with_capacity(k);
    for j in 0..k {
        let mut vp = Poly::zero();
        for c in 0..N {
            let mut acc: i64 = 0;
            for b in 0..BITS {
                acc += (node.0.0[j * BITS + b].coeffs[c] as i64) << b;
            }
            vp.coeffs[c] = acc.rem_euclid(Q) as i32;
        }
        out.push(vp);
    }
    ModuleVec(out)
}

fn matrix_apply_sum(a0: &ModuleMatrix, left: &AccNode, a1: &ModuleMatrix, right: &AccNode) -> ModuleVec {
    let mut v = a0.mul_vec(&left.0);
    let vr = a1.mul_vec(&right.0);
    for (vp, rp) in v.0.iter_mut().zip(vr.0.iter()) {
        vp.add_assign(rp);
        vp.normalize_mod_q_assign();
    }
    v
}

/// Internal node compression `parent = G^{-1}(A0·left + A1·right mod q)` (design §5).
#[must_use]
pub fn acc_compress(params: &AccParams, left: &AccNode, right: &AccNode) -> AccNode {
    decompose(&matrix_apply_sum(&params.a0, left, &params.a1, right))
}

/// Leaf compression `u_leaf = G^{-1}(A_leaf · x_attr mod q)` where `x_attr` is the length-`ACC_NODE_LEN`
/// attribute bit-vector (design §5).
#[must_use]
pub fn acc_leaf(params: &AccParams, x_attr: &AccNode) -> AccNode {
    decompose(&params.a_leaf.mul_vec(&x_attr.0))
}

/// Encode PVTN attributes into a length-`ACC_NODE_LEN` bit-vector preimage: `clearance` (32 bits),
/// `role_tag` (128 bits), `parent_digest` (256 bits), LSB-first, zero-padded. The clearance bits are
/// the same bits the V2 range proof (design §7) ranges over.
#[must_use]
pub fn encode_attr_bits(clearance: u32, role_tag: &[u8; 16], parent_digest: &[u8; 32]) -> AccNode {
    let mut bits: Vec<u8> = Vec::with_capacity(32 + 128 + 256);
    for b in 0..32 {
        bits.push(((clearance >> b) & 1) as u8);
    }
    for byte in role_tag {
        for b in 0..8 {
            bits.push((byte >> b) & 1);
        }
    }
    for byte in parent_digest {
        for b in 0..8 {
            bits.push((byte >> b) & 1);
        }
    }
    // Pack the bit string into ACC_NODE_LEN polynomials, one bit per coefficient, zero-padded.
    let mut out: Vec<Poly> = Vec::with_capacity(ACC_NODE_LEN);
    for slot in 0..ACC_NODE_LEN {
        let mut p = Poly::zero();
        for c in 0..N {
            let idx = slot * N + c;
            if idx < bits.len() {
                p.coeffs[c] = bits[idx] as i32;
            }
        }
        out.push(p);
    }
    AccNode(ModuleVec(out))
}

/// Direction at level `level`: `true` if the running node is the left child (mirrors
/// [`super::hierarchical::merkle_direction_at`]).
#[must_use]
pub fn acc_direction_at(path_index: u32, level: usize) -> bool {
    ((path_index >> level) & 1) == 0
}

/// Recompute the root from a leaf node and its sibling path (cleartext membership — the public
/// relation the ZK argument of design §6 will prove in zero knowledge).
#[must_use]
pub fn acc_root_from_path(
    params: &AccParams,
    leaf: &AccNode,
    path_index: u32,
    siblings: &[AccNode],
) -> AccNode {
    let mut cur = leaf.clone();
    for (level, sib) in siblings.iter().enumerate() {
        cur = if acc_direction_at(path_index, level) {
            acc_compress(params, &cur, sib)
        } else {
            acc_compress(params, sib, &cur)
        };
    }
    cur
}

/// Cleartext membership check: the leaf's path recomputes to `root`.
pub fn acc_verify_membership(
    params: &AccParams,
    root: &AccNode,
    leaf: &AccNode,
    path_index: u32,
    siblings: &[AccNode],
) -> Result<(), VerifyError> {
    if siblings.len() > 31 {
        return Err(VerifyError::InvalidFormat);
    }
    if path_index >= 1u32 << siblings.len() {
        return Err(VerifyError::Rejected);
    }
    if &acc_root_from_path(params, leaf, path_index, siblings) == root {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
    }
}

/// Build a full binary tree from `2^depth` leaves; returns the root and every level (level 0 = leaves).
/// Helper for tests / KAT generation. `leaves.len()` must be a power of two.
#[must_use]
pub fn acc_build_tree(params: &AccParams, leaves: &[AccNode]) -> (AccNode, Vec<Vec<AccNode>>) {
    assert!(leaves.len().is_power_of_two() && !leaves.is_empty());
    let mut levels: Vec<Vec<AccNode>> = Vec::new();
    levels.push(leaves.to_vec());
    let mut cur = leaves.to_vec();
    while cur.len() > 1 {
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks(2) {
            next.push(acc_compress(params, &pair[0], &pair[1]));
        }
        levels.push(next.clone());
        cur = next;
    }
    (cur[0].clone(), levels)
}

/// Sibling path + index for `leaf_index` in a tree produced by [`acc_build_tree`].
#[must_use]
pub fn acc_membership_witness(levels: &[Vec<AccNode>], leaf_index: usize) -> (u32, Vec<AccNode>) {
    let mut siblings = Vec::with_capacity(levels.len() - 1);
    let mut idx = leaf_index;
    for level in &levels[..levels.len() - 1] {
        let sib = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        siblings.push(level[sib].clone());
        idx /= 2;
    }
    (leaf_index as u32, siblings)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn base_seed(tag: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = tag;
        s
    }

    #[test]
    fn gadget_decompose_recompose_roundtrips() {
        // Build an arbitrary v in [0, q) and check G·G^{-1}(v) = v.
        let mut polys = Vec::new();
        for j in 0..ACC_K_ACC {
            let mut p = Poly::zero();
            for c in 0..N {
                p.coeffs[c] = (((c as i64 * 7919 + j as i64 * 104_729) % Q) as i32).rem_euclid(Q as i32);
            }
            polys.push(p);
        }
        let v = ModuleVec(polys);
        let bits = decompose(&v);
        // every coefficient is a bit
        for p in &bits.0.0 {
            for &c in &p.coeffs {
                assert!(c == 0 || c == 1, "decompose must yield bits");
            }
        }
        let v2 = recompose(&bits);
        for (a, b) in v.0.iter().zip(v2.0.iter()) {
            for c in 0..N {
                assert_eq!(a.coeffs[c].rem_euclid(Q as i32), b.coeffs[c], "roundtrip coeff");
            }
        }
    }

    #[test]
    fn compression_is_deterministic_and_node_shaped() {
        let params = AccParams::from_base_seed(&base_seed(1));
        let l = encode_attr_bits(7, &[0xAA; 16], &[0x11; 32]);
        let r = encode_attr_bits(9, &[0xBB; 16], &[0x22; 32]);
        let n1 = acc_compress(&params, &l, &r);
        let n2 = acc_compress(&params, &l, &r);
        assert_eq!(n1, n2, "compression deterministic");
        assert_eq!(n1.0.0.len(), ACC_NODE_LEN, "node has ACC_NODE_LEN slots");
        for p in &n1.0.0 {
            for &c in &p.coeffs {
                assert!(c == 0 || c == 1, "node is a bit-vector");
            }
        }
        // swapping children changes the node (A0 ≠ A1)
        assert_ne!(acc_compress(&params, &r, &l), n1, "left/right not symmetric");
    }

    #[test]
    fn membership_roundtrip_and_tamper_rejects() {
        let params = AccParams::from_base_seed(&base_seed(2));
        // 4 leaves (depth 2)
        let leaves = alloc::vec![
            acc_leaf(&params, &encode_attr_bits(5, &[1; 16], &[0; 32])),
            acc_leaf(&params, &encode_attr_bits(6, &[2; 16], &[0; 32])),
            acc_leaf(&params, &encode_attr_bits(7, &[3; 16], &[0; 32])),
            acc_leaf(&params, &encode_attr_bits(8, &[4; 16], &[0; 32])),
        ];
        let (root, levels) = acc_build_tree(&params, &leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let (idx, sibs) = acc_membership_witness(&levels, i);
            acc_verify_membership(&params, &root, leaf, idx, &sibs).expect("member verifies");
        }
        // tamper: wrong leaf at a valid path must be rejected
        let (idx0, sibs0) = acc_membership_witness(&levels, 0);
        let wrong = acc_leaf(&params, &encode_attr_bits(99, &[9; 16], &[9; 32]));
        assert!(
            acc_verify_membership(&params, &root, &wrong, idx0, &sibs0).is_err(),
            "non-member must be rejected"
        );
    }
}
