//! Merkle-tree membership over SHAKE256 leaf digests, for hierarchical authorization sketches.
//!
//! [`HierarchicalAuthProof`] composes [`verify_merkle_path`] with an Ajtai opening check.
//! This is **not** a full PVTN zero-knowledge protocol: the leaf payload is revealed.
//!
//! [`PrivateMembershipProof`] is the wire v0 PVTN variant: the raw leaf payload is not on the
//! wire; the opening transcript binds [`PrivateMembershipProof::leaf_digest`] and structured
//! public fields. Merkle path index and clearance level are recovered by verifier-side search;
//! see `path_index_commitment`, `recover_path_index`, and `recover_clearance_level`.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_ring::Poly;
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
use crate::sigma::norm::{
    CrtPackedNormProof,
    prove_inf_norm,
    verify_inf_norm,
    verify_inf_norm_proof,
};
use crate::sigma::opening::{
    OpeningProof,
    prove_opening,
    verify_opening,
};
use crate::util::module_norm_within_bound;

/// Pilot infinity-norm budget for packing `clearance_level - min_clearance` in coefficient 0.
pub const PVTN_CLEARANCE_MARGIN_NORM_BETA: i32 = 1_048_575;

/// Leaf digest `SHAKE256(0x00 ‖ payload)`.
pub fn leaf_hash(payload: &[u8]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(&[0x00]);
    h.update(payload);
    let mut out = [0u8; 32];
    let mut reader = h.finalize_xof();
    XofReader::read(&mut reader, &mut out);
    out
}

/// Internal node `SHAKE256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    let mut reader = h.finalize_xof();
    XofReader::read(&mut reader, &mut out);
    out
}

/// Domain tag for PVTN path-index commitments on the wire.
pub const PVTN_PATH_INDEX_COMMIT_DOMAIN: &[u8] = b"lattice-zkp/pvtn-path-index/v0";

/// Membership path: leaf index and sibling digests from leaf to root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerklePath {
    /// Leaf index in the tree (bit `l` of index selects left/right at level `l`).
    pub path_index: u32,
    pub siblings: Vec<[u8; 32]>,
}

/// Direction at Merkle level `level`: `true` if the running node is the left child.
#[must_use]
pub fn merkle_direction_at(path_index: u32, level: usize) -> bool {
    ((path_index >> level) & 1) == 0
}

/// Walk from `leaf` to `root` using `path_index` and `siblings`.
pub fn verify_merkle_path_from_index(
    leaf: &[u8; 32],
    root: &[u8; 32],
    path_index: u32,
    siblings: &[[u8; 32]],
) -> Result<(), VerifyError> {
    let depth = siblings.len();
    if depth > 31 {
        return Err(VerifyError::InvalidFormat);
    }
    if path_index >= 1u32 << depth {
        return Err(VerifyError::Rejected);
    }
    let mut cur = *leaf;
    for (level, sib) in siblings.iter().enumerate() {
        let go_left = merkle_direction_at(path_index, level);
        cur = if go_left {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
    }
    if &cur == root {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
    }
}

/// Walk from `leaf` to `root` using [`MerklePath`].
pub fn verify_merkle_path(
    leaf: &[u8; 32],
    root: &[u8; 32],
    path: &MerklePath,
) -> Result<(), VerifyError> {
    verify_merkle_path_from_index(leaf, root, path.path_index, &path.siblings)
}

/// Commitment to `(path_index, root, leaf, siblings)` carried on the PVTN wire.
#[must_use]
pub fn path_index_commitment(
    path_index: u32,
    root: &[u8; 32],
    leaf_digest: &[u8; 32],
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(PVTN_PATH_INDEX_COMMIT_DOMAIN);
    h.update(&path_index.to_le_bytes());
    h.update(root);
    h.update(leaf_digest);
    for s in siblings {
        h.update(s);
    }
    let mut out = [0u8; 32];
    let mut reader = h.finalize_xof();
    XofReader::read(&mut reader, &mut out);
    out
}

/// Recover `path_index` from a wire commitment by search (depth cap ≤ 16).
pub fn recover_path_index(
    root: &[u8; 32],
    leaf_digest: &[u8; 32],
    siblings: &[[u8; 32]],
    commitment: &[u8; 32],
) -> Result<u32, VerifyError> {
    let depth = siblings.len();
    if depth > 16 {
        return Err(VerifyError::InvalidFormat);
    }
    let max = 1u32 << depth;
    for index in 0..max {
        if path_index_commitment(index, root, leaf_digest, siblings) != *commitment {
            continue;
        }
        if verify_merkle_path_from_index(leaf_digest, root, index, siblings).is_ok() {
            return Ok(index);
        }
    }
    Err(VerifyError::Rejected)
}

/// Recover clearance level by search over `[min_clearance, min_clearance + β]`.
pub fn recover_clearance_level(
    min_clearance: u32,
    leaf_digest: &[u8; 32],
    role_tag: &[u8; 16],
    parent_digest: &[u8; 32],
) -> Result<u32, VerifyError> {
    let max = min_clearance.saturating_add(PVTN_CLEARANCE_MARGIN_NORM_BETA as u32);
    for level in min_clearance..=max {
        let payload = encode_pvtn_leaf(level, role_tag, parent_digest);
        if leaf_hash(&payload) == *leaf_digest {
            return Ok(level);
        }
    }
    Err(VerifyError::Rejected)
}

/// PVTN-style leaf: declared clearance level, opaque role tag, parent digest.
#[must_use]
pub fn encode_pvtn_leaf(
    clearance_level: u32,
    role_tag: &[u8; 16],
    parent_digest: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 16 + 32);
    v.extend_from_slice(&clearance_level.to_le_bytes());
    v.extend_from_slice(role_tag);
    v.extend_from_slice(parent_digest);
    v
}

/// Decode clearance level from [`encode_pvtn_leaf`] payload.
pub fn leaf_clearance_level(leaf_payload: &[u8]) -> Option<u32> {
    if leaf_payload.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes(leaf_payload[0..4].try_into().ok()?))
}

/// Fiat–Shamir context that binds an opening transcript to a tree leaf.
#[must_use]
pub fn hierarchical_opening_ctx(base_ctx: &[u8], leaf_payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(base_ctx.len() + 1 + leaf_payload.len());
    v.extend_from_slice(base_ctx);
    v.push(0);
    v.extend_from_slice(leaf_payload);
    v
}

/// Merkle path + revealed leaf + credential opening proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchicalAuthProof {
    pub merkle_path: MerklePath,
    pub leaf_payload: Vec<u8>,
    pub credential_com: AjtaiCommitment,
    pub opening_proof: OpeningProof,
}

/// Produce a hierarchical membership proof by proving:
/// 1) The provided leaf is in `tree_root`, and
/// 2) `credential_opening` opens `credential_com` under context bound to that leaf.
#[allow(clippy::too_many_arguments)]
pub fn prove_level_membership<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    credential_opening: &AjtaiOpening,
    credential_com: &AjtaiCommitment,
    leaf_payload: Vec<u8>,
    merkle_path: MerklePath,
    tree_root: &[u8; 32],
    min_clearance: u32,
    opening_base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<HierarchicalAuthProof, ProofError> {
    let level = leaf_clearance_level(&leaf_payload).ok_or(ProofError::InvalidParameters)?;
    if level < min_clearance {
        return Err(ProofError::InvalidParameters);
    }
    let lh = leaf_hash(&leaf_payload);
    if verify_merkle_path(&lh, tree_root, &merkle_path).is_err() {
        return Err(ProofError::InvalidParameters);
    }
    let ctx = hierarchical_opening_ctx(opening_base_ctx, &leaf_payload);
    let opening_proof = prove_opening(
        rng,
        key,
        credential_opening,
        credential_com,
        &ctx,
        tau,
        z_inf_bound,
        max_attempts,
    )?;
    Ok(HierarchicalAuthProof {
        merkle_path,
        leaf_payload,
        credential_com: credential_com.clone(),
        opening_proof,
    })
}

/// Verify tree membership at `min_clearance` and opening proof for `credential_com`.
#[allow(clippy::too_many_arguments)]
pub fn verify_hierarchical_membership(
    key: &AjtaiCommitmentKey,
    proof: &HierarchicalAuthProof,
    tree_root: &[u8; 32],
    min_clearance: u32,
    opening_base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let level = leaf_clearance_level(&proof.leaf_payload).ok_or(VerifyError::InvalidFormat)?;
    if level < min_clearance {
        return Err(VerifyError::Rejected);
    }
    let lh = leaf_hash(&proof.leaf_payload);
    verify_merkle_path(&lh, tree_root, &proof.merkle_path)?;
    let ctx = hierarchical_opening_ctx(opening_base_ctx, &proof.leaf_payload);
    verify_opening(
        key,
        &proof.credential_com,
        &proof.opening_proof,
        &ctx,
        tau,
        z_inf_bound,
    )
}

/// Alias for [`verify_private_membership`] (wire v0 PVTN API naming).
#[allow(clippy::too_many_arguments)]
pub fn verify_level_membership(
    key: &AjtaiCommitmentKey,
    proof: &HierarchicalAuthProof,
    tree_root: &[u8; 32],
    min_clearance: u32,
    opening_base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    verify_hierarchical_membership(
        key,
        proof,
        tree_root,
        min_clearance,
        opening_base_ctx,
        tau,
        z_inf_bound,
    )
}

/// Fiat–Shamir context for [`PrivateMembershipProof`]: binds the tree root, leaf digest, and
/// clearance predicate inputs without absorbing the full PVTN leaf byte string.
#[must_use]
pub fn private_membership_opening_ctx(
    base_ctx: &[u8],
    leaf_digest: &[u8; 32],
    tree_root: &[u8; 32],
    min_clearance: u32,
    clearance_level: u32,
    role_tag: &[u8; 16],
    parent_digest: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(base_ctx.len() + 1 + 32 + 1 + 32 + 4 + 4 + 16 + 32 + 8);
    v.extend_from_slice(base_ctx);
    v.push(0);
    v.extend_from_slice(b"lattice-zkp/private-membership/v1");
    v.push(0);
    v.extend_from_slice(leaf_digest);
    v.push(0);
    v.extend_from_slice(tree_root);
    v.extend_from_slice(&min_clearance.to_le_bytes());
    v.extend_from_slice(&clearance_level.to_le_bytes());
    v.push(0);
    v.extend_from_slice(role_tag);
    v.push(0);
    v.extend_from_slice(parent_digest);
    v
}

/// Membership proof that omits the raw [`encode_pvtn_leaf`] byte string from the bundle while
/// still letting the verifier recompute `leaf_hash` from structured public inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateMembershipProof {
    pub merkle_path: MerklePath,
    pub leaf_digest: [u8; 32],
    pub clearance_level: u32,
    pub role_tag: [u8; 16],
    pub parent_digest: [u8; 32],
    pub credential_com: AjtaiCommitment,
    pub opening_proof: OpeningProof,
    /// [`prove_inf_norm`] certificate for the packed clearance margin witness.
    pub clearance_margin_norm: CrtPackedNormProof,
    /// Single-polynomial witness whose coefficient 0 encodes `clearance_level - min_clearance`.
    pub clearance_margin_witness_polys: Vec<Poly>,
}

fn clearance_margin_witness(delta: u32) -> Result<Vec<Poly>, ProofError> {
    if delta > PVTN_CLEARANCE_MARGIN_NORM_BETA as u32 {
        return Err(ProofError::InvalidParameters);
    }
    let mut p = Poly::zero();
    p.coeffs[0] = delta as i32;
    Ok(alloc::vec![p])
}

fn prove_clearance_margin_norm(delta: u32) -> Result<(CrtPackedNormProof, Vec<Poly>), ProofError> {
    let polys = clearance_margin_witness(delta)?;
    let proof = prove_inf_norm(
        core::slice::from_ref(&polys),
        PVTN_CLEARANCE_MARGIN_NORM_BETA,
    );
    Ok((proof, polys))
}

fn verify_clearance_margin_public(
    min_clearance: u32,
    clearance_level: u32,
    norm_proof: &CrtPackedNormProof,
    witness_polys: &[Poly],
) -> Result<(), VerifyError> {
    if !verify_inf_norm_proof(norm_proof, PVTN_CLEARANCE_MARGIN_NORM_BETA) {
        return Err(VerifyError::Rejected);
    }
    if witness_polys.len() != 1 {
        return Err(VerifyError::InvalidFormat);
    }
    if !verify_inf_norm(witness_polys, PVTN_CLEARANCE_MARGIN_NORM_BETA) {
        return Err(VerifyError::Rejected);
    }
    let w0 = &witness_polys[0];
    if !bool::from(module_norm_within_bound(
        core::slice::from_ref(w0),
        PVTN_CLEARANCE_MARGIN_NORM_BETA,
    )) {
        return Err(VerifyError::Rejected);
    }
    for c in w0.coeffs.iter().skip(1) {
        if *c != 0 {
            return Err(VerifyError::Rejected);
        }
    }
    let margin = w0.coeffs[0];
    if margin < 0 {
        return Err(VerifyError::Rejected);
    }
    let margin_u = margin as u32;
    let recomputed = min_clearance
        .checked_add(margin_u)
        .ok_or(VerifyError::InvalidFormat)?;
    if recomputed != clearance_level {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}

/// Produce a PVTN private membership proof (wire v0): leaf bytes stay prover-local; verifier checks
/// Merkle membership on [`PrivateMembershipProof::leaf_digest`] and a packed clearance-margin norm
/// certificate composable with [`crate::sigma::norm`](super::norm).
#[allow(clippy::too_many_arguments)]
pub fn prove_private_membership<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    credential_opening: &AjtaiOpening,
    credential_com: &AjtaiCommitment,
    leaf_payload: Vec<u8>,
    merkle_path: MerklePath,
    tree_root: &[u8; 32],
    min_clearance: u32,
    opening_base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<PrivateMembershipProof, ProofError> {
    let level = leaf_clearance_level(&leaf_payload).ok_or(ProofError::InvalidParameters)?;
    if level < min_clearance {
        return Err(ProofError::InvalidParameters);
    }
    let delta = level - min_clearance;
    let (clearance_margin_norm, clearance_margin_witness_polys) =
        prove_clearance_margin_norm(delta)?;
    if leaf_payload.len() < 4 + 16 + 32 {
        return Err(ProofError::InvalidParameters);
    }
    let mut role_tag = [0u8; 16];
    role_tag.copy_from_slice(&leaf_payload[4..20]);
    let mut parent_digest = [0u8; 32];
    parent_digest.copy_from_slice(&leaf_payload[20..52]);

    let lh = leaf_hash(&leaf_payload);
    if verify_merkle_path(&lh, tree_root, &merkle_path).is_err() {
        return Err(ProofError::InvalidParameters);
    }

    let ctx = private_membership_opening_ctx(
        opening_base_ctx,
        &lh,
        tree_root,
        min_clearance,
        level,
        &role_tag,
        &parent_digest,
    );
    let opening_proof = prove_opening(
        rng,
        key,
        credential_opening,
        credential_com,
        &ctx,
        tau,
        z_inf_bound,
        max_attempts,
    )?;
    Ok(PrivateMembershipProof {
        merkle_path,
        leaf_digest: lh,
        clearance_level: level,
        role_tag,
        parent_digest,
        credential_com: credential_com.clone(),
        opening_proof,
        clearance_margin_norm,
        clearance_margin_witness_polys,
    })
}

/// Verify [`PrivateMembershipProof`]: structured leaf fields must match [`PrivateMembershipProof::leaf_digest`],
/// Merkle inclusion, clearance predicate, and the credential opening.
#[allow(clippy::too_many_arguments)]
pub fn verify_private_membership(
    key: &AjtaiCommitmentKey,
    proof: &PrivateMembershipProof,
    tree_root: &[u8; 32],
    min_clearance: u32,
    opening_base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let clearance_level = recover_clearance_level(
        min_clearance,
        &proof.leaf_digest,
        &proof.role_tag,
        &proof.parent_digest,
    )?;
    if clearance_level != proof.clearance_level {
        return Err(VerifyError::Rejected);
    }
    if clearance_level < min_clearance {
        return Err(VerifyError::Rejected);
    }
    verify_clearance_margin_public(
        min_clearance,
        proof.clearance_level,
        &proof.clearance_margin_norm,
        &proof.clearance_margin_witness_polys,
    )?;

    let recomposed = encode_pvtn_leaf(proof.clearance_level, &proof.role_tag, &proof.parent_digest);
    if leaf_hash(&recomposed) != proof.leaf_digest {
        return Err(VerifyError::Rejected);
    }

    verify_merkle_path(&proof.leaf_digest, tree_root, &proof.merkle_path)?;

    let ctx = private_membership_opening_ctx(
        opening_base_ctx,
        &proof.leaf_digest,
        tree_root,
        min_clearance,
        proof.clearance_level,
        &proof.role_tag,
        &proof.parent_digest,
    );
    verify_opening(
        key,
        &proof.credential_com,
        &proof.opening_proof,
        &ctx,
        tau,
        z_inf_bound,
    )
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn path_verifies_two_leaves() {
        let l0 = leaf_hash(b"a");
        let l1 = leaf_hash(b"b");
        let root = node_hash(&l0, &l1);
        let path = MerklePath {
            path_index: 0,
            siblings: vec![l1],
        };
        verify_merkle_path(&l0, &root, &path).expect("ok");
    }

    #[test]
    fn hierarchical_auth_accepts_leaf_at_level() {
        use lib_q_random::new_deterministic_rng;

        use crate::commitment::{
            AjtaiOpening,
            commit,
        };
        use crate::params::AjtaiParameters;
        use crate::sigma::opening::prove_opening;

        #[inline]
        fn test_seed32(tag: u64) -> [u8; 32] {
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&tag.to_le_bytes());
            seed
        }

        let role = [0xEEu8; 16];
        let parent = [0u8; 32];
        let leaf_payload = encode_pvtn_leaf(7, &role, &parent);
        let l0 = leaf_hash(&leaf_payload);
        let l1 = leaf_hash(b"other-node");
        let root = node_hash(&l0, &l1);
        let path = MerklePath {
            path_index: 0,
            siblings: vec![l1],
        };

        let params = AjtaiParameters::new(2, 1);
        let key = crate::commitment::AjtaiCommitmentKey {
            seed: [0x55u8; 32],
            params,
        };
        let opening = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let credential_com = commit(&key, &opening);
        let mut rng = new_deterministic_rng(test_seed32(0xCAB_u64));
        let ctx = hierarchical_opening_ctx(b"pvt", &leaf_payload);
        let opening_proof = prove_opening(
            &mut rng,
            &key,
            &opening,
            &credential_com,
            &ctx,
            39,
            20_000_000,
            512,
        )
        .expect("prove");

        let proof = HierarchicalAuthProof {
            merkle_path: path.clone(),
            leaf_payload: leaf_payload.clone(),
            credential_com: credential_com.clone(),
            opening_proof: opening_proof.clone(),
        };
        verify_level_membership(&key, &proof, &root, 5, b"pvt", 39, 20_000_000).expect("ok");
        assert!(verify_level_membership(&key, &proof, &root, 9, b"pvt", 39, 20_000_000).is_err());

        let mut rng = new_deterministic_rng(test_seed32(0xA11C_u64));
        let proved = prove_level_membership(
            &mut rng,
            &key,
            &opening,
            &credential_com,
            leaf_payload,
            path,
            &root,
            5,
            b"pvt",
            39,
            20_000_000,
            512,
        )
        .expect("prove level");
        verify_level_membership(&key, &proved, &root, 5, b"pvt", 39, 20_000_000)
            .expect("verify level");
    }

    #[test]
    fn private_membership_roundtrip_and_clearance_rejects_low_level() {
        use lib_q_random::new_deterministic_rng;

        use crate::commitment::{
            AjtaiOpening,
            commit,
        };
        use crate::params::AjtaiParameters;

        #[inline]
        fn test_seed32(tag: u64) -> [u8; 32] {
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&tag.to_le_bytes());
            seed
        }

        let role = [0xC3u8; 16];
        let parent = [0x11u8; 32];
        let leaf_payload = encode_pvtn_leaf(9, &role, &parent);
        let l0 = leaf_hash(&leaf_payload);
        let l1 = leaf_hash(b"other-private-node");
        let root = node_hash(&l0, &l1);
        let path = MerklePath {
            path_index: 0,
            siblings: vec![l1],
        };

        let params = AjtaiParameters::new(2, 1);
        let key = crate::commitment::AjtaiCommitmentKey {
            seed: [0x66u8; 32],
            params,
        };
        let opening = AjtaiOpening {
            message: lib_q_ring::ModuleVec(vec![
                lib_q_ring::Poly::zero(),
                lib_q_ring::Poly::zero(),
            ]),
            randomness: lib_q_ring::ModuleVec(vec![lib_q_ring::Poly::zero()]),
        };
        let credential_com = commit(&key, &opening);
        let mut rng = new_deterministic_rng(test_seed32(0x51A1_u64));
        let proof = prove_private_membership(
            &mut rng,
            &key,
            &opening,
            &credential_com,
            leaf_payload.clone(),
            path,
            &root,
            5,
            b"pvt-private",
            39,
            20_000_000,
            512,
        )
        .expect("prove private");

        verify_private_membership(&key, &proof, &root, 5, b"pvt-private", 39, 20_000_000)
            .expect("verify private");

        assert!(
            verify_private_membership(&key, &proof, &root, 10, b"pvt-private", 39, 20_000_000,)
                .is_err(),
            "min_clearance above the leaf level must be rejected"
        );

        let hier_ctx = hierarchical_opening_ctx(b"pvt-private", &leaf_payload);
        let priv_ctx = private_membership_opening_ctx(
            b"pvt-private",
            &proof.leaf_digest,
            &root,
            5,
            proof.clearance_level,
            &proof.role_tag,
            &proof.parent_digest,
        );
        assert!(
            !priv_ctx
                .windows(leaf_payload.len())
                .any(|w| w == leaf_payload.as_slice()),
            "private opening context must not embed the raw PVTN leaf payload"
        );
        assert!(
            hier_ctx
                .windows(leaf_payload.len())
                .any(|w| w == leaf_payload.as_slice()),
            "hierarchical opening context embeds the raw leaf for comparison"
        );
    }
}
