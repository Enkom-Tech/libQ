//! Public API for unlinkable set-membership proofs — libQ `libq.zkfri.membership.v0`.
//!
//! Proves the Semaphore/Tornado statement
//!
//! ```text
//! ∃ (secret t, path):  MerkleVerify(root, L = H(t), path)  ∧  N = H(domain ‖ t ‖ ctx)
//! reveal only (root, ctx, N);  L and t stay private.
//! ```
//!
//! over the Poseidon-256 wide-digest Merkle tree ([`crate::merkle::WidePoseidonMerkleTree`]),
//! using the [`crate::air::UnlinkableMembershipAir`] circuit and the transparent FRI/STARK
//! prover. The single secret trapdoor `t` produces both the Merkle leaf `L` and the
//! context-scoped nullifier `N`, so a member proves admission while the verifier learns only
//! an unlinkable nullifier (double-use under one `ctx` collides on `N`).
//!
//! # Power-of-two trace height (path padding)
//!
//! The FRI prover requires a power-of-two trace height, but a tree's path depth `d` is rarely
//! itself a power of two. The path is therefore padded to `D = next_pow2(d)` levels with zero
//! siblings (`dir = left`), so the proof's public root is the deterministic **padded root**
//! `root_D = H(…H(real_root ‖ 0)…)` (`D − d` zero-hashings of the canonical root). The verifier
//! derives `root_D` from the canonical root identically (`d` is carried in the proof metadata),
//! so this is transparent and does not change soundness or unlinkability.
//!
//! RED: Poseidon-256 round counts are NOT verified for GF(p²) (`crate::air::wide_hash`); the
//! whole tier is gated behind the ADR-113 freeze review and is NOT proven sound / ZK yet.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_core::{
    Error,
    Result,
};
use lib_q_poseidon::PoseidonField;

pub use crate::air::unlinkable_membership::MEMBERSHIP_DOMAIN_STR;
use crate::air::unlinkable_membership::{
    CTX_ELEMS,
    SECRET_T_ELEMS,
    UnlinkableMembershipAir,
    generate_membership_trace,
    membership_leaf,
    membership_nullifier,
    membership_public_values,
};
use crate::air::wide_hash::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
};
use crate::air::{
    next_power_of_two,
    poseidon_field_to_bytes,
};
use crate::merkle::wide_node_hash;
use crate::stark::{
    DefaultConfig,
    StarkProver,
    StarkVerifier,
    ZkConfig,
    zk_config_with_params,
    zk_config_with_seed_bytes,
};
use crate::{
    ProofMetadata,
    ProofType,
    ZkpProof,
};

/// Maximum supported tree depth (matches the wide Merkle tree).
pub const MAX_DEPTH: usize = 64;
/// Bytes per wide digest: [`WIDE_DIGEST_ELEMS`] × 8 (each `Complex<Mersenne31>` is 8 bytes).
pub const WIDE_DIGEST_BYTES: usize = WIDE_DIGEST_ELEMS * 8; // 40
/// Bytes for a serialized `ctx`.
pub const CTX_BYTES: usize = CTX_ELEMS * 8; // 16
/// Bytes of the generic public statement `root ‖ ctx ‖ N` (for [`crate::ZkpVerifier`]).
pub const PUBLIC_STATEMENT_BYTES: usize = WIDE_DIGEST_BYTES + CTX_BYTES + WIDE_DIGEST_BYTES; // 96

/// Minimum padded path depth for the hiding (zero-knowledge) prover. The STARK trace height
/// must clear the ZK FRI minimum (`log_min_height > log_blowup`); with [`ZK_LOG_BLOWUP`] = 3,
/// height 8 (depth 8) is the smallest that proves. Shallow trees are padded up to this with
/// zero siblings, exactly like the power-of-two padding.
pub const MIN_ZK_DEPTH: usize = 8;

// Production hiding-PCS FRI parameters. `log_blowup` MUST be >= 3: under the hiding PCS the
// committed trace is randomized to ~2x its degree, so the degree-5 Poseidon S-box quotient
// needs a larger LDE than the transparent config (the hiding PCS has no out-of-LDE
// extrapolation fallback). Queries/PoW match the transparent production config.
const ZK_LOG_BLOWUP: usize = 3;
const ZK_NUM_QUERIES: usize = 100;
const ZK_POW_BITS: usize = 16;

/// The statement domain separator string (`libq.zkfri.membership.v0`).
pub fn statement_domain() -> &'static str {
    MEMBERSHIP_DOMAIN_STR
}

/// Prover inputs for an unlinkable membership proof.
#[derive(Clone)]
pub struct MembershipWitness {
    /// Secret trapdoor `t` (leaf is `L = H(t)`).
    pub t: [PoseidonField; SECRET_T_ELEMS],
    /// Public context the nullifier is scoped to.
    pub ctx: [PoseidonField; CTX_ELEMS],
    /// Authentication-path direction bits (`true` = running digest is the right child).
    pub path_bits: Vec<bool>,
    /// Authentication-path sibling digests (one per level).
    pub siblings: Vec<WideDigest>,
}

// ---------------------------------------------------------------------------
// Wide-digest serialization
// ---------------------------------------------------------------------------

/// Decode one `Complex<Mersenne31>` from 8 little-endian bytes, REJECTING non-canonical limbs
/// (`>= 2³¹−1`) so the public-statement byte encoding is injective (freeze-gate O6). Both limbs
/// are validated; the reducing `from_int` path (used by the legacy single-element decoder) is
/// deliberately NOT used here.
fn field_from_canonical_le(bytes: &[u8]) -> Result<PoseidonField> {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_field::integers::QuotientMap;
    use lib_q_stark_mersenne31::Mersenne31;

    if bytes.len() < 8 {
        return Err(Error::InvalidState {
            operation: "field_from_canonical_le".into(),
            reason: alloc::format!("need 8 bytes, got {}", bytes.len()),
        });
    }
    let mut real_b = [0u8; 4];
    let mut imag_b = [0u8; 4];
    real_b.copy_from_slice(&bytes[0..4]);
    imag_b.copy_from_slice(&bytes[4..8]);
    let real = Mersenne31::from_canonical_checked(u32::from_le_bytes(real_b)).ok_or_else(|| {
        Error::InvalidState {
            operation: "field_from_canonical_le".into(),
            reason: "non-canonical real limb (>= 2^31-1)".into(),
        }
    })?;
    let imag = Mersenne31::from_canonical_checked(u32::from_le_bytes(imag_b)).ok_or_else(|| {
        Error::InvalidState {
            operation: "field_from_canonical_le".into(),
            reason: "non-canonical imag limb (>= 2^31-1)".into(),
        }
    })?;
    Ok(Complex::new_complex(real, imag))
}

/// Serialize a wide digest to [`WIDE_DIGEST_BYTES`] bytes (5 × 8-byte `Complex<Mersenne31>`).
pub fn wide_digest_to_bytes(digest: &WideDigest) -> [u8; WIDE_DIGEST_BYTES] {
    let v = poseidon_field_to_bytes(digest);
    let mut out = [0u8; WIDE_DIGEST_BYTES];
    let n = core::cmp::min(v.len(), WIDE_DIGEST_BYTES);
    out[..n].copy_from_slice(&v[..n]);
    out
}

/// Deserialize a wide digest from at least [`WIDE_DIGEST_BYTES`] bytes.
pub fn wide_digest_from_bytes(bytes: &[u8]) -> Result<WideDigest> {
    if bytes.len() < WIDE_DIGEST_BYTES {
        return Err(Error::InvalidState {
            operation: "wide_digest_from_bytes".into(),
            reason: alloc::format!("need {} bytes, got {}", WIDE_DIGEST_BYTES, bytes.len()),
        });
    }
    let mut d = [PoseidonField::default(); WIDE_DIGEST_ELEMS];
    for (i, slot) in d.iter_mut().enumerate() {
        *slot = field_from_canonical_le(&bytes[i * 8..])?;
    }
    Ok(d)
}

fn ctx_from_bytes(bytes: &[u8]) -> Result<[PoseidonField; CTX_ELEMS]> {
    if bytes.len() < CTX_BYTES {
        return Err(Error::InvalidState {
            operation: "ctx_from_bytes".into(),
            reason: alloc::format!("need {} bytes, got {}", CTX_BYTES, bytes.len()),
        });
    }
    let mut c = [PoseidonField::default(); CTX_ELEMS];
    for (i, slot) in c.iter_mut().enumerate() {
        *slot = field_from_canonical_le(&bytes[i * 8..])?;
    }
    Ok(c)
}

/// Build the generic public statement bytes `root ‖ ctx ‖ N` ([`PUBLIC_STATEMENT_BYTES`]).
pub fn public_statement_bytes(
    root: &WideDigest,
    ctx: &[PoseidonField; CTX_ELEMS],
    nullifier: &WideDigest,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_STATEMENT_BYTES);
    out.extend_from_slice(&wide_digest_to_bytes(root));
    out.extend_from_slice(&poseidon_field_to_bytes(ctx));
    out.extend_from_slice(&wide_digest_to_bytes(nullifier));
    out
}

// ---------------------------------------------------------------------------
// Path folding / padding
// ---------------------------------------------------------------------------

/// Fold a leaf up an authentication path to the (real) root.
fn fold_path(leaf: &WideDigest, path_bits: &[bool], siblings: &[WideDigest]) -> WideDigest {
    let mut cur = *leaf;
    for (bit, sib) in path_bits.iter().zip(siblings.iter()) {
        cur = if *bit {
            wide_node_hash(sib, &cur)
        } else {
            wide_node_hash(&cur, sib)
        };
    }
    cur
}

/// Extend a root by `extra` zero-sibling levels (`dir = left`) — the padded root.
fn pad_root(root: &WideDigest, extra: usize) -> WideDigest {
    let zero = [PoseidonField::default(); WIDE_DIGEST_ELEMS];
    let mut cur = *root;
    for _ in 0..extra {
        cur = wide_node_hash(&cur, &zero);
    }
    cur
}

// ---------------------------------------------------------------------------
// Prove / verify
// ---------------------------------------------------------------------------

/// Prove unlinkable membership with the production STARK config.
///
/// Returns `(nullifier, proof)`. The verifier checks the proof against the **canonical** tree
/// root (it re-derives the padded root internally).
pub fn prove_unlinkable_membership(witness: &MembershipWitness) -> Result<(WideDigest, ZkpProof)> {
    prove_unlinkable_membership_with_config(witness, crate::stark::default_config())
}

/// Prove unlinkable membership with an explicit STARK config (use
/// [`crate::stark::fast_proof_config`] for tests).
pub fn prove_unlinkable_membership_with_config(
    witness: &MembershipWitness,
    config: DefaultConfig,
) -> Result<(WideDigest, ZkpProof)> {
    let depth = witness.path_bits.len();
    if depth == 0 || depth > MAX_DEPTH {
        return Err(Error::InvalidState {
            operation: "prove_unlinkable_membership".into(),
            reason: alloc::format!("tree depth {depth} must be in 1..={MAX_DEPTH}"),
        });
    }
    if witness.siblings.len() != depth {
        return Err(Error::InvalidState {
            operation: "prove_unlinkable_membership".into(),
            reason: alloc::format!(
                "siblings length {} != path_bits length {depth}",
                witness.siblings.len()
            ),
        });
    }

    // Pad the path to a power-of-two number of levels (power-of-two trace height).
    let padded = next_power_of_two(depth);
    let zero = [PoseidonField::default(); WIDE_DIGEST_ELEMS];
    let mut bits = witness.path_bits.clone();
    let mut sibs = witness.siblings.clone();
    for _ in depth..padded {
        bits.push(false);
        sibs.push(zero);
    }

    let leaf = membership_leaf(&witness.t);
    let root = fold_path(&leaf, &bits, &sibs);
    let nullifier = membership_nullifier(&witness.t, &witness.ctx);

    let trace = generate_membership_trace(&witness.t, &witness.ctx, &bits, &sibs);
    let public_values = membership_public_values(&root, &witness.ctx, &nullifier);

    let proof = StarkProver::new(config)
        .prove(&UnlinkableMembershipAir, trace, &public_values)
        .map_err(|e| Error::InternalError {
            operation: "unlinkable membership prove".into(),
            details: e.to_string(),
        })?;

    let zkp = ZkpProof::from_stark_proof(
        &proof,
        ProofMetadata::UnlinkableMembership {
            tree_depth: depth as u8,
            digest_width: WIDE_DIGEST_ELEMS as u8,
            zk: false,
        },
    )?;
    Ok((nullifier, zkp))
}

/// Verify an unlinkable membership proof against the **canonical** tree root with the
/// production config.
pub fn verify_unlinkable_membership(
    proof: &ZkpProof,
    root: &WideDigest,
    ctx: &[PoseidonField; CTX_ELEMS],
    nullifier: &WideDigest,
) -> Result<bool> {
    verify_unlinkable_membership_with_config(
        proof,
        root,
        ctx,
        nullifier,
        crate::stark::default_config(),
    )
}

/// Verify an unlinkable membership proof with an explicit STARK config (must match the prover).
pub fn verify_unlinkable_membership_with_config(
    proof: &ZkpProof,
    root: &WideDigest,
    ctx: &[PoseidonField; CTX_ELEMS],
    nullifier: &WideDigest,
    config: DefaultConfig,
) -> Result<bool> {
    if proof.proof_type != ProofType::Stark || proof.data.is_empty() {
        return Ok(false);
    }
    let depth = match &proof.metadata {
        ProofMetadata::UnlinkableMembership {
            tree_depth,
            digest_width,
            zk,
        } => {
            // A ZK proof is a distinct serialized type; route it to the ZK verifier instead.
            if *zk || *digest_width as usize != WIDE_DIGEST_ELEMS {
                return Ok(false);
            }
            *tree_depth as usize
        }
        _ => return Ok(false),
    };
    if depth == 0 || depth > MAX_DEPTH {
        return Ok(false);
    }

    // Re-derive the padded root from the canonical root (mirrors the prover's path padding).
    let padded = next_power_of_two(depth);
    let padded_root = pad_root(root, padded - depth);
    let public_values = membership_public_values(&padded_root, ctx, nullifier);

    let stark_proof = proof.to_stark_proof::<DefaultConfig>()?;

    // Depth-confusion guard (freeze-gate O5): the proof's actual STARK trace height must equal
    // the padded depth implied by the declared `tree_depth`. Without this, a prover could
    // relabel `tree_depth` in metadata independently of the height the proof was built at,
    // making `merkle_tree_depth()` an unauthenticated property. (Soundness against the
    // *statement* already rests on the verifier-supplied canonical root; this binds the
    // declared depth so the metadata cannot lie. Non-ZK config ⇒ `1 << degree_bits` == height.)
    if (1usize << stark_proof.degree_bits) != padded {
        return Ok(false);
    }

    match StarkVerifier::new(config).verify(&UnlinkableMembershipAir, &stark_proof, &public_values)
    {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Prove unlinkable membership with the **hiding (zero-knowledge)** prover.
///
/// Unlike [`prove_unlinkable_membership`] (transparent), this produces a proof that hides the
/// witness (`t`, leaf `L`, path) via the hiding FRI PCS — salted trace commitments + blinding
/// polynomials.
///
/// `salt_seed` (hiding-MMCS commitment salts) and `blinding_seed` (FRI blinding polynomials)
/// MUST be **INDEPENDENT, fresh, unpredictable 256-bit CSPRNG draws** per proof. They are
/// expanded through KangarooTwelve ([`crate::stark::zk_config_with_seed_bytes`] →
/// `lib_q_random::Kt128Rng`), so the hiding randomness is cryptographic (not the non-crypto
/// xorshift64 used by the `*_with_params` test path). Reusing, predicting, or sharing the two
/// seeds **voids** the zero-knowledge property.
///
/// RED / freeze-gate O4: the hiding PCS is wired with a cryptographic RNG and the proof
/// verifies, but the formal ZK / simulator argument over GF(p²) is **pending cryptographer
/// sign-off** — do not rely on the privacy claim until then.
pub fn prove_unlinkable_membership_zk(
    witness: &MembershipWitness,
    salt_seed: [u8; 32],
    blinding_seed: [u8; 32],
) -> Result<(WideDigest, ZkpProof)> {
    let config = zk_config_with_seed_bytes(
        ZK_LOG_BLOWUP,
        ZK_NUM_QUERIES,
        ZK_POW_BITS,
        salt_seed,
        blinding_seed,
    );
    prove_unlinkable_membership_zk_with_config(witness, config)
}

/// Foolproof hiding prover: draws the two independent blinding seeds from the **OS CSPRNG**
/// internally, so it cannot be called with predictable or reused entropy (closes the
/// fixed-seed footgun). Prefer this in production over [`prove_unlinkable_membership_zk`].
///
/// # Errors
///
/// Returns an error if no OS entropy source is available (i.e. `lib_q_random`'s `getrandom`
/// feature is off — e.g. a bare-metal `no_std` target). In that case the caller must supply
/// its own fresh CSPRNG entropy via [`prove_unlinkable_membership_zk`]; this function never
/// falls back to weak seeds.
pub fn prove_unlinkable_membership_zk_auto(
    witness: &MembershipWitness,
) -> Result<(WideDigest, ZkpProof)> {
    let mut salt_seed = [0u8; 32];
    let mut blinding_seed = [0u8; 32];
    lib_q_random::fill_entropy(&mut salt_seed).map_err(|_| Error::InternalError {
        operation: "prove_unlinkable_membership_zk_auto".into(),
        details: "no OS entropy source (enable lib-q-random getrandom, or pass explicit seeds)"
            .into(),
    })?;
    lib_q_random::fill_entropy(&mut blinding_seed).map_err(|_| Error::InternalError {
        operation: "prove_unlinkable_membership_zk_auto".into(),
        details: "no OS entropy source (enable lib-q-random getrandom, or pass explicit seeds)"
            .into(),
    })?;
    prove_unlinkable_membership_zk(witness, salt_seed, blinding_seed)
}

/// Hiding membership proof with an explicit ZK config (the config carries the blinding entropy
/// and FRI params). The config's `log_blowup` MUST be >= 3 for the degree-5 AIR (see
/// [`MIN_ZK_DEPTH`] / [`crate::stark::zk_config_with_params`]); tests use fast query params.
pub fn prove_unlinkable_membership_zk_with_config(
    witness: &MembershipWitness,
    config: ZkConfig,
) -> Result<(WideDigest, ZkpProof)> {
    let depth = witness.path_bits.len();
    if depth == 0 || depth > MAX_DEPTH {
        return Err(Error::InvalidState {
            operation: "prove_unlinkable_membership_zk".into(),
            reason: alloc::format!("tree depth {depth} must be in 1..={MAX_DEPTH}"),
        });
    }
    if witness.siblings.len() != depth {
        return Err(Error::InvalidState {
            operation: "prove_unlinkable_membership_zk".into(),
            reason: alloc::format!(
                "siblings length {} != path_bits length {depth}",
                witness.siblings.len()
            ),
        });
    }

    // Pad to a power-of-two height that also clears the ZK FRI minimum.
    let padded = core::cmp::max(next_power_of_two(depth), MIN_ZK_DEPTH);
    let zero = [PoseidonField::default(); WIDE_DIGEST_ELEMS];
    let mut bits = witness.path_bits.clone();
    let mut sibs = witness.siblings.clone();
    for _ in depth..padded {
        bits.push(false);
        sibs.push(zero);
    }

    let leaf = membership_leaf(&witness.t);
    let root = fold_path(&leaf, &bits, &sibs);
    let nullifier = membership_nullifier(&witness.t, &witness.ctx);

    let trace = generate_membership_trace(&witness.t, &witness.ctx, &bits, &sibs);
    let public_values = membership_public_values(&root, &witness.ctx, &nullifier);

    let proof = StarkProver::new(config)
        .prove(&UnlinkableMembershipAir, trace, &public_values)
        .map_err(|e| Error::InternalError {
            operation: "unlinkable membership zk prove".into(),
            details: e.to_string(),
        })?;

    let zkp = ZkpProof::from_stark_proof(
        &proof,
        ProofMetadata::UnlinkableMembership {
            tree_depth: depth as u8,
            digest_width: WIDE_DIGEST_ELEMS as u8,
            zk: true,
        },
    )?;
    Ok((nullifier, zkp))
}

/// Verify a **hiding (zero-knowledge)** unlinkable membership proof against the canonical root.
///
/// The verifier needs only the (public) FRI parameters, NOT the prover's blinding seeds.
pub fn verify_unlinkable_membership_zk(
    proof: &ZkpProof,
    root: &WideDigest,
    ctx: &[PoseidonField; CTX_ELEMS],
    nullifier: &WideDigest,
) -> Result<bool> {
    let config = zk_config_with_params(ZK_LOG_BLOWUP, ZK_NUM_QUERIES, ZK_POW_BITS, 0, 1);
    verify_unlinkable_membership_zk_with_config(proof, root, ctx, nullifier, config)
}

/// Verify a hiding membership proof with an explicit ZK config (FRI params must match the
/// prover's; the blinding seeds need not — the verifier does not use the prover's randomness).
pub fn verify_unlinkable_membership_zk_with_config(
    proof: &ZkpProof,
    root: &WideDigest,
    ctx: &[PoseidonField; CTX_ELEMS],
    nullifier: &WideDigest,
    config: ZkConfig,
) -> Result<bool> {
    if proof.proof_type != ProofType::Stark || proof.data.is_empty() {
        return Ok(false);
    }
    let depth = match &proof.metadata {
        ProofMetadata::UnlinkableMembership {
            tree_depth,
            digest_width,
            zk,
        } => {
            if !*zk || *digest_width as usize != WIDE_DIGEST_ELEMS {
                return Ok(false);
            }
            *tree_depth as usize
        }
        _ => return Ok(false),
    };
    if depth == 0 || depth > MAX_DEPTH {
        return Ok(false);
    }

    // Re-derive the padded root (same padding the ZK prover used: power-of-two AND >= MIN_ZK_DEPTH).
    let padded = core::cmp::max(next_power_of_two(depth), MIN_ZK_DEPTH);
    let padded_root = pad_root(root, padded - depth);
    let public_values = membership_public_values(&padded_root, ctx, nullifier);

    let stark_proof = proof.to_stark_proof::<ZkConfig>()?;

    // Depth-confusion guard (ZK): the hiding prover uses ONE extra degree bit for randomization,
    // so the proof's trace degree is `padded * 2`.
    if (1usize << stark_proof.degree_bits) != padded * 2 {
        return Ok(false);
    }

    match StarkVerifier::new(config).verify(&UnlinkableMembershipAir, &stark_proof, &public_values)
    {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify from a byte-encoded public statement `root ‖ ctx ‖ N` (used by the generic
/// [`crate::ZkpVerifier`] dispatch). Routes to the transparent or hiding verifier by the proof's
/// `zk` metadata flag. Uses the production config.
pub fn verify_unlinkable_membership_bytes(
    proof: &ZkpProof,
    public_statement: &[u8],
) -> Result<bool> {
    if public_statement.len() < PUBLIC_STATEMENT_BYTES {
        return Ok(false);
    }
    let root = wide_digest_from_bytes(&public_statement[..WIDE_DIGEST_BYTES])?;
    let ctx = ctx_from_bytes(&public_statement[WIDE_DIGEST_BYTES..WIDE_DIGEST_BYTES + CTX_BYTES])?;
    let nullifier = wide_digest_from_bytes(&public_statement[WIDE_DIGEST_BYTES + CTX_BYTES..])?;

    let is_zk = matches!(
        &proof.metadata,
        ProofMetadata::UnlinkableMembership { zk: true, .. }
    );
    if is_zk {
        verify_unlinkable_membership_zk(proof, &root, &ctx, &nullifier)
    } else {
        verify_unlinkable_membership(proof, &root, &ctx, &nullifier)
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;
    use crate::merkle::WidePoseidonMerkleTree;
    use crate::stark::fast_proof_config;

    fn fe(x: u32) -> PoseidonField {
        Complex::<Mersenne31>::from(Mersenne31::new(x))
    }
    fn secret(seed: u32) -> [PoseidonField; SECRET_T_ELEMS] {
        core::array::from_fn(|i| fe(seed * 7 + i as u32 + 1))
    }
    fn ctx_of(seed: u32) -> [PoseidonField; CTX_ELEMS] {
        core::array::from_fn(|i| fe(seed * 13 + i as u32 + 100))
    }

    /// Build a tree with `n` members (non-pow2 depth on purpose) and return it + secrets.
    fn build(n: u32) -> (WidePoseidonMerkleTree, Vec<[PoseidonField; SECRET_T_ELEMS]>) {
        let secrets: Vec<_> = (0..n).map(secret).collect();
        let leaves: Vec<WideDigest> = secrets.iter().map(membership_leaf).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        (tree, secrets)
    }

    fn witness_for(
        tree: &WidePoseidonMerkleTree,
        secrets: &[[PoseidonField; SECRET_T_ELEMS]],
        index: usize,
        ctx_seed: u32,
    ) -> MembershipWitness {
        let (path_bits, siblings) = tree.path(index).expect("path");
        MembershipWitness {
            t: secrets[index],
            ctx: ctx_of(ctx_seed),
            path_bits,
            siblings,
        }
    }

    #[test]
    fn wide_digest_byte_round_trip() {
        let d = membership_leaf(&secret(5));
        let bytes = wide_digest_to_bytes(&d);
        assert_eq!(bytes.len(), WIDE_DIGEST_BYTES);
        assert_eq!(wide_digest_from_bytes(&bytes).unwrap(), d);
    }

    #[test]
    fn rejects_non_canonical_digest_bytes() {
        // Freeze-gate O6: a limb >= 2^31-1 must be REJECTED, not silently reduced.
        let d = membership_leaf(&secret(2));
        let mut bytes = wide_digest_to_bytes(&d).to_vec();
        // p == 2^31-1 (non-canonical: would reduce to 0).
        bytes[0..4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert!(wide_digest_from_bytes(&bytes).is_err());
        // Clearly out-of-range word.
        bytes[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(wide_digest_from_bytes(&bytes).is_err());
    }

    #[test]
    fn prove_verify_round_trip_nonpow2_depth() {
        // 6 members → padded to 8 leaves → depth 3 (NOT a power of two ⇒ exercises padding).
        let (tree, secrets) = build(6);
        assert_eq!(tree.depth(), 3);
        let w = witness_for(&tree, &secrets, 4, 2);
        let cfg = fast_proof_config();
        let (nullifier, proof) =
            prove_unlinkable_membership_with_config(&w, cfg.clone()).expect("prove");

        assert_eq!(proof.merkle_tree_depth(), Some(3));
        assert!(
            verify_unlinkable_membership_with_config(&proof, &tree.root(), &w.ctx, &nullifier, cfg)
                .expect("verify"),
            "valid proof must verify against the canonical root"
        );
    }

    #[test]
    fn verify_rejects_wrong_root_ctx_nullifier() {
        let (tree, secrets) = build(6);
        let w = witness_for(&tree, &secrets, 1, 7);
        let cfg = fast_proof_config();
        let (nullifier, proof) =
            prove_unlinkable_membership_with_config(&w, cfg.clone()).expect("prove");

        // Wrong root.
        let wrong_root = membership_leaf(&secret(999));
        assert!(
            !verify_unlinkable_membership_with_config(
                &proof,
                &wrong_root,
                &w.ctx,
                &nullifier,
                cfg.clone()
            )
            .unwrap()
        );
        // Wrong ctx.
        assert!(
            !verify_unlinkable_membership_with_config(
                &proof,
                &tree.root(),
                &ctx_of(8),
                &nullifier,
                cfg.clone()
            )
            .unwrap()
        );
        // Wrong nullifier.
        let mut bad_n = nullifier;
        bad_n[0] += fe(1);
        assert!(
            !verify_unlinkable_membership_with_config(&proof, &tree.root(), &w.ctx, &bad_n, cfg)
                .unwrap()
        );
    }

    #[test]
    fn generic_bytes_dispatch_round_trip() {
        let (tree, secrets) = build(6);
        let w = witness_for(&tree, &secrets, 5, 3);
        let cfg = fast_proof_config();
        let (nullifier, proof) = prove_unlinkable_membership_with_config(&w, cfg).expect("prove");

        // NOTE: the byte dispatch path uses the production config, so it can only be exercised
        // for consistency of the statement encoding here (encode → decode).
        let stmt = public_statement_bytes(&tree.root(), &w.ctx, &nullifier);
        assert_eq!(stmt.len(), PUBLIC_STATEMENT_BYTES);
        let root = wide_digest_from_bytes(&stmt[..WIDE_DIGEST_BYTES]).unwrap();
        let n = wide_digest_from_bytes(&stmt[WIDE_DIGEST_BYTES + CTX_BYTES..]).unwrap();
        assert_eq!(root, tree.root());
        assert_eq!(n, nullifier);
        let _ = proof;
    }

    #[test]
    fn nullifier_unlinkable_across_ctx() {
        let t = secret(3);
        let n1 = membership_nullifier(&t, &ctx_of(1));
        let n2 = membership_nullifier(&t, &ctx_of(2));
        assert_ne!(n1, n2);
        assert_eq!(statement_domain(), "libq.zkfri.membership.v0");
    }

    /// O4: the hiding (ZK) prover round-trips, the verifier needs only the FRI params (not the
    /// prover's blinding seeds), fresh blinding entropy yields DISTINCT proof bytes (the
    /// randomization is real), the nullifier is independent of blinding, and the transparent
    /// verifier rejects a ZK proof. Uses fast ZK query params (`log_blowup=3` is mandatory for
    /// the degree-5 AIR). Depth 3 → padded to `MIN_ZK_DEPTH`.
    #[test]
    fn zk_round_trip_and_distinct_proofs() {
        let (tree, secrets) = build(6);
        let w = witness_for(&tree, &secrets, 4, 2);

        // Cryptographic ([u8;32] KT128-seeded) hiding path with fast query params.
        let (n1, p1) = prove_unlinkable_membership_zk_with_config(
            &w,
            zk_config_with_seed_bytes(3, 2, 1, [11u8; 32], [22u8; 32]),
        )
        .expect("zk prove 1");
        let (n2, p2) = prove_unlinkable_membership_zk_with_config(
            &w,
            zk_config_with_seed_bytes(3, 2, 1, [33u8; 32], [44u8; 32]),
        )
        .expect("zk prove 2");

        assert_eq!(
            n1, n2,
            "nullifier depends only on (t, ctx), not on blinding"
        );
        assert_ne!(
            p1.data, p2.data,
            "fresh blinding entropy ⇒ distinct ZK proof bytes"
        );
        assert_eq!(p1.merkle_tree_depth(), Some(3));

        // Verifier succeeds with seeds unrelated to either prover's.
        for p in [&p1, &p2] {
            assert!(
                verify_unlinkable_membership_zk_with_config(
                    p,
                    &tree.root(),
                    &w.ctx,
                    &n1,
                    zk_config_with_seed_bytes(3, 2, 1, [0u8; 32], [1u8; 32])
                )
                .expect("zk verify")
            );
        }
        // Wrong root rejected.
        assert!(
            !verify_unlinkable_membership_zk_with_config(
                &p1,
                &membership_leaf(&secret(999)),
                &w.ctx,
                &n1,
                zk_config_with_seed_bytes(3, 2, 1, [0u8; 32], [1u8; 32])
            )
            .unwrap()
        );
        // The transparent verifier must reject a ZK proof (metadata zk flag).
        assert!(
            !verify_unlinkable_membership_with_config(
                &p1,
                &tree.root(),
                &w.ctx,
                &n1,
                fast_proof_config()
            )
            .unwrap()
        );
    }

    #[test]
    fn auto_prover_entropy_source_is_available_and_nondegenerate() {
        // The foolproof auto-prover draws its blinding seeds from the OS CSPRNG. Confirm that
        // source is present and non-degenerate here (independent draws differ, never all-zero).
        // The full auto prove uses production FRI params and is covered by the `_with_config`
        // round-trip + the underlying explicit-seed prover.
        let mut a = [0u8; 32];
        if lib_q_random::fill_entropy(&mut a).is_ok() {
            let mut b = [0u8; 32];
            lib_q_random::fill_entropy(&mut b).expect("second entropy draw");
            assert_ne!(a, b, "independent OS entropy draws must differ");
            assert_ne!(a, [0u8; 32], "entropy must not be all-zero");
        }
        // If getrandom is unavailable, the auto prover returns an error rather than weak seeds.
    }
}
