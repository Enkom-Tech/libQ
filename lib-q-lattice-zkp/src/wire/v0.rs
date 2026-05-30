//! Version 0 wire envelopes and proof encodings.

use alloc::vec::Vec;

use lib_q_ring::ModuleVec;
use lib_q_ring::encoding::simple_bit_pack_len;

use super::pack::{
    pack_rq_module,
    pack_rq_poly,
    pack_z_module,
    unpack_rq_module,
    unpack_rq_poly,
    unpack_z_module,
};
use crate::blind::UnblindedIssuance;
use crate::commitment::AjtaiCommitment;
use crate::error::VerifyError;
use crate::profile::{
    LATTICE_ZKP_WIRE_VERSION_V0,
    LatticeZkpProfileV0,
    RQ_COEFF_PACK_BITS,
};
use crate::sigma::amortise::AmortisedProof;
use crate::sigma::hierarchical::{
    MerklePath,
    PVTN_CLEARANCE_MARGIN_NORM_BETA,
    PrivateMembershipProof,
    path_index_commitment,
    recover_clearance_level,
    recover_path_index,
};
use crate::sigma::linear::LinearRelationProof;
use crate::sigma::opening::{
    DualRingOpeningProof,
    OpeningProof,
};
use crate::sigma::uniqueness::{
    NullifierOpeningProof,
    WitnessNullifierOpeningProof,
};
use crate::token::{
    SpendingProof,
    TOKEN_EPOCH_LEN,
    TOKEN_ORIGIN_LEN,
    TOKEN_SERIAL_LEN,
};

fn packed_rq_module_len(poly_count: usize) -> usize {
    2 + poly_count.saturating_mul(simple_bit_pack_len(usize::from(RQ_COEFF_PACK_BITS)))
}

fn packed_z_module_len(poly_count: usize, pack_bits: u8) -> usize {
    2 + poly_count.saturating_mul(simple_bit_pack_len(usize::from(pack_bits)))
}

fn opening_body_len(profile: &LatticeZkpProfileV0) -> usize {
    packed_rq_module_len(profile.mask_poly_count()) +
        packed_z_module_len(profile.witness_poly_count(), profile.z_pack_bits)
}

/// Envelope: `version || profile_id || proof_kind || payload_len(u16 le)`.
pub const WIRE_ENVELOPE_HEADER_LEN: usize = 5;

pub const MAX_WIRE_BYTES_PVTN_V0: usize = 4_096;
pub const MAX_WIRE_BYTES_OPENING_V0: usize = 32 * 1024;
pub const MAX_WIRE_BYTES_SPENDING_V0: usize = 32 * 1024;
pub const MAX_WIRE_BYTES_LINEAR_V0: usize = 48 * 1024;
pub const MAX_WIRE_BYTES_NULLIFIER_V0: usize = 32 * 1024;
pub const MAX_WIRE_BYTES_AMORTISED_V0: usize = 125 * 1024;
pub const MAX_WIRE_BYTES_BLIND_ISSUANCE_V0: usize = 64 * 1024;
pub const MAX_WIRE_BYTES_DUAL_RING_V0: usize = 125 * 1024;

/// Proof kind tags inside a v0 envelope.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofKindV0 {
    Opening = 0x01,
    PrivateMembership = 0x02,
    Spending = 0x03,
    LinearRelation = 0x04,
    NullifierOpening = 0x05,
    WitnessNullifierOpening = 0x06,
    AmortisedAggregate = 0x07,
    BlindIssuance = 0x08,
    DualRingOpening = 0x09,
}

impl ProofKindV0 {
    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Opening),
            0x02 => Some(Self::PrivateMembership),
            0x03 => Some(Self::Spending),
            0x04 => Some(Self::LinearRelation),
            0x05 => Some(Self::NullifierOpening),
            0x06 => Some(Self::WitnessNullifierOpening),
            0x07 => Some(Self::AmortisedAggregate),
            0x08 => Some(Self::BlindIssuance),
            0x09 => Some(Self::DualRingOpening),
            _ => None,
        }
    }
}

fn max_wire_for_kind(kind: ProofKindV0, profile: &LatticeZkpProfileV0) -> usize {
    match kind {
        ProofKindV0::Opening => profile.max_wire_bytes.min(MAX_WIRE_BYTES_OPENING_V0),
        ProofKindV0::PrivateMembership => profile.max_wire_bytes.min(MAX_WIRE_BYTES_PVTN_V0),
        ProofKindV0::Spending => profile.max_wire_bytes.min(MAX_WIRE_BYTES_SPENDING_V0),
        ProofKindV0::LinearRelation => MAX_WIRE_BYTES_LINEAR_V0,
        ProofKindV0::NullifierOpening | ProofKindV0::WitnessNullifierOpening => {
            MAX_WIRE_BYTES_NULLIFIER_V0
        }
        ProofKindV0::AmortisedAggregate => MAX_WIRE_BYTES_AMORTISED_V0,
        ProofKindV0::BlindIssuance => MAX_WIRE_BYTES_BLIND_ISSUANCE_V0,
        ProofKindV0::DualRingOpening => MAX_WIRE_BYTES_DUAL_RING_V0,
    }
}

fn wrap_envelope(
    profile: &LatticeZkpProfileV0,
    kind: ProofKindV0,
    payload: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    let max = max_wire_for_kind(kind, profile);
    if payload.len() > max {
        return Err(VerifyError::InvalidFormat);
    }
    if payload.len() > u16::MAX as usize {
        return Err(VerifyError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(WIRE_ENVELOPE_HEADER_LEN + payload.len());
    out.push(LATTICE_ZKP_WIRE_VERSION_V0);
    out.push(profile.profile_id);
    out.push(kind as u8);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn unwrap_envelope(
    wire: &[u8],
    expected_kind: ProofKindV0,
) -> Result<(&[u8], LatticeZkpProfileV0), VerifyError> {
    if wire.len() < WIRE_ENVELOPE_HEADER_LEN {
        return Err(VerifyError::InvalidFormat);
    }
    if wire[0] != LATTICE_ZKP_WIRE_VERSION_V0 {
        return Err(VerifyError::InvalidFormat);
    }
    let profile =
        LatticeZkpProfileV0::from_profile_id(wire[1]).ok_or(VerifyError::InvalidFormat)?;
    let kind = ProofKindV0::from_u8(wire[2]).ok_or(VerifyError::InvalidFormat)?;
    if kind != expected_kind {
        return Err(VerifyError::InvalidFormat);
    }
    let payload_len = u16::from_le_bytes([wire[3], wire[4]]) as usize;
    let need = WIRE_ENVELOPE_HEADER_LEN.saturating_add(payload_len);
    if wire.len() != need {
        return Err(VerifyError::InvalidFormat);
    }
    if payload_len > max_wire_for_kind(expected_kind, &profile) {
        return Err(VerifyError::InvalidFormat);
    }
    Ok((&wire[WIRE_ENVELOPE_HEADER_LEN..], profile))
}

fn encode_opening_body(
    profile: &LatticeZkpProfileV0,
    proof: &OpeningProof,
) -> Result<Vec<u8>, VerifyError> {
    if proof.w.0.len() != profile.mask_poly_count() ||
        proof.z.0.len() != profile.witness_poly_count()
    {
        return Err(VerifyError::InvalidFormat);
    }
    let mut body = Vec::new();
    pack_rq_module(&proof.w.0, profile.modulus, &mut body)?;
    pack_z_module(
        &proof.z.0,
        profile.z_inf_bound,
        profile.z_pack_bits,
        &mut body,
    )?;
    Ok(body)
}

fn decode_opening_body(
    profile: &LatticeZkpProfileV0,
    body: &[u8],
) -> Result<OpeningProof, VerifyError> {
    let mut off = 0usize;
    let (w_polys, n1) = unpack_rq_module(&body[off..], profile.modulus)?;
    off = off.saturating_add(n1);
    let (z_polys, n2) = unpack_z_module(&body[off..], profile.z_inf_bound, profile.z_pack_bits)?;
    off = off.saturating_add(n2);
    if off != body.len() {
        return Err(VerifyError::InvalidFormat);
    }
    if w_polys.len() != profile.mask_poly_count() || z_polys.len() != profile.witness_poly_count() {
        return Err(VerifyError::InvalidFormat);
    }
    Ok(OpeningProof {
        w: ModuleVec(w_polys),
        z: ModuleVec(z_polys),
    })
}

/// Encode [`OpeningProof`] with a v0 envelope.
pub fn encode_opening_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &OpeningProof,
) -> Result<Vec<u8>, VerifyError> {
    let body = encode_opening_body(profile, proof)?;
    wrap_envelope(profile, ProofKindV0::Opening, &body)
}

/// Decode [`OpeningProof`] from a v0 wire blob.
pub fn decode_opening_proof_v0(
    wire: &[u8],
) -> Result<(OpeningProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::Opening)?;
    let proof = decode_opening_body(&profile, body)?;
    Ok((proof, profile))
}

fn encode_merkle_path_hidden(
    path: &MerklePath,
    tree_root: &[u8; 32],
    leaf_digest: &[u8; 32],
    depth_cap: u8,
    out: &mut Vec<u8>,
) -> Result<(), VerifyError> {
    let depth = path.siblings.len();
    if depth > depth_cap as usize {
        return Err(VerifyError::InvalidFormat);
    }
    let commitment = path_index_commitment(path.path_index, tree_root, leaf_digest, &path.siblings);
    out.push(depth as u8);
    for s in &path.siblings {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&commitment);
    Ok(())
}

fn decode_merkle_path_hidden(
    data: &[u8],
    depth_cap: u8,
    tree_root: &[u8; 32],
    leaf_digest: &[u8; 32],
) -> Result<(MerklePath, usize), VerifyError> {
    if data.is_empty() {
        return Err(VerifyError::InvalidFormat);
    }
    let depth = data[0] as usize;
    if depth > depth_cap as usize {
        return Err(VerifyError::InvalidFormat);
    }
    let need = 1 + depth * 32 + 32;
    if data.len() < need {
        return Err(VerifyError::InvalidFormat);
    }
    let mut siblings = Vec::with_capacity(depth);
    let mut off = 1usize;
    for _ in 0..depth {
        let mut s = [0u8; 32];
        s.copy_from_slice(&data[off..off + 32]);
        siblings.push(s);
        off += 32;
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&data[off..off + 32]);
    off += 32;
    let path_index = recover_path_index(tree_root, leaf_digest, &siblings, &commitment)?;
    Ok((
        MerklePath {
            path_index,
            siblings,
        },
        off,
    ))
}

/// Encode PVTN private membership proof (credential commitment is **not** on the wire).
pub fn encode_private_membership_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &PrivateMembershipProof,
    tree_root: &[u8; 32],
    min_clearance: u32,
) -> Result<Vec<u8>, VerifyError> {
    if profile.profile_id != crate::profile::PROFILE_ID_PVTN_MEMBERSHIP_V0 {
        return Err(VerifyError::InvalidFormat);
    }
    if proof.clearance_level < min_clearance {
        return Err(VerifyError::Rejected);
    }
    let margin = proof
        .clearance_level
        .checked_sub(min_clearance)
        .ok_or(VerifyError::InvalidFormat)?;
    if margin > PVTN_CLEARANCE_MARGIN_NORM_BETA as u32 {
        return Err(VerifyError::InvalidFormat);
    }

    let mut body = Vec::new();
    encode_merkle_path_hidden(
        &proof.merkle_path,
        tree_root,
        &proof.leaf_digest,
        profile.merkle_depth_cap,
        &mut body,
    )?;
    body.extend_from_slice(&proof.leaf_digest);
    body.extend_from_slice(&proof.role_tag);
    body.extend_from_slice(&proof.parent_digest);
    body.extend_from_slice(&proof.clearance_margin_norm.max_norm.to_le_bytes());
    let opening_body = encode_opening_body(profile, &proof.opening_proof)?;
    body.extend_from_slice(&opening_body);
    wrap_envelope(profile, ProofKindV0::PrivateMembership, &body)
}

/// Decode PVTN proof and attach the externally supplied credential commitment.
pub fn decode_private_membership_proof_v0(
    wire: &[u8],
    min_clearance: u32,
    tree_root: &[u8; 32],
    credential_com: AjtaiCommitment,
) -> Result<PrivateMembershipProof, VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::PrivateMembership)?;
    if body.is_empty() {
        return Err(VerifyError::InvalidFormat);
    }
    let depth = body[0] as usize;
    if depth > profile.merkle_depth_cap as usize {
        return Err(VerifyError::InvalidFormat);
    }
    let merkle_len = 1 + depth * 32 + 32;
    if body.len() < merkle_len + 32 + 16 + 32 + 4 {
        return Err(VerifyError::InvalidFormat);
    }
    let mut leaf_digest = [0u8; 32];
    leaf_digest.copy_from_slice(&body[merkle_len..merkle_len + 32]);
    let (merkle_path, n0) =
        decode_merkle_path_hidden(body, profile.merkle_depth_cap, tree_root, &leaf_digest)?;
    let mut off = n0 + 32;
    let mut role_tag = [0u8; 16];
    role_tag.copy_from_slice(&body[off..off + 16]);
    off += 16;
    let mut parent_digest = [0u8; 32];
    parent_digest.copy_from_slice(&body[off..off + 32]);
    off += 32;
    let max_norm = i32::from_le_bytes(
        body[off..off + 4]
            .try_into()
            .map_err(|_| VerifyError::InvalidFormat)?,
    );
    off += 4;

    let opening_proof = decode_opening_body(&profile, &body[off..])?;

    let clearance_level =
        recover_clearance_level(min_clearance, &leaf_digest, &role_tag, &parent_digest)?;
    let margin = clearance_level - min_clearance;

    let clearance_margin_norm = crate::sigma::norm::CrtPackedNormProof {
        slot_bounds: alloc::vec![max_norm],
        beta: PVTN_CLEARANCE_MARGIN_NORM_BETA,
        max_norm,
    };
    let mut margin_poly = lib_q_ring::Poly::zero();
    margin_poly.coeffs[0] = margin as i32;

    Ok(PrivateMembershipProof {
        merkle_path,
        leaf_digest,
        clearance_level,
        role_tag,
        parent_digest,
        credential_com,
        opening_proof,
        clearance_margin_norm,
        clearance_margin_witness_polys: alloc::vec![margin_poly],
    })
}

/// Encode token spending proof (`serial` + opening).
pub fn encode_spending_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &SpendingProof,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    body.extend_from_slice(&proof.serial);
    let opening_body = encode_opening_body(profile, &proof.opening_proof)?;
    body.extend_from_slice(&opening_body);
    wrap_envelope(profile, ProofKindV0::Spending, &body)
}

/// Decode token spending proof.
pub fn decode_spending_proof_v0(
    wire: &[u8],
) -> Result<(SpendingProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::Spending)?;
    if body.len() < TOKEN_SERIAL_LEN {
        return Err(VerifyError::InvalidFormat);
    }
    let mut serial = [0u8; TOKEN_SERIAL_LEN];
    serial.copy_from_slice(&body[..TOKEN_SERIAL_LEN]);
    let opening_proof = decode_opening_body(&profile, &body[TOKEN_SERIAL_LEN..])?;
    Ok((
        SpendingProof {
            serial,
            opening_proof,
        },
        profile,
    ))
}

/// Encode linear relation proof (opening + `u` vector).
pub fn encode_linear_relation_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &LinearRelationProof,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = encode_opening_body(profile, &proof.opening)?;
    pack_rq_module(&proof.u.0, profile.modulus, &mut body)?;
    wrap_envelope(profile, ProofKindV0::LinearRelation, &body)
}

/// Decode linear relation proof.
pub fn decode_linear_relation_proof_v0(
    wire: &[u8],
) -> Result<(LinearRelationProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::LinearRelation)?;
    let split = opening_body_len(&profile);
    if body.len() < split {
        return Err(VerifyError::InvalidFormat);
    }
    let opening = decode_opening_body(&profile, &body[..split])?;
    let (u_polys, consumed) = unpack_rq_module(&body[split..], profile.modulus)?;
    if split.saturating_add(consumed) != body.len() {
        return Err(VerifyError::InvalidFormat);
    }
    Ok((
        LinearRelationProof {
            opening,
            u: ModuleVec(u_polys),
        },
        profile,
    ))
}

/// Encode nullifier-bound opening proof.
pub fn encode_nullifier_opening_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &NullifierOpeningProof,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    body.extend_from_slice(&proof.nullifier);
    let opening_body = encode_opening_body(profile, &proof.opening)?;
    body.extend_from_slice(&opening_body);
    wrap_envelope(profile, ProofKindV0::NullifierOpening, &body)
}

/// Decode nullifier-bound opening proof.
pub fn decode_nullifier_opening_proof_v0(
    wire: &[u8],
) -> Result<(NullifierOpeningProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::NullifierOpening)?;
    if body.len() < 32 {
        return Err(VerifyError::InvalidFormat);
    }
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&body[..32]);
    let opening = decode_opening_body(&profile, &body[32..])?;
    Ok((NullifierOpeningProof { nullifier, opening }, profile))
}

/// Encode witness-nullifier opening proof.
pub fn encode_witness_nullifier_opening_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &WitnessNullifierOpeningProof,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    body.extend_from_slice(&proof.nullifier);
    let opening_body = encode_opening_body(profile, &proof.opening)?;
    body.extend_from_slice(&opening_body);
    wrap_envelope(profile, ProofKindV0::WitnessNullifierOpening, &body)
}

/// Decode witness-nullifier opening proof.
pub fn decode_witness_nullifier_opening_proof_v0(
    wire: &[u8],
) -> Result<(WitnessNullifierOpeningProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::WitnessNullifierOpening)?;
    if body.len() < 32 {
        return Err(VerifyError::InvalidFormat);
    }
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&body[..32]);
    let opening = decode_opening_body(&profile, &body[32..])?;
    Ok((WitnessNullifierOpeningProof { nullifier, opening }, profile))
}

/// Encode amortised aggregate proof (transcript + scalars + aggregated masks/responses).
pub fn encode_amortised_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &AmortisedProof,
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    let tlen = proof.transcript.len();
    if tlen > u32::MAX as usize {
        return Err(VerifyError::InvalidFormat);
    }
    body.extend_from_slice(&(tlen as u32).to_le_bytes());
    body.extend_from_slice(&proof.transcript);
    let n = proof.r_scalars.len();
    if n > u16::MAX as usize {
        return Err(VerifyError::InvalidFormat);
    }
    body.extend_from_slice(&(n as u16).to_le_bytes());
    for &r in &proof.r_scalars {
        body.extend_from_slice(&r.to_le_bytes());
    }
    pack_z_module(
        &proof.agg_z.0,
        profile.z_inf_bound,
        profile.z_pack_bits,
        &mut body,
    )?;
    pack_rq_module(&proof.agg_w.0, profile.modulus, &mut body)?;
    wrap_envelope(profile, ProofKindV0::AmortisedAggregate, &body)
}

/// Decode amortised aggregate proof.
pub fn decode_amortised_proof_v0(
    wire: &[u8],
) -> Result<(AmortisedProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::AmortisedAggregate)?;
    if body.len() < 4 + 2 {
        return Err(VerifyError::InvalidFormat);
    }
    let tlen = u32::from_le_bytes(
        body[0..4]
            .try_into()
            .map_err(|_| VerifyError::InvalidFormat)?,
    ) as usize;
    let mut off = 4;
    if body.len() < off + tlen + 2 {
        return Err(VerifyError::InvalidFormat);
    }
    let transcript = body[off..off + tlen].to_vec().into_boxed_slice();
    off += tlen;
    let n = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + n * 4 {
        return Err(VerifyError::InvalidFormat);
    }
    let mut r_scalars = Vec::with_capacity(n);
    for _ in 0..n {
        r_scalars.push(u32::from_le_bytes(
            body[off..off + 4]
                .try_into()
                .map_err(|_| VerifyError::InvalidFormat)?,
        ));
        off += 4;
    }
    let (z_polys, n1) = unpack_z_module(&body[off..], profile.z_inf_bound, profile.z_pack_bits)?;
    off += n1;
    let (w_polys, n2) = unpack_rq_module(&body[off..], profile.modulus)?;
    off += n2;
    if off != body.len() {
        return Err(VerifyError::InvalidFormat);
    }
    Ok((
        AmortisedProof {
            transcript,
            r_scalars,
            agg_z: ModuleVec(z_polys),
            agg_w: ModuleVec(w_polys),
        },
        profile,
    ))
}

/// Blind issuance bundle on the wire (issuer attestation + blinded commitment digest).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindIssuanceWireV0 {
    pub issuer_params_digest: [u8; 32],
    pub com_blinded_digest: [u8; 32],
    pub issuer_com: AjtaiCommitment,
    pub issuer_proof: OpeningProof,
}

/// Encode blind issuance attestation (token opening stays prover-local).
pub fn encode_blind_issuance_v0(
    profile: &LatticeZkpProfileV0,
    bundle: &UnblindedIssuance,
    issuer_params_digest: &[u8; 32],
    com_blinded_digest: &[u8; 32],
) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    body.extend_from_slice(issuer_params_digest);
    body.extend_from_slice(com_blinded_digest);
    pack_rq_module(&bundle.issuer_com.value.0, profile.modulus, &mut body)?;
    let opening_body = encode_opening_body(profile, &bundle.issuer_proof)?;
    body.extend_from_slice(&opening_body);
    wrap_envelope(profile, ProofKindV0::BlindIssuance, &body)
}

/// Decode blind issuance attestation wire bundle.
pub fn decode_blind_issuance_v0(
    wire: &[u8],
) -> Result<(BlindIssuanceWireV0, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::BlindIssuance)?;
    if body.len() < 64 {
        return Err(VerifyError::InvalidFormat);
    }
    let mut issuer_params_digest = [0u8; 32];
    issuer_params_digest.copy_from_slice(&body[..32]);
    let mut com_blinded_digest = [0u8; 32];
    com_blinded_digest.copy_from_slice(&body[32..64]);
    let mut off = 64;
    let (issuer_polys, n1) = unpack_rq_module(&body[off..], profile.modulus)?;
    off += n1;
    let issuer_proof = decode_opening_body(&profile, &body[off..])?;
    Ok((
        BlindIssuanceWireV0 {
            issuer_params_digest,
            com_blinded_digest,
            issuer_com: AjtaiCommitment {
                value: ModuleVec(issuer_polys),
            },
            issuer_proof,
        },
        profile,
    ))
}

/// Encode DualRing opening proof (`challenges` + aggregated response `z`).
pub fn encode_dual_ring_opening_proof_v0(
    profile: &LatticeZkpProfileV0,
    proof: &DualRingOpeningProof,
) -> Result<Vec<u8>, VerifyError> {
    if proof.challenges.len() > u8::MAX as usize {
        return Err(VerifyError::InvalidFormat);
    }
    let mut body = Vec::new();
    body.push(proof.challenges.len() as u8);
    for challenge in &proof.challenges {
        pack_rq_poly(challenge, profile.modulus, &mut body)?;
    }
    pack_z_module(
        &proof.z.0,
        profile.z_inf_bound,
        profile.z_pack_bits,
        &mut body,
    )?;
    wrap_envelope(profile, ProofKindV0::DualRingOpening, &body)
}

/// Decode DualRing opening proof.
pub fn decode_dual_ring_opening_proof_v0(
    wire: &[u8],
) -> Result<(DualRingOpeningProof, LatticeZkpProfileV0), VerifyError> {
    let (body, profile) = unwrap_envelope(wire, ProofKindV0::DualRingOpening)?;
    if body.is_empty() {
        return Err(VerifyError::InvalidFormat);
    }
    let ring_len = usize::from(body[0]);
    let mut off = 1;
    let mut challenges = Vec::with_capacity(ring_len);
    for _ in 0..ring_len {
        let (poly, consumed) = unpack_rq_poly(&body[off..], profile.modulus)?;
        challenges.push(poly);
        off = off.saturating_add(consumed);
        if off > body.len() {
            return Err(VerifyError::InvalidFormat);
        }
    }
    let (z_polys, consumed) =
        unpack_z_module(&body[off..], profile.z_inf_bound, profile.z_pack_bits)?;
    off = off.saturating_add(consumed);
    if off != body.len() {
        return Err(VerifyError::InvalidFormat);
    }
    Ok((
        DualRingOpeningProof {
            challenges,
            z: ModuleVec(z_polys),
        },
        profile,
    ))
}

/// Public helper: encoded byte length of a complete v0 wire blob.
#[must_use]
pub fn wire_byte_len(wire: &[u8]) -> usize {
    wire.len()
}

/// Token header wire segment length.
#[allow(dead_code)]
pub const TOKEN_HEADER_WIRE_LEN: usize = TOKEN_SERIAL_LEN + TOKEN_ORIGIN_LEN + TOKEN_EPOCH_LEN;

#[cfg(test)]
mod tests {
    use lib_q_ring::Poly;

    use super::*;

    fn sample_opening_proof(k: usize, wit: usize) -> OpeningProof {
        OpeningProof {
            w: ModuleVec(alloc::vec![Poly::zero(); k]),
            z: ModuleVec(alloc::vec![Poly::zero(); wit]),
        }
    }

    #[test]
    fn opening_proof_wire_roundtrip() {
        let profile = LatticeZkpProfileV0::token_spend_v0();
        let proof = sample_opening_proof(profile.mask_poly_count(), profile.witness_poly_count());
        let wire = encode_opening_proof_v0(&profile, &proof).expect("encode");
        let (back, pid) = decode_opening_proof_v0(&wire).expect("decode");
        assert_eq!(pid.profile_id, profile.profile_id);
        assert_eq!(back, proof);
    }

    #[test]
    fn envelope_rejects_trailing_bytes() {
        let profile = LatticeZkpProfileV0::token_spend_v0();
        let proof = sample_opening_proof(profile.mask_poly_count(), profile.witness_poly_count());
        let mut wire = encode_opening_proof_v0(&profile, &proof).expect("encode");
        wire.push(0xFF);
        assert!(decode_opening_proof_v0(&wire).is_err());
    }

    #[test]
    fn pvtn_wire_respects_depth_cap() {
        let profile = LatticeZkpProfileV0::pvtn_membership_v0();
        let depth = profile.merkle_depth_cap as usize + 1;
        let proof = PrivateMembershipProof {
            merkle_path: MerklePath {
                path_index: 0,
                siblings: alloc::vec![[0u8; 32]; depth],
            },
            leaf_digest: [1u8; 32],
            clearance_level: 5,
            role_tag: [2u8; 16],
            parent_digest: [3u8; 32],
            credential_com: AjtaiCommitment {
                value: ModuleVec(alloc::vec![Poly::zero()]),
            },
            opening_proof: sample_opening_proof(1, 2),
            clearance_margin_norm: crate::sigma::norm::CrtPackedNormProof {
                slot_bounds: alloc::vec![0],
                beta: PVTN_CLEARANCE_MARGIN_NORM_BETA,
                max_norm: 0,
            },
            clearance_margin_witness_polys: alloc::vec![Poly::zero()],
        };
        assert!(encode_private_membership_proof_v0(&profile, &proof, &[0u8; 32], 5).is_err());
    }

    #[test]
    fn dual_ring_opening_wire_roundtrip() {
        use crate::sigma::opening::DualRingOpeningProof;

        let profile = LatticeZkpProfileV0::token_spend_v0();
        let proof = DualRingOpeningProof {
            challenges: alloc::vec![Poly::zero(), Poly::zero()],
            z: ModuleVec(alloc::vec![Poly::zero(); profile.witness_poly_count()]),
        };
        let wire = encode_dual_ring_opening_proof_v0(&profile, &proof).expect("encode");
        let (back, pid) = decode_dual_ring_opening_proof_v0(&wire).expect("decode");
        assert_eq!(pid.profile_id, profile.profile_id);
        assert_eq!(back.challenges.len(), 2);
        assert_eq!(back.z.0.len(), profile.witness_poly_count());
    }
}
