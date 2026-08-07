//! Versioned wire codecs for the round-1 commitment broadcast and complaints.
//!
//! Layouts are length-prefixed and budget-gated. They are **provisional** until the interoperable
//! wire freeze; the version + profile header lets a future freeze evolve them. Ring elements use the
//! canonical 6-byte-per-coefficient encoding of [`crate::lattice::ring`].

extern crate alloc;

use alloc::vec::Vec;

use crate::dkg::{
    CoeffCommitments,
    Complaint,
    ShareEvaluation,
};
use crate::error::DkgError;
use crate::lattice::bdlop::{
    Commitment,
    KAPPA,
    MU,
    ShareProof,
};
use crate::lattice::ring::{
    RQ_BYTES,
    Rq,
    rq_from_le_bytes,
    rq_to_le_bytes,
};
use crate::profile::{
    PROFILE_ID_V1,
    PROFILE_MAX_PARTIES_V1,
};

/// Wire version byte.
pub const WIRE_VERSION_V1: u8 = 1;

/// Wire bytes occupied by one encoded BDLOP commitment (`MU + 1` ring elements).
pub const COMMITMENT_WIRE_BYTES: usize = (MU + 1) * RQ_BYTES;

/// Maximum number of coefficient commitments a round-1 broadcast may declare.
///
/// A round-1 broadcast carries exactly `threshold` commitments, and the threshold can never exceed
/// [`PROFILE_MAX_PARTIES_V1`], so a larger declared count is malformed by construction.
pub const MAX_ROUND1_COMMITMENTS: usize = PROFILE_MAX_PARTIES_V1 as usize;

/// Maximum number of ring elements any length-prefixed `R_q` vector on the wire may declare.
///
/// The two wire-carried `R_q` vectors are the commitment randomness (`KAPPA` elements) and the
/// proof response `z` (`threshold · KAPPA` elements, `threshold <= PROFILE_MAX_PARTIES_V1`); the
/// larger of the two is the ceiling.
pub const MAX_WIRE_RQ_VEC_LEN: usize = PROFILE_MAX_PARTIES_V1 as usize * KAPPA;

/// Byte budget for an encoded round-1 commitment broadcast.
///
/// A commitment is `MU + 1` ring elements; at `MU = 6`, `t = 16` that is
/// `16·7·RQ_BYTES ≈ 672 KB` (under the 768 KB budget).
pub const WIRE_BUDGET_DKG_ROUND1_BYTES: usize = 786_432;

/// Byte budget for an encoded complaint (discloses the share value, randomness, and proof).
pub const WIRE_BUDGET_DKG_COMPLAINT_BYTES: usize = 1_048_576;

/// Byte budget for an encoded share evaluation (the share value, randomness, and proof).
pub const WIRE_BUDGET_DKG_SHARE_BYTES: usize = 1_048_576;

/// Encode a dealer's round-1 coefficient commitments.
pub fn encode_round1_commitments(c: &CoeffCommitments) -> Result<Vec<u8>, DkgError> {
    let n = u16::try_from(c.commitments.len()).map_err(|_| DkgError::LengthOverflow)?;
    let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1, c.party, c.threshold];
    out.extend_from_slice(&n.to_le_bytes());
    for com in &c.commitments {
        write_commitment(&mut out, com);
    }
    if out.len() > WIRE_BUDGET_DKG_ROUND1_BYTES {
        return Err(DkgError::BudgetExceeded {
            actual: out.len(),
            budget: WIRE_BUDGET_DKG_ROUND1_BYTES,
        });
    }
    Ok(out)
}

/// Decode a round-1 commitment broadcast.
///
/// # Errors
///
/// Returns [`DkgError::BudgetExceeded`] if the payload is larger than
/// [`WIRE_BUDGET_DKG_ROUND1_BYTES`], [`DkgError::WireVersionMismatch`] /
/// [`DkgError::WireProfileMismatch`] on a foreign header, [`DkgError::InvalidThreshold`] if the
/// declared commitment count exceeds [`MAX_ROUND1_COMMITMENTS`], [`DkgError::WireTruncated`] if the
/// declared count does not match the bytes actually present, and [`DkgError::Encoding`] if a ring
/// element is not canonically encoded.
///
/// The declared count is validated against both the protocol maximum and the remaining input length
/// *before* anything is allocated, so a short hostile payload cannot induce a large allocation.
pub fn decode_round1_commitments(wire: &[u8]) -> Result<CoeffCommitments, DkgError> {
    if wire.len() > WIRE_BUDGET_DKG_ROUND1_BYTES {
        return Err(DkgError::BudgetExceeded {
            actual: wire.len(),
            budget: WIRE_BUDGET_DKG_ROUND1_BYTES,
        });
    }
    let mut cur = 0usize;
    expect_header(wire, &mut cur)?;
    let party = read_u8(wire, &mut cur)?;
    let threshold = read_u8(wire, &mut cur)?;
    let n = usize::from(read_u16_le(wire, &mut cur)?);

    // Bound the attacker-declared count BEFORE any allocation: (a) against the named protocol
    // maximum, and (b) against the bytes actually present. `body` is the real remaining input, so
    // the `chunks_exact` collect below can only ever size itself from bytes the caller supplied.
    if n > MAX_ROUND1_COMMITMENTS {
        return Err(DkgError::InvalidThreshold);
    }
    let body = read_bytes(wire, &mut cur, n.saturating_mul(COMMITMENT_WIRE_BYTES))?;
    if cur != wire.len() {
        return Err(DkgError::WireTruncated);
    }
    let commitments = body
        .chunks_exact(COMMITMENT_WIRE_BYTES)
        .map(|chunk| {
            let mut inner = 0usize;
            read_commitment(chunk, &mut inner)
        })
        .collect::<Result<Vec<Commitment>, DkgError>>()?;

    Ok(CoeffCommitments {
        party,
        threshold,
        commitments,
    })
}

/// Encode a share evaluation (the share value, randomness, and proof).
pub fn encode_share_evaluation(s: &ShareEvaluation) -> Result<Vec<u8>, DkgError> {
    let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1];
    write_share_body(&mut out, s)?;
    if out.len() > WIRE_BUDGET_DKG_SHARE_BYTES {
        return Err(DkgError::BudgetExceeded {
            actual: out.len(),
            budget: WIRE_BUDGET_DKG_SHARE_BYTES,
        });
    }
    Ok(out)
}

/// Decode a share evaluation.
pub fn decode_share_evaluation(wire: &[u8]) -> Result<ShareEvaluation, DkgError> {
    if wire.len() > WIRE_BUDGET_DKG_SHARE_BYTES {
        return Err(DkgError::BudgetExceeded {
            actual: wire.len(),
            budget: WIRE_BUDGET_DKG_SHARE_BYTES,
        });
    }
    let mut cur = 0usize;
    expect_header(wire, &mut cur)?;
    let share = read_share_body(wire, &mut cur)?;
    if cur != wire.len() {
        return Err(DkgError::WireTruncated);
    }
    Ok(share)
}

/// Encode a complaint (discloses the disputed share value, randomness, and proof).
pub fn encode_complaint(c: &Complaint) -> Result<Vec<u8>, DkgError> {
    let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1, c.dealer, c.recipient];
    write_share_body(&mut out, &c.share)?;
    if out.len() > WIRE_BUDGET_DKG_COMPLAINT_BYTES {
        return Err(DkgError::BudgetExceeded {
            actual: out.len(),
            budget: WIRE_BUDGET_DKG_COMPLAINT_BYTES,
        });
    }
    Ok(out)
}

/// Decode a complaint.
pub fn decode_complaint(wire: &[u8]) -> Result<Complaint, DkgError> {
    if wire.len() > WIRE_BUDGET_DKG_COMPLAINT_BYTES {
        return Err(DkgError::BudgetExceeded {
            actual: wire.len(),
            budget: WIRE_BUDGET_DKG_COMPLAINT_BYTES,
        });
    }
    let mut cur = 0usize;
    expect_header(wire, &mut cur)?;
    let dealer = read_u8(wire, &mut cur)?;
    let recipient = read_u8(wire, &mut cur)?;
    let share = read_share_body(wire, &mut cur)?;
    if cur != wire.len() {
        return Err(DkgError::WireTruncated);
    }
    Ok(Complaint {
        dealer,
        recipient,
        share,
    })
}

// ---------------------------------------------------------------------------

/// Write a `ShareEvaluation` body (no version/profile header).
fn write_share_body(out: &mut Vec<u8>, s: &ShareEvaluation) -> Result<(), DkgError> {
    out.push(s.dealer);
    out.push(s.recipient);
    out.push(s.threshold);
    write_rq(out, &s.value);
    write_rq_vec(out, &s.rand)?;
    // Proof: challenge then response vector.
    write_rq(out, &s.proof.c);
    write_rq_vec(out, &s.proof.z)?;
    Ok(())
}

/// Read a `ShareEvaluation` body (no version/profile header).
fn read_share_body(wire: &[u8], cur: &mut usize) -> Result<ShareEvaluation, DkgError> {
    let dealer = read_u8(wire, cur)?;
    let recipient = read_u8(wire, cur)?;
    let threshold = read_u8(wire, cur)?;
    let value = read_rq(wire, cur)?;
    // The randomness is exactly `KAPPA` ring elements; the response `z` is `threshold · KAPPA`,
    // capped by `MAX_WIRE_RQ_VEC_LEN`. Each site passes its own named maximum.
    let rand = read_rq_vec(wire, cur, KAPPA)?;
    if rand.len() != KAPPA {
        return Err(DkgError::Encoding);
    }
    let c = read_rq(wire, cur)?;
    let z = read_rq_vec(wire, cur, MAX_WIRE_RQ_VEC_LEN)?;
    Ok(ShareEvaluation {
        dealer,
        recipient,
        threshold,
        value,
        rand,
        proof: ShareProof { c, z },
    })
}

fn write_commitment(out: &mut Vec<u8>, c: &Commitment) {
    for p in &c.t0 {
        write_rq(out, p);
    }
    write_rq(out, &c.t1);
}

fn read_commitment(wire: &[u8], cur: &mut usize) -> Result<Commitment, DkgError> {
    let mut t0 = Vec::with_capacity(MU);
    for _ in 0..MU {
        t0.push(read_rq(wire, cur)?);
    }
    let t1 = read_rq(wire, cur)?;
    Ok(Commitment { t0, t1 })
}

fn write_rq(out: &mut Vec<u8>, p: &Rq) {
    out.extend_from_slice(&rq_to_le_bytes(p));
}

fn read_rq(wire: &[u8], cur: &mut usize) -> Result<Rq, DkgError> {
    let body = read_bytes(wire, cur, RQ_BYTES)?;
    rq_from_le_bytes(body).ok_or(DkgError::Encoding)
}

fn write_rq_vec(out: &mut Vec<u8>, v: &[Rq]) -> Result<(), DkgError> {
    let n = u32::try_from(v.len()).map_err(|_| DkgError::LengthOverflow)?;
    out.extend_from_slice(&n.to_le_bytes());
    for p in v {
        write_rq(out, p);
    }
    Ok(())
}

/// Read a length-prefixed `R_q` vector, refusing to allocate on an unvalidated count.
///
/// `max_len` is the caller's named protocol maximum for this particular field. The declared count
/// is checked against it, and then the exact byte span is claimed from the remaining input, before
/// any allocation happens — the returned `Vec` is sized from bytes that are actually present.
fn read_rq_vec(wire: &[u8], cur: &mut usize, max_len: usize) -> Result<Vec<Rq>, DkgError> {
    let n = usize::try_from(read_u32_le(wire, cur)?).map_err(|_| DkgError::LengthOverflow)?;
    if n > max_len {
        return Err(DkgError::Encoding);
    }
    let body = read_bytes(wire, cur, n.saturating_mul(RQ_BYTES))?;
    body.chunks_exact(RQ_BYTES)
        .map(|chunk| rq_from_le_bytes(chunk).ok_or(DkgError::Encoding))
        .collect()
}

fn expect_header(wire: &[u8], cur: &mut usize) -> Result<(), DkgError> {
    let version = read_u8(wire, cur)?;
    if version != WIRE_VERSION_V1 {
        return Err(DkgError::WireVersionMismatch {
            expected: WIRE_VERSION_V1,
            found: version,
        });
    }
    let profile = read_u8(wire, cur)?;
    if profile != PROFILE_ID_V1 {
        return Err(DkgError::WireProfileMismatch {
            expected: PROFILE_ID_V1,
            found: profile,
        });
    }
    Ok(())
}

fn read_u8(wire: &[u8], cur: &mut usize) -> Result<u8, DkgError> {
    let b = wire.get(*cur).copied().ok_or(DkgError::WireTruncated)?;
    *cur += 1;
    Ok(b)
}

fn read_u16_le(wire: &[u8], cur: &mut usize) -> Result<u16, DkgError> {
    let b = read_bytes(wire, cur, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(wire: &[u8], cur: &mut usize) -> Result<u32, DkgError> {
    let b = read_bytes(wire, cur, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes<'a>(wire: &'a [u8], cur: &mut usize, len: usize) -> Result<&'a [u8], DkgError> {
    let end = cur.saturating_add(len);
    if end > wire.len() {
        return Err(DkgError::WireTruncated);
    }
    let out = &wire[*cur..end];
    *cur = end;
    Ok(out)
}
