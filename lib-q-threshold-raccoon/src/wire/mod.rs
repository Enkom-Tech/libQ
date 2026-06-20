//! Versioned, budget-gated codec for a [`crate::Signature`].
//!
//! Layout: `[ver=1][profile=1] c  z_s  z_r[KAPPA]` — `2 + KAPPA` ring elements in the canonical
//! 6-byte-per-coefficient encoding of `lib_q_dkg::lattice::ring`. Provisional until the wire freeze.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::KAPPA;
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
    rq_from_le_bytes,
    rq_to_le_bytes,
};

use crate::error::RaccoonError;
use crate::profile::PROFILE_ID_V1;
use crate::signer::Signature;

/// Wire version byte.
pub const WIRE_VERSION_V1: u8 = 1;

/// Byte budget for an encoded signature (`2 + KAPPA` ring elements + header).
pub const WIRE_BUDGET_SIGNATURE_BYTES: usize = 131_072;

/// Encode a signature.
pub fn encode_signature(sig: &Signature) -> Result<Vec<u8>, RaccoonError> {
    if sig.z_r.len() != KAPPA {
        return Err(RaccoonError::Encoding);
    }
    let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1];
    out.extend_from_slice(&rq_to_le_bytes(&sig.c));
    out.extend_from_slice(&rq_to_le_bytes(&sig.z_s));
    for p in &sig.z_r {
        out.extend_from_slice(&rq_to_le_bytes(p));
    }
    if out.len() > WIRE_BUDGET_SIGNATURE_BYTES {
        return Err(RaccoonError::BudgetExceeded {
            actual: out.len(),
            budget: WIRE_BUDGET_SIGNATURE_BYTES,
        });
    }
    Ok(out)
}

/// Decode a signature.
pub fn decode_signature(wire: &[u8]) -> Result<Signature, RaccoonError> {
    if wire.len() > WIRE_BUDGET_SIGNATURE_BYTES {
        return Err(RaccoonError::BudgetExceeded {
            actual: wire.len(),
            budget: WIRE_BUDGET_SIGNATURE_BYTES,
        });
    }
    let mut cur = 0usize;
    let version = read_u8(wire, &mut cur)?;
    if version != WIRE_VERSION_V1 {
        return Err(RaccoonError::WireVersionMismatch {
            expected: WIRE_VERSION_V1,
            found: version,
        });
    }
    let profile = read_u8(wire, &mut cur)?;
    if profile != PROFILE_ID_V1 {
        return Err(RaccoonError::WireProfileMismatch {
            expected: PROFILE_ID_V1,
            found: profile,
        });
    }
    let c = read_rq(wire, &mut cur)?;
    let z_s = read_rq(wire, &mut cur)?;
    let mut z_r = Vec::with_capacity(KAPPA);
    for _ in 0..KAPPA {
        z_r.push(read_rq(wire, &mut cur)?);
    }
    if cur != wire.len() {
        return Err(RaccoonError::WireTruncated);
    }
    Ok(Signature { c, z_s, z_r })
}

fn read_u8(wire: &[u8], cur: &mut usize) -> Result<u8, RaccoonError> {
    let b = wire.get(*cur).copied().ok_or(RaccoonError::WireTruncated)?;
    *cur += 1;
    Ok(b)
}

fn read_rq(wire: &[u8], cur: &mut usize) -> Result<Rq, RaccoonError> {
    let end = cur.saturating_add(RQ_BYTES);
    if end > wire.len() {
        return Err(RaccoonError::WireTruncated);
    }
    let p = rq_from_le_bytes(&wire[*cur..end]).ok_or(RaccoonError::Encoding)?;
    *cur = end;
    Ok(p)
}
