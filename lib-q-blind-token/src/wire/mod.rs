//! Versioned codec for the redeemable token value (a ZK proof of possession).
//!
//! Layout (length-prefixed, budget-gated, **provisional** until the wire freeze):
//! `[ver][profile] framed(w_commit) framed(z)` where `w_commit` is one ring element and `z` is the
//! `WITNESS_LEN` response ring elements. Std-gated: the token type lives in the std-only scheme.

/// Wire version byte.
pub const WIRE_VERSION_V1: u8 = 1;

/// Byte budget for an encoded token value. The secure instance (`N = 1024`, `q ≈ 2^46`, 6 bytes
/// per coefficient) yields a proof of `(1 + WITNESS_LEN)·N·6 ≈ 399 KB`; the budget leaves headroom.
pub const WIRE_BUDGET_BLIND_TOKEN_BYTES: usize = 524_288;

#[cfg(feature = "std")]
pub use imp::{
    decode_token_value,
    encode_token_value,
};

#[cfg(feature = "std")]
mod imp {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::{
        WIRE_BUDGET_BLIND_TOKEN_BYTES,
        WIRE_VERSION_V1,
    };
    use crate::error::BlindTokenError;
    use crate::lattice::ring::{
        N,
        Q,
        Rq,
    };
    use crate::lattice::scheme::{
        TokenProof,
        WITNESS_LEN,
    };
    use crate::profile::PROFILE_ID_V1;

    /// Bytes per coefficient (`q < 2^48` ⇒ 6 bytes suffice).
    const COEFF_BYTES: usize = 6;
    /// Encoded size of one ring element.
    const ELT_BYTES: usize = N * COEFF_BYTES;

    /// Serialize a [`TokenProof`] into a redeemable token value.
    pub fn encode_token_value(proof: &TokenProof) -> Result<Vec<u8>, BlindTokenError> {
        let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1];
        append_framed(&mut out, core::slice::from_ref(&proof.w_commit))?;
        append_framed(&mut out, &proof.z)?;
        if out.len() > WIRE_BUDGET_BLIND_TOKEN_BYTES {
            return Err(BlindTokenError::BudgetExceeded {
                actual: out.len(),
                budget: WIRE_BUDGET_BLIND_TOKEN_BYTES,
            });
        }
        Ok(out)
    }

    /// Parse a redeemable token value back into a [`TokenProof`].
    pub fn decode_token_value(wire: &[u8]) -> Result<TokenProof, BlindTokenError> {
        if wire.len() > WIRE_BUDGET_BLIND_TOKEN_BYTES {
            return Err(BlindTokenError::BudgetExceeded {
                actual: wire.len(),
                budget: WIRE_BUDGET_BLIND_TOKEN_BYTES,
            });
        }
        let mut cur = 0usize;
        let version = read_u8(wire, &mut cur)?;
        if version != WIRE_VERSION_V1 {
            return Err(BlindTokenError::WireVersionMismatch {
                expected: WIRE_VERSION_V1,
                found: version,
            });
        }
        let profile = read_u8(wire, &mut cur)?;
        if profile != PROFILE_ID_V1 {
            return Err(BlindTokenError::WireProfileMismatch {
                expected: PROFILE_ID_V1,
                found: profile,
            });
        }
        let w_polys = read_framed(wire, &mut cur)?;
        if w_polys.len() != 1 {
            return Err(BlindTokenError::Encoding);
        }
        let z = read_framed(wire, &mut cur)?;
        if z.len() != WITNESS_LEN {
            return Err(BlindTokenError::Encoding);
        }
        if cur != wire.len() {
            return Err(BlindTokenError::WireTruncated);
        }
        Ok(TokenProof {
            w_commit: w_polys.into_iter().next().unwrap(),
            z,
        })
    }

    fn append_framed(out: &mut Vec<u8>, polys: &[Rq]) -> Result<(), BlindTokenError> {
        let body = write_rq_vec(polys);
        let len = u32::try_from(body.len()).map_err(|_| BlindTokenError::LengthOverflow)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&body);
        Ok(())
    }

    fn read_framed(wire: &[u8], cur: &mut usize) -> Result<Vec<Rq>, BlindTokenError> {
        let len = usize::try_from(read_u32_le(wire, cur)?)
            .map_err(|_| BlindTokenError::LengthOverflow)?;
        let body = read_bytes(wire, cur, len)?;
        read_rq_vec(body)
    }

    /// Encode a vector of ring elements: each coefficient (in `[0, q)`) as `COEFF_BYTES` LE bytes.
    fn write_rq_vec(polys: &[Rq]) -> Vec<u8> {
        let mut out = Vec::with_capacity(polys.len() * ELT_BYTES);
        for p in polys {
            for &c in &p.coeffs {
                let v = c as u64; // c ∈ [0, q)
                out.extend_from_slice(&v.to_le_bytes()[..COEFF_BYTES]);
            }
        }
        out
    }

    /// Decode a `write_rq_vec` body: length must be a whole number of ring elements; each
    /// coefficient must be a canonical residue in `[0, q)`.
    fn read_rq_vec(body: &[u8]) -> Result<Vec<Rq>, BlindTokenError> {
        if !body.len().is_multiple_of(ELT_BYTES) {
            return Err(BlindTokenError::Encoding);
        }
        let count = body.len() / ELT_BYTES;
        let mut polys = Vec::with_capacity(count);
        let mut idx = 0usize;
        for _ in 0..count {
            let mut coeffs = [0i64; N];
            for c in &mut coeffs {
                let mut buf = [0u8; 8];
                buf[..COEFF_BYTES].copy_from_slice(&body[idx..idx + COEFF_BYTES]);
                let v = u64::from_le_bytes(buf);
                if v >= Q as u64 {
                    return Err(BlindTokenError::Encoding);
                }
                *c = v as i64;
                idx += COEFF_BYTES;
            }
            polys.push(Rq::from_coeffs(coeffs));
        }
        Ok(polys)
    }

    fn read_u8(wire: &[u8], cur: &mut usize) -> Result<u8, BlindTokenError> {
        let b = wire
            .get(*cur)
            .copied()
            .ok_or(BlindTokenError::WireTruncated)?;
        *cur += 1;
        Ok(b)
    }

    fn read_u32_le(wire: &[u8], cur: &mut usize) -> Result<u32, BlindTokenError> {
        let b = read_bytes(wire, cur, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_bytes<'a>(
        wire: &'a [u8],
        cur: &mut usize,
        len: usize,
    ) -> Result<&'a [u8], BlindTokenError> {
        let end = cur.saturating_add(len);
        if end > wire.len() {
            return Err(BlindTokenError::WireTruncated);
        }
        let out = &wire[*cur..end];
        *cur = end;
        Ok(out)
    }
}
