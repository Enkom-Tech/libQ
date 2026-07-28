//! Versioned codec for the redeemable token value (a ZK proof of possession).
//!
//! Layout (length-prefixed, budget-gated, **provisional** until the wire freeze):
//! `[ver][profile] framed(w_commit) framed(z)` where `w_commit` is one ring element and `z` is the
//! `WITNESS_LEN` response ring elements. Std-gated: the token type lives in the std-only scheme.

/// Wire version byte.
pub const WIRE_VERSION_V1: u8 = 1;

/// Byte budget for an encoded token value. The secure instance (`N = 1024`, `q ≈ 2^51`, 7 bytes
/// per coefficient) yields a proof of `(1 + WITNESS_LEN)·N·7 ≈ 497 KB`; the budget leaves headroom.
pub const WIRE_BUDGET_BLIND_TOKEN_BYTES: usize = 524_288;

#[cfg(feature = "std")]
pub use imp::{
    decode_issue_request,
    decode_issue_response,
    decode_token_value,
    encode_issue_request,
    encode_issue_response,
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
        IssueRequest,
        IssueResponse,
        TokenProof,
        WITNESS_LEN,
    };
    use crate::lattice::trapdoor::PREIMAGE_LEN;
    use crate::profile::PROFILE_ID_V1;

    /// Bytes per coefficient (`q < 2^56` ⇒ 7 bytes suffice; the `q ≈ 2^51` instance needs 7).
    const COEFF_BYTES: usize = 7;
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

    /// Serialize an [`IssueRequest`] (client → issuer): `[ver][profile] framed(a_tok)`. The hidden
    /// attribute is a single ring element. Issuance is interactive but **not** blind — unlinkability
    /// comes from redemption — so this carries a fresh random attribute, never an identity.
    pub fn encode_issue_request(req: &IssueRequest) -> Result<Vec<u8>, BlindTokenError> {
        let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1];
        append_framed(&mut out, core::slice::from_ref(&req.a_tok))?;
        Ok(out)
    }

    /// Parse an [`IssueRequest`].
    pub fn decode_issue_request(wire: &[u8]) -> Result<IssueRequest, BlindTokenError> {
        let mut cur = 0usize;
        read_header(wire, &mut cur)?;
        let polys = read_framed(wire, &mut cur)?;
        if polys.len() != 1 {
            return Err(BlindTokenError::Encoding);
        }
        if cur != wire.len() {
            return Err(BlindTokenError::WireTruncated);
        }
        Ok(IssueRequest {
            a_tok: polys.into_iter().next().unwrap(),
        })
    }

    /// Serialize an [`IssueResponse`] (issuer → client): `[ver][profile] framed(x)` where `x` is the
    /// GPV preimage (`PREIMAGE_LEN` ring elements).
    pub fn encode_issue_response(resp: &IssueResponse) -> Result<Vec<u8>, BlindTokenError> {
        let mut out = alloc::vec![WIRE_VERSION_V1, PROFILE_ID_V1];
        append_framed(&mut out, &resp.x)?;
        if out.len() > WIRE_BUDGET_BLIND_TOKEN_BYTES {
            return Err(BlindTokenError::BudgetExceeded {
                actual: out.len(),
                budget: WIRE_BUDGET_BLIND_TOKEN_BYTES,
            });
        }
        Ok(out)
    }

    /// Parse an [`IssueResponse`]; the preimage must be exactly `PREIMAGE_LEN` ring elements.
    pub fn decode_issue_response(wire: &[u8]) -> Result<IssueResponse, BlindTokenError> {
        if wire.len() > WIRE_BUDGET_BLIND_TOKEN_BYTES {
            return Err(BlindTokenError::BudgetExceeded {
                actual: wire.len(),
                budget: WIRE_BUDGET_BLIND_TOKEN_BYTES,
            });
        }
        let mut cur = 0usize;
        read_header(wire, &mut cur)?;
        let x = read_framed(wire, &mut cur)?;
        if x.len() != PREIMAGE_LEN {
            return Err(BlindTokenError::Encoding);
        }
        if cur != wire.len() {
            return Err(BlindTokenError::WireTruncated);
        }
        Ok(IssueResponse { x })
    }

    /// Read and validate the `[ver][profile]` header shared by every message.
    fn read_header(wire: &[u8], cur: &mut usize) -> Result<(), BlindTokenError> {
        let version = read_u8(wire, cur)?;
        if version != WIRE_VERSION_V1 {
            return Err(BlindTokenError::WireVersionMismatch {
                expected: WIRE_VERSION_V1,
                found: version,
            });
        }
        let profile = read_u8(wire, cur)?;
        if profile != PROFILE_ID_V1 {
            return Err(BlindTokenError::WireProfileMismatch {
                expected: PROFILE_ID_V1,
                found: profile,
            });
        }
        Ok(())
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

#[cfg(all(test, feature = "std"))]
mod issuance_wire_tests {
    use lib_q_random::new_deterministic_rng;

    use super::{
        decode_issue_request,
        decode_issue_response,
        encode_issue_request,
        encode_issue_response,
    };
    use crate::{
        blind,
        blind_sign,
        keygen_issuer,
    };

    #[test]
    fn issue_request_and_response_round_trip() {
        let mut rng = new_deterministic_rng([0x9Au8; 32]);
        let (public, secret) = keygen_issuer(&mut rng, 3, 5);

        let (req, _state) = blind(&mut rng, &public);
        let req_bytes = encode_issue_request(&req).unwrap();
        let req2 = decode_issue_request(&req_bytes).unwrap();
        // Canonical: re-encoding the decoded message is byte-identical.
        assert_eq!(encode_issue_request(&req2).unwrap(), req_bytes);

        let resp = blind_sign(&mut rng, &secret, &req2);
        let resp_bytes = encode_issue_response(&resp).unwrap();
        let resp2 = decode_issue_response(&resp_bytes).unwrap();
        assert_eq!(encode_issue_response(&resp2).unwrap(), resp_bytes);
    }

    #[test]
    fn issue_wire_rejects_truncation_and_bad_header() {
        let mut rng = new_deterministic_rng([0x9Bu8; 32]);
        let (public, _secret) = keygen_issuer(&mut rng, 1, 1);
        let (req, _state) = blind(&mut rng, &public);
        let bytes = encode_issue_request(&req).unwrap();

        assert!(decode_issue_request(&bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        bad[0] ^= 0xFF; // corrupt version
        assert!(decode_issue_request(&bad).is_err());
    }
}
