//! Wire codec for MAUL-v1 double encapsulation payload.

use crate::error::DoubleKemError;
use crate::profile::{
    MAUL_HINT_BYTES,
    MAUL_WIRE_BODY_BYTES,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
};

/// Fixed-size wire representation: `hint || body`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaulEncapWire {
    /// Compression hint bytes.
    pub hint: [u8; MAUL_HINT_BYTES],
    /// Ciphertext body bytes.
    pub body: [u8; MAUL_WIRE_BODY_BYTES],
}

impl MaulEncapWire {
    /// Construct from split fields.
    #[must_use]
    pub const fn from_parts(hint: [u8; MAUL_HINT_BYTES], body: [u8; MAUL_WIRE_BODY_BYTES]) -> Self {
        Self { hint, body }
    }

    /// Serialize to `hint || body` exact wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; WIRE_BUDGET_MAUL_ENCAP_BYTES] {
        let mut out = [0u8; WIRE_BUDGET_MAUL_ENCAP_BYTES];
        out[..MAUL_HINT_BYTES].copy_from_slice(&self.hint);
        out[MAUL_HINT_BYTES..].copy_from_slice(&self.body);
        out
    }

    /// Parse from exact `hint || body` wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DoubleKemError> {
        if bytes.len() != WIRE_BUDGET_MAUL_ENCAP_BYTES {
            return Err(DoubleKemError::InvalidWireLength {
                expected: WIRE_BUDGET_MAUL_ENCAP_BYTES,
                actual: bytes.len(),
            });
        }
        let mut hint = [0u8; MAUL_HINT_BYTES];
        let mut body = [0u8; MAUL_WIRE_BODY_BYTES];
        hint.copy_from_slice(&bytes[..MAUL_HINT_BYTES]);
        body.copy_from_slice(&bytes[MAUL_HINT_BYTES..]);
        Ok(Self { hint, body })
    }
}
