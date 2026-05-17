//! Anonymous rate-limit token layout and spending transcript binding.
//!
//! A token is an Ajtai commitment plus a Fiat–Shamir opening proof. The
//! [`AnonymousToken`] header carries serial, origin tag, and epoch for
//! application-layer replay suppression (per-origin tables).

extern crate alloc;

use alloc::vec::Vec;

use lib_q_ring::Poly;
use zeroize::Zeroizing;

use crate::commitment::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
};
use crate::error::VerifyError;
use crate::serialize::append_module_vec;
use crate::sigma::opening::{
    OpeningProof,
    verify_opening,
};

/// Fixed layout: first message polynomial carries serial, origin tag, and epoch LE.
pub const TOKEN_SERIAL_LEN: usize = 32;
pub const TOKEN_ORIGIN_LEN: usize = 16;
pub const TOKEN_EPOCH_LEN: usize = 8;

/// Build an [`AjtaiOpening`] whose first message polynomial embeds serial, origin, and epoch.
pub fn opening_from_token_fields(
    module_rank: usize,
    randomness_dimension: usize,
    serial: &[u8; TOKEN_SERIAL_LEN],
    origin: &[u8; TOKEN_ORIGIN_LEN],
    epoch_le: &[u8; TOKEN_EPOCH_LEN],
) -> Option<AjtaiOpening> {
    if module_rank < 1 {
        return None;
    }
    let mut msg0 = Poly::zero();
    let mut idx = 0usize;
    for b in serial.iter() {
        if idx >= 256 {
            return None;
        }
        msg0.coeffs[idx] = i32::from(*b);
        idx += 1;
    }
    for b in origin.iter() {
        if idx >= 256 {
            return None;
        }
        msg0.coeffs[idx] = i32::from(*b);
        idx += 1;
    }
    for b in epoch_le.iter() {
        if idx >= 256 {
            return None;
        }
        msg0.coeffs[idx] = i32::from(*b);
        idx += 1;
    }
    let mut message = Vec::with_capacity(module_rank);
    message.push(msg0);
    for _ in 1..module_rank {
        message.push(Poly::zero());
    }
    let mut randomness = Vec::with_capacity(randomness_dimension);
    for _ in 0..randomness_dimension {
        randomness.push(Poly::zero());
    }
    Some(AjtaiOpening {
        message: lib_q_ring::ModuleVec(message),
        randomness: lib_q_ring::ModuleVec(randomness),
    })
}

/// Spending proof: opening proof plus explicit serial for replay tracking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendingProof {
    pub serial: [u8; TOKEN_SERIAL_LEN],
    pub opening_proof: OpeningProof,
}

impl SpendingProof {
    /// Verify opening against a commitment and check serial matches token header.
    pub fn verify(
        &self,
        key: &AjtaiCommitmentKey,
        com: &AjtaiCommitment,
        ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
        expected_serial: &[u8; TOKEN_SERIAL_LEN],
    ) -> Result<(), VerifyError> {
        if self.serial != *expected_serial {
            return Err(VerifyError::Rejected);
        }
        verify_opening(key, com, &self.opening_proof, ctx, tau, z_inf_bound)
    }
}

/// Serializable anonymous token: commitment + opening proof + public header fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnonymousToken {
    pub commitment: AjtaiCommitment,
    pub serial: [u8; TOKEN_SERIAL_LEN],
    pub origin: [u8; TOKEN_ORIGIN_LEN],
    pub epoch_le: [u8; TOKEN_EPOCH_LEN],
    pub opening_proof: OpeningProof,
}

impl AnonymousToken {
    /// Encode for wire or hash registries.
    ///
    /// The buffer includes opening-proof polynomials (`w`, `z`); the returned
    /// [`Zeroizing`] wrapper zeroizes the `Vec` on drop so transient wire copies
    /// do not retain those bytes in allocator-visible memory longer than needed.
    /// Module-vector fields are appended in-place (no intermediate `write_module_vec`
    /// allocations) so serialized opening data is not duplicated on the heap while
    /// building the wire encoding.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::new();
        append_module_vec(&mut v, &self.commitment.value.0);
        v.extend_from_slice(&self.serial);
        v.extend_from_slice(&self.origin);
        v.extend_from_slice(&self.epoch_le);
        append_module_vec(&mut v, &self.opening_proof.w.0);
        append_module_vec(&mut v, &self.opening_proof.z.0);
        Zeroizing::new(v)
    }

    /// Verify Fiat–Shamir opening proof for the stored commitment.
    pub fn verify_opening_only(
        &self,
        key: &AjtaiCommitmentKey,
        ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        verify_opening(
            key,
            &self.commitment,
            &self.opening_proof,
            ctx,
            tau,
            z_inf_bound,
        )
    }

    /// Build a spending proof payload for verifier-side replay checks.
    #[must_use]
    pub fn spend(&self) -> SpendingProof {
        SpendingProof {
            serial: self.serial,
            opening_proof: self.opening_proof.clone(),
        }
    }
}

#[cfg(test)]
mod to_bytes_tests {
    use alloc::vec;

    use lib_q_ring::{
        ModuleVec,
        Poly,
    };

    use super::*;
    use crate::serialize::write_module_vec;

    #[test]
    fn anonymous_token_to_bytes_zeroizing_roundtrip_slice() {
        let p = Poly::zero();
        let com = AjtaiCommitment {
            value: ModuleVec(vec![p.clone()]),
        };
        let proof = OpeningProof {
            w: ModuleVec(vec![p.clone()]),
            z: ModuleVec(vec![p]),
        };
        let token = AnonymousToken {
            commitment: com,
            serial: [1u8; TOKEN_SERIAL_LEN],
            origin: [2u8; TOKEN_ORIGIN_LEN],
            epoch_le: [3u8; TOKEN_EPOCH_LEN],
            opening_proof: proof,
        };
        let wire = token.to_bytes();
        assert_eq!(wire.len(), wire.as_slice().len());
        let slice: &[u8] = wire.as_ref();
        assert!(!slice.is_empty());

        let mut expected = Vec::new();
        expected.extend_from_slice(&write_module_vec(&token.commitment.value.0));
        expected.extend_from_slice(&token.serial);
        expected.extend_from_slice(&token.origin);
        expected.extend_from_slice(&token.epoch_le);
        expected.extend_from_slice(&write_module_vec(&token.opening_proof.w.0));
        expected.extend_from_slice(&write_module_vec(&token.opening_proof.z.0));
        assert_eq!(slice, expected.as_slice());
    }
}
