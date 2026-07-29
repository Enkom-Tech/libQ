//! # WITHDRAWN — this crate is not a signature scheme and provides no security.
//!
//! `lib-q-threshold-sig` shipped a construction that does not authenticate anything. This is
//! not a standardization caveat, a parameter-selection concern, or a "pre-standard" hedge: the
//! scheme is unsound at the design level and cannot be repaired by adjusting constants, domain
//! separators, or the verification equation. **The entire signing and verification surface has
//! been removed and every entry point now fails closed.**
//!
//! ## What was wrong
//!
//! Three independent defects, each individually fatal, were confirmed against the public API:
//!
//! 1. **The published verifier set was the secret.** Key generation copied each party's raw
//!    byte-wise Shamir share directly into that party's *published* `verifying_key`. Public and
//!    private material were byte-identical for every party.
//! 2. **The group key was the master secret.** The "public" group key was produced by Lagrange
//!    interpolation of those published verifying keys at zero — that is precisely the Shamir
//!    master secret. Any threshold-sized subset of purely public data reconstructed it,
//!    including subsets wholly disjoint from the ones the dealer used.
//! 3. **Verification was a public computation.** The accept/reject relation was a fixed
//!    combination of the aggregated nonce, a hash of public values, and the group key. It
//!    contained no secret input and no one-way step, so it could be satisfied directly rather
//!    than by signing.
//!
//! The underlying reason is structural. The construction's only arithmetic was bytewise `XOR`
//! and multiplication in `GF(2^8)`. Both are efficiently invertible, and a 256-element field
//! admits exhaustive search regardless. **There is no hard problem anywhere in the
//! construction, therefore no one-way map from the secret to the published key and no trapdoor
//! to recover.** Hashing the shares, re-deriving the challenge, or rewriting the equation does
//! not create one. A sound scheme requires an actual hardness assumption, which means a
//! different construction — not a patch to this one.
//!
//! ## What this means for anything that used it
//!
//! * Any `ThresholdSigPublicKey` that was ever published, transmitted, logged, or persisted
//!   must be treated as **full disclosure of the signing key and of every party's share**.
//!   Rotate whatever it protected; the exposure is not undone by revocation alone.
//! * Any protocol that relied on this crate for authentication, authorization, admission
//!   control, or attestation obtained **no cryptographic assurance whatsoever** from it, and
//!   any decision it made on that basis should be re-evaluated as unauthenticated.
//! * Signatures and key material previously produced by this crate cannot be validated
//!   retroactively. There is no "verify old signatures" mode, because the original verifier
//!   accepted forgeries as readily as genuine signatures — the two are indistinguishable.
//!
//! ## Current status: fails closed, unconditionally
//!
//! [`keygen_shares`], [`sign_round1`], [`sign_round2`], [`aggregate`], [`verify`],
//! [`identify_abort`] and [`proactive_refresh`] return [`ThresholdSigError::SchemeWithdrawn`]
//! on every call. The broken arithmetic that backed them has been deleted from the source, so
//! **no feature flag, build configuration, or downstream crate can re-enable it** — there is no
//! longer any code path that computes a share, a partial, or a signature. In particular
//! [`verify`] cannot return `Ok(true)`; it cannot return `Ok` at all.
//!
//! The same applies to the WASM bindings (`wasm` feature), which fail closed on every export.
//! The previous JavaScript surface serialized every party's secret share to the host as
//! `verifyingKeyHex`.
//!
//! ## What deliberately still works
//!
//! The wire codecs — [`encode_threshold_sig_wire_v1`], [`decode_threshold_sig_wire_v1`],
//! [`encode_signature`] and [`decode_signature`] — remain live on the Rust side. They are pure
//! length-and-framing serialization that carry **no security claim of any kind**. They are kept
//! so that operators can still parse and decommission legacy stored blobs, and so the byte
//! parser stays covered by the existing fuzz harnesses. Decoding a blob asserts nothing about
//! its authenticity, and nothing decoded can subsequently be verified.
//!
//! ## Replacement
//!
//! There is no drop-in replacement for this crate's API, because that API was shaped around a
//! construction that never worked. Callers needing threshold signing should select a scheme
//! with a stated hardness assumption and a published security analysis. Within this workspace,
//! `lib-q-threshold-raccoon` documents itself as the successor to this crate; evaluate it on
//! its own merits before adopting it.

#![forbid(unsafe_code)]

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod error;
pub mod profile;
pub mod threshold_sig;
pub mod wire;

use core::fmt;

use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const PROFILE_ID_V1: u8 = 1;
pub const PROFILE_MAX_PARTIES_V1: u8 = 64;
pub const WIRE_VERSION_V1: u8 = 1;
pub const WIRE_BUDGET_THRESHOLD_SIG_BYTES: usize = 11_264;
pub const PROFILE_ENVELOPE_BUDGET_BYTES: usize = 8_192;

const SCALAR_BYTES: usize = 32;

/// Inert profile metadata. Retained only as a parameter to the wire codecs; it confers no
/// capability and gates nothing, because there is no longer a scheme to parameterize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdSigProfileV1 {
    pub id: u8,
    pub max_parties: u8,
}

impl Default for ThresholdSigProfileV1 {
    fn default() -> Self {
        Self {
            id: PROFILE_ID_V1,
            max_parties: PROFILE_MAX_PARTIES_V1,
        }
    }
}

/// Historical per-party "verifier". **Misnamed: `verifying_key` was secret material.**
///
/// This type is retained so that legacy persisted structures remain describable. The crate can
/// no longer produce a value of this type, and no value of this type can be used to verify
/// anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareVerifier {
    pub index: u8,
    /// **Secret material, historically published.** Was byte-identical to that party's
    /// [`SecretShare::share_bytes`]. Any recorded value must be treated as disclosed.
    pub verifying_key: [u8; SCALAR_BYTES],
    pub commitment: [u8; 32],
}

/// Historical "public key". **Misnamed: this value was the private key.**
///
/// `group_key` was the Shamir master secret and each `share_verifiers[i].verifying_key` was
/// that party's raw secret share. Any recorded value must be treated as full disclosure of the
/// signing key. The crate can no longer produce a value of this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSigPublicKey {
    pub profile_id: u8,
    pub threshold: u8,
    /// **Secret material, historically published.** Was the Shamir master secret.
    pub group_key: [u8; SCALAR_BYTES],
    /// **Secret material, historically published.** One raw Shamir share per party.
    pub share_verifiers: Vec<ShareVerifier>,
}

#[derive(Clone, Debug)]
pub struct SecretShare {
    pub index: u8,
    pub threshold: u8,
    pub share_bytes: Zeroizing<Vec<u8>>,
}

impl PartialEq for SecretShare {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index &&
            self.threshold == other.threshold &&
            self.share_bytes.as_slice() == other.share_bytes.as_slice()
    }
}

impl Eq for SecretShare {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeygenSharesOutput {
    pub public_key: ThresholdSigPublicKey,
    pub secret_shares: Vec<SecretShare>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Round1Commitment {
    pub index: u8,
    pub nonce_commitment: [u8; SCALAR_BYTES],
    pub binding: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Round1State {
    pub commitment: Round1Commitment,
    pub nonce: Zeroizing<[u8; SCALAR_BYTES]>,
}

impl PartialEq for Round1State {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && bool::from(self.nonce[..].ct_eq(&other.nonce[..]))
    }
}

impl Eq for Round1State {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Round2Partial {
    pub index: u8,
    pub z: [u8; SCALAR_BYTES],
    pub proof: [u8; 32],
}

/// Historical signature container. Decoding bytes into this type asserts nothing: there is no
/// verifier that can accept or reject it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSignature {
    pub r_agg: [u8; SCALAR_BYTES],
    pub z: [u8; SCALAR_BYTES],
    pub signers: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSigWireV1 {
    pub signature: Vec<u8>,
    pub meta: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateOutput {
    pub signature: ThresholdSignature,
    pub signature_bytes: Vec<u8>,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThresholdSigError {
    /// The scheme has been withdrawn as cryptographically unsound and removed.
    ///
    /// Returned unconditionally by every key-generation, signing and verification entry point.
    /// This variant is never accompanied by a successful result: no build configuration causes
    /// those functions to return `Ok`, and in particular [`verify`] can never yield `Ok(true)`.
    SchemeWithdrawn,
    InvalidProfile,
    BudgetExceeded {
        actual: usize,
        budget: usize,
    },
    WireTruncated,
    WireVersionMismatch {
        expected: u8,
        found: u8,
    },
    WireProfileMismatch {
        expected: u8,
        found: u8,
    },
    LengthOverflow,
}

impl fmt::Display for ThresholdSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemeWithdrawn => write!(
                f,
                "lib-q-threshold-sig is WITHDRAWN as cryptographically unsound: its published \
                 key material was the private key and its verification relation contained no \
                 secret, so it authenticated nothing. The signing and verification surface has \
                 been removed and cannot be re-enabled. Any key or signature it previously \
                 produced must be treated as compromised.",
            ),
            Self::InvalidProfile => write!(f, "invalid threshold signature profile"),
            Self::BudgetExceeded { actual, budget } => {
                write!(f, "wire payload exceeds budget: {actual} > {budget}")
            }
            Self::WireTruncated => write!(f, "wire payload truncated"),
            Self::WireVersionMismatch { expected, found } => {
                write!(
                    f,
                    "wire version mismatch: expected {expected}, found {found}"
                )
            }
            Self::WireProfileMismatch { expected, found } => {
                write!(
                    f,
                    "wire profile mismatch: expected {expected}, found {found}"
                )
            }
            Self::LengthOverflow => write!(f, "length conversion overflow"),
        }
    }
}

impl std::error::Error for ThresholdSigError {}

/// Return inert profile metadata.
///
/// Retained because the wire codecs take a profile argument. It performs no cryptographic work
/// and grants no capability.
#[must_use]
pub fn setup() -> ThresholdSigProfileV1 {
    ThresholdSigProfileV1::default()
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// The original implementation published every party's raw secret share as that party's
/// "verifying key" and exposed the master secret as the "group key". It has been removed; this
/// function has no implementation and cannot generate key material.
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn keygen_shares<R: CryptoRng + Rng>(
    _profile: &ThresholdSigProfileV1,
    _threshold: u8,
    _share_count: u8,
    _rng: &mut R,
) -> Result<KeygenSharesOutput, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn sign_round1<R: CryptoRng + Rng>(
    _profile: &ThresholdSigProfileV1,
    _secret_share: &SecretShare,
    _message: &[u8],
    _rng: &mut R,
) -> Result<Round1State, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn sign_round2(
    _profile: &ThresholdSigProfileV1,
    _public_key: &ThresholdSigPublicKey,
    _message: &[u8],
    _secret_share: &SecretShare,
    _round1_state: &Round1State,
    _commitments: &[Round1Commitment],
) -> Result<Round2Partial, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn aggregate(
    _profile: &ThresholdSigProfileV1,
    _public_key: &ThresholdSigPublicKey,
    _message: &[u8],
    _commitments: &[Round1Commitment],
    _partials: &[Round2Partial],
) -> Result<AggregateOutput, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// This function never returns `Ok`, so it can never report a signature as valid. Callers that
/// treated a boolean result as an authorization decision were never protected by it.
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn verify(
    _profile: &ThresholdSigProfileV1,
    _public_key: &ThresholdSigPublicKey,
    _message: &[u8],
    _signature: &ThresholdSignature,
) -> Result<bool, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn identify_abort(
    _profile: &ThresholdSigProfileV1,
    _public_key: &ThresholdSigPublicKey,
    _message: &[u8],
    _commitments: &[Round1Commitment],
    _partials: &[Round2Partial],
) -> Result<Vec<u8>, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// **WITHDRAWN — always fails.** Returns [`ThresholdSigError::SchemeWithdrawn`].
///
/// Refreshing shares of a secret that was already published alongside them would accomplish
/// nothing in any case.
///
/// # Errors
///
/// Always returns [`ThresholdSigError::SchemeWithdrawn`].
#[deprecated(
    note = "lib-q-threshold-sig is WITHDRAWN: it is not a signature scheme and provides no \
            security. This function has no implementation and always returns \
            ThresholdSigError::SchemeWithdrawn. See the crate documentation."
)]
pub fn proactive_refresh<R: CryptoRng + Rng>(
    _profile: &ThresholdSigProfileV1,
    _shares: &[SecretShare],
    _rng: &mut R,
) -> Result<Vec<SecretShare>, ThresholdSigError> {
    Err(ThresholdSigError::SchemeWithdrawn)
}

/// Frame a signature blob and its metadata into `threshold_sig_wire_v1`.
///
/// Pure serialization with **no security claim**: this performs length and budget framing only
/// and does not inspect, produce, or attest to the contents. See the crate documentation.
///
/// # Errors
///
/// Returns [`ThresholdSigError::InvalidProfile`] for a non-v1 profile,
/// [`ThresholdSigError::LengthOverflow`] if a length exceeds `u16`, or
/// [`ThresholdSigError::BudgetExceeded`] if the frame exceeds its byte budget.
pub fn encode_threshold_sig_wire_v1(
    profile: &ThresholdSigProfileV1,
    signature: &[u8],
    meta: &[u8],
) -> Result<Vec<u8>, ThresholdSigError> {
    validate_profile(profile)?;
    let sig_len = u16::try_from(signature.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let meta_len = u16::try_from(meta.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let total_len = 1usize + 1 + 2 + signature.len() + 2 + meta.len();
    if total_len > WIRE_BUDGET_THRESHOLD_SIG_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: total_len,
            budget: WIRE_BUDGET_THRESHOLD_SIG_BYTES,
        });
    }
    if profile.id == PROFILE_ID_V1 && total_len > PROFILE_ENVELOPE_BUDGET_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: total_len,
            budget: PROFILE_ENVELOPE_BUDGET_BYTES,
        });
    }

    let mut out = Vec::with_capacity(total_len);
    out.push(WIRE_VERSION_V1);
    out.push(profile.id);
    out.extend_from_slice(&sig_len.to_le_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(&meta_len.to_le_bytes());
    out.extend_from_slice(meta);
    Ok(out)
}

/// Parse a `threshold_sig_wire_v1` frame.
///
/// Pure deserialization with **no security claim**: a successful decode means the bytes were
/// well-formed, and nothing more. It is not an authenticity check, and nothing decoded here can
/// subsequently be verified. See the crate documentation.
///
/// # Errors
///
/// Returns [`ThresholdSigError::InvalidProfile`], [`ThresholdSigError::BudgetExceeded`],
/// [`ThresholdSigError::WireVersionMismatch`], [`ThresholdSigError::WireProfileMismatch`], or
/// [`ThresholdSigError::WireTruncated`] for malformed input.
pub fn decode_threshold_sig_wire_v1(
    profile: &ThresholdSigProfileV1,
    wire: &[u8],
) -> Result<ThresholdSigWireV1, ThresholdSigError> {
    validate_profile(profile)?;
    if wire.len() > WIRE_BUDGET_THRESHOLD_SIG_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: wire.len(),
            budget: WIRE_BUDGET_THRESHOLD_SIG_BYTES,
        });
    }
    if profile.id == PROFILE_ID_V1 && wire.len() > PROFILE_ENVELOPE_BUDGET_BYTES {
        return Err(ThresholdSigError::BudgetExceeded {
            actual: wire.len(),
            budget: PROFILE_ENVELOPE_BUDGET_BYTES,
        });
    }
    let mut cursor = 0usize;
    let version = read_u8(wire, &mut cursor)?;
    if version != WIRE_VERSION_V1 {
        return Err(ThresholdSigError::WireVersionMismatch {
            expected: WIRE_VERSION_V1,
            found: version,
        });
    }
    let profile_id = read_u8(wire, &mut cursor)?;
    if profile_id != profile.id {
        return Err(ThresholdSigError::WireProfileMismatch {
            expected: profile.id,
            found: profile_id,
        });
    }
    let sig_len = usize::from(read_u16_le(wire, &mut cursor)?);
    let signature = read_bytes(wire, &mut cursor, sig_len)?.to_vec();
    let meta_len = usize::from(read_u16_le(wire, &mut cursor)?);
    let meta = read_bytes(wire, &mut cursor, meta_len)?.to_vec();
    if cursor != wire.len() {
        return Err(ThresholdSigError::WireTruncated);
    }
    Ok(ThresholdSigWireV1 { signature, meta })
}

/// Serialize a [`ThresholdSignature`] container. **No security claim** — see the crate docs.
///
/// # Errors
///
/// Returns [`ThresholdSigError::LengthOverflow`] if the signer count exceeds `u8`.
pub fn encode_signature(sig: &ThresholdSignature) -> Result<Vec<u8>, ThresholdSigError> {
    let signer_len =
        u8::try_from(sig.signers.len()).map_err(|_| ThresholdSigError::LengthOverflow)?;
    let mut out = Vec::with_capacity(32 + 32 + 1 + usize::from(signer_len));
    out.extend_from_slice(&sig.r_agg);
    out.extend_from_slice(&sig.z);
    out.push(signer_len);
    out.extend_from_slice(sig.signers.as_slice());
    Ok(out)
}

/// Parse a [`ThresholdSignature`] container.
///
/// **No security claim.** A successful decode means the bytes were well-formed. It does not
/// mean the signature is genuine, and no verifier exists that could establish that.
///
/// # Errors
///
/// Returns [`ThresholdSigError::WireTruncated`] for malformed or trailing input.
pub fn decode_signature(data: &[u8]) -> Result<ThresholdSignature, ThresholdSigError> {
    if data.len() < 65 {
        return Err(ThresholdSigError::WireTruncated);
    }
    let mut cursor = 0usize;
    let mut r_agg = [0u8; SCALAR_BYTES];
    r_agg.copy_from_slice(read_bytes(data, &mut cursor, SCALAR_BYTES)?);
    let mut z = [0u8; SCALAR_BYTES];
    z.copy_from_slice(read_bytes(data, &mut cursor, SCALAR_BYTES)?);
    let signer_len = usize::from(read_u8(data, &mut cursor)?);
    let signers = read_bytes(data, &mut cursor, signer_len)?.to_vec();
    if cursor != data.len() {
        return Err(ThresholdSigError::WireTruncated);
    }
    Ok(ThresholdSignature { r_agg, z, signers })
}

fn validate_profile(profile: &ThresholdSigProfileV1) -> Result<(), ThresholdSigError> {
    if profile.id != PROFILE_ID_V1 || profile.max_parties != PROFILE_MAX_PARTIES_V1 {
        return Err(ThresholdSigError::InvalidProfile);
    }
    Ok(())
}

fn read_u8(wire: &[u8], cursor: &mut usize) -> Result<u8, ThresholdSigError> {
    let b = wire
        .get(*cursor)
        .copied()
        .ok_or(ThresholdSigError::WireTruncated)?;
    *cursor += 1;
    Ok(b)
}

fn read_u16_le(wire: &[u8], cursor: &mut usize) -> Result<u16, ThresholdSigError> {
    let bytes = read_bytes(wire, cursor, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_bytes<'a>(
    wire: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], ThresholdSigError> {
    let end = cursor.saturating_add(len);
    if end > wire.len() {
        return Err(ThresholdSigError::WireTruncated);
    }
    let out = &wire[*cursor..end];
    *cursor = end;
    Ok(out)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    fn any_rng() -> lib_q_random::LibQRng {
        lib_q_random::LibQRng::new_deterministic([0x5A; 32])
    }

    /// A caller cannot obtain key material: the generator refuses for every parameter choice.
    #[test]
    fn keygen_refuses() {
        let profile = setup();
        let mut rng = any_rng();
        for (threshold, count) in [(1u8, 1u8), (2, 3), (3, 5), (0, 0), (64, 64)] {
            let out = keygen_shares(&profile, threshold, count, &mut rng);
            assert_eq!(
                out.err(),
                Some(ThresholdSigError::SchemeWithdrawn),
                "keygen_shares({threshold},{count}) must refuse",
            );
        }
    }

    /// Every signing-path entry point refuses regardless of input.
    #[test]
    fn signing_path_refuses() {
        let profile = setup();
        let mut rng = any_rng();
        let share = SecretShare {
            index: 1,
            threshold: 3,
            share_bytes: Zeroizing::new(vec![0u8; SCALAR_BYTES]),
        };
        let pk = ThresholdSigPublicKey {
            profile_id: PROFILE_ID_V1,
            threshold: 3,
            group_key: [0u8; SCALAR_BYTES],
            share_verifiers: Vec::new(),
        };
        let commitment = Round1Commitment {
            index: 1,
            nonce_commitment: [0u8; SCALAR_BYTES],
            binding: [0u8; 32],
        };
        let state = Round1State {
            commitment: commitment.clone(),
            nonce: Zeroizing::new([0u8; SCALAR_BYTES]),
        };
        let partial = Round2Partial {
            index: 1,
            z: [0u8; SCALAR_BYTES],
            proof: [0u8; 32],
        };

        assert_eq!(
            sign_round1(&profile, &share, b"m", &mut rng).err(),
            Some(ThresholdSigError::SchemeWithdrawn),
        );
        let commitments = std::slice::from_ref(&commitment);
        let partials = std::slice::from_ref(&partial);
        assert_eq!(
            sign_round2(&profile, &pk, b"m", &share, &state, commitments).err(),
            Some(ThresholdSigError::SchemeWithdrawn),
        );
        assert_eq!(
            aggregate(&profile, &pk, b"m", commitments, partials).err(),
            Some(ThresholdSigError::SchemeWithdrawn),
        );
        assert_eq!(
            identify_abort(&profile, &pk, b"m", commitments, partials).err(),
            Some(ThresholdSigError::SchemeWithdrawn),
        );
        assert_eq!(
            proactive_refresh(&profile, &[share], &mut rng).err(),
            Some(ThresholdSigError::SchemeWithdrawn),
        );
    }

    /// The historical "published key is the private key" defect cannot recur through the API:
    /// no call produces a `ThresholdSigPublicKey` or a `SecretShare` at all.
    #[test]
    fn no_api_path_emits_key_material() {
        let profile = setup();
        let mut rng = any_rng();
        assert!(
            keygen_shares(&profile, 3, 5, &mut rng).is_err(),
            "no entry point may hand out a group key or share verifier set",
        );
    }

    /// Wire framing still round-trips; it is serialization only and asserts nothing.
    #[test]
    fn wire_codec_roundtrips_without_asserting_validity() {
        let profile = setup();
        let sig = vec![7u8; 96];
        let meta = vec![9u8; 128];
        let wire = encode_threshold_sig_wire_v1(&profile, &sig, &meta).expect("encode");
        let decoded = decode_threshold_sig_wire_v1(&profile, &wire).expect("decode");
        assert_eq!(decoded.signature, sig);
        assert_eq!(decoded.meta, meta);
    }

    #[test]
    fn oversize_reject_and_envelope_positive() {
        let profile = setup();
        let meta = vec![0u8; PROFILE_ENVELOPE_BUDGET_BYTES];
        let sig = vec![0u8; 80];
        assert!(
            encode_threshold_sig_wire_v1(&profile, &sig, &meta).is_err(),
            "expected budget rejection",
        );

        let small_meta = vec![0u8; 128];
        let small_sig = vec![0u8; 96];
        let wire2 = encode_threshold_sig_wire_v1(&profile, &small_sig, &small_meta)
            .expect("small envelope should pass");
        assert!(wire2.len() <= PROFILE_ENVELOPE_BUDGET_BYTES);
    }

    /// A decoded signature container is inert: it exists, and there is no way to have it
    /// accepted.
    #[test]
    fn decoded_signature_cannot_be_verified() {
        let sig = ThresholdSignature {
            r_agg: [1u8; SCALAR_BYTES],
            z: [2u8; SCALAR_BYTES],
            signers: vec![1, 2, 3],
        };
        let bytes = encode_signature(&sig).expect("encode");
        let back = decode_signature(&bytes).expect("decode");
        assert_eq!(back, sig);

        let profile = setup();
        let pk = ThresholdSigPublicKey {
            profile_id: PROFILE_ID_V1,
            threshold: 3,
            group_key: [0u8; SCALAR_BYTES],
            share_verifiers: Vec::new(),
        };
        assert_eq!(
            verify(&profile, &pk, b"m", &back).err(),
            Some(ThresholdSigError::SchemeWithdrawn),
            "a decoded container must not be verifiable",
        );
    }

    #[test]
    fn withdrawn_error_message_is_explicit() {
        let msg = ThresholdSigError::SchemeWithdrawn.to_string();
        assert!(msg.contains("WITHDRAWN"), "{msg}");
        assert!(msg.contains("compromised"), "{msg}");
    }
}
