//! Authenticated encapsulator — the **deployable** ("closure B") mitigation for the
//! malformed-ciphertext insider probe described in `THRESHOLD_SECURITY.md` §4–§5 and
//! `SECURITY-STATUS.md` §3 item 1.
//!
//! # The problem this closes
//!
//! A `t-1`-corrupt coalition that can hand a *hand-crafted* (not honestly XOF-derived) ciphertext to
//! `partial_decap*` learns the top bits of an honest party's share after ≈63 malformed queries
//! (`THRESHOLD_SECURITY.md` §4.1). FO⊥ rejects the bad output, but only at [`crate::combine`] — after
//! the partials have already been broadcast. Closing this **before** any partial is computed requires
//! the receiving party to reject a ciphertext it cannot attribute to an honest encapsulator, which
//! needs a way to check "did an entity who holds material only an authorized encapsulator holds
//! produce this exact ciphertext" — an authentication decision, not a well-formedness one (a bounded
//! norm alone does not suffice; the spike `f = δ·unit_k` passes any norm filter, `THRESHOLD_SECURITY.md`
//! §4.2).
//!
//! # Construction (this module's own — see the note below)
//!
//! `THRESHOLD_SECURITY.md` §5/§6 specifies closure B only at the level of a *deployment contract*
//! ("a signature over `ct` + a PKI layer"); it explicitly does not pin a scheme, "so as not to dictate
//! the deployment's PKI". This module instantiates the **simplest sound member of that family that
//! needs no new asymmetric-signature dependency**: a symmetric pre-shared authenticator key, shared
//! out-of-band between the encapsulator and every party authorized to compute partial decapsulations
//! (e.g. distributed alongside the DKG's `ZeroShareSeeds`, or over the same authenticated channel the
//! deployment already needs to distribute those). The authenticator is
//!
//! ```text
//! tag = SHAKE256(dom ‖ auth_key ‖ pk.t0_bytes ‖ ct.to_bytes())   (32 bytes)
//! ```
//!
//! i.e. a SHAKE-256 keyed hash (KMAC-style: the key is the *first* absorbed block, before any
//! attacker-influenced input) over the wire-frozen ciphertext bytes, bound to the specific public key
//! so a tag valid under one DKG key never verifies under another (rotation safety — §3 item 2 of
//! `SECURITY-STATUS.md`).
//!
//! **Explicit security assumption**: this is *symmetric-key, shared-secret* authentication — anyone
//! holding `auth_key` can both mint valid ciphertexts AND verify them, which means:
//! - It authenticates "holds `auth_key`", not necessarily a single named encapsulator identity. A
//!   deployment wanting per-identity accountability needs an asymmetric signature scheme instead
//!   (the PKI layer `THRESHOLD_SECURITY.md` §6 declines to embed) — that is a **stronger** and
//!   differently-shaped closure than this module provides.
//! - It requires `auth_key` to be established over a channel the malformed-ciphertext adversary (a
//!   `t-1`-corrupt *decapsulation* coalition) cannot read. A coalition that also compromises
//!   `auth_key` distribution regains the malformed-ct oracle — the boundary this module closes is
//!   "outsider forges a ciphertext", not "the decap coalition also breaks the encapsulator's own
//!   secrets".
//! - This is **NOT presented as the only or the specified construction** — the design docs leave the
//!   scheme to the deployment, and a deployment that already has a PKI (e.g. issues each authorized
//!   encapsulator an ML-DSA identity) should sign `ct` with it instead and adapt
//!   [`verify_authenticator`]'s check accordingly. This module exists so the enforcement hook
//!   (`THRESHOLD_SECURITY.md` §6: "the caller MUST gate `partial_decap*` on an authenticated-origin
//!   decision") has at least one concrete, sound, dependency-light instantiation shipped in-crate.
//!
//! # What this does NOT close
//!
//! See `SECURITY-STATUS.md` (updated alongside this module). In short: this is closure B, one half of
//! the argued-not-proven §7 conditional statement, and it does not by itself turn the crate's overall
//! RED status GREEN. Closure A (assumption-free ZK PoK of `μ`) remains the only closure that needs no
//! deployment trust assumption.
//!
//! # Wire compatibility
//!
//! Purely additive: [`AuthenticatedCiphertext`] is a **new** type with its **own** serialization
//! (`ct.to_bytes() ‖ tag`, both already-canonical), layered on top of the unmodified,
//! byte-for-byte-unchanged [`Ciphertext::to_bytes`]/`from_bytes`. No existing struct, wire format, or
//! public function signature is touched.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::{
    Choice,
    ConstantTimeEq,
};
use zeroize::Zeroizing;

use crate::error::ThresholdKemError;
use crate::kem::Ciphertext;
use crate::{
    ThresholdKemLatticePublicKey,
    encapsulate,
};

const DOM_AUTH_TAG: &[u8] = b"lib-q-threshold-kem-lattice/auth-encap-tag/v1";

/// Length in bytes of the authenticator tag.
pub const AUTH_TAG_BYTES: usize = 32;

/// A symmetric authenticator key shared out-of-band between an authorized encapsulator and every
/// party permitted to compute partial decapsulations. See the module docs for the exact
/// construction and its assumption. Zeroized on drop.
#[derive(Clone)]
pub struct AuthKey(pub Zeroizing<[u8; 32]>);

impl AuthKey {
    /// Wrap raw key bytes established by the deployment's own channel.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Sample a fresh random authenticator key (for setting up a new deployment / rotation).
    #[must_use]
    pub fn generate<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }
}

/// A [`Ciphertext`] carrying an authenticator tag proving the sender held [`AuthKey`] at encryption
/// time. Additive wire type: `ct.to_bytes() ‖ tag`, unrelated to and not embedded in
/// [`Ciphertext`]'s own (unchanged) wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCiphertext {
    /// The underlying, unmodified ciphertext.
    pub ct: Ciphertext,
    /// `SHAKE256(dom ‖ auth_key ‖ pk.t0_bytes ‖ ct.to_bytes())`, truncated to
    /// [`AUTH_TAG_BYTES`] bytes.
    pub tag: [u8; AUTH_TAG_BYTES],
}

impl AuthenticatedCiphertext {
    /// Serialized length: [`Ciphertext::BYTES`] `+` [`AUTH_TAG_BYTES`].
    pub const BYTES: usize = Ciphertext::BYTES + AUTH_TAG_BYTES;

    /// Canonical serialization: the (unchanged) ciphertext wire bytes followed by the tag.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.ct.to_bytes());
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parse from exactly [`AuthenticatedCiphertext::BYTES`] bytes. This only checks structure
    /// (delegates the ciphertext body to [`Ciphertext::from_bytes`], which enforces canonical
    /// coefficients and the wire-version byte); it does **not** verify the authenticator — call
    /// [`verify_authenticator`] separately with the relevant `pk`/`auth_key`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdKemError> {
        if bytes.len() != Self::BYTES {
            return Err(ThresholdKemError::EncodingCiphertext);
        }
        let ct = Ciphertext::from_bytes(&bytes[..Ciphertext::BYTES])?;
        let mut tag = [0u8; AUTH_TAG_BYTES];
        tag.copy_from_slice(&bytes[Ciphertext::BYTES..]);
        Ok(Self { ct, tag })
    }
}

/// Compute the authenticator tag for `(pk, ct)` under `auth_key`. Internal — both
/// [`authenticated_encapsulate`] and [`verify_authenticator`] must derive the identical value from
/// identical inputs, so this is the single point that defines the tag.
fn compute_tag(auth_key: &AuthKey, pk: &ThresholdKemLatticePublicKey, ct: &Ciphertext) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(DOM_AUTH_TAG);
    h.update(&*auth_key.0);
    h.update(&pk.t0_bytes);
    h.update(&ct.to_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// Encapsulate to `pk` and attach an authenticator tag proving possession of `auth_key`. Wraps the
/// existing, unmodified [`encapsulate`] — the shared secret and the inner [`Ciphertext`] are
/// bit-identical to the un-authenticated path; only the extra tag is new.
///
/// # Errors
///
/// Propagates [`encapsulate`]'s errors (a malformed `pk`).
pub fn authenticated_encapsulate<R: CryptoRng + Rng>(
    pk: &ThresholdKemLatticePublicKey,
    auth_key: &AuthKey,
    rng: &mut R,
) -> Result<([u8; 32], AuthenticatedCiphertext), ThresholdKemError> {
    let (ss, ct) = encapsulate(pk, rng)?;
    let tag = compute_tag(auth_key, pk, &ct);
    Ok((ss, AuthenticatedCiphertext { ct, tag }))
}

/// Check whether `act.tag` is the correct authenticator for `(pk, act.ct)` under `auth_key`.
///
/// Constant-time: the comparison folds every byte of the 32-byte tag via [`subtle::ConstantTimeEq`]
/// (no early exit, no branch on tag content) — this runs on attacker-supplied wire input
/// (`act.tag`), so it must not leak *where* a forged tag first diverges through timing. Returns a
/// [`subtle::Choice`] rather than `bool` so a caller who wants to fold the decision into a larger
/// constant-time predicate can do so without forcing a branch here.
#[must_use]
pub fn verify_authenticator(
    pk: &ThresholdKemLatticePublicKey,
    auth_key: &AuthKey,
    act: &AuthenticatedCiphertext,
) -> Choice {
    let expected = compute_tag(auth_key, pk, &act.ct);
    expected.ct_eq(&act.tag)
}
