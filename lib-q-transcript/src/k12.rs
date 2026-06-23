//! Out-of-circuit Fiat-Shamir transcript over the KangarooTwelve XOF.
//!
//! [`K12Transcript`] realises the [`DuplexTranscript`] discipline with `Unit = u8`. It is the layer
//! that prover/verifier code uses to derive challenges on the wire. Every hash is a `Kt128` with an
//! **empty customization string** and the instantiation label ([`labels::K12_TRANSCRIPT_V0`]) as a
//! **leading message prefix** — the lib-Q KangarooTwelve domain-separation discipline.

use alloc::vec;
use alloc::vec::Vec;

use lib_q_k12::Kt128;
use lib_q_k12::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::labels::K12_TRANSCRIPT_V0;
use crate::{
    DOMAIN_ABSORB,
    DOMAIN_CHAIN,
    DOMAIN_SQUEEZE,
    DuplexTranscript,
};

/// Width of the chaining value in bytes (256-bit: matches the K12 collision target).
pub const CHAINING_BYTES: usize = 32;

/// A Fiat-Shamir transcript over KangarooTwelve (see the module docs).
#[derive(Clone)]
pub struct K12Transcript {
    /// Running chaining value summarising everything absorbed so far.
    cv: [u8; CHAINING_BYTES],
}

impl core::fmt::Debug for K12Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Do not print the chaining value (it is transcript-secret until a challenge is squeezed).
        f.debug_struct("K12Transcript").finish_non_exhaustive()
    }
}

/// Start a `Kt128` with the lib-Q discipline: empty customization, instantiation label as the
/// leading message prefix, then the one-byte domain tag.
fn start(domain_tag: u8) -> Kt128<'static> {
    let mut h = Kt128::default(); // empty customization
    h.update(K12_TRANSCRIPT_V0); // leading message prefix (NOT the cSHAKE customization arg)
    h.update(&[domain_tag]);
    h
}

/// Absorb a length-prefixed byte string (`u64` big-endian length ‖ bytes) — injective encoding.
fn absorb_lp(h: &mut Kt128<'static>, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

impl K12Transcript {
    /// Create a fresh transcript bound to a protocol-specific `domain` separator. Two transcripts
    /// with different `domain`s produce independent challenge streams from identical absorbs.
    #[must_use]
    pub fn new(domain: &[u8]) -> Self {
        let mut h = Kt128::default();
        h.update(K12_TRANSCRIPT_V0);
        h.update(b"\x00init"); // seed tag, distinct from the absorb/squeeze/chain tags
        absorb_lp(&mut h, domain);
        let mut cv = [0u8; CHAINING_BYTES];
        h.finalize_xof().read(&mut cv);
        Self { cv }
    }

    /// Squeeze exactly `out.len()` challenge bytes into `out` (bound to everything absorbed and to
    /// `label`), advancing the chaining value. Avoids the [`DuplexTranscript::challenge`] allocation
    /// for fixed-size draws.
    pub fn challenge_bytes(&mut self, label: &[u8], out: &mut [u8]) {
        // Output: H(SQUEEZE ‖ cv ‖ lp(label) ‖ count).
        let mut h = start(DOMAIN_SQUEEZE);
        h.update(&self.cv);
        absorb_lp(&mut h, label);
        h.update(&(out.len() as u64).to_be_bytes());
        h.finalize_xof().read(out);

        // Chain: cv ← H(CHAIN ‖ cv ‖ lp(label) ‖ count). Separate domain tag ⇒ independent of `out`.
        let mut hc = start(DOMAIN_CHAIN);
        hc.update(&self.cv);
        absorb_lp(&mut hc, label);
        hc.update(&(out.len() as u64).to_be_bytes());
        let mut next = [0u8; CHAINING_BYTES];
        hc.finalize_xof().read(&mut next);
        self.cv = next;
    }

    /// Squeeze a fixed-size challenge array.
    #[must_use]
    pub fn challenge_array<const N: usize>(&mut self, label: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        self.challenge_bytes(label, &mut out);
        out
    }

    /// Squeeze a `u64` challenge (big-endian over 8 squeezed bytes).
    #[must_use]
    pub fn challenge_u64(&mut self, label: &[u8]) -> u64 {
        u64::from_be_bytes(self.challenge_array::<8>(label))
    }
}

impl DuplexTranscript for K12Transcript {
    type Unit = u8;

    fn absorb(&mut self, label: &[u8], message: &[u8]) {
        // cv ← H(ABSORB ‖ cv ‖ lp(label) ‖ lp(message)).
        let mut h = start(DOMAIN_ABSORB);
        h.update(&self.cv);
        absorb_lp(&mut h, label);
        absorb_lp(&mut h, message);
        let mut next = [0u8; CHAINING_BYTES];
        h.finalize_xof().read(&mut next);
        self.cv = next;
    }

    fn challenge(&mut self, label: &[u8], count: usize) -> Vec<u8> {
        let mut out = vec![0u8; count];
        self.challenge_bytes(label, &mut out);
        out
    }
}
