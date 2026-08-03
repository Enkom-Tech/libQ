//! Out-of-circuit Fiat-Shamir transcript over the KangarooTwelve XOF.
//!
//! [`K12Transcript`] realises the [`DuplexTranscript`] discipline with `Unit = u8`. It is the layer
//! that prover/verifier code uses to derive challenges on the wire. Every hash is a `Kt128` with an
//! **empty customization string** and the instantiation label ([`labels::K12_TRANSCRIPT_V0`](crate::labels::K12_TRANSCRIPT_V0)) as a
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Finalize `h` into a fixed-size digest without touching the public [`K12Transcript`] API —
    /// lets us test the private `start`/`absorb_lp` helpers directly and in isolation from the
    /// chaining-value bookkeeping that wraps them.
    fn finalize32(h: Kt128<'static>) -> [u8; 32] {
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        out
    }

    #[test]
    fn start_domain_tag_is_injected_and_distinguishes_domains() {
        // `start` is private and only reachable from within this module; it is the one place the
        // ABSORB/SQUEEZE/CHAIN one-byte domain separation is injected before any transcript state
        // is mixed in, so this isolates that mechanism from everything built on top of it.
        let a = finalize32(start(DOMAIN_ABSORB));
        let b = finalize32(start(DOMAIN_SQUEEZE));
        let c = finalize32(start(DOMAIN_CHAIN));
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);

        // Same domain tag, called twice, must be fully deterministic (no hidden entropy/state).
        assert_eq!(finalize32(start(DOMAIN_ABSORB)), a);
    }

    #[test]
    fn absorb_lp_boundary_is_injective() {
        // Directly exercises the length-prefix encoder that makes ("x","ab") and ("xa","b")
        // distinct absorbs; the equivalent property is checked end-to-end via `K12Transcript` in
        // the integration suite (`k12_label_message_boundary_is_injective`), but this isolates the
        // encoder itself from the chaining-value / domain-tag machinery around it.
        let mut ha = start(DOMAIN_ABSORB);
        absorb_lp(&mut ha, b"x");
        absorb_lp(&mut ha, b"ab");

        let mut hb = start(DOMAIN_ABSORB);
        absorb_lp(&mut hb, b"xa");
        absorb_lp(&mut hb, b"b");

        assert_ne!(finalize32(ha), finalize32(hb));
    }

    #[test]
    fn absorb_lp_empty_string_is_not_the_same_as_no_call() {
        // lp("") = length-prefix(0) with no payload bytes; must still perturb the hash relative to
        // not calling absorb_lp at all (otherwise an empty operand would be silently absorbable
        // as "nothing", breaking the "absorbed sequence is encoded injectively" guarantee).
        let mut with_empty = start(DOMAIN_ABSORB);
        absorb_lp(&mut with_empty, b"");

        let without = start(DOMAIN_ABSORB);

        assert_ne!(finalize32(with_empty), finalize32(without));
    }

    #[test]
    fn same_message_different_absorb_label_diverges() {
        // The property the task calls out explicitly: absorbing the SAME bytes under two DIFFERENT
        // labels must not collide. `k12_absorb_order_matters` (integration) covers reordering two
        // absorbs under one shared label; this covers a single absorb whose label alone differs.
        let mut a = K12Transcript::new(b"p");
        a.absorb(b"label-a", b"same-payload");
        let mut b = K12Transcript::new(b"p");
        b.absorb(b"label-b", b"same-payload");
        assert_ne!(a.challenge(b"c", 16), b.challenge(b"c", 16));
    }

    #[test]
    fn new_domain_separates_from_absorb_of_the_same_bytes() {
        // The `domain` argument to `new` and the `label` argument to `absorb` are absorbed through
        // different code paths (`new`'s `\x00init` seed tag vs. `absorb`'s `DOMAIN_ABSORB` tag).
        // Confirm they are not accidentally interchangeable: seeding with a domain equal to what
        // would otherwise be absorbed must not reproduce the same chaining value as an empty-domain
        // transcript that then absorbs that value as a message.
        let mut a = K12Transcript::new(b"shared");
        let mut b = K12Transcript::new(b"");
        b.absorb(b"", b"shared");
        assert_ne!(a.challenge(b"c", 16), b.challenge(b"c", 16));
    }
}
