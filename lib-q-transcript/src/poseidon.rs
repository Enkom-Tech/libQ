//! In-circuit Fiat-Shamir transcript over the Poseidon-256 sponge (`hash_suite_id = 5`).
//!
//! [`PoseidonTranscript`] realises the [`DuplexTranscript`] discipline with `Unit = PoseidonField`
//! (`Complex<Mersenne31>` = GF(p²)). It uses the **same** Poseidon-256 permutation (state width 7,
//! rate 2, capacity 5) the membership / mVE AIRs constrain, so it is the value-level reference an
//! in-circuit transcript can re-derive: the construction is a Poseidon hash *chain* over a
//! length-prefixed, domain-separated encoding — exactly the shape an AIR enforces.
//!
//! Byte-valued items (the protocol/operation labels, the domain tags, lengths) are encoded
//! injectively as one field element per byte; field-valued payloads are absorbed directly.

use alloc::vec::Vec;

use lib_q_poseidon::{
    Poseidon256,
    PoseidonField,
    PoseidonSponge,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;

use crate::labels::POSEIDON_TRANSCRIPT_V0;
use crate::{
    DOMAIN_ABSORB,
    DOMAIN_CHAIN,
    DOMAIN_SQUEEZE,
    DuplexTranscript,
};

/// Width of the chaining value in field elements (the Poseidon-256 capacity).
pub const CHAINING_ELEMS: usize = 5;

/// A Fiat-Shamir transcript over Poseidon-256 (see the module docs).
#[derive(Clone, Debug)]
pub struct PoseidonTranscript {
    /// Running chaining value (5 field elements) summarising everything absorbed so far.
    cv: [PoseidonField; CHAINING_ELEMS],
}

/// One field element per byte (`0..=255`, well within Mersenne31) — injective on byte strings.
fn byte_to_felt(b: u8) -> PoseidonField {
    Complex::new_real(Mersenne31::new(u32::from(b)))
}

/// A small non-negative count as one field element (`count < 2³¹`).
fn count_to_felt(n: usize) -> PoseidonField {
    debug_assert!(
        n < (1usize << 31),
        "transcript length must fit in Mersenne31"
    );
    Complex::new_real(Mersenne31::new(n as u32))
}

/// Append a length-prefixed byte string to a field stream: `len ‖ byte-per-element`.
fn push_lp_bytes(stream: &mut Vec<PoseidonField>, bytes: &[u8]) {
    stream.push(count_to_felt(bytes.len()));
    stream.extend(bytes.iter().copied().map(byte_to_felt));
}

/// Append a length-prefixed field-element string: `len ‖ elements`.
fn push_lp_felts(stream: &mut Vec<PoseidonField>, felts: &[PoseidonField]) {
    stream.push(count_to_felt(felts.len()));
    stream.extend_from_slice(felts);
}

/// Truncated Poseidon-256 sponge hash: rate-2 absorb of `stream` (10*1 padding), then squeeze
/// `out_len` field elements. Same construction `hash_suite_id = 5` uses on the wire-digest path.
fn poseidon_hash(stream: &[PoseidonField], out_len: usize) -> Vec<PoseidonField> {
    let mut sponge = PoseidonSponge::new(Poseidon256::params());
    sponge.absorb(stream);
    sponge.finish_absorbing().squeeze(out_len)
}

/// Hash a stream to a fresh chaining value (the first 5 squeezed elements).
fn hash_to_cv(stream: &[PoseidonField]) -> [PoseidonField; CHAINING_ELEMS] {
    let out = poseidon_hash(stream, CHAINING_ELEMS);
    core::array::from_fn(|i| out[i])
}

impl PoseidonTranscript {
    /// Create a fresh transcript bound to a protocol-specific `domain` separator.
    #[must_use]
    pub fn new(domain: &[u8]) -> Self {
        let mut stream = Vec::new();
        stream.extend(POSEIDON_TRANSCRIPT_V0.iter().copied().map(byte_to_felt));
        stream.push(byte_to_felt(0)); // init seed tag, distinct from absorb/squeeze/chain
        push_lp_bytes(&mut stream, domain);
        Self {
            cv: hash_to_cv(&stream),
        }
    }

    /// Begin a hash stream prefixed by the instantiation label, a domain tag, and the current `cv`.
    fn begin(&self, domain_tag: u8) -> Vec<PoseidonField> {
        let mut stream = Vec::new();
        stream.extend(POSEIDON_TRANSCRIPT_V0.iter().copied().map(byte_to_felt));
        stream.push(byte_to_felt(domain_tag));
        stream.extend_from_slice(&self.cv);
        stream
    }

    /// Absorb a byte string under `label` (convenience: encodes bytes as one field element each).
    pub fn absorb_bytes(&mut self, label: &[u8], message: &[u8]) {
        let mut stream = self.begin(DOMAIN_ABSORB);
        push_lp_bytes(&mut stream, label);
        // Encode as a length-prefixed field string so byte and field absorbs share one decoder.
        stream.push(count_to_felt(message.len()));
        stream.extend(message.iter().copied().map(byte_to_felt));
        self.cv = hash_to_cv(&stream);
    }
}

impl DuplexTranscript for PoseidonTranscript {
    type Unit = PoseidonField;

    fn absorb(&mut self, label: &[u8], message: &[PoseidonField]) {
        // cv ← H(ABSORB ‖ cv ‖ lp(label) ‖ lp(message)).
        let mut stream = self.begin(DOMAIN_ABSORB);
        push_lp_bytes(&mut stream, label);
        push_lp_felts(&mut stream, message);
        self.cv = hash_to_cv(&stream);
    }

    fn challenge(&mut self, label: &[u8], count: usize) -> Vec<PoseidonField> {
        // Output: H(SQUEEZE ‖ cv ‖ lp(label) ‖ count) truncated to `count` elements.
        let mut squeeze_stream = self.begin(DOMAIN_SQUEEZE);
        push_lp_bytes(&mut squeeze_stream, label);
        squeeze_stream.push(count_to_felt(count));
        let out = poseidon_hash(&squeeze_stream, count);

        // Chain: cv ← H(CHAIN ‖ cv ‖ lp(label) ‖ count). Distinct tag ⇒ independent of `out`.
        let mut chain_stream = self.begin(DOMAIN_CHAIN);
        push_lp_bytes(&mut chain_stream, label);
        chain_stream.push(count_to_felt(count));
        self.cv = hash_to_cv(&chain_stream);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_to_felt_is_injective_over_all_byte_values() {
        // Every byte 0..=255 must map to a distinct field element; a collision here would silently
        // break injectivity of every byte-encoded label/message in the transcript.
        let mut seen = alloc::vec::Vec::with_capacity(256);
        for b in 0u8..=255 {
            seen.push(byte_to_felt(b));
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(seen[i], seen[j], "byte_to_felt collided for {i} and {j}");
            }
        }
    }

    #[test]
    fn push_lp_bytes_encodes_length_then_bytes() {
        let mut stream = Vec::new();
        push_lp_bytes(&mut stream, b"ab");
        assert_eq!(stream.len(), 3);
        assert_eq!(stream[0], count_to_felt(2));
        assert_eq!(stream[1], byte_to_felt(b'a'));
        assert_eq!(stream[2], byte_to_felt(b'b'));
    }

    #[test]
    fn push_lp_bytes_boundary_is_injective() {
        // Same property `absorb_lp` gives the K12 side, checked directly against the field-stream
        // encoder rather than through the full `PoseidonTranscript::absorb` chaining.
        let mut a = Vec::new();
        push_lp_bytes(&mut a, b"x");
        push_lp_bytes(&mut a, b"ab");

        let mut b = Vec::new();
        push_lp_bytes(&mut b, b"xa");
        push_lp_bytes(&mut b, b"b");

        assert_ne!(a, b);
    }

    #[test]
    fn push_lp_felts_encodes_length_then_elements() {
        let elems = [byte_to_felt(1), byte_to_felt(2), byte_to_felt(3)];
        let mut stream = Vec::new();
        push_lp_felts(&mut stream, &elems);
        assert_eq!(stream.len(), 4);
        assert_eq!(stream[0], count_to_felt(3));
        assert_eq!(&stream[1..], &elems);
    }

    #[test]
    fn begin_domain_tags_distinguish_absorb_squeeze_chain() {
        // `begin` is private and is the single place ABSORB/SQUEEZE/CHAIN domain separation is
        // injected into the field stream before label/payload data is appended. Integration tests
        // only ever observe the final challenge output; this checks the raw pre-hash stream itself.
        let t = PoseidonTranscript::new(b"proto");
        let a = t.begin(DOMAIN_ABSORB);
        let s = t.begin(DOMAIN_SQUEEZE);
        let c = t.begin(DOMAIN_CHAIN);
        assert_ne!(a, s);
        assert_ne!(s, c);
        assert_ne!(a, c);
        // Same cv, same tag => identical stream (deterministic).
        assert_eq!(t.begin(DOMAIN_ABSORB), a);
    }

    #[test]
    fn hash_to_cv_changes_with_the_input_stream() {
        let s1 = [byte_to_felt(1), byte_to_felt(2)];
        let s2 = [byte_to_felt(1), byte_to_felt(3)];
        assert_ne!(hash_to_cv(&s1), hash_to_cv(&s2));
        assert_eq!(hash_to_cv(&s1), hash_to_cv(&s1), "must be deterministic");
    }

    #[test]
    fn same_message_different_absorb_label_diverges() {
        // The property the task calls out explicitly: same payload, different label, must not
        // collide. Integration tests already cover order-of-absorbs and message-content changes
        // (`poseidon_message_matters`) but not a single absorb whose label alone differs.
        let msg = [byte_to_felt(7), byte_to_felt(8)];
        let mut a = PoseidonTranscript::new(b"p");
        a.absorb(b"label-a", &msg);
        let mut b = PoseidonTranscript::new(b"p");
        b.absorb(b"label-b", &msg);
        assert_ne!(a.challenge(b"c", 4), b.challenge(b"c", 4));
    }
}
