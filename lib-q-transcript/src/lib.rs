//! `lib-q-transcript` — one shared Fiat-Shamir transcript discipline for lib-Q zero-knowledge proofs.
//!
//! This crate provides a single, hash-agnostic **duplex transcript** (CFRG sigma-protocol /
//! Fiat-Shamir style, cf. `draft-irtf-cfrg-fiat-shamir` / `draft-irtf-cfrg-sigma-protocols` and the
//! `spongefish` reference implementation): a running state into which a prover/verifier *absorbs*
//! labelled messages and from which it *squeezes* labelled challenges, so the whole interaction is
//! bound into every challenge. The point is **one** audited Fiat-Shamir layer shared by future
//! proving code instead of a bespoke transform per proof system.
//!
//! Two interoperable instantiations of the same [`DuplexTranscript`] discipline are provided:
//!
//! - [`k12::K12Transcript`] (`Unit = u8`) — **outside the circuit**, over the KangarooTwelve XOF
//!   (`lib-q-k12`). This is the layer prover/verifier code uses to derive challenges on the wire.
//! - [`poseidon::PoseidonTranscript`] (`Unit = PoseidonField`) — the **in-circuit** instantiation
//!   over the Poseidon-256 sponge (`hash_suite_id = 5`, the same permutation the membership / mVE
//!   AIRs constrain). Field-native, so it is the value-level reference an AIR can re-derive.
//!
//! ## Construction (chaining-value duplex)
//!
//! Both instantiations realise the duplex with the same construction. A fixed-width **chaining
//! value** `cv` summarises everything absorbed so far. Each operation is an injective,
//! length-prefixed, domain-separated hash of `(domain-tag ‖ cv ‖ label ‖ payload)`:
//!
//! ```text
//! absorb(label, msg):  cv  ← H(ABSORB  ‖ cv ‖ lp(label) ‖ lp(msg))
//! challenge(label, n):  out ← H(SQUEEZE ‖ cv ‖ lp(label) ‖ lp(n))[..n]
//!                       cv  ← H(CHAIN   ‖ cv ‖ lp(label) ‖ lp(n))      // bind the squeeze into cv
//! ```
//!
//! `lp(x)` is a length-prefixed encoding (injective), and `H` is the instantiation hash
//! (KangarooTwelve XOF, or the truncated Poseidon-256 sponge). The Keccak/Poseidon sponges have
//! non-zero capacity, so the construction is not length-extendable, and the distinct domain tags
//! keep absorb / squeeze / chain images disjoint.
//!
//! ## K12 label discipline
//!
//! The K12 instantiation follows the lib-Q KangarooTwelve domain-separation discipline used by the
//! frozen commitments (`lib-q-mve`, membership): the protocol label is a **leading message prefix**
//! under an **empty** customization string (`Kt128::default()` then `update(label)`), *not* the
//! cSHAKE customization argument. See [`labels`].
//!
//! ## RED — PENDING HUMAN CRYPTOGRAPHER SIGN-OFF
//!
//! This is a **new** foundational layer. The construction above (chaining-value duplex over a XOF /
//! truncated sponge) and the exact [`labels`] domain-separation strings are engineering drafts and
//! have **not** been signed off by a human cryptographer. Until they are, treat this crate as RED:
//! suitable for new proof code that wants the shared discipline, **not** a certified Fiat-Shamir
//! transform.
//!
//! It is deliberately **not** retrofitted into the already-frozen `lib-q-mve` / membership wire
//! formats (those predate this crate and ship their own challenger/commitment transcripts). Adopting
//! this layer there would change proof bytes and require a wire-version bump plus a fresh freeze /
//! sign-off, which is out of scope here.
//!
//! ## Feature flags & `no_std`
//!
//! The crate is `#![no_std]`. Features:
//! - `alloc` — enables the heap (`Vec`); required by both transcripts.
//! - `std` (default) — implies `alloc`.
//! - `poseidon` (default) — the in-circuit [`PoseidonTranscript`]. Optional only to keep the
//!   K12-only dependency surface small; it does **not** require `std`.
//!
//! Both transcripts build on a bare-metal `no_std` target (e.g. `thumbv7em-none-eabi`):
//! `--no-default-features --features alloc` for K12 only, or `--features alloc,poseidon` for both.
//! The full crate also builds for `wasm32-unknown-unknown`. (Actual RNG/entropy is never pulled in
//! here — challenges are derived deterministically from the hash; randomness lives in `lib-q-random`.)

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub mod k12;
pub mod labels;
#[cfg(feature = "poseidon")]
pub mod poseidon;

pub use k12::K12Transcript;
#[cfg(feature = "poseidon")]
pub use poseidon::PoseidonTranscript;

/// Domain-separation tag prefixing every `absorb` hash (keeps absorb images disjoint from squeeze /
/// chain). One byte; part of the frozen-once-signed encoding.
pub const DOMAIN_ABSORB: u8 = 0x01;
/// Domain-separation tag prefixing every challenge-output hash.
pub const DOMAIN_SQUEEZE: u8 = 0x02;
/// Domain-separation tag prefixing every chaining-value-update hash (binds a squeeze into `cv`).
pub const DOMAIN_CHAIN: u8 = 0x03;

/// A hash-agnostic Fiat-Shamir duplex transcript: absorb labelled messages, squeeze labelled
/// challenges, with the full interaction bound into every challenge.
///
/// Implementations differ only in the unit they speak ([`u8`] outside the circuit, a field element
/// in-circuit) and the underlying hash; the absorb/squeeze/chain discipline is identical (see the
/// crate docs). All operations are deterministic in the absorbed sequence, so a verifier that
/// replays the same labelled absorbs derives the same challenges as the prover.
pub trait DuplexTranscript {
    /// The unit this transcript absorbs and squeezes (`u8` for K12, a field element for Poseidon).
    type Unit: Clone;

    /// Absorb `message` under `label`. `label` domain-separates this absorb from others; both
    /// `label` and `message` are length-prefixed, so the absorbed sequence is encoded injectively.
    fn absorb(&mut self, label: &[u8], message: &[Self::Unit]);

    /// Squeeze `count` challenge units bound to everything absorbed so far and to `label`, then fold
    /// the squeeze back into the chaining value so subsequent operations depend on it.
    fn challenge(&mut self, label: &[u8], count: usize) -> Vec<Self::Unit>;
}
