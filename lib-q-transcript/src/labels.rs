//! Domain-separation labels for the lib-Q Fiat-Shamir transcript.
//!
//! Two kinds of label appear in the transcript:
//!
//! - **Instantiation labels** ([`K12_TRANSCRIPT_V0`], [`POSEIDON_TRANSCRIPT_V0`]) — the leading
//!   message prefix that seeds a fresh transcript's chaining value and separates this construction
//!   from every other lib-Q K12/Poseidon use. Per the lib-Q KangarooTwelve discipline these are
//!   absorbed as a **leading message prefix under empty customization**, never as the cSHAKE
//!   customization string.
//! - **Operation labels** — caller-supplied `&[u8]` tags passed to
//!   [`crate::DuplexTranscript::absorb`] / [`crate::DuplexTranscript::challenge`] that name *what* is
//!   being absorbed or which challenge is being drawn (e.g. `b"commitment"`, `b"beta"`). A small set
//!   of common ones is provided below for cross-proof consistency; callers may use their own.
//!
//! **RED:** these strings are part of the (as-yet-unsigned) transcript encoding. Changing one
//! changes every derived challenge. Do not alter a `*_V0` constant; mint a `*_V1` instead.

/// Instantiation label for the out-of-circuit K12 transcript (leading message prefix).
pub const K12_TRANSCRIPT_V0: &[u8] = b"libq.transcript.k12.v0";

/// Instantiation label for the in-circuit Poseidon-256 transcript (`hash_suite_id = 5`).
pub const POSEIDON_TRANSCRIPT_V0: &[u8] = b"libq.transcript.poseidon256.v0";

/// Suggested operation label: a public statement / instance being bound into the transcript.
pub const STATEMENT: &[u8] = b"statement";
/// Suggested operation label: a prover commitment / first message.
pub const COMMITMENT: &[u8] = b"commitment";
/// Suggested operation label: a public input.
pub const PUBLIC_INPUT: &[u8] = b"public-input";
/// Suggested operation label: a Fiat-Shamir verifier challenge / random coin.
pub const CHALLENGE: &[u8] = b"challenge";
