//! Shared fixtures for the withdrawn-scheme tests.
//!
//! This module previously drove a real 3-of-5 signing ceremony: `deterministic_keygen`,
//! `build_round_states` and `build_partials` produced live key material, round-1 states and
//! round-2 partials for the other test files to aggregate and verify. Those helpers are gone,
//! because the construction they exercised has been removed from the crate — no ceremony can
//! run at all now. Nothing here calls a signing or verification entry point.
//!
//! What remains builds *inert*, hand-constructed values: structurally well-formed inputs that
//! exist only so each test can hand them to an entry point and prove it refuses them. None of
//! these values is key material — they carry fixed filler bytes, not secrets.

#![allow(dead_code)]

use lib_q_threshold_sig::{
    PROFILE_ID_V1,
    Round1Commitment,
    Round1State,
    Round2Partial,
    SecretShare,
    ShareVerifier,
    ThresholdSigPublicKey,
    ThresholdSignature,
};
use zeroize::Zeroizing;

pub const THRESHOLD: u8 = 3;
pub const PARTIES: u8 = 5;

pub fn deterministic_rng(seed: u8) -> lib_q_random::LibQRng {
    lib_q_random::new_deterministic_rng([seed; 32])
}

/// A structurally plausible public key made of filler bytes. Not key material: the crate can no
/// longer produce key material, so tests construct this by hand purely as an input to refuse.
pub fn inert_public_key() -> ThresholdSigPublicKey {
    ThresholdSigPublicKey {
        profile_id: PROFILE_ID_V1,
        threshold: THRESHOLD,
        group_key: [0xAA; 32],
        share_verifiers: (1..=PARTIES)
            .map(|index| ShareVerifier {
                index,
                verifying_key: [0xBB; 32],
                commitment: [0xCC; 32],
            })
            .collect(),
    }
}

pub fn inert_share(index: u8) -> SecretShare {
    SecretShare {
        index,
        threshold: THRESHOLD,
        share_bytes: Zeroizing::new(vec![0xDD; 32]),
    }
}

pub fn inert_commitment(index: u8) -> Round1Commitment {
    Round1Commitment {
        index,
        nonce_commitment: [0xEE; 32],
        binding: [0xFF; 32],
    }
}

pub fn inert_round1_state(index: u8) -> Round1State {
    Round1State {
        commitment: inert_commitment(index),
        nonce: Zeroizing::new([0x11; 32]),
    }
}

pub fn inert_partial(index: u8) -> Round2Partial {
    Round2Partial {
        index,
        z: [0x22; 32],
        proof: [0x33; 32],
    }
}

pub fn inert_signature() -> ThresholdSignature {
    ThresholdSignature {
        r_agg: [0x44; 32],
        z: [0x55; 32],
        signers: (1..=THRESHOLD).collect(),
    }
}
