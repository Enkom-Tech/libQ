//! Fuzz target: the withdrawn `identify_abort` refusal contract, plus the retained signature
//! parser.
//!
//! This target previously generated real key material with `keygen_shares` and fuzzed
//! `identify_abort` against it. Both of those depend on the construction that has been removed:
//! `keygen_shares` now refuses, so the old body would bail out on its first statement and fuzz
//! nothing at all — a harness that reports success while exercising no code.
//!
//! It now does two useful things instead. First it asserts the refusal contract holds for
//! arbitrary attacker-shaped input: `identify_abort` must never return `Ok` no matter what it is
//! handed. Second it fuzzes `decode_signature`, one of the retained pure-serialization codecs,
//! which is a real byte parser and the only remaining place untrusted input reaches parsing
//! logic.

#![no_main]

use lib_q_threshold_sig::{
    Round1Commitment,
    Round2Partial,
    ThresholdSigError,
    ThresholdSigPublicKey,
    decode_signature,
    identify_abort,
    setup,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let profile = setup();

    // The retained parser: arbitrary bytes must never panic it.
    let _ = decode_signature(data);

    // The refusal contract: no input may coax `identify_abort` into returning `Ok`.
    let mut commitments = Vec::<Round1Commitment>::new();
    let mut partials = Vec::<Round2Partial>::new();

    let chunk = 1 + 32 + 32 + 32;
    let mut cursor = 0usize;
    while cursor + chunk <= data.len() && commitments.len() < 5 {
        let index = (data[cursor] % 5) + 1;
        cursor += 1;

        let mut nonce_commitment = [0u8; 32];
        nonce_commitment.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        let mut binding = [0u8; 32];
        binding.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        let mut z = [0u8; 32];
        z.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        commitments.push(Round1Commitment {
            index,
            nonce_commitment,
            binding,
        });
        partials.push(Round2Partial {
            index,
            z,
            proof: [0u8; 32],
        });
    }

    let public_key = ThresholdSigPublicKey {
        profile_id: 1,
        threshold: 3,
        group_key: [0u8; 32],
        share_verifiers: Vec::new(),
    };

    #[allow(deprecated)]
    let outcome: Result<Vec<u8>, ThresholdSigError> = identify_abort(
        &profile,
        &public_key,
        b"fuzz-identify-abort",
        commitments.as_slice(),
        partials.as_slice(),
    );
    assert!(
        matches!(outcome, Err(ThresholdSigError::SchemeWithdrawn)),
        "identify_abort must refuse every input",
    );
});
