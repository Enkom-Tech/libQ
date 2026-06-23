//! Behavioural tests for the shared Fiat-Shamir transcript: determinism (prover/verifier agree),
//! domain separation, injective absorb encoding, and challenge-driven state advancement. These
//! pin the *discipline*; the construction itself is RED pending cryptographer sign-off.

extern crate alloc;

#[cfg(feature = "poseidon")]
use lib_q_poseidon::PoseidonField;
#[cfg(feature = "poseidon")]
use lib_q_stark_field::PrimeField32;
#[cfg(feature = "poseidon")]
use lib_q_stark_field::extension::Complex;
#[cfg(feature = "poseidon")]
use lib_q_stark_mersenne31::Mersenne31;
#[cfg(feature = "poseidon")]
use lib_q_transcript::PoseidonTranscript;
use lib_q_transcript::{
    DuplexTranscript,
    K12Transcript,
};

#[cfg(feature = "poseidon")]
fn felts(xs: &[u32]) -> alloc::vec::Vec<PoseidonField> {
    xs.iter()
        .map(|&x| Complex::new_real(Mersenne31::new(x)))
        .collect()
}

// ---------------------------------------------------------------------------
// K12 (out-of-circuit) transcript
// ---------------------------------------------------------------------------

#[test]
fn k12_is_deterministic_replay() {
    // A verifier replaying the same labelled absorbs derives the same challenge as the prover.
    let mut prover = K12Transcript::new(b"proto");
    prover.absorb(b"statement", b"the instance");
    prover.absorb(b"commitment", &[1, 2, 3, 4]);
    let c_prover = prover.challenge(b"beta", 16);

    let mut verifier = K12Transcript::new(b"proto");
    verifier.absorb(b"statement", b"the instance");
    verifier.absorb(b"commitment", &[1, 2, 3, 4]);
    let c_verifier = verifier.challenge(b"beta", 16);

    assert_eq!(c_prover, c_verifier);
    assert_eq!(c_prover.len(), 16);
}

#[test]
fn k12_domain_separates() {
    let mut a = K12Transcript::new(b"proto-A");
    let mut b = K12Transcript::new(b"proto-B");
    a.absorb(b"x", b"same");
    b.absorb(b"x", b"same");
    assert_ne!(a.challenge(b"c", 32), b.challenge(b"c", 32));
}

#[test]
fn k12_absorb_order_matters() {
    let mut a = K12Transcript::new(b"p");
    a.absorb(b"l", b"A");
    a.absorb(b"l", b"B");

    let mut b = K12Transcript::new(b"p");
    b.absorb(b"l", b"B");
    b.absorb(b"l", b"A");

    assert_ne!(a.challenge(b"c", 16), b.challenge(b"c", 16));
}

#[test]
fn k12_label_message_boundary_is_injective() {
    // Length-prefixing must make ("x","ab") and ("xa","b") distinct absorbs (no boundary collision).
    let mut a = K12Transcript::new(b"p");
    a.absorb(b"x", b"ab");
    let mut b = K12Transcript::new(b"p");
    b.absorb(b"xa", b"b");
    assert_ne!(a.challenge(b"c", 16), b.challenge(b"c", 16));
}

#[test]
fn k12_challenge_advances_state() {
    let mut t = K12Transcript::new(b"p");
    t.absorb(b"s", b"data");
    let first = t.challenge(b"c", 16);
    let second = t.challenge(b"c", 16); // same label, but state advanced
    assert_ne!(first, second);
}

#[test]
fn k12_challenge_label_matters() {
    let mut a = K12Transcript::new(b"p");
    a.absorb(b"s", b"data");
    let mut b = K12Transcript::new(b"p");
    b.absorb(b"s", b"data");
    assert_ne!(a.challenge(b"alpha", 16), b.challenge(b"beta", 16));
}

#[test]
fn k12_convenience_matches_trait() {
    let mut a = K12Transcript::new(b"p");
    a.absorb(b"s", b"x");
    let via_array: [u8; 16] = a.challenge_array(b"c");

    let mut b = K12Transcript::new(b"p");
    b.absorb(b"s", b"x");
    let via_trait = b.challenge(b"c", 16);

    assert_eq!(&via_array[..], &via_trait[..]);

    // challenge_u64 is the big-endian read of an 8-byte squeeze.
    let mut c = K12Transcript::new(b"p");
    c.absorb(b"s", b"x");
    let n = c.challenge_u64(b"c");
    let mut d = K12Transcript::new(b"p");
    d.absorb(b"s", b"x");
    let bytes: [u8; 8] = d.challenge_array(b"c");
    assert_eq!(n, u64::from_be_bytes(bytes));
}

// ---------------------------------------------------------------------------
// Poseidon-256 (in-circuit) transcript
// ---------------------------------------------------------------------------

#[cfg(feature = "poseidon")]
#[test]
fn poseidon_is_deterministic_replay() {
    let mut prover = PoseidonTranscript::new(b"proto");
    prover.absorb(b"statement", &felts(&[7, 8, 9]));
    let c_prover = prover.challenge(b"beta", 3);

    let mut verifier = PoseidonTranscript::new(b"proto");
    verifier.absorb(b"statement", &felts(&[7, 8, 9]));
    let c_verifier = verifier.challenge(b"beta", 3);

    assert_eq!(c_prover, c_verifier);
    assert_eq!(c_prover.len(), 3);
}

#[cfg(feature = "poseidon")]
#[test]
fn poseidon_domain_separates() {
    let mut a = PoseidonTranscript::new(b"A");
    let mut b = PoseidonTranscript::new(b"B");
    a.absorb(b"x", &felts(&[1, 2]));
    b.absorb(b"x", &felts(&[1, 2]));
    assert_ne!(a.challenge(b"c", 4), b.challenge(b"c", 4));
}

#[cfg(feature = "poseidon")]
#[test]
fn poseidon_message_matters() {
    let mut a = PoseidonTranscript::new(b"p");
    a.absorb(b"s", &felts(&[1, 2, 3]));
    let mut b = PoseidonTranscript::new(b"p");
    b.absorb(b"s", &felts(&[1, 2, 4]));
    assert_ne!(a.challenge(b"c", 4), b.challenge(b"c", 4));
}

#[cfg(feature = "poseidon")]
#[test]
fn poseidon_challenge_advances_state() {
    let mut t = PoseidonTranscript::new(b"p");
    t.absorb(b"s", &felts(&[5]));
    let first = t.challenge(b"c", 4);
    let second = t.challenge(b"c", 4);
    assert_ne!(first, second);
}

#[cfg(feature = "poseidon")]
#[test]
fn poseidon_absorb_bytes_is_deterministic() {
    let mut a = PoseidonTranscript::new(b"p");
    a.absorb_bytes(b"ctx", b"hello world");
    let mut b = PoseidonTranscript::new(b"p");
    b.absorb_bytes(b"ctx", b"hello world");
    assert_eq!(a.challenge(b"c", 5), b.challenge(b"c", 5));

    let mut c = PoseidonTranscript::new(b"p");
    c.absorb_bytes(b"ctx", b"hello worle"); // one byte differs
    assert_ne!(a.challenge(b"c", 5), c.challenge(b"c", 5));
}

// ---------------------------------------------------------------------------
// KAT locks — pin the (RED, draft) wire encoding so an accidental change to the
// transcript construction, labels, or field encoding is caught as a regression.
// Regenerate deliberately (and bump the *_V0 labels) if the construction changes.
// ---------------------------------------------------------------------------

#[test]
fn k12_kat_lock() {
    let mut t = K12Transcript::new(b"libq.kat");
    t.absorb(b"statement", b"hello");
    t.absorb(b"commitment", &[0xAA, 0xBB, 0xCC]);
    let c = t.challenge(b"beta", 32);
    let hex: alloc::string::String = c.iter().map(|b| alloc::format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "ed0d4bb1de1f740e2e39a25878dc2bcb7d6689c1e34e25502003488980bda27c"
    );
}

#[cfg(feature = "poseidon")]
#[test]
fn poseidon_kat_lock() {
    let mut p = PoseidonTranscript::new(b"libq.kat");
    p.absorb(b"statement", &felts(&[7, 8, 9]));
    let pc = p.challenge(b"beta", 3);
    let got: alloc::vec::Vec<(u32, u32)> = pc
        .iter()
        .map(|e| (e.real().as_canonical_u32(), e.imag().as_canonical_u32()))
        .collect();
    assert_eq!(
        got,
        alloc::vec![
            (487_640_029, 1_614_115_946),
            (295_109_317, 1_703_314_955),
            (1_909_859_747, 458_278_153),
        ]
    );
}
