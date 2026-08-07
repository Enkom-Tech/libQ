//! Allocator-probe regression for `lattice_zkp_wire_v0` decoders.
//!
//! Every `decode_*_v0` entry point reads at least one element count from untrusted wire bytes
//! before it has validated that count against the input actually present. This file's
//! `#[global_allocator]` records the peak *single* allocation made while a decoder call is
//! "armed", so a regression is caught on the byte count itself — an `is_err()`-only assertion
//! would pass even while the decoder first performed an attacker-sized allocation, because every
//! hostile input below is rejected *eventually* regardless of the bug's presence.
//!
//! Not run on wasm32: a process-wide `#[global_allocator]` has no business in the wasm smoke
//! build, and this crate's wasm CI lane does not include this file.
#![cfg(not(target_arch = "wasm32"))]

use std::alloc::{
    GlobalAlloc,
    Layout,
    System,
};
use std::cell::Cell;

use lib_q_lattice_zkp::{
    AjtaiCommitment,
    LATTICE_ZKP_WIRE_VERSION_V0,
    LatticeZkpProfileV0,
    LinearRelationProof,
    OpeningProof,
    ProofKindV0,
    WIRE_ENVELOPE_HEADER_LEN,
    decode_amortised_proof_v0,
    decode_blind_issuance_v0,
    decode_dual_ring_opening_proof_v0,
    decode_linear_relation_proof_v0,
    decode_nullifier_opening_proof_v0,
    decode_opening_proof_v0,
    decode_private_membership_proof_v0,
    decode_spending_proof_v0,
    decode_witness_nullifier_opening_proof_v0,
    encode_linear_relation_proof_v0,
    path_index_commitment,
};
use lib_q_ring::{
    ModuleVec,
    Poly,
};

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static PEAK_SINGLE: Cell<usize> = const { Cell::new(0) };
    static TOTAL_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Records both the largest single allocation request and the cumulative bytes requested on the
/// current thread while armed.
///
/// The original defect was a single `Vec::with_capacity(n)` for an attacker-chosen `n`, which
/// `PEAK_SINGLE` catches. `TOTAL_BYTES` additionally closes the "many individually-small
/// allocations" evasion: a decoder that satisfies a per-allocation bound could still be made to
/// allocate unboundedly in aggregate from one small input.
struct TrackingAlloc;

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            let sz = layout.size();
            PEAK_SINGLE.with(|p| {
                if sz > p.get() {
                    p.set(sz);
                }
            });
            TOTAL_BYTES.with(|t| t.set(t.get().saturating_add(sz)));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: TrackingAlloc = TrackingAlloc;

/// Above what a *correctly bounded* decoder can ever allocate from a single envelope, yet well
/// below both measured defects: 261_120 B (the `u8` `ring_len` case) and 67_107_840 B (the
/// `u16`/`u32`-count cases). A bound strictly inside that gap is what makes this test
/// distinguish "fixed" from "still broken" rather than merely asserting `Err`.
///
/// Ceiling on the legitimate side: the envelope header carries `payload_len` as a `u16`, so a body
/// is at most 65535 B; the densest module packing is 704 B per `Poly`, giving at most 93 elements;
/// `collect::<Result<Vec<_>, _>>()` grows by doubling (its shunt reports a `size_hint` lower bound
/// of 0), so the final allocation is the next power of two — 128 x 1024 B = 131_072 B.
/// `largest_accepted_wire_allocates_under_the_bound` measures exactly this and observes 131_072 B,
/// leaving ~1.5x headroom under the constant below.
const MAX_DECODE_ALLOC_BYTES: usize = 200_000;

fn arm() {
    PEAK_SINGLE.with(|p| p.set(0));
    TOTAL_BYTES.with(|t| t.set(0));
    ARMED.with(|a| a.set(true));
}

/// Disarm and return the peak single-allocation size observed since [`arm`].
fn disarm() -> usize {
    ARMED.with(|a| a.set(false));
    PEAK_SINGLE.with(Cell::get)
}

/// Disarm and return `(peak single allocation, cumulative bytes requested)` since [`arm`].
fn disarm_full() -> (usize, usize) {
    ARMED.with(|a| a.set(false));
    (PEAK_SINGLE.with(Cell::get), TOTAL_BYTES.with(Cell::get))
}

fn assert_bounded(label: &str, peak: usize, input_len: usize) {
    assert!(
        peak <= MAX_DECODE_ALLOC_BYTES,
        "{label} allocated {peak} B from a {input_len}-byte input (bound {MAX_DECODE_ALLOC_BYTES})"
    );
}

/// Build a `version || profile_id || kind || payload_len(u16 le) || payload` envelope by hand —
/// exactly what an unauthenticated remote peer controls.
fn build_envelope(profile_id: u8, kind: ProofKindV0, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WIRE_ENVELOPE_HEADER_LEN + payload.len());
    out.push(LATTICE_ZKP_WIRE_VERSION_V0);
    out.push(profile_id);
    out.push(kind as u8);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn opening_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    // rq-module count prefix (u16 LE) set to u16::MAX, then nothing after it.
    let wire = build_envelope(profile.profile_id, ProofKindV0::Opening, &[0xFF, 0xFF]);
    arm();
    let result = decode_opening_proof_v0(&wire);
    let peak = disarm();
    assert_bounded("decode_opening_proof_v0", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn private_membership_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::pvtn_membership_v0();
    let root = [0u8; 32];
    let leaf_digest = [0u8; 32];
    // depth = 0 => no siblings; commitment must reproduce for `decode_merkle_path_hidden` to let
    // the decoder proceed past the Merkle check and reach the vulnerable opening-body decode.
    let commitment = path_index_commitment(0, &root, &leaf_digest, &[]);

    let mut body = Vec::new();
    body.push(0u8); // depth
    body.extend_from_slice(&0u32.to_le_bytes()); // path_index
    body.extend_from_slice(&commitment); // 32
    body.extend_from_slice(&leaf_digest); // 32
    body.extend_from_slice(&[0u8; 16]); // role_tag
    body.extend_from_slice(&[0u8; 32]); // parent_digest
    body.extend_from_slice(&0u32.to_le_bytes()); // clearance_level
    body.extend_from_slice(&0i32.to_le_bytes()); // max_norm
    body.extend_from_slice(&[0xFF, 0xFF]); // huge rq-module (w) count, nothing after

    let wire = build_envelope(profile.profile_id, ProofKindV0::PrivateMembership, &body);
    let credential_com = AjtaiCommitment {
        value: ModuleVec(vec![Poly::zero()]),
    };
    arm();
    let result = decode_private_membership_proof_v0(&wire, 0, &root, credential_com);
    let peak = disarm();
    assert_bounded("decode_private_membership_proof_v0", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn spending_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let mut body = vec![0u8; 32]; // serial
    body.extend_from_slice(&[0xFF, 0xFF]); // huge rq-module (w) count, nothing after
    let wire = build_envelope(profile.profile_id, ProofKindV0::Spending, &body);
    arm();
    let result = decode_spending_proof_v0(&wire);
    let peak = disarm();
    assert_bounded("decode_spending_proof_v0", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn linear_relation_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    // Build one genuinely valid wire first (u = empty vector) purely through the public encode
    // API, so we learn the real `split` (opening-body length) without touching any private
    // helper. Because `u` is encoded last as a 2-byte zero count with nothing after, the valid
    // body's final 2 bytes are exactly that count field.
    let opening = OpeningProof {
        w: ModuleVec(vec![Poly::zero(); profile.mask_poly_count()]),
        z: ModuleVec(vec![Poly::zero(); profile.witness_poly_count()]),
    };
    let valid = encode_linear_relation_proof_v0(
        &profile,
        &LinearRelationProof {
            opening,
            u: ModuleVec(vec![]),
        },
    )
    .expect("valid encode");
    let valid_body = &valid[WIRE_ENVELOPE_HEADER_LEN..];
    let split = valid_body.len() - 2;

    // Corrupt only the opening body's own leading rq-module (w) count — reached via
    // `decode_opening_body` before `decode_linear_relation_proof_v0` ever looks at `u`.
    let mut hostile_body = valid_body[..split].to_vec();
    hostile_body[0] = 0xFF;
    hostile_body[1] = 0xFF;

    let wire = build_envelope(
        profile.profile_id,
        ProofKindV0::LinearRelation,
        &hostile_body,
    );
    arm();
    let result = decode_linear_relation_proof_v0(&wire);
    let peak = disarm();
    assert_bounded("decode_linear_relation_proof_v0", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn nullifier_opening_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let mut body = vec![0u8; 32]; // nullifier
    body.extend_from_slice(&[0xFF, 0xFF]);
    let wire = build_envelope(profile.profile_id, ProofKindV0::NullifierOpening, &body);
    arm();
    let result = decode_nullifier_opening_proof_v0(&wire);
    let peak = disarm();
    assert_bounded("decode_nullifier_opening_proof_v0", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn witness_nullifier_opening_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let mut body = vec![0u8; 32]; // nullifier
    body.extend_from_slice(&[0xFF, 0xFF]);
    let wire = build_envelope(
        profile.profile_id,
        ProofKindV0::WitnessNullifierOpening,
        &body,
    );
    arm();
    let result = decode_witness_nullifier_opening_proof_v0(&wire);
    let peak = disarm();
    assert_bounded(
        "decode_witness_nullifier_opening_proof_v0",
        peak,
        wire.len(),
    );
    assert!(result.is_err());
}

#[test]
fn amortised_proof_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    // tlen(u32)=0 || n(u16)=0 || z_module count(u16)=0 || w_module count(u16)=MAX, nothing after.
    let body: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];
    let wire = build_envelope(profile.profile_id, ProofKindV0::AmortisedAggregate, &body);
    arm();
    let result = decode_amortised_proof_v0(&wire);
    let peak = disarm();
    assert_bounded("decode_amortised_proof_v0 (agg_w)", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn blind_issuance_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let mut body = vec![0u8; 64]; // issuer_params_digest || com_blinded_digest
    body.extend_from_slice(&[0xFF, 0xFF]); // huge issuer_com rq-module count, nothing after
    let wire = build_envelope(profile.profile_id, ProofKindV0::BlindIssuance, &body);
    arm();
    let result = decode_blind_issuance_v0(&wire);
    let peak = disarm();
    assert_bounded("decode_blind_issuance_v0", peak, wire.len());
    assert!(result.is_err());
}

#[test]
fn dual_ring_opening_challenges_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    // ring_len (u8) = 255, nothing after.
    let body = vec![0xFFu8];
    let wire = build_envelope(profile.profile_id, ProofKindV0::DualRingOpening, &body);
    arm();
    let result = decode_dual_ring_opening_proof_v0(&wire);
    let peak = disarm();
    assert_bounded(
        "decode_dual_ring_opening_proof_v0 (challenges)",
        peak,
        wire.len(),
    );
    assert!(result.is_err());
}

/// Cumulative-allocation ceiling for a single decode of one envelope.
///
/// The envelope header carries `payload_len` as a `u16`, so no decoder can ever see a body longer
/// than 65535 B. The most allocation-hungry decoder (`decode_amortised_proof_v0`) copies the
/// transcript, the `r_scalars` vector and two module vectors out of that one body, each at most
/// ~1.46x its packed size (1024 B `Poly` vs 704 B packed). 1 MiB is comfortably above every
/// legitimate decode yet far below any of the measured defects, so a regression that trades one
/// huge allocation for many medium ones is still caught.
const MAX_DECODE_TOTAL_ALLOC_BYTES: usize = 1_048_576;

fn assert_total_bounded(label: &str, total: usize, input_len: usize) {
    assert!(
        total <= MAX_DECODE_TOTAL_ALLOC_BYTES,
        "{label} allocated {total} B in total from a {input_len}-byte input \
         (bound {MAX_DECODE_TOTAL_ALLOC_BYTES})"
    );
}

/// Bypass attempt: a count one below the wire's own ceiling, with a body that carries exactly one
/// element. Rejecting only "count == MAX" or only "body empty" would let this through.
#[test]
fn bypass_rq_count_just_under_max_with_one_element_present() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let mut body = vec![0xFEu8, 0xFF]; // rq-module count = 65534
    body.extend_from_slice(&[0u8; 736]); // exactly one packed R_q poly (23 bits * 256 / 8)
    let wire = build_envelope(profile.profile_id, ProofKindV0::Opening, &body);
    arm();
    let result = decode_opening_proof_v0(&wire);
    let (peak, total) = disarm_full();
    assert_bounded("bypass rq count 65534 + 1 element", peak, wire.len());
    assert_total_bounded("bypass rq count 65534 + 1 element", total, wire.len());
    assert!(result.is_err());
}

/// Bypass attempt: same shape against the `u8`-counted dual-ring challenge list.
#[test]
fn bypass_dual_ring_u8_count_just_under_max_with_one_element_present() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let mut body = vec![0xFEu8]; // ring_len = 254
    body.extend_from_slice(&[0u8; 736]); // one packed challenge
    let wire = build_envelope(profile.profile_id, ProofKindV0::DualRingOpening, &body);
    arm();
    let result = decode_dual_ring_opening_proof_v0(&wire);
    let (peak, total) = disarm_full();
    assert_bounded("bypass dual-ring count 254 + 1 element", peak, wire.len());
    assert_total_bounded("bypass dual-ring count 254 + 1 element", total, wire.len());
    assert!(result.is_err());
}

/// Bypass attempt: counts of 0 and 1 — the values most likely to skip a bounds check that is
/// written as a strict inequality, and the values a `chunks_exact`-based reader handles specially.
#[test]
fn bypass_zero_and_one_counts_do_not_panic() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    for (label, body) in [
        ("count 0 / no body", vec![0x00u8, 0x00]),
        ("count 1 / no body", vec![0x01u8, 0x00]),
        ("count 1 / short body", {
            let mut b = vec![0x01u8, 0x00];
            b.extend_from_slice(&[0u8; 735]); // one byte short of a full element
            b
        }),
    ] {
        let wire = build_envelope(profile.profile_id, ProofKindV0::Opening, &body);
        arm();
        let result = decode_opening_proof_v0(&wire);
        let (peak, total) = disarm_full();
        assert_bounded(label, peak, wire.len());
        assert_total_bounded(label, total, wire.len());
        // token_spend_v0 has a non-zero mask_poly_count, so 0 and 1 are both wrong regardless.
        assert!(result.is_err(), "{label} unexpectedly decoded");
    }
}

/// Bypass attempt: a well-formed, genuinely decodable prefix followed by garbage that is still
/// inside the declared `payload_len`. The trailing-byte rejection must not happen only *after* an
/// unbounded allocation, and the garbage must not be re-interpreted as another count.
#[test]
fn bypass_wellformed_prefix_then_garbage() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let opening = OpeningProof {
        w: ModuleVec(vec![Poly::zero(); profile.mask_poly_count()]),
        z: ModuleVec(vec![Poly::zero(); profile.witness_poly_count()]),
    };
    let valid = encode_linear_relation_proof_v0(
        &profile,
        &LinearRelationProof {
            opening,
            u: ModuleVec(vec![]),
        },
    )
    .expect("valid encode");
    let mut hostile_body = valid[WIRE_ENVELOPE_HEADER_LEN..].to_vec();
    // Replace the trailing (empty) `u` count with a hostile one, then append garbage.
    let n = hostile_body.len();
    hostile_body[n - 2] = 0xFF;
    hostile_body[n - 1] = 0xFF;
    hostile_body.extend_from_slice(&[0xABu8; 64]);

    let wire = build_envelope(
        profile.profile_id,
        ProofKindV0::LinearRelation,
        &hostile_body,
    );
    arm();
    let result = decode_linear_relation_proof_v0(&wire);
    let (peak, total) = disarm_full();
    assert_bounded("bypass well-formed prefix + garbage", peak, wire.len());
    assert_total_bounded("bypass well-formed prefix + garbage", total, wire.len());
    assert!(result.is_err());
}

/// Bypass attempt: hostile `tlen` values in the amortised decoder, including the ones that wrap
/// `4 + tlen` in a 32-bit `usize`. On a 64-bit host this only exercises the rejection path, but it
/// pins the "no panic, no unbounded transcript copy" behaviour for every value.
#[test]
fn bypass_amortised_hostile_transcript_lengths() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    for tlen in [
        u32::MAX,
        u32::MAX - 2,
        u32::MAX - 4,
        0x8000_0000,
        0x0001_0000,
        65_531,
    ] {
        let mut body = tlen.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 8]); // r_scalars count, z count, w count — all zero
        let wire = build_envelope(profile.profile_id, ProofKindV0::AmortisedAggregate, &body);
        arm();
        let result = decode_amortised_proof_v0(&wire);
        let (peak, total) = disarm_full();
        assert_bounded("bypass amortised tlen", peak, wire.len());
        assert_total_bounded("bypass amortised tlen", total, wire.len());
        assert!(result.is_err(), "tlen={tlen} unexpectedly decoded");
    }
}

/// The other half of the bound: a *legitimate*, maximum-size wire must still decode, and the
/// allocation it makes must sit under the bound with real headroom. Without this, the bound above
/// could be "proved" by a decoder that simply rejects everything.
///
/// `ring_len = 0` then the largest `z` module that fits the envelope's `u16` payload length.
#[test]
fn largest_accepted_wire_allocates_under_the_bound() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    const Z_ELEM_LEN: usize = 704; // 22 bits * 256 / 8
    let k = (usize::from(u16::MAX) - 3) / Z_ELEM_LEN;
    let mut body = vec![0x00u8]; // ring_len = 0
    body.extend_from_slice(&(k as u16).to_le_bytes());
    body.extend_from_slice(&vec![0u8; k * Z_ELEM_LEN]);
    let wire = build_envelope(profile.profile_id, ProofKindV0::DualRingOpening, &body);
    arm();
    let result = decode_dual_ring_opening_proof_v0(&wire);
    let (peak, total) = disarm_full();
    let (proof, _) = result.expect("largest legitimate dual-ring wire must still decode");
    assert_eq!(proof.z.0.len(), k);
    // The probe must actually be observing this decode's allocations, otherwise every bound
    // assertion in this file would be vacuously true.
    assert!(peak > 0, "allocator probe observed nothing");
    eprintln!(
        "largest accepted wire: {} B input -> peak single {peak} B, total {total} B (k={k})",
        wire.len()
    );
    assert_bounded("largest accepted wire", peak, wire.len());
    assert_total_bounded("largest accepted wire", total, wire.len());
}

#[test]
fn dual_ring_opening_z_module_alloc_is_bounded() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    // ring_len (u8) = 0 || z-module count (u16 LE) = u16::MAX, nothing after.
    let body = vec![0x00u8, 0xFF, 0xFF];
    let wire = build_envelope(profile.profile_id, ProofKindV0::DualRingOpening, &body);
    arm();
    let result = decode_dual_ring_opening_proof_v0(&wire);
    let peak = disarm();
    assert_bounded(
        "decode_dual_ring_opening_proof_v0 (z module)",
        peak,
        wire.len(),
    );
    assert!(result.is_err());
}
