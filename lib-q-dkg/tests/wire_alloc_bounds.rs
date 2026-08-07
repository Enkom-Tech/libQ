//! Allocation bounds for the wire decoders under hostile input.
//!
//! A decoder that reads a count out of untrusted bytes must not size an allocation from that count
//! before checking it against the protocol maximum *and* against the bytes actually present. This
//! binary installs a counting global allocator and asserts that no decoder can be made to request
//! materially more memory than the caller handed it.
//!
//! An `is_err()` assertion alone would NOT catch the defect this file exists for: the decoders
//! already returned `Err` on these inputs -- after allocating. The bound, not the error, is the
//! subject here. (Scope: this measures heap requests through `GlobalAlloc`. It says nothing about
//! stack usage, which `tests/stack_budget.rs` covers.)
//!
//! This binary deliberately contains exactly ONE `#[test]`: the counters are process-global, so a
//! second test running concurrently on another harness thread would pollute the measurement.

use std::alloc::{
    GlobalAlloc,
    Layout,
    System,
};
use std::sync::atomic::{
    AtomicUsize,
    Ordering,
};

use lib_q_dkg::lattice::bdlop::{
    Commitment,
    MU,
};
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
};
use lib_q_dkg::{
    CoeffCommitments,
    MAX_ROUND1_COMMITMENTS,
    MAX_WIRE_RQ_VEC_LEN,
    decode_complaint,
    decode_round1_commitments,
    decode_share_evaluation,
    encode_round1_commitments,
};

/// The largest commitment count the protocol admits.
const MAX_T: usize = MAX_ROUND1_COMMITMENTS;
/// The largest response-vector length the protocol admits.
const MAX_Z: usize = MAX_WIRE_RQ_VEC_LEN;

static PEAK_SINGLE: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK_LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// Wraps `System` with counters; allocation behaviour itself is unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        PEAK_SINGLE.fetch_max(size, Ordering::SeqCst);
        let live = LIVE.fetch_add(size, Ordering::SeqCst) + size;
        PEAK_LIVE.fetch_max(live, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Slack over `4 x input length`, covering the small bookkeeping allocations a decode makes
/// regardless of payload size.
const SLACK_BYTES: usize = 4096;

/// Measured allocation for one decode: the largest single request, and the peak simultaneously
/// live bytes, both relative to the state on entry.
struct Measured {
    peak_single: usize,
    peak_live: usize,
}

/// Run `decode` with the counters zeroed and report what it allocated. Nothing is formatted or
/// printed inside the measured window.
fn measure(decode: impl FnOnce()) -> Measured {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK_SINGLE.store(0, Ordering::SeqCst);
    PEAK_LIVE.store(base, Ordering::SeqCst);
    decode();
    Measured {
        peak_single: PEAK_SINGLE.load(Ordering::SeqCst),
        peak_live: PEAK_LIVE.load(Ordering::SeqCst).saturating_sub(base),
    }
}

/// Assert a decode of `wire` allocated no more than `4 x wire.len() + SLACK_BYTES`.
///
/// The multiplier is deliberately loose: an honestly-encoded payload legitimately inflates by
/// `size_of::<Rq>() / RQ_BYTES` = 8192/6144 = 1.33x when parsed into ring elements. What the bound
/// forbids is allocation driven by a *declared* count rather than by bytes present.
fn assert_no_amplification(label: &str, wire: &[u8], decode: impl FnOnce()) {
    let limit = wire.len().saturating_mul(4).saturating_add(SLACK_BYTES);
    let m = measure(decode);
    assert!(
        m.peak_single <= limit,
        "{label}: decoding {} bytes made a single allocation request of {} bytes (limit {limit}) \
         -- the decoder sized an allocation from a declared count instead of from the input",
        wire.len(),
        m.peak_single,
    );
    assert!(
        m.peak_live <= limit,
        "{label}: decoding {} bytes held {} bytes live at peak (limit {limit})",
        wire.len(),
        m.peak_live,
    );
}

/// Assert a decode allocated no more than `limit` bytes, whatever the input size.
///
/// Used where the decoder is expected to reject *before* parsing a large but well-formed-looking
/// body: there the loose `4 x input` allowance would pass vacuously.
fn assert_alloc_under(label: &str, limit: usize, decode: impl FnOnce()) {
    let m = measure(decode);
    assert!(
        m.peak_single <= limit && m.peak_live <= limit,
        "{label}: peak single {} / peak live {} exceeds the stated limit of {limit} bytes",
        m.peak_single,
        m.peak_live,
    );
}

/// Header of every V1 payload: version, profile.
const HDR: [u8; 2] = [1, 1];

/// A round-1 broadcast declaring `n` commitments and supplying none of them.
fn round1_declaring(n: u16) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 1]); // party, threshold
    w.extend_from_slice(&n.to_le_bytes());
    w
}

/// A share evaluation that is well-formed up to `rand_len`, which it sets to `n`, then stops:
/// `n` ring elements declared, zero supplied.
fn share_declaring_rand(n: u32) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 2, 2]); // dealer, recipient, threshold
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES)); // value: the zero ring element
    w.extend_from_slice(&n.to_le_bytes());
    w
}

/// A share evaluation that is well-formed through `value`, `rand` and the challenge `c`, then
/// declares `z_len` response elements and supplies `z_supplied` of them.
fn share_declaring_z(z_len: u32, z_supplied: usize) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 2, 2]); // dealer, recipient, threshold
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES)); // value
    w.extend_from_slice(&9u32.to_le_bytes()); // rand_len = KAPPA
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES * 9)); // rand
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES)); // challenge c
    w.extend_from_slice(&z_len.to_le_bytes());
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES * z_supplied));
    w
}

/// A complaint that is well-formed up to the inner share's `rand_len`, set to `n`.
fn complaint_declaring_rand(n: u32) -> Vec<u8> {
    let mut w = Vec::from(HDR);
    w.extend_from_slice(&[1, 2]); // outer dealer, recipient
    w.extend_from_slice(&[1, 2, 2]); // inner dealer, recipient, threshold
    w.extend(core::iter::repeat_n(0u8, RQ_BYTES));
    w.extend_from_slice(&n.to_le_bytes());
    w
}

#[test]
fn hostile_wire_input_cannot_inflate_allocation() {
    // (1) The headline case: a 6-byte round-1 broadcast declaring the u16 maximum.
    let w = round1_declaring(u16::MAX);
    assert_no_amplification("round1 n=u16::MAX", &w, || {
        assert!(decode_round1_commitments(&w).is_err());
    });

    // (2) One over the protocol maximum -- the boundary the named constant defines.
    let w = round1_declaring(17);
    assert_no_amplification("round1 n=17", &w, || {
        assert!(decode_round1_commitments(&w).is_err());
    });

    // (3) At the protocol maximum but with none of the promised bytes: the count must also be
    //     reconciled against the input length, not just against the constant.
    let w = round1_declaring(16);
    assert_no_amplification("round1 n=16 with empty body", &w, || {
        assert!(decode_round1_commitments(&w).is_err());
    });

    // (4)/(5) The same shape one level down, in the length-prefixed R_q vector reached through the
    //     share and complaint decoders. 170 is the largest count the previous byte-budget guard let
    //     through.
    let w = share_declaring_rand(170);
    assert_no_amplification("share rand_len=170", &w, || {
        assert!(decode_share_evaluation(&w).is_err());
    });
    let w = complaint_declaring_rand(170);
    assert_no_amplification("complaint rand_len=170", &w, || {
        assert!(decode_complaint(&w).is_err());
    });

    // (6) rand_len = u32::MAX, the count the previous guard did already reject.
    let w = share_declaring_rand(u32::MAX);
    assert_no_amplification("share rand_len=u32::MAX", &w, || {
        assert!(decode_share_evaluation(&w).is_err());
    });

    // (7) POSITIVE CONTROL. An honest, complete broadcast must still decode -- and must satisfy the
    //     same bound, proving the bound is not vacuously large.
    let w = encode_round1_commitments(&honest_broadcast(3)).expect("honest encode");
    assert_no_amplification("round1 honest t=3", &w, || {
        let decoded = decode_round1_commitments(&w).expect("honest broadcast must still decode");
        assert_eq!(decoded.commitments.len(), 3);
        assert_eq!(decoded.threshold, 3);
    });

    // (8) POSITIVE CONTROL at the ceiling: the largest broadcast the protocol allows must decode
    //     and must still respect the same ratio, so the bound is not merely a small-input property.
    let w = encode_round1_commitments(&honest_broadcast(MAX_T)).expect("honest encode");
    assert_no_amplification("round1 honest t=MAX", &w, || {
        let decoded = decode_round1_commitments(&w).expect("max-size broadcast must still decode");
        assert_eq!(decoded.commitments.len(), MAX_T);
    });

    // ---- bypass attempts: inputs built to slip past the new bound -------------------------------

    // (9) Count AT the protocol maximum with a body one byte short of complete. The count clears the
    //     named-constant check, so only the reconciliation against bytes present can catch it.
    let mut w = encode_round1_commitments(&honest_broadcast(MAX_T)).expect("encode");
    w.pop();
    assert_no_amplification("round1 n=MAX body one byte short", &w, || {
        assert!(decode_round1_commitments(&w).is_err());
    });

    // (10) A complete max-size broadcast with one garbage byte appended. The loose `4 x input`
    //      allowance would pass vacuously here, so bound it tightly instead: the trailing byte must
    //      be caught before the commitments are materialised.
    let mut w = encode_round1_commitments(&honest_broadcast(MAX_T)).expect("encode");
    w.push(0);
    assert_alloc_under("round1 max-size + trailing garbage", SLACK_BYTES, || {
        assert!(decode_round1_commitments(&w).is_err());
    });

    // (11) The response vector `z` declared exactly at its protocol maximum with an empty body --
    //      the same "just under the ceiling, no bytes behind it" shape one field deeper, reached
    //      only after `value` and `rand` have decoded successfully.
    let w = share_declaring_z(u32::try_from(MAX_Z).expect("fits"), 0);
    assert_no_amplification("share z_len=MAX with empty body", &w, || {
        assert!(decode_share_evaluation(&w).is_err());
    });

    // (12) `z` at its maximum with all but one element supplied.
    let w = share_declaring_z(u32::try_from(MAX_Z).expect("fits"), MAX_Z - 1);
    assert_no_amplification("share z_len=MAX minus one element", &w, || {
        assert!(decode_share_evaluation(&w).is_err());
    });
}

/// A `CoeffCommitments` with `t` all-zero commitments.
fn honest_broadcast(t: usize) -> CoeffCommitments {
    CoeffCommitments {
        party: 1,
        threshold: u8::try_from(t).expect("t fits u8"),
        commitments: (0..t)
            .map(|_| Commitment {
                t0: (0..MU).map(|_| Rq::zero()).collect(),
                t1: Rq::zero(),
            })
            .collect(),
    }
}
