//! Pinned known-answer tests freezing the v1 wire.
//!
//! The fixtures in `tests/data/` (a fixed public key + `threshold` shares, generated once by
//! `kat_gen.rs`) and the pins below lock: the ciphertext wire bytes, the derandomized FO encryption
//! path, the KDF, the threshold decapsulation path, and the profile parameter digest. Every pinned
//! computation is **integer-only** (XOF-driven rejection sampling), so these vectors are exact on
//! every platform, build, and target — including wasm32 and `no_std`.
//!
//! A pin change is a WIRE BREAK: it must be intentional, reviewed, and versioned (`v1` → `v2`).

use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::threshold::{
    ZeroShareSeeds,
    partial_decap_masked,
};
use lib_q_threshold_kem_lattice::{
    Ciphertext,
    SecretShare,
    ThresholdKemLatticePublicKey,
    combine,
    decapsulate_reference,
    kem,
    setup,
};
use zeroize::Zeroizing;

const THRESHOLD: u8 = 3;

const PK_T0: &[u8] = include_bytes!("data/kat_pk_v1.bin");
const SHARE_1: &[u8] = include_bytes!("data/kat_share_1_v1.bin");
const SHARE_2: &[u8] = include_bytes!("data/kat_share_2_v1.bin");
const SHARE_3: &[u8] = include_bytes!("data/kat_share_3_v1.bin");

/// SHA3-256 of `PARAMETER_SET_CANONICAL_BLOB_V1` (locks the parameter set).
///
/// Pin history (pre-release, crate never published): `35395bbe…` (blob said `q48`) →
/// `a3a566b1…` on 2026-07-10, when the blob was changed to bind the **exact** prime
/// `q = 281474976694273` instead of its bit size (audit finding: two distinct 48-bit NTT-friendly
/// primes would have collided on the old blob). Ciphertext/shared-secret pins were unaffected.
const PIN_PROFILE_DIGEST: &str = "a3a566b1112bf8e9e210357b5bbfcc9cd25189d27125de87b4efc8ddd909044e";
/// SHA3-256 of the canonical ciphertext bytes for `μ = (0, 1, ..., 31)` under the fixture key.
///
/// Pin history (pre-release, crate never published): `48b826f9…` → `bd96da29…` on 2026-07-14, when
/// the FO encryption samplers were made **constant-time** (fixed byte budgets, branch-free
/// rejection, and constant-time compaction; see `kem.rs`, with `e` and `f` each drawn as one flat
/// fixed-budget block). The emitted coefficients are the same distribution, but the fixed
/// consumption boundaries shift where `f`/`g` begin in the XOF stream, changing the wire.
const PIN_CT_DIGEST: &str = "bd96da294e7d7318feeec12a9473f7b9f7ac53f3e913a247385d1e76a27e5a6c";
/// The shared secret `KDF(pk, μ, ct)` for that ciphertext (updated with the ciphertext, same change).
const PIN_SHARED_SECRET: &str = "4cb5bdfec4c2075dbbee32b4a06076107126770e2fb0a83056fd0516bda2e240";

fn fixture_pk() -> ThresholdKemLatticePublicKey {
    ThresholdKemLatticePublicKey {
        threshold: THRESHOLD,
        t0_bytes: PK_T0.to_vec(),
    }
}

fn fixture_shares() -> Vec<SecretShare> {
    [(1u8, SHARE_1), (2u8, SHARE_2), (3u8, SHARE_3)]
        .into_iter()
        .map(|(index, bytes)| SecretShare {
            index,
            threshold: THRESHOLD,
            share_bytes: Zeroizing::new(bytes.to_vec()),
        })
        .collect()
}

fn kat_mu() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn profile_digest_is_pinned() {
    assert_eq!(hex(&setup().parameter_set_digest), PIN_PROFILE_DIGEST);
}

#[test]
fn derand_encryption_and_kdf_are_pinned() {
    let pk = fixture_pk();
    let t0 = pk.t0().expect("t0");
    let mu = kat_mu();
    let ct = kem::encapsulate_derand(&t0, &mu);
    assert_eq!(ct.to_bytes().len(), Ciphertext::BYTES);
    assert_eq!(hex(&lib_q_sha3::sha3_256(&ct.to_bytes())), PIN_CT_DIGEST);
    assert_eq!(hex(&kem::kdf(&t0, &mu, &ct)), PIN_SHARED_SECRET);
}

#[test]
fn threshold_decapsulation_recovers_pinned_secret() {
    let pk = fixture_pk();
    let t0 = pk.t0().expect("t0");
    let ct = kem::encapsulate_derand(&t0, &kat_mu());
    let shares = fixture_shares();

    // Reference path.
    let ss = decapsulate_reference(&pk, &shares, &ct).expect("decap");
    assert_eq!(hex(&ss), PIN_SHARED_SECRET);

    // Distributed masked+flooded path (the masks/flooding must not disturb the pinned result).
    let mut rng = new_deterministic_rng([0xEEu8; 32]);
    let seeds = ZeroShareSeeds::setup(THRESHOLD, &mut rng);
    let subset: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let partials: Vec<_> = shares
        .iter()
        .map(|s| partial_decap_masked(s, &subset, &ct, &seeds, &mut rng).expect("partial"))
        .collect();
    let ss_masked = combine(&pk, &partials, &ct).expect("combine");
    assert_eq!(hex(&ss_masked), PIN_SHARED_SECRET);
}
