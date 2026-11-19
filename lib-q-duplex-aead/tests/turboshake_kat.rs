//! Known-answer tests of the TurboSHAKE duplex AEAD (GIP `aead_id = 17`).
//!
//! `tests/data/turboshake_duplex_kat_v0.json` is SELF-GENERATED: it is the output of this crate's
//! own `cargo run -q -p lib-q-duplex-aead --example dump_turboshake_duplex_kat` (see
//! `tests/data/PROVENANCE.md`). It is a regression pin, not independent conformance evidence: this
//! test only shows the construction still emits the bytes it emitted when the file was frozen, so
//! a change to the construction cannot pass here without a new vector file. The one external
//! anchor in this file is `init_call_equals_lib_q_sha3_turboshake256`, which ties the
//! initialization call to lib-q-sha3's TurboSHAKE256 (itself pinned to the RFC 9861 vectors).

use digest::{ExtendableOutput, Update};
use lib_q_duplex_aead::turboshake::{LABEL, TAG_BYTES, decrypt, encrypt, init_state_prefix};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn kat_file_matches_this_implementation() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("data/turboshake_duplex_kat_v0.json")).expect("json");
    let mut positive = 0;
    let mut negative = 0;
    for v in doc["vectors"].as_array().expect("vectors") {
        let i = &v["inputs"];
        let o = &v["outputs"];
        let key: [u8; 32] = h(i["key_hex"].as_str().unwrap()).try_into().unwrap();
        let nonce: [u8; 16] = h(i["nonce_hex"].as_str().unwrap()).try_into().unwrap();
        let id = v["id"].as_str().unwrap();
        if id.starts_with("init_state") {
            let mut got = [0u8; 32];
            init_state_prefix(&key, &nonce, &mut got);
            assert_eq!(hex::encode(got), o["state_prefix_hex"].as_str().unwrap());
            continue;
        }
        let ad = h(i["ad_hex"].as_str().unwrap());
        if v["negative"].as_bool().unwrap() {
            let ct = h(i["ciphertext_and_tag_hex"].as_str().unwrap());
            let mut sink = vec![0u8; ct.len().saturating_sub(TAG_BYTES)];
            assert!(decrypt(&key, &nonce, &ad, &ct, &mut sink).is_err(), "{id}");
            assert!(sink.iter().all(|&b| b == 0), "{id}: plaintext released");
            negative += 1;
        } else {
            let pt = h(i["plaintext_hex"].as_str().unwrap());
            let mut ct = vec![0u8; pt.len() + TAG_BYTES];
            encrypt(&key, &nonce, &ad, &pt, &mut ct).unwrap();
            assert_eq!(
                hex::encode(&ct),
                o["ciphertext_and_tag_hex"].as_str().unwrap(),
                "{id}"
            );
            let mut back = vec![0u8; pt.len()];
            decrypt(&key, &nonce, &ad, &ct, &mut back).unwrap();
            assert_eq!(back, pt, "{id}");
            positive += 1;
        }
    }
    assert_eq!((positive, negative), (15, 7));
}

/// The initialization call is a TurboSHAKE256 absorb with domain byte 0x41, so the state it
/// leaves must equal what libQ's own TurboSHAKE256 squeezes first. This ties the AEAD to the
/// permutation and padding K12 and TurboSHAKE use, through a second code path in libQ.
#[test]
fn init_call_equals_lib_q_sha3_turboshake256() {
    for seed in 0u8..8 {
        let key: [u8; 32] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed));
        let nonce: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ seed.wrapping_mul(37));
        let mut via_aead = [0u8; 136];
        init_state_prefix(&key, &nonce, &mut via_aead);

        let mut xof = lib_q_sha3::TurboShake256::<0x41>::default();
        xof.update(LABEL);
        xof.update(&key);
        xof.update(&nonce);
        let mut via_sha3 = [0u8; 136];
        xof.finalize_xof_into(&mut via_sha3);
        assert_eq!(via_aead, via_sha3, "seed {seed}");
    }
}
