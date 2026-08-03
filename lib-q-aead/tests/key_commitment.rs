//! Key-commitment (CMT-1) probes for the registry AEADs.
//!
//! # What this file can and cannot establish
//!
//! CMT-1 asks whether one ciphertext can be made to decrypt successfully under two *distinct*
//! keys, with the nonce and associated data free on each side.
//!
//! **These searches CANNOT show that an algorithm is key-committing, and no result in this file
//! should ever be quoted as if they did.** For six of the seven registry algorithms the tag is
//! 256 bits, so a generic CMT-1 collision costs ~2^128 work (~2^64 for the two Romulus modes,
//! whose tag is only 128 bits). A bounded search of 20 000 random second keys therefore has an
//! expected yield of ~2^-242 hits: **it returns zero whether or not the algorithm commits**, and
//! it would also return zero against a mode with a 2^40 structural break that the search does not
//! model. An unfalsifiable null is not evidence.
//!
//! What these searches *do* establish is narrower and still worth having: none of these
//! algorithms exhibits the *cheap structural* break that the two Saturnin modes turned out to
//! have (`lib-q-saturnin/tests/key_commitment.rs` and `lib_q_saturnin::aead_short`'s in-crate
//! tests), where a free nonce or a free associated data solves the second side in ~2^8 tries or
//! in closed form. A break of that shape *would* show up here; anything above ~2^30 would not.
//!
//! Discharging the other direction — actually demonstrating commitment — is not achievable by
//! search at these tag sizes. It needs either a proof, or a committing transform (bind
//! `H(key ‖ nonce ‖ ad)` into the tag) that changes the constructions. libQ has neither today;
//! see the "Key commitment (CMT-1)" section of the crate READMEs.
//!
//! Every search here therefore ships with two controls, so that "0 hits" is at least a statement
//! about the algorithm rather than about a broken harness:
//!
//! - `*_oracle_discriminates` — the success oracle accepts the right key and rejects a key that
//!   differs in one bit. A gate that cannot say "no" proves nothing.
//! - `*_search_reports_a_planted_hit` — the same search loop, with a triple that *is* accepted
//!   injected at a known index, must return exactly one hit. The plant travels through the
//!   identical `decrypt(...) -> hits += 1` statement the real trials use, so this control
//!   exercises the counter and the assertion, not just the plumbing around them.
//!
//! # Nonce extension (XChaCha-style) — evaluated and deliberately not pursued
//!
//! Every algorithm here takes a 128-bit nonce. XChaCha20-Poly1305 exists to stretch a 96-bit
//! nonce to 192 bits so that *random* nonces stop colliding around 2^32 messages per key; at 128
//! bits the birthday bound is already 2^64, which is beyond any realistic message volume. Nonce
//! extension buys nothing here and is not planned. Do not re-raise it. (The adjacent gap that is
//! real is key/context commitment — this file.)

#![cfg(feature = "alloc")]

use lib_q_aead::{
    Aead,
    AeadKey,
    AeadWithMetadata,
    Nonce,
};

/// Deterministic xorshift64* — test-only, not a CSPRNG.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let k = chunk.len();
            chunk.copy_from_slice(&v[..k]);
        }
        out
    }
}

/// Assert the success oracle can answer both ways for this algorithm.
fn oracle_discriminates(name: &str, aead: &dyn Aead, key_len: usize, nonce_len: usize) {
    // High-entropy key bytes: `Shake256Aead` runs a key-format/entropy validator and rejects
    // low-entropy constants such as `[0x11; 32]` outright (`security::validation::validate_key`).
    let good_bytes = Rng(0xA11C_E000_0000_0001).bytes(key_len);
    let good = AeadKey::new(good_bytes.clone());
    let mut bad_bytes = good_bytes;
    bad_bytes[0] ^= 0x01;
    let bad = AeadKey::new(bad_bytes);
    let nonce = Nonce::new(Rng(0xBEEF_0000_0000_0001).bytes(nonce_len));
    let ad: &[u8] = b"control";
    let ct = aead
        .encrypt(&good, &nonce, b"oracle control", Some(ad))
        .unwrap_or_else(|e| panic!("{name}: encrypt failed: {e:?}"));

    assert!(
        aead.decrypt(&good, &nonce, &ct, Some(ad)).is_ok(),
        "{name}: oracle refused the correct key — a null search result would be meaningless"
    );
    assert!(
        aead.decrypt(&bad, &nonce, &ct, Some(ad)).is_err(),
        "{name}: oracle accepted a key differing in one bit — this gate cannot fail"
    );
}

/// Bounded CMT-1 search, optionally with a planted hit.
///
/// Fixes one ciphertext produced under `k1`, then walks `trials` candidate second keys, each with
/// a fresh random nonce and fresh random associated data (CMT-1 leaves both free).
///
/// When `plant_at` is `Some(i)`, trial `i` uses the *accepting* triple `(k1, n1, ad1)` instead of
/// a random one. Crucially it is substituted into the same `k2 / n2 / ad2` bindings and then
/// falls through the *same* `decrypt(...) -> hits += 1` statement as every other trial — so the
/// returned count, and the assertion made on it, are shown to be capable of reporting a hit.
/// (An earlier version of this file scored the plant into a separate flag and `continue`d past
/// the counter, which left `assert_eq!(hits, 0)` unable to fail for any reason at all.)
///
/// Returns the number of accepted trials.
fn cmt1_search(
    name: &str,
    aead: &dyn Aead,
    key_len: usize,
    nonce_len: usize,
    trials: u32,
    plant_at: Option<u32>,
) -> u32 {
    let mut rng = Rng(0xC0FF_EE00_0000_0001);
    let k1_bytes = Rng(0xA11C_E000_0000_0001).bytes(key_len);
    let n1_bytes = Rng(0xBEEF_0000_0000_0001).bytes(nonce_len);
    let k1 = AeadKey::new(k1_bytes.clone());
    let n1 = Nonce::new(n1_bytes.clone());
    let ad1: &[u8] = b"side-1-associated-data";
    let ct = aead
        .encrypt(&k1, &n1, b"the quick brown fox", Some(ad1))
        .unwrap_or_else(|e| panic!("{name}: encrypt failed: {e:?}"));

    let mut hits = 0u32;
    for t in 0..trials {
        let (k2, n2, ad2) = if plant_at == Some(t) {
            (
                AeadKey::new(k1_bytes.clone()),
                Nonce::new(n1_bytes.clone()),
                ad1.to_vec(),
            )
        } else {
            (
                AeadKey::new(rng.bytes(key_len)),
                Nonce::new(rng.bytes(nonce_len)),
                rng.bytes(8),
            )
        };
        if aead.decrypt(&k2, &n2, &ct, Some(&ad2)).is_ok() {
            hits += 1;
        }
    }
    hits
}

macro_rules! cmt1_case {
    ($feature:literal, $modname:ident, $ty:path, $label:literal, $trials:expr) => {
        #[cfg(feature = $feature)]
        mod $modname {
            use super::*;

            fn build() -> ($ty, usize, usize) {
                let a = <$ty>::new();
                let kl = a.key_size();
                let nl = a.nonce_size();
                (a, kl, nl)
            }

            #[test]
            fn oracle_discriminates_control() {
                let (a, kl, nl) = build();
                oracle_discriminates($label, &a, kl, nl);
            }

            /// POSITIVE CONTROL for `bounded_cmt1_search`.
            ///
            /// Same loop, same counter, same kind of assertion — but with one accepting triple
            /// planted mid-run. It must be counted. If this test does not report exactly one
            /// hit, the sibling test's `hits == 0` is measuring the harness, not the algorithm,
            /// and must not be believed.
            #[test]
            fn search_reports_a_planted_hit() {
                let (a, kl, nl) = build();
                let trials: u32 = 16;
                let plant_at = 9u32;
                let hits = cmt1_search($label, &a, kl, nl, trials, Some(plant_at));
                println!(
                    "{}: planted-hit control: {} trials with an accepting triple at index {} \
                     -> {} hits counted (expect 1)",
                    $label, trials, plant_at, hits
                );
                assert_eq!(
                    hits, 1,
                    "{}: the search loop failed to count a triple that decrypts — every null \
                     result it produces is worthless",
                    $label
                );
            }

            /// Bounded search for a cheap structural CMT-1 break.
            ///
            /// A zero here is NOT evidence of key commitment: at a 256-bit tag the expected
            /// yield of this search is ~2^-242 hits, so zero is the outcome regardless. It rules
            /// out only breaks cheap enough for this many trials to find — the class the two
            /// Saturnin modes fell into. See the module docs.
            #[test]
            fn bounded_cmt1_search() {
                let (a, kl, nl) = build();
                let trials: u32 = $trials;
                let hits = cmt1_search($label, &a, kl, nl, trials, None);
                println!(
                    "{}: key={}B nonce={}B tag={}B | {} random (key, nonce, ad) triples tried \
                     against a fixed ciphertext, {} accepted. NOT a commitment result: the \
                     expected count is ~0 for a committing AND for a non-committing mode at \
                     this tag size; it only rules out a break cheaper than ~2^{} tries.",
                    $label,
                    kl,
                    nl,
                    a.tag_size(),
                    trials,
                    hits,
                    (u32::BITS - trials.leading_zeros())
                );
                assert_eq!(
                    hits, 0,
                    "{}: a random second key was accepted — that would be a practical CMT-1 break",
                    $label
                );
            }
        }
    };
}

cmt1_case!(
    "shake256",
    shake256,
    lib_q_aead::Shake256Aead,
    "Shake256Aead",
    20_000
);
cmt1_case!(
    "saturnin",
    saturnin,
    lib_q_aead::SaturninAead,
    "SaturninAead (CTR-Cascade)",
    20_000
);
cmt1_case!(
    "duplex-sponge-aead",
    duplex,
    lib_q_aead::DuplexSpongeAead,
    "DuplexSpongeAead",
    20_000
);
cmt1_case!(
    "tweak-aead",
    tweak,
    lib_q_aead::TweakAead,
    "TweakAead",
    20_000
);
cmt1_case!(
    "romulus-n",
    romulus_n,
    lib_q_aead::RomulusNAead,
    "RomulusNAead",
    20_000
);
cmt1_case!(
    "romulus-m",
    romulus_m,
    lib_q_aead::RomulusMAead,
    "RomulusMAead",
    20_000
);
cmt1_case!(
    "rocca-s",
    rocca_s,
    lib_q_aead::RoccaSAead,
    "RoccaSAead",
    20_000
);
