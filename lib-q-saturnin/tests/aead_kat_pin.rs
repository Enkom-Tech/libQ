//! Data-at-rest guard: pins `SaturninAead` (CTR-Cascade)'s ciphertext output byte-for-byte.
//!
//! # Why this exists
//!
//! `SaturninAead` encrypts data already stored in shipped products (My-Grid vault
//! `mygrid_vault_v1`, My-Grid recovery, GIP `bitlink-wrapkey-argon2id-v1`). The CTX committing
//! transform landing on a *new*, separate type (`SaturninAeadCtx`, see `src/aead_ctx.rs`) must
//! not perturb `SaturninAead`'s existing wire format by even one bit — any in-place change would
//! make every one of those blobs permanently undecryptable. This test is the tripwire: it pins
//! full ciphertext hex generated from the tree *before* `SaturninAeadCtx` was added, and must
//! stay green through every subsequent change to this crate. Provenance was re-verified during
//! review against a `git worktree` at the pre-change commit (`c1d27a6`): all six vectors below
//! are byte-identical to that tree's output. `src/aead.rs`'s only edits since are additive (a
//! `pub(crate)` helper and one visibility widening), which `git diff lib-q-saturnin/src/aead.rs`
//! shows directly.
//!
//! Generated with a one-off example (`examples/gen_kat_pin.rs`, not committed) run against the
//! unmodified tree: `cargo run --example gen_kat_pin --features "alloc,aead"`.
//!
//! Case matrix (key = `00..1f`, nonce = `00..0f`): crosses the 32-byte cascade/CTR block boundary
//! in both directions, empty pt/ad, and pt/ad lengths that are exact multiples of 32 vs not.

#![cfg(all(feature = "alloc", feature = "aead"))]

use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    SaturninAead,
};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key() -> AeadKey {
    AeadKey::new((0u8..32).collect())
}

fn nonce() -> Nonce {
    Nonce::new((0u8..16).collect())
}

/// (pt_hex, ad_hex, ct_hex). See module docs for provenance.
const CASES: &[(&str, &str, &str)] = &[
    (
        "",
        "",
        "ba6f18356b82c46910fe1738e72d99a43250269b8fe631ce0c1c6a38a5afc6cb",
    ),
    (
        "",
        "6173736f636961746564",
        "a721578328ce1f3fb62b31c0670e7066ee6bfa8199349f24a76587591eeb16ae",
    ),
    (
        "616263",
        "",
        "12c000dfae2f86a18601cabcf5267166b290638a8177ab284ba897d5e8be67a43eb385",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "686472",
        "73a2630524a64d55324ee045d1f28da3422619290256804dd65f51ff234d2dead000764f9c3ea91ea5c7b2ab714e7237f8442ec83b7b75dd40ff22a1b0ad4e0d",
    ),
    (
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672121",
        "61642d31",
        "27ca062555d32436596e8237be85e383244961096823ed3da57f3e89463f0d9e2135fb457b6d3ae5bffc697abe933423bd1ad61ace665b71c7ffa3e30814f83d7e6cef043627217b9f8677c2d6",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "73a3610620a34b523a47ea4eddff83ac52370b3a1643965ace464be43f5033f56971f90a3e3265e2f3ba2470b30254de4a209936778b94745f7e76b45b89dad3db6334124f8f46cbd7759dc6f4291caf7523db7b203642ce608387d119a9ed193346c052d8a33ccd1f5c57c6cc0f70357ba61f69ff1f4ba324066ab8312220f1",
    ),
];

/// **The tripwire.** Any change to `SaturninAead`'s tag or ciphertext-body construction turns
/// this red. *Observed red* during review by adding `tag[0] ^= 0x01` to `encrypt_bytes` in
/// `src/aead.rs`, which produced exactly this assertion's wire-format-break message with a
/// one-byte diff in the first vector.
#[test]
fn plain_saturnin_aead_wire_format_is_frozen() {
    let aead = SaturninAead::new();
    for (pt_hex, ad_hex, ct_hex) in CASES {
        let pt = from_hex(pt_hex);
        let ad = from_hex(ad_hex);
        let ad_opt = if ad.is_empty() {
            None
        } else {
            Some(ad.as_slice())
        };
        let ct = aead.encrypt(&key(), &nonce(), &pt, ad_opt).unwrap();
        assert_eq!(
            ct,
            from_hex(ct_hex),
            "SaturninAead ciphertext changed for pt={pt_hex} ad={ad_hex} — this is a wire-format \
             break that would make stored ciphertext (My-Grid vault, GIP wrapkey, ...) \
             undecryptable"
        );
        let dec = aead.decrypt(&key(), &nonce(), &ct, ad_opt).unwrap();
        assert_eq!(dec, pt, "round-trip mismatch for pt={pt_hex} ad={ad_hex}");
    }
}
