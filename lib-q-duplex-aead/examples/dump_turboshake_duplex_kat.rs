//! Print the known-answer cases of the TurboSHAKE duplex AEAD (GIP `aead_id = 17`) as JSON.
//!
//! This example is the generator of `tests/data/turboshake_duplex_kat_v0.json`; it is
//! deterministic (fixed keys, nonces and inputs), so the file can be re-created and compared:
//! `cargo run -q -p lib-q-duplex-aead --example dump_turboshake_duplex_kat > tests/data/turboshake_duplex_kat_v0.json`
//! Provenance (self-generated) is recorded in `tests/data/PROVENANCE.md` and `kats-manifest.toml`.

use lib_q_duplex_aead::turboshake::{BLOCK, TAG_BYTES, decrypt, encrypt, init_state_prefix};

/// `ptn(n)` of RFC 9861 section 5: `00 01 .. FA` repeated, truncated to `n`.
fn ptn(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// One negative case: id, description, nonce, AD, ciphertext with tag.
type Negative = (&'static str, &'static str, [u8; 16], Vec<u8>, Vec<u8>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce: [u8; 16] = core::array::from_fn(|i| 0xA0 + i as u8);
    let mut out = Vec::new();

    let mut init = [0u8; 32];
    init_state_prefix(&key, &nonce, &mut init);
    out.push(format!(
        "    {{\"id\": \"init_state\", \"description\": \"First 32 state bytes after the initialization call; equals TurboSHAKE256(label || key || nonce, D = 0x41, 32)\", \"inputs\": {{\"key_hex\": \"{}\", \"nonce_hex\": \"{}\"}}, \"outputs\": {{\"state_prefix_hex\": \"{}\"}}, \"negative\": false, \"references\": [\"aead-id-17-turboshake-duplex-v0.md#initialization\"]}}",
        hex(&key), hex(&nonce), hex(&init)
    ));

    let grid: &[(usize, usize)] = &[
        (0, 0),
        (0, 1),
        (1, 0),
        (0, BLOCK - 1),
        (0, BLOCK),
        (0, BLOCK + 1),
        (BLOCK, 0),
        (BLOCK + 1, 0),
        (BLOCK, BLOCK),
        (13, 2 * BLOCK),
        (13, 2 * BLOCK + 1),
        (300, 500),
    ];
    for &(adl, ml) in grid {
        let ad: Vec<u8> = ptn(adl).iter().map(|b| b ^ 0x5C).collect();
        let pt = ptn(ml);
        let mut ct = vec![0u8; ml + TAG_BYTES];
        encrypt(&key, &nonce, &ad, &pt, &mut ct).expect("seal");
        let mut back = vec![0u8; ml];
        decrypt(&key, &nonce, &ad, &ct, &mut back).expect("open");
        assert_eq!(back, pt);
        out.push(format!(
            "    {{\"id\": \"seal_ad{adl}_msg{ml}\", \"description\": \"Seal, AD {adl} bytes, message {ml} bytes\", \"inputs\": {{\"key_hex\": \"{}\", \"nonce_hex\": \"{}\", \"ad_hex\": \"{}\", \"plaintext_hex\": \"{}\"}}, \"outputs\": {{\"ciphertext_and_tag_hex\": \"{}\"}}, \"negative\": false, \"references\": [\"aead-id-17-turboshake-duplex-v0.md#construction\"]}}",
            hex(&key), hex(&nonce), hex(&ad), hex(&pt), hex(&ct)
        ));
    }

    // Second key and nonce: the same grid shape would only repeat the block
    // logic, so these cover the key/nonce absorption with a few lengths across the boundary.
    let key2: [u8; 32] = core::array::from_fn(|i| 0xFF - (i as u8).wrapping_mul(7));
    let nonce2_seal: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x1D) ^ 0x3C);
    let mut init2 = [0u8; 32];
    init_state_prefix(&key2, &nonce2_seal, &mut init2);
    out.push(format!(
        "    {{\"id\": \"init_state_key2\", \"description\": \"Initialization call under the second key and nonce\", \"inputs\": {{\"key_hex\": \"{}\", \"nonce_hex\": \"{}\"}}, \"outputs\": {{\"state_prefix_hex\": \"{}\"}}, \"negative\": false, \"references\": [\"aead-id-17-turboshake-duplex-v0.md#initialization\"]}}",
        hex(&key2), hex(&nonce2_seal), hex(&init2)
    ));
    for &(adl, ml) in &[(0usize, 0usize), (7, BLOCK + 1), (BLOCK, 2 * BLOCK + 1)] {
        let ad: Vec<u8> = ptn(adl).iter().map(|b| b ^ 0xA3).collect();
        let pt = ptn(ml);
        let mut ct = vec![0u8; ml + TAG_BYTES];
        encrypt(&key2, &nonce2_seal, &ad, &pt, &mut ct).expect("seal");
        let mut back = vec![0u8; ml];
        decrypt(&key2, &nonce2_seal, &ad, &ct, &mut back).expect("open");
        assert_eq!(back, pt);
        out.push(format!(
            "    {{\"id\": \"seal_key2_ad{adl}_msg{ml}\", \"description\": \"Seal under the second key and nonce, AD {adl} bytes, message {ml} bytes\", \"inputs\": {{\"key_hex\": \"{}\", \"nonce_hex\": \"{}\", \"ad_hex\": \"{}\", \"plaintext_hex\": \"{}\"}}, \"outputs\": {{\"ciphertext_and_tag_hex\": \"{}\"}}, \"negative\": false, \"references\": [\"aead-id-17-turboshake-duplex-v0.md#construction\"]}}",
            hex(&key2), hex(&nonce2_seal), hex(&ad), hex(&pt), hex(&ct)
        ));
    }

    // Negative cases: each is a valid (ad, ciphertext) pair from seal_ad13_msg269 with one change.
    let ad: Vec<u8> = ptn(13).iter().map(|b| b ^ 0x5C).collect();
    let pt = ptn(2 * BLOCK + 1);
    let mut ct = vec![0u8; pt.len() + TAG_BYTES];
    encrypt(&key, &nonce, &ad, &pt, &mut ct).expect("seal");
    let mut flip_tag = ct.clone();
    *flip_tag.last_mut().unwrap() ^= 0x01;
    let mut flip_body = ct.clone();
    flip_body[BLOCK] ^= 0x80;
    let mut ad2 = ad.clone();
    ad2[0] ^= 0x01;
    let mut nonce2 = nonce;
    nonce2[15] ^= 0x01;
    let negs: Vec<Negative> = vec![
        (
            "negative_tag_bit",
            "Last tag bit flipped",
            nonce,
            ad.clone(),
            flip_tag,
        ),
        (
            "negative_body_bit",
            "Top bit of the first byte of the second block flipped",
            nonce,
            ad.clone(),
            flip_body,
        ),
        (
            "negative_ad_changed",
            "First AD byte changed",
            nonce,
            ad2,
            ct.clone(),
        ),
        (
            "negative_nonce_changed",
            "Last nonce byte changed",
            nonce2,
            ad.clone(),
            ct.clone(),
        ),
        (
            "negative_truncated",
            "Ciphertext one byte short (tag truncated)",
            nonce,
            ad.clone(),
            ct[..ct.len() - 1].to_vec(),
        ),
        (
            "negative_ad_moved_into_message",
            "Empty AD and the 13 AD bytes prepended to the ciphertext",
            nonce,
            Vec::new(),
            [ad.clone(), ct.clone()].concat(),
        ),
        (
            "negative_key_changed",
            "Opened under the second key instead of the sealing key",
            nonce,
            ad.clone(),
            ct.clone(),
        ),
    ];
    for (id, d, n, a, c) in negs {
        let k = if id == "negative_key_changed" {
            key2
        } else {
            key
        };
        let mut sink = vec![0u8; c.len().saturating_sub(TAG_BYTES)];
        assert!(
            decrypt(&k, &n, &a, &c, &mut sink).is_err(),
            "{id} must fail"
        );
        out.push(format!(
            "    {{\"id\": \"{id}\", \"description\": \"{d}; open MUST fail and release no plaintext\", \"inputs\": {{\"key_hex\": \"{}\", \"nonce_hex\": \"{}\", \"ad_hex\": \"{}\", \"ciphertext_and_tag_hex\": \"{}\"}}, \"outputs\": {{\"error\": \"AuthenticationFailed\"}}, \"negative\": true, \"references\": [\"aead-id-17-turboshake-duplex-v0.md#decryption\"]}}",
            hex(&k), hex(&n), hex(&a), hex(&c)
        ));
    }

    println!("{{");
    println!("  \"spec_version\": \"aead-id-17-turboshake-duplex-v0\",");
    println!("  \"generator\": \"libQ lib-q-duplex-aead example dump_turboshake_duplex_kat\",");
    println!("  \"vectors\": [");
    println!("{}", out.join(",\n"));
    println!("  ]");
    println!("}}");
}
