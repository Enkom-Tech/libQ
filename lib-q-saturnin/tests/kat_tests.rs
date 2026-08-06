//! Known Answer Tests for Saturnin algorithms

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    AeadKey,
    Nonce,
    Result,
};
use lib_q_saturnin::*;

/// Parse hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars().peekable();

    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();
        bytes.push(byte);
    }

    bytes
}

/// Test AEAD KAT vectors
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_aead_kat() -> Result<()> {
    let aead = SaturninAead::new();

    // Test vectors from CTR-Cascade KAT file
    let test_cases = vec![
        // Empty plaintext, empty AD
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F",
            "",
            "",
            "BA6F18356B82C46910FE1738E72D99A43250269B8FE631CE0C1C6A38A5AFC6CB",
        ),
        // Empty plaintext, 1-byte AD
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F",
            "",
            "00",
            "A28C65EEEC626E92AAC152D90DB423EED31DCF4250CA5EB99D61658831DE5F98",
        ),
        // Empty plaintext, 2-byte AD
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F",
            "",
            "0001",
            "314B94BCB3A18CC867449BB06178E993528987C062DF2F7198EF4737EA1D9E5D",
        ),
        // Empty plaintext, 3-byte AD
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F",
            "",
            "000102",
            "A0A99EE21FED92166DA478310C15296C81A1B1F497899576AF6E68524722E6EF",
        ),
        // Empty plaintext, 4-byte AD
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F",
            "",
            "00010203",
            "86B60D4429A5249FF5CCD3DC9B98C767A6240256B0DDD278BCF0EF94E95F116B",
        ),
        // 1-byte plaintext, empty AD
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F",
            "00",
            "",
            "73C935ACB3FF171F54D63C3C682C713190AB0618EFF0CE7B79434E3347497CF0E8",
        ),
    ];

    for (key_hex, nonce_hex, pt_hex, ad_hex, expected_ct_hex) in test_cases {
        let key = AeadKey::new(hex_to_bytes(key_hex));
        let nonce = Nonce::new(hex_to_bytes(nonce_hex));
        let plaintext = hex_to_bytes(pt_hex);
        let expected_ciphertext = hex_to_bytes(expected_ct_hex);

        // Test encryption
        let ciphertext = if ad_hex.is_empty() {
            aead.encrypt(&key, &nonce, &plaintext, None)?
        } else {
            let ad_vec = hex_to_bytes(ad_hex);
            aead.encrypt(&key, &nonce, &plaintext, Some(&ad_vec))?
        };

        assert_eq!(
            ciphertext, expected_ciphertext,
            "Encryption failed for test case"
        );

        // Test decryption
        let decrypted = if ad_hex.is_empty() {
            aead.decrypt(&key, &nonce, &ciphertext, None)?
        } else {
            let ad_vec = hex_to_bytes(ad_hex);
            aead.decrypt(&key, &nonce, &ciphertext, Some(&ad_vec))?
        };

        assert_eq!(decrypted, plaintext, "Decryption failed for test case");
    }

    Ok(())
}

/// Official LWC KAT file for `saturninctrcascadev2` (NIST LWC round-2 submission, the
/// general Saturnin-CTR-Cascade AEAD tested via `test_aead_kat` above). Vendored under
/// `tests/fixtures/`: a byte-for-byte copy of the reference distribution's
/// `saturninctrcascadev2/LWC_AEAD_KAT_256_128.txt` (1089 vectors; plaintext and
/// associated-data lengths each range 0..=32 bytes). Diffed against
/// `reference/saturnin/...` on vendoring.
///
/// Provenance pin — upstream
/// `reference/saturnin/Implementations/crypto_aead/saturninctrcascadev2/LWC_AEAD_KAT_256_128.txt`
/// (NIST LWC round-2 Saturnin submission, gitignored in this repo) has
/// `sha256 = 1bda041286ecb3e8f6356034d878f135a86361a15275b77bc93a530cc6c96aec`, and the vendored
/// copy hashed identically at vendoring time. Re-verify with
/// `sha256sum <upstream> lib-q-saturnin/tests/fixtures/LWC_AEAD_KAT_256_128_saturninctrcascadev2.txt`.
/// The hash is over the upstream LF bytes; a Windows checkout with `core.autocrlf=true`
/// materialises CRLF and will hash differently — compare with `diff --strip-trailing-cr` there.
/// These bytes are the designers' own output and must never be regenerated from this crate.
#[cfg(all(feature = "alloc", feature = "aead"))]
const SATURNIN_AEAD_LWC_KAT: &str =
    include_str!("fixtures/LWC_AEAD_KAT_256_128_saturninctrcascadev2.txt");

/// One official AEAD KAT case: `(key, nonce, plaintext, associated_data, expected_ct)`.
#[cfg(all(feature = "alloc", feature = "aead"))]
type AeadKatCase = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Parse `LWC_AEAD_KAT_256_128.txt` (ctr-cascade variant) blocks into
/// `(key, nonce, pt, ad, expected_ct)` tuples. Unlike the Saturnin-Short parser,
/// associated data is not required to be empty here.
#[cfg(all(feature = "alloc", feature = "aead"))]
fn parse_saturnin_aead_lwc_kat(data: &str) -> Vec<AeadKatCase> {
    let mut out = Vec::new();
    let mut key = Vec::new();
    let mut nonce = Vec::new();
    let mut pt = Vec::new();
    let mut ad = Vec::new();
    let mut ct = Vec::new();
    let mut have_block = false;

    for line in data.lines() {
        // NOTE: do not `.trim()` this line — an empty-valued field is written as
        // `"Field = "` (trailing space, nothing after); trimming it strips that
        // trailing space too and `strip_prefix("Field = ")` then silently fails to
        // match, dropping the whole record. `str::lines()` already strips the
        // line terminator (including a trailing `\r`), so the raw line is safe to
        // match against directly.
        if line.is_empty() {
            if have_block && key.len() == 32 && nonce.len() == 16 {
                out.push((
                    key.clone(),
                    nonce.clone(),
                    pt.clone(),
                    ad.clone(),
                    ct.clone(),
                ));
            }
            key.clear();
            nonce.clear();
            pt.clear();
            ad.clear();
            ct.clear();
            have_block = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("Key = ") {
            key = hex_to_bytes(rest);
            have_block = true;
        } else if let Some(rest) = line.strip_prefix("Nonce = ") {
            nonce = hex_to_bytes(rest);
        } else if let Some(rest) = line.strip_prefix("PT = ") {
            pt = hex_to_bytes(rest);
        } else if let Some(rest) = line.strip_prefix("AD = ") {
            ad = hex_to_bytes(rest);
        } else if let Some(rest) = line.strip_prefix("CT = ") {
            ct = hex_to_bytes(rest);
        }
    }
    if have_block && key.len() == 32 && nonce.len() == 16 {
        out.push((key, nonce, pt, ad, ct));
    }
    out
}

/// All 1089 vectors from the official reference `LWC_AEAD_KAT_256_128.txt`
/// (`saturninctrcascadev2`).
///
/// This is the live enforcement of the provenance claim on the vendored fixture:
/// previously `tests/kat_aead.txt` made the same claim but was never read by any
/// test, and 3 of its 10 records (Count 8..10) turned out to be a fabricated filler
/// pattern with metadata that didn't even match the real reference record at that
/// Count. That file has been deleted; this test reads the real, diffed-verbatim
/// reference file instead.
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_aead_kat_full_official_vectors() -> Result<()> {
    let aead = SaturninAead::new();
    let cases = parse_saturnin_aead_lwc_kat(SATURNIN_AEAD_LWC_KAT);
    assert_eq!(
        cases.len(),
        1089,
        "expected all 1089 official Saturnin-AEAD (ctr-cascade) KAT vectors"
    );

    for (count, (key_bytes, nonce_bytes, pt, ad, expected_ct)) in cases.into_iter().enumerate() {
        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let ad_opt = if ad.is_empty() {
            None
        } else {
            Some(ad.as_slice())
        };

        let ciphertext = aead.encrypt(&key, &nonce, &pt, ad_opt)?;
        assert_eq!(
            ciphertext,
            expected_ct,
            "encrypt mismatch at official KAT Count={} (pt len {}, ad len {})",
            count + 1,
            pt.len(),
            ad.len()
        );

        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, ad_opt)?;
        assert_eq!(
            decrypted,
            pt,
            "decrypt mismatch at official KAT Count={}",
            count + 1
        );
    }

    Ok(())
}

/// Official LWC KAT file for `saturninshortv2` (NIST LWC round-2 submission; AD always empty).
/// Vendored under `tests/fixtures/`.
#[cfg(all(feature = "alloc", feature = "aead-short"))]
const SATURNIN_SHORT_LWC_KAT: &str =
    include_str!("fixtures/LWC_AEAD_KAT_256_128_saturninshortv2.txt");

/// One official KAT case: key, nonce, plaintext, expected ciphertext (32 bytes).
#[cfg(all(feature = "alloc", feature = "aead-short"))]
type ShortKatCase = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Parse `LWC_AEAD_KAT_256_128.txt` blocks into `(key, nonce, plaintext, expected_ct)` tuples.
#[cfg(all(feature = "alloc", feature = "aead-short"))]
fn parse_saturnin_short_lwc_kat(data: &str) -> Vec<ShortKatCase> {
    let mut out = Vec::new();
    let mut key = Vec::new();
    let mut nonce = Vec::new();
    let mut pt = Vec::new();
    let mut ad = String::new();
    let mut ct = Vec::new();
    let mut have_block = false;

    for line in data.lines() {
        // NOTE: do not `.trim()` this line — an empty-valued field is written as
        // `"Field = "` (trailing space, nothing after); trimming it strips that
        // trailing space too and `strip_prefix("Field = ")` then silently fails to
        // match, dropping the whole record. `str::lines()` already strips the
        // line terminator (including a trailing `\r`), so the raw line is safe to
        // match against directly.
        if line.is_empty() {
            if have_block && key.len() == 32 && nonce.len() == 16 && ct.len() == 32 {
                assert!(
                    ad.is_empty(),
                    "Saturnin-Short KAT must have empty AD, got {ad:?}"
                );
                out.push((key.clone(), nonce.clone(), pt.clone(), ct.clone()));
            }
            key.clear();
            nonce.clear();
            pt.clear();
            ad.clear();
            ct.clear();
            have_block = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("Key = ") {
            key = hex_to_bytes(rest);
            have_block = true;
        } else if let Some(rest) = line.strip_prefix("Nonce = ") {
            nonce = hex_to_bytes(rest);
        } else if let Some(rest) = line.strip_prefix("PT = ") {
            pt = hex_to_bytes(rest);
        } else if let Some(rest) = line.strip_prefix("AD = ") {
            ad = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("CT = ") {
            ct = hex_to_bytes(rest);
        }
    }
    if have_block && key.len() == 32 && nonce.len() == 16 && ct.len() == 32 {
        assert!(
            ad.is_empty(),
            "Saturnin-Short KAT must have empty AD, got {ad:?}"
        );
        out.push((key, nonce, pt, ct));
    }
    out
}

/// All 16 vectors from reference `LWC_AEAD_KAT_256_128.txt` (plaintext lengths 0..=15 bytes).
#[cfg(all(feature = "alloc", feature = "aead-short"))]
#[test]
fn test_aead_short_kat() -> Result<()> {
    let aead = SaturninShortAead::new();
    let cases = parse_saturnin_short_lwc_kat(SATURNIN_SHORT_LWC_KAT);
    assert_eq!(
        cases.len(),
        16,
        "expected 16 official Saturnin-Short KAT cases"
    );

    for (key_bytes, nonce_bytes, plaintext, expected_ciphertext) in cases {
        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);

        let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None)?;
        assert_eq!(
            ciphertext,
            expected_ciphertext,
            "encrypt mismatch for {}-byte plaintext",
            plaintext.len()
        );

        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
        assert_eq!(decrypted, plaintext);
    }

    Ok(())
}

/// Official LWC KAT file for `saturninhashv2` (NIST LWC round-2 submission).
/// Vendored under `tests/fixtures/`: a byte-for-byte copy of the reference
/// distribution's `saturninhashv2/LWC_HASH_KAT_256.txt` (1025 vectors, message
/// lengths 0..=1024 bytes). Diffed against `reference/saturnin/...` on vendoring.
///
/// Provenance pin — upstream
/// `reference/saturnin/Implementations/crypto_hash/saturninhashv2/LWC_HASH_KAT_256.txt`
/// (NIST LWC round-2 Saturnin submission, gitignored in this repo) has
/// `sha256 = c5d45e76325766f330070434cc24fb6ca7bab151df9707f2327247806acc7e52`, and the vendored
/// copy hashed identically at vendoring time. Re-verify with
/// `sha256sum <upstream> lib-q-saturnin/tests/fixtures/LWC_HASH_KAT_256_saturninhashv2.txt`.
/// The hash is over the upstream LF bytes; a Windows checkout with `core.autocrlf=true`
/// materialises CRLF and will hash differently — compare with `diff --strip-trailing-cr` there.
/// These bytes are the designers' own output and must never be regenerated from this crate.
#[cfg(all(feature = "alloc", feature = "hash"))]
const SATURNIN_HASH_LWC_KAT: &str = include_str!("fixtures/LWC_HASH_KAT_256_saturninhashv2.txt");

/// One official hash KAT case: `(message, expected_digest)`.
#[cfg(all(feature = "alloc", feature = "hash"))]
type HashKatCase = (Vec<u8>, Vec<u8>);

/// Parse `LWC_HASH_KAT_256.txt` blocks into `(msg, expected_md)` tuples.
#[cfg(all(feature = "alloc", feature = "hash"))]
fn parse_saturnin_hash_lwc_kat(data: &str) -> Vec<HashKatCase> {
    let mut out = Vec::new();
    let mut msg = Vec::new();
    let mut md = Vec::new();
    let mut have_block = false;

    for line in data.lines() {
        // NOTE: do not `.trim()` this line — an empty-valued field is written as
        // `"Field = "` (trailing space, nothing after); trimming it strips that
        // trailing space too and `strip_prefix("Field = ")` then silently fails to
        // match, dropping the whole record. `str::lines()` already strips the
        // line terminator (including a trailing `\r`), so the raw line is safe to
        // match against directly.
        if line.is_empty() {
            if have_block {
                out.push((msg.clone(), md.clone()));
            }
            msg.clear();
            md.clear();
            have_block = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("Msg = ") {
            msg = hex_to_bytes(rest);
            have_block = true;
        } else if let Some(rest) = line.strip_prefix("MD = ") {
            md = hex_to_bytes(rest);
        }
        // "Count = N" lines are ignored; block order is preserved instead.
    }
    if have_block {
        out.push((msg, md));
    }
    out
}

/// All 1025 vectors from the official reference `LWC_HASH_KAT_256.txt`.
///
/// This is the live enforcement of the provenance claim on the vendored fixture:
/// previously `tests/kat_hash.txt` made the same claim but was never read by any
/// test, and about 40% of its records (Count 13..20) turned out to be a fabricated
/// filler pattern, not real digests. That file has been deleted; this test reads
/// the real, diffed-verbatim reference file instead.
#[cfg(all(feature = "alloc", feature = "hash"))]
#[test]
fn test_hash_kat_full_official_vectors() -> Result<()> {
    let hash = SaturninHash::new();
    let cases = parse_saturnin_hash_lwc_kat(SATURNIN_HASH_LWC_KAT);
    assert_eq!(
        cases.len(),
        1025,
        "expected all 1025 official Saturnin-Hash KAT vectors"
    );

    for (count, (msg, expected_md)) in cases.into_iter().enumerate() {
        let digest = hash.hash(&msg)?;
        assert_eq!(
            digest,
            expected_md,
            "hash mismatch at official KAT Count={} (msg len {})",
            count + 1,
            msg.len()
        );
    }

    Ok(())
}

/// Test Hash KAT vectors
#[cfg(all(feature = "alloc", feature = "hash"))]
#[test]
fn test_hash_kat() -> Result<()> {
    let hash = SaturninHash::new();

    // Test vectors from reference KAT file
    let test_cases = vec![
        // Empty message
        (
            "",
            "83B15641B09569B04C606108FC8AE268AC0DC9288741B5735D8612D69C0AFDFE",
        ),
        // 1-byte message
        (
            "00",
            "E6B4434E7CD8CA452A28435C0C29A748AF906B827EDD7A7C714461A4EEE4CACB",
        ),
        // 2-byte message
        (
            "0001",
            "ED9A67306E55AC23D8A5FF664DAF0AC2695BEE8CD210AE5F01ED3F419344AECF",
        ),
        // 3-byte message
        (
            "000102",
            "7D03A7714D0031A707473EE8E132A8842BD801A653CD8820E8603AAC58325FDE",
        ),
        // 4-byte message
        (
            "00010203",
            "30D5739EC8A363BFE756039E18711E81982064DDA835302913406C9A104348E1",
        ),
        // 5-byte message
        (
            "0001020304",
            "9FEE77E397511868F9C768050F175D2A5DF99D8FC0F3DCEA59AB5A098AC71431",
        ),
        // 6-byte message
        (
            "000102030405",
            "1C3051A62544260168692714F2278B67297E9FAD86D83D5256B81475DE1A64FA",
        ),
        // 7-byte message
        (
            "00010203040506",
            "F83D8453387AE1DC9C282A23E3F57B0DBCAC6DE65EAD342D07CB12073A0AA11D",
        ),
        // 8-byte message
        (
            "0001020304050607",
            "38A334A6F095A785074999D0631685754551E25B1586A4CCCC7CB14F63714D2B",
        ),
        // 9-byte message
        (
            "000102030405060708",
            "9BD95972187400543DD54E47AA3A6AE1526EE91F8D3D94390268B543C39F1DF7",
        ),
        // 10-byte message
        (
            "00010203040506070809",
            "11C0ACE254EFA575F822F35248150B9FFF5F64DA51AEA69C4819A0EDBE8E53A6",
        ),
    ];

    for (msg_hex, expected_hash_hex) in test_cases {
        let message = hex_to_bytes(msg_hex);
        let expected_hash = hex_to_bytes(expected_hash_hex);

        let hash_output = hash.hash(&message)?;
        assert_eq!(
            hash_output, expected_hash,
            "Hash failed for test case: {}",
            msg_hex
        );
    }

    Ok(())
}

/// Test Block Cipher KAT vectors
#[cfg(all(feature = "alloc", feature = "block-cipher"))]
#[test]
fn test_block_cipher_kat() -> Result<()> {
    let cipher = SaturninBlockCipher::new();

    // Test vectors generated from our implementation
    let test_cases = vec![(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "260BBB94E535833FC815EDF37E2FB9907B2264697D3C98398093C83F2B127110",
    )];

    for (key_hex, plaintext_hex, expected_ciphertext_hex) in test_cases {
        let key = hex_to_bytes(key_hex);
        let plaintext = hex_to_bytes(plaintext_hex);
        let expected_ciphertext = hex_to_bytes(expected_ciphertext_hex);

        // Test encryption
        let ciphertext = cipher.encrypt_block(&key, &plaintext)?;
        assert_eq!(ciphertext, expected_ciphertext, "Block encryption failed");

        // Test decryption
        let decrypted = cipher.decrypt_block(&key, &ciphertext)?;
        assert_eq!(decrypted, plaintext, "Block decryption failed");
    }

    Ok(())
}
