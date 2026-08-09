//! Saturnin-SIV known-answer tests against `tests/vectors/saturnin_siv_kat.txt`.
//!
//! # Provenance, stated plainly
//!
//! These vectors are **self-generated**: Saturnin-SIV is assembled in this repository, so no
//! upstream reference implementation and no external vector set exists for it. They are a
//! REGRESSION PIN — they prove that this crate keeps producing the bytes it produced on the day
//! they were frozen, and they prove nothing whatever about agreement with any third party. The
//! same statement is in the vector file's own header and in `kats-manifest.toml`
//! (`origin = "self-generated"`).
//!
//! Regenerate deliberately, never silently:
//!
//! ```text
//! cargo test -p lib-q-aead --features saturnin-siv --test saturnin_siv_kat \
//!     -- --ignored --nocapture regenerate_vectors
//! ```
//!
//! then paste the printed file and update the `sha256` in `kats-manifest.toml`. A regeneration
//! that changes any existing line is a WIRE-FORMAT BREAK, not a test fix.

#![cfg(feature = "saturnin-siv")]

use lib_q_aead::saturnin_siv::SaturninSiv;

const VECTORS: &str = include_str!("vectors/saturnin_siv_kat.txt");

#[derive(Default)]
struct Vector {
    count: usize,
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
}

/// Parse the `key = ...` / `nonce = ...` / ... blocks, one blank-line-separated record each.
fn parse(text: &str) -> Vec<Vector> {
    let mut out: Vec<Vector> = Vec::new();
    let mut cur: Option<Vector> = None;

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (field, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("line {}: no '=' in {line:?}", lineno + 1));
        let field = field.trim();
        let value = value.trim();
        let bytes = || {
            hex::decode(value)
                .unwrap_or_else(|e| panic!("line {}: bad hex {value:?}: {e}", lineno + 1))
        };

        match field {
            "count" => {
                if let Some(v) = cur.take() {
                    out.push(v);
                }
                let n = value
                    .parse()
                    .unwrap_or_else(|e| panic!("line {}: bad count {value:?}: {e}", lineno + 1));
                cur = Some(Vector {
                    count: n,
                    ..Vector::default()
                });
            }
            "key" | "nonce" | "ad" | "pt" | "ct" => {
                let v = cur
                    .as_mut()
                    .unwrap_or_else(|| panic!("line {}: field before any count", lineno + 1));
                let b = bytes();
                match field {
                    "key" => v.key = b,
                    "nonce" => v.nonce = b,
                    "ad" => v.ad = b,
                    "pt" => v.pt = b,
                    _ => v.ct = b,
                }
            }
            other => panic!("line {}: unknown field {other:?}", lineno + 1),
        }
    }
    if let Some(v) = cur.take() {
        out.push(v);
    }
    out
}

#[test]
fn the_vector_file_is_not_empty_and_covers_the_block_boundary() {
    let vectors = parse(VECTORS);
    assert!(
        vectors.len() >= 6,
        "expected at least 6 KAT vectors, parsed {} — a KAT file that shrank is a KAT file that \
         stopped testing something",
        vectors.len()
    );

    let lengths: Vec<usize> = vectors.iter().map(|v| v.pt.len()).collect();
    for required in [0usize, 32, 33] {
        assert!(
            lengths.contains(&required),
            "no vector with a {required}-byte plaintext; lengths present: {lengths:?}. The \
             32-byte Saturnin block boundary must be covered on both sides."
        );
    }
    assert!(
        vectors.iter().any(|v| v.nonce.is_empty()),
        "no vector exercises the empty nonce"
    );
    assert!(
        vectors.iter().any(|v| !v.ad.is_empty()),
        "no vector exercises a non-empty AD"
    );
}

#[test]
fn encryption_reproduces_every_pinned_ciphertext() {
    let siv = SaturninSiv::new();
    for v in parse(VECTORS) {
        let got = siv
            .seal(&v.key, &v.nonce, &v.pt, &v.ad)
            .unwrap_or_else(|e| panic!("vector {}: seal failed: {e}", v.count));
        assert_eq!(
            hex::encode(&got),
            hex::encode(&v.ct),
            "vector {}: ciphertext differs from the pinned value. If this change is intended it \
             is a WIRE-FORMAT BREAK for Saturnin-SIV, not a test to update.",
            v.count
        );
    }
}

#[test]
fn decryption_recovers_every_pinned_plaintext() {
    let siv = SaturninSiv::new();
    for v in parse(VECTORS) {
        let got = siv
            .open(&v.key, &v.nonce, &v.ct, &v.ad)
            .unwrap_or_else(|e| panic!("vector {}: open failed: {e}", v.count));
        assert_eq!(
            hex::encode(&got),
            hex::encode(&v.pt),
            "vector {}: decryption did not recover the pinned plaintext",
            v.count
        );
    }
}

#[test]
fn every_pinned_vector_rejects_a_flipped_tag_byte() {
    // Keeps the KAT file from degenerating into a pure encode-check: each pinned ciphertext must
    // also still be *authenticated*.
    let siv = SaturninSiv::new();
    for v in parse(VECTORS) {
        let mut bad = v.ct.clone();
        bad[0] ^= 1;
        assert!(
            siv.open(&v.key, &v.nonce, &bad, &v.ad).is_err(),
            "vector {}: a flipped tag bit was accepted",
            v.count
        );
    }
}

/// Regenerate the vector file. Ignored by default; see this file's header.
#[test]
#[ignore = "regenerates tests/vectors/saturnin_siv_kat.txt; run deliberately"]
fn regenerate_vectors() {
    let siv = SaturninSiv::new();
    /// `(key, nonce, ad, plaintext)`.
    type Case = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    let cases: Vec<Case> = vec![
        (vec![0u8; 32], vec![0u8; 16], vec![], vec![]),
        (vec![0u8; 32], vec![], vec![], b"a".to_vec()),
        (
            (0..32u8).collect(),
            (0xA0..0xB0u8).collect(),
            b"associated-data".to_vec(),
            b"Hello, Saturnin-SIV!".to_vec(),
        ),
        (
            (0..32u8).map(|i| i ^ 0xFF).collect(),
            (0..16u8).collect(),
            vec![0xAB; 40],
            (0..32u8).collect(),
        ),
        (
            vec![0x5A; 32],
            vec![0x11; 16],
            b"hdr".to_vec(),
            (0..33u8).collect(),
        ),
        (
            vec![0xF0; 32],
            vec![0x0F; 64],
            (0..200u8).collect(),
            (0..200u8).map(|i| i.wrapping_mul(3)).collect(),
        ),
    ];

    let mut s = String::new();
    s.push_str(
        "# Saturnin-SIV known-answer vectors -- origin: self-generated.\n\
         #\n\
         # PRODUCED BY THE CODE UNDER TEST. These are a regression pin for lib-q-aead's\n\
         # SaturninSiv (256-bit deterministic, nonce-misuse-resistant AEAD assembled in this\n\
         # repository from Saturnin-CTR + KMAC256). Saturnin-SIV has no upstream reference\n\
         # implementation and no external vector set, so these vectors are self-generated and\n\
         # carry NO third-party conformance evidence whatsoever -- they show only that this\n\
         # crate still produces the bytes it produced when they were frozen.\n\
         #\n\
         # Generator: lib-q-aead/tests/saturnin_siv_kat.rs::regenerate_vectors\n\
         #   cargo test -p lib-q-aead --features saturnin-siv --test saturnin_siv_kat \\\n\
         #       -- --ignored --nocapture regenerate_vectors\n\
         # A change to any existing line here is a WIRE-FORMAT BREAK, not a test fix.\n\
         #\n\
         # Fields are hex; `ct` is tag(32 bytes) || body.\n",
    );

    for (i, (key, nonce, ad, pt)) in cases.iter().enumerate() {
        let ct = siv.seal(key, nonce, pt, ad).expect("seal");
        let back = siv.open(key, nonce, &ct, ad).expect("open");
        assert_eq!(&back, pt, "vector {i} does not round-trip");

        s.push_str(&format!("\ncount = {i}\n"));
        s.push_str(&format!("key = {}\n", hex::encode(key)));
        s.push_str(&format!("nonce = {}\n", hex::encode(nonce)));
        s.push_str(&format!("ad = {}\n", hex::encode(ad)));
        s.push_str(&format!("pt = {}\n", hex::encode(pt)));
        s.push_str(&format!("ct = {}\n", hex::encode(&ct)));
    }

    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/saturnin_siv_kat.txt"
        ),
        &s,
    )
    .expect("write vector file");
    println!("wrote {} bytes of vectors", s.len());
}
