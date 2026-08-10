//! Byte-exact conformance against the HQC v5.0.0 designers' own reference implementation.
//!
//! This is the crate's only EXTERNAL assurance. Everything else under `kats/` is a regression pin:
//! self-generated output that pins this implementation against itself and therefore cannot detect
//! a misreading of the specification, only a change of behaviour.
//!
//! The vectors are `kats/upstream-reference/hqc-{1,3,5}/intermediates_values`, vendored
//! byte-for-byte from <https://gitlab.com/pqc-hqc/hqc> v5.0.0. See that directory's
//! `PROVENANCE.md` for why these files and not the `.rsp` KATs that sit beside them upstream (the
//! short version: the `.rsp` files are NIST-harness output where the printed seed is fed to
//! AES-CTR-DRBG, so they can never match this crate's direct-seed path, and upstream's own two
//! files disagree with each other for exactly that reason).
//!
//! These vectors are not decorative. They caught three separate fixed-weight-sampling bugs that
//! every self-generated pin in this crate had happily pinned (card t_62273504, fixed at 113377f):
//! a big-endian 24-bit candidate where the reference is little-endian, an `xof_get_bytes` that
//! discarded stream bytes on unaligned requests, and per-vector buffering where the reference
//! draws exactly 3 bytes per attempt.

#![cfg(all(feature = "alloc", feature = "hqc"))]

use lib_q_hqc::hqc_kem::HqcKem;
use lib_q_hqc::hqc_pke::HqcPke;
use lib_q_hqc::internal::shake256::Shake256Xof;
use lib_q_hqc::params::HqcParams;
use lib_q_hqc::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex field");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Pull a `name: <hex>` field from the reference dump.
fn field(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("reference dump has no `{name}` field"))
        .trim()
        .to_string()
}

/// The crate stores ring elements as `u64` limbs; the wire form is little-endian truncated to
/// `VEC_N_SIZE_BYTES`, which is how the reference prints them.
fn limbs_to_bytes(v: &[u64], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for w in v {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.truncate(n);
    out
}

fn dump_for(set: &str) -> String {
    let path = format!("kats/upstream-reference/{set}/intermediates_values");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// Compare every keygen intermediate this crate can reproduce against the reference dump.
///
/// Checks the components separately rather than only the final public key. A single `pk`
/// comparison tells you that something is wrong; these tell you *which stage*, which is exactly
/// what made t_62273504 tractable (seed derivation and `h` were correct, the sampler was not).
fn assert_keygen_matches<P: HqcParams>(set: &str) {
    let iv = dump_for(set);
    let seed_ek = hex(&field(&iv, "seed_ek"));
    let seed_dk = hex(&field(&iv, "seed_dk"));
    let want_h = hex(&field(&iv, "h"));
    let want_x = hex(&field(&iv, "x"));
    let want_y = hex(&field(&iv, "y"));
    let want_s = hex(&field(&iv, "s"));

    let n = P::VEC_N_SIZE_BYTES;
    assert_eq!(
        want_h.len(),
        n,
        "{set}: reference h is not VEC_N_SIZE_BYTES"
    );

    let pke = HqcPke::<P>::new().expect("HqcPke::new");

    // h is expanded from seed_ek.
    let mut ek_xof = Shake256Xof::new();
    ek_xof.init_with_domain(&seed_ek, 1).expect("xof init");
    let mut h = vec![0u64; P::VEC_N_SIZE_64];
    pke.vect_set_random(&mut ek_xof, &mut h).expect("h");
    assert_eq!(
        limbs_to_bytes(&h, n),
        want_h,
        "{set}: h diverges from the reference (XOF-to-ring expansion)"
    );

    // y then x, both drawn from the same context seeded by seed_dk, in that order.
    let mut dk_xof = Shake256Xof::new();
    dk_xof.init_with_domain(&seed_dk, 1).expect("xof init");
    let mut y = vec![0u64; P::VEC_N_SIZE_64];
    let mut x = vec![0u64; P::VEC_N_SIZE_64];
    pke.vect_sample_fixed_weight1(&mut dk_xof, &mut y, P::OMEGA)
        .expect("y");
    pke.vect_sample_fixed_weight1(&mut dk_xof, &mut x, P::OMEGA)
        .expect("x");

    // Weight first: a wrong weight is a different (worse) defect from wrong positions, and saying
    // so in the failure message saves the next person a bisect.
    let weight = |b: &[u8]| b.iter().map(|v| v.count_ones()).sum::<u32>();
    assert_eq!(
        weight(&limbs_to_bytes(&y, n)),
        P::OMEGA as u32,
        "{set}: y has the wrong Hamming weight, which is a sampling-correctness defect, \
         not merely a conformance one"
    );
    assert_eq!(
        limbs_to_bytes(&y, n),
        want_y,
        "{set}: y diverges from the reference (fixed-weight sampling, first draw)"
    );
    assert_eq!(
        limbs_to_bytes(&x, n),
        want_x,
        "{set}: x diverges from the reference (fixed-weight sampling, second draw -- if y \
         matched and x did not, suspect XOF stream over-consumption between the two draws)"
    );

    let _ = want_s;
}

/// End-to-end through the public API: the 48-byte KAT seed in, the reference's `s` out.
///
/// `assert_keygen_matches` exercises the internals directly; this one proves the public entry
/// point wires them together the same way, so a future refactor cannot pass the component checks
/// while shipping a different key.
fn assert_public_keygen_matches<P: HqcParams>(set: &str) {
    let iv = dump_for(set);
    let want_s = hex(&field(&iv, "s"));

    // `HqcKem::keygen_with_seed` takes the 48-byte KAT seed and reads `seedKEM` as its first 32
    // bytes; the trailing 16 are `m`, used only by encapsulation. Keygen therefore depends on the
    // first 32 alone, so the seed is reconstructed here as the dump's own `seed_kem` followed by
    // 16 zero bytes. Deriving it from the dump rather than from a pinned `.req` matters: this
    // repo's `.req` files carry the canonical NIST seed sequence, which is NOT the seed upstream
    // used for these dumps, so there is no pinned record to look it up in.
    let mut seed = hex(&field(&iv, "seed_kem"));
    assert_eq!(seed.len(), 32, "{set}: reference seed_kem is not 32 bytes");
    seed.resize(48, 0u8);

    let kem = HqcKem::<P>::new().expect("HqcKem::new");
    let (pk, _sk) = kem.keygen_with_seed(&seed).expect("keygen_with_seed");
    let pkb = pk.as_bytes();
    assert_eq!(
        &pkb[32..],
        &want_s[..],
        "{set}: public keygen output diverges from the reference"
    );
    assert_eq!(
        &pkb[..32],
        &hex(&field(&iv, "seed_ek"))[..],
        "{set}: public key does not begin with seed_ek"
    );
}

#[test]
fn hqc1_keygen_matches_upstream_reference() {
    assert_keygen_matches::<Hqc1Params>("hqc-1");
}

#[test]
fn hqc3_keygen_matches_upstream_reference() {
    assert_keygen_matches::<Hqc3Params>("hqc-3");
}

#[test]
fn hqc5_keygen_matches_upstream_reference() {
    assert_keygen_matches::<Hqc5Params>("hqc-5");
}

#[test]
fn hqc1_public_api_keygen_matches_upstream_reference() {
    assert_public_keygen_matches::<Hqc1Params>("hqc-1");
    assert_public_keygen_matches::<Hqc3Params>("hqc-3");
    assert_public_keygen_matches::<Hqc5Params>("hqc-5");
}

/// The dumps must actually be present and parseable. Without this a path typo or a stripped
/// vector directory would turn every test above into a panic that reads like a build problem,
/// or worse, a skip.
#[test]
fn reference_dumps_are_present_and_populated() {
    for (set, expect_n) in [
        ("hqc-1", Hqc1Params::VEC_N_SIZE_BYTES),
        ("hqc-3", Hqc3Params::VEC_N_SIZE_BYTES),
        ("hqc-5", Hqc5Params::VEC_N_SIZE_BYTES),
    ] {
        let iv = dump_for(set);
        for f in ["seed_kem", "seed_ek", "seed_dk", "h", "x", "y", "s"] {
            let v = hex(&field(&iv, f));
            assert!(!v.is_empty(), "{set}: field {f} is empty");
        }
        assert_eq!(
            hex(&field(&iv, "h")).len(),
            expect_n,
            "{set}: reference h length does not match this crate's VEC_N_SIZE_BYTES"
        );
    }
}
