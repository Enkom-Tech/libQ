//! Reference-oracle tests: check libQ's scalar, AVX2, and NEON Saturnin backends against the
//! *designers'* own values, not against each other and not against libQ's own scalar core.
//!
//! `tests/simd_equivalence.rs` only ever checks "SIMD kernel vs libQ's own scalar core" — which
//! cannot catch a bug present in code both paths share (e.g. the round-constant generator that
//! used to be copy-pasted, broken, into `src/simd/avx2.rs` and `src/simd/neon.rs`: see
//! `src/bs32_core.rs::packed_round_constants` for the history). This file instead checks against
//! three things that come from the NIST LWC round-2 Saturnin submission itself and were never
//! derived from libQ:
//!
//! 1. The round-constant tables `RC_10_1..RC_10_5`, `RC_16_7`, `RC_16_8`, copied verbatim from the
//!    designers' portable reference implementation,
//!    `reference/saturnin/Implementations/extra/saturnin_portable.c` (lines 308-354 as read on
//!    2026-08). That file is the authoritative oracle for this repo (see the lane's task
//!    description) but lives in a **gitignored** directory — see "Fixture provenance" below for
//!    how that tension is resolved.
//! 2. The official KAT vectors for Saturnin-Hash and Saturnin-CTR-Cascade AEAD, vendored (by a
//!    sibling lane, for `tests/kat_tests.rs`) under `tests/fixtures/`, which this file re-reads
//!    independently.
//! 3. `NON_HASH_DOMAIN_CT` (Part D): block ciphertexts at `(R, D) = (10, 1..=5)` produced by
//!    *compiling and running* the designers' `saturnin_portable.c`. The official KAT files cover
//!    only the composed Hash and CTR-Cascade modes, so nothing else in this repo pins the raw
//!    block cipher at the CTR-Cascade domains — which is exactly where the deleted SIMD
//!    round-constant copies were wrong.
//!
//! All three are the designers' own outputs; matching them end-to-end (through the *actual*
//! AVX2/NEON kernels, not stand-ins) is the only check that can catch a bug the SIMD backend and
//! the scalar core happen to share.
//!
//! ## Fixture provenance
//!
//! `tests/fixtures/LWC_HASH_KAT_256_saturninhashv2.txt` and
//! `tests/fixtures/LWC_AEAD_KAT_256_128_saturninctrcascadev2.txt` are already vendored in this
//! repo (verbatim copies of the reference distribution's KAT files, per the provenance notes in
//! `tests/kat_tests.rs`) and are read here via `include_str!`, so this file has no runtime
//! dependency on the gitignored `reference/` tree and cannot silently no-op on a CI box that
//! lacks it — a `#[cfg]`-gated "skip if reference/ is absent" test is exactly the kind of gate
//! that cannot fail on CI, which this repo has been bitten by before.
//!
//! The `saturnin_portable.c` round-constant tables (`RC_10_1`..`RC_16_8` below), by contrast, are
//! NOT re-vendored as a file — they are seven short arrays of `u32` literals, transcribed by hand
//! from the reference source and double-checked against it, with the exact file+line provenance
//! recorded above and on each constant. Anyone without the `reference/` tree still gets the full
//! value of this check (it's the literals that matter, not the file), and there is no
//! include-the-gitignored-tree problem to solve for something this small.

use lib_q_core::Result;
use lib_q_saturnin::bs32_core::SaturninBs32Core;
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_saturnin::simd::avx2;
#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
use lib_q_saturnin::simd::neon;
// `lib_q_saturnin::simd` itself only exists when a SIMD feature is on (src/lib.rs gates
// `pub mod simd`), and `runtime` is only referenced from the arch-gated tests below — so this
// import must carry the same gate as its use sites, or `cargo test -p lib-q-saturnin` with default
// features fails to compile with E0432 (and `clippy --all-targets -- -D warnings` with it).
#[cfg(any(
    all(feature = "simd-avx2", target_arch = "x86_64"),
    all(feature = "simd-neon", target_arch = "aarch64")
))]
use lib_q_saturnin::simd::runtime;
#[cfg(all(feature = "aead", feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    SaturninAead,
};

/// Parse a hex string into bytes (local copy — this file is intentionally self-contained rather
/// than reaching into `tests/kat_tests.rs`'s private helpers).
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let hi = c1.to_digit(16).expect("valid hex digit");
        let lo = c2.to_digit(16).expect("valid hex digit");
        bytes.push(((hi << 4) | lo) as u8);
    }
    bytes
}

// ===========================================================================================
// Part A — round-constant oracle: libQ's shared generator vs. the designers' own tables.
//
// These seven `(num_super_rounds, domain)` pairs are transcribed byte-for-byte from
// `reference/saturnin/Implementations/extra/saturnin_portable.c`:
//   - RC_10_1..RC_10_5 (lines 308-336): the five CTR-Cascade phases (R=10, D=1..5).
//   - RC_16_7, RC_16_8 (lines 342-354): the two Saturnin-Hash phases (R=16, D=7/8) — these are the
//     exact two configurations the crate's old, now-deleted ROM tables in `avx2.rs`/`neon.rs`
//     special-cased; the other five were NOT covered by any ROM table and would previously have
//     gone through the broken LFSR with no coverage at all.
// `saturnin_portable.c`'s block-encrypt XORs `rc[i]` directly into a 32-bit register decoded the
// same way as `SaturninBs32Core`'s key/block decode (two bytes 16 apart packed into each 16-bit
// half of a `u32`), so these tables are directly comparable to
// `SaturninBs32Core::round_constants()` with no repacking.
// ===========================================================================================

const RC_10_1: [u32; 10] = [
    0x4EB0_26C2,
    0x9059_5303,
    0xAA8F_E632,
    0xFE92_8A92,
    0x4115_A419,
    0x9353_9532,
    0x5DB1_CC4E,
    0x5415_15CA,
    0xBD1F_55A8,
    0x5A6E_1A0D,
];

const RC_10_2: [u32; 10] = [
    0x4E45_26B5,
    0xA356_5FF0,
    0x0F8F_20D8,
    0x0B54_BEE1,
    0x7D1A_6C9D,
    0x17A6_280A,
    0xAA46_C986,
    0xC119_9062,
    0x182C_5CDE,
    0xA00D_53FE,
];

const RC_10_3: [u32; 10] = [
    0x4E16_2698,
    0xB253_5BA1,
    0x6C8F_9D65,
    0x5816_AD30,
    0x691F_D4FA,
    0x6BF5_BCF9,
    0xF8EB_3525,
    0xB21D_ECFA,
    0x7B3D_A417,
    0xF62C_94B4,
];

const RC_10_4: [u32; 10] = [
    0x4FAF_265B,
    0xC548_4616,
    0x45DC_AD21,
    0xE08B_D607,
    0x0504_FDB8,
    0x1E1F_5257,
    0x45FB_C216,
    0xEB52_9B1F,
    0x5219_4E32,
    0x5498_C018,
];

const RC_10_5: [u32; 10] = [
    0x4FFC_2676,
    0xD44D_4247,
    0x26DC_109C,
    0xB3C9_C5D6,
    0x1101_45DF,
    0x624C_C6A4,
    0x1756_3EB5,
    0x9856_E787,
    0x3108_B6FB,
    0x02B9_0752,
];

const RC_16_7: [u32; 16] = [
    0x3FBA_180C,
    0x563A_B9AB,
    0x125E_A5EF,
    0x859D_A26C,
    0xB8CF_779B,
    0x7D4D_E793,
    0x07EF_B49F,
    0x8D52_5306,
    0x1E08_E6AB,
    0x4172_9F87,
    0x8C4A_EF0A,
    0x4AA0_C9A7,
    0xD93A_95EF,
    0xBB00_D2AF,
    0xB62C_5BF0,
    0x386D_94D8,
];

const RC_16_8: [u32; 16] = [
    0x3C9B_19A7,
    0xA909_8694,
    0x23F8_78DA,
    0xA7B6_47D3,
    0x74FC_9D78,
    0xEACA_AE11,
    0x2F31_A677,
    0x4CC8_C054,
    0x2F51_CA05,
    0x5268_F195,
    0x4F5B_8A2B,
    0xF614_B4AC,
    0xF1D9_5401,
    0x764D_2568,
    0x6A49_3611,
    0x8EEF_9C3E,
];

/// The single shared generator (`SaturninBs32Core::packed_round_constants`, exercised via the
/// public `round_constants()` accessor) must reproduce all seven designer tables exactly. AVX2
/// and NEON no longer carry their own copy of this generator (see `src/simd/avx2.rs` /
/// `src/simd/neon.rs`) — they delegate to this same function — so this one assertion covers all
/// three backends for the round-constant step specifically. The full-pipeline tests below (Part B
/// / Part C) additionally exercise the AVX2/NEON kernels' own S-box/MDS/shift-rows code, which
/// this test does not touch.
#[test]
fn bs32_round_constants_match_designers_reference_tables() -> Result<()> {
    let cases: [(usize, u8, &[u32]); 7] = [
        (10, 1, &RC_10_1),
        (10, 2, &RC_10_2),
        (10, 3, &RC_10_3),
        (10, 4, &RC_10_4),
        (10, 5, &RC_10_5),
        (16, 7, &RC_16_7),
        (16, 8, &RC_16_8),
    ];

    for (rounds, domain, expected) in cases {
        let core = SaturninBs32Core::new(rounds, domain)?;
        assert_eq!(
            core.round_constants(),
            expected,
            "round-constant mismatch at (num_super_rounds={rounds}, domain={domain}) \
             against reference/saturnin/Implementations/extra/saturnin_portable.c"
        );
    }
    Ok(())
}

// ===========================================================================================
// Part B — Saturnin-Hash full pipeline oracle: scalar / AVX2 / NEON kernels vs. the official
// LWC_HASH_KAT_256 vectors (1025 cases, message lengths 0..=1024 bytes), reimplementing
// `SaturninHash::hash`'s Merkle-Damgard loop (matching `saturnin_hash_update`/`saturnin_hash_out`
// in the reference C exactly: domain 7 for each full 32-byte block, domain 8 with 0x80 padding
// for the final short block, feedback `r = encrypt(r, t) XOR t`) but with the block-encrypt
// function swapped out per backend, so each backend's *own* S-box/MDS/shift-rows/round-constant
// code runs the whole way to a real digest, not just the round-constant step.
// ===========================================================================================

/// One official Saturnin-Hash KAT case: `(message, expected_digest)`.
type HashKatCase = (Vec<u8>, Vec<u8>);

const SATURNIN_HASH_LWC_KAT: &str = include_str!("fixtures/LWC_HASH_KAT_256_saturninhashv2.txt");

fn parse_hash_kat(data: &str) -> Vec<HashKatCase> {
    let mut out = Vec::new();
    let mut msg = Vec::new();
    let mut md = Vec::new();
    let mut have_block = false;

    for line in data.lines() {
        // NOTE: do not `.trim()` this line — an empty-valued field is written as `"Msg = "`
        // (trailing space, nothing after); trimming strips that trailing space too and
        // `strip_prefix("Msg = ")` then silently fails to match, dropping the whole record
        // (OBSERVED: this parser originally used `.trim()` and silently dropped KAT Count=1,
        // the empty-message case, giving 1024 records instead of 1025 with no error — see the
        // lane's progress log). `str::lines()` already strips the line terminator (including a
        // trailing `\r`), so the raw line is safe to match against directly.
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
    }
    if have_block {
        out.push((msg, md));
    }
    out
}

/// Saturnin-Hash's Merkle-Damgard loop, parameterized over the block-encrypt function so the same
/// driver can run the scalar core, the raw AVX2 kernel, or the raw NEON kernel. Mirrors
/// `src/hash.rs::SaturninHash::hash` and the reference `saturnin_hash_update`/`saturnin_hash_out`
/// in `saturnin_portable.c` exactly (including the domain-8 zero-length final-block case).
fn hash_via_kernel(
    data: &[u8],
    mut encrypt_block: impl FnMut(usize, u8, &[u8; 32], &mut [u8; 32]) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut r = [0u8; 32];
    let mut u = 0usize;
    let len = data.len();

    loop {
        let mut t = [0u8; 32];
        let clen = len - u;
        let domain = if clen >= 32 {
            t.copy_from_slice(&data[u..u + 32]);
            u += 32;
            7u8
        } else {
            t[..clen].copy_from_slice(&data[u..u + clen]);
            t[clen] = 0x80;
            8u8
        };

        let mut m = t;
        encrypt_block(16, domain, &r, &mut m)?;
        for i in 0..32 {
            r[i] = m[i] ^ t[i];
        }

        if clen < 32 {
            break;
        }
    }

    Ok(r)
}

fn scalar_encrypt_block(
    rounds: usize,
    domain: u8,
    key: &[u8; 32],
    block: &mut [u8; 32],
) -> Result<()> {
    let core = SaturninBs32Core::new(rounds, domain)?;
    core.encrypt_block(key, block)
}

#[test]
fn scalar_hash_matches_all_official_kat_vectors() -> Result<()> {
    let cases = parse_hash_kat(SATURNIN_HASH_LWC_KAT);
    assert_eq!(
        cases.len(),
        1025,
        "expected all 1025 official Saturnin-Hash KAT vectors"
    );

    for (count, (msg, expected_md)) in cases.into_iter().enumerate() {
        let digest = hash_via_kernel(&msg, scalar_encrypt_block)?;
        assert_eq!(
            digest.to_vec(),
            expected_md,
            "scalar bs32 kernel mismatch at official Hash KAT Count={} (msg len {})",
            count + 1,
            msg.len()
        );
    }
    Ok(())
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_hash_kernel_matches_all_official_kat_vectors() -> Result<()> {
    if !runtime::has_avx2() {
        // Honest skip: AVX2 genuinely unavailable on this host. On the host this test was
        // developed on, `runtime::has_avx2()` was OBSERVED true, so this branch was not taken —
        // see the lane's progress log for the actual pass/fail counts.
        return Ok(());
    }

    let cases = parse_hash_kat(SATURNIN_HASH_LWC_KAT);
    assert_eq!(
        cases.len(),
        1025,
        "expected all 1025 official Saturnin-Hash KAT vectors"
    );

    let avx2_encrypt_block =
        |rounds: usize, domain: u8, key: &[u8; 32], block: &mut [u8; 32]| -> Result<()> {
            let mut lanes = [*block; 8];
            // SAFETY: guarded by `runtime::has_avx2()` above.
            unsafe {
                avx2::encrypt_blocks8(rounds, domain, key, &mut lanes)?;
            }
            *block = lanes[0];
            Ok(())
        };

    for (count, (msg, expected_md)) in cases.into_iter().enumerate() {
        let digest = hash_via_kernel(&msg, avx2_encrypt_block)?;
        assert_eq!(
            digest.to_vec(),
            expected_md,
            "AVX2 kernel (single-lane broadcast) mismatch at official Hash KAT Count={} (msg len {})",
            count + 1,
            msg.len()
        );
    }
    Ok(())
}

/// Genuinely parallel (not broadcast) 8-lane use of `avx2::encrypt_blocks8`: batches 8 official
/// KAT messages that are each short enough to need exactly one domain-8 block (so all 8 lanes
/// legitimately share the same `(rounds, domain, key) = (16, 8, [0u8; 32])`, matching the kernel's
/// documented contract of "independent blocks that share the same params"), encrypts all 8 lanes
/// in a single kernel call, and checks each lane's resulting digest against its own official MD.
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_hash_kernel_batched_8_lanes_matches_official_kat() -> Result<()> {
    if !runtime::has_avx2() {
        return Ok(());
    }

    let cases = parse_hash_kat(SATURNIN_HASH_LWC_KAT);
    let short: Vec<&HashKatCase> = cases
        .iter()
        .filter(|(msg, _)| msg.len() < 32)
        .take(8)
        .collect();
    assert_eq!(
        short.len(),
        8,
        "need 8 official KAT messages under 32 bytes to fill an AVX2 batch"
    );

    let key = [0u8; 32];
    let mut lanes = [[0u8; 32]; 8];
    let mut t = [[0u8; 32]; 8];
    for (lane, (msg, _)) in short.iter().enumerate() {
        t[lane][..msg.len()].copy_from_slice(msg);
        t[lane][msg.len()] = 0x80;
        lanes[lane] = t[lane];
    }

    // SAFETY: guarded by `runtime::has_avx2()` above.
    unsafe {
        avx2::encrypt_blocks8(16, 8, &key, &mut lanes)?;
    }

    for (lane, (_, expected_md)) in short.iter().enumerate() {
        let mut digest = [0u8; 32];
        for i in 0..32 {
            digest[i] = lanes[lane][i] ^ t[lane][i];
        }
        assert_eq!(
            digest.to_vec(),
            *expected_md,
            "AVX2 batched kernel mismatch at lane {lane} (msg len {})",
            short[lane].0.len()
        );
    }
    Ok(())
}

/// NEON counterpart of `avx2_hash_kernel_matches_all_official_kat_vectors`. Only compiles (and
/// only runs) on `aarch64` with `simd-neon` enabled; cross-compile-checked against
/// `aarch64-unknown-linux-gnu` from this (x86_64) development host — see the lane's progress log
/// for the exact command and its "Finished" output, and for the honest statement that it was not
/// *executed* here for lack of aarch64 hardware.
#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[test]
fn neon_hash_kernel_matches_all_official_kat_vectors() -> Result<()> {
    if !runtime::has_neon() {
        return Ok(());
    }

    let cases = parse_hash_kat(SATURNIN_HASH_LWC_KAT);
    assert_eq!(
        cases.len(),
        1025,
        "expected all 1025 official Saturnin-Hash KAT vectors"
    );

    let neon_encrypt_block =
        |rounds: usize, domain: u8, key: &[u8; 32], block: &mut [u8; 32]| -> Result<()> {
            // SAFETY: guarded by `runtime::has_neon()` above.
            unsafe { neon::encrypt_block_bs32(rounds, domain, key, block) }
        };

    for (count, (msg, expected_md)) in cases.into_iter().enumerate() {
        let digest = hash_via_kernel(&msg, neon_encrypt_block)?;
        assert_eq!(
            digest.to_vec(),
            expected_md,
            "NEON kernel mismatch at official Hash KAT Count={} (msg len {})",
            count + 1,
            msg.len()
        );
    }
    Ok(())
}

// ===========================================================================================
// Part C — Saturnin-CTR-Cascade AEAD oracle for the domain-1 (R=10) path, which the AVX2 kernel
// reaches via `encrypt_blocks8_core`/`encrypt_blocks8_dispatch` in production (aead.rs, stream.rs)
// — unlike the bs32 (domain 7/8) kernel above, this path was never dead code. This exercises it
// through the public `SaturninAead` API against the official CTR-Cascade KAT, while asserting
// AVX2 was actually detected so the run is known to have gone through the AVX2 kernel and not
// silently fallen back to scalar.
// ===========================================================================================

/// One official Saturnin-CTR-Cascade AEAD KAT case: `(key, nonce, pt, ad, expected_ct)`.
#[cfg(all(feature = "aead", feature = "simd-avx2", target_arch = "x86_64"))]
type AeadKatCase = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

#[cfg(all(feature = "aead", feature = "simd-avx2", target_arch = "x86_64"))]
const SATURNIN_AEAD_LWC_KAT: &str =
    include_str!("fixtures/LWC_AEAD_KAT_256_128_saturninctrcascadev2.txt");

#[cfg(all(feature = "aead", feature = "simd-avx2", target_arch = "x86_64"))]
fn parse_aead_kat(data: &str) -> Vec<AeadKatCase> {
    let mut out = Vec::new();
    let mut key = Vec::new();
    let mut nonce = Vec::new();
    let mut pt = Vec::new();
    let mut ad = Vec::new();
    let mut ct = Vec::new();
    let mut have_block = false;

    for line in data.lines() {
        // NOTE: do not `.trim()` — see the identical note in `parse_hash_kat` above.
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

#[cfg(all(feature = "aead", feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_aead_dispatch_matches_all_official_kat_vectors() -> Result<()> {
    if !runtime::has_avx2() {
        // Without AVX2, `encrypt_blocks8_dispatch` falls back to scalar and this test would
        // silently validate nothing beyond what `tests/kat_tests.rs` already covers on its own —
        // so it is skipped rather than passed vacuously.
        return Ok(());
    }

    let aead = SaturninAead::new();
    let cases = parse_aead_kat(SATURNIN_AEAD_LWC_KAT);
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
            "AVX2-dispatched encrypt mismatch at official AEAD KAT Count={} (pt len {}, ad len {})",
            count + 1,
            pt.len(),
            ad.len()
        );

        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, ad_opt)?;
        assert_eq!(
            decrypted,
            pt,
            "AVX2-dispatched decrypt mismatch at official AEAD KAT Count={}",
            count + 1
        );
    }
    Ok(())
}

// ===========================================================================================
// Part D — the specific regression this lane fixed: AVX2/NEON's bs32 kernel at (rounds, domain)
// pairs OTHER than the two the crate's old ROM-table shortcut covered.
//
// Every test above that exercises the bs32 kernel (Part B) does so only at `(16, 7)`/`(16, 8)` —
// exactly the two configurations Saturnin-Hash ships and the old, now-deleted ROM tables in
// `avx2.rs`/`neon.rs` special-cased. That ROM shortcut is precisely why those two configurations
// could never have caught the broken LFSR that used to sit beneath it (see the doc comment on
// `avx2::round_constants` / `neon::round_constants`): the moment `num_super_rounds == 16 &&
// domain` is 7 or 8, the old code returned the hardcoded table immediately, before the broken
// generator ever ran. `SaturninAead`/`SaturninStream` also never reach the LFSR-affected branch —
// they call `avx2::encrypt_blocks8_core`, a different function that always used
// `SaturninCore::round_constants()` directly and was never bugged.
//
// The five `(10, 1..=5)` pairs below are reachable through the exact same public
// `avx2::encrypt_blocks8`/`neon::encrypt_block_bs32` API and are NOT covered by the ROM shortcut.
// They are checked against a DIRECT designer oracle — `NON_HASH_DOMAIN_CT[d - 1]` below — rather
// than only against libQ's own scalar core, so the check does not depend on the two libQ
// representations being independently right.
// ===========================================================================================

/// Ciphertexts produced by the DESIGNERS' OWN C implementation for
/// `key = [0x5A; 32]`, `block[i] = (i * 7 + domain) & 0xFF`, `R = 10`, `D = 1..=5`.
///
/// Generated by compiling `reference/saturnin/Implementations/extra/saturnin_portable.c`
/// (MinGW-W64 gcc 15.2.0, `-O2`) with a driver that calls the reference's own exported
/// `saturnin_key_expand(kb, key)` then `saturnin_block_encrypt(10, RC_10_<d>, kb, blk)` and prints
/// `blk` as hex. Nothing in libQ was consulted to produce these values.
///
/// `(10, 1..=5)` is the CTR-Cascade parameter family; `saturnin_portable.c` ships exactly these
/// five `RC_10_*` tables for it.
const NON_HASH_DOMAIN_CT: [[u8; 32]; 5] = [
    // D = 1: 6272927aeb05eb505e7abaf46dbc70da5c08fade632eb609c8a6a5564d575923
    [
        0x62, 0x72, 0x92, 0x7A, 0xEB, 0x05, 0xEB, 0x50, 0x5E, 0x7A, 0xBA, 0xF4, 0x6D, 0xBC, 0x70,
        0xDA, 0x5C, 0x08, 0xFA, 0xDE, 0x63, 0x2E, 0xB6, 0x09, 0xC8, 0xA6, 0xA5, 0x56, 0x4D, 0x57,
        0x59, 0x23,
    ],
    // D = 2: 679cb56bc54e4603de5c55687a8b7c7d12059411fb1ef09f18fc6b1762b9c252
    [
        0x67, 0x9C, 0xB5, 0x6B, 0xC5, 0x4E, 0x46, 0x03, 0xDE, 0x5C, 0x55, 0x68, 0x7A, 0x8B, 0x7C,
        0x7D, 0x12, 0x05, 0x94, 0x11, 0xFB, 0x1E, 0xF0, 0x9F, 0x18, 0xFC, 0x6B, 0x17, 0x62, 0xB9,
        0xC2, 0x52,
    ],
    // D = 3: 5bcccd02d368e1f72e07d6fe1ccb005c3efca3d11a191a98789d0c13f1407a87
    [
        0x5B, 0xCC, 0xCD, 0x02, 0xD3, 0x68, 0xE1, 0xF7, 0x2E, 0x07, 0xD6, 0xFE, 0x1C, 0xCB, 0x00,
        0x5C, 0x3E, 0xFC, 0xA3, 0xD1, 0x1A, 0x19, 0x1A, 0x98, 0x78, 0x9D, 0x0C, 0x13, 0xF1, 0x40,
        0x7A, 0x87,
    ],
    // D = 4: 6b788eb87c9eca778185d3bbc8ef05c8decfbabf5983e5359b80283a62050c02
    [
        0x6B, 0x78, 0x8E, 0xB8, 0x7C, 0x9E, 0xCA, 0x77, 0x81, 0x85, 0xD3, 0xBB, 0xC8, 0xEF, 0x05,
        0xC8, 0xDE, 0xCF, 0xBA, 0xBF, 0x59, 0x83, 0xE5, 0x35, 0x9B, 0x80, 0x28, 0x3A, 0x62, 0x05,
        0x0C, 0x02,
    ],
    // D = 5: 554968052165e1d34bc00f127c12b21e6b350093a9f6c6791e1d5426e858f3ac
    [
        0x55, 0x49, 0x68, 0x05, 0x21, 0x65, 0xE1, 0xD3, 0x4B, 0xC0, 0x0F, 0x12, 0x7C, 0x12, 0xB2,
        0x1E, 0x6B, 0x35, 0x00, 0x93, 0xA9, 0xF6, 0xC6, 0x79, 0x1E, 0x1D, 0x54, 0x26, 0xE8, 0x58,
        0xF3, 0xAC,
    ],
];

/// The Part-D plaintext block for a given domain.
fn non_hash_domain_block(domain: u8) -> [u8; 32] {
    let mut block = [0u8; 32];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(domain);
    }
    block
}

/// The scalar bs32 core must itself match the designers' C at the five non-hash domains. This is
/// the base of Part D: it makes the SIMD assertions below oracle-backed rather than merely
/// self-consistent, and it runs with no SIMD feature and on every architecture.
#[test]
fn scalar_bs32_kernel_matches_designers_c_for_non_hash_domains() -> Result<()> {
    let key = [0x5Au8; 32];
    for domain in 1u8..=5 {
        let mut block = non_hash_domain_block(domain);
        SaturninBs32Core::new(10, domain)?.encrypt_block(&key, &mut block)?;
        assert_eq!(
            block,
            NON_HASH_DOMAIN_CT[(domain - 1) as usize],
            "scalar bs32 core disagreed with the designers' saturnin_portable.c at \
             (rounds=10, domain={domain})"
        );
    }
    Ok(())
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_bs32_kernel_matches_designers_c_for_non_hash_domains() -> Result<()> {
    if !runtime::has_avx2() {
        return Ok(());
    }

    let key = [0x5Au8; 32];
    for domain in 1u8..=5 {
        let block = non_hash_domain_block(domain);

        let mut lanes = [block; 8];
        // SAFETY: guarded by `runtime::has_avx2()` above.
        unsafe {
            avx2::encrypt_blocks8(10, domain, &key, &mut lanes)?;
        }
        for (lane, out) in lanes.iter().enumerate() {
            assert_eq!(
                *out,
                NON_HASH_DOMAIN_CT[(domain - 1) as usize],
                "AVX2 bs32 kernel (lane {lane}) disagreed with the designers' \
                 saturnin_portable.c at (rounds=10, domain={domain}) — this is exactly the \
                 non-hash-domain LFSR bug the old ROM table used to mask"
            );
        }
    }
    Ok(())
}

/// NEON counterpart of the above. Cross-compile-checked against `aarch64-unknown-linux-gnu`
/// (`cargo check -p lib-q-saturnin --features simd-neon --target aarch64-unknown-linux-gnu
/// --tests`, which needs the crate's `criterion` dev-dependency temporarily dropped for aarch64
/// because its `alloca` build script wants an `aarch64-linux-gnu-gcc`); NOT executed, for lack of
/// aarch64 hardware or an emulator on the authoring host. Treat NEON as compile-verified only
/// until it runs somewhere real.
#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[test]
fn neon_bs32_kernel_matches_designers_c_for_non_hash_domains() -> Result<()> {
    if !runtime::has_neon() {
        return Ok(());
    }

    let key = [0x5Au8; 32];
    for domain in 1u8..=5 {
        let mut neon_block = non_hash_domain_block(domain);
        // SAFETY: guarded by `runtime::has_neon()` above.
        unsafe {
            neon::encrypt_block_bs32(10, domain, &key, &mut neon_block)?;
        }
        assert_eq!(
            neon_block,
            NON_HASH_DOMAIN_CT[(domain - 1) as usize],
            "NEON bs32 kernel disagreed with the designers' saturnin_portable.c at \
             (rounds=10, domain={domain}) — this is exactly the non-hash-domain LFSR bug the old \
             ROM table used to mask"
        );
    }
    Ok(())
}

/// Guard against the AVX2 oracle tests above being a vacuous skip: `runtime::has_avx2()` must be
/// true wherever `simd-avx2` is enabled on x86_64, or every AVX2 test above returns `Ok(())`
/// having checked nothing.
///
/// This DOES gate CI, deliberately: it is a hard failure on an x86_64 runner that enables
/// `simd-avx2` but lacks AVX2, because in that configuration the AVX2 coverage silently
/// evaporates and this repo has shipped green-and-useless gates before. If such a runner ever
/// becomes legitimate, delete this test consciously rather than letting the skips go unnoticed.
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_is_actually_available_on_this_development_host() {
    assert!(
        runtime::has_avx2(),
        "expected AVX2 on the lane's development host; if this fails, every AVX2 oracle test \
         above silently skipped and provided no coverage"
    );
}
