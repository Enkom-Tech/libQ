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
/// This DOES gate CI by default, deliberately: it is a hard failure on an x86_64 runner that
/// enables `simd-avx2` but lacks AVX2, because in that configuration the AVX2 coverage silently
/// evaporates and this repo has shipped green-and-useless gates before — that is exactly the ROM
/// class of bug this whole file exists to catch, and a bare printed-notice skip would make "AVX2
/// coverage evaporated" indistinguishable, in CI's pass/fail signal, from "AVX2 coverage ran and
/// passed". (Demonstrated, not just argued: with the `has_avx2()` check below temporarily
/// inverted to simulate a non-AVX2 host, `cargo test` PANICs with the message below rather than
/// silently passing — see the lane's progress log for the exact quoted output on both branches.)
///
/// `SATURNIN_ALLOW_MISSING_AVX2=1` is the deliberate escape hatch for the one case where a hard
/// failure would be wrong: a genuinely new non-AVX2 x86_64 CI runner. `.github/workflows/ci.yml`'s
/// "Saturnin" `algorithm-tests` matrix entry runs on `ubuntu-latest`, which GitHub-hosted runners
/// have provided AVX2 on since long before this crate existed (SUSPECTED, not directly observed
/// from this lane — this lane did not run anything on that runner; what IS OBSERVED is
/// `has_avx2()` returning true on this development host, and the card's stated baseline of this
/// test passing in CI, "130 passed with simd-avx2", which is only possible if AVX2 was in fact
/// present there too). Either way the var is unset everywhere today, so this stays a hard failure
/// by default and nothing about existing CI needs to change for this test to keep doing its job;
/// the escape hatch exists so a future legitimate non-AVX2 runner has a documented way to opt out
/// without deleting the test.
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
#[allow(clippy::disallowed_methods)] // env read is intentional: documented CI escape hatch, see above
fn avx2_is_actually_available_on_this_development_host() {
    if runtime::has_avx2() {
        return;
    }

    if std::env::var_os("SATURNIN_ALLOW_MISSING_AVX2").is_some() {
        eprintln!(
            "SATURNIN_ALLOW_MISSING_AVX2 is set: AVX2 is unavailable on this host, so every AVX2 \
             oracle test above silently skipped and this run has NO AVX2 coverage."
        );
        return;
    }

    panic!(
        "expected AVX2 on this host because simd-avx2 is enabled on x86_64; if this fails, every \
         AVX2 oracle test above silently skipped and provided no coverage. If this is a genuine, \
         intentional non-AVX2 x86_64 CI runner, set SATURNIN_ALLOW_MISSING_AVX2=1 rather than \
         deleting this test."
    );
}

// ===========================================================================================
// Part E — full (R, D) grid oracle: the designers' SECOND, independent reference implementation.
//
// `reference/saturnin/Implementations/crypto_aead/saturninshortv2/ref/saturnin.c` is a plain
// (word-sliced, not bitsliced) implementation of the same block cipher, generic in BOTH
// parameters: `saturnin_block_encrypt(int R, int D, const uint8_t *key, uint8_t *buf)` accepts
// any `0 <= R <= 31, 0 <= D <= 15` via its own `make_round_constants(R, D, ...)` (the same LFSR
// formula as `SaturninBs32Core::packed_round_constants`, transcribed independently by the
// designers into a second C file). `saturnin_portable.c` (Part D's source), by contrast, only
// ships hardcoded round-constant TABLES for the 7 `(R, D)` pairs the two shipped NIST modes use —
// it has no generic generator to call for anything else. This second reference file is therefore
// the oracle for the FULL 512-point domain `SaturninBs32Core::new` accepts, closing essentially
// the entire gap Part D left open (5 of 512 non-hash points, plus the 2 hash points Part A/Part B
// already cover via the round-constant and full-hash-KAT routes respectively).
//
// Provenance: compiled with the same toolchain Part D's provenance comment cites (MinGW-W64 gcc
// 15.2.0, `-O2`, OBSERVED via `gcc --version` on the authoring host) via a small driver — outside
// this repo, in the lane's scratch directory, never committed — that declares
// `saturnin_block_encrypt` `extern` and links it directly against the unmodified reference file;
// no libQ code was consulted to produce `FULL_RD_GRID_CT` below. For every `(R, D)` in
// `0..=31 x 0..=15` the driver encrypts `block[i] = (i * 7 + D) & 0xFF` under `key = [0x5A; 32]` —
// the exact convention `non_hash_domain_block` above already uses, chosen specifically so this
// table specializes to `NON_HASH_DOMAIN_CT` at `(R=10, D=1..=5)`.
//
// `full_grid_ct_agrees_with_non_hash_domain_ct` below checks that overlap explicitly and is the
// load-bearing sanity check on the oracle data itself (it does not touch libQ at all): two
// independently-implemented designer references — bitsliced `saturnin_portable.c` and plain
// `ref/saturnin.c` — producing byte-identical ciphertexts at those 5 points, OBSERVED on the
// authoring host, is what makes trusting the other 507 points reasonable.
//
// Not attempted: genuinely-parallel distinct-(R,D)-per-lane AVX2 coverage. `avx2::encrypt_blocks8`
// takes one `(rounds, domain)` pair per call (shared across all 8 lanes), so the AVX2 test below
// broadcasts one block to all 8 lanes per `(R, D)` — matching Part D's AVX2 style — rather than
// attempting to pack 8 different `(R, D)` pairs into one call, which the kernel's API does not
// support.
// ===========================================================================================

/// `R,D,<64 hex chars>` for every `(R, D)` in `0..=31 x 0..=15` (512 lines) — see the Part E doc
/// comment above for exactly how this was produced. `key = [0x5A; 32]`,
/// `block[i] = (i * 7 + D) & 0xFF` (matches `non_hash_domain_block` above).
const FULL_RD_GRID_CT: &str = r"
0,0,5a5d544f4679706b62651c170e0138332a2d24dfd6c9c0fbf2f5ece79e918883
0,1,5b52554c477e7168631a1d140f0639302b2225dcd7cec1f8f3eaede49f968980
0,2,58534a4d447f7669601b12150c073e312823daddd4cfc6f9f0ebe2e59c978e81
0,3,59504b42457c776e6118130a0d043f362920dbd2d5ccc7fef1e8e39a9d948f86
0,4,5e5148437a7d746f6619100b02053c372e21d8d3cacdc4fff6e9e09b92958c87
0,5,5f5649407b72756c671e1108033a3d342f26d9d0cbc2c5fcf7eee198938a8d84
0,6,5c574e4178736a6d641f1609003b32352c27ded1c8c3fafdf4efe699908b8285
0,7,5d544f4679706b62651c170e0138332a2d24dfd6c9c0fbf2f5ece79e918883ba
0,8,52554c477e7168631a1d140f0639302b2225dcd7cec1f8f3eaede49f968980bb
0,9,534a4d447f7669601b12150c073e312823daddd4cfc6f9f0ebe2e59c978e81b8
0,10,504b42457c776e6118130a0d043f362920dbd2d5ccc7fef1e8e39a9d948f86b9
0,11,5148437a7d746f6619100b02053c372e21d8d3cacdc4fff6e9e09b92958c87be
0,12,5649407b72756c671e1108033a3d342f26d9d0cbc2c5fcf7eee198938a8d84bf
0,13,574e4178736a6d641f1609003b32352c27ded1c8c3fafdf4efe699908b8285bc
0,14,544f4679706b62651c170e0138332a2d24dfd6c9c0fbf2f5ece79e918883babd
0,15,554c477e7168631a1d140f0639302b2225dcd7cec1f8f3eaede49f968980bbb2
1,0,fadcd9ca2001e543c3cf8c7ea54f7daa9693298af03175d343cffcdea5ffbd3a
1,1,d05cd8482f6aea08cfed8fdeadb9748cc2232848ff6a7ae84f8dff2ead59b42c
1,2,f75b484945654a0717e14cddc7b13c85c724384965659ae7b7811c2de7510c25
1,3,dd1a49c54a8e45251b834f35cf39353093e539156afe9545bbc31fb5eff90550
1,4,8e1da9c48181e12adb8f6e36a53195396ae3191421f1714a1bcf4eb655f10559
1,5,a423a87d8e70eed1d7216d94ad179c8d3eed183d2e107ef117914de45de70c7d
1,6,1d24cb7c0e7f4cdec32d7d97471fa38425ea8b3c3e1fdcfec39ddde7f7ef3374
1,7,37f8cacf0197433ccf0c7e074fe4aa4b71568a1f3197d3bccf4cde97ffd43a8b
1,8,1cfe48ce6a980833ed00de04b9ec8c42e052481e6a98e8b38d402e9459dc2c82
1,9,3693498965100735e153dd8cb1c5858db4ef496965e0e71581832d1c514525cd
1,10,0094c5888e1f253a835f358f39cd308480e81568feef451ac38fb51ff94d50c4
1,11,2a44c4a881552a3a8ff7363c3177393cd45814f8f1254a9acf67b63cf13759ac
1,12,d7437da9705ad13521fb943f177f8d35635e3df9102af195916be43fe73f7da5
1,13,fd337c997fa1de612d8b97ae1f9584b5376e3c391f21fe119dabe71eef457475
1,14,5634cf9897ae3c6e0c8707ade49d4bbc7e691f38972ebc1e4ca7971dd44d8b7c
1,15,7c3acedb98be339c001304edecc742032ab71e7b98eeb38c40a3948ddce78253
2,0,30e0a54bda5310fa415cb2f7806c81e5acc74421183c41d1cbe58a5b039f9f75
2,1,f27f24ce8ff5897fbb7639f0ae7cc15f636771470a5eec8832ee5e891b5d1a46
2,2,57df2f2a8b5906a39fa45b9927101a861657902d4ae89fa86e0392a114d229be
2,3,45d556d16e1a435d15559a35f9c003b58e30efffb0000159be7f8e52db03479a
2,4,a637ad39f2f64e13b260460f85ae5acb8d9dc3d2737898afb4fcf92fe615fde3
2,5,b06186f3b4a34eac048662654f3f1dc57710ac5975667dd763c3ea09f0c4d440
2,6,cd9965b89124b16869e4fa0555fc83e3308e842238483ebb797c81f2261b16a1
2,7,17d5cf64135bd336ecbd31cfbc209b174089ebe621a9a871d2bec5c8d3ac663c
2,8,2b608d6b1fdd1b4a2a7ad10686655ced0b4b79eedc927e11c71399baf42f5ec4
2,9,96fa655d6b2634b5437b2ccdf5c183a4be7bca94bb4510a2eae771ce5a34350d
2,10,c25eac2b783ee162dd8f8cd3c147630f2e93530239203048f78389db0d5c642a
2,11,aaf431454a18481152a997fa2eb13866504b0ca92422929e04dbbaf46256c1ab
2,12,40618b9c7a642be70347c4e620ac02315e3b8aa8fb8ad9bb340d0b067f183062
2,13,d1099c911760e6b88809c31b8834ab064b04e38398adf277cd589f29537bb119
2,14,72e63926097deb52f21e6fd3cad04a98bf453a40e0a2e2a7f1cd64e0895d80f4
2,15,ed058c999f3d75395710c62bc13aa98559542a1a93de7facf5a9f3496d417277
3,0,3b0d3dd985d3aeac620459269d57c4ebb3b8ab9ec15f907591ae0203328a68e7
3,1,4e6afa8a2fdbf5397a974740ee772d53912fa6ba6a3f69a7c1df8edb904a063c
3,2,1ce10d7c895f9faf9a5e4660273b8156389717c8901c201e7b3f744fe49d51e1
3,3,8e10d794557ff71b8d0eb971a202639540d27abe32dc1e4c249d26a64806fac3
3,4,0e5c4239c25ed1b05b6d195a87e4d0d5444ec6ba7e85a7488beef67b5e5906e6
3,5,6e8099b669f96af598ebbaf53e6e563577df560736ba55a2d15e27fc065bd7ed
3,6,670354173f2847ef7de7a6490127b35ce0f8bc80162623ca7910d67850828ac7
3,7,038b8e344ad47ee7869d600cd7da8556a8b6530846e49a2361a3568b5994dfc4
3,8,818a933e8719d6cd3defc2811f27461754f04c36ff9a4bcb9834ac7cf353ac66
3,9,575d67316ffffd45d18a82609ce1ffaa391671c2ca72fbb60d66d5cf60277f36
3,10,004b5b5f4c412a1739ca9550e582dc9ea4bd4497131faa0a72323c7987949e9a
3,11,90be238ddc08c9b76d1503b44c690ada811fd77e1fa50e3c8bda024a95d04958
3,12,e8827f8f1427ff064307976c9f27a708ff6609a18705fc5d14e9601896940942
3,13,fffb371a8bc01c400fd2e3d8dd4d953acbabf34667b1ce17f1e5fdd929089c26
3,14,8e4e1883a66aa36119e45dac2f5ea7e4ca8eb421b85856450efb24af591993cb
3,15,3e9b59de94bd53c73ea386313701118341a289dc995de672bf1b4e4c30afab5e
4,0,f4ab214f622369ff9fcf8c201cce202adcb0a7873040f27f0811701b12e159e7
4,1,f8f89eb9651bac59a2d0fdd50225d14b08e3ea22f87718945816cbdb09b7567b
4,2,15ef722bfcd5235536dbab2388850655bd85700065a351f693ab9cd613f218ae
4,3,2d6d8b49977e3a0060409501440f17413a3a5657e16d66e3191ed93be5435a7f
4,4,0fc1587693c4fc558c2de4685f23a9977773ba7cb09f652ee366edbf7c512673
4,5,dec88c4081837ee3e84842358184a2e0334af2a1f23ddf95cbfce788c3b0f678
4,6,1d4496fe78d5c0f782c3dc3462f2c8098ca8882a56088293e14ad35f5f91e1a8
4,7,1a3c94df9e3f5ad600b8099eb2f46634e9b5803d334aa1ceff8424d3323a43e0
4,8,34ba633d2d4cdf1d7df59f8a0c860647dd88ac7022d525f7949afce4074003a5
4,9,afc7dd37172a6722038ab2ed7f1d3f8bb9075d25b53261562a8e9295f52d1ae3
4,10,c3a0fd6987b5586a316cf99d4a8f7da895ffb1042fc9a831f2b6dee2e1b6ed4e
4,11,f76b976bb812d66778b0b312e6deacee162a049555fcd13d581c57966217ec53
4,12,191da4af58c9f4ce6f946637824bc6baa431e96992f2cffab79a799548a47829
4,13,919b173fcb0e540fea272e273eb61e98b019bbc104e6d2eb53987fcc72344313
4,14,1bb5ba0e956e76a631a97fd0906f202f059f2e15f4d1d58bbd6f6604c92b6f7f
4,15,735cd18e21799d96dc3a66daaacbc13707b39063881ef8c4a6e7479228e00687
5,0,38bc19b45e6c78f7e3e8ea3ec6b538a4b68df6ca1943dbcfd904077f4504c23c
5,1,26cc4a392266f06c9006eb7c67e5b8bddeece7f1996a2d70b204cdd3f2f27a4c
5,2,36db94855695c540b67c4539c00666c40d5e9574300542fb5683d6b081472d1f
5,3,17ea38a33c2ba9dc50e0cae20a5cf89affa1d2caebcda900d947d4433e4e0016
5,4,9c13f4a7bfbee32b3106f13247535cb49ccf53fe6fc9f7635cabca76b10ebc9c
5,5,c2ac88eb9c705506a7ef31e7ab3abef3f03565b277044a517da76c8ca4fb9124
5,6,9a1e5249f721c91f827a38bfeb3e6ba071909bd139c7d94d305553e9f08b0961
5,7,d4e8e29dbd31d1da15566fb8a8cd013758a7d9bfa68b387a774b434aec62dd92
5,8,d40b3c417c7e867de48f62efde882e9ace5c7c92d20e8e1c0b2deef4ffc62eeb
5,9,1d45f8ee86715754ae27ec6b6be63d7bf54f887f8b4a70567d5f4fe3ebbaed7a
5,10,de866e0cf2a12a33be7222d78d65ad9a0bdc61a8198b01a2d11ab143bd693052
5,11,d4111937a9bf9780fa6112ca2546ff48de49575389caf5451006765872696354
5,12,2336bdcf2a69c6b1eb4b89d32a220680df038b76b99bedd3cd9316d80c1c815a
5,13,51fc9545bf2a1a11f8bb1567e9ec7dc75aba3995b2d7835a62fe18d0225fb17d
5,14,3c0aaae67ac6f0a4bed4746503c6f75ee27477dab01f948cd9dc89f8d4605c22
5,15,661327001ae8e41d532aa0748a7ad5559fede9960ba95e3c9b5d524875503d24
6,0,76df7721816cd4fc108e3827c4b32b636fc3d804d2d03594a114f1048b706031
6,1,2336205a2c5275a663a7e3af156479ee6eeb7b09928c3466f29b54646652d4a3
6,2,51b88d1e5b9ef1286567fac42b53dae360049375c8484df470f34f77ac96ccf9
6,3,905ccb7998442ec11c72098857a5d62fee51966930fa02f89259578e5d25848f
6,4,9cd79be437a7df52ceecff1e7053104b5bb2584555449a7bb891c2cee7381621
6,5,23166cc7a9b6f7c12ecc1fe14c3ac90e79c97f382490950cacd9562018fe5470
6,6,d566df7235fa5ece33ed2d0b7da96b4bfd4a0da831003a101dde93e6d83e4034
6,7,2990b50a4dfbb120221478c578b5baac6fc68e0566faf2f7bf13e940f89bbb65
6,8,80b83e4bc1a6fbe871a68ab450d00e99be4fe447df300b76373ffde07da08a92
6,9,b6c3c6a30562a1fad96d8a8e86355a45e70c4f7ec0c5e985ba0a28db223b540c
6,10,624c47c4b0c411d90462c8a0ae056cd49e2f55b8153975f3df0048ccd535bb4f
6,11,a94965d2a001403e29e05c830cabdde96542cab6b885c37ea13d52e53a5f9737
6,12,1c9ead001d953e2a4202cbab08627d7dc1265a5551e92a2712e0112e0014e27a
6,13,677cafa53e5981407a6fff807b08b0f4e3e53d7f195cebd56dab7cdba7c9f90e
6,14,75742d5d1fc23fae6eb257a0e93877d2e37e633c7b611f505d53c4ce4b4a8d8e
6,15,927bcaf28330157e4f9dab4381c6d1cd97f3fbaa8080f3d60d95541bc718f874
7,0,cefdba8013d6150a141a4b1ffd79054e25bbc641a6a19be6af3fa4e642e6eb09
7,1,8ac78667849bdfdba97fef71ae699d9c971c8561e6eb2c6869a0350ce5ed7037
7,2,7d3f36ca811004b173b9f9c69b5c7390b239624d63a6971841116ee01f6d7dd5
7,3,552285d69c79cf46060edde9c528496981650247d111110acedf77e71f786372
7,4,75c905c0bfde785fb77c15e920b4c95dda684992931a569480bc76445ebad610
7,5,f72fddfbbf670986e4c34628497a1c9404b9e8afd8069a25c14e45d642e3713e
7,6,8383712a8ff3910f23e03a5e51813001735b6351285a457283a2e0679bdc399a
7,7,94f851ac9261089892dde80f730b8b01d58fd8ef06f842fad579a5ca632d9f60
7,8,372b6bf308460b925b6db39ebd041f4350e2b76b7a5aac8777e4079e930bd878
7,9,e6b69edec9bc887de79745eccf265e5c80cb08f55ad786ac0f03df58f6b9c999
7,10,f30072fae819b0f7c6922d76e648c225364f7315af3d674bfeaf9e70461b005f
7,11,7b382f57487e44e250862cffd5c52e0d3e39cfebedb9b2e0f186d8d65d599915
7,12,bb8c65c08909975c68b50236cd9838aeb53a1c93ea443c0116588ae671ab3a35
7,13,6222f7a7f91a38efe850afdf3dc0125b1127c18c788f3e239d6e782b868d71d5
7,14,142cfb0c2d6ab519c728e8a0491a03d0f61218df23376020b7a00f2b9f8613d4
7,15,a22fee45f5bd7c22fe43df96b2fa8bc4e85a65e1091147e1a5de4ae93e2d80f8
8,0,851239b220ccbbd1b65769dab29052ff1b115eaf336e366e1b57c8ecc7d54b7b
8,1,12d94209d8474bdfc5c030c1eabd3bf0d4846679f924efe8c266701d72826dc1
8,2,5614f5d97c721608b6dffddc63b4b664ce743fa6668f5807440bba205b741339
8,3,3a01b0da5e100b0c540f324be63fb4d5dc0bcf07ae219b96e4a9171f0bf65d86
8,4,d8ec1441b363dd897b0d23f2f0df23abc7a3776e2089eec2a218e852d135e734
8,5,7fd1fc87e22c3c034b34a7ae5d4eb70bb773d11f91aaef796053b422b3fb1a09
8,6,d9260d5d2a5a6d486714446dcac636ed6e8e85e5284db064a2b513c7b6949a8b
8,7,637cee15784668a36ffa44f855ee6eefa312f8cca4e443a75c85a78391103e89
8,8,19b8568795492956585ee14404f57d349c7d025b6fd384a12e467e9a3f3aa5c3
8,9,215c785df2ceb4295ab17515a966e63eb50b85bcba2267c484960bbdea786d14
8,10,3036bc408d345ead4f61efce3081c647342ccef1cd6016142c73d23d34f50569
8,11,b51127cde3547dc241094e8f5e99dbf599a82880b0fea18f12fa99211121d476
8,12,e591a42d56c0326beabc8987bbdc8f109ff04f0f1a87c922120d81df0238b64f
8,13,729c75234c7732eefc5a5921684a03eb2cd25437fb15d83b5875b5d04262b81b
8,14,90d3c692b5e54c86c8afc31532ac45ccd1dcd03c14b59dc580cf6518d4f7217d
8,15,f880a23d3c66af260154cf6c20ea5dfdef1307b9f14e1aa85ef48ca4c2547e9c
9,0,2135636ac393b34c891adbf32527e2f2218f23abc60a70d32a7556203340b27c
9,1,defa354f984b58f87e716b234c835ef41d8ab25065086258b59378911c138262
9,2,0eae4bd772a8f2f5e2539ada34feb53fceaa62578b7c062baf5eab4f64a40c51
9,3,5796ee83c001ae71007cd667dd64f7fb71e3d4557f037c491f5028e548d84352
9,4,3d2e3da6f1dd81edd740da240e5349708e4416e9fd43bcc1f2509ec1f687d1b9
9,5,501eba327096e7b1c62633d4a74e8770738012e58fd88095e431346f1505a77a
9,6,5c373c40c47c08fb706e7947113b1030244f531508cf0733728644651385c25d
9,7,ec56b1bd114b31214af30afcb7170c8a85b2278d855b152f729f1337fe255945
9,8,531d64a627cb25439f582b4cb45773dcffc8b01984d5b4c82864b0ed92e7cd0b
9,9,37d526984c3be39d83f34784031b4596d271f73d76a89fd2d52d87444f045d6c
9,10,c836abb4d96da17acbf645299c950c88bd014bb0b85f8830af5777dcfafccf68
9,11,40dd46a1af295aaf1345a85d830bd4419ffdb1fdd2aec428f7ce82036a3b9dda
9,12,1754d737bde58a0cda59d6b48ebfbfbdc24dc5e231b602b072329d50d5850660
9,13,d67d26a2725b6c95f46c4fc82c052bbb42fc558c0faf124775a8a121734a4e1f
9,14,05d822d461eaebbf0471d9dd0f7d085bf53f6053faca69488d2fe682cdd13862
9,15,df260d04b1eb02aaa54d4f5d50b867a417db1fafcc23c6584e27cda4f20099c9
10,0,7eb42b4620fa401fe1b001eff272c9cddab4a24ac0dfa89a2f167405db80eb6c
10,1,6272927aeb05eb505e7abaf46dbc70da5c08fade632eb609c8a6a5564d575923
10,2,679cb56bc54e4603de5c55687a8b7c7d12059411fb1ef09f18fc6b1762b9c252
10,3,5bcccd02d368e1f72e07d6fe1ccb005c3efca3d11a191a98789d0c13f1407a87
10,4,6b788eb87c9eca778185d3bbc8ef05c8decfbabf5983e5359b80283a62050c02
10,5,554968052165e1d34bc00f127c12b21e6b350093a9f6c6791e1d5426e858f3ac
10,6,e18ea1372178b3785b8ef3244e397434abe008b9f20819b1a87acd75aafedfce
10,7,ae62731e64b3428398ae9f0127d9e7c3d527b7f20015589b2ee5847a66f20c34
10,8,480a2d6444a659806c127800caef67e454bb4c43d6dd24fcc38e68c6e1bb4d02
10,9,5c19802ad4411221a6975450110e822688f2896f1077e859e18097969512773f
10,10,9710dc54125aeecfcd1dee23f81fde1e247a40697131e464db99647f6f26725c
10,11,a16640c24335a3679feed6501d02af2c86831e001d75f7450de9b2bc6db45e9b
10,12,46ee35c7befb34145a5d95f487f03fa5b896dfff6dd3ae5f33ef9d319804f33d
10,13,523718ade9dd2bd9dc2d098d693141cdd424efe9c40e98b94eec073fa5268fe5
10,14,781d03b06b4ecc0845a123fcf0583dca86c46456977b06e2e0a9ae4727204931
10,15,fa6afce8b994ed9f1e1fcef229030542aa1e358620d49bd67c3ba1fbaa82d397
11,0,f693f79b77873a30bfae96de2202631061be29fc28a0ed85c5bf1ccde1651075
11,1,bc55d79068f10f0bd47fe91967dffd17517cfe0d532331333f7b55c8382bd8b8
11,2,ccedcfc2897eeb83cb0dfe4bdf975823612eb6431105b3f90f53455bb37a8846
11,3,c40f2a6ff9783f86ab190176d55f9384ce98b0b18ec7af41a13fe41ac3c142a1
11,4,f60d2ff426d087de8b8b4a9af0c201985aa1a0a48328df7b44a333e8b2b3b891
11,5,fd65cb4636423762b73cc63772dc86eef4fa7e34b4b690545abe4b544c0b6f9d
11,6,4b1362ff6f4f1e759ed1e4a4d6c7ba6e296a4498d5d4db0fe82847a76e5436f8
11,7,6f216ce7d41f9078785ada317771495742c21582f212e523f12cff260201693c
11,8,d0ac3311a081d05fbc1238332a3cd6c8630e56367daf9e4d8a5ba6a9c35b1dd5
11,9,f1a4ea4ff2473feae702703ee83d4d2416449364b7560760615152b86fc0f00a
11,10,333f11ecd1feff127ef7f66c74fcb78397718fc7b2bb794835bd143397d3ddd3
11,11,24cdfce8c4874c8092b458acf5ebb48a206f95e524eaa97380fdadcd2643c787
11,12,495d64bf973c00ec8cadd3ad2c4f526e73752f0d241a2b0e2c198a380040aa65
11,13,4c9e5a511be8dbde879178acb650c532e0f4243ec7ee935890d844389ae52a72
11,14,2d63034d77b50353f2a35dbe99bc2449f34244df93b76c717d412c02825cfa7d
11,15,140e09182e211393524982275706bcf1951a562936912bc7d459b2caf0300706
12,0,c5589c174d685f064ce961559b30e0c2da4f0c2f1e05045338b4cc64de0f4b8f
12,1,9886457b4d796f498fb8e9207be6f98ca5eb891d0046803da721ce74bfb99940
12,2,e104197a115e41a2a68d354acb79dc8f46c524fbbc602ac9072eb9ec670ee242
12,3,61bba4c686494feb40facfa50aa5b1ed211ea89704e9c0dd6406f936ccacfe36
12,4,d7d9653ad7af48c2e1bced05d0d5a9c58372c4eb92a3ac1495d17b7c0a7ce797
12,5,2d6afd9aceba333b5312428fa9d0ffe6dbf44a1b92d2bb3929a4dbd82a92c196
12,6,78852c121a26f615f104bb045352d524e43a87e2e79f411356ec952759fed616
12,7,12c8d652f227293f24f44b262fce9fb55d79774d0b951f13b1901787a38e861e
12,8,8974d95afe2430fc9bbe8464c6f0c7dcb5979c76a9450bc34d9000510fb95e59
12,9,b65d6c947b4a4057912af3677178d7cdcc74306c5d248d8546d6f6ebb08e0350
12,10,535d54837c670a44d65d38e0648972093f3ffc5cdd63895a55bbd2ed2bd6689d
12,11,11effe714307b8e6e72bcaa2fdfe9245e95190ee47183459427aaf35cf1794e4
12,12,e87674eacc2576187198d9e667ffca1301857c8e30057e19b37929cc014d88f7
12,13,6df88929c4feb2b643b0c5cd5f519b1f45a6e1db90a94cdca6832bb42168a397
12,14,332e6286d31a429255cd9101d8b115a69603fd44eb1ddad9fb992d6da74dc6a0
12,15,1f4b235426109724e8d8d81c91c8548dede6ed45a7d2839d5e7345ab036bc799
13,0,4b8c8687d6dcbbc1bc8c98ead1119217d905f50c6f13753068ce3ae261695e68
13,1,029687f0ec380d63f315737d3e75ba8e33599fbd7b53cf8de2b9cb2f74f84fdf
13,2,2fbca7d215438d61729c412b6088b3410cbceeca614e75b0349144b8b716d75b
13,3,cd5f2c872028759413e1d94652fbfc5eceb569e335ab6ef2b7568593c0ad056f
13,4,d6384964054b2bfe45f5d84c84d251d7782c1d43d12bb35dfff13ba84d3f4baa
13,5,f035efcb6228213919f4d926f597d2987f674401cfb591614ad7455d85920aa0
13,6,e67091344325df05e3a7c32d68381c74821e30076c32f923b1276d934d3294ec
13,7,590bb251ad76295a48e748cb0cb61a0b9d2f376f31ae48df8b8478dc14d92ee7
13,8,50b7835bb4a753d42a593cefc0c6fbc55a6acc7d5b3fb783a3aee8bd2538ac1a
13,9,9aaf1ddb8eae7dfc74a1cf8b61268d26a5ccf137de9e160d5745624759823eb8
13,10,40e0b75af58d6605a7bef75401e1f2a9a00968f7c7f6273dd7d24f54fd82724c
13,11,f7a05d7313cfe00d16d31922188baf725189b9e50eb4ef942c72df2133372b22
13,12,06d316bd80bbaae989c8386fb01af8248b4bd96f623090f5ab373a62c028122d
13,13,8c31f8d63c50d47842d0aebf213154a3196ecce6ad09dbd36dbbadd682342ce1
13,14,e5c127ed51e5703481296294ce407f17bc303f1c1ae8e0a3f1002c29370f45af
13,15,52da26557036a1c179eb811f44144013ec46ea411430015e7fe82a2bf98a41a7
14,0,e53a0c47fea1df6d2f9f4fd5342cf951ed599afec0a5f20b59ad4847b32a43b0
14,1,37959e936b2d9ccf257192663475bf54616ac85f3b6d41b541d060e8146e6f24
14,2,57f9d53fba01ba8e1dab184bd62b1e0d04a05982b5af5039952371b1091d3971
14,3,61949ac9b917361bcc624572788a0ba2cb54b617fa7727d87df71544139ceeea
14,4,254a61a9810ef418c59935c43c88cdbebfa9bf820435a48846eab2f90ff7500e
14,5,aea1be15f84f02dc03bc167979cfeac31e18a88b913ea39d86282c5f76b9cd95
14,6,33f52db162dcc59d18f92b9a85517a1d5ae755ee648fb5f679187200ee930a64
14,7,d201ebba1c574e93290df9b2b4f3a872e0190a5bfc72092c1e8b1b64ead64b4f
14,8,03010c3522759769ee16691787de1b768e76b8c1c465db66728ffdbc650da0aa
14,9,ce5301493aa16845f881fea7e98a661dc7f16af500233a21b0870dd0b8664f85
14,10,6d6882e1f769991a7d58fbc05c5422ab6a3d583e734807e3469fc514ee831b19
14,11,c1778aa63f26e446438d29590cbe321f83c7056b4d65006e7a321cd5cd3b7338
14,12,85789206157d1fd755f1239f8cd7436a87c7b5e2154456f430ee4ceb338eb875
14,13,4386266133fdf6b9c623ff71c367f0a404bfee2a2ffc76898ab03cf4e854f4d4
14,14,79b3b7da7b80e53761910fb81d41b2b525d987eaaea0d4878ff6dc03d2803f8c
14,15,649ff8d0cf275b45aebd15b41606a61176084bcb39b1c64fac9ace587eb23c96
15,0,a7e0dc36303e9dc50ec9decebb4ba5f381237c972fb343e604c5ee533012bb98
15,1,76d573477aca75c66c3bb466cffe2e364bc7e31846b0ee7fcc9440399fd61a0d
15,2,125220d4e7623c6f2644be22cf477f8fc83bdbe1445b2ef896f78dc817b03985
15,3,11f2c5a35e04d287afdc29c6560629ef2b20ae8b5a38fe1517a5eed15d860115
15,4,b4901bf8f45ad6d846db44157e3fb6ef653a0c0a0781c80e45d581d786f73d2e
15,5,e6395f7ff498860cfa898eac4f8143ed315859b352e471693e1efec0a33737d0
15,6,8837984157b89023d32bac07346372aa7ffa5bb103274f1fec10175e021db016
15,7,d0e3c4fe7b4e1c4ffae2170c3b3cbcdba68fa5f7ecb1dc3331882ff156509d2e
15,8,de50e0d22de91157aa144c959b464a153e0eac34adbe9e20646cda45f6fcf8e2
15,9,18bc0a3c952c079a2cb8c700a5030e366015979e10eadd244a09923f5df4ccec
15,10,f24830c1bc569734b742852052a67bf9b2a50f1b3da12de8fb7ad751655dcbdf
15,11,e72ec1fbf193533f8c86c69825b88559d3e887d7cb9223d9cbb0887b695ed46f
15,12,1e0b023f4d222deabd26c096af325895166a14270ec407458ae4c7dfd81adbc4
15,13,d5ac13ab9069ced6d067935d0b828ef88636bd52f510056385cbb6f5516987ac
15,14,495f326f4a4f038e5aaf79386e2848dd2e337e9b3573c8640217180f83d244aa
15,15,128f7b2b58c14cf379b5bb0577d9a6bb3fd963e20f7b6d424c8d8c2ae81020e6
16,0,6c96cd43a2ca9c10fd4691971bdaaf9d6df11c84cab4b72e7bec2b9cba6cf713
16,1,f6d61019fc4f566c6915ae9ad8856885ecc139a33529027bf7090d33c893155a
16,2,b614c226cab367e99ab5053327477507019d68dc7d4250eef555aeadd62d5223
16,3,b5bd9ad9099e303a1f3de2a076ae1542daf7d18881343ffcd2530c992d3e214d
16,4,81010f58f46e13a8cef6458ea2bb5a679fb0747d0ea044842ff6636bdb272236
16,5,f5e3efe05105ba22c588132a8835cae6022fa9ce8a0d1c31a42f54e241ba045b
16,6,b02c5277437e98f2d77227ad886239867504bfb71209d0cc61661ae8c305ec45
16,7,dc4df7da196877545a90f03aa5ddb50dadbef1b1c8ca60ac87fc390b377a3a31
16,8,60de3bc4fc1baa3333de9804741010af8f44b6a47619303bb6ccf9e14f0ce2c0
16,9,eb6bdfbc90ba269fa991a86ebf1b86895547e07da6ad2793054f389148442fe7
16,10,f383789ac7a8970c4d6b26c6efa3dee5ef4905ee5ca95933f888f57ad2849fc6
16,11,b3cc9f9d23d98ba61ab9c68aa60b7a57ab6f8b14ed59f12884211f60b24feaa0
16,12,3c162a957cba7ed980b49c48355292bff66a800717ff215288752c9c7c45c904
16,13,3c4e112be07c1dc72541c579a954e5f2fcc724874a303b56bbd5cc194cac3935
16,14,7f89d5a93041e553de23a1d8709dd8a19d6b24db78e1d908ee3ae628a1b8facb
16,15,3ad40ceef1ebe7119f193852a6574724d4f173464266d6555a2c920ce2404cc5
17,0,ee8d5e49ab583d5cbd5cc17a9c5c1056b023a0a3f22a6d187f1061ad1dfcdacb
17,1,43041956d6ba380aa4f9dc6e77767d116b06cfb00381aaaebd9cbd6c6dff9dc4
17,2,e69a6d729cfff4a30553f5081cb712907bbe4a6fe28864de1eb6c224ab2f3b5d
17,3,725358a1f4870080ecc0b9bf5347a4f1bcd52995e80a7fcc8c6de93271540525
17,4,7fe9691dc799e2d99a70fbcce1062536873bf4680f66d526c74676a4b3cb6a34
17,5,7eee75be54a0940c359408577b316eda62b780f8f2eca90f3a1bdcc0bbe3fbc7
17,6,496d7b4528e6a3ad3a5cf46eb64686166856b574183bc932935b2959e650ecb9
17,7,1b4446a3fafb8c766d3c20689b29f9e713d1577ef7c55b763c3415ffdc03eb3b
17,8,87263750c5f9f43cdc8d40ae14ae44bc1dc9f5c66e4f702cdceb5aeeb3008a15
17,9,6cf271147ff6364f330fdab7660947cf64c25e428f8208f7c82784ad0d04a28e
17,10,c8d2372335be937e5ce14135d09648772dac6b13ee436c31e19873653f44ab69
17,11,cce7b54f1314310460eb61dcb1c3cd31954b46a48310c384b7505a191c167d1a
17,12,4dda06a205fe197138f24d9669d2085d3704ee03032326ce625f1570a5f13f6b
17,13,ba57aebb08cb24e6d2bdfa88fc9d97ab3762588d3e8e3877ef86c1a351c1430d
17,14,380c2d7f69ccc3b26dde3c752efb68311f3ef947da7784c3a10eb64cabdee092
17,15,18d43e4b2d4b9f4efbe1d8aed0ea1c3d4a8318e4ec284cd720771abef240c8cb
18,0,d27698a48abe096920875afea5574013a5214eb3bd822d10724e32dcaf1225fa
18,1,11528babe6d1ce642b3e8be469fc1982df8514ea196ba787f63f742978bb97fa
18,2,dca6dd460e0f6a8a77f43da50c62810558a7fd04ce5e1c1acadfed4bed3447fc
18,3,8e5cf2b78d7d77303eee5b7bb76d0aaba434bf7c59fba9e79c4a69500544b71c
18,4,49b4376e51b18ba42be9aec7482f310a7930f45689911c9583910e76c6c33178
18,5,51c1343f6544645dc6dc145148626c650b13a02d6a485d978b78820676e29711
18,6,efdebd7de06adb5b627429a988f1a241bd25ee87414ae73fd4f3c3ab4b5c0c3d
18,7,4c7e93fe400ec8b0c72a0de53933eaebc57901af298efc8d6c97c741ae5cf132
18,8,4a27c09cb87fc355611895446a2de6b52aa93d6a2ef36551bbcf3464e461ec3f
18,9,bbefb6bb1955851c1eeb34f20f89ea1857fe96400d012b077ec0bfc79b277658
18,10,019591a812fe36c72ed88deeebde75e65a42101ac295884d080fddccd3cccc4f
18,11,d7871ed2d501200114ed0a3a8c4763c453ad165307e85fedba864de3b8388220
18,12,bfd7e17fe9cc8f19373c998a3cacacc6a0e67bf1c812cabf93e50e6062370924
18,13,d74f747ce28cd128d16208ea5c69b1ebe0b653c714e6b56f18a4a41ed67d4f42
18,14,e5aa25016b5dbced0834f6a3de560b7239f35264312fe14e5a1ece9180c734a5
18,15,211b0a007c6bba7223cfc2824b9ef1afcd49d5e0e81b4cc377031512f4311621
19,0,b75b3f1ad8922ba714086a75baeb378d3a6130a8abcf2d62c5ef94589d1dcc58
19,1,a9e4d2471040fd864122555e408499e0648b3792fe37c21fea6b216b534ea2d0
19,2,a91a43421c628c9b1835fff1bb28e293a62fbf85c048f1b3d751b1bdce3f968e
19,3,b7583cc93cfd7eee5439906c8540d9774e7fdcabc4f385ca3725df478591da4b
19,4,516485ad553f4099a2188fa17bd232974c56514e432c7d346165c636864fc79b
19,5,4ab4d23f532ee003bc021624ccf89b3ad8ab76538a770eb6ef4a7142d0b8647a
19,6,3517ef0180ac627f60d745e013301867e98521b07ac9509c651162b1e59cfbf1
19,7,40b2db03af59ff497014e3c8334962fd7301e0826cd32cc1e778f86a70f3d628
19,8,62d9fd3ae596cb5bcf57dcdd87e97a71785c13c27da6636519fc711fbced543f
19,9,402b4d49aea907d74be35d003fa8d2247437f7494ec50e2b2b0eca42e6735d5c
19,10,435bdce129091f0397940881c1506e42243bea446c6c65149afdf5c666c3a382
19,11,5133012a2dc71ce3f5a331cf1ff537a8e61258a7e45608d4585a417ed9849c57
19,12,ef7cd7581634479d25830632a5faa563e02abb4dc8d3974778a3ba5b5818738e
19,13,bc812a7d90f14ddf34a0b57e48c1249f5ef7e2a7b6db5b5cfe3542a948d3d4c1
19,14,336b6f30a2aa092c54f967f5c1c1ec2e3eae4f61597ba609b5f3bb875f160835
19,15,d20c46b404ceff3a0c0b03ed68437ba533064e97544395f0a65d229076f9921d
20,0,3cbd4a29e4727a27b081dc2d28d5b736e7526922f4f0c66870f3f52880c9fca1
20,1,692cb9a7c14023d1be04efc83629e0a0d1f0487ea9c47aee026e29255b85fb88
20,2,acc9104a1283d1300824928085000f4d96caef8763c274e6b81ac70cc5e94262
20,3,14d563c7de2642a0c73d02e9e03c18d8db4eaa435b14ab02483596f772a572dc
20,4,58c86557af2e7c5023664db137439736a36b8e0e544f4a9e5a693371f4692fc8
20,5,d532f86369ee91e50415e780e861a02cf98c48e40afecf7d53e5efcf1d585e8e
20,6,ab8cbddc04086efb59d489918b04a0c5e91cf24671ca1ba9a378774e6de806d8
20,7,da98f07ef720eb499f57b804e52dc71040e38dbe60f661e97ebf2d9d0b13541c
20,8,81b65cf462c65c4455a12eb63b0cbdf3dc32089e83bddb7e5ec67a0bc3297ebd
20,9,8302dbf33e511544931404e3fb6f5d95c680f527940bbcc04552932f166b3c93
20,10,bacc24196d34dfe9e9fadcd34f0290ac35a0d56c528d0049e69026dfb9f858c8
20,11,df27cda5b33627cc529826bb18357b7f7df279087a339fa910cbb29408baf076
20,12,c12c76dc70663d93f7a1f6b1bfe1aca9145075b881e6fd8af02d5278d1035ef1
20,13,e796498f94bc8859fa3f2778543c17fa29a58c09a02a66f8c0d627fdaf687b42
20,14,25dcc30f308a47ae16b96180f7fbf061afead4a5ad828a5088ac6c2b155f3765
20,15,48a2c29d49542848cb1fd4ff5d0fc548d84d3f372164706a45adb8539cbd2270
21,0,514da952f2aefb09da6df4080efde13e51345e015aed34dd95d1c3b74040ef8b
21,1,2db197eb4a09e2b8a23f7a70d24a196b6197564c3586e61aa3bb77986518fdc2
21,2,caeb191f0314c818d6f39f59e827fa00588ea26ea2d54d22969539b30bd81513
21,3,a779f965cb6a918ba6f69b7210f7e41297e4fccdd9e41480f3861c463c3335f8
21,4,1c08680359017495c0ac904cf874adb977bed3778944849ba0da32316e108977
21,5,bc0fae921be8f78d7471268532896c552c8a86dc80df4119ff18c8ea1a1e5118
21,6,93fc85455d495c0f34fa357682eb18ed23c25ec53a039b1f7c98a2e30939b7ee
21,7,727c709a0112264bb0ed3d9629d555f3cfec5f65e80d9a6e35c13cdd956210a9
21,8,c1e13cd9df6ccbc633326e01650450f5506e81fadce833dccd80a5e11dbeef33
21,9,fb9129db84d4911aac7ac7584c5659fbc9d5875d053ed587ec4e6165a52d5c8b
21,10,d8beef23627d40a6d1cd4485b4419f5d717bfd6b067e7362a85febeb78f07ea6
21,11,7cc5abea1211025ae241ea03df12a7bb349644ea1aabb35375c1bcb727a3bd0b
21,12,264b0df0c8e32322f38a109db7e67fed3c21b6f0a89340d6a648b948842016d0
21,13,f5c8180cf19a1dc23be2ba190cc1bb302624752b07210e4d3f194c912acb3646
21,14,c63cae9efaf819df1102f39e1221eaffc613df9ecfbcc2419f3a3a8ae5812506
21,15,aab7fe1b5a71ac783e2f8e6113424f30cea8ba87b712bc0f6da4cf534c91749c
22,0,36af385448db3717ca780ab5ac6b0ecb02b14b7fbd1614595be41eb65fd1a7ab
22,1,c3c909014d4fb8c2cd3ca3eabb2e6b017d4575071dd4b1a9a19d4b6669b4f2c9
22,2,2a90e35e7f4beaa11eb8b2e5041272853c2e875ec6585e7ed370537352516c15
22,3,51eadab603adb6c6c595e6d5906fd46d402b0e8257fb67c851d4b85196d310b7
22,4,9966bf14ca0b6ef66cc872ffecb6dc4d9133736a2f79a57d895808f57c5d49d7
22,5,895a72510f24f722a9b932cb6f982199643dbf991f40124b11e7181213635729
22,6,960c1e81322b0b839188abdcac5b22409f8a5abda398a244112a92674bc4a611
22,7,f3790ae792283a952b36faa3f0650c7e7b70ea98444ece7072d2b02cab50dbfb
22,8,1e31df19d0e7e2722970185e030cb1bf583216f31b34d1612805690e218bd0a1
22,9,2cc54f05f45bd248216d2bd0a92a6517741b7674b0d38fe018ebfc84698cb16c
22,10,3a72ad0dce2caaad69adc27ced2c0f4659f7b102a8e98d1d748e7432a03ef711
22,11,53deedb299705bb45a5235292f1f7d9f6a4f867e7027690823695ee570b60327
22,12,201b903afc318ffc0e0c53ce08a22ed699067ec901b77cb4b0207a4b4d83c1c1
22,13,8777717223d1d2b05a66e8907b96a8f5b02225b843dfb8442bed007751d20b7a
22,14,511eebbd69787c9bd77fbd9779bb30851ecded15dc049b8e2e4e4181d8be3b60
22,15,895a18005eee0b118813e2dd73b8ac0433ba76a0604c905c735632c63716829f
23,0,59c73f9066e805e34137babbe032f7fb6b51ef9e53eca66990744b03692f7a83
23,1,a43f03b36ada8b3f03aa7cd089f2e48f2144b104707296ee56596e44b2528ae6
23,2,5c4cc942c049425f0fb37d6b8c8bcc68f22d9a4fe4ae72e2c43f08cd679216dd
23,3,5f008a9e1ed96c823b87edcab3e88a86f5e22c23a9250fa6f0a206e5fac97bed
23,4,80a3d9dc1dab353782828f132d241a92387294f83b892dab4e026c43975f023f
23,5,a4af7b0de248ccaefd277827d3124d67faf106cde197c5e992e05c6934cd4c95
23,6,d7ebf9a4343be13c698c984181f85e2db2381517fd1720669a0a471e1281cd78
23,7,7be15bc0345a188c25c72ee08bcc35ceda6828628e4630106e5f0476de2771c5
23,8,fe90ed4d3a484d3f7cdb6b15fb0a5889cfd6a1b79dc28da9573e1afbe21509a1
23,9,37ad4a509da4a3396fcdfdb9639974fd70c24d3a85a3b9e7599e2025cdc71466
23,10,1864d6effa74775da4415700062c9bb4107c405566175c49bcc5052f8ae33df1
23,11,9d53ad75ee4dfa901bc30a8b9ad1314f9a68aaed8e75689fde2307f60125da06
23,12,0e6dbca26ffd337bee42a558f724eaf9558ce4e7e3325b06b0c040d35a6978c4
23,13,76369b1d7dbb2065a2ac5b1f859166013cf9336f262f711705b3024fbf252fd3
23,14,80cb6afd3ee3c385c4407890724208e6f9512dd2c699de0194c526c33dc7a4e8
23,15,db9e3622e98a16f516f5fd2ca058ecd2d739f8e60a79210527436f4fd7186916
24,0,d5371ea8a6ffb5982727b9f0f0b748cae22ed937c682dc626b756b37d3bd7f47
24,1,abf1beb4853c2bc1571c5f0f268b5008ad4e523ad2a00e7d2cf016d9c2fa9569
24,2,34bb76b76115b1fe50550c5f1b4f195599299d0edb01f4e33808ed7c0c91d175
24,3,0cd737cc3f5b8e5bfe748f108aeaef6258a2acedd14a371aab9de6fc1d0d0d1f
24,4,5de610ec7e536cea5cfc9bb0f121eb0b159f0cb19ea226d7d5e40df7ada31e95
24,5,d923ff7f6c742b6500ef27118ce046b5bc4e381a8d364919a7ea2c616ae715e6
24,6,4b388e5ab194c9b662587c7399bb3a74ae67e76ae527b8657597f994a435e305
24,7,06ef264a3822ea15bdb5e66e23fe528c1b7b7f8170e9e7af054a0fce490afbfe
24,8,4e72f2d76c4b359e20555f27be3bd293c4c72c8fac470817c5f46bc1c3f5791e
24,9,4df90298c5e33e56c212edc2f26955ae682c30e253d2dc2751e8ddf766878510
24,10,7409d86a4559b00934ed342942ada06d023a3f9d3d8fedfe852fd861fd28ee2a
24,11,684273e7437c3f26244a46c6656c98a16d80a772dddb3a295087a0837f12c3ba
24,12,0993d4d1944d0c164fa2c1d39935561e71992fa4c93e4ce5ff7e8f9d8c7911d2
24,13,57a3976280a5403646ba0e6df438e9f49b4dc1e7be45d052a760c94ba66f2eae
24,14,3c76e298f4f8302372057d51e11469159a0ae596de6b487156d108754bee885a
24,15,c26270b912397ffa9be48e38f21ff610235846f2e55be43acfb87261ed9caf26
25,0,8fc43ff81d674f93a8179ad1b214b4d8309ebf6ddfd0805424358efdc2a1a9ca
25,1,d314b4d367a5a6b6e08780d0654c197e4d75da88e01b45d0af18e4a57d71cb1a
25,2,66db4c82ca6880c9b7db65b722d325e3abb209ce88c83cda75c17b71a55752d1
25,3,485d146b5b961facb4740f4717169aa47b60edab6629fb7de2e603e610f7d3b0
25,4,168f18278c54de461c5c0620d72077a000ff0455a71a951a66059c1b110c34b0
25,5,d050d483fdf6a1b8e6d90afdd70f684fccf1d809aaa60b3caf5369bf4d732a24
25,6,228ad19370a6c2fc864f14d238fd4532e8b1822958aea42eba603f616fc44772
25,7,f02a6f97da0f538176ae18be6b4b1f5c60f135be88635154bf37a8e2e0c18d14
25,8,55789cbc4055461e095e132ff9e7f174f669a40062ea37422bd14d21f8c267cf
25,9,731ce8d2aa8d7f0530d0ea6e2820cb43f090d0da22786427010d977caea46990
25,10,8d5c5bb8ba26d1a060d1d66c0683750843e61ea127c30d8ba7eff396d23aedea
25,11,9edcf5139ad2957c90019eaf9e20125008bccac25fc74e93c7b1d321d9c96619
25,12,5f5733cc2931ab481ace9ce24eb4f9086ec63cd8114f78d4ad52c97d1911b056
25,13,a5a632e2d86bc588b3816bbb4777e7408fd08a9b9d854396069054b8221daf98
25,14,8faf0ebd521b08572c80f72ad523812eef2d8896041659d8099ee3b3fede40c7
25,15,c97b0614c97f83a6e733527017e79c1db0921c39d594ffcd8fed3ff711367370
26,0,b174ec32837319c36d86cf8b9046ea7e7524ff03cb6b55671291e1234a738d50
26,1,2388f88d8cbbfd20881bd61a7b55963784a372ca3ab8ab15ca18803f4b8bdeb2
26,2,58304d01e756c6b631561a9478c765f2f4ff88c2047db543b025a7e37791c0f3
26,3,041ad5a6e731cc252cd0e33fb7d9786488d523c6ff1236fcd9aedc530674664d
26,4,60b59425d57bbea65c3fe6817cafa506bfaad8f6952cd0ed43404a9916fdd433
26,5,ee23c8840f33940dfd68dce59702ed7b8fc23eb7fd3053b4ef80a254171f17f7
26,6,145e46efd7386f12f8824bf946a718bfbb63168159c91755456d270ff357169b
26,7,80db7a16af1808ccd54f0eff8e3e91c56a985b228e68f8ac47203a16a6724ef7
26,8,d2ba346ed40362505497300ea3b48dbc546fb631771cb647ad0fbed08cbecfcb
26,9,37cb8993522d55955903c6be6eae4df46c4d7c833b1a1de3034dc66c195b683d
26,10,4f096eb647ac2476da0e97c62ec473fa071e456e902896eee1c5dba5b94d355f
26,11,6f90184f4b40c9a8ab11d15f80bf7d901cfa1598af089babb47ee1a50291dff5
26,12,0e1ba5346b59c4613e80969e1329742771936bdc9edc5a23cc867aa589a22c18
26,13,4c3d6bc3977808bba0214f7bbf4546987371a2059826e2f34784f0c065cb9319
26,14,4a9de668ce8cbadf4168908e7f701b4838ffc016c18c138e4654bc836e613fb8
26,15,b50cc61eed41117f81253ac03b1f47a32c9a0b17a3c2c54af720b7252d679995
27,0,8f1419ee996dfa4d99def94fc122d25128a9aeb8f567119c3ce5002250387fd6
27,1,289a89dd31d8f010df37809d18e41c69daf039a91ba2d415b69423ad6f5f961c
27,2,713793acc573afac81aad8158a55fafbcbafbdab9215390278ca52e213ade0e2
27,3,f29192a5aba9c11712c09bad977e830c9f74a5d76b7c5904ce1d1e3e7173aa82
27,4,4048a7fd3e4d9e6174b63d268a135236db4f3abd57ecd1df80e293c8da82a700
27,5,bcbe95a190d7561d5fd30740557c79ef2a25218c84d24d2a484252eed8ed7345
27,6,cc752b0832b098f19808707df95a097af9641bb7cd80a1733e1ea579cef274fa
27,7,8dd94dd4654c82f93a31a0c577a8661425bffaa90644e6474f6c15662742a4c2
27,8,331803fbc23fe14a9234f7ab7cc518f0e7c0fdc3df7c6a7ea698c13d297f8d8b
27,9,f46f8c2b771b39805ded150e26140f7dae2fc668261ee4d07382aa5c2faff04b
27,10,0ea526d9a90ee0f16fe436eb61e2b0fe9d0916073c97e4518b5d644f5cccf202
27,11,3b5f51eb50b635d32ccbe5b1577df01327a1e8f491b84abf4eee7344e638ac33
27,12,b396075e7f3417426745b83b71d477fe597347228efb649cf8ee5fb5bd0765af
27,13,319fc28d62654a6421b5aa65f25aad9ee9216f213a84130c8af11f7beb950343
27,14,23b6734a3c6deb9be60545a042a20b12ab3843347275efaf98af09709d26dc8a
27,15,345507272e4c3283debea398ee834281c3ad202cbff5345e28d12088ab69f239
28,0,95006e0be497693778e32720a4abd6d9482489199a00b902a27face8c404b7f7
28,1,2bc7c9cae1a644fa06ce044fbb1fa968f6ac817cf36a014d4f2f3303346e536b
28,2,61154ff7f2615601eb95b9341446b546c777c0b578844194441e52d9eaefac88
28,3,fe28319c0c84afe155f988b4e75d3355a5ce5d58b07807ec2679240e7a8bcf84
28,4,7804444eb9b3005bf4b47a9b5e021555f0f69b95bece6f626782d94031e0d5a0
28,5,e0bc877c6ebc50472990926e6c19d69560e2eb3c82b4276fe801de6faa5e3a28
28,6,377324c7480db00336fcb17af71b3f6fb239fccb96bd6441f7f7245e1e425c2a
28,7,bbff0960a6fc1be8d7c85d8bdd7ccef130367f635bbabc40673eb19ca121989f
28,8,5a3986a8f5e89c3e2ffa0d7618885177317e9d794025d9a0eab086fdc714ec10
28,9,46e75a432bb24e76952fb3179f16012708a719547cccc26fee54bd3b2c4fd18f
28,10,893ee13b51552f5ff67d273b4b6d5e3e35bae2578895f60d0fd07f8f27d81a0f
28,11,35a43be698aa3a60485cf5633a8bf72e57a5a47c021d5a7810d8d7be5c10c040
28,12,63e3f150064c2fac97a89a9bb10e74534d6d729b54e9a4bdaaf5e7fb912877ef
28,13,e12a65255e459c1de1fef7d16835260d286af634ef22c837ee8fd2762dc83152
28,14,96dded9c0b48e74eb1eebe878924a9178159db63820ed44c3fd2be9007620792
28,15,f19f0dfcaafb68fedbd047b292f4b771b84ef9a4c44ec4dbbc0c5625ac55424f
29,0,c3d32dfdd27348744541fe749807f1bcd296ac6e8fe1633c2155c3d35d83b0f1
29,1,cb7c97a6fe27d6d88aa8cfa02419df2f64a0fdfe4b772070acd661b1638db841
29,2,c99f07e65a0c2760cf70c14a09cab5a0ee72c15e7a70ebcdcdebf21d0f47c098
29,3,1cca7dc9259b921105707a2344bc9675fdf20c490df312d99793b481e6541072
29,4,c89601e0ec120b3cd8f7e4f870db43b8f4ecae71435254bebdebaf01c9437012
29,5,39b0788a0756dfb8934e93d6b3952f0629513258fdc1d22ef134c3d012956ac7
29,6,15a7b6d2d4fbd4d4320cbc16fdf3e1ff90a210988b58ec33d5b9f8ca535f23b3
29,7,73db14b73028ebf280b49ec8251b1d7ef7b10c743d47f379ad2b454baf236695
29,8,3f74e17469a31573b21f8e7c2e7eef223ca2ac6bf74ab1879f4783e2f59ba3fc
29,9,705d77801d18f862aaf311cd1c51877488a8b07b6e8907bf44667f3f72dcba69
29,10,d692fcff42ff24de8504a38b33a35f33c89e01f0d54c957a94320aca7a8e793b
29,11,a7cc8783a041991c80d94897d98746598505ca13119c3c3a3bed42809183cb78
29,12,cb0c0a01429c0f8a45435757bf8ad42b627c0ebf166a1268de4d1c10c7475f49
29,13,8d7442bc77ef4ff4ec7229dbf427efd0fb0ea64b14b92c7ea16cd47786103fa0
29,14,32033b3b94b021cc10a2b81261dc0b6561a5231b7a48c17be301b71b57625d41
29,15,b0cdcb3c702d452b975c8634f2e021b1210704296aee1c8225a03e155b92bf83
30,0,466d2c93dcae97d82e211e7ed98e5665e58103a55496d68d77ec3de5f4b42edb
30,1,96d4f9fa5bd8e9786498ad0198b60f30e45757079bf5dbffe2ea4725b166b132
30,2,5f5aa972f0fc3c11f7c86dfdccdd9f4fad69319066488e5e1e547b36a2be984d
30,3,25c1db41fd480da5c82d9378da9ac645b74a07bb22794b28d34f9764e9d11751
30,4,f2d348e5c6eb439b29d22e15f7a98374c903af3ddb2427f5cc0b0730400bd6dd
30,5,24d431a01ff86599bb422e71591dfd09ef68b1d9ea638daac5503aeb4de825f8
30,6,b6f229b3d8811d78ece6e24067f9cc41925b900a1dd605bc34e2dc34bb82869d
30,7,3793655123f352dabad90d8acbc659b5e62d1f9ce7b94053094e13364bf5acc0
30,8,61ab0daa6326ee35a291e6010f0aeb827df081837bd13e4def41b287b624e810
30,9,6535d19ea5f1cec2aa4e0a2b332c059833a5dead84851bbf7600ee3040df73a4
30,10,a3718611e087467a0cef8921f0c2ea4f35036382e5c6d613ff038bd010cc93bb
30,11,44dda6fb84630ce8c6930028aece1082b4416978e3094f61963e2622ad429b22
30,12,e8e38e4a0bbdfd748256afb61c43f4502baba80c53c6727356b664ca8ea673de
30,13,d278ae271c90d3017d1b3139a4716c649986c073c09da5a8d3908016ec1927e2
30,14,2d0dba6f0e8c0101a670a56e1e953c195798b66290a6e05fcfccd67da32c4a68
30,15,6a86c1ac2d3447893a83c76a164cf20518022dd3e7374c30d74993fa57b990ae
31,0,6dc484cb889b65b4b6479ed27ccf27b68a1bd169cb88f992826d3474befe8263
31,1,bc7c18b5532ba73301167da64aae228130bdf50382119385926848aa1ddbebfd
31,2,05fd481964f28f1d1dbefa2589974eb3fbe3aa72e173731a2255bb89530d9f1d
31,3,6b782c28cc2c7b19741533e31371952eb33dc228aa75dac9d7e2ce9093db1f53
31,4,f277aa8140a17d606e4100632f201634b5c450e2d07d4cbe08184b22c4c9dc84
31,5,ffc1d436c8e00590c7d61886b82ec21e1e9bffe2fdbb7e0e6d812a7ec089f6e2
31,6,197fc69b02f4f1d4657c79b708b17d289d5ffefcccc5ab728cceddeeb8cba115
31,7,dc22e23695b8994fede8f4f3131ce97837941c4210da9c79a9f85269e3cb116c
31,8,02cd801fd1bf57d22e517f229e3d8197950c7ea65d8416b1cbe5092d6567a225
31,9,d42a0163f16fb46b20918e803b2eb281c52d31aca6c69d26c6bb2834ad855c6e
31,10,625d0702eaf71085ee92a909490f5414134a3b6b11fa732837f7c295c7c298c9
31,11,8e37a7c968645c72a93596b13575911b0cfe5cb412572d08c8425b92b6e744f7
31,12,545369dd593554a46cc43ff84f6570b40f456309dba670a6e8e55d3ea44494ba
31,13,23826326e1e445a9753da3094246f126fa4b01db3e6db946ba59c3983f02c922
31,14,ca6310a0eda5921f317f0f74dc2e19c25a3455c4d9964938390a7711ac2f34dd
31,15,d14e2c4a5439978d4d5835251c359942ac3e63f8991dc989c30f9f95b617dbef
";

/// Parsed `(num_super_rounds, domain, expected_ciphertext)` rows from [`FULL_RD_GRID_CT`].
fn full_rd_grid() -> Vec<(usize, u8, [u8; 32])> {
    let mut out = Vec::with_capacity(512);
    for line in FULL_RD_GRID_CT.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(',');
        let rounds: usize = parts
            .next()
            .expect("R field present")
            .parse()
            .expect("R is a valid number");
        let domain: u8 = parts
            .next()
            .expect("D field present")
            .parse()
            .expect("D is a valid number");
        let hex = parts.next().expect("hex field present");
        let bytes = hex_to_bytes(hex);
        let mut ct = [0u8; 32];
        ct.copy_from_slice(&bytes);
        out.push((rounds, domain, ct));
    }
    out
}

/// Two independently-implemented designer references — bitsliced `saturnin_portable.c` (Part D's
/// `NON_HASH_DOMAIN_CT`) and plain `ref/saturnin.c` (this table) — must agree at every point they
/// both cover. This does not touch libQ at all; it is a sanity check on the oracle data itself,
/// and is why the rest of `FULL_RD_GRID_CT` can be trusted at the 507 points Part D never covered.
#[test]
fn full_grid_ct_agrees_with_non_hash_domain_ct() {
    let grid = full_rd_grid();
    for domain in 1u8..=5 {
        let (_, _, ct) = grid
            .iter()
            .find(|&&(rounds, d, _)| rounds == 10 && d == domain)
            .expect("full grid covers (rounds=10, domain=1..=5)");
        assert_eq!(
            *ct,
            NON_HASH_DOMAIN_CT[(domain - 1) as usize],
            "the two designer reference implementations disagree at (rounds=10, domain={domain}) \
             — investigate before trusting the rest of the full (R, D) grid table"
        );
    }
}

/// The scalar bs32 core must match the designers' generic reference at all 512 `(R, D)` points it
/// accepts — not just the 7 points Part A/Part D happen to cover.
#[test]
fn scalar_bs32_kernel_matches_designers_reference_for_full_rd_grid() -> Result<()> {
    let key = [0x5Au8; 32];
    let grid = full_rd_grid();
    assert_eq!(grid.len(), 512, "expected the full 32 x 16 (R, D) grid");

    for (rounds, domain, expected) in grid {
        let mut block = non_hash_domain_block(domain);
        SaturninBs32Core::new(rounds, domain)?.encrypt_block(&key, &mut block)?;
        assert_eq!(
            block, expected,
            "scalar bs32 core disagreed with the designers' ref/saturnin.c at \
             (rounds={rounds}, domain={domain})"
        );
    }
    Ok(())
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_bs32_kernel_matches_designers_reference_for_full_rd_grid() -> Result<()> {
    if !runtime::has_avx2() {
        return Ok(());
    }

    let key = [0x5Au8; 32];
    let grid = full_rd_grid();
    assert_eq!(grid.len(), 512, "expected the full 32 x 16 (R, D) grid");

    for (rounds, domain, expected) in grid {
        let block = non_hash_domain_block(domain);
        let mut lanes = [block; 8];
        // SAFETY: guarded by `runtime::has_avx2()` above.
        unsafe {
            avx2::encrypt_blocks8(rounds, domain, &key, &mut lanes)?;
        }
        for (lane, out) in lanes.iter().enumerate() {
            assert_eq!(
                *out, expected,
                "AVX2 bs32 kernel (lane {lane}) disagreed with the designers' ref/saturnin.c at \
                 (rounds={rounds}, domain={domain})"
            );
        }
    }
    Ok(())
}

/// NEON counterpart, structurally identical to
/// `neon_bs32_kernel_matches_designers_c_for_non_hash_domains` above (same `runtime::has_neon()`
/// guard, same `neon::encrypt_block_bs32` call shape) — NOT executed, for lack of aarch64
/// hardware or an emulator on the authoring host, and its aarch64 cross-compile was NOT verified
/// either: `cargo check -p lib-q-saturnin --features simd-neon --target
/// aarch64-unknown-linux-gnu --tests` (attempted on the authoring host) fails before reaching
/// this file, because the crate's `criterion` dev-dependency pulls in `alloca`, whose build
/// script needs an `aarch64-linux-gnu-gcc` this host does not have (OBSERVED: "failed to find
/// tool \"aarch64-linux-gnu-gcc\": program not found"). The existing test above's doc comment
/// says that check was done by temporarily dropping the `criterion` dev-dependency from
/// `Cargo.toml` — that edit is outside this lane's file ownership (another agent owns
/// `Cargo.toml` concurrently), so it was not repeated here. Treat this test as source-reviewed
/// only (it mirrors an already-existing, presumably-checked test) until someone with Cargo.toml
/// access or aarch64 hardware verifies it for real.
#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[test]
fn neon_bs32_kernel_matches_designers_reference_for_full_rd_grid() -> Result<()> {
    if !runtime::has_neon() {
        return Ok(());
    }

    let key = [0x5Au8; 32];
    let grid = full_rd_grid();
    assert_eq!(grid.len(), 512, "expected the full 32 x 16 (R, D) grid");

    for (rounds, domain, expected) in grid {
        let mut neon_block = non_hash_domain_block(domain);
        // SAFETY: guarded by `runtime::has_neon()` above.
        unsafe {
            neon::encrypt_block_bs32(rounds, domain, &key, &mut neon_block)?;
        }
        assert_eq!(
            neon_block, expected,
            "NEON bs32 kernel disagreed with the designers' ref/saturnin.c at \
             (rounds={rounds}, domain={domain})"
        );
    }
    Ok(())
}
