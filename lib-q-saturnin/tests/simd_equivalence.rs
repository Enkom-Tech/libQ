#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_saturnin::bs32_core::SaturninBs32Core;
use lib_q_saturnin::core::SaturninCore;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
use lib_q_saturnin::simd::{
    SimdOptimizedCore,
    encrypt_block_dispatch,
    encrypt_blocks8_dispatch,
    runtime,
    simd_xor,
};

fn fill_deterministic(seed: u64, out: &mut [u8]) {
    let mut x = seed;
    for b in out {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = (x >> 56) as u8;
    }
}

#[test]
fn scalar_reference_round_trip() {
    let core = SaturninCore::new(10, 1).expect("core");
    let mut key = [0u8; 32];
    let mut block = [0u8; 32];
    fill_deterministic(7, &mut key);
    fill_deterministic(11, &mut block);
    let original = block;
    core.encrypt_block(&key, &mut block).expect("encrypt");
    core.decrypt_block(&key, &mut block).expect("decrypt");
    assert_eq!(block, original);
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn simd_wrapper_matches_scalar_for_multiple_vectors() {
    let scalar = SaturninCore::new(10, 1).expect("scalar");
    let simd = SimdOptimizedCore::new(10, 1).expect("simd");

    for i in 0..128u64 {
        let mut key = [0u8; 32];
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        fill_deterministic(0x1000 + i, &mut key);
        fill_deterministic(0x2000 + i, &mut b1);
        b2.copy_from_slice(&b1);

        simd.encrypt_block(&key, &mut b1).expect("simd encrypt");
        scalar.encrypt_block(&key, &mut b2).expect("scalar encrypt");
        assert_eq!(b1, b2, "mismatch at vector {}", i);
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn simd_xor_matches_scalar() {
    for i in 0..64u64 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_deterministic(0x3000 + i, &mut a);
        fill_deterministic(0x4000 + i, &mut b);

        let mut simd_out = [0u8; 32];
        simd_xor::xor_blocks_32(&a, &b, &mut simd_out);

        let mut scalar_out = [0u8; 32];
        for j in 0..32 {
            scalar_out[j] = a[j] ^ b[j];
        }
        assert_eq!(simd_out, scalar_out);
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_batch_matches_scalar_bs32() {
    if !runtime::has_avx2() {
        return;
    }

    let scalar = SaturninBs32Core::new(16, 8).expect("core");
    let mut key = [0u8; 32];
    fill_deterministic(0x5555, &mut key);

    let mut blocks = [[0u8; 32]; 8];
    for (i, block) in blocks.iter_mut().enumerate() {
        fill_deterministic(0x6000 + i as u64, block);
    }
    let mut scalar_blocks = blocks;

    // SAFETY: guarded by runtime AVX2 detection.
    unsafe {
        lib_q_saturnin::simd::avx2::encrypt_blocks8(16, 8, &key, &mut blocks).expect("avx2");
    }

    for block in &mut scalar_blocks {
        scalar.encrypt_block(&key, block).expect("scalar");
    }

    assert_eq!(blocks, scalar_blocks);
}

/// `avx2::encrypt_blocks8` (bs32 bitsliced representation) and `SaturninCore::encrypt_block`
/// (half-word representation) are two internal encodings of the *same* Saturnin block cipher, so
/// on identical byte inputs they must produce identical bytes at every `(R, D)`.
///
/// This test previously read `raw_avx2_kernel_is_not_core_equivalent_domain1` and asserted
/// `assert_ne!` — it was pinning a defect, not a property. `avx2::round_constants` carried its own
/// copy of a broken round-constant LFSR that was short-circuited by hardcoded ROM tables only at
/// the Saturnin-Hash pairs `(16, 7)`/`(16, 8)`; at `(10, 1)` the broken generator ran and the two
/// representations disagreed. With `avx2::round_constants` delegating to the single corrected
/// generator, they agree — and the agreed value is the designers' own: compiling
/// `reference/saturnin/Implementations/extra/saturnin_portable.c` and calling
/// `saturnin_block_encrypt(10, RC_10_1, ...)` reproduces it byte for byte (see
/// `tests/reference_oracle.rs`, which checks `RC_10_1..RC_10_5` against that same reference file).
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn raw_avx2_kernel_matches_core_domain1() {
    if !runtime::has_avx2() {
        return;
    }

    let scalar = SaturninCore::new(10, 1).expect("core");
    for i in 0..64u64 {
        let mut key = [0u8; 32];
        let mut block = [0u8; 32];
        fill_deterministic(0x7000 + i, &mut key);
        fill_deterministic(0x8000 + i, &mut block);

        let mut lanes = [block; 8];
        // SAFETY: guarded by runtime AVX2 detection.
        unsafe {
            lib_q_saturnin::simd::avx2::encrypt_blocks8(10, 1, &key, &mut lanes).expect("avx2");
        }

        let mut scalar_block = block;
        scalar
            .encrypt_block(&key, &mut scalar_block)
            .expect("scalar");
        assert_eq!(
            lanes[0], scalar_block,
            "raw AVX2 bs32 kernel disagreed with the half-word core on vector {i}"
        );
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_core_kernel_matches_scalar_core_domain1() {
    if !runtime::has_avx2() {
        return;
    }

    let scalar = SaturninCore::new(10, 1).expect("core");
    for i in 0..128u64 {
        let mut key = [0u8; 32];
        fill_deterministic(0xD000 + i, &mut key);
        let mut blocks = [[0u8; 32]; 8];
        for (lane, block) in blocks.iter_mut().enumerate() {
            fill_deterministic(0xE000 + i * 8 + lane as u64, block);
        }
        let mut scalar_blocks = blocks;

        // SAFETY: guarded by runtime AVX2 detection.
        unsafe {
            lib_q_saturnin::simd::avx2::encrypt_blocks8_core(10, 1, &key, &mut blocks)
                .expect("avx2-core");
        }

        for block in &mut scalar_blocks {
            scalar.encrypt_block(&key, block).expect("scalar");
        }
        assert_eq!(blocks, scalar_blocks, "mismatch on corpus batch {i}");
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_core_kernel_matches_scalar_core_domain1_edge_vectors() {
    if !runtime::has_avx2() {
        return;
    }

    let scalar = SaturninCore::new(10, 1).expect("core");
    let edge_keys = [
        [0x00u8; 32],
        [0xFFu8; 32],
        core::array::from_fn(|i| i as u8),
        core::array::from_fn(|i| if i % 2 == 0 { 0x80 } else { 0x7F }),
    ];
    let edge_blocks = [
        [0x00u8; 32],
        [0xFFu8; 32],
        core::array::from_fn(|i| i as u8),
        core::array::from_fn(|i| if i % 2 == 0 { 0xAA } else { 0x55 }),
        core::array::from_fn(|i| if i % 2 == 0 { 0x80 } else { 0x01 }),
    ];

    for key in edge_keys {
        let mut batch = [[0u8; 32]; 8];
        for (lane, block) in batch.iter_mut().enumerate() {
            *block = edge_blocks[lane % edge_blocks.len()];
        }
        let mut scalar_batch = batch;

        // SAFETY: guarded by runtime AVX2 detection.
        unsafe {
            lib_q_saturnin::simd::avx2::encrypt_blocks8_core(10, 1, &key, &mut batch)
                .expect("avx2-core");
        }
        for block in &mut scalar_batch {
            scalar.encrypt_block(&key, block).expect("scalar");
        }
        assert_eq!(batch, scalar_batch);
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn dispatch_single_lane_matches_scalar_core_domain1() {
    if !runtime::has_avx2() {
        return;
    }

    let scalar = SaturninCore::new(10, 1).expect("core");
    for i in 0..64u64 {
        let mut key = [0u8; 32];
        let mut block = [0u8; 32];
        fill_deterministic(0xB000 + i, &mut key);
        fill_deterministic(0xC000 + i, &mut block);
        let mut dispatched = block;
        encrypt_block_dispatch(10, 1, &key, &mut dispatched).expect("dispatch");
        let mut scalar_block = block;
        scalar
            .encrypt_block(&key, &mut scalar_block)
            .expect("scalar");
        assert_eq!(dispatched, scalar_block, "mismatch on vector {i}");
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn dispatch_batch_matches_scalar_core_domain1() {
    if !runtime::has_avx2() {
        return;
    }

    let scalar = SaturninCore::new(10, 1).expect("core");
    let mut key = [0u8; 32];
    fill_deterministic(0x9000, &mut key);

    let mut blocks = [[0u8; 32]; 8];
    for (i, block) in blocks.iter_mut().enumerate() {
        fill_deterministic(0xA000 + i as u64, block);
    }
    let mut scalar_blocks = blocks;

    encrypt_blocks8_dispatch(10, 1, &key, &mut blocks, None).expect("dispatch");

    for block in &mut scalar_blocks {
        scalar.encrypt_block(&key, block).expect("scalar");
    }
    assert_eq!(blocks, scalar_blocks);
}

#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[test]
fn neon_runtime_detection_is_consistent() {
    // Presence check only; hardware-dependent behavior is validated in integration CI.
    let _ = runtime::has_neon();
}

// ---------------------------------------------------------------------------
// Additional coverage: bs32 dispatch path, error paths, SimdCapabilities,
// SimdOptimizedCore::decrypt_block, reuse_scalar_core, and the plain XOR
// scalar routine.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn dispatch_single_block_bs32_path_matches_scalar_bs32_core() {
    use lib_q_saturnin::bs32_core::SaturninBs32Core;

    // (num_super_rounds = 16, domain in {7, 8}) selects the bs32 kernel path
    // inside `uses_bs32_kernel`; exercise both domains.
    for domain in [7u8, 8u8] {
        let scalar = SaturninBs32Core::new(16, domain).expect("bs32 core");
        for i in 0..16u64 {
            let mut key = [0u8; 32];
            let mut block = [0u8; 32];
            fill_deterministic(0x11_0000 + u64::from(domain) * 0x100 + i, &mut key);
            fill_deterministic(0x12_0000 + u64::from(domain) * 0x100 + i, &mut block);

            let mut dispatched = block;
            encrypt_block_dispatch(16, domain, &key, &mut dispatched).expect("dispatch");

            let mut scalar_block = block;
            scalar
                .encrypt_block(&key, &mut scalar_block)
                .expect("scalar bs32");

            assert_eq!(
                dispatched, scalar_block,
                "bs32 dispatch mismatch at domain {domain}, vector {i}"
            );
        }
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn dispatch_batch_bs32_path_matches_scalar_bs32_core() {
    use lib_q_saturnin::bs32_core::SaturninBs32Core;

    for domain in [7u8, 8u8] {
        let scalar = SaturninBs32Core::new(16, domain).expect("bs32 core");
        let mut key = [0u8; 32];
        fill_deterministic(0x13_0000 + u64::from(domain), &mut key);

        let mut blocks = [[0u8; 32]; 8];
        for (i, block) in blocks.iter_mut().enumerate() {
            fill_deterministic(0x14_0000 + u64::from(domain) * 0x10 + i as u64, block);
        }
        let mut scalar_blocks = blocks;

        encrypt_blocks8_dispatch(16, domain, &key, &mut blocks, None).expect("dispatch batch");

        for block in &mut scalar_blocks {
            scalar.encrypt_block(&key, block).expect("scalar bs32");
        }
        assert_eq!(
            blocks, scalar_blocks,
            "bs32 batch mismatch at domain {domain}"
        );
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn dispatch_batch_non_bs32_path_reuses_supplied_scalar_core() {
    let scalar_core = SaturninCore::new(10, 1).expect("core");
    let mut key = [0u8; 32];
    fill_deterministic(0x15_0000, &mut key);

    let mut blocks = [[0u8; 32]; 8];
    for (i, block) in blocks.iter_mut().enumerate() {
        fill_deterministic(0x16_0000 + i as u64, block);
    }
    let mut expected = blocks;

    encrypt_blocks8_dispatch(10, 1, &key, &mut blocks, Some(&scalar_core))
        .expect("dispatch with reused core");

    for block in &mut expected {
        scalar_core.encrypt_block(&key, block).expect("scalar");
    }
    assert_eq!(
        blocks, expected,
        "reused-core batch path diverged from scalar core"
    );
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn dispatch_single_block_rejects_wrong_length_key() {
    let mut block = [0u8; 32];
    let short_key = [0u8; 16];
    let err = encrypt_block_dispatch(10, 1, &short_key, &mut block)
        .expect_err("wrong-length key must be rejected");
    match err {
        lib_q_core::Error::InvalidKeySize { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn dispatch_single_block_rejects_wrong_length_block() {
    let key = [0u8; 32];
    let mut short_block = [0u8; 16];
    let err = encrypt_block_dispatch(10, 1, &key, &mut short_block)
        .expect_err("wrong-length block must be rejected");
    match err {
        lib_q_core::Error::InvalidMessageSize { max, actual } => {
            assert_eq!(max, 32);
            assert_eq!(actual, 16);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn dispatch_batch_rejects_wrong_length_key() {
    let short_key = [0u8; 8];
    let mut blocks = [[0u8; 32]; 8];
    let err = encrypt_blocks8_dispatch(10, 1, &short_key, &mut blocks, None)
        .expect_err("wrong-length key must be rejected for batch dispatch");
    match err {
        lib_q_core::Error::InvalidKeySize { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 8);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn simd_optimized_core_decrypt_matches_scalar_core() {
    let simd = SimdOptimizedCore::new(10, 1).expect("simd");
    let scalar = SaturninCore::new(10, 1).expect("scalar");

    for i in 0..32u64 {
        let mut key = [0u8; 32];
        let mut original = [0u8; 32];
        fill_deterministic(0x17_0000 + i, &mut key);
        fill_deterministic(0x18_0000 + i, &mut original);

        let mut via_simd = original;
        simd.encrypt_block(&key, &mut via_simd).expect("encrypt");
        simd.decrypt_block(&key, &mut via_simd).expect("decrypt");
        assert_eq!(via_simd, original, "simd round-trip mismatch on vector {i}");

        let mut via_scalar = original;
        scalar
            .encrypt_block(&key, &mut via_scalar)
            .expect("encrypt");
        scalar
            .decrypt_block(&key, &mut via_scalar)
            .expect("decrypt");
        assert_eq!(
            via_simd, via_scalar,
            "simd/scalar decrypt disagreement on vector {i}"
        );
    }
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn simd_capabilities_helpers_reflect_flags() {
    use lib_q_saturnin::simd::SimdCapabilities;

    let none = SimdCapabilities {
        has_avx2: false,
        has_neon: false,
    };
    assert!(!none.has_simd());
    assert_eq!(none.best_simd(), "Scalar");

    let avx2_only = SimdCapabilities {
        has_avx2: true,
        has_neon: false,
    };
    assert!(avx2_only.has_simd());
    assert_eq!(avx2_only.best_simd(), "AVX2");

    let neon_only = SimdCapabilities {
        has_avx2: false,
        has_neon: true,
    };
    assert!(neon_only.has_simd());
    assert_eq!(neon_only.best_simd(), "NEON");

    // AVX2 takes priority when both are (hypothetically) set.
    let both = SimdCapabilities {
        has_avx2: true,
        has_neon: true,
    };
    assert!(both.has_simd());
    assert_eq!(both.best_simd(), "AVX2");
}

#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[test]
fn xor_blocks_32_scalar_matches_dispatch() {
    for i in 0..16u64 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_deterministic(0x19_0000 + i, &mut a);
        fill_deterministic(0x1A_0000 + i, &mut b);

        let mut scalar_out = [0u8; 32];
        simd_xor::xor_blocks_32_scalar(&a, &b, &mut scalar_out);

        let mut dispatch_out = [0u8; 32];
        simd_xor::xor_blocks_32(&a, &b, &mut dispatch_out);

        assert_eq!(
            scalar_out, dispatch_out,
            "scalar XOR disagreed with dispatch on vector {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// avx2 kernel input-validation paths. These kernels are `pub unsafe fn` and are
// never called with an out-of-range domain/round-count from anywhere else in the
// crate (all internal callers pass domain in 1..=8 and rounds <= 16), so the
// `domain > 15` / `num_super_rounds > 31` guards are otherwise dead in every
// existing test. They are public API, so call them directly here.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_encrypt_blocks8_rejects_out_of_range_domain() {
    if !runtime::has_avx2() {
        return;
    }
    use lib_q_saturnin::simd::avx2;

    let key = [0u8; 32];
    let mut blocks = [[0u8; 32]; 8];
    // domain = 16 is out of the 4-bit (0..=15) range the bs32 kernel accepts.
    let err = unsafe { avx2::encrypt_blocks8(10, 16, &key, &mut blocks) }
        .expect_err("domain > 15 must be rejected");
    match err {
        lib_q_core::Error::InvalidAlgorithm { .. } => {}
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_encrypt_blocks8_rejects_out_of_range_super_rounds() {
    if !runtime::has_avx2() {
        return;
    }
    use lib_q_saturnin::simd::avx2;

    let key = [0u8; 32];
    let mut blocks = [[0u8; 32]; 8];
    // num_super_rounds = 32 is out of the accepted 0..=31 range.
    let err = unsafe { avx2::encrypt_blocks8(32, 7, &key, &mut blocks) }
        .expect_err("num_super_rounds > 31 must be rejected");
    match err {
        lib_q_core::Error::InvalidAlgorithm { .. } => {}
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_encrypt_blocks8_core_rejects_out_of_range_domain() {
    if !runtime::has_avx2() {
        return;
    }
    use lib_q_saturnin::simd::avx2;

    let key = [0u8; 32];
    let mut blocks = [[0u8; 32]; 8];
    let err = unsafe { avx2::encrypt_blocks8_core(10, 16, &key, &mut blocks) }
        .expect_err("domain > 15 must be rejected");
    match err {
        lib_q_core::Error::InvalidAlgorithm { .. } => {}
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn avx2_encrypt_blocks8_core_rejects_out_of_range_rounds() {
    if !runtime::has_avx2() {
        return;
    }
    use lib_q_saturnin::simd::avx2;

    let key = [0u8; 32];
    let mut blocks = [[0u8; 32]; 8];
    let err = unsafe { avx2::encrypt_blocks8_core(32, 1, &key, &mut blocks) }
        .expect_err("num_rounds > 31 must be rejected");
    match err {
        lib_q_core::Error::InvalidAlgorithm { .. } => {}
        other => panic!("unexpected error variant: {other:?}"),
    }
}
