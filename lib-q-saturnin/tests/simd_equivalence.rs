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

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn raw_avx2_kernel_is_not_core_equivalent_domain1() {
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
        assert_ne!(
            lanes[0], scalar_block,
            "raw AVX2 kernel unexpectedly matched core on vector {i}"
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

    encrypt_blocks8_dispatch(10, 1, &key, &mut blocks).expect("dispatch");

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
