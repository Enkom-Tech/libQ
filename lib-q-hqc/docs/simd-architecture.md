# HQC SIMD Architecture Documentation

## Overview

The HQC implementation includes optional AVX2 SIMD optimizations for some operations. Not every `*_avx2`-named function is actually accelerated — see "AVX2 Optimizations" below for which operations genuinely use AVX2 intrinsics, which are only conditionally accelerated, and which have no AVX2 implementation at all. No percentage speedup figure is published for this crate; see `benches/performance_benchmarks.rs` for a reproducible `simd-avx2`-vs-default comparison. This document describes the architecture, design decisions, and implementation details.

PKE-layer vector semantics (sparse sampling, `xof_get_bytes`, schoolbook vs Toom multiply) are documented in [vector-operations.md](vector-operations.md).

## Architecture Design

### Zero-Sized Type (ZST) Pattern

The SIMD implementation uses a Zero-Sized Type pattern for static dispatch:

```rust
/// Portable (non-SIMD) implementation marker
pub struct Portable;

/// AVX2 implementation marker  
pub struct Avx2;
```

**Benefits:**
- Zero runtime overhead for dispatch
- Compile-time optimization opportunities
- Clean trait-based interface
- No dynamic allocation required

### Trait-Based Interface

All SIMD operations are defined through traits:

```rust
pub trait PolynomialOps {
    fn sparse_dense_mul(
        output: &mut [u8],
        sparse: &[u8],
        dense: &[u8],
        weight: u32,
        n_bits: usize,
    );
    fn shift_xor(dest: &mut [u64], source: &[u64], distance: usize);
    fn vect_add(output: &mut [u8], a: &[u8], b: &[u8]);
}

pub trait SyndromeOps {
    fn generate_syndrome(syndrome: &mut [u8], vector: &[u8], parity: &[u8]);
    fn correct_errors(corrected: &mut [u8], received: &[u8], syndrome: &[u8]);
}
```

**Benefits:**
- Polymorphic interface for different implementations
- Easy testing and validation
- Clear separation of concerns
- Extensible for future SIMD instruction sets

## Runtime CPU Detection

### Custom CPUID Implementation

The implementation uses custom CPUID detection for maximum control:

```rust
pub fn detect_cpu_features() {
    #[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
    {
        unsafe {
            // CPUID function 1: Processor Info and Feature Bits
            let result = core::arch::x86_64::__cpuid(1);
            
            // Check OSXSAVE (bit 27 of ECX)
            let osxsave = (result.ecx & (1 << 27)) != 0;
            
            if osxsave {
                // CPUID function 7: Extended Features
                let result = core::arch::x86_64::__cpuid_count(7, 0);
                
                // Check AVX2 (bit 5 of EBX)
                let avx2 = (result.ebx & (1 << 5)) != 0;
                
                if avx2 {
                    // Verify OS support via XGETBV
                    let xcr0 = core::arch::x86_64::_xgetbv(0);
                    let avx_enabled = (xcr0 & 0x6) == 0x6;
                    
                    if avx_enabled {
                        AVX2_AVAILABLE.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}
```

**Features:**
- Thread-safe detection with atomic caching
- One-time detection with cached results
- Graceful fallback for unsupported systems
- No external dependencies

### Detection Process

1. **OSXSAVE Check**: Verify OS supports extended state management
2. **AVX2 Check**: Verify CPU supports AVX2 instructions
3. **OS Support Check**: Verify OS enables AVX2 state via XGETBV
4. **Caching**: Store result in atomic boolean for thread safety

## AVX2 Optimizations

### The actual dense polynomial multiply — `gf2x` Toom-3/PCLMUL

HQC's polynomial multiply (`HqcPke::vect_mul`) is the operation that matters for
performance, and it is **not** `PolynomialOps::sparse_dense_mul`. It dispatches
to `simd::avx2::gf2x::avx2_vect_mul_mod_xnm1`, a Toom-3 + Karatsuba + PCLMUL
implementation carrying real `#[target_feature(enable = "avx2", enable =
"pclmulqdq")]` attributes, with a schoolbook fallback when AVX2 is unavailable.
See the "Dispatch Logic" section below for the real call site.

### `PolynomialOps::sparse_dense_mul` — no AVX2 implementation

`sparse_dense_mul` is a separate, trait-only operation with **no AVX2
implementation**. Its `Avx2` impl delegates to the portable code
(`portable::sparse_dense_mul_portable`) in every build configuration —
enabling `simd-avx2` changes nothing for this function. It has no production
callers; it exists only for the `PolynomialOps` trait shape and
cross-implementation equivalence tests. A previous revision of this document
showed a fictional `sparse_dense_mul_avx2` implementation (calling a
`shift_xor_avx2_unsafe` helper that has never existed in this crate) — that
code sample was never accurate and has been removed.

Vectorizing `sparse_dense_mul` for real would also be the wrong investment:
its portable algorithm is `O(n_bits × weight)` bit-at-a-time cyclic shift-XOR,
asymptotically worse than the Toom-3 approach `gf2x` already uses for the same
ring product, and off the KEM's hot path entirely.

### Vector Operations

AVX2-optimized vector addition (XOR):

```rust
pub fn vect_add_avx2(output: &mut [u8], a: &[u8], b: &[u8]) {
    unsafe {
        let chunks = output.len() / 32;
        
        for i in 0..chunks {
            let offset = i * 32;
            let vec_a = _mm256_loadu_si256(a.as_ptr().add(offset) as *const __m256i);
            let vec_b = _mm256_loadu_si256(b.as_ptr().add(offset) as *const __m256i);
            let result = _mm256_xor_si256(vec_a, vec_b);
            _mm256_storeu_si256(output.as_mut_ptr().add(offset) as *mut __m256i, result);
        }
        
        // Handle remaining bytes with portable implementation
        let remaining = output.len() % 32;
        if remaining > 0 {
            let offset = chunks * 32;
            for j in 0..remaining {
                output[offset + j] = a[offset + j] ^ b[offset + j];
            }
        }
    }
}
```

**Features:**
- 32-byte vector processing
- Automatic fallback for unaligned data
- Hybrid approach for optimal performance

### Syndrome Generation

AVX2-optimized syndrome computation:

```rust
pub fn generate_syndrome_avx2(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
    unsafe {
        let chunks = syndrome.len() / 32;
        
        for i in 0..chunks {
            let offset = i * 32;
            let vec_chunk = _mm256_loadu_si256(vector.as_ptr().add(offset) as *const __m256i);
            let parity_chunk = _mm256_loadu_si256(parity.as_ptr().add(offset) as *const __m256i);
            let syndrome_chunk = compute_syndrome_chunk(vec_chunk, parity_chunk);
            _mm256_storeu_si256(syndrome.as_mut_ptr().add(offset) as *mut __m256i, syndrome_chunk);
        }
    }
}
```

## Safety Considerations

### Unsafe Code Management

All unsafe operations are properly documented and contained:

```rust
#![allow(unsafe_code)]

/// # Safety
///
/// This function uses unsafe AVX2 intrinsics and requires:
/// - x86_64 CPU with AVX2 support (Intel Haswell+ or AMD Excavator+)
/// - OS support for AVX2 state management (XSAVE/XSAVEOPT)
/// - Proper memory alignment (handled internally with unaligned loads/stores)
/// - All input slices must be valid and properly sized
///
/// The function is safe to call when the above conditions are met and
/// the `simd-avx2` feature is enabled. Runtime CPU feature detection
/// should be performed before calling this function.
pub fn vect_add_avx2(output: &mut [u8], a: &[u8], b: &[u8]) {
    unsafe {
        // Implementation...
    }
}
```

**Safety Features:**
- Comprehensive safety documentation
- Runtime CPU feature detection
- Graceful fallback to portable implementation
- Bounds checking and error handling
- Thread-safe operation

### Memory Safety

- **Unaligned Access**: Uses `_mm256_loadu_si256` and `_mm256_storeu_si256` for safe unaligned access
- **Bounds Checking**: All operations include proper bounds checking
- **Buffer Validation**: Input validation ensures proper slice sizes
- **Atomic Operations**: Thread-safe CPU feature detection

## Performance Characteristics

### Benchmark Results

No measured speedup table is published for this crate. A previous revision of
this document listed a "Sparse-Dense Multiplication ... 40% faster" figure;
that row could not have been measured from this code, because the AVX2 and
portable arms of `sparse_dense_mul` are byte-identical (see above) — enabling
`simd-avx2` changes nothing for that function, so there is nothing to measure
a speedup for. The other rows (keygen/encapsulation/decapsulation) were not
independently verified and have been removed pending a reproducible number.

For a reproducible `simd-avx2`-vs-default comparison on real HQC operations
(keygen/encapsulate/decapsulate), run
`lib-q-hqc/benches/performance_benchmarks.rs`, e.g.:

```bash
BENCH_CRITERION_FLAGS="--save-baseline portable --warm-up-time 3 --measurement-time 10" \
  bash scripts/run-criterion-benches.sh -p lib-q-hqc -f "alloc,hqc128,random" -b performance_benchmarks

BENCH_CRITERION_FLAGS="--save-baseline avx2 --warm-up-time 3 --measurement-time 10" \
  bash scripts/run-criterion-benches.sh -p lib-q-hqc -f "alloc,hqc128,random,simd-avx2" -b performance_benchmarks

cargo bench -p lib-q-hqc --bench performance_benchmarks \
  --features "alloc,hqc128,random,simd-avx2" -- --load-baseline avx2 --baseline portable
```

The benchmark group name is suffixed with the backend string reported by
`simd::runtime::get_best_implementation()` (`"avx2"` or `"portable"`), so a
run that reports the same backend for both baselines is not a valid
comparison.

### Optimization Strategies

1. **Vectorization**: 32-byte AVX2 vector processing
2. **Memory Access**: Unaligned loads/stores for flexibility
3. **Bit Operations**: Efficient bit-level shifts with AVX2
4. **Hybrid Processing**: AVX2 for aligned data, portable for remainder
5. **Runtime Detection**: Zero-overhead dispatch with cached results

## Integration with HQC

### Dispatch Logic

The HQC implementation automatically selects the best available implementation:

```rust
// This is the real dispatch (hqc_pke.rs); it does not call `sparse_dense_mul`.
fn vect_mul(&self, output: &mut [u64], a: &[u64], b: &[u64]) -> Result<(), HqcPkeError> {
    #[cfg(all(feature = "simd-avx2", target_arch = "x86_64", feature = "alloc"))]
    {
        if crate::simd::runtime::has_avx2() {
            return crate::simd::avx2::gf2x::avx2_vect_mul_mod_xnm1::<P>(output, a, b);
        }
    }
    // Fallback: schoolbook GF(2)[x]/(x^n-1) multiply
    schoolbook_vect_mul_mod_xnm1(output, a, b, P::VEC_N_SIZE_64, P::N)
}
```

**Features:**
- Automatic runtime detection
- Zero-overhead dispatch
- Graceful fallback
- Feature flag control

## Testing and Validation

### Correctness Testing

Comprehensive test suite ensures AVX2 and portable implementations produce identical results:

```rust
#[test]
fn test_avx2_vect_add_correctness() {
    let mut output_avx2 = [0u8; 128];
    let mut output_portable = [0u8; 128];
    let a = [0xABu8; 128];
    let b = [0xCDu8; 128];

    Avx2::vect_add(&mut output_avx2, &a, &b);
    Portable::vect_add(&mut output_portable, &a, &b);

    assert_eq!(output_avx2, output_portable);
}
```

(`sparse_dense_mul` has the same test shape, but for that operation the
equality holds trivially: `Avx2::sparse_dense_mul` delegates to the portable
implementation directly, in every configuration.)

**Test Coverage:**
- Large buffer operations (1KB, 4KB)
- Known-answer tests with reference vectors
- Stress tests with pseudo-random data
- Edge cases and boundary conditions
- All HQC parameter sets (HQC-128, HQC-192, HQC-256)

### Performance Testing

Criterion benchmarks provide detailed performance analysis:

```rust
// A meaningful avx2-vs-portable comparison must exercise two different code
// paths. Timing `Avx2::sparse_dense_mul` against `Portable::sparse_dense_mul`
// would time the same function twice (the former delegates to the latter) —
// that is a defect this crate's benchmarks used to have and no longer do.
// The comparison that corresponds to what the KEM actually calls is:
fn bench_vect_mul_avx2_vs_schoolbook(c: &mut Criterion) {
    let mut group = c.benchmark_group("vect_mul");

    group.bench_function("avx2", |b| {
        b.iter(|| {
            avx2_vect_mul_mod_xnm1::<Hqc1Params>(&mut output, &a, &b_op);
        });
    });

    group.bench_function("schoolbook", |b| {
        b.iter(|| {
            schoolbook_vect_mul_mod_xnm1(&mut output, &a, &b_op, vec_n_size_64, n);
        });
    });
}
```

## Future Extensions

### Additional SIMD Instruction Sets

The architecture is designed for easy extension:

1. **AVX-512**: For even higher performance on supported CPUs
2. **NEON**: For ARM64 optimization
3. **AltiVec**: For PowerPC optimization

### Implementation Strategy

1. Create new ZST marker (e.g., `Avx512`, `Neon`)
2. Implement trait methods for new instruction set
3. Add runtime detection logic
4. Update dispatch logic with priority ordering
5. Add comprehensive tests and benchmarks

## Conclusion

The HQC SIMD architecture provides:

- **Targeted acceleration**: real AVX2 intrinsics for the operations the KEM
  actually calls (`gf2x` Toom-3/PCLMUL multiply, `vect_add`); no measured
  speedup figure is published — see `benches/performance_benchmarks.rs` for a
  reproducible comparison
- **Safety**: Comprehensive safety documentation and runtime detection
- **Flexibility**: Easy extension to new SIMD instruction sets
- **Reliability**: Extensive testing and validation
- **Maintainability**: Clean, well-documented code following Rust best practices

The implementation successfully balances performance optimization with safety and maintainability, providing a production-ready SIMD optimization layer for the HQC cryptographic algorithm.