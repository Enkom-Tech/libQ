//! Scrubbing of secret-derived scratch: SHAKE sponge lanes, squeeze buffers and seed copies.
//!
//! Gated on the `zeroize` feature exactly like every other wipe in this crate (`hardened`
//! implies it): without the feature these are no-ops and cost nothing.
//!
//! Every wipe funnels through here (and through `Sponge`'s / `KeccakStateX4`'s `Drop`) so that a
//! test can observe them: under `cfg(test)` each wipe is recorded in [`audit`] together with
//! whether the memory still held data when it was cleared. Removing a wipe removes its event, and
//! neutering the clear itself leaves a residue event, so the tests below fail either way.

/// Clear a byte buffer (squeeze output, seed copy).
#[inline(always)]
#[cfg_attr(not(any(test, feature = "zeroize")), allow(unused_variables))]
pub(crate) fn bytes(buf: &mut [u8]) {
    #[cfg(test)]
    let dirty = buf.iter().any(|&b| b != 0);
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(buf);
    #[cfg(test)]
    audit::record(audit::Event::Bytes {
        len: buf.len(),
        dirty,
        residue: buf.iter().any(|&b| b != 0),
    });
}

/// Clear several equally-shaped byte buffers.
#[inline(always)]
pub(crate) fn byte_blocks<const N: usize, const M: usize>(blocks: &mut [[u8; N]; M]) {
    for block in blocks.iter_mut() {
        bytes(block);
    }
}

/// Clear a coefficient buffer (rejection-sampling output holding secret polynomial coefficients).
#[inline(always)]
#[cfg_attr(not(any(test, feature = "zeroize")), allow(unused_variables))]
pub(crate) fn coefficients(buf: &mut [i32]) {
    #[cfg(test)]
    let dirty = buf.iter().any(|&c| c != 0);
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(buf);
    #[cfg(test)]
    audit::record(audit::Event::Coefficients {
        len: buf.len(),
        dirty,
        residue: buf.iter().any(|&c| c != 0),
    });
}

/// Clear one set of Keccak lanes. `rate` identifies the sponge flavour in the test audit only.
#[inline(always)]
#[cfg_attr(not(test), allow(unused_variables))]
pub(crate) fn lanes(state: &mut [u64; 25], rate: usize) {
    #[cfg(test)]
    let dirty = state.iter().any(|&l| l != 0);
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(state);
    #[cfg(test)]
    audit::record(audit::Event::Lanes {
        rate,
        dirty,
        residue: state.iter().any(|&l| l != 0),
    });
}

/// Test-only record of every wipe performed on the current thread.
#[cfg(test)]
pub(crate) mod audit {
    use std::cell::RefCell;
    use std::vec::Vec;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Event {
        /// A Keccak state (one lane set) of the given rate was cleared.
        Lanes {
            rate: usize,
            dirty: bool,
            residue: bool,
        },
        Bytes {
            len: usize,
            dirty: bool,
            residue: bool,
        },
        Coefficients {
            len: usize,
            dirty: bool,
            residue: bool,
        },
    }

    impl Event {
        /// `true` when memory still held non-zero data after the wipe ran.
        pub(crate) fn residue(&self) -> bool {
            match *self {
                Event::Lanes { residue, .. }
                | Event::Bytes { residue, .. }
                | Event::Coefficients { residue, .. } => residue,
            }
        }

        /// `true` when memory held non-zero data before the wipe ran.
        pub(crate) fn dirty(&self) -> bool {
            match *self {
                Event::Lanes { dirty, .. }
                | Event::Bytes { dirty, .. }
                | Event::Coefficients { dirty, .. } => dirty,
            }
        }
    }

    std::thread_local! {
        static LOG: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(event: Event) {
        LOG.with(|log| log.borrow_mut().push(event));
    }

    /// Drain and return this thread's wipe events.
    pub(crate) fn take() -> Vec<Event> {
        LOG.with(|log| core::mem::take(&mut *log.borrow_mut()))
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    //! Proof that the SHAKE states and squeeze buffers built during key generation and signing
    //! are cleared. Each test fails if the corresponding wipe is deleted (its event disappears) or
    //! reduced to a no-op (its event reports residue) -- checked by hand when this was written.
    use std::vec::Vec;

    use super::audit::{Event, take};
    use crate::constants::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
    use crate::sha3_shim::Sponge;

    fn assert_no_residue(events: &[Event]) {
        let leaked: Vec<_> = events.iter().filter(|e| e.residue()).collect();
        assert!(leaked.is_empty(), "wipe left data behind: {leaked:?}");
    }

    fn saw(events: &[Event], want: impl Fn(&Event) -> bool) -> bool {
        events.iter().any(|e| e.dirty() && want(e))
    }

    #[test]
    fn sponge_clears_absorbed_seed_when_dropped_unsqueezed() {
        take();
        {
            let mut s = Sponge::<136>::new();
            s.absorb(&[0xA5; 32]);
        }
        let events = take();
        assert_eq!(
            events,
            [Event::Lanes {
                rate: 136,
                dirty: true,
                residue: false
            }]
        );
    }

    #[test]
    fn sponge_clears_squeezed_state_when_dropped() {
        take();
        {
            let mut s = Sponge::<168>::new();
            s.absorb(&[0x5A; 32]);
            let mut out = [0u8; 500];
            s.squeeze(&mut out);
        }
        assert_eq!(
            take(),
            [Event::Lanes {
                rate: 168,
                dirty: true,
                residue: false
            }]
        );
    }

    macro_rules! keygen_and_sign_tests {
        ($module:ident, $param:ident, $backend:path, $gamma1_bytes:expr) => {
            mod $module {
                use super::*;
                use $backend as backend;
                use crate::ml_dsa_generic::$param::{
                    SIGNATURE_SIZE,
                    SIGNING_KEY_SIZE,
                    VERIFICATION_KEY_SIZE,
                };

                fn keygen() -> [u8; SIGNING_KEY_SIZE] {
                    let mut sk = [0u8; SIGNING_KEY_SIZE];
                    let mut vk = [0u8; VERIFICATION_KEY_SIZE];
                    backend::$param::generate_key_pair(
                        &[0x42; KEY_GENERATION_RANDOMNESS_SIZE],
                        &mut sk,
                        &mut vk,
                    );
                    sk
                }

                #[test]
                fn key_generation_clears_every_shake_state_and_buffer() {
                    take();
                    keygen();
                    let events = take();

                    assert_no_residue(&events);
                    // xi -> (rho, rho', K) expansion and the tr = H(pk) hash.
                    assert!(saw(&events, |e| matches!(e, Event::Lanes { rate: 136, .. })));
                    // rho'-keyed s1/s2 sampling: seed copies, squeezed blocks, coefficients.
                    assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 66, .. })));
                    assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 136, .. })));
                    assert!(saw(&events, |e| matches!(e, Event::Coefficients { len: 263, .. })));
                }

                #[test]
                fn signing_clears_every_shake_state_and_buffer() {
                    let sk = keygen();
                    take();
                    let sig = backend::$param::sign(
                        &sk,
                        b"message",
                        b"",
                        [0x17; SIGNING_RANDOMNESS_SIZE],
                    );
                    assert!(sig.is_ok());
                    let events = take();
                    let _ = SIGNATURE_SIZE;

                    assert_no_residue(&events);
                    // SHAKE256(K || rnd || mu) -> rho'' and the rho''-keyed mask streams.
                    assert!(saw(&events, |e| matches!(e, Event::Lanes { rate: 136, .. })));
                    assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 66, .. })));
                    assert!(saw(&events, |e| matches!(e, Event::Bytes { len, .. } if *len == $gamma1_bytes)));
                    #[cfg(feature = "hardened")]
                    assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 136, .. })));
                }
            }
        };
    }

    mod portable {
        use super::*;
        keygen_and_sign_tests!(
            ml_dsa_44,
            ml_dsa_44,
            crate::ml_dsa_generic::instantiations::portable,
            576
        );
        keygen_and_sign_tests!(
            ml_dsa_65,
            ml_dsa_65,
            crate::ml_dsa_generic::instantiations::portable,
            640
        );
        keygen_and_sign_tests!(
            ml_dsa_87,
            ml_dsa_87,
            crate::ml_dsa_generic::instantiations::portable,
            640
        );
    }

    /// AVX2 back-end: the 4-way sponge (`KeccakStateX4`) and the batched one-shot SHAKE256 used
    /// for the `rho''` mask streams.
    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    mod avx2 {
        use super::*;
        // The runtime dispatcher only picks AVX2 when the CPU has it; calling the AVX2
        // instantiation on a CPU without it would be undefined behaviour, so these must not
        // silently pass or run there: they are compiled only with `simd256` and assert support.
        fn require_avx2() {
            assert!(
                lib_q_platform::simd256_support(),
                "AVX2 wipe tests need an AVX2 CPU"
            );
        }
        macro_rules! avx2_case {
            ($module:ident, $param:ident, $gamma1_bytes:expr) => {
                mod $module {
                    use super::*;
                    use crate::ml_dsa_generic::instantiations::avx2::$param as backend;
                    use crate::ml_dsa_generic::$param::{
                        SIGNING_KEY_SIZE,
                        VERIFICATION_KEY_SIZE,
                    };

                    fn keygen() -> [u8; SIGNING_KEY_SIZE] {
                        let mut sk = [0u8; SIGNING_KEY_SIZE];
                        let mut vk = [0u8; VERIFICATION_KEY_SIZE];
                        backend::generate_key_pair(
                            &[0x42; KEY_GENERATION_RANDOMNESS_SIZE],
                            &mut sk,
                            &mut vk,
                        );
                        sk
                    }

                    #[test]
                    fn key_generation_clears_every_shake_state_and_buffer() {
                        require_avx2();
                        take();
                        keygen();
                        let events = take();
                        assert_no_residue(&events);
                        assert!(saw(&events, |e| matches!(e, Event::Lanes { .. })));
                        assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 66, .. })));
                        assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 136, .. })));
                        assert!(saw(&events, |e| matches!(e, Event::Coefficients { len: 263, .. })));
                    }

                    #[test]
                    fn signing_clears_every_shake_state_and_buffer() {
                        require_avx2();
                        let sk = keygen();
                        take();
                        let sig = backend::sign(
                            &sk,
                            b"message",
                            b"",
                            [0x17; SIGNING_RANDOMNESS_SIZE],
                        );
                        assert!(sig.is_ok());
                        let events = take();
                        assert_no_residue(&events);
                        assert!(saw(&events, |e| matches!(e, Event::Lanes { .. })));
                        assert!(saw(&events, |e| matches!(e, Event::Bytes { len: 66, .. })));
                        assert!(saw(&events, |e| matches!(e, Event::Bytes { len, .. } if *len == $gamma1_bytes)));
                    }
                }
            };
        }
        avx2_case!(ml_dsa_44, ml_dsa_44, 576);
        avx2_case!(ml_dsa_65, ml_dsa_65, 640);
        avx2_case!(ml_dsa_87, ml_dsa_87, 640);

        #[test]
        fn batched_one_shot_shake256_clears_its_four_states() {
            require_avx2();
            take();
            let mut outs = [[0u8; 576]; 4];
            {
                let [o0, o1, o2, o3] = &mut outs;
                crate::sha3_shim::avx2::x4::shake256(
                    &[1; 66], &[2; 66], &[3; 66], &[4; 66], o0, o1, o2, o3,
                );
            }
            let events = take();
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e, Event::Lanes { .. }))
                    .count(),
                4,
                "one wipe per lane"
            );
            assert!(
                events
                    .iter()
                    .all(|e| e.dirty() || !matches!(e, Event::Lanes { .. }))
            );
            assert_no_residue(&events);
        }
    }

    /// NEON back-end (compiled only for aarch64 + simd128; exercised by the QEMU CI job).
    #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
    mod neon {
        use super::*;
        keygen_and_sign_tests!(
            ml_dsa_44,
            ml_dsa_44,
            crate::ml_dsa_generic::instantiations::neon,
            576
        );
        keygen_and_sign_tests!(
            ml_dsa_65,
            ml_dsa_65,
            crate::ml_dsa_generic::instantiations::neon,
            640
        );
        keygen_and_sign_tests!(
            ml_dsa_87,
            ml_dsa_87,
            crate::ml_dsa_generic::instantiations::neon,
            640
        );
    }

    /// Exact per-buffer accounting for the two `rho'`/`rho''`-keyed samplers, run against every
    /// back-end's 4-way SHAKE256. Counting (not just "some wipe happened") pins each individual
    /// seed copy, squeeze buffer and coefficient buffer: dropping any one changes a count.
    mod samplers {
        use super::*;
        use crate::constants::Eta;
        use crate::hash_functions::shake256::{DsaXof, XofX4};
        use crate::polynomial::PolynomialRingElement;
        use crate::simd::portable::PortableSIMDUnit;

        fn dirty(events: &[Event], want: impl Fn(&Event) -> bool) -> usize {
            events.iter().filter(|e| e.dirty() && want(e)).count()
        }

        fn check_error_sampler<X4: XofX4>() {
            let mut re = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 4];
            take();
            crate::sample::sample_four_error_ring_elements::<PortableSIMDUnit, X4>(
                Eta::Two,
                &[0x99; 64],
                0,
                &mut re,
            );
            let events = take();
            assert_no_residue(&events);
            // 4 lanes: one seed copy, one squeezed block and one coefficient buffer each.
            assert_eq!(
                dirty(&events, |e| matches!(e, Event::Bytes { len: 66, .. })),
                4
            );
            // (>= because the AVX2 sponge also wipes its four padded final blocks, also 136 bytes.)
            assert!(dirty(&events, |e| matches!(e, Event::Bytes { len: 136, .. })) >= 4);
            assert_eq!(
                dirty(&events, |e| matches!(
                    e,
                    Event::Coefficients { len: 263, .. }
                )),
                4
            );
        }

        fn check_mask_sampler<D: DsaXof, X4: XofX4>(gamma1: usize, dimension: usize, len: usize) {
            let mut mask = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 7];
            let mut domain_separator = 0u16;
            take();
            crate::sample::sample_mask_vector::<PortableSIMDUnit, D, X4>(
                dimension,
                gamma1,
                &[0x77; 64],
                &mut domain_separator,
                &mut mask[..dimension],
            );
            let events = take();
            assert_no_residue(&events);
            // Four lanes through the batched path, then one ring element at a time.
            assert_eq!(
                dirty(&events, |e| matches!(e, Event::Bytes { len: 66, .. })),
                dimension,
                "one wiped seed copy per sampled element"
            );
            assert_eq!(
                dirty(
                    &events,
                    |e| matches!(e, Event::Bytes { len: l, .. } if *l == len)
                ),
                dimension,
                "one wiped SHAKE output buffer per sampled element"
            );
        }

        fn check_all<D: DsaXof, X4: XofX4>() {
            check_error_sampler::<X4>();
            check_mask_sampler::<D, X4>(17, 4, 576);
            check_mask_sampler::<D, X4>(19, 5, 640);
            check_mask_sampler::<D, X4>(19, 7, 640);
        }

        #[test]
        fn portable_backend() {
            check_all::<
                crate::hash_functions::portable::Shake256,
                crate::hash_functions::portable::Shake256X4,
            >();
        }

        #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
        #[test]
        fn avx2_backend() {
            assert!(
                lib_q_platform::simd256_support(),
                "AVX2 wipe tests need an AVX2 CPU"
            );
            check_all::<
                crate::hash_functions::simd256::Shake256,
                crate::hash_functions::simd256::Shake256x4,
            >();
        }

        #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
        #[test]
        fn neon_backend() {
            check_all::<
                crate::hash_functions::portable::Shake256,
                crate::hash_functions::neon::Shake256x4,
            >();
        }
    }
}
