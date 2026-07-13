//! Test-only shared macros for the crate's AIR test modules.

/// Assert that a deliberately-invalid trace is REJECTED by the full prove→verify pipeline, robustly
/// across build profiles.
///
/// In **debug** builds `lib-q-stark`'s `check_constraints` self-check runs inside `prove` and
/// **panics** the instant a constraint is violated; in **release** that check is compiled out, so
/// `prove` instead returns a proof that must then fail verification. A caught panic, a `prove`
/// error, or a proof whose verification fails all count as the required rejection — only a trace
/// that both proves *and* verifies is a test failure. The argument shape mirrors
/// `StarkProver::prove(air, trace, pubs)`: pass the AIR reference, the (moved) trace, and the public
/// values slice exactly as you would to `prove`.
macro_rules! assert_air_rejects {
    ($air:expr, $trace:expr, $pubs:expr $(,)?) => {
        assert_air_rejects!($air, $trace, $pubs, "an invalid witness must not verify")
    };
    ($air:expr, $trace:expr, $pubs:expr, $msg:expr $(,)?) => {{
        let __outcome = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
            ::lib_q_zkp::stark::StarkProver::new(::lib_q_zkp::stark::default_config())
                .prove($air, $trace, $pubs)
        }));
        match __outcome {
            // debug `check_constraints` panicked on the violating trace ⇒ rejected
            ::core::result::Result::Err(_) => {}
            // prover refused to build a proof ⇒ rejected
            ::core::result::Result::Ok(::core::result::Result::Err(_)) => {}
            // a proof was built: it MUST fail verification
            ::core::result::Result::Ok(::core::result::Result::Ok(__proof)) => {
                assert!(
                    ::lib_q_zkp::stark::StarkVerifier::new(::lib_q_zkp::stark::default_config())
                        .verify($air, &__proof, $pubs)
                        .is_err(),
                    $msg
                );
            }
        }
    }};
}

pub(crate) use assert_air_rejects;
