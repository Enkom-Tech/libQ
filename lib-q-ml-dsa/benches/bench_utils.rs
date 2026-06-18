use lib_q_random::new_secure_rng;
use rand_core::Rng;

#[allow(unused)]
pub(crate) fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = new_secure_rng().expect("Failed to create RNG");
    let mut seed = [0; L];
    rng.fill_bytes(&mut seed);
    seed
}

#[allow(unused)]
pub(crate) fn print_time(label: &str, d: std::time::Duration) {
    let micros = d.as_micros();
    let time = if micros < MILLI_PER_ITERATION_THRESHOLD {
        format!("{} μs/iter", micros / ITERATIONS as u128)
    } else if micros < SECOND_PER_ITERATION_THRESHOLD {
        format!(
            "{:.2} ms/iter",
            (micros as f64 / (MICROS_PER_MILLI * ITERATIONS as f64))
        )
    } else {
        format!(
            "{:.2}s/iter",
            (micros as f64 / (MICROS_PER_SECOND * ITERATIONS as f64))
        )
    };
    let space = if label.len() < 6 {
        "\t\t".to_string()
    } else {
        "\t".to_string()
    };

    println!("{label} ... bench:{space}{time}");
}

pub(crate) const ITERATIONS: usize = 10_000;
#[allow(unused)]
pub(crate) const WARMUP_ITERATIONS: usize = 1_000;

pub(crate) const MICROS_PER_MILLI: f64 = 1_000.0;
pub(crate) const MICROS_PER_SECOND: f64 = 1_000_000.0;
pub(crate) const MILLI_PER_ITERATION_THRESHOLD: u128 = 1_000 * ITERATIONS as u128;
pub(crate) const SECOND_PER_ITERATION_THRESHOLD: u128 = 1_000_000 * ITERATIONS as u128;

// A benchmarking macro to avoid copying memory and skewing the results.
#[macro_export]
macro_rules! bench {
    ($implementation:literal, $fun_label:literal, $hardware:literal, $keysize:literal, $input:expr, $setup:expr, $routine:expr) => {{
        let mut time = std::time::Duration::ZERO;

        // Warmup
        for _ in 0..bench_utils::WARMUP_ITERATIONS {
            let input = $setup($input);
            let _ = $routine(input);
        }

        // Benchmark
        for _ in 0..bench_utils::ITERATIONS {
            let input = $setup($input);

            let start = std::time::Instant::now();
            let _ = core::hint::black_box($routine(input));
            let end = std::time::Instant::now();

            time += end.duration_since(start);
        }
        bench_utils::print_time(
            &format!(
                "test implementation={} ML-DSA,keySize={},label={},hardware={}",
                $implementation, $keysize, $fun_label, $hardware
            ),
            time,
        );
    }};
}

#[macro_export]
macro_rules! bench_group_libcrux {
    ($keysize:literal, $hardware:literal, $mod:path, $keypair_t:ident, $signature_t:ident) => {{
        use $mod as p;
        bench!(
            "libcrux",
            "KeyGen",
            $hardware,
            $keysize,
            (),
            |()| {
                let key_generation_seed: [u8; KEY_GENERATION_RANDOMNESS_SIZE] =
                    bench_utils::random_array();
                key_generation_seed
            },
            |key_generation_seed: [u8; KEY_GENERATION_RANDOMNESS_SIZE]| {
                p::generate_key_pair(key_generation_seed)
            }
        );

        bench!(
            "libcrux",
            "Sign",
            $hardware,
            $keysize,
            (),
            |()| {
                let key_generation_seed: [u8; KEY_GENERATION_RANDOMNESS_SIZE] =
                    bench_utils::random_array();
                let signing_randomness: [u8; SIGNING_RANDOMNESS_SIZE] = bench_utils::random_array();
                let message = bench_utils::random_array::<1023>();
                let keypair = p::generate_key_pair(key_generation_seed);

                (keypair, message, signing_randomness)
            },
            |(keypair, message, signing_randomness): (
                $keypair_t,
                [u8; 1023],
                [u8; SIGNING_RANDOMNESS_SIZE]
            )| { p::sign(&keypair.signing_key, &message, b"", signing_randomness) }
        );

        bench!(
            "libcrux",
            "Verify",
            $hardware,
            $keysize,
            (),
            |()| {
                let message = bench_utils::random_array::<1023>();
                loop {
                    let key_generation_seed: [u8; KEY_GENERATION_RANDOMNESS_SIZE] =
                        bench_utils::random_array();
                    let signing_randomness: [u8; SIGNING_RANDOMNESS_SIZE] =
                        bench_utils::random_array();
                    let keypair = p::generate_key_pair(key_generation_seed);
                    if let Ok(signature) =
                        p::sign(&keypair.signing_key, &message, b"", signing_randomness)
                    {
                        return (keypair, message, signature);
                    }
                }
            },
            |(keypair, message, signature): ($keypair_t, [u8; 1023], $signature_t)| {
                p::verify(&keypair.verification_key, &message, b"", &signature).unwrap()
            }
        );

        println!("");
    }};
}

/// Benchmarks against the pure-Rust [`fips204`](https://crates.io/crates/fips204) implementation
/// (FIPS 204 final) for rough cross-implementation timing comparison.
#[macro_export]
macro_rules! bench_group_fips204 {
    ($variant:literal, $mod:path, $sig_len:literal) => {{
        use $mod as m;

        bench!("fips204", "KeyGen", "auto", $variant, (), |()| {}, |()| {
            let _ = m::try_keygen().expect("fips204 keygen");
        });
        bench!(
            "fips204",
            "Sign",
            "auto",
            $variant,
            (),
            |()| {
                let (_pk, sk) = m::try_keygen().expect("fips204 keygen");
                let message = bench_utils::random_array::<1023>();
                (sk, message)
            },
            |(sk, message): (m::PrivateKey, [u8; 1023])| {
                let _ =
                    fips204::traits::Signer::try_sign(&sk, &message, &[]).expect("fips204 sign");
            }
        );
        bench!(
            "fips204",
            "Verify",
            "auto",
            $variant,
            (),
            |()| {
                let (pk, sk) = m::try_keygen().expect("fips204 keygen");
                let message = bench_utils::random_array::<1023>();
                let signature =
                    fips204::traits::Signer::try_sign(&sk, &message, &[]).expect("fips204 sign");
                (pk, message, signature)
            },
            |(pk, message, signature): (m::PublicKey, [u8; 1023], [u8; $sig_len])| {
                assert!(fips204::traits::Verifier::verify(
                    &pk,
                    &message,
                    &signature,
                    &[]
                ));
            }
        );
    }};
}
