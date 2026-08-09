//! TurboSHAKE128/256 KATs from RFC 9861 ("KangarooTwelve and TurboSHAKE"), Section 5.
//!
//! Provenance: `tests/data/turboshake{128,256}_{6,7}.blb` are byte-for-byte copies of
//! RustCrypto's `turbo-shake` crate test data (which are themselves the RFC 9861 vectors packed
//! into the `blobby` 0.4 container format used by that crate's own test harness). See
//! `tests/data/upstream/PROVENANCE.md` for hashes and fetch instructions.
//!
//! Each vector carries `(input, input_pattern_length, output, truncate_output)`:
//! * `input_pattern_length`, when non-empty, means the actual input is the `ptn(n)` pattern from
//!   RFC 9861 Section 5 (repetition of `00 01 02 .. F9 FA` truncated to `n` bytes), not a literal
//!   byte string — this keeps large patterned inputs (megabytes for the KT128/256 tree tests) out
//!   of the `.blb` file.
//! * `truncate_output` lets a vector assert a suffix of a long XOF stream (RFC 9861 has "last 32
//!   bytes of a 10032-byte output" vectors) without storing the whole stream.
//!
//! Both `_6` and `_7` suffixes are the domain-separation byte (`0x06`/`0x07`) baked into the type
//! parameter, e.g. `lib_q_sha3::TurboShake128::<6>`.

use core::fmt::Debug;

use digest::ExtendableOutput;

#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub input: &'static [u8],
    pub input_pattern_length: &'static [u8],
    pub output: &'static [u8],
    pub truncate_output: &'static [u8],
}

pub(crate) fn turbo_shake_test<D>(
    input: &[u8],
    output: &[u8],
    truncate_output: usize,
) -> Result<(), &'static str>
where
    D: ExtendableOutput + Default + Debug + Clone,
{
    // A zero-length expected output would make every comparison below `[] == []` and the vector
    // would be counted as passing while squeezing nothing.
    if output.is_empty() {
        return Err("zero-length expected output");
    }
    let total_len = truncate_output
        .checked_add(output.len())
        .ok_or("truncate_output + output.len() overflowed")?;
    if total_len > 16 * 1024 {
        return Err("expected output longer than the 16 KiB scratch buffer");
    }

    let mut hasher = D::default();
    let mut buf = [0u8; 16 * 1024];
    let buf = &mut buf[..total_len];
    // Test that it works when accepting the message all at once.
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if &buf[truncate_output..] != output {
        return Err("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test that it works when accepting the message in chunks.
    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::default();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
            hasher2.update(chunk);
        }
        hasher.finalize_xof_into(buf);
        if &buf[truncate_output..] != output {
            return Err("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    Ok(())
}

fn resolve_input(input: &'static [u8], input_pattern_length: &'static [u8]) -> Vec<u8> {
    if input_pattern_length.is_empty() {
        return input.to_vec();
    }
    assert!(
        input.is_empty(),
        "test vector has both a literal input and an input_pattern_length"
    );
    let pattern_length = u64::from_be_bytes(
        input_pattern_length
            .try_into()
            .expect("input_pattern_length must be 8 bytes"),
    );
    // RFC 9861 Section 5: ptn(n) repeats `00 01 02 .. F9 FA` (251 bytes) truncated to n bytes.
    (0..pattern_length)
        .map(|value| (value % 0xFB) as u8)
        .collect()
}

macro_rules! new_turbo_shake_test {
    ($name:ident, $hasher:ty, $count:literal $(,)?) => {
        #[test]
        fn $name() {
            digest::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/turboshake/", stringify!($name), ".blb"));
                static TEST_VECTORS: &[TestVector {
                    input, input_pattern_length, output, truncate_output
                }];
            );

            // Assert the vector count before running so an empty or truncated `.blb` fails loudly
            // instead of silently passing having checked nothing.
            assert_eq!(
                TEST_VECTORS.len(),
                $count,
                concat!(
                    "data/turboshake/",
                    stringify!($name),
                    ".blb: expected ",
                    stringify!($count),
                    " TurboSHAKE vectors, decoded {}"
                ),
                TEST_VECTORS.len(),
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                let &TestVector {
                    input,
                    input_pattern_length,
                    output,
                    truncate_output,
                } = tv;
                let input = resolve_input(input, input_pattern_length);
                let truncate_output = u64::from_be_bytes(
                    truncate_output
                        .try_into()
                        .expect("truncate_output must be 8 bytes"),
                ) as usize;

                if let Err(reason) = turbo_shake_test::<$hasher>(&input, output, truncate_output) {
                    panic!(
                        "\n\
                         Failed test #{i}\n\
                         reason:\t{reason}\n\
                         input:\t{input:02x?}\n\
                         output:\t{output:02x?}\n"
                    );
                }
            }
        }
    };
}

new_turbo_shake_test!(turboshake128_6, lib_q_sha3::TurboShake128<6>, 2);
new_turbo_shake_test!(turboshake128_7, lib_q_sha3::TurboShake128<7>, 10);
new_turbo_shake_test!(turboshake256_6, lib_q_sha3::TurboShake256<6>, 4);
new_turbo_shake_test!(turboshake256_7, lib_q_sha3::TurboShake256<7>, 9);
