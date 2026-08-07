//! cSHAKE KATs

use digest::{
    CustomizedInit,
    ExtendableOutput,
};

#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub customization: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

pub(crate) fn cshake_test<D>(
    &TestVector {
        customization,
        input,
        output,
    }: &TestVector,
) -> Result<(), &'static str>
where
    D: CustomizedInit + ExtendableOutput + Clone,
{
    // The buffer below is sized from `output.len()`, so a zero-length expected output would make
    // every comparison in this function `[] == []` — the vector would be counted and reported as
    // passing while squeezing nothing. Reject it rather than pass vacuously.
    if output.is_empty() {
        return Err("zero-length expected output");
    }
    // Likewise, an expected output longer than the buffer would panic on the slice below; say why.
    if output.len() > 1024 {
        return Err("expected output longer than the 1024-byte scratch buffer");
    }
    let mut hasher = D::new_customized(customization);
    let mut buf = [0u8; 1024];
    let buf = &mut buf[..output.len()];
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if buf != output {
        return Err("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::new_customized(customization);
        for chunk in input.chunks(n) {
            hasher.update(chunk);
            hasher2.update(chunk);
        }
        hasher.finalize_xof_into(buf);
        if buf != output {
            return Err("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    Ok(())
}

macro_rules! new_cshake_test {
    ($name:ident, $hasher:ty, $count:literal $(,)?) => {
        #[test]
        fn $name() {
            digest::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", stringify!($name), ".blb"));
                static TEST_VECTORS: &[TestVector { customization, input, output }];
            );

            // Without this, an empty or truncated `.blb` would make the loop below a no-op and
            // the test would pass having checked nothing. The count is exact on purpose: shrinking
            // the vector set has to be a deliberate edit visible in the diff.
            assert_eq!(
                TEST_VECTORS.len(),
                $count,
                concat!(
                    "data/",
                    stringify!($name),
                    ".blb: expected ",
                    stringify!($count),
                    " cSHAKE vectors, decoded {}"
                ),
                TEST_VECTORS.len(),
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                if let Err(reason) = cshake_test::<$hasher>(tv) {
                    panic!(
                        "\n\
                         Failed test #{i}\n\
                         reason:\t{reason}
                         test vector:\t{tv:?}\n"
                    );
                }
            }
        }
    };
}

/// `cshake_test` sizes its output buffer as `&mut buf[..output.len()]`, so a vector with a
/// zero-length expected output squeezes nothing and then compares two empty slices — it is
/// counted by the assertion above yet exercises no cSHAKE at all. Landed RED against the
/// unguarded helper (it returned `Ok(())`) before the guard was added.
#[test]
fn cshake_test_rejects_zero_length_expected_output() {
    let vector = TestVector {
        customization: b"",
        input: b"abc",
        output: b"",
    };
    assert_eq!(
        cshake_test::<lib_q_sha3::CShake128>(&vector),
        Err("zero-length expected output")
    );
}

new_cshake_test!(cshake128, lib_q_sha3::CShake128, 258);
new_cshake_test!(cshake256, lib_q_sha3::CShake256, 258);

// When bytepad output aligns exactly to the block boundary (SP 800-185 2.3.3), regression #834.
new_cshake_test!(cshake128_bytepad_block_aligned, lib_q_sha3::CShake128, 1);
new_cshake_test!(cshake256_bytepad_block_aligned, lib_q_sha3::CShake256, 1);
