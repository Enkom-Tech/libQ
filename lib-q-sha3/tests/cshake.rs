use digest::{
    CustomizedInit,
    ExtendableOutputReset,
};

#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub customization: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

pub(crate) fn cshake_reset_test<D>(
    &TestVector {
        customization,
        input,
        output,
    }: &TestVector,
) -> Result<(), &'static str>
where
    D: CustomizedInit + ExtendableOutputReset + Clone,
{
    let mut hasher = D::new_customized(customization);
    let mut buf = [0u8; 1024];
    let buf = &mut buf[..output.len()];
    // Test that it works when accepting the message all at once
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if buf != output {
        return Err("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test if reset works correctly
    hasher2.reset();
    hasher2.update(input);
    hasher2.finalize_xof_reset_into(buf);
    if buf != output {
        return Err("whole message after reset");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test that it works when accepting the message in chunks
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

        hasher2.finalize_xof_reset_into(buf);
        if buf != output {
            return Err("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    Ok(())
}

// Simple test vectors for cSHAKE
const CSHAKE128_TEST_VECTORS: &[TestVector] = &[TestVector {
    customization: b"",
    input: b"",
    output: &[
        0x7F, 0x9C, 0x2B, 0xA4, 0xE8, 0x8F, 0x82, 0x7D, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85,
        0x3E,
    ],
}];

const CSHAKE256_TEST_VECTORS: &[TestVector] = &[TestVector {
    customization: b"",
    input: b"",
    output: &[
        0x46, 0xB9, 0xDD, 0x2B, 0x0B, 0xA8, 0x8D, 0x13, 0x23, 0x3B, 0x3F, 0xEB, 0x74, 0x3E, 0xEB,
        0x24, 0x3F, 0xCD, 0x52, 0xEA, 0x62, 0xB8, 0x1B, 0x82, 0xB5, 0x0C, 0x27, 0x64, 0x6E, 0xD5,
        0x76, 0x2F,
    ],
}];

#[test]
fn cshake128_reset() {
    for (i, tv) in CSHAKE128_TEST_VECTORS.iter().enumerate() {
        if let Err(reason) = cshake_reset_test::<lib_q_sha3::CShake128>(tv) {
            panic!(
                "\n\
                 Failed test #{i}\n\
                 reason:\t{reason}
                 test vector:\t{tv:?}\n"
            );
        }
    }
}

#[test]
fn cshake256_reset() {
    for (i, tv) in CSHAKE256_TEST_VECTORS.iter().enumerate() {
        if let Err(reason) = cshake_reset_test::<lib_q_sha3::CShake256>(tv) {
            panic!(
                "\n\
                 Failed test #{i}\n\
                 reason:\t{reason}
                 test vector:\t{tv:?}\n"
            );
        }
    }
}
