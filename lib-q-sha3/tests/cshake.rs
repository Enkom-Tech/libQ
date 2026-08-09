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

/// Genuine external cSHAKE conformance vectors, sourced (not recalled from memory, not
/// re-derived) from NIST's own published "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash,
/// ParallelHash" sample document ("cSHAKE_samples.pdf"):
///
/// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf>
///
/// All four official samples ("Sample #1".."Sample #4") are transcribed byte-for-byte from that
/// document's "Data is" / "N is" / "S (as a character string) is" / "Outval is" fields. This
/// closes the gap the 516-vector `cshake128.blb`/`cshake256.blb` corpus cannot: those are
/// explicitly self-generated (see `data/PROVENANCE.md` and `kats-manifest.toml`), so they prove
/// self-consistency, not conformance to the standard. These four do the latter, and specifically
/// exercise the `N`/`S` customization-string path (a non-empty `S`, the part most likely to be
/// wrong and least likely to be caught by a round-trip/self-consistency test).
mod nist_cshake_samples {
    use digest::{
        CustomizedInit,
        ExtendableOutput,
        Update,
        XofReader,
    };

    /// Sample #2 / #4 input: the 200-byte ramp 0x00, 0x01, .., 0xC7, exactly as given in the
    /// NIST document ("Length of data is 1600-bits").
    fn ramp_200() -> Vec<u8> {
        (0u16..200).map(|i| (i % 256) as u8).collect()
    }

    fn run<D: CustomizedInit + ExtendableOutput>(
        input: &[u8],
        customization: &[u8],
        expected: &[u8],
    ) {
        let mut hasher = D::new_customized(customization);
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; expected.len()];
        reader.read(&mut out);
        assert_eq!(
            out,
            expected,
            "NIST cSHAKE sample mismatch (customization={customization:?}, input len={})",
            input.len()
        );
    }

    #[test]
    fn nist_sample_1_cshake128_short_input() {
        // Sample #1: Security Strength 128-bits, data = 00 01 02 03, N = "", S = "Email
        // Signature", requested output length 256 bits.
        run::<lib_q_sha3::CShake128>(
            &[0x00, 0x01, 0x02, 0x03],
            b"Email Signature",
            &[
                0xC1, 0xC3, 0x69, 0x25, 0xB6, 0x40, 0x9A, 0x04, 0xF1, 0xB5, 0x04, 0xFC, 0xBC, 0xA9,
                0xD8, 0x2B, 0x40, 0x17, 0x27, 0x7C, 0xB5, 0xED, 0x2B, 0x20, 0x65, 0xFC, 0x1D, 0x38,
                0x14, 0xD5, 0xAA, 0xF5,
            ],
        );
    }

    #[test]
    fn nist_sample_2_cshake128_long_input() {
        // Sample #2: Security Strength 128-bits, data = 00..C7 (1600 bits), N = "", S = "Email
        // Signature", requested output length 256 bits.
        run::<lib_q_sha3::CShake128>(
            &ramp_200(),
            b"Email Signature",
            &[
                0xC5, 0x22, 0x1D, 0x50, 0xE4, 0xF8, 0x22, 0xD9, 0x6A, 0x2E, 0x88, 0x81, 0xA9, 0x61,
                0x42, 0x0F, 0x29, 0x4B, 0x7B, 0x24, 0xFE, 0x3D, 0x20, 0x94, 0xBA, 0xED, 0x2C, 0x65,
                0x24, 0xCC, 0x16, 0x6B,
            ],
        );
    }

    #[test]
    fn nist_sample_3_cshake256_short_input() {
        // Sample #3: Security Strength 256-bits, data = 00 01 02 03, N = "", S = "Email
        // Signature", requested output length 512 bits.
        run::<lib_q_sha3::CShake256>(
            &[0x00, 0x01, 0x02, 0x03],
            b"Email Signature",
            &[
                0xD0, 0x08, 0x82, 0x8E, 0x2B, 0x80, 0xAC, 0x9D, 0x22, 0x18, 0xFF, 0xEE, 0x1D, 0x07,
                0x0C, 0x48, 0xB8, 0xE4, 0xC8, 0x7B, 0xFF, 0x32, 0xC9, 0x69, 0x9D, 0x5B, 0x68, 0x96,
                0xEE, 0xE0, 0xED, 0xD1, 0x64, 0x02, 0x0E, 0x2B, 0xE0, 0x56, 0x08, 0x58, 0xD9, 0xC0,
                0x0C, 0x03, 0x7E, 0x34, 0xA9, 0x69, 0x37, 0xC5, 0x61, 0xA7, 0x4C, 0x41, 0x2B, 0xB4,
                0xC7, 0x46, 0x46, 0x95, 0x27, 0x28, 0x1C, 0x8C,
            ],
        );
    }

    #[test]
    fn nist_sample_4_cshake256_long_input() {
        // Sample #4: Security Strength 256-bits, data = 00..C7 (1600 bits), N = "", S = "Email
        // Signature", requested output length 512 bits.
        run::<lib_q_sha3::CShake256>(
            &ramp_200(),
            b"Email Signature",
            &[
                0x07, 0xDC, 0x27, 0xB1, 0x1E, 0x51, 0xFB, 0xAC, 0x75, 0xBC, 0x7B, 0x3C, 0x1D, 0x98,
                0x3E, 0x8B, 0x4B, 0x85, 0xFB, 0x1D, 0xEF, 0xAF, 0x21, 0x89, 0x12, 0xAC, 0x86, 0x43,
                0x02, 0x73, 0x09, 0x17, 0x27, 0xF4, 0x2B, 0x17, 0xED, 0x1D, 0xF6, 0x3E, 0x8E, 0xC1,
                0x18, 0xF0, 0x4B, 0x23, 0x63, 0x3C, 0x1D, 0xFB, 0x15, 0x74, 0xC8, 0xFB, 0x55, 0xCB,
                0x45, 0xDA, 0x8E, 0x25, 0xAF, 0xB0, 0x92, 0xBB,
            ],
        );
    }

    /// Not an externally-cited vector (labeled as such, per the instruction not to invent
    /// plausible-looking provenance): a structural/spec-contract check that cSHAKE with an empty
    /// function-name `N` AND an empty customization `S` must reduce EXACTLY to plain SHAKE (FIPS
    /// 202 §6.2 / NIST SP 800-185 §3, "cSHAKE(X, L, "", "") == SHAKE(X, L)"). This is the
    /// customization-string edge case least likely to be caught by a round-trip test, since a
    /// buggy bytepad/encode_string path could still round-trip against itself while disagreeing
    /// with plain SHAKE.
    #[test]
    fn cshake_with_empty_n_and_s_reduces_to_plain_shake() {
        for input in [&b""[..], &b"abc"[..], &ramp_200()[..]] {
            let mut c128 = lib_q_sha3::CShake128::new_customized(b"");
            c128.update(input);
            let mut c128_out = [0u8; 64];
            c128.finalize_xof().read(&mut c128_out);

            let mut s128 = lib_q_sha3::Shake128::default();
            s128.update(input);
            let mut s128_out = [0u8; 64];
            s128.finalize_xof().read(&mut s128_out);

            assert_eq!(
                c128_out,
                s128_out,
                "CShake128 with empty N/S must equal Shake128 for input len {}",
                input.len()
            );

            let mut c256 = lib_q_sha3::CShake256::new_customized(b"");
            c256.update(input);
            let mut c256_out = [0u8; 64];
            c256.finalize_xof().read(&mut c256_out);

            let mut s256 = lib_q_sha3::Shake256::default();
            s256.update(input);
            let mut s256_out = [0u8; 64];
            s256.finalize_xof().read(&mut s256_out);

            assert_eq!(
                c256_out,
                s256_out,
                "CShake256 with empty N/S must equal Shake256 for input len {}",
                input.len()
            );
        }
    }
}
