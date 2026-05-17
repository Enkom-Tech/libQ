use crate::constants::COEFFICIENTS_IN_RING_ELEMENT;
use crate::polynomial::PolynomialRingElement;
use crate::simd::traits::Operations;
use crate::{
    VerificationError,
    encoding,
};

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn serialize<SIMDUnit: Operations>(
    commitment_hash: &[u8],
    signer_response: &[PolynomialRingElement<SIMDUnit>],
    hint: &[[i32; COEFFICIENTS_IN_RING_ELEMENT]],
    commitment_hash_size: usize,
    columns_in_a: usize,
    rows_in_a: usize,
    gamma1_exponent: usize,
    gamma1_ring_element_size: usize,
    max_ones_in_hint: usize,
    signature: &mut [u8],
) {
    let mut offset = 0;

    signature[offset..offset + commitment_hash_size].copy_from_slice(commitment_hash);
    offset += commitment_hash_size;

    for elem in signer_response.iter().take(columns_in_a) {
        encoding::gamma1::serialize::<SIMDUnit>(
            elem,
            &mut signature[offset..offset + gamma1_ring_element_size],
            gamma1_exponent,
        );
        offset += gamma1_ring_element_size;
    }

    let mut true_hints_seen = 0;

    // Unfortunately the following does not go through hax:
    //
    //     let hint_serialized = &mut signature[offset..];
    //
    // Instead, we have to mutate signature[offset + ..] directly.
    for i in 0..rows_in_a {
        // Use enumerate to avoid the Clippy needless_range_loop warning
        for (j, &value) in hint[i].iter().enumerate() {
            if value == 1 {
                signature[offset + true_hints_seen] = j as u8;
                true_hints_seen += 1;
            }
        }
        signature[offset + max_ones_in_hint + i] = true_hints_seen as u8;
    }
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn deserialize<SIMDUnit: Operations>(
    columns_in_a: usize,
    rows_in_a: usize,
    commitment_hash_size: usize,
    gamma1_exponent: usize,
    gamma1_ring_element_size: usize,
    max_ones_in_hint: usize,
    signature_size: usize,
    serialized: &[u8],
    out_commitment_hash: &mut [u8],
    out_signer_response: &mut [PolynomialRingElement<SIMDUnit>],
    out_hint: &mut [[i32; COEFFICIENTS_IN_RING_ELEMENT]],
) -> Result<(), VerificationError> {
    debug_assert!(serialized.len() == signature_size);

    let (commitment_hash, rest_of_serialized) = serialized.split_at(commitment_hash_size);
    out_commitment_hash[0..commitment_hash_size].copy_from_slice(commitment_hash);

    let (signer_response_serialized, hint_serialized) =
        rest_of_serialized.split_at(gamma1_ring_element_size * columns_in_a);

    for i in 0..columns_in_a {
        encoding::gamma1::deserialize::<SIMDUnit>(
            gamma1_exponent,
            &signer_response_serialized
                [i * gamma1_ring_element_size..(i + 1) * gamma1_ring_element_size],
            &mut out_signer_response[i],
        );
    }

    // While there are several ways to encode the same hint vector, we
    // allow only one such encoding, to ensure strong unforgeability.
    let mut previous_true_hints_seen = 0usize;

    for i in 0..rows_in_a {
        let current_true_hints_seen = hint_serialized[max_ones_in_hint + i] as usize;

        if (current_true_hints_seen < previous_true_hints_seen) ||
            (previous_true_hints_seen > max_ones_in_hint)
        {
            // the true hints seen should be increasing
            return Err(VerificationError::MalformedHintError);
        }

        for j in previous_true_hints_seen..current_true_hints_seen {
            if j > previous_true_hints_seen && hint_serialized[j] <= hint_serialized[j - 1] {
                // indices of true hints for a specific polynomial should be
                // increasing
                return Err(VerificationError::MalformedHintError);
            }

            set_hint(out_hint, i, hint_serialized[j] as usize);
        }

        previous_true_hints_seen = current_true_hints_seen;
    }

    for &value in hint_serialized
        .iter()
        .take(max_ones_in_hint)
        .skip(previous_true_hints_seen)
    {
        if value != 0 {
            // ensures padding indices are zero
            return Err(VerificationError::MalformedHintError);
        }
    }

    Ok(())
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn set_hint(out_hint: &mut [[i32; 256]], i: usize, j: usize) {
    out_hint[i][j] = 1
}

#[cfg(all(test, feature = "mldsa44"))]
mod malformed_hint_coverage {
    use super::*;
    use crate::constants::gamma1_ring_element_size;
    use crate::constants::ml_dsa_44::{
        BITS_PER_GAMMA1_COEFFICIENT,
        COLUMNS_IN_A,
        COMMITMENT_HASH_SIZE,
        GAMMA1_EXPONENT,
        MAX_ONES_IN_HINT,
        ROWS_IN_A,
        SIGNATURE_SIZE,
    };
    use crate::polynomial::PolynomialRingElement;
    use crate::simd::portable::PortableSIMDUnit;

    type S = PortableSIMDUnit;

    fn gamma1_re_size() -> usize {
        gamma1_ring_element_size(BITS_PER_GAMMA1_COEFFICIENT)
    }

    fn hint_byte_offset() -> usize {
        COMMITMENT_HASH_SIZE + gamma1_re_size() * COLUMNS_IN_A
    }

    fn deserialize_all(serialized: &[u8]) -> Result<(), VerificationError> {
        let mut commitment = [0u8; COMMITMENT_HASH_SIZE];
        let mut signer_response = [PolynomialRingElement::<S>::zero(); COLUMNS_IN_A];
        let mut hint = [[0i32; COEFFICIENTS_IN_RING_ELEMENT]; ROWS_IN_A];
        deserialize::<S>(
            COLUMNS_IN_A,
            ROWS_IN_A,
            COMMITMENT_HASH_SIZE,
            GAMMA1_EXPONENT,
            gamma1_re_size(),
            MAX_ONES_IN_HINT,
            SIGNATURE_SIZE,
            serialized,
            &mut commitment,
            &mut signer_response,
            &mut hint,
        )
    }

    #[test]
    fn rejects_decreasing_per_row_hint_counts() {
        let mut buf = [0u8; SIGNATURE_SIZE];
        let h0 = hint_byte_offset();
        buf[h0] = 10;
        buf[h0 + 1] = 20;
        buf[h0 + MAX_ONES_IN_HINT] = 2;
        buf[h0 + MAX_ONES_IN_HINT + 1] = 1;
        assert!(matches!(
            deserialize_all(&buf),
            Err(VerificationError::MalformedHintError)
        ));
    }

    #[test]
    fn rejects_non_monotonic_indices_within_row() {
        let mut buf = [0u8; SIGNATURE_SIZE];
        let h0 = hint_byte_offset();
        buf[h0] = 50;
        buf[h0 + 1] = 40;
        buf[h0 + MAX_ONES_IN_HINT] = 2;
        for r in 1..ROWS_IN_A {
            buf[h0 + MAX_ONES_IN_HINT + r] = 2;
        }
        assert!(matches!(
            deserialize_all(&buf),
            Err(VerificationError::MalformedHintError)
        ));
    }

    #[test]
    fn rejects_nonzero_padding_after_hints() {
        let mut buf = [0u8; SIGNATURE_SIZE];
        let h0 = hint_byte_offset();
        buf[h0 + 5] = 7;
        for r in 0..ROWS_IN_A {
            buf[h0 + MAX_ONES_IN_HINT + r] = 0;
        }
        assert!(matches!(
            deserialize_all(&buf),
            Err(VerificationError::MalformedHintError)
        ));
    }

    #[test]
    fn accepts_minimal_valid_hint_encoding() {
        let mut buf = [0u8; SIGNATURE_SIZE];
        let h0 = hint_byte_offset();
        for r in 0..ROWS_IN_A {
            buf[h0 + MAX_ONES_IN_HINT + r] = 0;
        }
        assert!(deserialize_all(&buf).is_ok());
    }
}
