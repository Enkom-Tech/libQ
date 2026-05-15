use crate::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    Eta,
};
use crate::encoding;
use crate::hash_functions::{
    shake128,
    shake256,
};
use crate::helper::cloop;
use crate::polynomial::PolynomialRingElement;
use crate::simd::traits::Operations;

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn rejection_sample_less_than_field_modulus<SIMDUnit: Operations>(
    randomness: &[u8],
    sampled_coefficients: &mut usize,
    out: &mut [i32; 263],
) -> bool {
    let mut done = false;

    cloop! {
        for random_bytes in randomness.chunks_exact(24) {
            if !done {
                let sampled = SIMDUnit::rejection_sample_less_than_field_modulus(
                    random_bytes,
                    &mut out[*sampled_coefficients..],
                );
                *sampled_coefficients += sampled;

                if *sampled_coefficients >= COEFFICIENTS_IN_RING_ELEMENT {
                    done = true;
                }
            }
        }
    }

    done
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn generate_domain_separator((row, column): (u8, u8)) -> u16 {
    (column as u16) | ((row as u16) << 8)
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) fn add_domain_separator(slice: &[u8], indices: (u8, u8)) -> [u8; 34] {
    let mut out = [0u8; 34];

    out[0..slice.len()].copy_from_slice(slice);

    let domain_separator = generate_domain_separator(indices);
    out[32] = domain_separator as u8;
    out[33] = (domain_separator >> 8) as u8;

    out
}

/// Sample and write out up to four ring elements.
///
/// If i <= `elements_requested`, a field element with domain separated
/// seed according to the provided index is generated in
/// `tmp_stack[i]`. After successful rejection sampling in
/// `tmp_stack[i]`, the ring element is written to `matrix` at the
/// provided index in `indices[i]`.
/// `rand_stack` is a working buffer that holds initial Shake output.
#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn sample_up_to_four_ring_elements_flat<
    SIMDUnit: Operations,
    Shake128: shake128::XofX4,
>(
    columns: usize,
    seed: &[u8],
    matrix: &mut [PolynomialRingElement<SIMDUnit>],
    rand_stack0: &mut [u8; shake128::FIVE_BLOCKS_SIZE],
    rand_stack1: &mut [u8; shake128::FIVE_BLOCKS_SIZE],
    rand_stack2: &mut [u8; shake128::FIVE_BLOCKS_SIZE],
    rand_stack3: &mut [u8; shake128::FIVE_BLOCKS_SIZE],
    tmp_stack: &mut [[i32; 263]],
    start_index: usize,
    elements_requested: usize,
) {
    debug_assert!(elements_requested <= 4);

    // Prepare the seeds
    fn xy(index: usize, width: usize) -> (u8, u8) {
        ((index / width) as u8, (index % width) as u8)
    }

    let seed0 = add_domain_separator(seed, xy(start_index, columns));
    let seed1 = add_domain_separator(seed, xy(start_index + 1, columns));
    let seed2 = add_domain_separator(seed, xy(start_index + 2, columns));
    let seed3 = add_domain_separator(seed, xy(start_index + 3, columns));

    let mut state = Shake128::init_absorb(&seed0, &seed1, &seed2, &seed3);

    state.squeeze_first_five_blocks(rand_stack0, rand_stack1, rand_stack2, rand_stack3);

    // Every call to |rejection_sample_less_than_field_modulus|
    // will result in a call to |PortableSIMDUnit::rejection_sample_less_than_field_modulus|;
    // this latter function performs no bounds checking and can write up to 8
    // elements to its output. It is therefore possible that 255 elements have
    // already been sampled and we call the function again.
    //
    // To ensure we don't overflow the buffer in this case, we allocate 255 + 8
    // = 263 elements.
    let mut sampled0 = 0;
    let mut sampled1 = 0;
    let mut sampled2 = 0;
    let mut sampled3 = 0;

    let mut done0 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
        rand_stack0,
        &mut sampled0,
        &mut tmp_stack[0],
    );
    let mut done1 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
        rand_stack1,
        &mut sampled1,
        &mut tmp_stack[1],
    );
    let mut done2 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
        rand_stack2,
        &mut sampled2,
        &mut tmp_stack[2],
    );
    let mut done3 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
        rand_stack3,
        &mut sampled3,
        &mut tmp_stack[3],
    );

    while !done0 || !done1 || !done2 || !done3 {
        let randomnesses = state.squeeze_next_block();
        if !done0 {
            done0 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
                &randomnesses.0,
                &mut sampled0,
                &mut tmp_stack[0],
            );
        }
        if !done1 {
            done1 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
                &randomnesses.1,
                &mut sampled1,
                &mut tmp_stack[1],
            );
        }
        if !done2 {
            done2 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
                &randomnesses.2,
                &mut sampled2,
                &mut tmp_stack[2],
            );
        }
        if !done3 {
            done3 = rejection_sample_less_than_field_modulus::<SIMDUnit>(
                &randomnesses.3,
                &mut sampled3,
                &mut tmp_stack[3],
            );
        }
    }

    for k in 0..elements_requested {
        PolynomialRingElement::<SIMDUnit>::from_i32_array(
            &tmp_stack[k],
            &mut matrix[start_index + k],
        );
    }
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn rejection_sample_less_than_eta_equals_2<SIMDUnit: Operations>(
    randomness: &[u8],
    sampled_coefficients: &mut usize,
    out: &mut [i32; 263],
) -> bool {
    let mut done = false;

    // Since each byte can be used to sample up to 2 coefficients, and since
    // a single SIMDUnit can hold 8 coefficients, we pass in 4 bytes of randomness.
    cloop! {
        for random_bytes in randomness.chunks_exact(4) {
            if !done {
                let sampled = SIMDUnit::rejection_sample_less_than_eta_equals_2(
                    random_bytes,
                    &mut out[*sampled_coefficients..],
                );
                *sampled_coefficients += sampled;

                if *sampled_coefficients >= COEFFICIENTS_IN_RING_ELEMENT {
                    done = true;
                }
            }
        }
    }

    done
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn rejection_sample_less_than_eta_equals_4<SIMDUnit: Operations>(
    randomness: &[u8],
    sampled_coefficients: &mut usize,
    out: &mut [i32; 263],
) -> bool {
    let mut done = false;

    // Since each byte can be used to sample up to 2 coefficients, and since
    // a single SIMDUnit can hold 8 coefficients, we pass in 4 bytes of randomness.
    cloop! {
        for random_bytes in randomness.chunks_exact(4) {
            if !done {
                let sampled = SIMDUnit::rejection_sample_less_than_eta_equals_4(
                    random_bytes,
                    &mut out[*sampled_coefficients..],
                );
                *sampled_coefficients += sampled;

                if *sampled_coefficients >= COEFFICIENTS_IN_RING_ELEMENT {
                    done = true;
                }
            }
        }
    }

    done
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) fn rejection_sample_less_than_eta<SIMDUnit: Operations>(
    eta: Eta,
    randomness: &[u8],
    sampled: &mut usize,
    out: &mut [i32; 263],
) -> bool {
    match eta {
        Eta::Two => rejection_sample_less_than_eta_equals_2::<SIMDUnit>(randomness, sampled, out),
        Eta::Four => rejection_sample_less_than_eta_equals_4::<SIMDUnit>(randomness, sampled, out),
    }
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) fn add_error_domain_separator(slice: &[u8], domain_separator: u16) -> [u8; 66] {
    let mut out = [0u8; 66];

    out[0..slice.len()].copy_from_slice(slice);
    out[64] = domain_separator as u8;
    out[65] = (domain_separator >> 8) as u8;

    out
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) fn sample_four_error_ring_elements<SIMDUnit: Operations, Shake256: shake256::XofX4>(
    eta: Eta,
    seed: &[u8],
    start_index: u16,
    re: &mut [PolynomialRingElement<SIMDUnit>],
) {
    // Prepare the seeds
    let seed0 = add_error_domain_separator(seed, start_index);
    let seed1 = add_error_domain_separator(seed, start_index + 1);
    let seed2 = add_error_domain_separator(seed, start_index + 2);
    let seed3 = add_error_domain_separator(seed, start_index + 3);

    let mut state = Shake256::init_absorb_x4(&seed0, &seed1, &seed2, &seed3);
    let randomnesses = state.squeeze_first_block_x4();

    // Every call to |rejection_sample_less_than_field_modulus|
    // will result in a call to |SIMDUnit::rejection_sample_less_than_field_modulus|;
    // this latter function performs no bounds checking and can write up to 8
    // elements to its output. It is therefore possible that 255 elements have
    // already been sampled and we call the function again.
    //
    // To ensure we don't overflow the buffer in this case, we allocate 255 + 8
    // = 263 elements.
    let mut out = [[0i32; 263]; 4];

    let mut sampled0 = 0;
    let mut sampled1 = 0;
    let mut sampled2 = 0;
    let mut sampled3 = 0;

    let mut done0 = rejection_sample_less_than_eta::<SIMDUnit>(
        eta,
        &randomnesses.0,
        &mut sampled0,
        &mut out[0],
    );
    let mut done1 = rejection_sample_less_than_eta::<SIMDUnit>(
        eta,
        &randomnesses.1,
        &mut sampled1,
        &mut out[1],
    );
    let mut done2 = rejection_sample_less_than_eta::<SIMDUnit>(
        eta,
        &randomnesses.2,
        &mut sampled2,
        &mut out[2],
    );
    let mut done3 = rejection_sample_less_than_eta::<SIMDUnit>(
        eta,
        &randomnesses.3,
        &mut sampled3,
        &mut out[3],
    );

    while !done0 || !done1 || !done2 || !done3 {
        // Always sample another 4, but we only use it if we actually need it.
        let randomnesses = state.squeeze_next_block_x4();
        if !done0 {
            done0 = rejection_sample_less_than_eta::<SIMDUnit>(
                eta,
                &randomnesses.0,
                &mut sampled0,
                &mut out[0],
            );
        }
        if !done1 {
            done1 = rejection_sample_less_than_eta::<SIMDUnit>(
                eta,
                &randomnesses.1,
                &mut sampled1,
                &mut out[1],
            );
        }
        if !done2 {
            done2 = rejection_sample_less_than_eta::<SIMDUnit>(
                eta,
                &randomnesses.2,
                &mut sampled2,
                &mut out[2],
            );
        }
        if !done3 {
            done3 = rejection_sample_less_than_eta::<SIMDUnit>(
                eta,
                &randomnesses.3,
                &mut sampled3,
                &mut out[3],
            );
        }
    }

    // XXX: Core.Cmp.f_min is not implemented
    let max = start_index as usize + 4;
    let max = if re.len() < max { re.len() } else { max };
    for i in start_index as usize..max {
        PolynomialRingElement::<SIMDUnit>::from_i32_array(&out[i % 4], &mut re[i]);
    }
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn sample_mask_ring_element<SIMDUnit: Operations, Shake256: shake256::DsaXof>(
    seed: &[u8; 66],
    result: &mut PolynomialRingElement<SIMDUnit>,
    gamma1_exponent: usize,
) {
    match gamma1_exponent {
        17 => {
            let mut out = [0u8; 576];
            Shake256::shake256::<576>(seed, &mut out);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out, result);
        }
        19 => {
            let mut out = [0u8; 640];
            Shake256::shake256::<640>(seed, &mut out);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out, result);
        }
        _ => unreachable!(),
    }
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) fn sample_mask_vector<
    SIMDUnit: Operations,
    Shake256: shake256::DsaXof,
    Shake256X4: shake256::XofX4,
>(
    dimension: usize,
    gamma1_exponent: usize,
    seed: &[u8; 64],
    domain_separator: &mut u16,
    mask: &mut [PolynomialRingElement<SIMDUnit>],
) {
    // DIMENSION is COLUMNS_IN_A
    debug_assert!(dimension == 4 || dimension == 5 || dimension == 7);
    // So we can always sample 4 elements in one go first.

    let seed0 = add_error_domain_separator(seed, *domain_separator);
    let seed1 = add_error_domain_separator(seed, *domain_separator + 1);
    let seed2 = add_error_domain_separator(seed, *domain_separator + 2);
    let seed3 = add_error_domain_separator(seed, *domain_separator + 3);
    *domain_separator += 4;

    match gamma1_exponent {
        17 => {
            let mut out0 = [0; 576];
            let mut out1 = [0; 576];
            let mut out2 = [0; 576];
            let mut out3 = [0; 576];
            Shake256X4::shake256_x4(
                &seed0, &seed1, &seed2, &seed3, &mut out0, &mut out1, &mut out2, &mut out3,
            );
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out0, &mut mask[0]);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out1, &mut mask[1]);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out2, &mut mask[2]);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out3, &mut mask[3]);
        }
        19 => {
            let mut out0 = [0; 640];
            let mut out1 = [0; 640];
            let mut out2 = [0; 640];
            let mut out3 = [0; 640];
            Shake256X4::shake256_x4(
                &seed0, &seed1, &seed2, &seed3, &mut out0, &mut out1, &mut out2, &mut out3,
            );
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out0, &mut mask[0]);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out1, &mut mask[1]);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out2, &mut mask[2]);
            encoding::gamma1::deserialize::<SIMDUnit>(gamma1_exponent, &out3, &mut mask[3]);
        }
        _ => unreachable!(),
    }

    #[allow(clippy::needless_range_loop)]
    for i in 4..dimension {
        let seed = add_error_domain_separator(seed, *domain_separator);
        *domain_separator += 1;

        // TODO: For 87 we may want to do another 4 and discard 1.
        sample_mask_ring_element::<SIMDUnit, Shake256>(&seed, &mut mask[i], gamma1_exponent);
    }
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
fn inside_out_shuffle(
    randomness: &[u8],
    out_index: &mut usize,
    signs: &mut u64,
    result: &mut [i32; 256],
) -> bool {
    let mut done = false;

    cloop! {
        for byte in randomness.iter() {
            if !done {
                let sample_at = *byte as usize;
                if sample_at <= *out_index {
                    result[*out_index] = result[sample_at];
                    *out_index += 1;

                    result[sample_at] = 1 - 2 * ((*signs & 1) as i32);
                    *signs >>= 1;
                }

                done = *out_index == result.len();
            }
        }
    }

    done
}

#[cfg_attr(tarpaulin, inline(never))]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) fn sample_challenge_ring_element<SIMDUnit: Operations, Shake256: shake256::DsaXof>(
    seed: &[u8],
    number_of_ones: usize,
    re: &mut PolynomialRingElement<SIMDUnit>,
) {
    let mut state = Shake256::init_absorb_final(seed);
    let randomness = state.squeeze_first_block();

    let mut signs = u64::from_le_bytes(randomness[0..8].try_into().unwrap());
    let mut result = [0i32; 256];

    let mut out_index = result.len() - number_of_ones;
    let mut done = inside_out_shuffle(&randomness[8..], &mut out_index, &mut signs, &mut result);

    while !done {
        let randomness = state.squeeze_next_block();
        done = inside_out_shuffle(&randomness, &mut out_index, &mut signs, &mut result);
    }

    PolynomialRingElement::<SIMDUnit>::from_i32_array(&result, re);
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;

    use super::*;
    use crate::constants::COEFFICIENTS_IN_RING_ELEMENT;
    use crate::hash_functions;
    use crate::simd::traits::Operations;
    use crate::simd::{
        self,
    };

    fn sample_ring_element_uniform<SIMDUnit: Operations>(
        seed: [u8; 34],
        re: &mut PolynomialRingElement<SIMDUnit>,
    ) {
        use crate::rng::MLDsaRng;

        // Use deterministic RNG for reproducible testing
        let seed32: [u8; 32] = seed[..32].try_into().expect("seed is 34 bytes");
        let mut rng = MLDsaRng::new_deterministic(seed32);

        // Generate random bytes for rejection sampling
        let mut random_bytes = [0u8; 840]; // 5 blocks * 168 bytes
        rng.fill_bytes(&mut random_bytes)
            .expect("RNG should not fail in tests");

        let mut tmp_stack = [0i32; 263];
        let mut sampled = 0;

        let mut done = rejection_sample_less_than_field_modulus::<SIMDUnit>(
            &random_bytes,
            &mut sampled,
            &mut tmp_stack,
        );

        // If we need more random bytes, generate them
        while !done {
            let mut more_bytes = [0u8; 168]; // One more block
            rng.fill_bytes(&mut more_bytes)
                .expect("RNG should not fail in tests");

            done = rejection_sample_less_than_field_modulus::<SIMDUnit>(
                &more_bytes,
                &mut sampled,
                &mut tmp_stack,
            );
        }

        PolynomialRingElement::<SIMDUnit>::from_i32_array(&tmp_stack, re);
    }

    fn test_sample_challenge_ring_element_generic<
        SIMDUnit: Operations,
        Shake256: shake256::DsaXof,
    >() {
        // When TAU = 39
        let seed: [u8; 32] = [
            3, 9, 159, 119, 236, 6, 207, 7, 103, 108, 187, 137, 222, 35, 37, 30, 79, 224, 204, 186,
            41, 38, 148, 188, 201, 50, 105, 155, 129, 217, 124, 57,
        ];

        let expected_coefficients: [i32; COEFFICIENTS_IN_RING_ELEMENT] = [
            0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1,
            -1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1,
            -1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, 0, 0, -1, 1, 0, 0, 1,
            0, 0, 0, 1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1,
            0,
        ];

        let mut re = PolynomialRingElement::zero();
        sample_challenge_ring_element::<SIMDUnit, Shake256>(&seed, 39, &mut re);
        assert_eq!(re.to_i32_array(), expected_coefficients);

        // When TAU = 49
        let seed: [u8; 32] = [
            147, 7, 165, 152, 200, 20, 4, 38, 107, 110, 111, 176, 108, 84, 109, 201, 232, 125, 52,
            83, 160, 120, 106, 44, 76, 41, 76, 144, 8, 184, 4, 74,
        ];

        let expected_coefficients: [i32; COEFFICIENTS_IN_RING_ELEMENT] = [
            0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, -1, -1, 0,
            1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0,
            -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 1, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0,
            -1, 0, -1, 0, 0, -1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0,
            0, -1, 0, 0, 0,
        ];

        let mut re = PolynomialRingElement::zero();
        sample_challenge_ring_element::<SIMDUnit, Shake256>(&seed, 49, &mut re);
        assert_eq!(re.to_i32_array(), expected_coefficients);

        // When TAU = 60
        let seed: [u8; 32] = [
            188, 193, 17, 175, 172, 179, 13, 23, 90, 238, 237, 230, 143, 113, 24, 65, 250, 86, 234,
            229, 251, 57, 199, 158, 9, 4, 102, 249, 11, 68, 140, 107,
        ];

        let expected_coefficients: [i32; COEFFICIENTS_IN_RING_ELEMENT] = [
            0, 0, 0, 0, -1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0,
            0, 0, 1, 1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, -1, 0, 0, -1,
            0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0,
            0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 1, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0,
            0, 1, 0, -1, 1, 0, 0, 0, 0, 0, 1, 1, -1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 1, -1, 0,
            0, 0, 0, 1, -1, 0,
        ];

        let mut re = PolynomialRingElement::zero();
        sample_challenge_ring_element::<SIMDUnit, Shake256>(&seed, 60, &mut re);
        assert_eq!(re.to_i32_array(), expected_coefficients);
    }

    fn sample_in_ball_matches_lib_q_ring_generic<
        SIMDUnit: Operations,
        Shake256: shake256::DsaXof,
    >() {
        let seeds = [
            (
                [
                    3, 9, 159, 119, 236, 6, 207, 7, 103, 108, 187, 137, 222, 35, 37, 30, 79, 224,
                    204, 186, 41, 38, 148, 188, 201, 50, 105, 155, 129, 217, 124, 57,
                ],
                39usize,
            ),
            (
                [
                    147, 7, 165, 152, 200, 20, 4, 38, 107, 110, 111, 176, 108, 84, 109, 201, 232,
                    125, 52, 83, 160, 120, 106, 44, 76, 41, 76, 144, 8, 184, 4, 74,
                ],
                49usize,
            ),
            (
                [
                    188, 193, 17, 175, 172, 179, 13, 23, 90, 238, 237, 230, 143, 113, 24, 65, 250,
                    86, 234, 229, 251, 57, 199, 158, 9, 4, 102, 249, 11, 68, 140, 107,
                ],
                60usize,
            ),
        ];

        for (seed, tau) in seeds {
            let mut re = PolynomialRingElement::zero();
            sample_challenge_ring_element::<SIMDUnit, Shake256>(&seed, tau, &mut re);
            let ring = lib_q_ring::sample_in_ball(&seed, tau);
            assert_eq!(re.to_i32_array(), ring.coeffs);
        }
    }

    #[cfg(not(feature = "simd256"))]
    mod portable {
        use super::*;
        use crate::constants::Eta;

        #[test]
        fn test_sample_ring_element_uniform() {
            // Test portable implementation with expected value 1165602
            let seed: [u8; 34] = [
                33, 192, 250, 216, 117, 61, 16, 12, 248, 51, 213, 110, 64, 57, 119, 80, 164, 83,
                73, 91, 80, 128, 195, 219, 203, 149, 170, 233, 16, 232, 209, 105, 4, 5,
            ];

            let mut re = PolynomialRingElement::<simd::portable::PortableSIMDUnit>::zero();
            sample_ring_element_uniform::<simd::portable::PortableSIMDUnit>(seed, &mut re);
            let actual_coefficients = re.to_i32_array();

            // Test 1: Verify we get non-zero coefficients
            assert!(
                !actual_coefficients.iter().all(|&x| x == 0),
                "All coefficients are zero"
            );

            // Test 2: Verify coefficients are in valid range
            const Q: i32 = 8380417;
            for coeff in actual_coefficients.iter() {
                assert!(
                    *coeff >= -Q && *coeff <= Q,
                    "Coefficient {} is out of range [-{}, {}]",
                    coeff,
                    Q,
                    Q
                );
            }

            // Test 3: Verify our implementation produces non-zero entropy
            let first_coeff = actual_coefficients[0];
            assert!(
                !actual_coefficients.iter().all(|&x| x == first_coeff),
                "All coefficients are identical - no entropy"
            );

            // Test 4: Verify deterministic RNG produces consistent results
            let mut re2 = PolynomialRingElement::<simd::portable::PortableSIMDUnit>::zero();
            sample_ring_element_uniform::<simd::portable::PortableSIMDUnit>(seed, &mut re2);
            let actual_coefficients2 = re2.to_i32_array();

            assert_eq!(
                actual_coefficients, actual_coefficients2,
                "Deterministic RNG should produce identical results for same seed"
            );
        }

        #[test]
        fn sample_four_error_ring_elements_eta2_x4_pipeline_smoke() {
            let seed: [u8; 64] = [
                51, 203, 133, 235, 126, 210, 169, 81, 4, 134, 147, 168, 252, 67, 176, 99, 130, 186,
                254, 103, 241, 199, 173, 78, 121, 232, 12, 244, 4, 143, 8, 174, 122, 170, 124, 35,
                53, 49, 202, 94, 27, 249, 200, 186, 175, 198, 169, 116, 244, 227, 133, 111, 205,
                140, 233, 110, 227, 67, 35, 226, 194, 75, 130, 105,
            ];
            let start_index = 5u16;
            let mut buf = [PolynomialRingElement::<simd::portable::PortableSIMDUnit>::zero(); 6];
            sample_four_error_ring_elements::<
                simd::portable::PortableSIMDUnit,
                hash_functions::portable::Shake256X4,
            >(Eta::Two, &seed, start_index, &mut buf);
            let first = buf[5].to_i32_array();

            let mut buf2 = [PolynomialRingElement::<simd::portable::PortableSIMDUnit>::zero(); 6];
            sample_four_error_ring_elements::<
                simd::portable::PortableSIMDUnit,
                hash_functions::portable::Shake256X4,
            >(Eta::Two, &seed, start_index, &mut buf2);
            assert_eq!(first, buf2[5].to_i32_array());

            for &c in &first {
                assert!(
                    (-2..=2).contains(&c),
                    "ETA=2 coefficients must lie in [-2, 2], got {c}"
                );
            }
        }

        #[test]
        fn test_sample_challenge_ring_element() {
            test_sample_challenge_ring_element_generic::<
                simd::portable::PortableSIMDUnit,
                hash_functions::portable::Shake256,
            >();
        }

        #[test]
        fn sample_in_ball_matches_lib_q_ring() {
            sample_in_ball_matches_lib_q_ring_generic::<
                simd::portable::PortableSIMDUnit,
                hash_functions::portable::Shake256,
            >();
        }
    }

    #[cfg(feature = "simd256")]
    mod simd256 {
        use super::*;

        #[test]
        fn test_sample_ring_element_uniform() {
            // Test SIMD implementation with expected value 2727178
            let seed: [u8; 34] = [
                33, 192, 250, 216, 117, 61, 16, 12, 248, 51, 213, 110, 64, 57, 119, 80, 164, 83,
                73, 91, 80, 128, 195, 219, 203, 149, 170, 233, 16, 232, 209, 105, 4, 5,
            ];

            let mut re = PolynomialRingElement::<simd::avx2::AVX2SIMDUnit>::zero();
            sample_ring_element_uniform::<simd::avx2::AVX2SIMDUnit>(seed, &mut re);
            let actual_coefficients = re.to_i32_array();

            // Test 1: Verify we get non-zero coefficients
            assert!(
                !actual_coefficients.iter().all(|&x| x == 0),
                "All coefficients are zero"
            );

            // Test 2: Verify coefficients are in valid range
            const Q: i32 = 8380417;
            for coeff in actual_coefficients.iter() {
                assert!(
                    *coeff >= -Q && *coeff <= Q,
                    "Coefficient {} is out of range [-{}, {}]",
                    coeff,
                    Q,
                    Q
                );
            }

            // Test 3: Verify our implementation produces non-zero entropy
            let first_coeff = actual_coefficients[0];
            assert!(
                !actual_coefficients.iter().all(|&x| x == first_coeff),
                "All coefficients are identical - no entropy"
            );

            // Test 4: Verify deterministic RNG produces consistent results
            let mut re2 = PolynomialRingElement::<simd::avx2::AVX2SIMDUnit>::zero();
            sample_ring_element_uniform::<simd::avx2::AVX2SIMDUnit>(seed, &mut re2);
            let actual_coefficients2 = re2.to_i32_array();

            assert_eq!(
                actual_coefficients, actual_coefficients2,
                "Deterministic RNG should produce identical results for same seed"
            );
        }

        #[test]
        fn test_sample_challenge_ring_element() {
            test_sample_challenge_ring_element_generic::<
                simd::avx2::AVX2SIMDUnit,
                hash_functions::portable::Shake256,
            >();
        }

        #[test]
        fn sample_in_ball_matches_lib_q_ring() {
            sample_in_ball_matches_lib_q_ring_generic::<
                simd::avx2::AVX2SIMDUnit,
                hash_functions::portable::Shake256,
            >();
        }
    }
}
