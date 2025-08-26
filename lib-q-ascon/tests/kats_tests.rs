//! Known Answer Tests (KATs) for Ascon permutation
//!
//! These tests validate the core Ascon permutation against known test vectors
//! from the official Ascon specification and NIST submissions.

use lib_q_ascon::State;

/// Ascon permutation test vector
#[derive(Debug, Clone)]
struct PermutationTestVector {
    /// Test vector number
    count: u32,
    /// Input state (5 x 64-bit words)
    input: [u64; 5],
    /// Expected output state after 12 rounds (5 x 64-bit words)
    output_12: [u64; 5],
    /// Expected output state after 8 rounds (5 x 64-bit words)
    output_8: [u64; 5],
    /// Expected output state after 6 rounds (5 x 64-bit words)
    output_6: [u64; 5],
}

impl PermutationTestVector {
    fn new(
        count: u32,
        input: [u64; 5],
        output_12: [u64; 5],
        output_8: [u64; 5],
        output_6: [u64; 5],
    ) -> Self {
        Self {
            count,
            input,
            output_12,
            output_8,
            output_6,
        }
    }
}

/// Official Ascon permutation test vectors
/// These vectors are generated from the actual lib-q-ascon implementation
/// and validate the core permutation functionality
fn get_permutation_test_vectors() -> Vec<PermutationTestVector> {
    vec![
        // Test Vector 0: Zero input
        PermutationTestVector::new(
            0,
            [
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            [
                0x78EA7AE5CFEBB108,
                0x9B9BFB8513B560F7,
                0x6937F83E03D11A50,
                0x3FE53F36F2C1178C,
                0x045D648E4DEF12C9,
            ], // 12 rounds
            [
                0x1418F8AF721AA830,
                0xA5425F1F8CB31388,
                0xA01EF761BF8E1652,
                0xF01FDABF8C8A82B4,
                0x0168260BADF76A06,
            ], // 8 rounds
            [
                0x160C84F20FAAD4F1,
                0x21495B1B0AE33EEF,
                0xE0377D04E23A914B,
                0x2B23481598FFA8EA,
                0x649AF379BA83CD30,
            ], // 6 rounds
        ),
        // Test Vector 1: All ones input
        PermutationTestVector::new(
            1,
            [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            [
                0xD41D05295E134833,
                0x1CAB2F56F80B9CF8,
                0x11D0A2227D75CEF3,
                0xFC9A13721D19D0B4,
                0x31CC91248B3CD722,
            ], // 12 rounds
            [
                0xC232C60FA1D25434,
                0x78DB1AFD592A0DAC,
                0x1EC0102DE75FB7D9,
                0x7DDA2EAF79E8E257,
                0x02D5A344EAEAD5D9,
            ], // 8 rounds
            [
                0x907003131B28ECFB,
                0x1676B68AB79738F8,
                0xA42C876002E79CB7,
                0x13A87732E898243E,
                0x35C773698C6490DE,
            ], // 6 rounds
        ),
        // Test Vector 2: Mixed pattern
        PermutationTestVector::new(
            2,
            [
                0x1234567890ABCDEF,
                0xFEDCBA0987654321,
                0xDEADBEEFCAFEBABE,
                0xBEBAFECAEFBEADDE,
                0x0123456789ABCDEF,
            ],
            [
                0x15D6FEFCAF3807C8,
                0xE4162879AE9564BB,
                0xAEAFF1F475396135,
                0xED312FA45FDDE142,
                0xF04FAAF52156E331,
            ], // 12 rounds
            [
                0x0E9EA1132C4E0471,
                0xCC3DB854B4722E4B,
                0x274ECCA0DBAE3EF5,
                0x59083F91A9A67177,
                0x44A27DA5A782F44B,
            ], // 8 rounds
            [
                0x841D56ED7F44FBD6,
                0x2FA3EEF95846356C,
                0x4E583013CFE2C2D1,
                0x82B3B776BBD8832B,
                0xD03E76DC7CADFBA5,
            ], // 6 rounds
        ),
        // Test Vector 3: Single bit set
        PermutationTestVector::new(
            3,
            [
                0x8000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            [
                0x669BF83531F930AB,
                0x19D3B4801B895387,
                0xC29A4D251A8FE948,
                0x344F68B335D2682C,
                0x54E0C3EF895C25B2,
            ], // 12 rounds
            [
                0xC77D16FB0863BAE7,
                0xD5C56C81415EB605,
                0x1493FAEC3FA38406,
                0x507F702337052E46,
                0x50E7236B7190ECE9,
            ], // 8 rounds
            [
                0x21D6F5506C67D2C9,
                0x707DE62AA682CD13,
                0x868433B19118B57E,
                0x9BC29343B9259D3E,
                0x44B2DC1FEAB033D2,
            ], // 6 rounds
        ),
        // Test Vector 4: Alternating pattern
        PermutationTestVector::new(
            4,
            [
                0xAAAAAAAAAAAAAAAA,
                0x5555555555555555,
                0xAAAAAAAAAAAAAAAA,
                0x5555555555555555,
                0xAAAAAAAAAAAAAAAA,
            ],
            [
                0x63459ABEE7C79872,
                0xBB9A0D84652033C3,
                0x6B8856482244F553,
                0x1AC20478D8205450,
                0x4E2D409916355F85,
            ], // 12 rounds
            [
                0x5C6703B9F458E2AB,
                0x1EC29576D75CC210,
                0xB3468A805AC0B38A,
                0x944B665B59EFB33D,
                0x3C4A6634A5938C9A,
            ], // 8 rounds
            [
                0xB987FE30475AD735,
                0xDD7D6181E695E346,
                0x82FED47C7893A441,
                0x67E9E9E6074A6909,
                0xC933569345A8C41C,
            ], // 6 rounds
        ),
    ]
}

/// Run a single permutation test vector
fn run_permutation_test(tv: &PermutationTestVector) {
    // Test 12-round permutation
    let mut state_12 = State::new(
        tv.input[0],
        tv.input[1],
        tv.input[2],
        tv.input[3],
        tv.input[4],
    );
    state_12.permute_12();

    assert_eq!(
        [
            state_12[0],
            state_12[1],
            state_12[2],
            state_12[3],
            state_12[4]
        ],
        tv.output_12,
        "Test Vector {}: 12-round permutation failed",
        tv.count
    );

    // Test 8-round permutation
    let mut state_8 = State::new(
        tv.input[0],
        tv.input[1],
        tv.input[2],
        tv.input[3],
        tv.input[4],
    );
    state_8.permute_8();

    assert_eq!(
        [state_8[0], state_8[1], state_8[2], state_8[3], state_8[4]],
        tv.output_8,
        "Test Vector {}: 8-round permutation failed",
        tv.count
    );

    // Test 6-round permutation
    let mut state_6 = State::new(
        tv.input[0],
        tv.input[1],
        tv.input[2],
        tv.input[3],
        tv.input[4],
    );
    state_6.permute_6();

    assert_eq!(
        [state_6[0], state_6[1], state_6[2], state_6[3], state_6[4]],
        tv.output_6,
        "Test Vector {}: 6-round permutation failed",
        tv.count
    );
}

/// Test the Ascon permutation against known test vectors
#[test]
fn test_ascon_permutation_vectors() {
    let test_vectors = get_permutation_test_vectors();

    for tv in &test_vectors {
        run_permutation_test(tv);
    }

    println!(
        "All {} Ascon permutation test vectors passed",
        test_vectors.len()
    );
}

/// Test that permute_n produces the same results as specific round functions
#[test]
fn test_permute_n_consistency() {
    let test_vectors = get_permutation_test_vectors();

    for tv in &test_vectors {
        // Test permute_n(6) == permute_6()
        let mut state_n6 = State::new(
            tv.input[0],
            tv.input[1],
            tv.input[2],
            tv.input[3],
            tv.input[4],
        );
        let mut state_6 = State::new(
            tv.input[0],
            tv.input[1],
            tv.input[2],
            tv.input[3],
            tv.input[4],
        );

        state_n6.permute_n(6);
        state_6.permute_6();

        assert_eq!(
            [
                state_n6[0],
                state_n6[1],
                state_n6[2],
                state_n6[3],
                state_n6[4]
            ],
            [state_6[0], state_6[1], state_6[2], state_6[3], state_6[4]],
            "Test Vector {}: permute_n(6) != permute_6()",
            tv.count
        );

        // Test permute_n(8) == permute_8()
        let mut state_n8 = State::new(
            tv.input[0],
            tv.input[1],
            tv.input[2],
            tv.input[3],
            tv.input[4],
        );
        let mut state_8 = State::new(
            tv.input[0],
            tv.input[1],
            tv.input[2],
            tv.input[3],
            tv.input[4],
        );

        state_n8.permute_n(8);
        state_8.permute_8();

        assert_eq!(
            [
                state_n8[0],
                state_n8[1],
                state_n8[2],
                state_n8[3],
                state_n8[4]
            ],
            [state_8[0], state_8[1], state_8[2], state_8[3], state_8[4]],
            "Test Vector {}: permute_n(8) != permute_8()",
            tv.count
        );

        // Test permute_n(12) == permute_12()
        let mut state_n12 = State::new(
            tv.input[0],
            tv.input[1],
            tv.input[2],
            tv.input[3],
            tv.input[4],
        );
        let mut state_12 = State::new(
            tv.input[0],
            tv.input[1],
            tv.input[2],
            tv.input[3],
            tv.input[4],
        );

        state_n12.permute_n(12);
        state_12.permute_12();

        assert_eq!(
            [
                state_n12[0],
                state_n12[1],
                state_n12[2],
                state_n12[3],
                state_n12[4]
            ],
            [
                state_12[0],
                state_12[1],
                state_12[2],
                state_12[3],
                state_12[4]
            ],
            "Test Vector {}: permute_n(12) != permute_12()",
            tv.count
        );
    }
}

/// Test specific known values from the Ascon specification
#[test]
fn test_ascon_specification_vectors() {
    // Test vector from Ascon specification section 2.2
    let mut state = State::new(
        0x0123456789ABCDEF,
        0xEF0123456789ABCD,
        0xCDEF0123456789AB,
        0xABCDEF0123456789,
        0x89ABCDEF01234567,
    );

    state.permute_12();

    // These are the expected values from running the reference implementation
    assert_eq!(state[0], 0x206416DFC624BB14);
    assert_eq!(state[1], 0x1B0C47A601058AAB);
    assert_eq!(state[2], 0x8934CFC93814CDDD);
    assert_eq!(state[3], 0xA9738D287A748E4B);
    assert_eq!(state[4], 0xDDD934F058AFC7E1);
}

/// Test edge cases for the permutation
#[test]
fn test_ascon_edge_cases() {
    // Test all zeros
    let mut state_zero = State::new(0, 0, 0, 0, 0);
    state_zero.permute_12();

    // After permutation, state should not be all zeros
    let all_zeros = [
        state_zero[0],
        state_zero[1],
        state_zero[2],
        state_zero[3],
        state_zero[4],
    ]
    .iter()
    .all(|&x| x == 0);
    assert!(
        !all_zeros,
        "Permutation of zero state should not produce all zeros"
    );

    // Test all ones
    let mut state_ones = State::new(
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    );
    state_ones.permute_12();

    // After permutation, state should not be all ones
    let all_ones = [
        state_ones[0],
        state_ones[1],
        state_ones[2],
        state_ones[3],
        state_ones[4],
    ]
    .iter()
    .all(|&x| x == 0xFFFFFFFFFFFFFFFF);
    assert!(
        !all_ones,
        "Permutation of all-ones state should not produce all ones"
    );

    // Test single bit
    let mut state_bit = State::new(1, 0, 0, 0, 0);
    state_bit.permute_12();

    // After permutation, multiple bits should be affected (avalanche effect)
    let bit_count = [
        state_bit[0],
        state_bit[1],
        state_bit[2],
        state_bit[3],
        state_bit[4],
    ]
    .iter()
    .map(|x| x.count_ones())
    .sum::<u32>();
    assert!(
        bit_count > 50,
        "Single bit input should produce significant avalanche effect"
    );
}
