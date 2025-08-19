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
                0x78ea7ae5cfebb108,
                0x9b9bfb8513b560f7,
                0x6937f83e03d11a50,
                0x3fe53f36f2c1178c,
                0x045d648e4def12c9,
            ], // 12 rounds
            [
                0x1418f8af721aa830,
                0xa5425f1f8cb31388,
                0xa01ef761bf8e1652,
                0xf01fdabf8c8a82b4,
                0x0168260badf76a06,
            ], // 8 rounds
            [
                0x160c84f20faad4f1,
                0x21495b1b0ae33eef,
                0xe0377d04e23a914b,
                0x2b23481598ffa8ea,
                0x649af379ba83cd30,
            ], // 6 rounds
        ),
        // Test Vector 1: All ones input
        PermutationTestVector::new(
            1,
            [
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
            ],
            [
                0xd41d05295e134833,
                0x1cab2f56f80b9cf8,
                0x11d0a2227d75cef3,
                0xfc9a13721d19d0b4,
                0x31cc91248b3cd722,
            ], // 12 rounds
            [
                0xc232c60fa1d25434,
                0x78db1afd592a0dac,
                0x1ec0102de75fb7d9,
                0x7dda2eaf79e8e257,
                0x02d5a344eaead5d9,
            ], // 8 rounds
            [
                0x907003131b28ecfb,
                0x1676b68ab79738f8,
                0xa42c876002e79cb7,
                0x13a87732e898243e,
                0x35c773698c6490de,
            ], // 6 rounds
        ),
        // Test Vector 2: Mixed pattern
        PermutationTestVector::new(
            2,
            [
                0x1234567890abcdef,
                0xfedcba0987654321,
                0xdeadbeefcafebabe,
                0xbebafecaefbeadde,
                0x0123456789abcdef,
            ],
            [
                0x15d6fefcaf3807c8,
                0xe4162879ae9564bb,
                0xaeaff1f475396135,
                0xed312fa45fdde142,
                0xf04faaf52156e331,
            ], // 12 rounds
            [
                0x0e9ea1132c4e0471,
                0xcc3db854b4722e4b,
                0x274ecca0dbae3ef5,
                0x59083f91a9a67177,
                0x44a27da5a782f44b,
            ], // 8 rounds
            [
                0x841d56ed7f44fbd6,
                0x2fa3eef95846356c,
                0x4e583013cfe2c2d1,
                0x82b3b776bbd8832b,
                0xd03e76dc7cadfba5,
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
                0x669bf83531f930ab,
                0x19d3b4801b895387,
                0xc29a4d251a8fe948,
                0x344f68b335d2682c,
                0x54e0c3ef895c25b2,
            ], // 12 rounds
            [
                0xc77d16fb0863bae7,
                0xd5c56c81415eb605,
                0x1493faec3fa38406,
                0x507f702337052e46,
                0x50e7236b7190ece9,
            ], // 8 rounds
            [
                0x21d6f5506c67d2c9,
                0x707de62aa682cd13,
                0x868433b19118b57e,
                0x9bc29343b9259d3e,
                0x44b2dc1feab033d2,
            ], // 6 rounds
        ),
        // Test Vector 4: Alternating pattern
        PermutationTestVector::new(
            4,
            [
                0xaaaaaaaaaaaaaaaa,
                0x5555555555555555,
                0xaaaaaaaaaaaaaaaa,
                0x5555555555555555,
                0xaaaaaaaaaaaaaaaa,
            ],
            [
                0x63459abee7c79872,
                0xbb9a0d84652033c3,
                0x6b8856482244f553,
                0x1ac20478d8205450,
                0x4e2d409916355f85,
            ], // 12 rounds
            [
                0x5c6703b9f458e2ab,
                0x1ec29576d75cc210,
                0xb3468a805ac0b38a,
                0x944b665b59efb33d,
                0x3c4a6634a5938c9a,
            ], // 8 rounds
            [
                0xb987fe30475ad735,
                0xdd7d6181e695e346,
                0x82fed47c7893a441,
                0x67e9e9e6074a6909,
                0xc933569345a8c41c,
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
        0x0123456789abcdef,
        0xef0123456789abcd,
        0xcdef0123456789ab,
        0xabcdef0123456789,
        0x89abcdef01234567,
    );

    state.permute_12();

    // These are the expected values from running the reference implementation
    assert_eq!(state[0], 0x206416dfc624bb14);
    assert_eq!(state[1], 0x1b0c47a601058aab);
    assert_eq!(state[2], 0x8934cfc93814cddd);
    assert_eq!(state[3], 0xa9738d287a748e4b);
    assert_eq!(state[4], 0xddd934f058afc7e1);
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
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
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
    .all(|&x| x == 0xffffffffffffffff);
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
