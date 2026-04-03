//! DoS and allocation-limit tests for AIR public constants (`MAX_*`) and
//! `validate_trace_dimensions`.

#![cfg(feature = "zkp")]

use lib_q_zkp::air::session_key::{
    MAX_SESSION_KEY_SIZE,
    MAX_SHARED_SECRET_SIZE,
};
use lib_q_zkp::air::{
    AirError,
    ArithmeticAir,
    KdfParams,
    MAX_OPERATIONS,
    MAX_TRACE_HEIGHT,
    MAX_TRACE_WIDTH,
    MerkleInclusionAir,
    SessionKeyDerivationAir,
    SessionKeyInput,
    TraceGenerator,
    validate_trace_dimensions,
};

#[test]
fn arithmetic_air_rejects_num_operations_above_max() {
    let result = ArithmeticAir::new(MAX_OPERATIONS + 1);
    assert!(
        matches!(
            &result,
            Err(AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            }) if parameter == "num_operations" && *max == MAX_OPERATIONS && *actual == MAX_OPERATIONS + 1
        ),
        "expected ExceedsMaxSize for num_operations, got {:?}",
        result
    );
}

#[test]
fn arithmetic_air_rejects_trace_width_above_max() {
    let min_ops_for_wide_trace = MAX_TRACE_WIDTH / 3 + 1;
    assert!(
        min_ops_for_wide_trace <= MAX_OPERATIONS,
        "test assumes trace_width limit binds before MAX_OPERATIONS"
    );
    let result = ArithmeticAir::new(min_ops_for_wide_trace);
    assert!(
        matches!(
            &result,
            Err(AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            }) if parameter == "trace_width" && *max == MAX_TRACE_WIDTH && *actual == min_ops_for_wide_trace * 3
        ),
        "expected ExceedsMaxSize for trace_width, got {:?}",
        result
    );
}

#[test]
fn validate_trace_dimensions_rejects_excessive_width() {
    let w = MAX_TRACE_WIDTH + 1;
    let err = validate_trace_dimensions(w, 8).unwrap_err();
    assert!(
        matches!(
            &err,
            AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            } if parameter == "width" && *max == MAX_TRACE_WIDTH && *actual == w
        ),
        "got {:?}",
        err
    );
}

#[test]
fn validate_trace_dimensions_rejects_excessive_height() {
    // `MAX_TRACE_HEIGHT` is already a power of two; double it for the next power of two.
    let height_above_max = MAX_TRACE_HEIGHT.saturating_mul(2);
    assert!(
        height_above_max > MAX_TRACE_HEIGHT && height_above_max.is_power_of_two(),
        "need a power-of-two height strictly above MAX_TRACE_HEIGHT"
    );
    let err = validate_trace_dimensions(4, height_above_max).unwrap_err();
    assert!(
        matches!(
            &err,
            AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            } if parameter == "height" && *max == MAX_TRACE_HEIGHT && *actual == height_above_max
        ),
        "got {:?}",
        err
    );
}

#[test]
fn session_key_air_rejects_output_length_above_max() {
    let params = KdfParams {
        output_length: MAX_SESSION_KEY_SIZE + 1,
        ..KdfParams::default()
    };
    let err = SessionKeyDerivationAir::new(params).unwrap_err();
    assert!(
        matches!(
            &err,
            AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            } if parameter == "output_length" && *max == MAX_SESSION_KEY_SIZE && *actual == MAX_SESSION_KEY_SIZE + 1
        ),
        "got {:?}",
        err
    );
}

#[test]
fn session_key_trace_rejects_oversized_shared_secret() {
    let air = SessionKeyDerivationAir::new(KdfParams::default()).unwrap();
    let input = SessionKeyInput {
        shared_secret: vec![0u8; MAX_SHARED_SECRET_SIZE + 1],
        session_keys: vec![0u8; 32],
    };
    let err = air.generate_trace(&input).unwrap_err();
    assert!(
        matches!(
            &err,
            AirError::ExceedsMaxSize {
                parameter,
                max,
                actual,
            } if parameter == "shared_secret" && *max == MAX_SHARED_SECRET_SIZE && *actual == MAX_SHARED_SECRET_SIZE + 1
        ),
        "got {:?}",
        err
    );
}

#[test]
fn merkle_inclusion_air_rejects_depth_above_max() {
    let result = MerkleInclusionAir::new(65);
    assert!(
        matches!(result, Err(AirError::ExceedsMaxSize { .. })),
        "expected ExceedsMaxSize for excessive tree depth, got {:?}",
        result
    );
}
