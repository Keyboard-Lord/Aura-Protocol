// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
mod support;

use aura_intent_lineage_v1::{
    DcmConfigV1, DcmExecutionErrorV1, DcmExecutionV1, DcmInputV1, DcmStateV1,
};

use support::{
    encode_hex, legacy_canonical_dcm_config, legacy_canonical_dcm_input, legacy_changed_dcm_input,
    LEGACY_CANONICAL_DCM_TRACE_COMMITMENT_HEX, LEGACY_CANONICAL_TRACE_STATES_V1,
};

#[test]
fn deterministic_execution_matches_itself() {
    let config = legacy_canonical_dcm_config();
    let input = legacy_canonical_dcm_input();

    let first = DcmExecutionV1::run(&config, &input).unwrap();
    let second = DcmExecutionV1::run(&config, &input).unwrap();

    assert_eq!(first, second);
}

#[test]
fn changing_initial_state_changes_output() {
    let config = legacy_canonical_dcm_config();
    let baseline = DcmExecutionV1::run(&config, &legacy_canonical_dcm_input()).unwrap();
    let changed = DcmExecutionV1::run(&config, &legacy_changed_dcm_input()).unwrap();

    assert_ne!(baseline.final_state, changed.final_state);
    assert_ne!(baseline.trace_commitment, changed.trace_commitment);
}

#[test]
fn iteration_count_changes_output() {
    let short = DcmExecutionV1::run(
        &DcmConfigV1 {
            modulus: 97,
            iteration_count: 4,
        },
        &DcmInputV1 { x0: 3, y0: 7 },
    )
    .unwrap();
    let long = DcmExecutionV1::run(
        &DcmConfigV1 {
            modulus: 97,
            iteration_count: 5,
        },
        &DcmInputV1 { x0: 3, y0: 7 },
    )
    .unwrap();

    assert_ne!(short.final_state, long.final_state);
    assert_ne!(short.trace_commitment, long.trace_commitment);
    assert_ne!(short.trace_length, long.trace_length);
}

#[test]
fn invalid_modulus_rejects_deterministically() {
    let error = DcmExecutionV1::run(
        &DcmConfigV1 {
            modulus: 1,
            iteration_count: 5,
        },
        &DcmInputV1 { x0: 0, y0: 0 },
    )
    .unwrap_err();

    assert_eq!(error, DcmExecutionErrorV1::InvalidModulus { actual: 1 });
}

#[test]
fn canonical_fixed_vector_is_stable() {
    let execution = DcmExecutionV1::run(
        &legacy_canonical_dcm_config(),
        &legacy_canonical_dcm_input(),
    )
    .unwrap();

    assert_eq!(execution.states, LEGACY_CANONICAL_TRACE_STATES_V1);
    assert_eq!(execution.final_state, DcmStateV1 { x: 2, y: 12 });
    assert_eq!(execution.trace_length, 6);
    assert_eq!(
        encode_hex(&execution.trace_commitment),
        LEGACY_CANONICAL_DCM_TRACE_COMMITMENT_HEX
    );
}
