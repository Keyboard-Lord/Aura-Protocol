// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use aura_intent_lineage_v1::{
    coordinate_recurrence_next_521_v1, derive_trace_commitment_521_v1,
    fast_forward_dcm_state_521_v1, fast_rewind_dcm_state_521_v1, DcmConfig521V1, DcmExecution521V1,
    DcmInput521V1, DcmState521V1, DcmTraceCommitment521ErrorV1, FieldElement521V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
};

const PINNED_TRACE_COMMITMENT_HEX: &str =
    "aa69585e473dd210900a92c881ceaeb9414c611f01913c5e2e35767fb844fc99";

#[test]
fn canonical_521_bit_cat_map_path_succeeds() {
    let execution = canonical_execution();

    assert_eq!(execution.trace_length, 3);
    assert_eq!(execution.states.len(), 3);
    assert_eq!(execution.states[0], state(max_minus_one(), small_value(1)));
    assert_eq!(execution.states[1], state(zero(), small_value(1)));
    assert_eq!(execution.final_state, state(small_value(1), small_value(2)));
}

#[test]
fn deterministic_execution_matches_itself() {
    let first = canonical_execution();
    let second = canonical_execution();

    assert_eq!(first, second);
}

#[test]
fn zero_iteration_returns_initial_state_and_singleton_trace() {
    let execution = DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 0 },
        &DcmInput521V1 {
            x0: small_value(7),
            y0: small_value(3),
        },
    )
    .unwrap();

    assert_eq!(execution.trace_length, 1);
    assert_eq!(execution.states.len(), 1);
    assert_eq!(execution.final_state, state(small_value(7), small_value(3)));
    assert_eq!(execution.states[0], state(small_value(7), small_value(3)));
}

#[test]
fn changing_x0_changes_final_state() {
    let baseline = canonical_execution();
    let changed = DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 2 },
        &DcmInput521V1 {
            x0: small_value(2),
            y0: small_value(1),
        },
    )
    .unwrap();

    assert_ne!(baseline.final_state, changed.final_state);
    assert_ne!(baseline.trace_commitment, changed.trace_commitment);
}

#[test]
fn changing_y0_changes_final_state() {
    let baseline = canonical_execution();
    let changed = DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 2 },
        &DcmInput521V1 {
            x0: max_minus_one(),
            y0: small_value(2),
        },
    )
    .unwrap();

    assert_ne!(baseline.final_state, changed.final_state);
    assert_ne!(baseline.trace_commitment, changed.trace_commitment);
}

#[test]
fn different_iteration_counts_change_output() {
    let short = DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 1 },
        &DcmInput521V1 {
            x0: max_minus_one(),
            y0: small_value(1),
        },
    )
    .unwrap();
    let long = canonical_execution();

    assert_ne!(short.final_state, long.final_state);
    assert_ne!(short.trace_commitment, long.trace_commitment);
    assert_ne!(short.trace_length, long.trace_length);
}

#[test]
fn fast_forward_matches_materialized_execution() {
    let input = DcmInput521V1 {
        x0: max_minus_one(),
        y0: small_value(1),
    };
    let execution = canonical_execution();

    assert_eq!(
        fast_forward_dcm_state_521_v1(input.initial_state(), 2),
        execution.final_state
    );
}

#[test]
fn inverse_jump_recovers_initial_state() {
    let input = DcmInput521V1 {
        x0: max_minus_one(),
        y0: small_value(1),
    };
    let execution = canonical_execution();

    assert_eq!(
        fast_rewind_dcm_state_521_v1(execution.final_state, 2),
        input.initial_state()
    );
}

#[test]
fn coordinate_recurrence_matches_both_coordinates() {
    let execution = canonical_execution();

    assert_eq!(
        coordinate_recurrence_next_521_v1(execution.states[0].x, execution.states[1].x),
        execution.states[2].x
    );
    assert_eq!(
        coordinate_recurrence_next_521_v1(execution.states[0].y, execution.states[1].y),
        execution.states[2].y
    );
}

#[test]
fn pinned_521_bit_vector_is_stable() {
    let execution = canonical_execution();

    assert_eq!(
        encode_hex(&execution.trace_commitment),
        PINNED_TRACE_COMMITMENT_HEX
    );
}

#[test]
fn trace_commitment_rejects_truncated_trace() {
    let config = DcmConfig521V1 { iteration_count: 2 };
    let input = DcmInput521V1 {
        x0: max_minus_one(),
        y0: small_value(1),
    };
    let execution = canonical_execution();

    let error =
        derive_trace_commitment_521_v1(&config, &input, &execution.states[..2]).unwrap_err();

    assert_eq!(
        error,
        DcmTraceCommitment521ErrorV1::TraceLengthMismatch {
            expected: 3,
            actual: 2,
        }
    );
}

#[test]
fn trace_commitment_rejects_non_canonical_initial_state_binding() {
    let config = DcmConfig521V1 { iteration_count: 2 };
    let input = DcmInput521V1 {
        x0: max_minus_one(),
        y0: small_value(1),
    };
    let execution = canonical_execution();
    let mut tampered_states = execution.states.clone();
    tampered_states[0] = state(small_value(9), small_value(9));

    let error = derive_trace_commitment_521_v1(&config, &input, &tampered_states).unwrap_err();

    assert_eq!(
        error,
        DcmTraceCommitment521ErrorV1::InitialStateMismatch {
            expected: input.initial_state(),
            actual: tampered_states[0],
        }
    );
}

fn canonical_execution() -> DcmExecution521V1 {
    DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 2 },
        &DcmInput521V1 {
            x0: max_minus_one(),
            y0: small_value(1),
        },
    )
    .unwrap()
}

fn state(x: FieldElement521V1, y: FieldElement521V1) -> DcmState521V1 {
    DcmState521V1 { x, y }
}

fn zero() -> FieldElement521V1 {
    FieldElement521V1::zero()
}

fn small_value(value: u8) -> FieldElement521V1 {
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn max_minus_one() -> FieldElement521V1 {
    let mut bytes = FIELD_MODULUS_521_V1;
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
