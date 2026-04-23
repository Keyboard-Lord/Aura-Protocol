// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1,
    evaluate_dcm_air_transition_constraints_v1, evaluate_dcm_air_v1, expected_next_dcm_air_row_v1,
    validate_dcm_air_v1, DcmAirErrorV1, DcmAirEvaluationResultV1, DcmAirEvaluationSummaryV1,
    DcmAirFrameV1, DcmAirPublicInputsV1, DcmAirTraceV1, DcmConfig521V1, DcmExecution521V1,
    DcmInput521V1, DcmState521V1, FieldElement521V1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
};

#[test]
fn canonical_air_evaluation_succeeds() {
    let execution = canonical_execution();
    let trace = DcmAirTraceV1::new(execution.states.clone());
    let public_inputs = canonical_public_inputs();

    assert_eq!(DCM_AIR_TRACE_WIDTH_V1, 2);
    assert_eq!(DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, 2);
    assert_eq!(trace.row_count(), 3);
    assert_eq!(trace.row(0), Some(public_inputs.initial_state));
    assert_eq!(trace.row(1), Some(state(small_value(0), small_value(1))));
    assert_eq!(trace.row(2), Some(public_inputs.final_state));

    assert_eq!(
        evaluate_dcm_air_v1(&public_inputs, &trace),
        DcmAirEvaluationResultV1::Accept(DcmAirEvaluationSummaryV1 {
            row_count: 3,
            checked_transition_count: 2,
            first_row: public_inputs.initial_state,
            final_row: public_inputs.final_state,
        })
    );
}

#[test]
fn trace_step_constraint_accepts_canonical_transition() {
    let trace = DcmAirTraceV1::new(canonical_execution().states);
    let frame = trace.frame(0).unwrap();
    let evaluation = evaluate_dcm_air_transition_constraints_v1(&frame);

    assert_eq!(frame.current_row, state(pinned_x0(), small_value(1)));
    assert_eq!(frame.next_row, expected_next_dcm_air_row_v1(&frame));
    assert!(evaluation.is_satisfied());
    assert_eq!(evaluation.x_transition_residual, FieldElement521V1::zero());
    assert_eq!(evaluation.y_transition_residual, FieldElement521V1::zero());
}

#[test]
fn trace_step_constraint_rejects_modified_x_next() {
    let frame = DcmAirFrameV1 {
        current_row: state(pinned_x0(), small_value(1)),
        next_row: state(small_value(3), small_value(1)),
    };
    let evaluation = evaluate_dcm_air_transition_constraints_v1(&frame);

    assert!(!evaluation.is_satisfied());
    assert_eq!(evaluation.x_transition_residual, small_value(3));
    assert_eq!(evaluation.y_transition_residual, FieldElement521V1::zero());
}

#[test]
fn trace_step_constraint_rejects_modified_y_next() {
    let frame = DcmAirFrameV1 {
        current_row: state(pinned_x0(), small_value(1)),
        next_row: state(small_value(0), small_value(4)),
    };
    let evaluation = evaluate_dcm_air_transition_constraints_v1(&frame);

    assert!(!evaluation.is_satisfied());
    assert_eq!(evaluation.x_transition_residual, FieldElement521V1::zero());
    assert_eq!(evaluation.y_transition_residual, small_value(3));
}

#[test]
fn initial_public_input_must_match_first_row() {
    let public_inputs = canonical_public_inputs();
    let trace = DcmAirTraceV1::new(vec![
        state(small_value(1), small_value(1)),
        state(small_value(0), small_value(1)),
        public_inputs.final_state,
    ]);

    assert_eq!(
        validate_dcm_air_v1(&public_inputs, &trace).unwrap_err(),
        DcmAirErrorV1::FirstRowMismatch {
            expected: public_inputs.initial_state,
            actual: state(small_value(1), small_value(1)),
        }
    );
}

#[test]
fn final_public_input_must_match_last_row() {
    let public_inputs = canonical_public_inputs();
    let trace = DcmAirTraceV1::new(vec![
        public_inputs.initial_state,
        state(small_value(0), small_value(1)),
        state(small_value(1), small_value(3)),
    ]);

    assert_eq!(
        validate_dcm_air_v1(&public_inputs, &trace).unwrap_err(),
        DcmAirErrorV1::FinalRowMismatch {
            expected: public_inputs.final_state,
            actual: state(small_value(1), small_value(3)),
        }
    );
}

#[test]
fn iteration_count_matches_trace_shape() {
    let public_inputs = canonical_public_inputs();
    let trace = DcmAirTraceV1::new(vec![
        public_inputs.initial_state,
        state(small_value(0), small_value(1)),
    ]);

    assert_eq!(
        validate_dcm_air_v1(&public_inputs, &trace).unwrap_err(),
        DcmAirErrorV1::RowCountMismatch {
            expected: 3,
            actual: 2,
        }
    );
}

#[test]
fn empty_trace_rejects() {
    let public_inputs = canonical_public_inputs();
    let trace = DcmAirTraceV1::new(Vec::new());

    assert_eq!(
        validate_dcm_air_v1(&public_inputs, &trace).unwrap_err(),
        DcmAirErrorV1::EmptyTrace
    );
}

#[test]
fn tampered_interior_row_rejects_with_transition_violation() {
    let public_inputs = canonical_public_inputs();
    let trace = DcmAirTraceV1::new(vec![
        public_inputs.initial_state,
        state(small_value(3), small_value(3)),
        public_inputs.final_state,
    ]);

    assert_eq!(
        validate_dcm_air_v1(&public_inputs, &trace).unwrap_err(),
        DcmAirErrorV1::TransitionConstraintViolation {
            row_index: 0,
            expected: state(small_value(0), small_value(1)),
            actual: state(small_value(3), small_value(3)),
            x_transition_residual: small_value(3),
            y_transition_residual: small_value(2),
        }
    );
}

#[test]
fn scalar_legacy_semantics_do_not_reach_active_air() {
    let public_inputs = canonical_public_inputs();
    let trace = DcmAirTraceV1::new(vec![
        public_inputs.initial_state,
        state(small_value(0), small_value(0)),
        public_inputs.final_state,
    ]);

    assert_eq!(
        validate_dcm_air_v1(&public_inputs, &trace).unwrap_err(),
        DcmAirErrorV1::TransitionConstraintViolation {
            row_index: 0,
            expected: state(small_value(0), small_value(1)),
            actual: state(small_value(0), small_value(0)),
            x_transition_residual: FieldElement521V1::zero(),
            y_transition_residual: modulus_minus(1),
        }
    );
}

#[test]
fn canonical_pair_state_trace_is_deterministic() {
    let first = canonical_execution();
    let second = canonical_execution();

    assert_eq!(first.states, second.states);
    assert_eq!(first.final_state, second.final_state);
    assert_eq!(first.trace_commitment, second.trace_commitment);
}

fn canonical_execution() -> DcmExecution521V1 {
    DcmExecution521V1::run(
        &DcmConfig521V1 { iteration_count: 2 },
        &DcmInput521V1 {
            x0: pinned_x0(),
            y0: small_value(1),
        },
    )
    .unwrap()
}

fn canonical_public_inputs() -> DcmAirPublicInputsV1 {
    let config = DcmConfig521V1 { iteration_count: 2 };
    let input = DcmInput521V1 {
        x0: pinned_x0(),
        y0: small_value(1),
    };
    let execution = canonical_execution();
    dcm_air_public_inputs_from_claim_521_v1(&build_dcm_claim_521_v1(&config, &input, &execution))
}

fn state(x: FieldElement521V1, y: FieldElement521V1) -> DcmState521V1 {
    DcmState521V1 { x, y }
}

fn pinned_x0() -> FieldElement521V1 {
    let mut bytes = FIELD_MODULUS_521_V1;
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn small_value(value: u8) -> FieldElement521V1 {
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn modulus_minus(value: u8) -> FieldElement521V1 {
    FieldElement521V1::zero().sub_mod(&small_value(value))
}
