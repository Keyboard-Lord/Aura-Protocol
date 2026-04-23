// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1,
    package_dcm_air_proof_session_v1, DcmAirAdapterErrorV1, DcmAirErrorV1, DcmAirPublicInputsV1,
    DcmAirTraceV1, DcmConfig521V1, DcmExecution521V1, DcmInput521V1, DcmState521V1,
    FieldElement521V1, DCM_AIR_ADAPTER_PACKAGING_VERSION_V1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
};

const PINNED_TRACE_DIGEST_HEX: &str =
    "e80085cfc12ca91ac97ecc2726f1978a7814ff97104dd899a95ad411402e6038";
const PINNED_SESSION_ID_HEX: &str =
    "62afcfab4ff8c8b58cf2ccb9279e2d2614082238d685d805fcb78deae70c5ef0";

#[test]
fn canonical_air_adapter_packaging_succeeds() {
    let trace = canonical_trace();
    let public_inputs = canonical_public_inputs();

    let session = package_dcm_air_proof_session_v1(&public_inputs, &trace).unwrap();

    assert_eq!(session.session_metadata().packaging_version(), 1);
    assert_eq!(
        session.session_metadata().trace_width(),
        DCM_AIR_TRACE_WIDTH_V1
    );
    assert_eq!(session.session_metadata().row_count(), 3);
    assert_eq!(session.session_metadata().checked_transition_count(), 2);
    assert_eq!(
        session.session_metadata().transition_constraint_count(),
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    );
    assert_eq!(
        session.prover_input().packaging_version(),
        DCM_AIR_ADAPTER_PACKAGING_VERSION_V1
    );
    assert_eq!(session.prover_input().trace_width(), DCM_AIR_TRACE_WIDTH_V1);
    assert_eq!(session.prover_input().trace(), &trace);
    assert_eq!(session.prover_input().public_inputs(), &public_inputs);
    assert_eq!(
        session.prover_input().transition_constraint_count(),
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    );
    assert_eq!(session.verifier_input().public_inputs(), &public_inputs);
    assert_eq!(
        session.verifier_input().trace_width(),
        DCM_AIR_TRACE_WIDTH_V1
    );
    assert_eq!(session.verifier_input().row_count(), 3);
    assert_eq!(session.verifier_input().checked_transition_count(), 2);
    assert_eq!(
        session.verifier_input().transition_constraint_count(),
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    );
}

#[test]
fn verifier_input_excludes_full_witness_trace() {
    let trace = canonical_trace();
    let public_inputs = canonical_public_inputs();

    let session = package_dcm_air_proof_session_v1(&public_inputs, &trace).unwrap();

    assert_eq!(
        session.verifier_input().packaging_version(),
        DCM_AIR_ADAPTER_PACKAGING_VERSION_V1
    );
    assert_eq!(
        session.verifier_input().trace_width(),
        DCM_AIR_TRACE_WIDTH_V1
    );
    assert_eq!(session.verifier_input().public_inputs(), &public_inputs);
    assert_eq!(session.verifier_input().row_count(), 3);
    assert_eq!(session.verifier_input().checked_transition_count(), 2);
    assert_eq!(
        session.verifier_input().transition_constraint_count(),
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    );
    assert_eq!(
        session.verifier_input().trace_digest(),
        session.prover_input().trace_digest()
    );
}

#[test]
fn failed_air_evaluation_prevents_packaging() {
    let public_inputs = canonical_public_inputs();
    let invalid_trace = DcmAirTraceV1::new(vec![
        state(small_value(1), small_value(1)),
        state(small_value(0), small_value(1)),
        state(small_value(1), small_value(2)),
    ]);

    assert_eq!(
        package_dcm_air_proof_session_v1(&public_inputs, &invalid_trace).unwrap_err(),
        DcmAirAdapterErrorV1::AirEvaluationFailed(DcmAirErrorV1::FirstRowMismatch {
            expected: canonical_public_inputs().initial_state,
            actual: state(small_value(1), small_value(1)),
        })
    );
}

#[test]
fn changing_air_trace_and_public_inputs_changes_session_identifiers() {
    let first =
        package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        package_dcm_air_proof_session_v1(&alternate_public_inputs(), &alternate_trace()).unwrap();

    assert_ne!(
        first.prover_input().trace_digest(),
        second.prover_input().trace_digest()
    );
    assert_ne!(
        first.verifier_input().trace_digest(),
        second.verifier_input().trace_digest()
    );
    assert_ne!(first.session_id(), second.session_id());
}

#[test]
fn repeated_packaging_is_stable() {
    let first =
        package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();

    assert_eq!(first, second);
}

#[test]
fn tampered_public_inputs_after_air_evaluation_prevents_packaging() {
    let trace = canonical_trace();
    let mut tampered_public_inputs = canonical_public_inputs();
    tampered_public_inputs.final_state = state(small_value(4), small_value(4));

    assert_eq!(
        package_dcm_air_proof_session_v1(&tampered_public_inputs, &trace).unwrap_err(),
        DcmAirAdapterErrorV1::AirEvaluationFailed(DcmAirErrorV1::FinalRowMismatch {
            expected: state(small_value(4), small_value(4)),
            actual: state(small_value(1), small_value(2)),
        })
    );
}

#[test]
fn empty_trace_prevents_packaging() {
    let public_inputs = canonical_public_inputs();
    let empty_trace = DcmAirTraceV1::new(Vec::new());

    assert_eq!(
        package_dcm_air_proof_session_v1(&public_inputs, &empty_trace).unwrap_err(),
        DcmAirAdapterErrorV1::AirEvaluationFailed(DcmAirErrorV1::EmptyTrace)
    );
}

#[test]
fn pinned_air_adapter_vector_is_stable() {
    let session =
        package_dcm_air_proof_session_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();

    assert_eq!(
        encode_hex(*session.prover_input().trace_digest()),
        PINNED_TRACE_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(*session.session_id().as_bytes()),
        PINNED_SESSION_ID_HEX
    );
}

fn canonical_trace() -> DcmAirTraceV1 {
    DcmAirTraceV1::new(canonical_execution().states)
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

fn alternate_trace() -> DcmAirTraceV1 {
    DcmAirTraceV1::new(
        DcmExecution521V1::run(
            &DcmConfig521V1 { iteration_count: 3 },
            &DcmInput521V1 {
                x0: zero(),
                y0: small_value(1),
            },
        )
        .unwrap()
        .states,
    )
}

fn alternate_public_inputs() -> DcmAirPublicInputsV1 {
    let config = DcmConfig521V1 { iteration_count: 3 };
    let input = DcmInput521V1 {
        x0: zero(),
        y0: small_value(1),
    };
    let execution = DcmExecution521V1::run(&config, &input).unwrap();
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

fn zero() -> FieldElement521V1 {
    FieldElement521V1::zero()
}

fn small_value(value: u8) -> FieldElement521V1 {
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn encode_hex(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
