// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1,
    prove_dcm_air_with_mock_proof_v1, verify_dcm_air_mock_proof_v1, DcmAirErrorV1,
    DcmAirMockProverErrorV1, DcmAirMockVerifierErrorV1, DcmAirPublicInputsV1, DcmAirTraceV1,
    DcmConfig521V1, DcmExecution521V1, DcmInput521V1, DcmState521V1, FieldElement521V1,
    DCM_AIR_TRACE_WIDTH_V1, DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, FIELD_ELEMENT_521_BYTE_LEN_V1,
    FIELD_MODULUS_521_V1,
};

const PINNED_BOUND_PUBLIC_INPUT_DIGEST_HEX: &str =
    "abc856fd2a40a40b2b764bf4f427800cc38a3994fbc1900092726761b039f8e3";
const PINNED_BOUND_CONSTRAINT_DIGEST_HEX: &str =
    "e9e2dd333b6778614747e91a6786fed9b17c1a3f361fa332acbb235347a8339a";
const PINNED_BOUND_SESSION_ID_HEX: &str =
    "62afcfab4ff8c8b58cf2ccb9279e2d2614082238d685d805fcb78deae70c5ef0";
const PINNED_PROOF_PLACEHOLDER_DIGEST_HEX: &str =
    "e3baa788dafcba77b8df76284c5c75ec838df09c1429cb4c11446e87dc80ba5b";

#[test]
fn canonical_mock_prove_verify_succeeds() {
    let output =
        prove_dcm_air_with_mock_proof_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();

    assert_eq!(output.verifier_bindings.packaging_version, 1);
    assert_eq!(output.verifier_bindings.trace_width, DCM_AIR_TRACE_WIDTH_V1);
    assert_eq!(output.verifier_bindings.row_count, 3);
    assert_eq!(output.verifier_bindings.checked_transition_count, 2);
    assert_eq!(
        output.verifier_bindings.transition_constraint_count,
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    );
    assert_eq!(
        output.verifier_bindings.public_inputs,
        canonical_public_inputs()
    );

    verify_dcm_air_mock_proof_v1(&output.verifier_bindings, &output.mock_proof_artifact).unwrap();
}

#[test]
fn tampered_verifier_input_rejects() {
    let output =
        prove_dcm_air_with_mock_proof_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let mut tampered_verifier_bindings = output.verifier_bindings;
    tampered_verifier_bindings.public_inputs.final_state = state(small_value(4), small_value(4));

    match verify_dcm_air_mock_proof_v1(&tampered_verifier_bindings, &output.mock_proof_artifact)
        .unwrap_err()
    {
        DcmAirMockVerifierErrorV1::PublicInputDigestMismatch { actual, .. } => {
            assert_eq!(actual, output.mock_proof_artifact.bound_public_input_digest);
        }
        other => panic!("unexpected verifier error: {other:?}"),
    }
}

#[test]
fn tampered_placeholder_proof_artifact_rejects() {
    let output =
        prove_dcm_air_with_mock_proof_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let mut tampered_proof = output.mock_proof_artifact;
    tampered_proof.proof_placeholder_digest = [0x99; 32];

    assert_eq!(
        verify_dcm_air_mock_proof_v1(&output.verifier_bindings, &tampered_proof).unwrap_err(),
        DcmAirMockVerifierErrorV1::ProofPlaceholderDigestMismatch {
            expected: output.mock_proof_artifact.proof_placeholder_digest,
            actual: [0x99; 32],
        }
    );
}

#[test]
fn missing_air_acceptance_prevents_proving() {
    let invalid_trace = DcmAirTraceV1::new(vec![
        state(small_value(1), small_value(1)),
        state(small_value(0), small_value(1)),
        state(small_value(1), small_value(2)),
    ]);

    assert_eq!(
        prove_dcm_air_with_mock_proof_v1(&canonical_public_inputs(), &invalid_trace).unwrap_err(),
        DcmAirMockProverErrorV1::AirEvaluationFailed(DcmAirErrorV1::FirstRowMismatch {
            expected: canonical_public_inputs().initial_state,
            actual: state(small_value(1), small_value(1)),
        })
    );
}

#[test]
fn pinned_mock_proof_vector_is_stable() {
    let output =
        prove_dcm_air_with_mock_proof_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();

    assert_eq!(
        encode_hex(&output.mock_proof_artifact.bound_public_input_digest),
        PINNED_BOUND_PUBLIC_INPUT_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&output.mock_proof_artifact.bound_constraint_digest),
        PINNED_BOUND_CONSTRAINT_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&output.mock_proof_artifact.bound_session_id),
        PINNED_BOUND_SESSION_ID_HEX
    );
    assert_eq!(
        encode_hex(&output.mock_proof_artifact.proof_placeholder_digest),
        PINNED_PROOF_PLACEHOLDER_DIGEST_HEX
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

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
