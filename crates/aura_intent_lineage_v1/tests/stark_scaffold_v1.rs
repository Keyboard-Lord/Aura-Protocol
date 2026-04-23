// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1,
    prove_dcm_air_stark_scaffold_v1, verify_dcm_air_stark_scaffold_v1, DcmAirPublicInputsV1,
    DcmAirStarkVerifierErrorV1, DcmAirTraceV1, DcmConfig521V1, DcmExecution521V1, DcmInput521V1,
    DcmState521V1, FieldElement521V1, DCM_AIR_TRACE_WIDTH_V1,
    DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1, FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
};

const PINNED_TRACE_COMMITMENT_ROOT_HEX: &str =
    "5d549584d1dee0cf3780d6d2fc0e224c373aa45f91d5ad041884713a64da1c1b";
const PINNED_PUBLIC_INPUT_DIGEST_HEX: &str =
    "4ab7553e623dbd33bf531179e894cb3013338f1faa571e4fb50d88e16b86b961";
const PINNED_TRANSCRIPT_DIGEST_HEX: &str =
    "46b2f19f6e957da77afa5bea51fd8bfe0c74602fcfeeba6f40d70e7b8de07f75";
const PINNED_QUERY_CHALLENGE_DIGEST_HEX: &str =
    "8f8d234b9a886354d305d23acddef8cdf4f4a2c3d93a81e1f5ded24d67b78070";
const PINNED_PROOF_ARTIFACT_DIGEST_HEX: &str =
    "b5037d53f4cab0c3e84430539b2bdb3579e4d1662af34aad0a0473f1dda6086e";

#[test]
fn canonical_recurrence_only_stark_scaffold_succeeds() {
    let proof =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let acceptance = verify_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &proof).unwrap();

    assert_eq!(proof.proof_version, 1);
    assert_eq!(proof.opening_metadata.trace_row_count, 3);
    assert_eq!(proof.opening_metadata.transition_query_count, 1);
    assert_eq!(proof.opening_metadata.trace_width, DCM_AIR_TRACE_WIDTH_V1);
    assert_eq!(
        proof.opening_metadata.transition_constraint_count,
        DCM_AIR_TRANSITION_CONSTRAINT_COUNT_V1
    );
    assert_eq!(
        acceptance.verified_trace_commitment_root,
        proof.trace_commitment_root
    );
    assert_eq!(acceptance.verified_transition_query_count, 1);
    assert_eq!(
        acceptance.verified_proof_artifact_digest,
        proof.proof_artifact_digest
    );
}

#[test]
fn tampered_opened_row_rejects() {
    let mut proof =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    proof
        .queried_transition_openings
        .as_mut()
        .unwrap()
        .next_row_opening
        .row_value = state(small_value(6), small_value(6));

    assert!(matches!(
        verify_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &proof).unwrap_err(),
        DcmAirStarkVerifierErrorV1::CommitmentMismatch { .. }
    ));
}

#[test]
fn tampered_trace_commitment_rejects() {
    let mut proof =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    proof.trace_commitment_root = [0x44; 32];

    assert_eq!(
        verify_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &proof).unwrap_err(),
        DcmAirStarkVerifierErrorV1::TranscriptMismatch {
            field: "transcript_digest",
        }
    );
}

#[test]
fn tampered_public_input_digest_rejects() {
    let mut proof =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    proof.public_input_digest = [0x55; 32];

    assert!(matches!(
        verify_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &proof).unwrap_err(),
        DcmAirStarkVerifierErrorV1::PublicInputBindingMismatch { .. }
    ));
}

#[test]
fn changing_trace_changes_proof_artifact_digest() {
    let first =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        prove_dcm_air_stark_scaffold_v1(&alternate_public_inputs(), &alternate_trace()).unwrap();

    assert_ne!(first.trace_commitment_root, second.trace_commitment_root);
    assert_ne!(first.transcript_digest, second.transcript_digest);
    assert_ne!(first.proof_artifact_digest, second.proof_artifact_digest);
}

#[test]
fn proof_material_changes_when_x_column_changes() {
    let first =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        prove_dcm_air_stark_scaffold_v1(&x_changed_public_inputs(), &x_changed_trace()).unwrap();

    assert_ne!(first.trace_commitment_root, second.trace_commitment_root);
    assert_ne!(first.public_input_digest, second.public_input_digest);
    assert_ne!(first.proof_artifact_digest, second.proof_artifact_digest);
}

#[test]
fn proof_material_changes_when_y_column_changes() {
    let first =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        prove_dcm_air_stark_scaffold_v1(&y_changed_public_inputs(), &y_changed_trace()).unwrap();

    assert_ne!(first.trace_commitment_root, second.trace_commitment_root);
    assert_ne!(first.public_input_digest, second.public_input_digest);
    assert_ne!(first.proof_artifact_digest, second.proof_artifact_digest);
}

#[test]
fn changing_iteration_count_changes_final_state_and_bindings() {
    let first =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        prove_dcm_air_stark_scaffold_v1(&alternate_public_inputs(), &alternate_trace()).unwrap();

    assert_ne!(
        canonical_public_inputs().final_state,
        alternate_public_inputs().final_state
    );
    assert_ne!(
        canonical_public_inputs().iteration_count,
        alternate_public_inputs().iteration_count
    );
    assert_ne!(first.public_input_digest, second.public_input_digest);
    assert_ne!(first.proof_artifact_digest, second.proof_artifact_digest);
}

#[test]
fn verifier_rejects_tampered_pair_state_claims() {
    let proof =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let mut tampered_public_inputs = canonical_public_inputs();
    tampered_public_inputs.final_state = state(small_value(4), small_value(4));

    assert!(matches!(
        verify_dcm_air_stark_scaffold_v1(&tampered_public_inputs, &proof).unwrap_err(),
        DcmAirStarkVerifierErrorV1::PublicInputBindingMismatch { .. }
    ));
}

#[test]
fn pinned_stark_scaffold_vector_is_stable() {
    let proof =
        prove_dcm_air_stark_scaffold_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();

    assert_eq!(
        encode_hex(&proof.trace_commitment_root),
        PINNED_TRACE_COMMITMENT_ROOT_HEX
    );
    assert_eq!(
        encode_hex(&proof.public_input_digest),
        PINNED_PUBLIC_INPUT_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&proof.transcript_digest),
        PINNED_TRANSCRIPT_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&proof.query_challenge_digest),
        PINNED_QUERY_CHALLENGE_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&proof.proof_artifact_digest),
        PINNED_PROOF_ARTIFACT_DIGEST_HEX
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

fn x_changed_trace() -> DcmAirTraceV1 {
    DcmAirTraceV1::new(
        DcmExecution521V1::run(
            &DcmConfig521V1 { iteration_count: 2 },
            &DcmInput521V1 {
                x0: zero(),
                y0: small_value(1),
            },
        )
        .unwrap()
        .states,
    )
}

fn x_changed_public_inputs() -> DcmAirPublicInputsV1 {
    let config = DcmConfig521V1 { iteration_count: 2 };
    let input = DcmInput521V1 {
        x0: zero(),
        y0: small_value(1),
    };
    let execution = DcmExecution521V1::run(&config, &input).unwrap();
    dcm_air_public_inputs_from_claim_521_v1(&build_dcm_claim_521_v1(&config, &input, &execution))
}

fn y_changed_trace() -> DcmAirTraceV1 {
    DcmAirTraceV1::new(
        DcmExecution521V1::run(
            &DcmConfig521V1 { iteration_count: 2 },
            &DcmInput521V1 {
                x0: pinned_x0(),
                y0: small_value(2),
            },
        )
        .unwrap()
        .states,
    )
}

fn y_changed_public_inputs() -> DcmAirPublicInputsV1 {
    let config = DcmConfig521V1 { iteration_count: 2 };
    let input = DcmInput521V1 {
        x0: pinned_x0(),
        y0: small_value(2),
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

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
