// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
mod support;

use aura_intent_lineage_v1::{
    construct_proof_transcript_from_assembly_v1, construct_proof_transcript_v1, DcmInput521V1,
    DcmState521V1, Layer3ClaimConstructionInputV1, ProofTranscriptErrorV1,
    RecurrenceConstraintErrorV1, PROOF_TRANSCRIPT_VERSION_V1,
};

use support::{
    canonical_layer3_assembly, canonical_layer3_input, changed_dcm_input, encode_hex, hex32,
    layer3_assembly_for_dcm_input, layer3_input_for_dcm_input, CANONICAL_DCM_COMMITMENT_ROOT_HEX,
    CANONICAL_INTENT_HASH_HEX, CANONICAL_LINEAGE_HASH_HEX,
    CANONICAL_TRANSCRIPT_CONSTRAINT_SUMMARY_DIGEST_HEX, CANONICAL_TRANSCRIPT_DIGEST_HEX,
    CANONICAL_TRANSCRIPT_PUBLIC_CLAIM_DIGEST_HEX, CANONICAL_TRANSCRIPT_WITNESS_DIGEST_HEX,
};

#[test]
fn canonical_transcript_construction_succeeds() {
    let input = canonical_input();
    let transcript = construct_proof_transcript_v1(&input).unwrap();

    assert_eq!(transcript.transcript_version, PROOF_TRANSCRIPT_VERSION_V1);
    assert_eq!(
        transcript.lower_layer_claim.initial_state,
        input.lower_layer_claim.initial_state
    );
    assert_eq!(
        transcript.lower_layer_claim.final_state,
        input.lower_layer_claim.final_state
    );
    assert_eq!(transcript.lower_layer_claim.trace_state_count(), 6);
    assert_eq!(
        transcript.lower_layer_public_inputs,
        input.lower_layer_public_inputs
    );
    assert_eq!(transcript.checked_transition_count, 5);
    assert_eq!(transcript.trace_state_count, 6);
    assert_eq!(transcript.intent_hash, hex32(CANONICAL_INTENT_HASH_HEX));
    assert_eq!(transcript.lineage_hash, hex32(CANONICAL_LINEAGE_HASH_HEX));
    assert_eq!(
        transcript.legacy_dcm_commitment_root,
        hex32(CANONICAL_DCM_COMMITMENT_ROOT_HEX)
    );
}

#[test]
fn changing_dcm_input_changes_transcript_digest() {
    let first = construct_proof_transcript_v1(&canonical_input()).unwrap();
    let second = construct_proof_transcript_v1(&input_for_dcm_input(changed_dcm_input())).unwrap();

    assert_ne!(first.public_claim_digest, second.public_claim_digest);
    assert_ne!(first.witness_digest, second.witness_digest);
    assert_ne!(
        first.constraint_summary_digest,
        second.constraint_summary_digest
    );
    assert_ne!(first.transcript_digest, second.transcript_digest);
}

#[test]
fn changing_witness_trace_changes_witness_digest_and_transcript_digest() {
    let first_assembly = canonical_assembly();
    let second_assembly = assembly_for_dcm_input(changed_dcm_input());

    assert_ne!(
        first_assembly.witness_bundle.layer1_execution_trace,
        second_assembly.witness_bundle.layer1_execution_trace
    );

    let first = construct_proof_transcript_from_assembly_v1(&first_assembly).unwrap();
    let second = construct_proof_transcript_from_assembly_v1(&second_assembly).unwrap();

    assert_ne!(first.witness_digest, second.witness_digest);
    assert_ne!(first.transcript_digest, second.transcript_digest);
}

#[test]
fn failed_constraint_validation_prevents_transcript_construction() {
    let mut assembly = canonical_assembly();
    assembly.witness_bundle.layer1_execution_trace[2] = state(70, 44);

    let error = construct_proof_transcript_from_assembly_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        ProofTranscriptErrorV1::ConstraintValidationFailed(
            RecurrenceConstraintErrorV1::RecurrenceViolation {
                index: 1,
                expected: state(27, 44),
                actual: state(70, 44),
            }
        )
    );
}

#[test]
fn tampered_initial_state_prevents_transcript_construction() {
    let mut assembly = canonical_assembly();
    assembly.witness_bundle.layer1_execution_trace[0] = state(4, 7);

    let error = construct_proof_transcript_from_assembly_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        ProofTranscriptErrorV1::ConstraintValidationFailed(
            RecurrenceConstraintErrorV1::InitialStateMismatch {
                expected: state(3, 7),
                actual: state(4, 7),
            }
        )
    );
}

#[test]
fn tampered_witness_trace_commitment_prevents_transcript_construction() {
    let mut assembly = canonical_assembly();
    assembly
        .witness_bundle
        .layer2_witness_fields
        .dcm_trace_commitment = Some([0x99; 32]);

    let error = construct_proof_transcript_from_assembly_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        ProofTranscriptErrorV1::ConstraintValidationFailed(
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "witness_bundle.layer2_witness_fields.dcm_trace_commitment",
            }
        )
    );
}

#[test]
fn pinned_transcript_vector_is_stable() {
    let transcript = construct_proof_transcript_v1(&canonical_input()).unwrap();

    assert_eq!(
        encode_hex(&transcript.public_claim_digest),
        CANONICAL_TRANSCRIPT_PUBLIC_CLAIM_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&transcript.witness_digest),
        CANONICAL_TRANSCRIPT_WITNESS_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&transcript.constraint_summary_digest),
        CANONICAL_TRANSCRIPT_CONSTRAINT_SUMMARY_DIGEST_HEX
    );
    assert_eq!(
        encode_hex(&transcript.transcript_digest),
        CANONICAL_TRANSCRIPT_DIGEST_HEX
    );
}

fn canonical_assembly() -> aura_intent_lineage_v1::ProofClaimAssemblyV1 {
    canonical_layer3_assembly()
}

fn assembly_for_dcm_input(
    dcm_input: DcmInput521V1,
) -> aura_intent_lineage_v1::ProofClaimAssemblyV1 {
    layer3_assembly_for_dcm_input(dcm_input)
}

fn canonical_input() -> Layer3ClaimConstructionInputV1 {
    canonical_layer3_input()
}

fn input_for_dcm_input(dcm_input: DcmInput521V1) -> Layer3ClaimConstructionInputV1 {
    layer3_input_for_dcm_input(dcm_input)
}

fn state(x: u64, y: u64) -> DcmState521V1 {
    DcmState521V1::from_u64(x, y)
}
