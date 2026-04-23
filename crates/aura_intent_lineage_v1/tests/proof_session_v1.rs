// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
mod support;

use aura_intent_lineage_v1::{
    accept_lower_layer_mock_session_v1, accept_lower_layer_real_stark_session_v1,
    dcm_air_public_inputs_from_claim_521_v1, package_proof_session_from_assembly_v1,
    package_proof_session_v1, prove_dcm_air_with_mock_proof_v1,
    prove_lower_layer_real_stark_session_v1, DcmAirTraceV1, DcmState521V1,
    FieldElement521V1, Layer3ClaimConstructionInputV1, LowerLayerRealStarkAcceptanceErrorV1,
    LowerLayerRealStarkProofSessionV1, ProofSessionAcceptanceErrorV1, ProofSessionErrorV1,
    ProofSessionPackageV1, ProofTranscriptErrorV1, ProverInputBundleV1,
    RecurrenceConstraintErrorV1, StormClaim521V1, StormState521V1, VerifierInputBundleV1,
    LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1, PROOF_SESSION_PACKAGING_VERSION_V1,
    PROOF_TRANSCRIPT_VERSION_V1,
};

use support::{
    canonical_layer3_assembly, canonical_layer3_input, canonical_trace_states_v1,
    changed_dcm_input, encode_hex, hex32, layer3_input_for_dcm_input, CANONICAL_INTENT_HASH_HEX,
    CANONICAL_LINEAGE_HASH_HEX, CANONICAL_PROOF_SESSION_ID_HEX,
};

#[test]
fn canonical_proof_session_packaging_succeeds() {
    let package = package_proof_session_v1(&canonical_input()).unwrap();

    assert_eq!(
        package.session_metadata.packaging_version,
        PROOF_SESSION_PACKAGING_VERSION_V1
    );
    assert_eq!(
        package.session_metadata.transcript_version,
        PROOF_TRANSCRIPT_VERSION_V1
    );
    assert_eq!(
        package.session_metadata.assembly_version,
        LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1
    );
    assert_eq!(package.session_metadata.checked_transition_count, 5);
    assert_eq!(package.session_metadata.trace_state_count, 6);
    assert_ne!(package.session_id.bytes, [0u8; 32]);
    assert_eq!(
        package.prover_input_bundle.transcript.transcript_digest,
        package.verifier_input_bundle.transcript.transcript_digest
    );
    assert_eq!(
        package.prover_input_bundle.constraint_summary.lineage_hash,
        hex32(CANONICAL_LINEAGE_HASH_HEX)
    );
    assert_eq!(
        package.verifier_input_bundle.public_claim.intent_hash,
        hex32(CANONICAL_INTENT_HASH_HEX)
    );
}

#[test]
fn changing_transcript_input_changes_session_id() {
    let first = package_proof_session_v1(&canonical_input()).unwrap();
    let second = package_proof_session_v1(&input_for_dcm_input(changed_dcm_input())).unwrap();

    assert_ne!(first.session_id, second.session_id);
    assert_ne!(
        first.prover_input_bundle.transcript.transcript_digest,
        second.prover_input_bundle.transcript.transcript_digest
    );
}

#[test]
fn verifier_bundle_excludes_witness_only_data() {
    let package = package_proof_session_v1(&canonical_input()).unwrap();

    // Exact destructuring here intentionally pins the verifier bundle surface to the current
    // public-only fields. Adding witness-only fields will fail this test at compile time until
    // the surface change is made deliberately.
    let ProverInputBundleV1 {
        packaging_version: prover_packaging_version,
        transcript: prover_transcript,
        witness_bundle,
        constraint_summary,
    } = package.prover_input_bundle;
    let VerifierInputBundleV1 {
        packaging_version: verifier_packaging_version,
        transcript: verifier_transcript,
        lower_layer_claim,
        lower_layer_public_inputs,
        legacy_lower_layer_claim,
        public_claim,
        constraint_summary_digest,
        ..
    } = package.verifier_input_bundle;

    assert_eq!(prover_packaging_version, PROOF_SESSION_PACKAGING_VERSION_V1);
    assert_eq!(
        verifier_packaging_version,
        PROOF_SESSION_PACKAGING_VERSION_V1
    );
    assert_eq!(
        witness_bundle.layer1_execution_trace,
        canonical_trace_states_v1()
    );
    assert_eq!(constraint_summary.trace_state_count, 6);
    assert_eq!(lower_layer_claim, witness_bundle.lower_layer_claim);
    assert_eq!(lower_layer_public_inputs, witness_bundle.lower_layer_public_inputs);
    assert_eq!(
        legacy_lower_layer_claim,
        witness_bundle.legacy_lower_layer_claim
    );
    assert_eq!(public_claim.lineage_hash, verifier_transcript.lineage_hash);
    assert_eq!(
        constraint_summary_digest,
        verifier_transcript.constraint_summary_digest
    );
    assert_eq!(
        prover_transcript.transcript_digest,
        verifier_transcript.transcript_digest
    );
}

#[test]
fn failed_transcript_construction_prevents_packaging() {
    let mut assembly = canonical_layer3_assembly();
    assembly.witness_bundle.layer1_execution_trace[2] = state(70, 44);

    let error = package_proof_session_from_assembly_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        ProofSessionErrorV1::TranscriptConstructionFailed(
            ProofTranscriptErrorV1::ConstraintValidationFailed(
                RecurrenceConstraintErrorV1::RecurrenceViolation {
                    index: 1,
                    expected: state(27, 44),
                    actual: state(70, 44),
                }
            )
        )
    );
}

#[test]
fn execution_trace_air_pipeline_accepts_canonical_case() {
    let (package, mock_output) = canonical_mock_session();

    let acceptance = accept_lower_layer_mock_session_v1(
        &package,
        &mock_output.verifier_bindings,
        &mock_output.mock_proof_artifact,
    )
    .unwrap();

    assert_eq!(acceptance.session_id, *package.session_id.as_bytes());
    assert_eq!(
        acceptance.lower_layer_claim,
        package.verifier_input_bundle.lower_layer_claim
    );
    assert_eq!(
        acceptance.transcript_digest,
        package.verifier_input_bundle.transcript.transcript_digest
    );
    assert_eq!(
        acceptance.legacy_dcm_commitment_root,
        package
            .verifier_input_bundle
            .legacy_lower_layer_claim
            .commitment_root
    );
}

#[test]
fn changing_initial_x_breaks_end_to_end_acceptance() {
    let (mut package, mock_output) = canonical_mock_session();
    mutate_lower_layer_claim_everywhere(&mut package, |claim| {
        claim.initial_state = storm_state(4, 7);
    });

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.lower_layer_claim_digest",
        }
    );
}

#[test]
fn changing_initial_y_breaks_end_to_end_acceptance() {
    let (mut package, mock_output) = canonical_mock_session();
    mutate_lower_layer_claim_everywhere(&mut package, |claim| {
        claim.initial_state = storm_state(3, 8);
    });

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.lower_layer_claim_digest",
        }
    );
}

#[test]
fn changing_final_x_breaks_end_to_end_acceptance() {
    let (mut package, mock_output) = canonical_mock_session();
    mutate_lower_layer_claim_everywhere(&mut package, |claim| {
        claim.final_state = storm_state(488, 788);
    });

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.lower_layer_claim_digest",
        }
    );
}

#[test]
fn changing_final_y_breaks_end_to_end_acceptance() {
    let (mut package, mock_output) = canonical_mock_session();
    mutate_lower_layer_claim_everywhere(&mut package, |claim| {
        claim.final_state = storm_state(487, 789);
    });

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.lower_layer_claim_digest",
        }
    );
}

#[test]
fn changing_iteration_count_breaks_end_to_end_acceptance() {
    let (mut package, mock_output) = canonical_mock_session();
    mutate_lower_layer_claim_everywhere(&mut package, |claim| {
        claim.iteration_count = 6;
    });

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.lower_layer_claim_digest",
        }
    );
}

#[test]
fn verifier_facing_claim_rejects_tampered_commitment_material() {
    let (mut package, mock_output) = canonical_mock_session();
    package
        .verifier_input_bundle
        .public_claim
        .dcm_commitment_root = [0x99; 32];

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.public_claim.dcm_commitment_root",
        }
    );
}

#[test]
fn settlement_or_local_acceptance_rejects_tampered_lower_layer_claim() {
    let (mut package, mock_output) = canonical_mock_session();
    package
        .verifier_input_bundle
        .lower_layer_claim
        .trace_root = [0x55; 32];

    assert_eq!(
        accept_lower_layer_mock_session_v1(
            &package,
            &mock_output.verifier_bindings,
            &mock_output.mock_proof_artifact
        )
        .unwrap_err(),
        ProofSessionAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.lower_layer_claim",
        }
    );
}

#[test]
fn pinned_session_id_vector_is_stable() {
    let package = package_proof_session_v1(&canonical_input()).unwrap();

    assert_eq!(
        encode_hex(package.session_id.as_bytes()),
        CANONICAL_PROOF_SESSION_ID_HEX
    );
}

#[test]
fn local_acceptance_rejects_claim_proof_mismatch() {
    let mut session = canonical_real_stark_session();
    mutate_lower_layer_claim_everywhere(&mut session.session_package, |claim| {
        claim.final_state = storm_state(999, 1617);
    });

    assert_eq!(
        accept_lower_layer_real_stark_session_v1(&session).unwrap_err(),
        LowerLayerRealStarkAcceptanceErrorV1::ClaimRelationshipMismatch {
            field: "verifier_input_bundle.transcript.lower_layer_claim_digest",
        }
    );
}

#[test]
fn staged_mock_path_is_explicitly_separate_if_retained() {
    let (mock_package, mock_output) = canonical_mock_session();
    let real_session = canonical_real_stark_session();
    let mock_acceptance = accept_lower_layer_mock_session_v1(
        &mock_package,
        &mock_output.verifier_bindings,
        &mock_output.mock_proof_artifact,
    )
    .unwrap();
    let real_acceptance = accept_lower_layer_real_stark_session_v1(&real_session).unwrap();

    assert_eq!(
        mock_acceptance.lower_layer_claim,
        real_acceptance.lower_layer_claim
    );
    assert_ne!(mock_acceptance.session_id, real_acceptance.session_id);
    assert_ne!(
        mock_acceptance.transcript_digest,
        real_acceptance.transcript_digest
    );
}

fn canonical_input() -> Layer3ClaimConstructionInputV1 {
    canonical_layer3_input()
}

fn input_for_dcm_input(
    dcm_input: aura_intent_lineage_v1::DcmInput521V1,
) -> Layer3ClaimConstructionInputV1 {
    layer3_input_for_dcm_input(dcm_input)
}

fn canonical_mock_session() -> (
    ProofSessionPackageV1,
    aura_intent_lineage_v1::DcmAirMockProverOutputV1,
) {
    let package = package_proof_session_v1(&canonical_input()).unwrap();
    let public_inputs =
        dcm_air_public_inputs_from_claim_521_v1(
            &package.verifier_input_bundle.legacy_lower_layer_claim,
        );
    let trace = DcmAirTraceV1::new(
        package
            .prover_input_bundle
            .witness_bundle
            .layer1_execution_trace
            .clone(),
    );
    let mock_output = prove_dcm_air_with_mock_proof_v1(&public_inputs, &trace).unwrap();
    (package, mock_output)
}

fn canonical_real_stark_session() -> LowerLayerRealStarkProofSessionV1 {
    prove_lower_layer_real_stark_session_v1(&canonical_input()).unwrap()
}

fn mutate_lower_layer_claim_everywhere<F>(package: &mut ProofSessionPackageV1, mut mutate: F)
where
    F: FnMut(&mut StormClaim521V1),
{
    mutate(&mut package.verifier_input_bundle.lower_layer_claim);
    mutate(&mut package.verifier_input_bundle.transcript.lower_layer_claim);
    mutate(&mut package.prover_input_bundle.witness_bundle.lower_layer_claim);
    mutate(&mut package.prover_input_bundle.transcript.lower_layer_claim);
}

fn state(x: u64, y: u64) -> DcmState521V1 {
    DcmState521V1::from_u64(x, y)
}

fn storm_state(x: u64, y: u64) -> StormState521V1 {
    StormState521V1 {
        x: FieldElement521V1::from_u64(x),
        y: FieldElement521V1::from_u64(y),
    }
}
