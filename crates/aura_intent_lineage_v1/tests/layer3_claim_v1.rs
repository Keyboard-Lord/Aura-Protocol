// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
mod support;

use aura_intent_lineage_v1::{
    assemble_layer3_proof_claim_v1, AuthorizationEnvelopeFreshnessContextV1,
    AuthorizationEnvelopeV1Decision, AuthorizationEnvelopeV1Error, DcmCommitmentKindV1,
    DcmExecution521ErrorV1, DcmInput521V1, DcmState521V1, FreshnessModeV1, IntentTypeV1,
    Layer3ClaimConstructionInputV1, Layer3ClaimErrorV1,
    LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1, LAYER3_PUBLIC_INPUT_CATEGORY_COUNT_V1,
    LAYER3_WITNESS_CATEGORY_COUNT_V1,
};

use support::{
    canonical_layer3_input, canonical_trace_states_v1, changed_dcm_input, encode_hex, hex32,
    layer3_input_for_dcm_input, CANONICAL_DCM_COMMITMENT_ROOT_HEX, CANONICAL_INTENT_HASH_HEX,
    CANONICAL_LINEAGE_HASH_HEX,
};

#[test]
fn canonical_native_proof_claim_assembly_succeeds() {
    let input = canonical_input();
    let assembly = assemble_layer3_proof_claim_v1(&input).unwrap();

    assert_eq!(
        assembly.public_claim.dcm_commitment_kind,
        DcmCommitmentKindV1::DcmRootCommitmentV1
    );
    assert_eq!(
        assembly.public_claim.intent_type,
        IntentTypeV1::AuraLayer4IntentHashV1
    );
    assert_eq!(assembly.public_claim.controlled_account_id, [0x22; 32]);
    assert_eq!(
        assembly.witness_bundle.layer1_execution_trace,
        canonical_trace_states_v1()
    );
    assert_eq!(
        assembly.witness_bundle.lower_layer_claim.initial_state,
        input.lower_layer_claim.initial_state
    );
    assert_eq!(
        assembly.witness_bundle.lower_layer_claim.final_state,
        input.lower_layer_claim.final_state
    );
    assert_eq!(
        assembly
            .witness_bundle
            .lower_layer_claim
            .trace_state_count(),
        6
    );
    assert_eq!(
        assembly
            .witness_bundle
            .legacy_lower_layer_claim
            .commitment_root,
        hex32(CANONICAL_DCM_COMMITMENT_ROOT_HEX)
    );
    assert_eq!(
        assembly.witness_bundle.lower_layer_claim.legacy_commitment_root,
        hex32(CANONICAL_DCM_COMMITMENT_ROOT_HEX)
    );
    assert_eq!(
        assembly
            .witness_bundle
            .layer2_witness_fields
            .dcm_trace_commitment,
        None
    );
    assert_eq!(
        assembly.metadata.assembly_version,
        LAYER3_PROOF_CLAIM_ASSEMBLY_VERSION_V1
    );
    assert_eq!(
        assembly.metadata.public_input_category_count,
        LAYER3_PUBLIC_INPUT_CATEGORY_COUNT_V1
    );
    assert_eq!(
        assembly.metadata.witness_category_count,
        LAYER3_WITNESS_CATEGORY_COUNT_V1
    );
}

#[test]
fn changing_dcm_input_changes_assembled_claim() {
    let first = canonical_assembly().unwrap();
    let second = assembly_for_input(changed_dcm_input()).unwrap();

    assert_ne!(
        first.public_claim.dcm_commitment_root,
        second.public_claim.dcm_commitment_root
    );
    assert_ne!(
        first.public_claim.lineage_hash,
        second.public_claim.lineage_hash
    );
    assert_ne!(
        first.witness_bundle.layer1_execution_trace,
        second.witness_bundle.layer1_execution_trace
    );
}

#[test]
fn unaccepted_envelope_input_rejects() {
    let mut input = canonical_input();
    input.envelope_decision =
        AuthorizationEnvelopeV1Decision::Reject(AuthorizationEnvelopeV1Error::ModeConflict {
            reason: "synthetic_reject_for_layer3_test",
        });

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(error, Layer3ClaimErrorV1::EnvelopeNotAccepted);
}

#[test]
fn mode_conflict_rejects() {
    let mut input = canonical_input();
    input.lineage.freshness_mode = FreshnessModeV1::LegacyV1ChallengeFreshness;
    if let Some(mut inline) = input.envelope.inline_authorization_lineage_v1 {
        inline.freshness_mode = FreshnessModeV1::LegacyV1ChallengeFreshness;
        input.envelope.inline_authorization_lineage_v1 = Some(inline);
    }

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_use_legacy_freshness_mode",
        }
    );
}

#[test]
fn controlled_account_mismatch_rejects() {
    let mut input = canonical_input();
    input.envelope.controlled_account_id = [0x44; 32];

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "envelope.controlled_account_id",
        }
    );
}

#[test]
fn envelope_validity_bounds_mismatch_rejects() {
    let mut input = canonical_input();
    input
        .envelope
        .envelope_validity_bounds
        .not_after_batch_number = 126;

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "envelope_validity_bounds.not_after_batch_number",
        }
    );
}

#[test]
fn unexpected_native_trace_category_rejects() {
    let mut input = canonical_input();
    input.lineage.lineage_flags = 0x0001;
    input.lineage.dcm_trace_commitment = [0x88; 32];

    let mut inline = input
        .envelope
        .inline_authorization_lineage_v1
        .expect("canonical input must carry inline lineage");
    inline.lineage_flags = 0x0001;
    inline.dcm_trace_commitment = [0x88; 32];
    input.envelope.inline_authorization_lineage_v1 = Some(inline);
    input.envelope.lineage_hash = input.lineage.lineage_hash().unwrap();
    input.envelope_decision = input
        .envelope
        .validate(&AuthorizationEnvelopeFreshnessContextV1::default());

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_carry_dcm_trace_commitment",
        }
    );
}

#[test]
fn inline_lineage_hash_drift_rejects() {
    let mut input = canonical_input();
    let mut inline = input
        .envelope
        .inline_authorization_lineage_v1
        .expect("canonical input must carry inline lineage");
    inline.subject_id = [0x77; 32];
    input.envelope.inline_authorization_lineage_v1 = Some(inline);
    input.envelope.lineage_hash = inline.lineage_hash().unwrap();
    input.envelope_decision = input
        .envelope
        .validate(&AuthorizationEnvelopeFreshnessContextV1::default());

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::HashMismatch {
            field: "envelope.lineage_hash",
            expected: input.lineage.lineage_hash().unwrap(),
            actual: inline.lineage_hash().unwrap(),
        }
    );
}

#[test]
fn inconsistent_dcm_execution_initial_state_rejects() {
    let mut input = canonical_input();
    input.dcm_execution.states[0] = state(4, 7);

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "dcm_execution.states[0]",
        }
    );
}

#[test]
fn inconsistent_dcm_execution_trace_length_rejects() {
    let mut input = canonical_input();
    input.dcm_execution.trace_length = 7;

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::ClaimRelationshipMismatch {
            field: "dcm_execution.trace_length",
        }
    );
}

#[test]
fn inconsistent_dcm_execution_trace_commitment_is_non_authoritative() {
    let mut input = canonical_input();
    input.dcm_execution.trace_commitment = [0x99; 32];

    let assembly = assemble_layer3_proof_claim_v1(&input).unwrap();
    assert_eq!(
        assembly.public_claim.dcm_commitment_root,
        hex32(CANONICAL_DCM_COMMITMENT_ROOT_HEX)
    );
}

#[test]
fn invalid_layer1_parameters_reject_before_assembly() {
    let mut input = canonical_input();
    input.legacy_lower_layer_claim.config.iteration_count = u64::MAX;

    let error = assemble_layer3_proof_claim_v1(&input).unwrap_err();
    assert_eq!(
        error,
        Layer3ClaimErrorV1::Layer1ParametersInvalid(
            DcmExecution521ErrorV1::IterationCountTooLarge { actual: u64::MAX }
        )
    );
}

#[test]
fn pinned_proof_claim_vector_is_stable() {
    let assembly = canonical_assembly().unwrap();

    assert_eq!(
        encode_hex(&assembly.public_claim.dcm_commitment_root),
        CANONICAL_DCM_COMMITMENT_ROOT_HEX
    );
    assert_eq!(
        encode_hex(&assembly.public_claim.intent_hash),
        CANONICAL_INTENT_HASH_HEX
    );
    assert_eq!(
        encode_hex(&assembly.public_claim.lineage_hash),
        CANONICAL_LINEAGE_HASH_HEX
    );
    assert_eq!(assembly.metadata.assembly_version, 1);
    assert_eq!(assembly.metadata.public_input_category_count, 2);
    assert_eq!(assembly.metadata.witness_category_count, 6);
    assert_eq!(assembly.metadata.trace_state_count, 6);
    assert_eq!(assembly.witness_bundle.lineage_preimage.len(), 300);
    assert_eq!(assembly.witness_bundle.intent_hash_preimage.len(), 217);
}

fn canonical_assembly() -> Result<aura_intent_lineage_v1::ProofClaimAssemblyV1, Layer3ClaimErrorV1>
{
    assemble_layer3_proof_claim_v1(&canonical_input())
}

fn assembly_for_input(
    dcm_input: DcmInput521V1,
) -> Result<aura_intent_lineage_v1::ProofClaimAssemblyV1, Layer3ClaimErrorV1> {
    assemble_layer3_proof_claim_v1(&layer3_input_for_dcm_input(dcm_input))
}

fn canonical_input() -> Layer3ClaimConstructionInputV1 {
    canonical_layer3_input()
}

fn state(x: u64, y: u64) -> DcmState521V1 {
    DcmState521V1::from_u64(x, y)
}
