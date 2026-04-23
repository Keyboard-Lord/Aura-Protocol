// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
mod support;

use aura_intent_lineage_v1::{
    evaluate_recurrence_constraints_v1, validate_recurrence_constraints_v1, DcmCommitmentKindV1,
    DcmExecution521ErrorV1, DcmState521V1, FreshnessModeV1, IntentTypeV1, ProofClaimAssemblyV1,
    RecurrenceConstraintDecisionV1, RecurrenceConstraintErrorV1, RecurrenceConstraintSummaryV1,
    SubjectBindingTypeV1, LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH,
};

use support::{
    canonical_layer3_assembly, encode_hex, hex32, CANONICAL_DCM_COMMITMENT_ROOT_HEX,
    CANONICAL_DCM_TRACE_COMMITMENT_HEX, CANONICAL_INTENT_HASH_HEX, CANONICAL_LINEAGE_HASH_HEX,
};

#[test]
fn canonical_recurrence_constraints_succeed() {
    let assembly = canonical_assembly();

    let decision = evaluate_recurrence_constraints_v1(&assembly);
    assert_eq!(
        decision,
        RecurrenceConstraintDecisionV1::Accept(RecurrenceConstraintSummaryV1 {
            checked_transition_count: 5,
            trace_state_count: 6,
            recomputed_trace_commitment: hex32(CANONICAL_DCM_TRACE_COMMITMENT_HEX),
            recomputed_dcm_commitment_root: hex32(CANONICAL_DCM_COMMITMENT_ROOT_HEX),
            intent_hash: hex32(CANONICAL_INTENT_HASH_HEX),
            lineage_hash: hex32(CANONICAL_LINEAGE_HASH_HEX),
        })
    );
}

#[test]
fn tampered_trace_element_rejects() {
    let mut assembly = canonical_assembly();
    assembly.witness_bundle.layer1_execution_trace[2] = state(70, 44);

    let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        RecurrenceConstraintErrorV1::RecurrenceViolation {
            index: 1,
            expected: state(27, 44),
            actual: state(70, 44),
        }
    );
}

#[test]
fn tampered_initial_state_rejects() {
    let mut assembly = canonical_assembly();
    assembly.witness_bundle.layer1_execution_trace[0] = state(4, 7);

    let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        RecurrenceConstraintErrorV1::InitialStateMismatch {
            expected: state(3, 7),
            actual: state(4, 7),
        }
    );
}

#[test]
fn tampered_final_state_rejects() {
    let mut assembly = canonical_assembly();
    assembly.witness_bundle.legacy_lower_layer_claim.final_state = state(92, 12);

    let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        RecurrenceConstraintErrorV1::FinalStateMismatch {
            expected: state(487, 788),
            actual: state(92, 12),
        }
    );
}

#[test]
fn invalid_layer1_parameters_reject_before_recurrence_math() {
    let mut assembly = canonical_assembly();
    assembly
        .witness_bundle
        .legacy_lower_layer_claim
        .config
        .iteration_count = u64::MAX;

    let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        RecurrenceConstraintErrorV1::Layer1ParametersInvalid(
            DcmExecution521ErrorV1::IterationCountTooLarge { actual: u64::MAX }
        )
    );
}

#[test]
fn tampered_trace_commitment_rejects() {
    let mut assembly = canonical_assembly();
    assembly
        .witness_bundle
        .layer2_witness_fields
        .dcm_trace_commitment = Some([0x99; 32]);

    let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
            field: "witness_bundle.layer2_witness_fields.dcm_trace_commitment",
        }
    );
}

#[test]
fn public_claim_tampering_rejects() {
    let cases: [(
        &str,
        fn(&mut ProofClaimAssemblyV1),
        RecurrenceConstraintErrorV1,
    ); 9] = [
        (
            "wrong_dcm_commitment_root",
            tamper_public_claim_dcm_commitment_root,
            RecurrenceConstraintErrorV1::CommitmentRootMismatch {
                expected: hex32(CANONICAL_DCM_COMMITMENT_ROOT_HEX),
                actual: [0x99; 32],
            },
        ),
        (
            "wrong_lineage_flags",
            tamper_public_claim_lineage_flags,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.lineage_flags",
            },
        ),
        (
            "wrong_subject_binding_type",
            tamper_public_claim_subject_binding_type,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.subject_binding_type",
            },
        ),
        (
            "wrong_subject_id",
            tamper_public_claim_subject_id,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.subject_id",
            },
        ),
        (
            "wrong_intent_hash",
            tamper_public_claim_intent_hash,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.intent_hash",
            },
        ),
        (
            "wrong_freshness_nonce",
            tamper_public_claim_freshness_nonce,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.freshness_nonce",
            },
        ),
        (
            "wrong_freshness_reference",
            tamper_public_claim_freshness_reference,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.freshness_reference",
            },
        ),
        (
            "wrong_controlled_account_id",
            tamper_public_claim_controlled_account_id,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.controlled_account_id",
            },
        ),
        (
            "wrong_envelope_validity_bounds",
            tamper_public_claim_envelope_validity_bounds,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "public_claim.envelope_validity_bounds.not_after_batch_number",
            },
        ),
    ];

    for (name, tamper, expected) in cases {
        let mut assembly = canonical_assembly();
        tamper(&mut assembly);
        let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
        assert_eq!(error, expected, "{name}");
    }
}

#[test]
fn public_claim_mode_conflicts_reject() {
    let cases: [(
        &str,
        fn(&mut ProofClaimAssemblyV1),
        RecurrenceConstraintErrorV1,
    ); 4] = [
        (
            "wrong_dcm_commitment_kind",
            tamper_public_claim_dcm_commitment_kind,
            RecurrenceConstraintErrorV1::ModeConflict {
                reason: "legacy_dcm_commitment_kind_not_allowed",
            },
        ),
        (
            "wrong_intent_type",
            tamper_public_claim_intent_type,
            RecurrenceConstraintErrorV1::ModeConflict {
                reason: "legacy_or_non_native_intent_type_not_allowed",
            },
        ),
        (
            "wrong_freshness_mode",
            tamper_public_claim_freshness_mode,
            RecurrenceConstraintErrorV1::ModeConflict {
                reason: "legacy_freshness_mode_not_allowed",
            },
        ),
        (
            "legacy_compatibility_lineage_flag",
            tamper_public_claim_legacy_compatibility_flag,
            RecurrenceConstraintErrorV1::ModeConflict {
                reason: "legacy_compatibility_fields_not_allowed",
            },
        ),
    ];

    for (name, tamper, expected) in cases {
        let mut assembly = canonical_assembly();
        tamper(&mut assembly);
        let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
        assert_eq!(error, expected, "{name}");
    }
}

#[test]
fn witness_and_metadata_tampering_rejects() {
    let cases: [(
        &str,
        fn(&mut ProofClaimAssemblyV1),
        RecurrenceConstraintErrorV1,
    ); 4] = [
        (
            "unexpected_dcm_trace_commitment",
            tamper_unexpected_witness_trace_commitment,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "witness_bundle.layer2_witness_fields.dcm_trace_commitment",
            },
        ),
        (
            "tampered_lineage_preimage",
            tamper_lineage_preimage,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "witness_bundle.lineage_preimage",
            },
        ),
        (
            "tampered_intent_preimage",
            tamper_intent_preimage,
            RecurrenceConstraintErrorV1::ClaimRelationshipMismatch {
                field: "witness_bundle.intent_hash_preimage",
            },
        ),
        (
            "metadata_trace_state_count",
            tamper_metadata_trace_state_count,
            RecurrenceConstraintErrorV1::TraceLengthMismatch {
                expected: 7,
                actual: 6,
            },
        ),
    ];

    for (name, tamper, expected) in cases {
        let mut assembly = canonical_assembly();
        tamper(&mut assembly);
        let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
        assert_eq!(error, expected, "{name}");
    }
}

#[test]
fn native_mode_conflict_inside_envelope_rejects() {
    let mut assembly = canonical_assembly();
    let mut inline = assembly
        .witness_bundle
        .authorization_envelope
        .inline_authorization_lineage_v1
        .expect("canonical assembly must carry inline lineage");
    inline.freshness_mode = FreshnessModeV1::LegacyV1ChallengeFreshness;
    assembly
        .witness_bundle
        .authorization_envelope
        .inline_authorization_lineage_v1 = Some(inline);

    let error = validate_recurrence_constraints_v1(&assembly).unwrap_err();
    assert_eq!(
        error,
        RecurrenceConstraintErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_use_legacy_freshness_mode",
        }
    );
}

#[test]
fn pinned_constraint_check_vector_is_stable() {
    let summary = validate_recurrence_constraints_v1(&canonical_assembly()).unwrap();

    assert_eq!(summary.checked_transition_count, 5);
    assert_eq!(summary.trace_state_count, 6);
    assert_eq!(
        encode_hex(&summary.recomputed_trace_commitment),
        CANONICAL_DCM_TRACE_COMMITMENT_HEX
    );
    assert_eq!(
        encode_hex(&summary.recomputed_dcm_commitment_root),
        CANONICAL_DCM_COMMITMENT_ROOT_HEX
    );
    assert_eq!(encode_hex(&summary.intent_hash), CANONICAL_INTENT_HASH_HEX);
    assert_eq!(
        encode_hex(&summary.lineage_hash),
        CANONICAL_LINEAGE_HASH_HEX
    );
}

fn canonical_assembly() -> aura_intent_lineage_v1::ProofClaimAssemblyV1 {
    canonical_layer3_assembly()
}

fn tamper_public_claim_dcm_commitment_root(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.dcm_commitment_root = [0x99; 32];
}

fn tamper_public_claim_lineage_flags(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.lineage_flags = 0x0002;
}

fn tamper_public_claim_subject_binding_type(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.subject_binding_type = SubjectBindingTypeV1::ExternalSubjectId32;
}

fn tamper_public_claim_subject_id(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.subject_id = [0x77; 32];
}

fn tamper_public_claim_intent_hash(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.intent_hash = [0x88; 32];
}

fn tamper_public_claim_freshness_nonce(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.freshness_nonce = [0x67; 32];
}

fn tamper_public_claim_freshness_reference(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.freshness_reference = 4243;
}

fn tamper_public_claim_controlled_account_id(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.controlled_account_id = [0x44; 32];
}

fn tamper_public_claim_envelope_validity_bounds(assembly: &mut ProofClaimAssemblyV1) {
    assembly
        .public_claim
        .envelope_validity_bounds
        .not_after_batch_number = 124;
}

fn tamper_public_claim_dcm_commitment_kind(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.dcm_commitment_kind = DcmCommitmentKindV1::LegacyV1CompatibilityOnly;
}

fn tamper_public_claim_intent_type(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.intent_type = IntentTypeV1::OpaqueIntentHash32;
}

fn tamper_public_claim_freshness_mode(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.freshness_mode = FreshnessModeV1::LegacyV1ChallengeFreshness;
}

fn tamper_public_claim_legacy_compatibility_flag(assembly: &mut ProofClaimAssemblyV1) {
    assembly.public_claim.lineage_flags |= LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH;
}

fn tamper_unexpected_witness_trace_commitment(assembly: &mut ProofClaimAssemblyV1) {
    assembly
        .witness_bundle
        .layer2_witness_fields
        .dcm_trace_commitment = Some([0x99; 32]);
}

fn tamper_lineage_preimage(assembly: &mut ProofClaimAssemblyV1) {
    assembly.witness_bundle.lineage_preimage[0] ^= 0x01;
}

fn tamper_intent_preimage(assembly: &mut ProofClaimAssemblyV1) {
    assembly.witness_bundle.intent_hash_preimage[0] ^= 0x01;
}

fn tamper_metadata_trace_state_count(assembly: &mut ProofClaimAssemblyV1) {
    assembly.metadata.trace_state_count = 7;
}

fn state(x: u64, y: u64) -> DcmState521V1 {
    DcmState521V1::from_u64(x, y)
}
