// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
mod support;

use aura_intent_lineage_v1::{
    run_native_layer1_layer2_bridge_521_v1, run_native_layer1_layer2_bridge_v1,
    AuthorizationEnvelopeV1Decision, DcmCommitmentKindV1, DcmConfig521V1, DcmConfigV1,
    DcmExecutionErrorV1, DcmInput521V1, DcmState521V1, DcmStateV1, FieldElement521V1,
    FreshnessModeV1, IntentTypeV1, Layer1Layer2BridgeErrorV1, Layer1Layer2BridgeFreshnessV1,
    Layer1Layer2BridgeIntentSourceV1, SubjectBindingTypeV1, FIELD_ELEMENT_521_BYTE_LEN_V1,
    FIELD_MODULUS_521_V1,
};

use support::{
    canonical_bridge_result, canonical_dcm_config, canonical_dcm_input, canonical_freshness,
    canonical_intent, canonical_subject_binding, changed_dcm_input, encode_hex,
    legacy_canonical_bridge_result, legacy_canonical_dcm_config, legacy_canonical_dcm_input,
    CANONICAL_DCM_COMMITMENT_ROOT_HEX, CANONICAL_DCM_TRACE_COMMITMENT_HEX,
    CANONICAL_LINEAGE_HASH_HEX, LEGACY_CANONICAL_DCM_COMMITMENT_ROOT_HEX,
    LEGACY_CANONICAL_DCM_TRACE_COMMITMENT_HEX, LEGACY_CANONICAL_LINEAGE_HASH_HEX,
};

#[test]
fn canonical_native_bridge_succeeds() {
    let result = canonical_bridge_result().unwrap();

    assert_eq!(
        result.dcm_claim.initial_state,
        DcmState521V1::from_u64(3, 7)
    );
    assert_eq!(
        result.dcm_execution.final_state,
        DcmState521V1::from_u64(487, 788)
    );
    assert_eq!(
        result.dcm_claim.final_state,
        result.dcm_execution.final_state
    );
    assert_eq!(result.dcm_execution.trace_length, 6);
    assert_eq!(
        result.dcm_claim.trace_state_count(),
        result.dcm_execution.trace_length
    );
    assert_eq!(
        result.dcm_claim.commitment_root,
        result.dcm_commitments.dcm_commitment_root
    );
    assert_eq!(
        result.lineage.dcm_commitment_kind,
        DcmCommitmentKindV1::DcmRootCommitmentV1
    );
    assert_eq!(
        result.lineage.intent_type,
        IntentTypeV1::AuraLayer4IntentHashV1
    );
    assert_eq!(
        result.lineage.subject_binding_type,
        SubjectBindingTypeV1::RawEd25519PublicKey32
    );
    assert_eq!(result.lineage.subject_id, [0x55; 32]);
    assert_eq!(
        result.lineage.intent_hash,
        canonical_intent().intent_hash().unwrap()
    );
    assert_eq!(result.lineage.dcm_trace_commitment, [0u8; 32]);
    assert_eq!(
        result.envelope_decision,
        AuthorizationEnvelopeV1Decision::Accept {
            lineage_hash: result.lineage_hash,
        }
    );
}

#[test]
fn changing_dcm_input_changes_native_lineage_output() {
    let first = run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config(),
        &canonical_dcm_input(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap();
    let second = run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config(),
        &changed_dcm_input(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap();

    assert_ne!(
        first.dcm_commitments.dcm_commitment_root,
        second.dcm_commitments.dcm_commitment_root
    );
    assert_ne!(
        first.dcm_commitments.dcm_trace_commitment,
        second.dcm_commitments.dcm_trace_commitment
    );
    assert_ne!(first.lineage_hash, second.lineage_hash);
}

#[test]
fn canonical_native_521_bridge_succeeds() {
    let result = run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config_521(),
        &canonical_dcm_input_521(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap();

    assert_eq!(
        result.dcm_execution.final_state,
        DcmState521V1 {
            x: small_value_521(1),
            y: small_value_521(2),
        }
    );
    assert_eq!(result.dcm_execution.trace_length, 3);
    assert_eq!(
        result.lineage.dcm_commitment_kind,
        DcmCommitmentKindV1::DcmRootCommitmentV1
    );
    assert_eq!(
        result.lineage.intent_type,
        IntentTypeV1::AuraLayer4IntentHashV1
    );
    assert_eq!(
        result.envelope_decision,
        AuthorizationEnvelopeV1Decision::Accept {
            lineage_hash: result.lineage_hash,
        }
    );
    assert_eq!(
        result.lineage.dcm_commitment_root,
        result.dcm_commitments.dcm_commitment_root
    );
    assert_eq!(result.lineage.dcm_trace_commitment, [0u8; 32]);
}

#[test]
fn changing_521_dcm_input_changes_native_lineage_output() {
    let first = run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config_521(),
        &canonical_dcm_input_521(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap();
    let second = run_native_layer1_layer2_bridge_521_v1(
        &canonical_dcm_config_521(),
        &changed_dcm_input_521(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap();

    assert_ne!(
        first.dcm_commitments.dcm_commitment_root,
        second.dcm_commitments.dcm_commitment_root
    );
    assert_ne!(
        first.dcm_commitments.dcm_trace_commitment,
        second.dcm_commitments.dcm_trace_commitment
    );
    assert_ne!(first.lineage_hash, second.lineage_hash);
}

#[test]
fn mode_conflict_rejects() {
    let error = run_native_layer1_layer2_bridge_v1(
        &legacy_canonical_dcm_config(),
        &legacy_canonical_dcm_input(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        Layer1Layer2BridgeFreshnessV1 {
            freshness_mode: FreshnessModeV1::LegacyV1ChallengeFreshness,
            freshness_nonce: [0x66; 32],
            freshness_reference: 4242,
        },
    )
    .unwrap_err();

    assert_eq!(
        error,
        Layer1Layer2BridgeErrorV1::ModeConflict {
            reason: "native_dcm_rooted_cannot_use_legacy_freshness_mode",
        }
    );
}

#[test]
fn invalid_dcm_config_rejects_before_lineage_construction() {
    let error = run_native_layer1_layer2_bridge_v1(
        &DcmConfigV1 {
            modulus: 1,
            iteration_count: 5,
        },
        &legacy_canonical_dcm_input(),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        canonical_subject_binding(),
        canonical_freshness(),
    )
    .unwrap_err();

    assert_eq!(
        error,
        Layer1Layer2BridgeErrorV1::DcmExecution(DcmExecutionErrorV1::InvalidModulus { actual: 1 })
    );
}

#[test]
fn pinned_native_bridge_vector_is_stable() {
    let result = canonical_bridge_result().unwrap();

    assert_eq!(
        encode_hex(&result.dcm_commitments.dcm_commitment_root),
        CANONICAL_DCM_COMMITMENT_ROOT_HEX
    );
    assert_eq!(
        encode_hex(&result.dcm_commitments.dcm_trace_commitment),
        CANONICAL_DCM_TRACE_COMMITMENT_HEX
    );
    assert_eq!(encode_hex(&result.lineage_hash), CANONICAL_LINEAGE_HASH_HEX);
    assert_eq!(
        result.envelope_decision,
        AuthorizationEnvelopeV1Decision::Accept {
            lineage_hash: result.lineage_hash,
        }
    );
}

#[test]
fn legacy_small_modulus_bridge_vector_remains_isolated() {
    let result = legacy_canonical_bridge_result().unwrap();

    assert_eq!(result.dcm_execution.final_state, DcmStateV1 { x: 2, y: 12 });
    assert_eq!(
        encode_hex(&result.dcm_commitments.dcm_commitment_root),
        LEGACY_CANONICAL_DCM_COMMITMENT_ROOT_HEX
    );
    assert_eq!(
        encode_hex(&result.dcm_commitments.dcm_trace_commitment),
        LEGACY_CANONICAL_DCM_TRACE_COMMITMENT_HEX
    );
    assert_eq!(
        encode_hex(&result.lineage_hash),
        LEGACY_CANONICAL_LINEAGE_HASH_HEX
    );
}

fn canonical_dcm_config_521() -> DcmConfig521V1 {
    DcmConfig521V1 { iteration_count: 2 }
}

fn canonical_dcm_input_521() -> DcmInput521V1 {
    DcmInput521V1 {
        x0: max_minus_one_521(),
        y0: small_value_521(1),
    }
}

fn changed_dcm_input_521() -> DcmInput521V1 {
    DcmInput521V1 {
        x0: small_value_521(2),
        y0: small_value_521(1),
    }
}

fn max_minus_one_521() -> FieldElement521V1 {
    let mut bytes = FIELD_MODULUS_521_V1;
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
    FieldElement521V1::from_bytes(bytes).unwrap()
}

fn small_value_521(value: u8) -> FieldElement521V1 {
    FieldElement521V1::from_bytes(small_value_bytes_521(value)).unwrap()
}

fn small_value_bytes_521(value: u8) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
    bytes
}
