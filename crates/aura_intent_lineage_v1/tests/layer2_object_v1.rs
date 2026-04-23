mod support;

use aura_intent_lineage_v1::{
    NativeLayer2AuthorizationLineageObjectV1, NativeLayer2AuthorizationLineageObjectV1Error,
    NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1,
};
use sha2::Digest;

use support::{
    canonical_bridge_result, canonical_layer2_object, changed_dcm_input,
    layer2_object_for_dcm_input,
};

#[test]
fn canonical_layer2_object_production_is_deterministic_and_trace_bound() {
    let first = canonical_layer2_object();
    let second = canonical_layer2_object();

    assert_eq!(first, second);
    assert_ne!(first.lineage.dcm_trace_commitment, [0u8; 32]);
    assert_ne!(
        first.lineage_hash,
        canonical_bridge_result().unwrap().lineage_hash
    );
}

#[test]
fn serialized_object_round_trip_is_exact_and_stable() {
    let object = canonical_layer2_object();
    let first = object.serialized_object().unwrap();
    let second = object.serialized_object().unwrap();
    let reparsed =
        NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(&first).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.len(),
        NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1
    );
    assert_eq!(reparsed, object);
}

#[test]
fn changing_lower_layer_input_changes_the_frozen_layer2_object() {
    let first = canonical_layer2_object();
    let second = layer2_object_for_dcm_input(changed_dcm_input());

    assert_ne!(
        first.lineage.dcm_commitment_root,
        second.lineage.dcm_commitment_root
    );
    assert_ne!(
        first.lineage.dcm_trace_commitment,
        second.lineage.dcm_trace_commitment
    );
    assert_ne!(first.lineage_hash, second.lineage_hash);
}

#[test]
fn layer2_object_consumes_the_exact_bridge_handoff_plus_trace_commitment() {
    let object = canonical_layer2_object();
    let bridge = canonical_bridge_result().unwrap();

    assert_eq!(
        object.lineage.dcm_commitment_root,
        bridge.dcm_commitments.dcm_commitment_root
    );
    assert_eq!(object.lineage.intent_hash, bridge.lineage.intent_hash);
    assert_eq!(
        object.lineage.subject_binding_type,
        bridge.lineage.subject_binding_type
    );
    assert_eq!(object.lineage.subject_id, bridge.lineage.subject_id);
    assert_eq!(object.lineage.freshness_mode, bridge.lineage.freshness_mode);
    assert_eq!(
        object.lineage.freshness_nonce,
        bridge.lineage.freshness_nonce
    );
    assert_eq!(
        object.lineage.freshness_reference,
        bridge.lineage.freshness_reference
    );
    assert_eq!(bridge.lineage.dcm_trace_commitment, [0u8; 32]);
    assert_eq!(
        object.lineage.dcm_trace_commitment,
        bridge.dcm_commitments.dcm_trace_commitment
    );
}

#[test]
fn lineage_without_trace_commitment_rejects_for_this_object_family() {
    let lineage = canonical_bridge_result().unwrap().lineage;

    let error = NativeLayer2AuthorizationLineageObjectV1::new(lineage).unwrap_err();
    assert_eq!(
        error,
        NativeLayer2AuthorizationLineageObjectV1Error::TraceCommitmentRequired
    );
}

#[test]
fn tampered_trailing_lineage_hash_is_ignored_and_recanonicalized() {
    let mut bytes = canonical_layer2_object().serialized_object().unwrap();
    let last_index = bytes.len() - 1;
    bytes[last_index] ^= 0x01;

    let reparsed =
        NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(&bytes).unwrap();

    assert_eq!(reparsed, canonical_layer2_object());
    assert_eq!(
        reparsed.serialized_object().unwrap(),
        canonical_layer2_object().serialized_object().unwrap()
    );
}

#[test]
fn tampered_lineage_commitment_rejects_even_with_matching_helper_hash() {
    let mut bytes = canonical_layer2_object().serialized_object().unwrap();
    let commitment_start = NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1 - 32 - 66;
    bytes[commitment_start] ^= 0x01;
    let hash_start = bytes.len() - 32;
    let digest = sha2::Sha256::digest(&bytes[..hash_start]);
    bytes[hash_start..].copy_from_slice(&digest);

    let error =
        NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(&bytes).unwrap_err();
    assert!(matches!(
        error,
        NativeLayer2AuthorizationLineageObjectV1Error::LineageCommitmentMismatch { .. }
            | NativeLayer2AuthorizationLineageObjectV1Error::InvalidLineageCommitmentEncoding
    ));
}

#[test]
fn lineage_with_zero_commitment_root_rejects_for_this_object_family() {
    let mut lineage = canonical_layer2_object().lineage;
    lineage.dcm_commitment_root = [0u8; 32];

    let error = NativeLayer2AuthorizationLineageObjectV1::new(lineage).unwrap_err();

    assert_eq!(
        error,
        NativeLayer2AuthorizationLineageObjectV1Error::CommitmentRootMustNotBeZero
    );
}

#[test]
fn truncated_serialized_object_rejects_before_lineage_reconstruction() {
    let mut bytes = canonical_layer2_object().serialized_object().unwrap();
    bytes.truncate(bytes.len() - 1);

    let error =
        NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(&bytes).unwrap_err();

    assert_eq!(
        error,
        NativeLayer2AuthorizationLineageObjectV1Error::InvalidSerializedLength {
            expected: NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1,
            actual: NATIVE_LAYER2_AUTHORIZATION_LINEAGE_OBJECT_SERIALIZED_LEN_V1 - 1,
        }
    );
}

#[test]
fn serialized_object_with_zero_commitment_root_rejects_even_with_matching_lineage_hash() {
    let mut bytes = canonical_layer2_object().serialized_object().unwrap();
    let root_start = b"AURA_AUTHORIZATION_LINEAGE_V1".len() + 1 + 2 + 1;
    let root_end = root_start + 32;
    bytes[root_start..root_end].fill(0);
    let hash_start = bytes.len() - 32;
    let digest = sha2::Sha256::digest(&bytes[..hash_start]);
    bytes[hash_start..].copy_from_slice(&digest);

    let error =
        NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(&bytes).unwrap_err();

    assert_eq!(
        error,
        NativeLayer2AuthorizationLineageObjectV1Error::CommitmentRootMustNotBeZero
    );
}
