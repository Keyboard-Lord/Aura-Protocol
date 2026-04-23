use aura_intent_lineage_v1::{
    produce_native_layer2_authorization_lineage_object_521_v1, AuraLayer4FeePolicyKindV1,
    AuraLayer4IntentBodyV1, AuraLayer4OperationBodyV1, AuraLayer4TxKindV1, DcmConfig521V1,
    DcmInput521V1, FreshnessModeV1, Layer1Layer2BridgeFreshnessV1,
    Layer1Layer2BridgeIntentSourceV1, Layer1Layer2BridgeSubjectBindingV1,
    NativeLayer2AuthorizationLineageObjectV1, SubjectBindingTypeV1, ValueTransferOperationV1,
    AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1,
};
use aura_proof_material_v2::{
    is_supported_proof_material_type_v2, supported_proof_material_types_v2,
    CanonicalVerifierBundleV2Input, CanonicalVerifierBundleV2Payload, ExtensionInputV2,
    ExtensionPayloadV2, NativeLayer2AuthorizationLineageV1Input,
    NativeLayer2AuthorizationLineageV1Payload, ProofMaterialHashV2, ProofMaterialTypeV2,
    ProofMaterialV2, ProofMaterialV2BuildRequest, ProofMaterialV2Error, ProofMaterialV2Header,
    ProofMaterialV2VerifyRequest, CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
    NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE, PROOF_MATERIAL_DOMAIN_SEPARATOR_V2,
    PROOF_MATERIAL_VERSION_V2,
};
use sha2::{Digest, Sha256};

fn supported_type() -> ProofMaterialTypeV2 {
    CANONICAL_VERIFIER_BUNDLE_V2_TYPE
}

fn unsupported_type() -> ProofMaterialTypeV2 {
    ProofMaterialTypeV2::new(0x1002)
}

fn layer2_supported_type() -> ProofMaterialTypeV2 {
    NATIVE_LAYER2_AUTHORIZATION_LINEAGE_V1_TYPE
}

fn sample_bundle_input() -> CanonicalVerifierBundleV2Input {
    CanonicalVerifierBundleV2Input::new(
        vec![0x10, 0x11, 0x12, 0x13],
        vec![0x20, 0x21, 0x22],
        vec![0x30, 0x31, 0x32, 0x33, 0x34],
    )
}

fn sample_input() -> ExtensionInputV2 {
    ExtensionInputV2::canonical_verifier_bundle(sample_bundle_input())
}

fn sample_payload() -> ExtensionPayloadV2 {
    ExtensionPayloadV2::canonical_verifier_bundle(CanonicalVerifierBundleV2Payload::from_input(
        &sample_bundle_input(),
    ))
}

fn sample_artifact() -> ProofMaterialV2 {
    ProofMaterialV2::new(supported_type(), sample_payload())
}

fn unsupported_artifact() -> ProofMaterialV2 {
    ProofMaterialV2::new(
        unsupported_type(),
        ExtensionPayloadV2::opaque(unsupported_type(), vec![0xaa, 0xbb, 0xcc]),
    )
}

fn unsupported_input() -> ExtensionInputV2 {
    ExtensionInputV2::opaque(unsupported_type(), vec![0x44, 0x55])
}

fn canonical_intent() -> AuraLayer4IntentBodyV1 {
    AuraLayer4IntentBodyV1 {
        intent_version: 1,
        intent_flags: 0,
        rollup_id: [0x11; 32],
        tx_kind: AuraLayer4TxKindV1::ValueTransfer,
        sender_account_id: [0x22; 32],
        sender_nonce: 7,
        validity_flags: 0x000c,
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
        not_before_batch_number: 120,
        not_after_batch_number: 125,
        fee_policy_kind: AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
        max_fee_native: 500,
        client_context_commitment: [0u8; 32],
        operation_body: AuraLayer4OperationBodyV1::ValueTransfer(ValueTransferOperationV1 {
            recipient_account_id: [0x33; 32],
            amount: 2500,
        }),
    }
}

fn canonical_layer2_object() -> NativeLayer2AuthorizationLineageObjectV1 {
    produce_native_layer2_authorization_lineage_object_521_v1(
        &DcmConfig521V1 { iteration_count: 5 },
        &DcmInput521V1::from_u64(3, 7),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        Layer1Layer2BridgeSubjectBindingV1 {
            subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            subject_id: [0x55; 32],
            subject_public_key: None,
        },
        Layer1Layer2BridgeFreshnessV1 {
            freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
            freshness_nonce: [0x66; 32],
            freshness_reference: 4242,
        },
    )
    .expect("canonical native layer2 object should succeed")
}

fn changed_layer2_object() -> NativeLayer2AuthorizationLineageObjectV1 {
    produce_native_layer2_authorization_lineage_object_521_v1(
        &DcmConfig521V1 { iteration_count: 5 },
        &DcmInput521V1::from_u64(4, 7),
        Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
        Layer1Layer2BridgeSubjectBindingV1 {
            subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            subject_id: [0x55; 32],
            subject_public_key: None,
        },
        Layer1Layer2BridgeFreshnessV1 {
            freshness_mode: FreshnessModeV1::NoncePlusSlotNumber,
            freshness_nonce: [0x66; 32],
            freshness_reference: 4242,
        },
    )
    .expect("changed native layer2 object should succeed")
}

fn sample_layer2_input() -> NativeLayer2AuthorizationLineageV1Input {
    NativeLayer2AuthorizationLineageV1Input::new(
        canonical_layer2_object()
            .serialized_object()
            .expect("canonical object bytes should serialize"),
    )
}

fn changed_layer2_input() -> NativeLayer2AuthorizationLineageV1Input {
    NativeLayer2AuthorizationLineageV1Input::new(
        changed_layer2_object()
            .serialized_object()
            .expect("changed object bytes should serialize"),
    )
}

fn sample_layer2_payload() -> NativeLayer2AuthorizationLineageV1Payload {
    NativeLayer2AuthorizationLineageV1Payload::from_input(&sample_layer2_input())
        .expect("canonical layer2 payload should derive")
}

fn sample_layer2_artifact() -> ProofMaterialV2 {
    ProofMaterialV2::new(
        layer2_supported_type(),
        ExtensionPayloadV2::native_layer2_authorization_lineage(sample_layer2_payload()),
    )
}

fn sha256_bytes(bytes: &[u8]) -> ProofMaterialHashV2 {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn expected_supported_hash_from_input(
    input: &CanonicalVerifierBundleV2Input,
) -> ProofMaterialHashV2 {
    let proof_blob_hash = sha256_bytes(input.proof_blob_bytes());
    let public_inputs_hash = sha256_bytes(input.public_inputs_bytes());
    let verification_key_hash = sha256_bytes(input.verification_key_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROOF_MATERIAL_DOMAIN_SEPARATOR_V2);
    bytes.push(PROOF_MATERIAL_VERSION_V2);
    bytes.extend_from_slice(&supported_type().as_u16().to_le_bytes());
    bytes.extend_from_slice(&proof_blob_hash);
    bytes.extend_from_slice(&public_inputs_hash);
    bytes.extend_from_slice(&verification_key_hash);
    sha256_bytes(&bytes)
}

fn expected_layer2_hash_from_input(
    input: &NativeLayer2AuthorizationLineageV1Input,
) -> ProofMaterialHashV2 {
    let object = NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(
        input.serialized_object_bytes(),
    )
    .expect("canonical object bytes should validate");

    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROOF_MATERIAL_DOMAIN_SEPARATOR_V2);
    bytes.push(PROOF_MATERIAL_VERSION_V2);
    bytes.extend_from_slice(&layer2_supported_type().as_u16().to_le_bytes());
    bytes.extend_from_slice(&object.lineage.lineage_hash().unwrap());
    sha256_bytes(&bytes)
}

fn direct_artifact_from_input(input: &CanonicalVerifierBundleV2Input) -> ProofMaterialV2 {
    let payload = CanonicalVerifierBundleV2Payload::from_input(input);

    ProofMaterialV2::new(
        supported_type(),
        ExtensionPayloadV2::canonical_verifier_bundle(payload),
    )
}

fn build_artifact_from_input(input: &CanonicalVerifierBundleV2Input) -> ProofMaterialV2 {
    ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        supported_type(),
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
    ))
    .expect("supported build should succeed")
}

#[test]
fn header_defaults_to_v2_identity() {
    let header = ProofMaterialV2Header::new(supported_type());

    assert_eq!(header.proof_material_version, PROOF_MATERIAL_VERSION_V2);
    assert_eq!(header.proof_material_type, supported_type());
}

#[test]
fn supported_type_is_registered_and_other_type_remains_fail_closed() {
    assert_eq!(
        supported_proof_material_types_v2(),
        &[supported_type(), layer2_supported_type()]
    );
    assert!(is_supported_proof_material_type_v2(supported_type()));
    assert!(is_supported_proof_material_type_v2(layer2_supported_type()));
    assert!(!is_supported_proof_material_type_v2(unsupported_type()));

    let unsupported = ProofMaterialV2Error::UnsupportedProofMaterialType {
        actual: unsupported_type(),
    };

    assert_eq!(unsupported_artifact().verify_structure(), Err(unsupported));
    assert_eq!(
        unsupported_artifact().proof_material_hash(),
        Err(unsupported)
    );
    assert_eq!(
        ProofMaterialV2BuildRequest::new(unsupported_type(), unsupported_input())
            .verify_type_binding(),
        Err(unsupported)
    );

    let verify_request = ProofMaterialV2VerifyRequest::new(
        unsupported_type(),
        unsupported_artifact(),
        unsupported_input(),
        [0x77; 32],
    );
    assert_eq!(verify_request.verify_outer_consistency(), Err(unsupported));
    assert_eq!(ProofMaterialV2::verify(&verify_request), Err(unsupported));
}

#[test]
fn build_succeeds_for_canonical_verifier_bundle_v2() {
    let input = sample_bundle_input();
    let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        supported_type(),
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
    ))
    .expect("supported build should succeed");

    assert_eq!(artifact.declared_type(), supported_type());
    assert_eq!(
        artifact.header.proof_material_version,
        PROOF_MATERIAL_VERSION_V2
    );
    assert_eq!(artifact.header.proof_material_type, supported_type());
    assert_eq!(
        artifact.extension_payload().owning_proof_material_type(),
        supported_type()
    );

    let payload = artifact
        .extension_payload()
        .as_canonical_verifier_bundle()
        .expect("canonical payload should be present");
    assert_eq!(
        payload.proof_blob_hash(),
        sha256_bytes(input.proof_blob_bytes())
    );
    assert_eq!(
        payload.public_inputs_hash(),
        sha256_bytes(input.public_inputs_bytes())
    );
    assert_eq!(
        payload.verification_key_hash(),
        sha256_bytes(input.verification_key_bytes())
    );
}

#[test]
fn proof_material_hash_is_deterministic_for_supported_artifact() {
    let input = sample_bundle_input();
    let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        supported_type(),
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
    ))
    .expect("supported build should succeed");
    let expected_hash = expected_supported_hash_from_input(&input);

    assert_eq!(artifact.verify_structure(), Ok(()));
    assert_eq!(artifact.proof_material_hash(), Ok(expected_hash));
}

#[test]
fn verify_succeeds_for_matching_supported_artifact_input_and_hash() {
    let input = sample_bundle_input();
    let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        supported_type(),
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
    ))
    .expect("supported build should succeed");
    let expected_hash = expected_supported_hash_from_input(&input);
    let request = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact,
        ExtensionInputV2::canonical_verifier_bundle(input),
        expected_hash,
    );

    assert_eq!(request.verify_outer_consistency(), Ok(()));
    assert_eq!(ProofMaterialV2::verify(&request), Ok(expected_hash));
}

#[test]
fn derived_payload_construction_matches_build_generated_artifact_and_hash() {
    let input = sample_bundle_input();
    let direct_artifact = direct_artifact_from_input(&input);
    let built_artifact = build_artifact_from_input(&input);
    let expected_hash = expected_supported_hash_from_input(&input);

    assert_eq!(direct_artifact, built_artifact);
    assert_eq!(direct_artifact.verify_structure(), Ok(()));
    assert_eq!(built_artifact.verify_structure(), Ok(()));
    assert_eq!(direct_artifact.proof_material_hash(), Ok(expected_hash));
    assert_eq!(built_artifact.proof_material_hash(), Ok(expected_hash));
}

#[test]
fn verify_succeeds_equally_for_derived_payload_and_build_generated_artifacts() {
    let input = sample_bundle_input();
    let direct_artifact = direct_artifact_from_input(&input);
    let built_artifact = build_artifact_from_input(&input);
    let expected_hash = expected_supported_hash_from_input(&input);

    let direct_request = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        direct_artifact,
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
        expected_hash,
    );
    let built_request = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        built_artifact,
        ExtensionInputV2::canonical_verifier_bundle(input),
        expected_hash,
    );

    assert_eq!(direct_request.verify_outer_consistency(), Ok(()));
    assert_eq!(built_request.verify_outer_consistency(), Ok(()));
    assert_eq!(ProofMaterialV2::verify(&direct_request), Ok(expected_hash));
    assert_eq!(ProofMaterialV2::verify(&built_request), Ok(expected_hash));
}

#[test]
fn expected_proof_material_hash_is_not_a_dispatch_key_for_supported_owner() {
    let input = sample_bundle_input();
    let artifact = build_artifact_from_input(&input);
    let expected_hash = expected_supported_hash_from_input(&input);

    let request_a = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact.clone(),
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
        expected_hash,
    );
    let request_b = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact,
        ExtensionInputV2::canonical_verifier_bundle(input),
        [0xfe; 32],
    );

    assert_eq!(request_a.verify_outer_consistency(), Ok(()));
    assert_eq!(request_b.verify_outer_consistency(), Ok(()));
    assert_eq!(ProofMaterialV2::verify(&request_a), Ok(expected_hash));
    assert_eq!(
        ProofMaterialV2::verify(&request_b),
        Err(ProofMaterialV2Error::ProofMaterialHashMismatch)
    );
}

#[test]
fn build_succeeds_for_native_layer2_authorization_lineage_owner() {
    let input = sample_layer2_input();
    let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        layer2_supported_type(),
        ExtensionInputV2::native_layer2_authorization_lineage(input.clone()),
    ))
    .expect("layer2 build should succeed");

    assert_eq!(artifact.declared_type(), layer2_supported_type());
    assert_eq!(
        artifact.extension_payload().owning_proof_material_type(),
        layer2_supported_type()
    );

    let payload = artifact
        .extension_payload()
        .as_native_layer2_authorization_lineage()
        .expect("layer2 payload should be present");
    let object = NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(
        input.serialized_object_bytes(),
    )
    .expect("canonical layer2 object should validate");

    assert_eq!(payload.lineage_hash(), object.lineage.lineage_hash().unwrap());
}

#[test]
fn proof_material_hash_is_deterministic_for_layer2_owner() {
    let input = sample_layer2_input();
    let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        layer2_supported_type(),
        ExtensionInputV2::native_layer2_authorization_lineage(input.clone()),
    ))
    .expect("layer2 build should succeed");
    let expected_hash = expected_layer2_hash_from_input(&input);

    assert_eq!(artifact.verify_structure(), Ok(()));
    assert_eq!(artifact.proof_material_hash(), Ok(expected_hash));
}

#[test]
fn direct_layer2_payload_construction_matches_build_generated_artifact_and_hash() {
    let input = sample_layer2_input();
    let direct_artifact = sample_layer2_artifact();
    let built_artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        layer2_supported_type(),
        ExtensionInputV2::native_layer2_authorization_lineage(input.clone()),
    ))
    .expect("layer2 build should succeed");
    let expected_hash = expected_layer2_hash_from_input(&input);

    assert_eq!(direct_artifact, built_artifact);
    assert_eq!(direct_artifact.proof_material_hash(), Ok(expected_hash));
    assert_eq!(built_artifact.proof_material_hash(), Ok(expected_hash));
}

#[test]
fn verify_succeeds_for_matching_layer2_object_input_and_hash() {
    let input = sample_layer2_input();
    let artifact = sample_layer2_artifact();
    let expected_hash = expected_layer2_hash_from_input(&input);
    let request = ProofMaterialV2VerifyRequest::new(
        layer2_supported_type(),
        artifact,
        ExtensionInputV2::native_layer2_authorization_lineage(input),
        expected_hash,
    );

    assert_eq!(request.verify_outer_consistency(), Ok(()));
    assert_eq!(ProofMaterialV2::verify(&request), Ok(expected_hash));
}

#[test]
fn layer2_input_rejects_tampered_object_bytes() {
    let mut bytes = sample_layer2_input().serialized_object_bytes().to_vec();
    let tamper_index = bytes.len() - 1;
    bytes[tamper_index] ^= 0x01;
    let input = NativeLayer2AuthorizationLineageV1Input::new(bytes);

    let request = ProofMaterialV2BuildRequest::new(
        layer2_supported_type(),
        ExtensionInputV2::native_layer2_authorization_lineage(input.clone()),
    );

    let artifact = ProofMaterialV2::build(request)
        .expect("helper-only lineage hash drift should be recanonicalized");
    let payload = artifact
        .extension_payload()
        .as_native_layer2_authorization_lineage()
        .expect("layer2 payload should be present");
    let canonical_hash = NativeLayer2AuthorizationLineageObjectV1::from_serialized_object_bytes(
        input.serialized_object_bytes(),
    )
    .expect("tampered helper hash should still parse to a canonical layer2 object")
    .lineage
    .lineage_hash()
    .unwrap();

    assert_eq!(payload.lineage_hash(), canonical_hash);
}

#[test]
fn layer2_input_rejects_zero_commitment_root_even_with_matching_lineage_hash() {
    let mut bytes = sample_layer2_input().serialized_object_bytes().to_vec();
    let root_start = AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1.len() + 1 + 2 + 1;
    let root_end = root_start + 32;
    bytes[root_start..root_end].fill(0);
    let hash_start = bytes.len() - 32;
    let digest = sha256_bytes(&bytes[..hash_start]);
    bytes[hash_start..].copy_from_slice(&digest);
    let input = NativeLayer2AuthorizationLineageV1Input::new(bytes);

    let request = ProofMaterialV2BuildRequest::new(
        layer2_supported_type(),
        ExtensionInputV2::native_layer2_authorization_lineage(input),
    );

    assert_eq!(
        ProofMaterialV2::build(request),
        Err(
            ProofMaterialV2Error::NativeLayer2AuthorizationLineageObjectInvalid {
                reason: "native_layer2_object_commitment_root_must_not_be_zero",
            }
        )
    );
}

#[test]
fn layer2_input_rejects_truncated_object_bytes() {
    let mut bytes = sample_layer2_input().serialized_object_bytes().to_vec();
    bytes.truncate(bytes.len() - 1);
    let input = NativeLayer2AuthorizationLineageV1Input::new(bytes);

    let request = ProofMaterialV2BuildRequest::new(
        layer2_supported_type(),
        ExtensionInputV2::native_layer2_authorization_lineage(input),
    );

    assert_eq!(
        ProofMaterialV2::build(request),
        Err(
            ProofMaterialV2Error::NativeLayer2AuthorizationLineageObjectInvalid {
                reason: "native_layer2_object_serialized_length_invalid",
            }
        )
    );
}

#[test]
fn layer2_verify_rejects_valid_mismatched_object() {
    let canonical_input = sample_layer2_input();
    let changed_input = changed_layer2_input();
    let request = ProofMaterialV2VerifyRequest::new(
        layer2_supported_type(),
        sample_layer2_artifact(),
        ExtensionInputV2::native_layer2_authorization_lineage(changed_input),
        expected_layer2_hash_from_input(&canonical_input),
    );

    assert_eq!(request.verify_outer_consistency(), Ok(()));
    assert_eq!(
        ProofMaterialV2::verify(&request),
        Err(ProofMaterialV2Error::NativeLayer2AuthorizationLineageHashMismatch)
    );
}

#[test]
fn layer2_verify_rejects_wrong_expected_hash() {
    let input = sample_layer2_input();
    let request = ProofMaterialV2VerifyRequest::new(
        layer2_supported_type(),
        sample_layer2_artifact(),
        ExtensionInputV2::native_layer2_authorization_lineage(input),
        [0x5a; 32],
    );

    assert_eq!(request.verify_outer_consistency(), Ok(()));
    assert_eq!(
        ProofMaterialV2::verify(&request),
        Err(ProofMaterialV2Error::ProofMaterialHashMismatch)
    );
}

#[test]
fn artifact_rejects_invalid_version() {
    let mut artifact = sample_artifact();
    artifact.header.proof_material_version = 3;

    assert_eq!(
        artifact.verify_structure(),
        Err(ProofMaterialV2Error::InvalidVersion {
            expected: PROOF_MATERIAL_VERSION_V2,
            actual: 3,
        })
    );
}

#[test]
fn hash_and_verify_entrypoints_reject_invalid_version_before_supported_dispatch() {
    let mut artifact = sample_artifact();
    artifact.header.proof_material_version = 4;
    let request = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact.clone(),
        sample_input(),
        [0x91; 32],
    );
    let expected = ProofMaterialV2Error::InvalidVersion {
        expected: PROOF_MATERIAL_VERSION_V2,
        actual: 4,
    };

    assert_eq!(artifact.proof_material_hash(), Err(expected));
    assert_eq!(request.verify_outer_consistency(), Err(expected));
    assert_eq!(ProofMaterialV2::verify(&request), Err(expected));
}

#[test]
fn artifact_payload_type_mismatch_rejects_before_supported_dispatch() {
    let artifact = ProofMaterialV2::new(
        supported_type(),
        ExtensionPayloadV2::opaque(unsupported_type(), vec![0xaa]),
    );
    let request = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact.clone(),
        sample_input(),
        [0xa2; 32],
    );
    let expected = ProofMaterialV2Error::ArtifactPayloadTypeMismatch {
        artifact_type: supported_type(),
        payload_type: unsupported_type(),
    };

    assert_eq!(artifact.verify_structure(), Err(expected));
    assert_eq!(artifact.proof_material_hash(), Err(expected));
    assert_eq!(request.verify_outer_consistency(), Err(expected));
    assert_eq!(ProofMaterialV2::verify(&request), Err(expected));
}

#[test]
fn build_request_rejects_input_type_mismatch_before_owner_dispatch() {
    let request = ProofMaterialV2BuildRequest::new(supported_type(), unsupported_input());

    assert_eq!(
        request.verify_type_binding(),
        Err(ProofMaterialV2Error::BuildTypeInputMismatch {
            request_type: supported_type(),
            input_type: unsupported_type(),
        })
    );
    assert_eq!(
        ProofMaterialV2::build(request),
        Err(ProofMaterialV2Error::BuildTypeInputMismatch {
            request_type: supported_type(),
            input_type: unsupported_type(),
        })
    );
}

#[test]
fn verify_request_rejects_expected_type_mismatches_before_owner_dispatch() {
    let artifact_type_mismatch = ProofMaterialV2VerifyRequest::new(
        unsupported_type(),
        sample_artifact(),
        sample_input(),
        [0x44; 32],
    );
    assert_eq!(
        artifact_type_mismatch.verify_outer_consistency(),
        Err(ProofMaterialV2Error::VerifyExpectedArtifactTypeMismatch {
            expected_type: unsupported_type(),
            artifact_type: supported_type(),
        })
    );
    assert_eq!(
        ProofMaterialV2::verify(&artifact_type_mismatch),
        Err(ProofMaterialV2Error::VerifyExpectedArtifactTypeMismatch {
            expected_type: unsupported_type(),
            artifact_type: supported_type(),
        })
    );

    let input_type_mismatch = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        sample_artifact(),
        unsupported_input(),
        [0x55; 32],
    );
    assert_eq!(
        input_type_mismatch.verify_outer_consistency(),
        Err(ProofMaterialV2Error::VerifyExpectedInputTypeMismatch {
            expected_type: supported_type(),
            input_type: unsupported_type(),
        })
    );
    assert_eq!(
        ProofMaterialV2::verify(&input_type_mismatch),
        Err(ProofMaterialV2Error::VerifyExpectedInputTypeMismatch {
            expected_type: supported_type(),
            input_type: unsupported_type(),
        })
    );
}

#[test]
fn expected_proof_material_hash_does_not_change_unsupported_verify_failure_class() {
    let request_a = ProofMaterialV2VerifyRequest::new(
        unsupported_type(),
        unsupported_artifact(),
        unsupported_input(),
        [0x01; 32],
    );
    let request_b = ProofMaterialV2VerifyRequest::new(
        unsupported_type(),
        unsupported_artifact(),
        unsupported_input(),
        [0xfe; 32],
    );
    let expected = ProofMaterialV2Error::UnsupportedProofMaterialType {
        actual: unsupported_type(),
    };

    assert_eq!(request_a.verify_outer_consistency(), Err(expected));
    assert_eq!(request_b.verify_outer_consistency(), Err(expected));
    assert_eq!(ProofMaterialV2::verify(&request_a), Err(expected));
    assert_eq!(ProofMaterialV2::verify(&request_b), Err(expected));
}

#[test]
fn supported_artifact_rejects_opaque_payload_family() {
    let artifact = ProofMaterialV2::new(
        supported_type(),
        ExtensionPayloadV2::opaque(supported_type(), vec![0xaa, 0xbb]),
    );

    assert_eq!(
        artifact.verify_structure(),
        Err(ProofMaterialV2Error::CanonicalVerifierBundlePayloadRequired)
    );
    assert_eq!(
        artifact.proof_material_hash(),
        Err(ProofMaterialV2Error::CanonicalVerifierBundlePayloadRequired)
    );
}

#[test]
fn supported_build_and_verify_paths_reject_opaque_input_family() {
    let build_request = ProofMaterialV2BuildRequest::new(
        supported_type(),
        ExtensionInputV2::opaque(supported_type(), vec![0x11, 0x22]),
    );
    assert_eq!(
        ProofMaterialV2::build(build_request),
        Err(ProofMaterialV2Error::CanonicalVerifierBundleInputRequired)
    );

    let verify_request = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        sample_artifact(),
        ExtensionInputV2::opaque(supported_type(), vec![0x33, 0x44]),
        [0x66; 32],
    );
    assert_eq!(verify_request.verify_outer_consistency(), Ok(()));
    assert_eq!(
        ProofMaterialV2::verify(&verify_request),
        Err(ProofMaterialV2Error::CanonicalVerifierBundleInputRequired)
    );
}

#[test]
fn verify_rejects_component_hash_mismatches_and_final_hash_mismatch() {
    let artifact = sample_artifact();
    let expected_hash = artifact.proof_material_hash().expect("hash should succeed");

    let wrong_proof_blob = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact.clone(),
        ExtensionInputV2::canonical_verifier_bundle(CanonicalVerifierBundleV2Input::new(
            vec![0xff],
            sample_bundle_input().public_inputs_bytes().to_vec(),
            sample_bundle_input().verification_key_bytes().to_vec(),
        )),
        expected_hash,
    );
    assert_eq!(
        ProofMaterialV2::verify(&wrong_proof_blob),
        Err(ProofMaterialV2Error::CanonicalVerifierBundleProofBlobHashMismatch)
    );

    let wrong_public_inputs = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact.clone(),
        ExtensionInputV2::canonical_verifier_bundle(CanonicalVerifierBundleV2Input::new(
            sample_bundle_input().proof_blob_bytes().to_vec(),
            vec![0xee],
            sample_bundle_input().verification_key_bytes().to_vec(),
        )),
        expected_hash,
    );
    assert_eq!(
        ProofMaterialV2::verify(&wrong_public_inputs),
        Err(ProofMaterialV2Error::CanonicalVerifierBundlePublicInputsHashMismatch)
    );

    let wrong_verification_key = ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact.clone(),
        ExtensionInputV2::canonical_verifier_bundle(CanonicalVerifierBundleV2Input::new(
            sample_bundle_input().proof_blob_bytes().to_vec(),
            sample_bundle_input().public_inputs_bytes().to_vec(),
            vec![0xdd],
        )),
        expected_hash,
    );
    assert_eq!(
        ProofMaterialV2::verify(&wrong_verification_key),
        Err(ProofMaterialV2Error::CanonicalVerifierBundleVerificationKeyHashMismatch)
    );

    let wrong_expected_hash =
        ProofMaterialV2VerifyRequest::new(supported_type(), artifact, sample_input(), [0x99; 32]);
    assert_eq!(wrong_expected_hash.verify_outer_consistency(), Ok(()));
    assert_eq!(
        ProofMaterialV2::verify(&wrong_expected_hash),
        Err(ProofMaterialV2Error::ProofMaterialHashMismatch)
    );
}
