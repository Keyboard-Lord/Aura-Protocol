use aura_proof_material_v2::{
    CanonicalVerifierBundleV2Input, CanonicalVerifierBundleV2Payload, ExtensionInputV2,
    ExtensionPayloadV2, ProofMaterialTypeV2, ProofMaterialV2, ProofMaterialV2BuildRequest,
    ProofMaterialV2Error, ProofMaterialV2VerifyRequest, CANONICAL_VERIFIER_BUNDLE_V2_TYPE,
};
use aura_verifier_adapter_v2::{
    is_supported_verifier_adapter_type_v2, supported_verifier_adapter_types_v2,
    verify_with_adapter_v2, VerifierAdapterInputV2, VerifierAdapterV2Error,
    VerifierAdapterVerifyRequestV2,
};

fn supported_type() -> ProofMaterialTypeV2 {
    CANONICAL_VERIFIER_BUNDLE_V2_TYPE
}

fn unsupported_type() -> ProofMaterialTypeV2 {
    ProofMaterialTypeV2::new(0x1002)
}

fn sample_bundle_input() -> CanonicalVerifierBundleV2Input {
    CanonicalVerifierBundleV2Input::new(
        vec![0x10, 0x11, 0x12, 0x13],
        vec![0x20, 0x21, 0x22],
        vec![0x30, 0x31, 0x32, 0x33, 0x34],
    )
}

fn supported_proof_material_request() -> ProofMaterialV2VerifyRequest {
    let input = sample_bundle_input();
    let artifact = ProofMaterialV2::build(ProofMaterialV2BuildRequest::new(
        supported_type(),
        ExtensionInputV2::canonical_verifier_bundle(input.clone()),
    ))
    .expect("supported build should succeed");
    let expected_hash = artifact
        .proof_material_hash()
        .expect("supported artifact hash should succeed");

    ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact,
        ExtensionInputV2::canonical_verifier_bundle(input),
        expected_hash,
    )
}

fn direct_supported_proof_material_request() -> ProofMaterialV2VerifyRequest {
    let input = sample_bundle_input();
    let payload = CanonicalVerifierBundleV2Payload::from_input(&input);
    let artifact = ProofMaterialV2::new(
        supported_type(),
        ExtensionPayloadV2::canonical_verifier_bundle(payload),
    );
    let expected_hash = artifact
        .proof_material_hash()
        .expect("supported artifact hash should succeed");

    ProofMaterialV2VerifyRequest::new(
        supported_type(),
        artifact,
        ExtensionInputV2::canonical_verifier_bundle(input),
        expected_hash,
    )
}

#[test]
fn supported_adapter_set_remains_fail_closed_without_concrete_adapter() {
    assert_eq!(supported_verifier_adapter_types_v2(), &[]);
    assert!(!is_supported_verifier_adapter_type_v2(supported_type()));
    assert!(!is_supported_verifier_adapter_type_v2(unsupported_type()));

    let request = VerifierAdapterVerifyRequestV2::new(
        supported_proof_material_request(),
        VerifierAdapterInputV2::opaque(supported_type(), vec![0xaa, 0xbb]),
    );

    assert_eq!(request.verify_type_binding(), Ok(()));
    assert_eq!(
        verify_with_adapter_v2(&request),
        Err(VerifierAdapterV2Error::UnsupportedProofMaterialType {
            actual: supported_type(),
        })
    );
}

#[test]
fn adapter_input_type_mismatch_rejects_before_lower_layer_verification() {
    let request = VerifierAdapterVerifyRequestV2::new(
        supported_proof_material_request(),
        VerifierAdapterInputV2::opaque(unsupported_type(), vec![0x01]),
    );

    assert_eq!(
        request.verify_type_binding(),
        Err(VerifierAdapterV2Error::AdapterInputTypeMismatch {
            expected_type: supported_type(),
            input_type: unsupported_type(),
        })
    );
    assert_eq!(
        verify_with_adapter_v2(&request),
        Err(VerifierAdapterV2Error::AdapterInputTypeMismatch {
            expected_type: supported_type(),
            input_type: unsupported_type(),
        })
    );
}

#[test]
fn direct_and_build_generated_supported_requests_fail_closed_identically_without_adapter_owner() {
    let direct_request = VerifierAdapterVerifyRequestV2::new(
        direct_supported_proof_material_request(),
        VerifierAdapterInputV2::opaque(supported_type(), vec![0xa0]),
    );
    let built_request = VerifierAdapterVerifyRequestV2::new(
        supported_proof_material_request(),
        VerifierAdapterInputV2::opaque(supported_type(), vec![0xb0]),
    );
    let expected = Err(VerifierAdapterV2Error::UnsupportedProofMaterialType {
        actual: supported_type(),
    });

    assert_eq!(direct_request.verify_type_binding(), Ok(()));
    assert_eq!(built_request.verify_type_binding(), Ok(()));
    assert_eq!(verify_with_adapter_v2(&direct_request), expected);
    assert_eq!(verify_with_adapter_v2(&built_request), expected);
}

#[test]
fn lower_layer_failures_propagate_before_adapter_ownership_failure() {
    let request = supported_proof_material_request();
    let bad_request = VerifierAdapterVerifyRequestV2::new(
        ProofMaterialV2VerifyRequest::new(
            request.expected_type,
            request.artifact.clone(),
            ExtensionInputV2::canonical_verifier_bundle(sample_bundle_input()),
            [0x99; 32],
        ),
        VerifierAdapterInputV2::opaque(supported_type(), vec![0x02]),
    );

    assert_eq!(bad_request.verify_type_binding(), Ok(()));
    assert_eq!(
        verify_with_adapter_v2(&bad_request),
        Err(VerifierAdapterV2Error::ProofMaterialVerificationFailed(
            ProofMaterialV2Error::ProofMaterialHashMismatch,
        ))
    );
}

#[test]
fn lower_layer_input_type_mismatch_propagates_before_adapter_ownership_failure() {
    let request = supported_proof_material_request();
    let bad_request = VerifierAdapterVerifyRequestV2::new(
        ProofMaterialV2VerifyRequest::new(
            request.expected_type,
            request.artifact.clone(),
            ExtensionInputV2::opaque(unsupported_type(), vec![0x55]),
            request.expected_proof_material_hash,
        ),
        VerifierAdapterInputV2::opaque(supported_type(), vec![0x03]),
    );

    assert_eq!(bad_request.verify_type_binding(), Ok(()));
    assert_eq!(
        verify_with_adapter_v2(&bad_request),
        Err(VerifierAdapterV2Error::ProofMaterialVerificationFailed(
            ProofMaterialV2Error::VerifyExpectedInputTypeMismatch {
                expected_type: supported_type(),
                input_type: unsupported_type(),
            },
        ))
    );
}
