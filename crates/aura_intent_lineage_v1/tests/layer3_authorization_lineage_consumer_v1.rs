mod support;

use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, consume_layer3_authorization_lineage_consumer_object_v1,
    produce_layer3_authorization_lineage_consumer_object_v1,
    produce_native_layer2_authorization_lineage_object_521_v1,
    prove_layer3_authorization_lineage_real_stark_v1, DcmExecution521V1, DcmInput521V1,
    Layer1Layer2BridgeFreshnessV1, Layer1Layer2BridgeIntentSourceV1,
    Layer1Layer2BridgeSubjectBindingV1, Layer3AuthorizationLineageConsumerDecisionV1,
    Layer3AuthorizationLineageConsumerErrorV1, Layer3AuthorizationLineageProvingInputV1,
    NativeLayer2AuthorizationLineageObjectV1, SubjectBindingTypeV1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
};
use sha2::Digest;

use support::{
    canonical_dcm_config, canonical_freshness, canonical_intent, canonical_subject_binding,
    changed_dcm_input,
};

#[test]
fn canonical_layer3_authorization_lineage_consumer_object_succeeds() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical layer3 proof should succeed");
    let object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical layer3 consumer object should succeed");
    let acceptance = consume_layer3_authorization_lineage_consumer_object_v1(&object)
        .expect("canonical layer3 consumer object should validate");

    assert_eq!(
        acceptance.decision,
        Layer3AuthorizationLineageConsumerDecisionV1::AcceptVerifiedProofV1
    );
    assert_eq!(
        acceptance.proof_result.lineage_commitment,
        object.public_claim.layer2_object.lineage_commitment
    );
    assert_eq!(
        acceptance.proof_result.lineage_hash,
        object.public_claim.layer2_object.lineage_hash
    );
    assert_eq!(
        acceptance.proof_result.result_commitment,
        object.proof_result.result_commitment
    );
    assert_eq!(
        acceptance.proof_result.dcm_commitment_root,
        object.public_claim.lower_layer_claim.commitment_root
    );
    assert_eq!(
        acceptance.proof_result.intent_hash,
        object.public_claim.layer2_object.lineage.intent_hash
    );
    assert_eq!(
        acceptance.proof_result.layer3_proof_bound_transcript_digest,
        proof.proof_bound_transcript_digest
    );
    assert_eq!(
        acceptance.proof_result.layer3_proof_binding_digest,
        proof.proof_artifact.proof_binding_digest
    );
    assert_eq!(
        object
            .consumer_commitment()
            .expect("consumer commitment should succeed"),
        acceptance.consumer_object_commitment
    );
    assert_eq!(
        object
            .consumer_hash()
            .expect("consumer hash should succeed"),
        acceptance.consumer_object_hash
    );
}

#[test]
fn layer3_authorization_lineage_consumer_object_is_deterministic() {
    let first_proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("first proof should succeed");
    let second_proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("second proof should succeed");

    let first = produce_layer3_authorization_lineage_consumer_object_v1(&first_proof)
        .expect("first consumer object should succeed");
    let second = produce_layer3_authorization_lineage_consumer_object_v1(&second_proof)
        .expect("second consumer object should succeed");

    assert_eq!(first, second);
    assert_eq!(
        first.serialized_object().unwrap(),
        second.serialized_object().unwrap()
    );
    assert_eq!(
        first.consumer_commitment().unwrap(),
        second.consumer_commitment().unwrap()
    );
    assert_eq!(
        first.consumer_hash().unwrap(),
        second.consumer_hash().unwrap()
    );
}

#[test]
fn validation_rejects_version_mismatch() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    object.consumer_version += 1;

    assert_eq!(
        consume_layer3_authorization_lineage_consumer_object_v1(&object),
        Err(Layer3AuthorizationLineageConsumerErrorV1::InvalidVersion {
            expected: 1,
            actual: 2,
        })
    );
}

#[test]
fn validation_rejects_tampered_proof_result() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    object.proof_result.layer3_proof_binding_digest[0] ^= 0x01;

    let error = consume_layer3_authorization_lineage_consumer_object_v1(&object).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageConsumerErrorV1::CommitmentMismatch {
            field: "proof_result.result_commitment",
            ..
        }
    ));
}

#[test]
fn helper_public_claim_digest_drift_is_ignored_for_acceptance() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    object.proof_result.public_claim_digest[0] ^= 0x01;
    object.proof_result.result_digest = canonical_consumer_result_digest(
        object.decision,
        &object.proof_result,
    );

    let acceptance = consume_layer3_authorization_lineage_consumer_object_v1(&object)
        .expect("helper digest drift should not reject");
    assert_eq!(
        acceptance.proof_result.public_claim_digest,
        produce_layer3_authorization_lineage_consumer_object_v1(&proof)
            .unwrap()
            .proof_result
            .public_claim_digest
    );
}

#[test]
fn validation_rejects_tampered_layer2_binding() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    let mut lineage = object.public_claim.layer2_object.lineage;
    lineage.dcm_trace_commitment[0] ^= 0x01;
    object.public_claim.layer2_object = NativeLayer2AuthorizationLineageObjectV1::new(lineage)
        .expect("tampered lineage remains structurally valid");

    let error = consume_layer3_authorization_lineage_consumer_object_v1(&object).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageConsumerErrorV1::HashMismatch {
            field: "public_claim.layer2_object.dcm_trace_commitment",
            ..
        }
    ));
}

#[test]
fn helper_lineage_hash_drift_is_ignored_for_acceptance() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    let alternate_hash =
        layer2_proof_material_hash_from_lineage_hash(object.public_claim.layer2_object.lineage_hash);
    assert_ne!(alternate_hash, object.public_claim.layer2_object.lineage_hash);
    object.proof_result.lineage_hash = alternate_hash;

    let acceptance = consume_layer3_authorization_lineage_consumer_object_v1(&object)
        .expect("helper digest drift should not reject");
    assert_eq!(
        acceptance.proof_result.lineage_hash,
        produce_layer3_authorization_lineage_consumer_object_v1(&proof)
            .unwrap()
            .proof_result
            .lineage_hash
    );
}

#[test]
fn primary_result_commitment_mutation_rejects_even_if_helper_digest_is_repaired() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    object.proof_result.result_commitment = object.public_claim.layer2_object.lineage_commitment;
    object.proof_result.result_digest = canonical_consumer_result_digest(
        object.decision,
        &object.proof_result,
    );

    let error = consume_layer3_authorization_lineage_consumer_object_v1(&object).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageConsumerErrorV1::CommitmentMismatch {
            field: "proof_result.result_commitment",
            ..
        }
    ));
}

#[test]
fn validation_rejects_public_claim_mismatch() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut object = produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical consumer object should succeed");
    let wrong_input = changed_dcm_input();
    let wrong_execution = DcmExecution521V1::run(&canonical_dcm_config(), &wrong_input)
        .expect("changed execution should succeed");
    object.public_claim.lower_layer_claim =
        build_dcm_claim_521_v1(&canonical_dcm_config(), &wrong_input, &wrong_execution);

    let error = consume_layer3_authorization_lineage_consumer_object_v1(&object).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageConsumerErrorV1::HashMismatch {
            field: "public_claim.layer2_object.dcm_commitment_root",
            ..
        }
    ));
}

fn canonical_input() -> Layer3AuthorizationLineageProvingInputV1 {
    let dcm_input = DcmInput521V1::from_u64(3, 7);
    let config = canonical_dcm_config();
    let execution = DcmExecution521V1::run(&config, &dcm_input).unwrap();
    let claim = build_dcm_claim_521_v1(&config, &dcm_input, &execution);

    Layer3AuthorizationLineageProvingInputV1::new(
        claim,
        produce_native_layer2_authorization_lineage_object_521_v1(
            &config,
            &dcm_input,
            Layer1Layer2BridgeIntentSourceV1::IntentBody(canonical_intent()),
            Layer1Layer2BridgeSubjectBindingV1 {
                subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
                subject_id: canonical_subject_binding().subject_id,
                subject_public_key: canonical_subject_binding().subject_public_key,
            },
            Layer1Layer2BridgeFreshnessV1 {
                freshness_mode: canonical_freshness().freshness_mode,
                freshness_nonce: canonical_freshness().freshness_nonce,
                freshness_reference: canonical_freshness().freshness_reference,
            },
        )
        .unwrap(),
        canonical_intent(),
    )
}

fn layer2_proof_material_hash_from_lineage_hash(lineage_hash: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AURA_PROOF_MATERIAL_V2");
    bytes.push(2);
    bytes.extend_from_slice(&0x2001u16.to_le_bytes());
    bytes.extend_from_slice(&lineage_hash);
    let digest = sha2::Sha256::digest(&bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn canonical_consumer_result_digest(
    decision: Layer3AuthorizationLineageConsumerDecisionV1,
    proof_result: &aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerProofResultV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.push(decision.as_u8());
    bytes.extend_from_slice(&proof_result.public_claim_digest);
    bytes.extend_from_slice(&proof_result.layer3_transcript_digest);
    bytes.extend_from_slice(&proof_result.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&proof_result.layer3_proof_binding_digest);
    bytes.extend_from_slice(&proof_result.lineage_hash);
    bytes.extend_from_slice(&proof_result.dcm_commitment_root);
    bytes.extend_from_slice(&proof_result.dcm_trace_commitment);
    bytes.extend_from_slice(&proof_result.intent_hash);
    let digest = sha2::Sha256::digest(
        [
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
            &bytes,
        ]
        .concat(),
    );
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}
