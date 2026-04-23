mod support;

use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, produce_native_layer2_authorization_lineage_object_521_v1,
    prove_layer3_authorization_lineage_real_stark_v1,
    verify_layer3_authorization_lineage_real_stark_v1, DcmExecution521V1, DcmInput521V1,
    Layer1Layer2BridgeFreshnessV1, Layer1Layer2BridgeIntentSourceV1,
    Layer1Layer2BridgeSubjectBindingV1, Layer3AuthorizationLineageBoundaryErrorV1,
    Layer3AuthorizationLineageProverErrorV1, Layer3AuthorizationLineageProvingInputV1,
    Layer3AuthorizationLineageVerifierErrorV1, SubjectBindingTypeV1,
};
use sha2::Digest;

use support::{
    canonical_dcm_config, canonical_freshness, canonical_intent, canonical_subject_binding,
    changed_dcm_input,
};

#[test]
fn canonical_layer3_authorization_lineage_proof_succeeds() {
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical layer3 authorization-lineage proof should succeed");
    let acceptance = verify_layer3_authorization_lineage_real_stark_v1(&proof)
        .expect("canonical layer3 authorization-lineage proof should verify");

    assert_eq!(
        acceptance.lower_layer_claim,
        proof.public_claim.lower_layer_claim
    );
    assert_eq!(
        acceptance.lineage_hash,
        proof.public_claim.layer2_object.lineage_hash
    );
    assert_eq!(
        acceptance.intent_hash,
        proof.public_claim.layer2_object.lineage.intent_hash
    );
    assert_eq!(
        acceptance.dcm_commitment_root,
        proof.public_claim.lower_layer_claim.commitment_root
    );
    assert_eq!(
        acceptance.dcm_trace_commitment,
        proof
            .public_claim
            .layer2_object
            .lineage
            .dcm_trace_commitment
    );
    assert_eq!(
        acceptance.layer3_transcript_digest,
        proof.transcript.transcript_digest
    );
    assert_eq!(
        acceptance.layer3_proof_bound_transcript_digest,
        proof.proof_bound_transcript_digest
    );
    assert_eq!(
        acceptance.proof_binding_digest,
        proof.proof_artifact.proof_binding_digest
    );
}

#[test]
fn canonical_layer3_authorization_lineage_proof_is_deterministic() {
    let first = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("first proof should succeed");
    let second = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("second proof should succeed");

    assert_eq!(first.transcript, second.transcript);
    assert_eq!(
        first.proof_bound_transcript_digest,
        second.proof_bound_transcript_digest
    );
    assert_eq!(
        first.proof_artifact.proof_bytes_digest,
        second.proof_artifact.proof_bytes_digest
    );
    assert_eq!(
        first.proof_artifact.proof_binding_digest,
        second.proof_artifact.proof_binding_digest
    );
}

#[test]
fn proving_rejects_layer2_object_from_different_execution() {
    let mut input = canonical_input();
    input.public_claim.layer2_object = layer2_object_for_input(changed_dcm_input());

    let error = prove_layer3_authorization_lineage_real_stark_v1(&input).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageProverErrorV1::BoundaryValidationFailed(
            Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
                field: "public_claim.layer2_object.dcm_commitment_root",
                ..
            }
        )
    ));
}

#[test]
fn verify_rejects_wrong_intent_body() {
    let mut proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut wrong_intent = canonical_intent();
    wrong_intent.sender_nonce += 1;
    proof.intent_body = wrong_intent;

    let error = verify_layer3_authorization_lineage_real_stark_v1(&proof).unwrap_err();
    assert_eq!(
        error,
        Layer3AuthorizationLineageVerifierErrorV1::BoundaryValidationFailed(
            Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
                field: "public_claim.layer2_object.intent_hash",
                expected: proof.intent_body.intent_hash().unwrap(),
                actual: proof.public_claim.layer2_object.lineage.intent_hash,
            }
        )
    );
}

#[test]
fn verify_rejects_tampered_layer2_trace_commitment() {
    let mut proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let mut lineage = proof.public_claim.layer2_object.lineage;
    lineage.dcm_trace_commitment[0] ^= 0x01;
    proof.public_claim.layer2_object =
        aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1::new(lineage)
            .expect("tampered lineage remains structurally valid");

    let error = verify_layer3_authorization_lineage_real_stark_v1(&proof).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageVerifierErrorV1::BoundaryValidationFailed(
            Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
                field: "public_claim.layer2_object.dcm_trace_commitment",
                ..
            }
        )
    ));
}

#[test]
fn verify_ignores_proof_material_hash_substituted_for_layer2_lineage_hash() {
    let mut proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    let canonical_hash = proof.public_claim.layer2_object.lineage.lineage_hash().unwrap();
    let alternate_hash =
        layer2_proof_material_hash_from_lineage_hash(proof.public_claim.layer2_object.lineage_hash);
    assert_ne!(alternate_hash, canonical_hash);
    proof.public_claim.layer2_object.lineage_hash = alternate_hash;

    let acceptance = verify_layer3_authorization_lineage_real_stark_v1(&proof)
        .expect("helper-only lineage hash drift should be ignored");
    assert_eq!(acceptance.lineage_hash, canonical_hash);
}

#[test]
fn verify_rejects_tampered_transcript_digest() {
    let mut proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    proof.transcript.transcript_digest[0] ^= 0x01;

    let error = verify_layer3_authorization_lineage_real_stark_v1(&proof).unwrap_err();
    assert_eq!(
        error,
        Layer3AuthorizationLineageVerifierErrorV1::TranscriptMismatch {
            field: "transcript_digest",
        }
    );
}

#[test]
fn verify_rejects_tampered_real_stark_proof_bytes() {
    let mut proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical proof should succeed");
    proof.proof_artifact.proof_bytes[0] ^= 0x01;

    let error = verify_layer3_authorization_lineage_real_stark_v1(&proof).unwrap_err();
    assert!(matches!(
        error,
        Layer3AuthorizationLineageVerifierErrorV1::RealStarkVerifierRejected(_)
    ));
}

fn canonical_input() -> Layer3AuthorizationLineageProvingInputV1 {
    input_for_dcm_input(DcmInput521V1::from_u64(3, 7))
}

fn input_for_dcm_input(dcm_input: DcmInput521V1) -> Layer3AuthorizationLineageProvingInputV1 {
    let config = canonical_dcm_config();
    let execution = DcmExecution521V1::run(&config, &dcm_input).unwrap();
    let claim = build_dcm_claim_521_v1(&config, &dcm_input, &execution);
    Layer3AuthorizationLineageProvingInputV1::new(
        claim,
        layer2_object_for_input(dcm_input),
        canonical_intent(),
    )
}

fn layer2_object_for_input(
    dcm_input: DcmInput521V1,
) -> aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1 {
    produce_native_layer2_authorization_lineage_object_521_v1(
        &canonical_dcm_config(),
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
    .unwrap()
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
