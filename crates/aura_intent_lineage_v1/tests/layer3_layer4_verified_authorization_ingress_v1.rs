mod support;

use aura_intent_lineage_v1::{
    accept_layer3_layer4_verified_authorization_ingress_v1,
    build_dcm_claim_521_v1, produce_layer3_authorization_lineage_consumer_object_v1,
    produce_layer3_layer4_verified_authorization_ingress_v1,
    produce_native_layer2_authorization_lineage_object_521_v1,
    prove_layer3_authorization_lineage_real_stark_v1, AuthorizationEnvelopeAuthKindV1,
    AuthorizationEnvelopeFreshnessContextV1, AuthorizationEnvelopeLineageTransportKindV1,
    AuthorizationEnvelopeV1, AuthorizationEnvelopeV1Decision, AuthorizationEnvelopeV1Error,
    consume_layer3_authorization_lineage_consumer_object_v1,
    derive_deterministic_commitment_521_v1, DcmExecution521V1, DcmInput521V1,
    Layer1Layer2BridgeFreshnessV1,
    Layer1Layer2BridgeIntentSourceV1, Layer1Layer2BridgeSubjectBindingV1,
    Layer3AuthorizationLineageProvingInputV1, Layer3Layer4VerifiedAuthorizationIngressErrorV1,
    SubjectBindingTypeV1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
    AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
};
use sha2::Digest;

use support::{
    canonical_dcm_config, canonical_freshness, canonical_intent, canonical_subject_binding,
};

#[test]
fn canonical_verified_authorization_ingress_succeeds() {
    let ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical verified authorization ingress should succeed");

    let context = ingress
        .canonical_layer4_intent_context()
        .expect("ingress should expose canonical layer4 context");
    let public_statement = ingress
        .verified_authorization_public_statement()
        .expect("ingress should expose verified public statement");

    assert_eq!(
        context.controlled_account_id,
        canonical_intent().sender_account_id
    );
    assert_eq!(context.sender_nonce, canonical_intent().sender_nonce);
    assert_eq!(
        context.envelope_validity_bounds.validity_flags,
        canonical_intent().validity_flags
    );
    assert_eq!(
        context.intent_hash,
        canonical_intent().intent_hash().unwrap()
    );

    assert_eq!(
        public_statement.lineage_commitment,
        ingress.layer2_object().lineage_commitment
    );
    assert_eq!(
        public_statement.lineage_hash,
        ingress.layer2_object().lineage_hash
    );
    assert_eq!(
        public_statement.subject_binding_type,
        canonical_subject_binding().subject_binding_type
    );
    assert_eq!(
        public_statement.subject_id,
        canonical_subject_binding().subject_id
    );
    assert_eq!(public_statement.intent_hash, context.intent_hash);
    assert_eq!(
        public_statement.freshness_mode,
        canonical_freshness().freshness_mode
    );
    assert_eq!(
        public_statement.freshness_nonce,
        canonical_freshness().freshness_nonce
    );
    assert_eq!(
        public_statement.freshness_reference,
        canonical_freshness().freshness_reference
    );
    assert_eq!(
        public_statement.layer3_result_commitment,
        ingress
            .verified_authorization_result()
            .unwrap()
            .result_commitment
    );
    assert_eq!(
        public_statement.layer3_proof_bound_transcript_digest,
        ingress
            .verified_authorization_result()
            .unwrap()
            .layer3_proof_bound_transcript_digest
    );
    assert_eq!(
        public_statement.layer3_proof_binding_digest,
        ingress
            .verified_authorization_result()
            .unwrap()
            .layer3_proof_binding_digest
    );
}

#[test]
fn centralized_acceptance_recomputes_full_commitment_chain() {
    let ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");

    let acceptance = accept_layer3_layer4_verified_authorization_ingress_v1(&ingress)
        .expect("centralized acceptance should succeed");

    assert_eq!(acceptance.lineage_commitment, ingress.layer2_object().lineage_commitment);
    assert_eq!(
        acceptance.result_commitment,
        ingress.consumer_object.proof_result.result_commitment
    );
    assert_eq!(
        acceptance.consumer_commitment,
        ingress.consumer_object.consumer_commitment().unwrap()
    );
    assert_eq!(acceptance.ingress_commitment, ingress.ingress_commitment().unwrap());
    assert_eq!(
        acceptance.public_statement_commitment,
        ingress
            .verified_authorization_public_statement_commitment()
            .unwrap()
    );
}

#[test]
fn verified_authorization_ingress_is_deterministic() {
    let first = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("first ingress should succeed");
    let second = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("second ingress should succeed");

    assert_eq!(
        first.verified_authorization_result().unwrap(),
        second.verified_authorization_result().unwrap()
    );
    assert_eq!(first.layer2_object(), second.layer2_object());
    assert_eq!(first.intent_body, second.intent_body);
    assert_eq!(
        first.serialized_object().unwrap(),
        second.serialized_object().unwrap()
    );
    assert_eq!(
        first.ingress_commitment().unwrap(),
        second.ingress_commitment().unwrap()
    );
    assert_eq!(
        first.ingress_hash().unwrap(),
        second.ingress_hash().unwrap()
    );
    assert_eq!(
        first.verified_authorization_public_statement_commitment().unwrap(),
        second.verified_authorization_public_statement_commitment().unwrap()
    );
}

#[test]
fn construction_rejects_tampered_consumer_object_binding() {
    let mut consumer = canonical_consumer_object();
    let mut lineage = consumer.public_claim.layer2_object.lineage;
    lineage.dcm_trace_commitment[0] ^= 0x01;
    consumer.public_claim.layer2_object =
        aura_intent_lineage_v1::NativeLayer2AuthorizationLineageObjectV1::new(lineage)
            .expect("tampered lineage remains structurally valid");

    let error =
        produce_layer3_layer4_verified_authorization_ingress_v1(&consumer, canonical_intent())
            .unwrap_err();
    assert!(matches!(
        error,
        Layer3Layer4VerifiedAuthorizationIngressErrorV1::Layer3ConsumerRejected(
            aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerErrorV1::HashMismatch {
                field: "public_claim.layer2_object.dcm_trace_commitment",
                ..
            }
        )
    ));
}

#[test]
fn validation_rejects_tampered_intent_context() {
    let mut ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");
    ingress.intent_body.sender_nonce += 1;

    let error = ingress.validate().unwrap_err();
    assert!(matches!(
        error,
        Layer3Layer4VerifiedAuthorizationIngressErrorV1::Layer3VerificationRejected(
            aura_intent_lineage_v1::Layer3AuthorizationLineageVerifierErrorV1::BoundaryValidationFailed(
                aura_intent_lineage_v1::Layer3AuthorizationLineageBoundaryErrorV1::HashMismatch {
                    field: "public_claim.layer2_object.intent_hash",
                    ..
                }
            )
        )
            | Layer3Layer4VerifiedAuthorizationIngressErrorV1::HashMismatch {
                field: "layer2_object.intent_hash",
                ..
            }
            | Layer3Layer4VerifiedAuthorizationIngressErrorV1::HashMismatch {
                field: "verified_authorization.intent_hash",
                ..
            }
    ));
}

#[test]
fn helper_lineage_hash_drift_in_consumer_object_does_not_break_full_chain_acceptance() {
    let mut ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");
    ingress.consumer_object.proof_result.lineage_hash[0] ^= 0x01;

    ingress
        .validate()
        .expect("helper digest drift should not break full-chain acceptance");
}

#[test]
fn validation_rejects_recomputed_consumer_result_with_noncanonical_layer3_transcript_digest() {
    let mut ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");
    ingress.consumer_object.proof_result.layer3_transcript_digest[0] ^= 0x01;
    ingress.consumer_object.proof_result.result_commitment =
        canonical_consumer_result_commitment(&ingress.consumer_object);
    ingress.consumer_object.proof_result.result_digest =
        canonical_consumer_result_digest(&ingress.consumer_object);

    let error = ingress.validate().unwrap_err();
    assert!(matches!(
        error,
        Layer3Layer4VerifiedAuthorizationIngressErrorV1::CommitmentMismatch {
            field: "consumer_object.proof_result.result_commitment",
            ..
        }
    ));
}

#[test]
fn helper_result_digest_drift_in_consumer_object_does_not_break_full_chain_acceptance() {
    let mut ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");
    ingress.consumer_object.proof_result.result_digest[0] ^= 0x01;

    ingress
        .validate()
        .expect("helper digest drift should not break full-chain acceptance");
}

#[test]
fn public_statement_binds_exact_consumer_digest_fields() {
    let ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");
    let acceptance = consume_layer3_authorization_lineage_consumer_object_v1(&ingress.consumer_object)
        .expect("consumer object should validate");
    let public_statement = ingress
        .verified_authorization_public_statement()
        .expect("ingress should expose verified public statement");

    assert_eq!(
        public_statement.layer3_transcript_digest,
        acceptance.proof_result.layer3_transcript_digest
    );
    assert_eq!(
        public_statement.layer3_proof_bound_transcript_digest,
        acceptance.proof_result.layer3_proof_bound_transcript_digest
    );
    assert_eq!(
        public_statement.layer3_proof_binding_digest,
        acceptance.proof_result.layer3_proof_binding_digest
    );
}

#[test]
fn active_envelope_path_still_rejects_proof_mediated_transport() {
    let ingress = produce_layer3_layer4_verified_authorization_ingress_v1(
        &canonical_consumer_object(),
        canonical_intent(),
    )
    .expect("canonical ingress should succeed");
    let context = ingress.canonical_layer4_intent_context().unwrap();

    let envelope = AuthorizationEnvelopeV1 {
        auth_version: 1,
        auth_kind: AuthorizationEnvelopeAuthKindV1::AuthorizationLineageV1ExactIntent,
        controlled_account_id: context.controlled_account_id,
        envelope_validity_bounds: context.envelope_validity_bounds,
        lineage_transport_kind:
            AuthorizationEnvelopeLineageTransportKindV1::ProofMediatedLineageStatementV1,
        lineage_hash: ingress.layer2_object().lineage_hash,
        inline_authorization_lineage_v1: None,
    };

    assert_eq!(
        envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default()),
        AuthorizationEnvelopeV1Decision::Reject(
            AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "proof_mediated_lineage_statement_not_implemented_in_thin_slice",
            }
        )
    );
}

fn canonical_consumer_object() -> aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1
{
    let proof = prove_layer3_authorization_lineage_real_stark_v1(&canonical_input())
        .expect("canonical layer3 proof should succeed");
    produce_layer3_authorization_lineage_consumer_object_v1(&proof)
        .expect("canonical layer3 consumer should succeed")
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

fn canonical_consumer_result_commitment(
    consumer_object: &aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1,
) -> aura_intent_lineage_v1::DeterministicCommitment521V1 {
    derive_deterministic_commitment_521_v1(
        AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_COMMITMENT_DOMAIN_SEPARATOR_V1,
        &canonical_consumer_result_material_bytes(consumer_object),
    )
}

fn canonical_consumer_result_digest(
    consumer_object: &aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1,
) -> [u8; 32] {
    let digest = sha2::Sha256::digest(
        [
            AURA_LAYER3_AUTHORIZATION_LINEAGE_CONSUMER_RESULT_DOMAIN_SEPARATOR_V1,
            &canonical_consumer_result_material_bytes(consumer_object),
        ]
        .concat(),
    );
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn canonical_consumer_result_material_bytes(
    consumer_object: &aura_intent_lineage_v1::Layer3AuthorizationLineageConsumerObjectV1,
) -> Vec<u8> {
    let layer2_preimage = consumer_object
        .public_claim
        .layer2_object
        .lineage
        .canonical_preimage()
        .unwrap();
    let mut bytes = Vec::new();
    bytes.push(consumer_object.decision.as_u8());
    bytes.extend_from_slice(&consumer_object.public_claim.lower_layer_claim.canonical_bytes());
    bytes.extend_from_slice(&layer2_preimage);
    bytes.extend_from_slice(
        &consumer_object
            .public_claim
            .layer2_object
            .lineage_commitment
            .to_bytes(),
    );
    bytes.extend_from_slice(&consumer_object.proof_result.layer3_transcript_digest);
    bytes.extend_from_slice(&consumer_object.proof_result.layer3_proof_bound_transcript_digest);
    bytes.extend_from_slice(&consumer_object.proof_result.layer3_proof_binding_digest);
    bytes
}
