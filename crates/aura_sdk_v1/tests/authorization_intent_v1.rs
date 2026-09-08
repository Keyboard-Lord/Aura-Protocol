use aura_sdk_v1::{legacy::generate_authorization_intent_v1, proof_hash_hex_from_wallet_visual_v1, legacy::validate_authorization_intent_envelope_v1, AuraSdkErrorV1, legacy::AuthorizationIntentEnvelopeV1, legacy::GenerateAuthorizationIntentV1, legacy::GenerateSubmitProofRequestV1};
use serde_json::{json, Value};

#[path = "support/canonical_pipeline_fixture_v1.rs"]
mod canonical_pipeline_fixture_v1;

fn canonical_fixture_v1() -> AuthorizationIntentEnvelopeV1 {
    canonical_pipeline_fixture_v1::load_canonical_pipeline_fixture_json_v1(
        "authorization_intent_v1.json",
    )
}

#[test]
fn generate_authorization_intent_matches_the_canonical_wallet_fixture() {
    let fixture = canonical_fixture_v1();
    let generated = generate_authorization_intent_v1(GenerateAuthorizationIntentV1 {
        intent_id_hex: fixture.intent_id_hex.clone(),
        submit_proof_request: GenerateSubmitProofRequestV1 {
            program_id_base58: fixture.submit_proof_request.program_id_base58.clone(),
            submitter_pubkey_base58: fixture.submit_proof_request.submitter_pubkey_base58.clone(),
            challenge_pubkey_base58: fixture.submit_proof_request.challenge_pubkey_base58.clone(),
            proof_hash_hex: fixture.submit_proof_request.proof_hash_hex.clone(),
        },
    })
    .unwrap();

    assert_eq!(generated, fixture);
    assert_eq!(
        proof_hash_hex_from_wallet_visual_v1(&generated.submit_proof_request.wallet_visual_v1)
            .unwrap(),
        generated.submit_proof_request.proof_hash_hex
    );
}

#[test]
fn authorization_intent_rejects_alternate_wallet_peer_fields() {
    let fixture = canonical_fixture_v1();
    let mut value = serde_json::to_value(&fixture).unwrap();
    value
        .pointer_mut("/submit_proof_request")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert("seal_line".to_owned(), json!("forbidden"));

    let error = serde_json::from_value::<AuthorizationIntentEnvelopeV1>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field `seal_line`"));
}

#[test]
fn authorization_intent_rejects_non_round_trippable_wallet_visuals() {
    let mut fixture = canonical_fixture_v1();
    fixture.submit_proof_request.wallet_visual_v1 = fixture
        .submit_proof_request
        .wallet_visual_v1
        .replacen('○', "◌", 1);

    let error = validate_authorization_intent_envelope_v1(fixture).unwrap_err();
    assert!(matches!(error, AuraSdkErrorV1::UdotArtifactValidationFailed(_)));
    assert!(error.to_string().contains("mismatch"));
}
