use aura_sdk_v1::{legacy::generate_solana_settlement_request_v1, proof_hash_hex_from_wallet_visual_v1, legacy::validate_solana_settlement_request_v1, AuraSdkErrorV1, legacy::GenerateAuthorizationIntentV1, legacy::GenerateSolanaSettlementRequestV1, legacy::GenerateStarkProofEnvelopeV1, legacy::GenerateSubmitProofRequestV1, legacy::SolanaCommitmentConfigV1, legacy::SolanaSettlementRequestWireV1};
use serde_json::{json, Value};

const PROGRAM_ID_BASE58: &str = "11111111111111111111111111111111";
const SUBMITTER_PUBKEY_BASE58: &str = "11111111111111111111111111111111";
const CHALLENGE_PUBKEY_BASE58: &str = "11111111111111111111111111111111";
const INTENT_ID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROOF_SESSION_ID_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMMITMENT_ROOT_HEX: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PROOF_HASH_HEX: &str = "30701f142e89ace16515b1e32d18dba996e3adaa15cc1e5b42fded287506c7db";
const SOLANA_RPC_URL: &str = "https://rpc.aura.invalid";

fn canonical_state_hex(x_low: u8, y_low: u8) -> String {
    let mut bytes = vec![0u8; 132];
    bytes[65] = x_low;
    bytes[131] = y_low;
    encode_hex_lower(&bytes)
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn generate_request() -> GenerateSolanaSettlementRequestV1 {
    GenerateSolanaSettlementRequestV1 {
        solana_rpc_url: Some(SOLANA_RPC_URL.to_owned()),
        commitment_config: SolanaCommitmentConfigV1::Confirmed,
        stark_proof_envelope: GenerateStarkProofEnvelopeV1 {
            proof_session_id_hex: PROOF_SESSION_ID_HEX.to_owned(),
            iteration_count: 5,
            initial_state_hex: canonical_state_hex(0x11, 0x22),
            final_state_hex: canonical_state_hex(0x33, 0x44),
            commitment_root_hex: COMMITMENT_ROOT_HEX.to_owned(),
            authorization_intent: GenerateAuthorizationIntentV1 {
                intent_id_hex: INTENT_ID_HEX.to_owned(),
                submit_proof_request: GenerateSubmitProofRequestV1 {
                    program_id_base58: PROGRAM_ID_BASE58.to_owned(),
                    submitter_pubkey_base58: SUBMITTER_PUBKEY_BASE58.to_owned(),
                    challenge_pubkey_base58: CHALLENGE_PUBKEY_BASE58.to_owned(),
                    proof_hash_hex: PROOF_HASH_HEX.to_owned(),
                },
            },
        },
    }
}

#[test]
fn settlement_request_keeps_the_canonical_wallet_visual_nested_in_submit_request() {
    let settlement = generate_solana_settlement_request_v1(generate_request()).unwrap();
    let submit = &settlement.stark_proof_envelope.authorization_intent.submit_proof_request;

    assert_eq!(
        proof_hash_hex_from_wallet_visual_v1(&submit.wallet_visual_v1).unwrap(),
        PROOF_HASH_HEX
    );

    let value = serde_json::to_value(&settlement).unwrap();
    assert!(value.get("wallet_visual_v1").is_none());
    assert!(value.get("udot_bundle").is_none());
    assert_eq!(
        value.pointer("/stark_proof_envelope/authorization_intent/submit_proof_request"),
        Some(&json!({
            "program_id_base58": PROGRAM_ID_BASE58,
            "submitter_pubkey_base58": SUBMITTER_PUBKEY_BASE58,
            "challenge_pubkey_base58": CHALLENGE_PUBKEY_BASE58,
            "proof_hash_hex": PROOF_HASH_HEX,
            "wallet_visual_v1": submit.wallet_visual_v1,
        }))
    );
}

#[test]
fn settlement_request_rejects_alternate_wallet_peer_fields() {
    let settlement = generate_solana_settlement_request_v1(generate_request()).unwrap();
    let mut value = serde_json::to_value(&settlement).unwrap();
    value
        .pointer_mut("/stark_proof_envelope/authorization_intent/submit_proof_request")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert("udot_bundle".to_owned(), json!({"seal_line": "forbidden"}));

    let error = serde_json::from_value::<SolanaSettlementRequestWireV1>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field `udot_bundle`"));
}

#[test]
fn settlement_request_rejects_non_round_trippable_wallet_visuals() {
    let mut settlement = generate_solana_settlement_request_v1(generate_request()).unwrap();
    settlement
        .stark_proof_envelope
        .authorization_intent
        .submit_proof_request
        .wallet_visual_v1 = settlement
        .stark_proof_envelope
        .authorization_intent
        .submit_proof_request
        .wallet_visual_v1
        .replacen('○', "◌", 1);

    let error = validate_solana_settlement_request_v1(settlement).unwrap_err();
    assert!(matches!(error, AuraSdkErrorV1::UdotArtifactValidationFailed(_)));
    assert!(error.to_string().contains("mismatch"));
}

#[test]
fn settlement_request_rejects_bad_rpc_urls() {
    let error = generate_solana_settlement_request_v1(GenerateSolanaSettlementRequestV1 {
        solana_rpc_url: Some(" ".to_owned()),
        commitment_config: SolanaCommitmentConfigV1::Confirmed,
        ..generate_request()
    })
    .unwrap_err();

    assert!(matches!(
        error,
        AuraSdkErrorV1::SettlementFieldInvalid {
            field: "solana_rpc_url",
            ..
        }
    ));
}
