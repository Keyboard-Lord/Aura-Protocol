use aura_sdk_v1::{legacy::generate_solana_settlement_request_v1, legacy::generate_submit_proof_request_v1, legacy::prepare_submit_proof_flow_v1, proof_hash_hex_from_wallet_visual_v1, AuraSdkErrorV1, legacy::GenerateAuthorizationIntentV1, legacy::GenerateSolanaSettlementRequestV1, legacy::GenerateStarkProofEnvelopeV1, legacy::GenerateSubmitProofRequestV1, legacy::SolanaCommitmentConfigV1, legacy::SolanaSettlementRequestWireV1, UdotHashError};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[path = "support/canonical_pipeline_fixture_v1.rs"]
mod canonical_pipeline_fixture_v1;

const PROGRAM_ID_BASE58: &str = "4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4";
const SUBMITTER_PUBKEY_BASE58: &str = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const CHALLENGE_PUBKEY_BASE58: &str = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
const INTENT_ID_HEX: &str = "7fbb895d47d0231a4b63d6637409833956fb9d19fa399624d0076ed8824bb288";
const PROOF_SESSION_ID_HEX: &str =
    "f30feec3d39040852dfef190c97d6af58405824749db861bc2b6cc99454f92cc";
const SOLANA_RPC_URL: &str = "https://rpc.aura.invalid";

fn canonical_prepare_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("canonical_prepare")
}

fn load_hex_fixture(name: &str) -> String {
    fs::read_to_string(canonical_prepare_fixture_dir().join(name))
        .unwrap()
        .trim()
        .to_owned()
}

fn load_bytes_fixture(name: &str) -> Vec<u8> {
    fs::read(canonical_prepare_fixture_dir().join(name)).unwrap()
}

fn decode_hex_32(input: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
    }
    bytes
}

fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}

fn canonical_prepared_submit_proof_v1() -> aura_sdk_v1::legacy::PreparedSubmitProofV1 {
    prepare_submit_proof_flow_v1(
        decode_hex_32(&load_hex_fixture("subject_pubkey.hex")),
        decode_hex_32(&load_hex_fixture("challenge_account_pubkey.hex")),
        &load_bytes_fixture("proof_blob.bin"),
        &load_bytes_fixture("public_inputs.bin"),
        &load_bytes_fixture("verification_key.bin"),
    )
    .unwrap()
}

#[test]
fn canonical_prepare_and_submit_fixture_stay_byte_exact_under_the_wallet_lock() {
    let prepared = canonical_prepared_submit_proof_v1();
    let proof_hash_hex = encode_hex_lower(&prepared.proof_hash);

    assert_eq!(proof_hash_hex, load_hex_fixture("proof_hash.hex"));

    let submit = generate_submit_proof_request_v1(GenerateSubmitProofRequestV1 {
        program_id_base58: PROGRAM_ID_BASE58.to_owned(),
        submitter_pubkey_base58: SUBMITTER_PUBKEY_BASE58.to_owned(),
        challenge_pubkey_base58: CHALLENGE_PUBKEY_BASE58.to_owned(),
        proof_hash_hex: proof_hash_hex.clone(),
    })
    .unwrap();
    assert_eq!(
        serde_json::to_string(&submit).unwrap(),
        canonical_pipeline_fixture_v1::load_canonical_pipeline_fixture_text_v1(
            "submit_proof_request_v1.json",
        )
    );
    assert_eq!(
        proof_hash_hex_from_wallet_visual_v1(&submit.wallet_visual_v1).unwrap(),
        proof_hash_hex
    );
}

#[test]
fn canonical_pipeline_rejects_non_canonical_uppercase_proof_hash_without_normalizing() {
    let error = generate_submit_proof_request_v1(GenerateSubmitProofRequestV1 {
        program_id_base58: PROGRAM_ID_BASE58.to_owned(),
        submitter_pubkey_base58: SUBMITTER_PUBKEY_BASE58.to_owned(),
        challenge_pubkey_base58: CHALLENGE_PUBKEY_BASE58.to_owned(),
        proof_hash_hex: load_hex_fixture("proof_hash.hex").to_uppercase(),
    })
    .unwrap_err();

    assert!(matches!(
        error,
        AuraSdkErrorV1::UdotHashNormalizationFailed(UdotHashError::NonCanonicalHex { .. })
    ));
}

#[test]
fn settlement_generation_keeps_wallet_identity_nested_at_submit_boundaries_only() {
    let prepared = canonical_prepared_submit_proof_v1();
    let proof_hash_hex = encode_hex_lower(&prepared.proof_hash);
    let settlement = generate_solana_settlement_request_v1(GenerateSolanaSettlementRequestV1 {
        solana_rpc_url: Some(SOLANA_RPC_URL.to_owned()),
        commitment_config: SolanaCommitmentConfigV1::Finalized,
        stark_proof_envelope: GenerateStarkProofEnvelopeV1 {
            proof_session_id_hex: PROOF_SESSION_ID_HEX.to_owned(),
            iteration_count: 5,
            initial_state_hex: "0".repeat(264),
            final_state_hex: "0".repeat(264),
            commitment_root_hex: "0".repeat(64),
            authorization_intent: GenerateAuthorizationIntentV1 {
                intent_id_hex: INTENT_ID_HEX.to_owned(),
                submit_proof_request: GenerateSubmitProofRequestV1 {
                    program_id_base58: PROGRAM_ID_BASE58.to_owned(),
                    submitter_pubkey_base58: SUBMITTER_PUBKEY_BASE58.to_owned(),
                    challenge_pubkey_base58: CHALLENGE_PUBKEY_BASE58.to_owned(),
                    proof_hash_hex,
                },
            },
        },
    })
    .unwrap();

    let value = serde_json::to_value(&settlement).unwrap();
    assert!(value.get("proof_hash_hex").is_none());
    assert!(value.get("wallet_visual_v1").is_none());
    assert_eq!(
        value.pointer(
            "/stark_proof_envelope/authorization_intent/submit_proof_request/proof_hash_hex"
        )
        .unwrap(),
        &json!(load_hex_fixture("proof_hash.hex"))
    );
    assert!(value
        .pointer("/stark_proof_envelope/authorization_intent/submit_proof_request/wallet_visual_v1")
        .is_some());
}

#[test]
fn settlement_wire_json_requires_explicit_solana_rpc_url_field() {
    let mut value: Value = serde_json::to_value(
        generate_solana_settlement_request_v1(GenerateSolanaSettlementRequestV1 {
            solana_rpc_url: Some(SOLANA_RPC_URL.to_owned()),
            commitment_config: SolanaCommitmentConfigV1::Finalized,
            stark_proof_envelope: GenerateStarkProofEnvelopeV1 {
                proof_session_id_hex: PROOF_SESSION_ID_HEX.to_owned(),
                iteration_count: 5,
                initial_state_hex: "0".repeat(264),
                final_state_hex: "0".repeat(264),
                commitment_root_hex: "0".repeat(64),
                authorization_intent: GenerateAuthorizationIntentV1 {
                    intent_id_hex: INTENT_ID_HEX.to_owned(),
                    submit_proof_request: GenerateSubmitProofRequestV1 {
                        program_id_base58: PROGRAM_ID_BASE58.to_owned(),
                        submitter_pubkey_base58: SUBMITTER_PUBKEY_BASE58.to_owned(),
                        challenge_pubkey_base58: CHALLENGE_PUBKEY_BASE58.to_owned(),
                        proof_hash_hex: load_hex_fixture("proof_hash.hex"),
                    },
                },
            },
        })
        .unwrap(),
    )
    .unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("solana_rpc_url")
        .expect("fixture must include solana_rpc_url");

    let error = serde_json::from_value::<SolanaSettlementRequestWireV1>(value).unwrap_err();
    assert!(error.to_string().contains("missing field `solana_rpc_url`"));
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
