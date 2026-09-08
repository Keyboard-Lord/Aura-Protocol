use aura_sdk_v1::{legacy::build_settlement_pipeline_from_prepared_proof_v1, proof_hash_hex_from_wallet_visual_v1, legacy::validate_solana_settlement_request_v1, legacy::AuthorizationIntentEnvelopeV1, legacy::BuildSettlementPipelineFromPreparedProofRequestV1, legacy::SolanaCommitmentConfigV1, legacy::SolanaSettlementRequestWireV1, legacy::StarkProofEnvelopeV1, legacy::SubmitProofRequestWireV1};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const PROGRAM_ID_BASE58: &str = "11111111111111111111111111111111";
const SUBMITTER_PUBKEY_BASE58: &str = "11111111111111111111111111111111";
const CHALLENGE_PUBKEY_BASE58: &str = "11111111111111111111111111111111";
const INTENT_ID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROOF_SESSION_ID_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMMITMENT_ROOT_HEX: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SOLANA_RPC_URL: &str = "https://rpc.aura.invalid";

fn canonical_prepare_fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("canonical_prepare")
        .join(name)
}

fn load_canonical_prepare_hex(name: &str) -> String {
    fs::read_to_string(canonical_prepare_fixture_path(name))
        .unwrap()
        .trim()
        .to_owned()
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(chunk[0]) << 4) | decode_nibble(chunk[1]);
    }
    output
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex fixture"),
    }
}

fn canonical_prepared_submit_proof_v1() -> aura_sdk_v1::PreparedSubmitProofV1 {
    aura_sdk_v1::prepare_submit_proof_flow_v1(
        decode_hex_32(&load_canonical_prepare_hex("subject_pubkey.hex")),
        decode_hex_32(&load_canonical_prepare_hex("challenge_account_pubkey.hex")),
        &fs::read(canonical_prepare_fixture_path("proof_blob.bin")).unwrap(),
        &fs::read(canonical_prepare_fixture_path("public_inputs.bin")).unwrap(),
        &fs::read(canonical_prepare_fixture_path("verification_key.bin")).unwrap(),
    )
    .unwrap()
}

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

fn build_request() -> BuildSettlementPipelineFromPreparedProofRequestV1 {
    BuildSettlementPipelineFromPreparedProofRequestV1 {
        prepared_submit_proof: canonical_prepared_submit_proof_v1(),
        program_id_base58: PROGRAM_ID_BASE58.to_owned(),
        submitter_pubkey_base58: SUBMITTER_PUBKEY_BASE58.to_owned(),
        challenge_pubkey_base58: CHALLENGE_PUBKEY_BASE58.to_owned(),
        intent_id_hex: INTENT_ID_HEX.to_owned(),
        proof_session_id_hex: PROOF_SESSION_ID_HEX.to_owned(),
        iteration_count: 5,
        initial_state_hex: canonical_state_hex(0x11, 0x22),
        final_state_hex: canonical_state_hex(0x33, 0x44),
        commitment_root_hex: COMMITMENT_ROOT_HEX.to_owned(),
        solana_rpc_url: Some(SOLANA_RPC_URL.to_owned()),
        commitment_config: SolanaCommitmentConfigV1::Confirmed,
    }
}

#[test]
fn prepared_proof_pipeline_builder_emits_a_single_wallet_visual_surface() {
    let pipeline = build_settlement_pipeline_from_prepared_proof_v1(build_request()).unwrap();

    assert_eq!(
        pipeline.submit_proof_request_wire,
        pipeline.authorization_intent_envelope.submit_proof_request
    );
    assert_eq!(
        pipeline.authorization_intent_envelope,
        pipeline.stark_proof_envelope.authorization_intent
    );
    assert_eq!(
        pipeline.stark_proof_envelope,
        pipeline.solana_settlement_request_wire.stark_proof_envelope
    );
    assert_eq!(
        proof_hash_hex_from_wallet_visual_v1(&pipeline.submit_proof_request_wire.wallet_visual_v1)
            .unwrap(),
        pipeline.submit_proof_request_wire.proof_hash_hex
    );
}

#[test]
fn prepared_proof_pipeline_builder_keeps_wallet_visual_nested_without_parallel_wallet_fields() {
    let pipeline = build_settlement_pipeline_from_prepared_proof_v1(build_request()).unwrap();
    let settlement_value = serde_json::to_value(&pipeline.solana_settlement_request_wire).unwrap();

    assert!(settlement_value.get("proof_hash_hex").is_none());
    assert!(settlement_value.get("wallet_visual_v1").is_none());
    assert!(settlement_value.get("udot_bundle").is_none());
    assert_eq!(
        settlement_value.pointer(
            "/stark_proof_envelope/authorization_intent/submit_proof_request/proof_hash_hex"
        ),
        Some(&json!(pipeline.submit_proof_request_wire.proof_hash_hex))
    );
    assert_eq!(
        settlement_value.pointer(
            "/stark_proof_envelope/authorization_intent/submit_proof_request/wallet_visual_v1"
        ),
        Some(&json!(pipeline.submit_proof_request_wire.wallet_visual_v1))
    );
}

#[test]
fn prepared_proof_pipeline_builder_round_trips_through_current_wire_types() {
    let pipeline = build_settlement_pipeline_from_prepared_proof_v1(build_request()).unwrap();

    let reparsed_submit: SubmitProofRequestWireV1 =
        serde_json::from_value(serde_json::to_value(&pipeline.submit_proof_request_wire).unwrap())
            .unwrap();
    let reparsed_intent: AuthorizationIntentEnvelopeV1 = serde_json::from_value(
        serde_json::to_value(&pipeline.authorization_intent_envelope).unwrap(),
    )
    .unwrap();
    let reparsed_proof: StarkProofEnvelopeV1 =
        serde_json::from_value(serde_json::to_value(&pipeline.stark_proof_envelope).unwrap())
            .unwrap();
    let reparsed_settlement: SolanaSettlementRequestWireV1 = serde_json::from_value(
        serde_json::to_value(&pipeline.solana_settlement_request_wire).unwrap(),
    )
    .unwrap();

    assert_eq!(reparsed_submit, pipeline.submit_proof_request_wire);
    assert_eq!(reparsed_intent, pipeline.authorization_intent_envelope);
    assert_eq!(reparsed_proof, pipeline.stark_proof_envelope);
    assert_eq!(
        validate_solana_settlement_request_v1(reparsed_settlement.clone()).unwrap(),
        reparsed_settlement
    );
    assert_eq!(reparsed_settlement, pipeline.solana_settlement_request_wire);
}
