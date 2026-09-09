use aura_sdk_v1::{legacy::build_submit_proof_request_wire_v1, legacy::generate_submit_proof_request_v1, proof_hash_hex_from_wallet_visual_v1, legacy::validate_submit_proof_request_wire_v1, AuraSdkErrorV1, legacy::BuildSubmitProofRequestWireRequestV1, legacy::GenerateSubmitProofRequestV1, legacy::SubmitProofRequestWireV1};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "support/canonical_pipeline_fixture_v1.rs"]
mod canonical_pipeline_fixture_v1;

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

fn canonical_prepared_submit_proof_v1() -> aura_sdk_v1::legacy::PreparedSubmitProofV1 {
    aura_sdk_v1::legacy::prepare_submit_proof_flow_v1(
        decode_hex_32(&load_canonical_prepare_hex("subject_pubkey.hex")),
        decode_hex_32(&load_canonical_prepare_hex("challenge_account_pubkey.hex")),
        &fs::read(canonical_prepare_fixture_path("proof_blob.bin")).unwrap(),
        &fs::read(canonical_prepare_fixture_path("public_inputs.bin")).unwrap(),
        &fs::read(canonical_prepare_fixture_path("verification_key.bin")).unwrap(),
    )
    .unwrap()
}

fn canonical_submit_fixture_v1() -> SubmitProofRequestWireV1 {
    canonical_pipeline_fixture_v1::load_canonical_pipeline_fixture_json_v1(
        "submit_proof_request_v1.json",
    )
}

fn assert_wallet_visual_shape(wallet_visual_v1: &str) {
    let rows = wallet_visual_v1.split('\n').collect::<Vec<_>>();
    assert_eq!(rows.len(), 8);
    for row in rows {
        assert_eq!(row.chars().count(), 8);
    }
    assert!(!wallet_visual_v1.ends_with('\n'));
}

#[test]
fn build_submit_proof_request_wire_matches_the_canonical_wallet_fixture() {
    let fixture = canonical_submit_fixture_v1();
    let request = build_submit_proof_request_wire_v1(BuildSubmitProofRequestWireRequestV1 {
        prepared_submit_proof: canonical_prepared_submit_proof_v1(),
        program_id_base58: fixture.program_id_base58.clone(),
        submitter_pubkey_base58: fixture.submitter_pubkey_base58.clone(),
        challenge_pubkey_base58: fixture.challenge_pubkey_base58.clone(),
    })
    .unwrap();

    assert_eq!(request, fixture);
    assert_eq!(
        proof_hash_hex_from_wallet_visual_v1(&request.wallet_visual_v1).unwrap(),
        request.proof_hash_hex
    );
    assert_wallet_visual_shape(&request.wallet_visual_v1);
}

#[test]
fn generate_submit_proof_request_uses_wallet_visual_v1_as_the_only_wallet_surface() {
    let fixture = canonical_submit_fixture_v1();
    let request = generate_submit_proof_request_v1(GenerateSubmitProofRequestV1 {
        program_id_base58: fixture.program_id_base58.clone(),
        submitter_pubkey_base58: fixture.submitter_pubkey_base58.clone(),
        challenge_pubkey_base58: fixture.challenge_pubkey_base58.clone(),
        proof_hash_hex: fixture.proof_hash_hex.clone(),
    })
    .unwrap();

    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value,
        json!({
            "program_id_base58": fixture.program_id_base58,
            "submitter_pubkey_base58": fixture.submitter_pubkey_base58,
            "challenge_pubkey_base58": fixture.challenge_pubkey_base58,
            "proof_hash_hex": fixture.proof_hash_hex,
            "wallet_visual_v1": fixture.wallet_visual_v1,
        })
    );
    assert!(value.get("udot_bundle").is_none());
    assert!(value.get("seal_line").is_none());
    assert!(value.get("crest").is_none());
}

#[test]
fn submit_request_wire_json_rejects_alternate_wallet_peer_fields() {
    let fixture = canonical_submit_fixture_v1();

    let seal_line_error = serde_json::from_value::<SubmitProofRequestWireV1>(json!({
        "program_id_base58": fixture.program_id_base58,
        "submitter_pubkey_base58": fixture.submitter_pubkey_base58,
        "challenge_pubkey_base58": fixture.challenge_pubkey_base58,
        "proof_hash_hex": fixture.proof_hash_hex,
        "wallet_visual_v1": fixture.wallet_visual_v1,
        "seal_line": "forbidden"
    }))
    .unwrap_err();
    assert!(seal_line_error.to_string().contains("unknown field `seal_line`"));

    let bundle_error = serde_json::from_value::<SubmitProofRequestWireV1>(json!({
        "program_id_base58": fixture.program_id_base58,
        "submitter_pubkey_base58": fixture.submitter_pubkey_base58,
        "challenge_pubkey_base58": fixture.challenge_pubkey_base58,
        "proof_hash_hex": fixture.proof_hash_hex,
        "wallet_visual_v1": fixture.wallet_visual_v1,
        "udot_bundle": {"seal_line": "forbidden"}
    }))
    .unwrap_err();
    assert!(bundle_error.to_string().contains("unknown field `udot_bundle`"));
}

#[test]
fn validate_submit_proof_request_wire_rejects_malformed_wallet_visuals() {
    let fixture = canonical_submit_fixture_v1();
    let mut rows = fixture.wallet_visual_v1.split('\n').map(str::to_owned).collect::<Vec<_>>();
    rows[0].pop();

    let error = validate_submit_proof_request_wire_v1(SubmitProofRequestWireV1 {
        wallet_visual_v1: rows.join("\n"),
        ..fixture
    })
    .unwrap_err();

    assert!(matches!(error, AuraSdkErrorV1::UdotArtifactValidationFailed(_)));
    assert!(error.to_string().contains("row length"));
}

#[test]
fn validate_submit_proof_request_wire_rejects_non_round_trippable_wallet_visuals() {
    let fixture = canonical_submit_fixture_v1();
    let error = validate_submit_proof_request_wire_v1(SubmitProofRequestWireV1 {
        wallet_visual_v1: fixture.wallet_visual_v1.replacen('○', "◌", 1),
        ..fixture
    })
    .unwrap_err();

    assert!(matches!(error, AuraSdkErrorV1::UdotArtifactValidationFailed(_)));
    assert!(error.to_string().contains("mismatch"));
}
