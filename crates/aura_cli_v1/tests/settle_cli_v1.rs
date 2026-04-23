use aura_cli_v1::Cli;
use clap::Parser;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const INTENT_ID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROOF_SESSION_ID_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROGRAM_ID_BASE58: &str = "11111111111111111111111111111111";
const SUBMITTER_PUBKEY_BASE58: &str = "11111111111111111111111111111111";
const CHALLENGE_PUBKEY_BASE58: &str = "11111111111111111111111111111111";
const PROOF_HASH_HEX: &str = "30701f142e89ace16515b1e32d18dba996e3adaa15cc1e5b42fded287506c7db";
const COMMITMENT_ROOT_HEX: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SOLANA_RPC_URL: &str = "https://rpc.aura.invalid";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("canonical_prepare")
        .join(name)
}

fn run_aura(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aura"))
        .args(args)
        .output()
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

#[test]
fn settle_generate_json_emits_wallet_visual_v1_without_parallel_wallet_fields() {
    let initial_state = canonical_state_hex(0x11, 0x22);
    let final_state = canonical_state_hex(0x33, 0x44);
    let output = run_aura(&[
        "settle",
        "generate",
        "--session-id",
        PROOF_SESSION_ID_HEX,
        "--iteration-count",
        "5",
        "--initial-state",
        &initial_state,
        "--final-state",
        &final_state,
        "--commitment-root",
        COMMITMENT_ROOT_HEX,
        "--intent-id",
        INTENT_ID_HEX,
        "--program-id",
        PROGRAM_ID_BASE58,
        "--submitter",
        SUBMITTER_PUBKEY_BASE58,
        "--challenge",
        CHALLENGE_PUBKEY_BASE58,
        "--proof-hash",
        PROOF_HASH_HEX,
        "--solana-rpc-url",
        SOLANA_RPC_URL,
        "--commitment-config",
        "processed",
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value.pointer(
            "/stark_proof_envelope/authorization_intent/submit_proof_request/proof_hash_hex"
        ),
        Some(&serde_json::json!(PROOF_HASH_HEX))
    );
    assert!(value
        .pointer("/stark_proof_envelope/authorization_intent/submit_proof_request/wallet_visual_v1")
        .is_some());
    assert!(value
        .pointer("/stark_proof_envelope/authorization_intent/submit_proof_request/udot_bundle")
        .is_none());
}

#[test]
fn settle_build_pipeline_json_emits_wallet_visual_v1_without_parallel_wallet_fields() {
    let output = run_aura(&[
        "settle",
        "build-pipeline",
        "--subject",
        &std::fs::read_to_string(fixture_path("subject_pubkey.hex")).unwrap().trim(),
        "--challenge",
        &std::fs::read_to_string(fixture_path("challenge_account_pubkey.hex")).unwrap().trim(),
        "--proof-blob",
        fixture_path("proof_blob.bin").to_str().unwrap(),
        "--public-inputs",
        fixture_path("public_inputs.bin").to_str().unwrap(),
        "--verification-key",
        fixture_path("verification_key.bin").to_str().unwrap(),
        "--intent-id",
        INTENT_ID_HEX,
        "--session-id",
        PROOF_SESSION_ID_HEX,
        "--iteration-count",
        "5",
        "--initial-state",
        &canonical_state_hex(0x11, 0x22),
        "--final-state",
        &canonical_state_hex(0x33, 0x44),
        "--commitment-root",
        COMMITMENT_ROOT_HEX,
        "--program-id",
        PROGRAM_ID_BASE58,
        "--submitter",
        SUBMITTER_PUBKEY_BASE58,
        "--challenge-pubkey",
        CHALLENGE_PUBKEY_BASE58,
        "--solana-rpc-url",
        SOLANA_RPC_URL,
        "--commitment-config",
        "processed",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value
        .pointer("/submit_proof_request_wire/wallet_visual_v1")
        .is_some());
    assert!(value
        .pointer("/submit_proof_request_wire/udot_bundle")
        .is_none());
}

#[test]
fn settle_generate_text_mode_prints_wallet_visual_v1_only() {
    let output = run_aura(&[
        "settle",
        "generate",
        "--session-id",
        PROOF_SESSION_ID_HEX,
        "--iteration-count",
        "5",
        "--initial-state",
        &canonical_state_hex(0x11, 0x22),
        "--final-state",
        &canonical_state_hex(0x33, 0x44),
        "--commitment-root",
        COMMITMENT_ROOT_HEX,
        "--intent-id",
        INTENT_ID_HEX,
        "--program-id",
        PROGRAM_ID_BASE58,
        "--submitter",
        SUBMITTER_PUBKEY_BASE58,
        "--challenge",
        CHALLENGE_PUBKEY_BASE58,
        "--proof-hash",
        PROOF_HASH_HEX,
        "--solana-rpc-url",
        SOLANA_RPC_URL,
        "--commitment-config",
        "processed",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("wallet_visual_v1:"));
    assert!(!stdout.contains("seal_line:"));
    assert!(!stdout.contains("udot_version:"));
}

#[test]
fn settle_generate_rejects_removed_udot_version_flag() {
    let error = Cli::try_parse_from([
        "aura",
        "settle",
        "generate",
        "--session-id",
        PROOF_SESSION_ID_HEX,
        "--iteration-count",
        "5",
        "--initial-state",
        &canonical_state_hex(0x11, 0x22),
        "--final-state",
        &canonical_state_hex(0x33, 0x44),
        "--commitment-root",
        COMMITMENT_ROOT_HEX,
        "--intent-id",
        INTENT_ID_HEX,
        "--program-id",
        PROGRAM_ID_BASE58,
        "--submitter",
        SUBMITTER_PUBKEY_BASE58,
        "--challenge",
        CHALLENGE_PUBKEY_BASE58,
        "--proof-hash",
        PROOF_HASH_HEX,
        "--udot-version",
        "v2",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("--udot-version"));
}
