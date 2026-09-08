use aura_cli_v1::Cli;
use aura_sdk_v1::legacy::SubmitProofRequestWireV1;
use clap::Parser;
use serde_json::Value;
use std::process::Command;

#[path = "../../aura_sdk_v1/tests/support/canonical_pipeline_fixture_v1.rs"]
mod canonical_pipeline_fixture_v1;

fn run_aura(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aura"))
        .args(args)
        .output()
        .unwrap()
}

fn canonical_submit_fixture_v1() -> SubmitProofRequestWireV1 {
    canonical_pipeline_fixture_v1::load_canonical_pipeline_fixture_json_v1(
        "submit_proof_request_v1.json",
    )
}

#[test]
fn submit_proof_generate_json_emits_the_canonical_wallet_surface() {
    let fixture = canonical_submit_fixture_v1();
    let output = run_aura(&[
        "submit-proof",
        "generate",
        "--program-id",
        &fixture.program_id_base58,
        "--submitter",
        &fixture.submitter_pubkey_base58,
        "--challenge",
        &fixture.challenge_pubkey_base58,
        "--proof-hash",
        &fixture.proof_hash_hex,
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value, serde_json::to_value(&fixture).unwrap());
    assert!(value.get("udot_bundle").is_none());
    assert!(value.get("seal_line").is_none());
    assert!(value.get("crest").is_none());
}

#[test]
fn submit_proof_generate_text_mode_prints_wallet_visual_v1_only() {
    let fixture = canonical_submit_fixture_v1();
    let output = run_aura(&[
        "submit-proof",
        "generate",
        "--program-id",
        &fixture.program_id_base58,
        "--submitter",
        &fixture.submitter_pubkey_base58,
        "--challenge",
        &fixture.challenge_pubkey_base58,
        "--proof-hash",
        &fixture.proof_hash_hex,
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "program_id_base58: {}\nsubmitter_pubkey_base58: {}\nchallenge_pubkey_base58: {}\nproof_hash_hex: {}\nwallet_visual_v1:\n{}\n",
            fixture.program_id_base58,
            fixture.submitter_pubkey_base58,
            fixture.challenge_pubkey_base58,
            fixture.proof_hash_hex,
            fixture.wallet_visual_v1,
        )
    );
}

#[test]
fn submit_proof_generate_rejects_removed_udot_version_flag() {
    let fixture = canonical_submit_fixture_v1();
    let error = Cli::try_parse_from([
        "aura",
        "submit-proof",
        "generate",
        "--program-id",
        &fixture.program_id_base58,
        "--submitter",
        &fixture.submitter_pubkey_base58,
        "--challenge",
        &fixture.challenge_pubkey_base58,
        "--proof-hash",
        &fixture.proof_hash_hex,
        "--udot-version",
        "v2",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("--udot-version"));
}
