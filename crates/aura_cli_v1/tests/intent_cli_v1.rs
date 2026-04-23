use aura_cli_v1::Cli;
use aura_sdk_v1::AuthorizationIntentEnvelopeV1;
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

fn canonical_fixture_v1() -> AuthorizationIntentEnvelopeV1 {
    canonical_pipeline_fixture_v1::load_canonical_pipeline_fixture_json_v1(
        "authorization_intent_v1.json",
    )
}

#[test]
fn intent_generate_json_emits_the_canonical_wallet_surface() {
    let fixture = canonical_fixture_v1();
    let submit = &fixture.submit_proof_request;
    let output = run_aura(&[
        "intent",
        "generate",
        "--intent-id",
        &fixture.intent_id_hex,
        "--program-id",
        &submit.program_id_base58,
        "--submitter",
        &submit.submitter_pubkey_base58,
        "--challenge",
        &submit.challenge_pubkey_base58,
        "--proof-hash",
        &submit.proof_hash_hex,
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value, serde_json::to_value(&fixture).unwrap());
    assert!(value.pointer("/submit_proof_request/udot_bundle").is_none());
}

#[test]
fn intent_generate_text_mode_prints_wallet_visual_v1_only() {
    let fixture = canonical_fixture_v1();
    let submit = &fixture.submit_proof_request;
    let output = run_aura(&[
        "intent",
        "generate",
        "--intent-id",
        &fixture.intent_id_hex,
        "--program-id",
        &submit.program_id_base58,
        "--submitter",
        &submit.submitter_pubkey_base58,
        "--challenge",
        &submit.challenge_pubkey_base58,
        "--proof-hash",
        &submit.proof_hash_hex,
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "intent_version: v1\nintent_id_hex: {}\nsubject_binding_type: submitter-pubkey-base58\nsubject_binding: {}\nintent_type: opaque-intent-hash-32\nintent_commitment_hex: {}\nfreshness_binding_type: challenge-pubkey-base58\nfreshness_binding: {}\nprogram_id_base58: {}\nsubmitter_pubkey_base58: {}\nchallenge_pubkey_base58: {}\nproof_hash_hex: {}\nwallet_visual_v1:\n{}\n",
            fixture.intent_id_hex,
            fixture.authorization_lineage.subject_binding,
            fixture.authorization_lineage.intent_commitment_hex,
            fixture.authorization_lineage.freshness_binding,
            submit.program_id_base58,
            submit.submitter_pubkey_base58,
            submit.challenge_pubkey_base58,
            submit.proof_hash_hex,
            submit.wallet_visual_v1,
        )
    );
}

#[test]
fn intent_generate_rejects_removed_udot_version_flag() {
    let fixture = canonical_fixture_v1();
    let submit = &fixture.submit_proof_request;
    let error = Cli::try_parse_from([
        "aura",
        "intent",
        "generate",
        "--intent-id",
        &fixture.intent_id_hex,
        "--program-id",
        &submit.program_id_base58,
        "--submitter",
        &submit.submitter_pubkey_base58,
        "--challenge",
        &submit.challenge_pubkey_base58,
        "--proof-hash",
        &submit.proof_hash_hex,
        "--udot-version",
        "v2",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("--udot-version"));
}
