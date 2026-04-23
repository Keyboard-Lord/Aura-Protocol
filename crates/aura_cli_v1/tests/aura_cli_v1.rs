use aura_cli_v1::{
    encode_hex_lower, AuraCommandV1, Cli, CliSolanaCommitmentConfigV1, CliUdotOutputFormatV1,
    CliUdotVersionV1, FlowArgsV1, IntentArgsV1, IntentCommandV1, IntentGenerateArgsV1, ProofArgsV1,
    ProofCommandV1, ProofGenerateArgsV1, SettleArgsV1, SettleBuildPipelineArgsV1, SettleCommandV1,
    SettleGenerateArgsV1, SubmitProofArgsV1, SubmitProofCommandV1, SubmitProofGenerateArgsV1,
};
use aura_sdk_v1::prepare_submit_proof_flow_v1;
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("canonical_prepare")
        .join(name)
}

fn subject_hex() -> &'static str {
    "1111111111111111111111111111111111111111111111111111111111111111"
}

fn challenge_hex() -> &'static str {
    "2222222222222222222222222222222222222222222222222222222222222222"
}

fn subject_bytes() -> [u8; 32] {
    [0x11; 32]
}

fn challenge_bytes() -> [u8; 32] {
    [0x22; 32]
}

#[test]
fn prepare_command_parses_expected_arguments() {
    let proof_blob = fixture_path("proof_blob.bin");
    let public_inputs = fixture_path("public_inputs.bin");
    let verification_key = fixture_path("verification_key.bin");

    let cli = Cli::try_parse_from([
        "aura",
        "prepare",
        "--subject",
        subject_hex(),
        "--challenge",
        challenge_hex(),
        "--proof-blob",
        proof_blob.to_str().unwrap(),
        "--public-inputs",
        public_inputs.to_str().unwrap(),
        "--verification-key",
        verification_key.to_str().unwrap(),
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Prepare(FlowArgsV1 {
            subject: subject_bytes(),
            challenge: challenge_bytes(),
            proof_blob,
            public_inputs,
            verification_key,
        })
    );
}

#[test]
fn inspect_command_parses_expected_arguments() {
    let proof_blob = fixture_path("proof_blob.bin");
    let public_inputs = fixture_path("public_inputs.bin");
    let verification_key = fixture_path("verification_key.bin");

    let cli = Cli::try_parse_from([
        "aura",
        "inspect",
        "--subject",
        subject_hex(),
        "--challenge",
        challenge_hex(),
        "--proof-blob",
        proof_blob.to_str().unwrap(),
        "--public-inputs",
        public_inputs.to_str().unwrap(),
        "--verification-key",
        verification_key.to_str().unwrap(),
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Inspect(FlowArgsV1 {
            subject: subject_bytes(),
            challenge: challenge_bytes(),
            proof_blob,
            public_inputs,
            verification_key,
        })
    );
}

#[test]
fn prepare_output_is_deterministic() {
    let proof_blob = std::fs::read(fixture_path("proof_blob.bin")).unwrap();
    let public_inputs = std::fs::read(fixture_path("public_inputs.bin")).unwrap();
    let verification_key = std::fs::read(fixture_path("verification_key.bin")).unwrap();
    let prepared = prepare_submit_proof_flow_v1(
        subject_bytes(),
        challenge_bytes(),
        &proof_blob,
        &public_inputs,
        &verification_key,
    )
    .unwrap();

    let expected = format!(
        "proof_material_hash: {}\nproof_hash: {}\n",
        encode_hex_lower(&prepared.proof_material_hash),
        encode_hex_lower(&prepared.proof_hash)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_aura"))
        .args([
            "prepare",
            "--subject",
            subject_hex(),
            "--challenge",
            challenge_hex(),
            "--proof-blob",
            fixture_path("proof_blob.bin").to_str().unwrap(),
            "--public-inputs",
            fixture_path("public_inputs.bin").to_str().unwrap(),
            "--verification-key",
            fixture_path("verification_key.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

#[test]
fn inspect_output_is_deterministic() {
    let proof_blob = std::fs::read(fixture_path("proof_blob.bin")).unwrap();
    let public_inputs = std::fs::read(fixture_path("public_inputs.bin")).unwrap();
    let verification_key = std::fs::read(fixture_path("verification_key.bin")).unwrap();
    let prepared = prepare_submit_proof_flow_v1(
        subject_bytes(),
        challenge_bytes(),
        &proof_blob,
        &public_inputs,
        &verification_key,
    )
    .unwrap();

    let expected = format!(
        "proof_blob_hash: {}\npublic_inputs_hash: {}\nverification_key_hash: {}\nproof_material_hash: {}\nproof_hash: {}\n",
        encode_hex_lower(&prepared.proof_material.proof_blob_hash),
        encode_hex_lower(&prepared.proof_material.public_inputs_hash),
        encode_hex_lower(&prepared.proof_material.verification_key_hash),
        encode_hex_lower(&prepared.proof_material_hash),
        encode_hex_lower(&prepared.proof_hash)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_aura"))
        .args([
            "inspect",
            "--subject",
            subject_hex(),
            "--challenge",
            challenge_hex(),
            "--proof-blob",
            fixture_path("proof_blob.bin").to_str().unwrap(),
            "--public-inputs",
            fixture_path("public_inputs.bin").to_str().unwrap(),
            "--verification-key",
            fixture_path("verification_key.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

#[test]
fn submit_proof_generate_command_parses_expected_arguments() {
    let cli = Cli::try_parse_from([
        "aura",
        "submit-proof",
        "generate",
        "--program-id",
        "11111111111111111111111111111111",
        "--submitter",
        "11111111111111111111111111111111",
        "--challenge",
        "11111111111111111111111111111111",
        "--proof-hash",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--udot-version",
        "v2",
        "--output",
        "json",
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::SubmitProof(SubmitProofArgsV1 {
            command: SubmitProofCommandV1::Generate(SubmitProofGenerateArgsV1 {
                program_id: "11111111111111111111111111111111".to_owned(),
                submitter: "11111111111111111111111111111111".to_owned(),
                challenge: "11111111111111111111111111111111".to_owned(),
                proof_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                udot_version: CliUdotVersionV1::V2,
                output: CliUdotOutputFormatV1::Json,
            }),
        })
    );
}

#[test]
fn intent_generate_command_parses_expected_arguments() {
    let cli = Cli::try_parse_from([
        "aura",
        "intent",
        "generate",
        "--intent-id",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--program-id",
        "11111111111111111111111111111111",
        "--submitter",
        "11111111111111111111111111111111",
        "--challenge",
        "11111111111111111111111111111111",
        "--proof-hash",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--udot-version",
        "v2",
        "--output",
        "json",
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Intent(IntentArgsV1 {
            command: IntentCommandV1::Generate(IntentGenerateArgsV1 {
                intent_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                program_id: "11111111111111111111111111111111".to_owned(),
                submitter: "11111111111111111111111111111111".to_owned(),
                challenge: "11111111111111111111111111111111".to_owned(),
                proof_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                udot_version: CliUdotVersionV1::V2,
                output: CliUdotOutputFormatV1::Json,
            }),
        })
    );
}

#[test]
fn proof_generate_command_parses_expected_arguments() {
    let cli = Cli::try_parse_from([
        "aura",
        "proof",
        "generate",
        "--session-id",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--iteration-count",
        "5",
        "--initial-state",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022",
        "--final-state",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044",
        "--commitment-root",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--intent-id",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--program-id",
        "11111111111111111111111111111111",
        "--submitter",
        "11111111111111111111111111111111",
        "--challenge",
        "11111111111111111111111111111111",
        "--proof-hash",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--udot-version",
        "v2",
        "--output",
        "json",
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Proof(ProofArgsV1 {
            command: ProofCommandV1::Generate(ProofGenerateArgsV1 {
                session_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
                iteration_count: 5,
                initial_state: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022"
                    .to_owned(),
                final_state: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044"
                    .to_owned(),
                commitment_root:
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned(),
                intent_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                program_id: "11111111111111111111111111111111".to_owned(),
                submitter: "11111111111111111111111111111111".to_owned(),
                challenge: "11111111111111111111111111111111".to_owned(),
                proof_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                udot_version: CliUdotVersionV1::V2,
                output: CliUdotOutputFormatV1::Json,
            }),
        })
    );
}

#[test]
fn settle_generate_command_parses_expected_arguments() {
    let cli = Cli::try_parse_from([
        "aura",
        "settle",
        "generate",
        "--session-id",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--iteration-count",
        "5",
        "--initial-state",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022",
        "--final-state",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044",
        "--commitment-root",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--intent-id",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--program-id",
        "11111111111111111111111111111111",
        "--submitter",
        "11111111111111111111111111111111",
        "--challenge",
        "11111111111111111111111111111111",
        "--proof-hash",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--udot-version",
        "v2",
        "--solana-rpc-url",
        "https://rpc.aura.invalid",
        "--commitment-config",
        "finalized",
        "--output",
        "json",
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Settle(SettleArgsV1 {
            command: SettleCommandV1::Generate(SettleGenerateArgsV1 {
                session_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
                iteration_count: 5,
                initial_state: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022"
                    .to_owned(),
                final_state: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044"
                    .to_owned(),
                commitment_root:
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned(),
                intent_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                program_id: "11111111111111111111111111111111".to_owned(),
                submitter: "11111111111111111111111111111111".to_owned(),
                challenge: "11111111111111111111111111111111".to_owned(),
                proof_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                udot_version: CliUdotVersionV1::V2,
                solana_rpc_url: Some("https://rpc.aura.invalid".to_owned()),
                commitment_config: CliSolanaCommitmentConfigV1::Finalized,
                output: CliUdotOutputFormatV1::Json,
            }),
        })
    );
}

#[test]
fn settle_build_pipeline_command_parses_expected_arguments() {
    let proof_blob = fixture_path("proof_blob.bin");
    let public_inputs = fixture_path("public_inputs.bin");
    let verification_key = fixture_path("verification_key.bin");

    let cli = Cli::try_parse_from([
        "aura",
        "settle",
        "build-pipeline",
        "--subject",
        subject_hex(),
        "--challenge",
        challenge_hex(),
        "--proof-blob",
        proof_blob.to_str().unwrap(),
        "--public-inputs",
        public_inputs.to_str().unwrap(),
        "--verification-key",
        verification_key.to_str().unwrap(),
        "--intent-id",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--session-id",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--iteration-count",
        "5",
        "--initial-state",
        "11",
        "--final-state",
        "22",
        "--commitment-root",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--program-id",
        "11111111111111111111111111111111",
        "--submitter",
        "11111111111111111111111111111111",
        "--challenge-pubkey",
        "11111111111111111111111111111111",
        "--udot-version",
        "v2",
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Settle(SettleArgsV1 {
            command: SettleCommandV1::BuildPipeline(SettleBuildPipelineArgsV1 {
                flow: FlowArgsV1 {
                    subject: subject_bytes(),
                    challenge: challenge_bytes(),
                    proof_blob,
                    public_inputs,
                    verification_key,
                },
                intent_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                session_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
                iteration_count: 5,
                initial_state: "11".to_owned(),
                final_state: "22".to_owned(),
                commitment_root: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_owned(),
                program_id: "11111111111111111111111111111111".to_owned(),
                submitter: "11111111111111111111111111111111".to_owned(),
                challenge_pubkey: "11111111111111111111111111111111".to_owned(),
                udot_version: CliUdotVersionV1::V2,
                solana_rpc_url: None,
                commitment_config: CliSolanaCommitmentConfigV1::Confirmed,
            }),
        })
    );
}
