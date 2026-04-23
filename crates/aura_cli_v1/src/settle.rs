use crate::proof::write_stark_proof_envelope_text;
use crate::{
    load_and_prepare, write_field, write_json, AuraCliErrorV1, CliSolanaCommitmentConfigV1,
    CliUdotOutputFormatV1, FlowArgsV1,
};
use aura_sdk_v1::{
    build_settlement_pipeline_from_prepared_proof_v1, generate_solana_settlement_request_v1,
    BuildSettlementPipelineFromPreparedProofRequestV1, GenerateAuthorizationIntentV1,
    GenerateSolanaSettlementRequestV1, GenerateStarkProofEnvelopeV1, GenerateSubmitProofRequestV1,
    SolanaSettlementRequestWireV1,
};
use clap::{Args, Subcommand};
use std::io::Write;

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct SettleArgsV1 {
    #[command(subcommand)]
    pub command: SettleCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum SettleCommandV1 {
    Generate(SettleGenerateArgsV1),
    BuildPipeline(SettleBuildPipelineArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct SettleGenerateArgsV1 {
    #[arg(long)]
    pub session_id: String,
    #[arg(long)]
    pub iteration_count: u64,
    #[arg(long)]
    pub initial_state: String,
    #[arg(long)]
    pub final_state: String,
    #[arg(long)]
    pub commitment_root: String,
    #[arg(long)]
    pub intent_id: String,
    #[arg(long)]
    pub program_id: String,
    #[arg(long)]
    pub submitter: String,
    #[arg(long)]
    pub challenge: String,
    #[arg(long)]
    pub proof_hash: String,
    #[arg(long)]
    pub solana_rpc_url: Option<String>,
    #[arg(long, value_enum, default_value_t = CliSolanaCommitmentConfigV1::Confirmed)]
    pub commitment_config: CliSolanaCommitmentConfigV1,
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct SettleBuildPipelineArgsV1 {
    #[command(flatten)]
    pub flow: FlowArgsV1,
    #[arg(long)]
    pub intent_id: String,
    #[arg(long)]
    pub session_id: String,
    #[arg(long)]
    pub iteration_count: u64,
    #[arg(long)]
    pub initial_state: String,
    #[arg(long)]
    pub final_state: String,
    #[arg(long)]
    pub commitment_root: String,
    #[arg(long)]
    pub program_id: String,
    #[arg(long)]
    pub submitter: String,
    #[arg(long)]
    pub challenge_pubkey: String,
    #[arg(long)]
    pub solana_rpc_url: Option<String>,
    #[arg(long, value_enum, default_value_t = CliSolanaCommitmentConfigV1::Confirmed)]
    pub commitment_config: CliSolanaCommitmentConfigV1,
}

pub fn run_settle<W: Write>(args: SettleArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    match args.command {
        SettleCommandV1::Generate(args) => run_settle_generate(args, writer),
        SettleCommandV1::BuildPipeline(args) => run_settle_build_pipeline(args, writer),
    }
}

fn run_settle_generate<W: Write>(
    args: SettleGenerateArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let request = generate_solana_settlement_request_v1(GenerateSolanaSettlementRequestV1 {
        solana_rpc_url: args.solana_rpc_url,
        commitment_config: args.commitment_config.into(),
        stark_proof_envelope: GenerateStarkProofEnvelopeV1 {
            proof_session_id_hex: args.session_id,
            iteration_count: args.iteration_count,
            initial_state_hex: args.initial_state,
            final_state_hex: args.final_state,
            commitment_root_hex: args.commitment_root,
            authorization_intent: GenerateAuthorizationIntentV1 {
                intent_id_hex: args.intent_id,
                submit_proof_request: GenerateSubmitProofRequestV1 {
                    program_id_base58: args.program_id,
                    submitter_pubkey_base58: args.submitter,
                    challenge_pubkey_base58: args.challenge,
                    proof_hash_hex: args.proof_hash,
                },
            },
        },
    })?;

    if args.output == CliUdotOutputFormatV1::Json {
        write_json(writer, &request)?;
        return Ok(());
    }

    write_solana_settlement_request_text(writer, &request)
}

fn run_settle_build_pipeline<W: Write>(
    args: SettleBuildPipelineArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let prepared_submit_proof = load_and_prepare(args.flow)?;
    let pipeline = build_settlement_pipeline_from_prepared_proof_v1(
        BuildSettlementPipelineFromPreparedProofRequestV1 {
            prepared_submit_proof,
            program_id_base58: args.program_id,
            submitter_pubkey_base58: args.submitter,
            challenge_pubkey_base58: args.challenge_pubkey,
            intent_id_hex: args.intent_id,
            proof_session_id_hex: args.session_id,
            iteration_count: args.iteration_count,
            initial_state_hex: args.initial_state,
            final_state_hex: args.final_state,
            commitment_root_hex: args.commitment_root,
            solana_rpc_url: args.solana_rpc_url,
            commitment_config: args.commitment_config.into(),
        },
    )?;

    write_json(writer, &pipeline)
}

fn write_solana_settlement_request_text<W: Write>(
    writer: &mut W,
    request: &SolanaSettlementRequestWireV1,
) -> Result<(), AuraCliErrorV1> {
    write_field(writer, "settlement_version", "v1")?;
    if let Some(url) = &request.solana_rpc_url {
        write_field(writer, "solana_rpc_url", url)?;
    }
    write_field(
        writer,
        "commitment_config",
        match request.commitment_config {
            aura_sdk_v1::SolanaCommitmentConfigV1::Processed => "processed",
            aura_sdk_v1::SolanaCommitmentConfigV1::Confirmed => "confirmed",
            aura_sdk_v1::SolanaCommitmentConfigV1::Finalized => "finalized",
        },
    )?;
    write_stark_proof_envelope_text(writer, &request.stark_proof_envelope)
}
