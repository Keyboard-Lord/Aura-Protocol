use crate::{write_field, write_json, AuraCliErrorV1, CliUdotOutputFormatV1};
use aura_sdk_v1::{
    generate_submit_proof_request_v1, GenerateSubmitProofRequestV1, SubmitProofRequestWireV1,
};
use clap::{Args, Subcommand};
use std::io::Write;

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct SubmitProofArgsV1 {
    #[command(subcommand)]
    pub command: SubmitProofCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum SubmitProofCommandV1 {
    Generate(SubmitProofGenerateArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct SubmitProofGenerateArgsV1 {
    #[arg(long)]
    pub program_id: String,
    #[arg(long)]
    pub submitter: String,
    #[arg(long)]
    pub challenge: String,
    #[arg(long)]
    pub proof_hash: String,
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

pub fn run_submit_proof<W: Write>(
    args: SubmitProofArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    match args.command {
        SubmitProofCommandV1::Generate(args) => run_submit_proof_generate(args, writer),
    }
}

fn run_submit_proof_generate<W: Write>(
    args: SubmitProofGenerateArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let request = generate_submit_proof_request_v1(GenerateSubmitProofRequestV1 {
        program_id_base58: args.program_id,
        submitter_pubkey_base58: args.submitter,
        challenge_pubkey_base58: args.challenge,
        proof_hash_hex: args.proof_hash,
    })?;

    if args.output == CliUdotOutputFormatV1::Json {
        write_json(writer, &request)?;
        return Ok(());
    }

    write_submit_proof_request_text(writer, &request)
}

pub(crate) fn write_submit_proof_request_text<W: Write>(
    writer: &mut W,
    request: &SubmitProofRequestWireV1,
) -> Result<(), AuraCliErrorV1> {
    write_field(writer, "program_id_base58", &request.program_id_base58)?;
    write_field(
        writer,
        "submitter_pubkey_base58",
        &request.submitter_pubkey_base58,
    )?;
    write_field(
        writer,
        "challenge_pubkey_base58",
        &request.challenge_pubkey_base58,
    )?;
    write_field(writer, "proof_hash_hex", &request.proof_hash_hex)?;
    write_field(writer, "wallet_visual_v1", &request.wallet_visual_v1)?;

    Ok(())
}
