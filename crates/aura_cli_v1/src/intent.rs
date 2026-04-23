use crate::submit::write_submit_proof_request_text;
use crate::{write_field, write_json, AuraCliErrorV1, CliUdotOutputFormatV1};
use aura_sdk_v1::{
    generate_authorization_intent_v1, AuthorizationIntentEnvelopeV1, GenerateAuthorizationIntentV1,
    GenerateSubmitProofRequestV1,
};
use clap::{Args, Subcommand};
use std::io::Write;

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct IntentArgsV1 {
    #[command(subcommand)]
    pub command: IntentCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum IntentCommandV1 {
    Generate(IntentGenerateArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct IntentGenerateArgsV1 {
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
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

pub fn run_intent<W: Write>(args: IntentArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    match args.command {
        IntentCommandV1::Generate(args) => run_intent_generate(args, writer),
    }
}

fn run_intent_generate<W: Write>(
    args: IntentGenerateArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let intent = generate_authorization_intent_v1(GenerateAuthorizationIntentV1 {
        intent_id_hex: args.intent_id,
        submit_proof_request: GenerateSubmitProofRequestV1 {
            program_id_base58: args.program_id,
            submitter_pubkey_base58: args.submitter,
            challenge_pubkey_base58: args.challenge,
            proof_hash_hex: args.proof_hash,
        },
    })?;

    if args.output == CliUdotOutputFormatV1::Json {
        write_json(writer, &intent)?;
        return Ok(());
    }

    write_authorization_intent_text(writer, &intent)
}

pub(crate) fn write_authorization_intent_text<W: Write>(
    writer: &mut W,
    intent: &AuthorizationIntentEnvelopeV1,
) -> Result<(), AuraCliErrorV1> {
    write_field(writer, "intent_version", "v1")?;
    write_field(writer, "intent_id_hex", &intent.intent_id_hex)?;
    write_field(writer, "subject_binding_type", "submitter-pubkey-base58")?;
    write_field(
        writer,
        "subject_binding",
        &intent.authorization_lineage.subject_binding,
    )?;
    write_field(writer, "intent_type", "opaque-intent-hash-32")?;
    write_field(
        writer,
        "intent_commitment_hex",
        &intent.authorization_lineage.intent_commitment_hex,
    )?;
    write_field(writer, "freshness_binding_type", "challenge-pubkey-base58")?;
    write_field(
        writer,
        "freshness_binding",
        &intent.authorization_lineage.freshness_binding,
    )?;
    write_submit_proof_request_text(writer, &intent.submit_proof_request)
}
