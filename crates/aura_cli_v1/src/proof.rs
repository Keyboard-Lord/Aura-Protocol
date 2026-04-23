use crate::intent::write_authorization_intent_text;
use crate::{write_field, write_json, AuraCliErrorV1, CliUdotOutputFormatV1};
use aura_sdk_v1::{
    generate_stark_proof_envelope_v1, GenerateAuthorizationIntentV1, GenerateStarkProofEnvelopeV1,
    GenerateSubmitProofRequestV1, StarkProofEnvelopeV1,
};
use clap::{Args, Subcommand};
use std::io::Write;

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct ProofArgsV1 {
    #[command(subcommand)]
    pub command: ProofCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum ProofCommandV1 {
    Generate(ProofGenerateArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct ProofGenerateArgsV1 {
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
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

pub fn run_proof<W: Write>(args: ProofArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    match args.command {
        ProofCommandV1::Generate(args) => run_proof_generate(args, writer),
    }
}

fn run_proof_generate<W: Write>(
    args: ProofGenerateArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let proof = generate_stark_proof_envelope_v1(GenerateStarkProofEnvelopeV1 {
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
    })?;

    if args.output == CliUdotOutputFormatV1::Json {
        write_json(writer, &proof)?;
        return Ok(());
    }

    write_stark_proof_envelope_text(writer, &proof)
}

pub(crate) fn write_stark_proof_envelope_text<W: Write>(
    writer: &mut W,
    proof: &StarkProofEnvelopeV1,
) -> Result<(), AuraCliErrorV1> {
    write_field(writer, "proof_version", "v1")?;
    write_field(writer, "proof_session_id_hex", &proof.proof_session_id_hex)?;
    write_field(
        writer,
        "iteration_count",
        &proof.dcm_claim.iteration_count.to_string(),
    )?;
    write_field(writer, "initial_state", &proof.dcm_claim.initial_state)?;
    write_field(writer, "final_state", &proof.dcm_claim.final_state)?;
    write_field(writer, "commitment_root", &proof.dcm_claim.commitment_root)?;
    write_authorization_intent_text(writer, &proof.authorization_intent)
}
