mod commands;
mod intent;
mod notarization;
mod proof;
mod settle;
mod submit;

use aura_notarization_export_v1::AuraNotarizationExportErrorV1;
use aura_sdk_v1::{prepare_submit_proof_flow_v1, AuraSdkErrorV1, PreparedSubmitProofV1, legacy::SolanaCommitmentConfigV1, UdotArtifactEnvelopeV1, UdotArtifactKind, UdotArtifactWireV1, UdotVersion};
use clap::{Args, Parser, Subcommand, ValueEnum};
use core::fmt;
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub use commands::udot::{
    run_udot, UdotArgsV1, UdotCommandV1, UdotGenerateArgsV1, UdotParseArgsV1, UdotValidateArgsV1,
};
pub use intent::{run_intent, IntentArgsV1, IntentCommandV1, IntentGenerateArgsV1};
pub use notarization::{
    run_notarization, NotarizationArgsV1, NotarizationCommandV1, NotarizationRenderFormatV1,
    NotarizationRenderSummaryArgsV1, NotarizationSummarizeArgsV1,
};
pub use proof::{run_proof, ProofArgsV1, ProofCommandV1, ProofGenerateArgsV1};
pub use settle::{
    run_settle, SettleArgsV1, SettleBuildPipelineArgsV1, SettleCommandV1, SettleGenerateArgsV1,
};
pub use submit::{
    run_submit_proof, SubmitProofArgsV1, SubmitProofCommandV1, SubmitProofGenerateArgsV1,
};

#[derive(Debug)]
pub enum AuraCliErrorV1 {
    Io(io::Error),
    Json(serde_json::Error),
    NotarizationExport(AuraNotarizationExportErrorV1),
    Sdk(AuraSdkErrorV1),
}

impl fmt::Display for AuraCliErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::NotarizationExport(error) => write!(f, "{error}"),
            Self::Sdk(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuraCliErrorV1 {}

impl From<io::Error> for AuraCliErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for AuraCliErrorV1 {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<AuraNotarizationExportErrorV1> for AuraCliErrorV1 {
    fn from(error: AuraNotarizationExportErrorV1) -> Self {
        Self::NotarizationExport(error)
    }
}

impl From<AuraSdkErrorV1> for AuraCliErrorV1 {
    fn from(error: AuraSdkErrorV1) -> Self {
        Self::Sdk(error)
    }
}

#[derive(Clone, Debug, Parser, PartialEq, Eq)]
#[command(name = "aura")]
pub struct Cli {
    #[command(subcommand)]
    pub command: AuraCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum AuraCommandV1 {
    Prepare(FlowArgsV1),
    Inspect(FlowArgsV1),
    Notarization(NotarizationArgsV1),
    Udot(UdotArgsV1),
    SubmitProof(SubmitProofArgsV1),
    Intent(IntentArgsV1),
    Proof(ProofArgsV1),
    Settle(SettleArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct FlowArgsV1 {
    #[arg(long, value_parser = parse_hex_32)]
    pub subject: [u8; 32],
    #[arg(long, value_parser = parse_hex_32)]
    pub challenge: [u8; 32],
    #[arg(long)]
    pub proof_blob: PathBuf,
    #[arg(long)]
    pub public_inputs: PathBuf,
    #[arg(long)]
    pub verification_key: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CliUdotVersionV1 {
    V2,
    V1Legacy,
}

impl CliUdotVersionV1 {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "v2",
            Self::V1Legacy => "v1-legacy",
        }
    }
}

impl From<CliUdotVersionV1> for UdotVersion {
    fn from(value: CliUdotVersionV1) -> Self {
        match value {
            CliUdotVersionV1::V2 => UdotVersion::V2,
            CliUdotVersionV1::V1Legacy => UdotVersion::V1Legacy,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CliUdotArtifactKindV1 {
    SealLine,
    Crest,
    MatrixSequence,
    MatrixForm,
}

impl CliUdotArtifactKindV1 {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SealLine => "seal-line",
            Self::Crest => "crest",
            Self::MatrixSequence => "matrix-sequence",
            Self::MatrixForm => "matrix-form",
        }
    }
}

impl From<CliUdotArtifactKindV1> for UdotArtifactKind {
    fn from(value: CliUdotArtifactKindV1) -> Self {
        match value {
            CliUdotArtifactKindV1::SealLine => UdotArtifactKind::SealLine,
            CliUdotArtifactKindV1::Crest => UdotArtifactKind::Crest,
            CliUdotArtifactKindV1::MatrixSequence => UdotArtifactKind::MatrixSequence,
            CliUdotArtifactKindV1::MatrixForm => UdotArtifactKind::MatrixForm,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CliUdotOutputFormatV1 {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CliSolanaCommitmentConfigV1 {
    Processed,
    Confirmed,
    Finalized,
}

impl From<CliSolanaCommitmentConfigV1> for SolanaCommitmentConfigV1 {
    fn from(value: CliSolanaCommitmentConfigV1) -> Self {
        match value {
            CliSolanaCommitmentConfigV1::Processed => SolanaCommitmentConfigV1::Processed,
            CliSolanaCommitmentConfigV1::Confirmed => SolanaCommitmentConfigV1::Confirmed,
            CliSolanaCommitmentConfigV1::Finalized => SolanaCommitmentConfigV1::Finalized,
        }
    }
}

pub fn run_cli<W: Write>(cli: Cli, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    match cli.command {
        AuraCommandV1::Prepare(args) => run_prepare(args, writer),
        AuraCommandV1::Inspect(args) => run_inspect(args, writer),
        AuraCommandV1::Notarization(args) => run_notarization(args, writer),
        AuraCommandV1::Udot(args) => run_udot(args, writer),
        AuraCommandV1::SubmitProof(args) => run_submit_proof(args, writer),
        AuraCommandV1::Intent(args) => run_intent(args, writer),
        AuraCommandV1::Proof(args) => run_proof(args, writer),
        AuraCommandV1::Settle(args) => run_settle(args, writer),
    }
}

fn run_prepare<W: Write>(args: FlowArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    let prepared = load_and_prepare(args)?;
    writeln!(
        writer,
        "proof_material_hash: {}",
        encode_hex_lower(&prepared.proof_material_hash)
    )?;
    writeln!(
        writer,
        "proof_hash: {}",
        encode_hex_lower(&prepared.proof_hash)
    )?;
    Ok(())
}

fn run_inspect<W: Write>(args: FlowArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    let prepared = load_and_prepare(args)?;
    writeln!(
        writer,
        "proof_blob_hash: {}",
        encode_hex_lower(&prepared.proof_material.proof_blob_hash)
    )?;
    writeln!(
        writer,
        "public_inputs_hash: {}",
        encode_hex_lower(&prepared.proof_material.public_inputs_hash)
    )?;
    writeln!(
        writer,
        "verification_key_hash: {}",
        encode_hex_lower(&prepared.proof_material.verification_key_hash)
    )?;
    writeln!(
        writer,
        "proof_material_hash: {}",
        encode_hex_lower(&prepared.proof_material_hash)
    )?;
    writeln!(
        writer,
        "proof_hash: {}",
        encode_hex_lower(&prepared.proof_hash)
    )?;
    Ok(())
}

pub(crate) fn load_and_prepare(args: FlowArgsV1) -> Result<PreparedSubmitProofV1, AuraCliErrorV1> {
    let proof_blob_bytes = fs::read(args.proof_blob)?;
    let public_inputs_bytes = fs::read(args.public_inputs)?;
    let verification_key_bytes = fs::read(args.verification_key)?;

    prepare_submit_proof_flow_v1(
        args.subject,
        args.challenge,
        &proof_blob_bytes,
        &public_inputs_bytes,
        &verification_key_bytes,
    )
    .map_err(AuraCliErrorV1::Sdk)
}

fn parse_hex_32(input: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(input)?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes of hex input, got {} bytes",
            bytes.len()
        ));
    }

    let mut value = [0u8; 32];
    value.copy_from_slice(&bytes);
    Ok(value)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("hex input must have an even number of characters".to_string());
    }

    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output.push((high << 4) | low);
    }

    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex input contains a non-hex character".to_string()),
    }
}

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn write_envelope<W: Write>(
    writer: &mut W,
    artifact: &UdotArtifactEnvelopeV1,
) -> Result<(), AuraCliErrorV1> {
    write_field(
        writer,
        udot_artifact_key(artifact.artifact_kind),
        artifact.as_str(),
    )?;
    Ok(())
}

pub(crate) fn write_udot_wire_artifact_text<W: Write>(
    writer: &mut W,
    status: &str,
    artifact: &UdotArtifactWireV1,
) -> Result<(), AuraCliErrorV1> {
    write_field(writer, "status", status)?;
    write_field(
        writer,
        "udot_version",
        udot_version_label(artifact.udot_version),
    )?;
    write_field(
        writer,
        "artifact_kind",
        udot_artifact_kind_label(artifact.artifact_kind),
    )?;
    write_field(writer, "value", &artifact.value)?;
    Ok(())
}

pub(crate) fn write_field<W: Write>(
    writer: &mut W,
    key: &str,
    value: &str,
) -> Result<(), AuraCliErrorV1> {
    if value.contains('\n') {
        writeln!(writer, "{key}:")?;
        writeln!(writer, "{value}")?;
    } else {
        writeln!(writer, "{key}: {value}")?;
    }

    Ok(())
}

pub(crate) fn write_json<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), AuraCliErrorV1> {
    serde_json::to_writer(&mut *writer, value)?;
    writeln!(writer)?;
    Ok(())
}

pub(crate) fn read_json_file<T: DeserializeOwned>(path: PathBuf) -> Result<T, AuraCliErrorV1> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn read_json_input<T: DeserializeOwned>(
    path: Option<PathBuf>,
) -> Result<T, AuraCliErrorV1> {
    match path {
        Some(path) => read_json_file(path),
        None => {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes)?;
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
}

pub(crate) fn udot_version_label(version: UdotVersion) -> &'static str {
    match version {
        UdotVersion::V2 => CliUdotVersionV1::V2.as_str(),
        UdotVersion::V1Legacy => CliUdotVersionV1::V1Legacy.as_str(),
    }
}

pub(crate) fn udot_artifact_kind_label(kind: UdotArtifactKind) -> &'static str {
    match kind {
        UdotArtifactKind::SealLine => CliUdotArtifactKindV1::SealLine.as_str(),
        UdotArtifactKind::Crest => CliUdotArtifactKindV1::Crest.as_str(),
        UdotArtifactKind::MatrixSequence => CliUdotArtifactKindV1::MatrixSequence.as_str(),
        UdotArtifactKind::MatrixForm => CliUdotArtifactKindV1::MatrixForm.as_str(),
    }
}

pub(crate) fn udot_artifact_key(kind: UdotArtifactKind) -> &'static str {
    match kind {
        UdotArtifactKind::SealLine => "seal_line",
        UdotArtifactKind::Crest => "crest",
        UdotArtifactKind::MatrixSequence => "matrix_sequence",
        UdotArtifactKind::MatrixForm => "matrix_form",
    }
}
