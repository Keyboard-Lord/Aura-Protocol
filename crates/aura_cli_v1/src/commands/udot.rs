use crate::{
    read_json_file, udot_version_label, write_envelope, write_json, write_udot_wire_artifact_text,
    AuraCliErrorV1, CliUdotArtifactKindV1, CliUdotOutputFormatV1, CliUdotVersionV1,
};
use aura_sdk_v1::{legacy::generate_udot_artifact_bundle_wire_v1, legacy::generate_udot_artifacts_v1, legacy::parse_udot_artifact_v1, legacy::parse_udot_artifact_wire_v1, legacy::validate_udot_artifact_v1, legacy::validate_udot_artifact_wire_v1, legacy::GenerateUdotArtifactBundleWireRequestV1, legacy::GenerateUdotArtifactsRequestV1, legacy::ParseUdotArtifactRequestV1, legacy::UdotArtifactWireV1, legacy::ValidateUdotArtifactRequestV1, legacy::ValidateUdotArtifactWireRequestV1};
use clap::{ArgGroup, Args, Subcommand};
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct UdotArgsV1 {
    #[command(subcommand)]
    pub command: UdotCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum UdotCommandV1 {
    Generate(UdotGenerateArgsV1),
    Parse(UdotParseArgsV1),
    Validate(UdotValidateArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct UdotGenerateArgsV1 {
    #[arg(long)]
    pub hash: String,
    #[arg(long, value_enum)]
    pub udot_version: CliUdotVersionV1,
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
#[command(group(
    ArgGroup::new("parse_input")
        .required(true)
        .args(["input_json", "artifact_kind"])
))]
pub struct UdotParseArgsV1 {
    #[arg(long, value_enum, requires_all = ["value", "udot_version"], conflicts_with = "input_json")]
    pub artifact_kind: Option<CliUdotArtifactKindV1>,
    #[arg(long, requires_all = ["artifact_kind", "udot_version"], conflicts_with = "input_json")]
    pub value: Option<String>,
    #[arg(long, value_enum, requires_all = ["artifact_kind", "value"], conflicts_with = "input_json")]
    pub udot_version: Option<CliUdotVersionV1>,
    #[arg(long, conflicts_with_all = ["artifact_kind", "value", "udot_version"])]
    pub input_json: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
#[command(group(
    ArgGroup::new("validate_input")
        .required(true)
        .args(["input_json", "hash"])
))]
pub struct UdotValidateArgsV1 {
    #[arg(long, requires_all = ["artifact_kind", "value", "udot_version"], conflicts_with = "input_json")]
    pub hash: Option<String>,
    #[arg(long, value_enum, requires_all = ["hash", "value", "udot_version"], conflicts_with = "input_json")]
    pub artifact_kind: Option<CliUdotArtifactKindV1>,
    #[arg(long, requires_all = ["hash", "artifact_kind", "udot_version"], conflicts_with = "input_json")]
    pub value: Option<String>,
    #[arg(long, value_enum, requires_all = ["hash", "artifact_kind", "value"], conflicts_with = "input_json")]
    pub udot_version: Option<CliUdotVersionV1>,
    #[arg(long, conflicts_with_all = ["hash", "artifact_kind", "value", "udot_version"])]
    pub input_json: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliUdotOutputFormatV1::Text)]
    pub output: CliUdotOutputFormatV1,
}

pub fn run_udot<W: Write>(args: UdotArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    match args.command {
        UdotCommandV1::Generate(args) => run_udot_generate(args, writer),
        UdotCommandV1::Parse(args) => run_udot_parse(args, writer),
        UdotCommandV1::Validate(args) => run_udot_validate(args, writer),
    }
}

fn run_udot_generate<W: Write>(
    args: UdotGenerateArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    if args.output == CliUdotOutputFormatV1::Json {
        let generated =
            generate_udot_artifact_bundle_wire_v1(GenerateUdotArtifactBundleWireRequestV1 {
                udot_version: args.udot_version.into(),
                aura_hash_hex: args.hash,
            })?;
        write_json(writer, &generated)?;
        return Ok(());
    }

    let generated = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: args.udot_version.into(),
        aura_hash_hex: &args.hash,
    })?;

    crate::write_field(
        writer,
        "udot_version",
        udot_version_label(generated.udot_version),
    )?;
    crate::write_field(writer, "aura_hash_hex", &generated.aura_hash_hex)?;
    write_envelope(writer, &generated.seal_line)?;
    write_envelope(writer, &generated.crest)?;

    if let Some(matrix_sequence) = &generated.matrix_sequence {
        write_envelope(writer, matrix_sequence)?;
    }
    if let Some(matrix_form) = &generated.matrix_form {
        write_envelope(writer, matrix_form)?;
    }

    Ok(())
}

fn run_udot_parse<W: Write>(args: UdotParseArgsV1, writer: &mut W) -> Result<(), AuraCliErrorV1> {
    let parsed = if let Some(path) = args.input_json {
        let payload = read_json_file::<UdotArtifactWireV1>(path)?;
        parse_udot_artifact_wire_v1(payload)?
    } else {
        let parsed = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
            udot_version: args
                .udot_version
                .expect("clap requires udot_version")
                .into(),
            artifact_kind: args
                .artifact_kind
                .expect("clap requires artifact_kind")
                .into(),
            serialized_artifact: args.value.as_deref().expect("clap requires value"),
        })?;
        UdotArtifactWireV1 {
            udot_version: parsed.udot_version,
            artifact_kind: parsed.artifact_kind,
            value: parsed.serialized_artifact,
        }
    };

    if args.output == CliUdotOutputFormatV1::Json {
        write_json(writer, &parsed)?;
        return Ok(());
    }

    write_udot_wire_artifact_text(writer, "parsed", &parsed)?;
    Ok(())
}

fn run_udot_validate<W: Write>(
    args: UdotValidateArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let validated = if let Some(path) = args.input_json {
        let payload = read_json_file::<ValidateUdotArtifactWireRequestV1>(path)?;
        validate_udot_artifact_wire_v1(payload)?
    } else {
        let validated = validate_udot_artifact_v1(ValidateUdotArtifactRequestV1 {
            udot_version: args
                .udot_version
                .expect("clap requires udot_version")
                .into(),
            artifact_kind: args
                .artifact_kind
                .expect("clap requires artifact_kind")
                .into(),
            aura_hash_hex: args.hash.as_deref().expect("clap requires hash"),
            serialized_artifact: args.value.as_deref().expect("clap requires value"),
        })?;
        UdotArtifactWireV1 {
            udot_version: validated.udot_version,
            artifact_kind: validated.artifact_kind,
            value: validated.serialized_artifact,
        }
    };

    if args.output == CliUdotOutputFormatV1::Json {
        write_json(writer, &validated)?;
        return Ok(());
    }

    write_udot_wire_artifact_text(writer, "valid", &validated)?;
    Ok(())
}
