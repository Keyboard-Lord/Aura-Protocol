use crate::{read_json_input, write_json, AuraCliErrorV1};
use aura_notarization_export_v1::{
    build_notarization_export_summary_v1, validate_notarization_record_wire_v1,
    CanonicalTokenTransactionNotarizationRecordWireV1,
    CanonicalTokenTransactionNotarizationSummaryV1,
};
use aura_notarization_render_v1::{
    render_notarization_summary_html_v1, render_notarization_summary_markdown_v1,
};
use clap::{Args, Subcommand, ValueEnum};
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct NotarizationArgsV1 {
    #[command(subcommand)]
    pub command: NotarizationCommandV1,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
pub enum NotarizationCommandV1 {
    Summarize(NotarizationSummarizeArgsV1),
    RenderSummary(NotarizationRenderSummaryArgsV1),
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct NotarizationSummarizeArgsV1 {
    #[arg(long = "input-json")]
    pub input_json: Option<PathBuf>,
}

#[derive(Clone, Debug, Args, PartialEq, Eq)]
pub struct NotarizationRenderSummaryArgsV1 {
    #[arg(long = "input-json")]
    pub input_json: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = NotarizationRenderFormatV1::Markdown)]
    pub format: NotarizationRenderFormatV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NotarizationRenderFormatV1 {
    Markdown,
    Html,
}

pub fn run_notarization<W: Write>(
    args: NotarizationArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    match args.command {
        NotarizationCommandV1::Summarize(args) => run_notarization_summarize(args, writer),
        NotarizationCommandV1::RenderSummary(args) => run_notarization_render_summary(args, writer),
    }
}

fn run_notarization_summarize<W: Write>(
    args: NotarizationSummarizeArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let payload =
        read_json_input::<CanonicalTokenTransactionNotarizationRecordWireV1>(args.input_json)?;
    let validated = validate_notarization_record_wire_v1(payload)?;
    let summary = build_notarization_export_summary_v1(validated)?;
    write_json(writer, &summary)
}

fn run_notarization_render_summary<W: Write>(
    args: NotarizationRenderSummaryArgsV1,
    writer: &mut W,
) -> Result<(), AuraCliErrorV1> {
    let summary =
        read_json_input::<CanonicalTokenTransactionNotarizationSummaryV1>(args.input_json)?;
    let rendered = match args.format {
        NotarizationRenderFormatV1::Markdown => render_notarization_summary_markdown_v1(&summary),
        NotarizationRenderFormatV1::Html => render_notarization_summary_html_v1(&summary),
    };
    write!(writer, "{rendered}")?;
    Ok(())
}
