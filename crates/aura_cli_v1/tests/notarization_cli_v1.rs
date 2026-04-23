use aura_cli_v1::{
    AuraCommandV1, Cli, NotarizationArgsV1, NotarizationCommandV1, NotarizationRenderFormatV1,
    NotarizationRenderSummaryArgsV1, NotarizationSummarizeArgsV1,
};
use aura_notarization_render_v1::{
    render_notarization_summary_html_v1, render_notarization_summary_markdown_v1,
    CanonicalTokenTransactionNotarizationSummaryV1,
};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureVectorFileV1 {
    vectors: Vec<FixtureVectorV1>,
}

#[derive(Debug, Deserialize)]
struct FixtureVectorV1 {
    notarization_summary: Value,
    notary_ack_digest_hex: String,
    seal_payload_digest_hex: String,
    udot_seed_digest_hex: String,
    notarization_record_digest_hex: String,
    #[serde(flatten)]
    rest: std::collections::BTreeMap<String, Value>,
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("deterministic_transaction_v1")
        .join("test_vectors.json")
}

fn load_fixture() -> FixtureVectorFileV1 {
    serde_json::from_str(&fs::read_to_string(fixture_path()).unwrap()).unwrap()
}

fn write_temp_json(label: &str, value: &Value) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "aura_notarization_cli_{}_{}_{}.json",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed),
        label
    ));
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

fn fixture_record_wire(vector: &FixtureVectorV1) -> Value {
    serde_json::json!({
        "record_version": vector.notarization_summary["record_version"],
        "proof_statement_type": vector.notarization_summary["proof_statement_type"],
        "ack_digest_hex": vector.notary_ack_digest_hex,
        "seal_payload_digest_hex": vector.seal_payload_digest_hex,
        "udot_seed_digest_hex": vector.udot_seed_digest_hex,
        "notarization_record_digest_hex": vector.notarization_record_digest_hex,
    })
}

fn run_aura(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aura"))
        .args(args)
        .output()
        .unwrap()
}

fn run_aura_with_stdin(args: &[&str], input: &Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aura"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();

    child.wait_with_output().unwrap()
}

#[test]
fn notarization_summarize_command_parses_expected_arguments() {
    let path = PathBuf::from("/tmp/notarization-record.json");

    let cli = Cli::try_parse_from([
        "aura",
        "notarization",
        "summarize",
        "--input-json",
        path.to_str().unwrap(),
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Notarization(NotarizationArgsV1 {
            command: NotarizationCommandV1::Summarize(NotarizationSummarizeArgsV1 {
                input_json: Some(path),
            }),
        })
    );
}

#[test]
fn notarization_render_summary_command_parses_expected_arguments() {
    let path = PathBuf::from("/tmp/notarization-summary.json");

    let cli = Cli::try_parse_from([
        "aura",
        "notarization",
        "render-summary",
        "--input-json",
        path.to_str().unwrap(),
    ])
    .unwrap();

    assert_eq!(
        cli.command,
        AuraCommandV1::Notarization(NotarizationArgsV1 {
            command: NotarizationCommandV1::RenderSummary(NotarizationRenderSummaryArgsV1 {
                input_json: Some(path),
                format: NotarizationRenderFormatV1::Markdown,
            }),
        })
    );
}

#[test]
fn valid_canonical_record_wire_json_via_file_produces_exact_frozen_summary_json_output() {
    let fixture = load_fixture();
    let vector = &fixture.vectors[0];
    let input_path = write_temp_json("valid_record", &fixture_record_wire(vector));
    let input_string = input_path.to_str().unwrap().to_owned();

    let output = run_aura(&["notarization", "summarize", "--input-json", &input_string]);

    assert!(output.status.success());
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, vector.notarization_summary);
    assert!(vector.rest.contains_key("transaction"));
}

#[test]
fn valid_canonical_record_wire_json_from_stdin_produces_exact_frozen_summary_json_output() {
    let fixture = load_fixture();
    let vector = &fixture.vectors[0];

    let output = run_aura_with_stdin(&["notarization", "summarize"], &fixture_record_wire(vector));

    assert!(output.status.success());
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, vector.notarization_summary);
}

#[test]
fn malformed_record_wire_input_from_file_fails_closed() {
    let path = write_temp_json(
        "malformed_record",
        &serde_json::json!({
            "record_version": 1,
            "proof_statement_type": 1,
            "ack_digest_hex": "abcd",
        }),
    );
    let input_string = path.to_str().unwrap().to_owned();

    let output = run_aura(&["notarization", "summarize", "--input-json", &input_string]);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("json error:") || stderr.contains("invalid notarization record:"));
}

#[test]
fn malformed_record_wire_input_from_stdin_fails_closed() {
    let output = run_aura_with_stdin(
        &["notarization", "summarize"],
        &serde_json::json!({
            "record_version": 1,
            "proof_statement_type": 1,
            "ack_digest_hex": "abcd",
        }),
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("json error:") || stderr.contains("invalid notarization record:"));
}

#[test]
fn bad_record_digest_from_file_fails_closed() {
    let fixture = load_fixture();
    let vector = &fixture.vectors[0];
    let mut record = fixture_record_wire(vector);
    record["notarization_record_digest_hex"] = Value::String(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
    );
    let path = write_temp_json("bad_digest", &record);
    let input_string = path.to_str().unwrap().to_owned();

    let output = run_aura(&["notarization", "summarize", "--input-json", &input_string]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("invalid notarization record:"));
}

#[test]
fn bad_record_digest_from_stdin_fails_closed() {
    let fixture = load_fixture();
    let vector = &fixture.vectors[0];
    let mut record = fixture_record_wire(vector);
    record["notarization_record_digest_hex"] = Value::String(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
    );

    let output = run_aura_with_stdin(&["notarization", "summarize"], &record);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("invalid notarization record:"));
}

#[test]
fn canonical_summary_behavior_does_not_drift() {
    let fixture = load_fixture();

    for vector in &fixture.vectors {
        let input_path = write_temp_json("fixture_vector", &fixture_record_wire(vector));
        let input_string = input_path.to_str().unwrap().to_owned();
        let output = run_aura(&["notarization", "summarize", "--input-json", &input_string]);

        assert!(output.status.success());
        let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, vector.notarization_summary);
    }
}

#[test]
fn renderer_facing_wrapper_consumes_frozen_summary_surface_deterministically() {
    let fixture = load_fixture();
    let summary_value = fixture.vectors[0].notarization_summary.clone();
    let summary_path = write_temp_json("summary_input", &summary_value);
    let summary_string = summary_path.to_str().unwrap().to_owned();

    let output = run_aura(&[
        "notarization",
        "render-summary",
        "--input-json",
        &summary_string,
        "--format",
        "markdown",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let summary: CanonicalTokenTransactionNotarizationSummaryV1 =
        serde_json::from_value(summary_value).unwrap();
    assert_eq!(stdout, render_notarization_summary_markdown_v1(&summary));
}

#[test]
fn renderer_facing_wrapper_can_read_summary_from_stdin() {
    let fixture = load_fixture();
    let summary_value = fixture.vectors[0].notarization_summary.clone();

    let output = run_aura_with_stdin(
        &["notarization", "render-summary", "--format", "markdown"],
        &summary_value,
    );

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let summary: CanonicalTokenTransactionNotarizationSummaryV1 =
        serde_json::from_value(summary_value).unwrap();
    assert_eq!(stdout, render_notarization_summary_markdown_v1(&summary));
}

#[test]
fn render_summary_html_matches_frozen_renderer_output_exactly() {
    let fixture = load_fixture();
    let summary_value = fixture.vectors[0].notarization_summary.clone();
    let summary_path = write_temp_json("summary_html_input", &summary_value);
    let summary_string = summary_path.to_str().unwrap().to_owned();

    let output = run_aura(&[
        "notarization",
        "render-summary",
        "--input-json",
        &summary_string,
        "--format",
        "html",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let summary: CanonicalTokenTransactionNotarizationSummaryV1 =
        serde_json::from_value(summary_value).unwrap();
    assert_eq!(stdout, render_notarization_summary_html_v1(&summary));
}

#[test]
fn malformed_summary_input_still_fails_closed() {
    let output = run_aura_with_stdin(
        &["notarization", "render-summary", "--format", "markdown"],
        &serde_json::json!({
            "summary_version": 1,
            "record_version": 1,
            "proof_statement_type": 1
        }),
    );

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("json error:"));
}
