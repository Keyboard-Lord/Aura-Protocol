use aura_cli_v1::Cli;
use clap::Parser;
use serde_json::{json, Value};
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "../../aura_udot_v2/tests/support/udot_fixture_v1.rs"]
mod udot_fixture_v1;

use udot_fixture_v1::{
    assert_udot_fixture_schema_v1, load_udot_fixture_v1, udot_artifact_value_by_kind_v1,
    FixtureArtifactKindV1,
};

static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn run_aura(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aura"))
        .args(args)
        .output()
        .unwrap()
}

fn load_fixture() -> udot_fixture_v1::FixtureFileV1 {
    load_udot_fixture_v1()
}

fn write_temp_json(label: &str, value: &Value) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "aura_udot_cli_{}_{}_{}.json",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed),
        label
    ));
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

#[test]
fn shared_fixture_schema_is_pinned_for_cli_consumer_boundary() {
    assert_udot_fixture_schema_v1(&load_fixture());
}

#[test]
fn udot_generate_v2_succeeds_with_explicit_version() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let output = run_aura(&[
        "udot",
        "generate",
        "--hash",
        &vector.input_aura_hash_hex,
        "--udot-version",
        "v2",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "udot_version: v2\naura_hash_hex: {}\nseal_line: {}\ncrest: {}\nmatrix_sequence: {}\nmatrix_form:\n{}\n",
            vector.input_aura_hash_hex,
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::Crest),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixForm),
        )
    );
}

#[test]
fn udot_generate_v1_legacy_succeeds_only_when_explicitly_requested() {
    let fixture = load_fixture();
    let legacy = &fixture.legacy_v1_regression;
    let output = run_aura(&[
        "udot",
        "generate",
        "--hash",
        &legacy.input_aura_hash_hex,
        "--udot-version",
        "v1-legacy",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "udot_version: v1-legacy\naura_hash_hex: {}\nseal_line: {}\ncrest: {}\n",
            legacy.input_aura_hash_hex,
            udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::SealLine),
            udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::Crest),
        )
    );
}

#[test]
fn udot_generate_v2_json_matches_exact_wire_schema() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let output = run_aura(&[
        "udot",
        "generate",
        "--hash",
        &vector.input_aura_hash_hex,
        "--udot-version",
        "v2",
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({
            "udot_version": "v2",
            "aura_hash_hex": vector.input_aura_hash_hex,
            "seal_line": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
            "crest": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::Crest),
            "matrix_sequence": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence),
            "matrix_form": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixForm),
        })
    );
}

#[test]
fn udot_generate_v1_legacy_json_matches_exact_wire_schema() {
    let fixture = load_fixture();
    let legacy = &fixture.legacy_v1_regression;
    let output = run_aura(&[
        "udot",
        "generate",
        "--hash",
        &legacy.input_aura_hash_hex,
        "--udot-version",
        "v1-legacy",
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({
            "udot_version": "v1-legacy",
            "aura_hash_hex": legacy.input_aura_hash_hex,
            "seal_line": udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::SealLine),
            "crest": udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::Crest),
        })
    );
}

#[test]
fn udot_generate_fails_when_udot_version_is_omitted() {
    let fixture = load_fixture();
    let error = Cli::try_parse_from([
        "aura",
        "udot",
        "generate",
        "--hash",
        &fixture.v2_vectors[0].input_aura_hash_hex,
    ])
    .unwrap_err();

    let rendered = error.to_string();
    assert!(rendered.contains("--udot-version"));
}

#[test]
fn udot_generate_json_still_requires_explicit_udot_version() {
    let fixture = load_fixture();
    let error = Cli::try_parse_from([
        "aura",
        "udot",
        "generate",
        "--hash",
        &fixture.v2_vectors[0].input_aura_hash_hex,
        "--output",
        "json",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("--udot-version"));
}

#[test]
fn udot_parse_rejects_malformed_glyph_strings() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let malformed = format!(
        "x{}",
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
            .chars()
            .skip(1)
            .collect::<String>()
    );
    let output = run_aura(&[
        "udot",
        "parse",
        "--artifact-kind",
        "seal-line",
        "--value",
        &malformed,
        "--udot-version",
        "v2",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("udot artifact parse failed"));
}

#[test]
fn udot_parse_json_rejects_missing_udot_version() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let path = write_temp_json(
        "parse_missing_version",
        &json!({
            "artifact_kind": "seal-line",
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        }),
    );
    let path_string = path.to_str().unwrap().to_owned();
    let output = run_aura(&[
        "udot",
        "parse",
        "--input-json",
        &path_string,
        "--output",
        "json",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("missing field `udot_version`"));
}

#[test]
fn udot_parse_json_round_trip_succeeds_for_known_good_wire_payload() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let path = write_temp_json(
        "parse_round_trip",
        &json!({
            "udot_version": "v2",
            "artifact_kind": "seal-line",
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        }),
    );
    let path_string = path.to_str().unwrap().to_owned();
    let output = run_aura(&[
        "udot",
        "parse",
        "--input-json",
        &path_string,
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({
            "udot_version": "v2",
            "artifact_kind": "seal-line",
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        })
    );
}

#[test]
fn udot_parse_succeeds_for_known_good_canonical_vectors() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let output = run_aura(&[
        "udot",
        "parse",
        "--artifact-kind",
        "seal-line",
        "--value",
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        "--udot-version",
        "v2",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "status: parsed\nudot_version: v2\nartifact_kind: seal-line\nvalue: {}\n",
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
        )
    );
}

#[test]
fn udot_validate_json_rejects_missing_artifact_kind() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let path = write_temp_json(
        "validate_missing_kind",
        &json!({
            "udot_version": "v2",
            "aura_hash_hex": vector.input_aura_hash_hex,
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        }),
    );
    let path_string = path.to_str().unwrap().to_owned();
    let output = run_aura(&[
        "udot",
        "validate",
        "--input-json",
        &path_string,
        "--output",
        "json",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("missing field `artifact_kind`"));
}

#[test]
fn udot_validate_json_rejects_v1_matrix_payloads() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let legacy = &fixture.legacy_v1_regression;
    let path = write_temp_json(
        "validate_v1_matrix",
        &json!({
            "udot_version": "v1-legacy",
            "artifact_kind": "matrix-sequence",
            "aura_hash_hex": legacy.input_aura_hash_hex,
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence),
        }),
    );
    let path_string = path.to_str().unwrap().to_owned();
    let output = run_aura(&[
        "udot",
        "validate",
        "--input-json",
        &path_string,
        "--output",
        "json",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("matrix_sequence is not defined for UDOT V1 legacy"));
}

#[test]
fn udot_validate_rejects_version_mismatch() {
    let fixture = load_fixture();
    let legacy = &fixture.legacy_v1_regression;
    let output = run_aura(&[
        "udot",
        "validate",
        "--hash",
        &legacy.input_aura_hash_hex,
        "--artifact-kind",
        "seal-line",
        "--value",
        udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::SealLine),
        "--udot-version",
        "v2",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("udot artifact validation failed"));
}

#[test]
fn udot_validate_json_round_trip_succeeds_for_known_good_wire_payload() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let path = write_temp_json(
        "validate_round_trip",
        &json!({
            "udot_version": "v2",
            "artifact_kind": "seal-line",
            "aura_hash_hex": vector.input_aura_hash_hex,
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        }),
    );
    let path_string = path.to_str().unwrap().to_owned();
    let output = run_aura(&[
        "udot",
        "validate",
        "--input-json",
        &path_string,
        "--output",
        "json",
    ]);

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({
            "udot_version": "v2",
            "artifact_kind": "seal-line",
            "value": udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        })
    );
}

#[test]
fn udot_validate_succeeds_for_known_good_canonical_vectors() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let output = run_aura(&[
        "udot",
        "validate",
        "--hash",
        &vector.input_aura_hash_hex,
        "--artifact-kind",
        "seal-line",
        "--value",
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
        "--udot-version",
        "v2",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "status: valid\nudot_version: v2\nartifact_kind: seal-line\nvalue: {}\n",
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
        )
    );
}

#[test]
fn udot_matrix_artifacts_are_rejected_for_v1_legacy() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let output = run_aura(&[
        "udot",
        "parse",
        "--artifact-kind",
        "matrix-sequence",
        "--value",
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence),
        "--udot-version",
        "v1-legacy",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("matrix_sequence is not defined for UDOT V1 legacy"));
}

#[test]
fn no_udot_command_path_silently_defaults_the_version() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let parse_error = Cli::try_parse_from([
        "aura",
        "udot",
        "parse",
        "--artifact-kind",
        "seal-line",
        "--value",
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
    ])
    .unwrap_err();
    assert!(parse_error.to_string().contains("--udot-version"));

    let validate_error = Cli::try_parse_from([
        "aura",
        "udot",
        "validate",
        "--hash",
        &vector.input_aura_hash_hex,
        "--artifact-kind",
        "seal-line",
        "--value",
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine),
    ])
    .unwrap_err();
    assert!(validate_error.to_string().contains("--udot-version"));
}
