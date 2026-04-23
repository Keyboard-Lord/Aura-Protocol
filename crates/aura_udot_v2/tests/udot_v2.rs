use aura_udot_v2::{
    derive_udot_v1_legacy, derive_udot_v2, parse_udot_artifact, validate_udot_artifact,
    AuraHashBytes, UdotArtifactKind, UdotHashError, UdotParseError, UdotValidationError,
    UdotVersion,
};

#[path = "support/udot_fixture_v1.rs"]
mod udot_fixture_v1;

use udot_fixture_v1::{
    assert_udot_fixture_schema_v1, load_udot_fixture_v1, udot_artifact_value_by_kind_v1,
    FixtureArtifactKindV1, FixtureFileV1, FixtureUdotVersionV1,
};

fn hash(input: &str) -> AuraHashBytes {
    AuraHashBytes::from_hex(input).expect("valid test hash")
}

impl From<FixtureUdotVersionV1> for UdotVersion {
    fn from(value: FixtureUdotVersionV1) -> Self {
        match value {
            FixtureUdotVersionV1::V2 => UdotVersion::V2,
            FixtureUdotVersionV1::V1Legacy => UdotVersion::V1Legacy,
        }
    }
}

impl From<FixtureArtifactKindV1> for UdotArtifactKind {
    fn from(value: FixtureArtifactKindV1) -> Self {
        match value {
            FixtureArtifactKindV1::SealLine => UdotArtifactKind::SealLine,
            FixtureArtifactKindV1::Crest => UdotArtifactKind::Crest,
            FixtureArtifactKindV1::MatrixSequence => UdotArtifactKind::MatrixSequence,
            FixtureArtifactKindV1::MatrixForm => UdotArtifactKind::MatrixForm,
        }
    }
}

fn load_fixture() -> FixtureFileV1 {
    load_udot_fixture_v1()
}

#[test]
fn shared_fixture_schema_is_pinned_for_rust_and_typescript_parity() {
    let fixture = load_fixture();
    assert_udot_fixture_schema_v1(&fixture);
}

#[test]
fn v2_known_answer_vectors_match_shared_machine_readable_fixture() {
    let fixture = load_fixture();

    for vector in &fixture.v2_vectors {
        let artifacts = derive_udot_v2(hash(&vector.input_aura_hash_hex));
        assert_eq!(artifacts.format_version, UdotVersion::V2);
        assert_eq!(
            artifacts.seal_line.as_str(),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
        );
        assert_eq!(
            artifacts.crest.as_str(),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::Crest)
        );
        assert_eq!(
            artifacts.matrix_sequence.as_str(),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence)
        );
        assert_eq!(
            artifacts.matrix_form.as_str(),
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixForm)
        );
        assert!(!artifacts.matrix_form.as_str().ends_with('\n'));
    }
}

#[test]
fn legacy_v1_regression_vector_matches_shared_machine_readable_fixture() {
    let fixture = load_fixture();
    let artifacts = derive_udot_v1_legacy(hash(&fixture.legacy_v1_regression.input_aura_hash_hex));

    assert_eq!(artifacts.format_version, UdotVersion::V1Legacy);
    assert_eq!(
        artifacts.seal_line.as_str(),
        udot_artifact_value_by_kind_v1(
            &fixture.legacy_v1_regression,
            FixtureArtifactKindV1::SealLine
        )
    );
    assert_eq!(
        artifacts.crest.as_str(),
        udot_artifact_value_by_kind_v1(&fixture.legacy_v1_regression, FixtureArtifactKindV1::Crest)
    );
}

#[test]
fn uppercase_hash_text_normalizes_to_same_bytes_and_outputs() {
    let fixture = load_fixture();
    let lower = hash(&fixture.v2_vectors[0].input_aura_hash_hex);
    let upper = hash(&fixture.v2_vectors[0].input_aura_hash_hex.to_uppercase());

    assert_eq!(lower, upper);
    assert_eq!(lower.to_string(), fixture.v2_vectors[0].input_aura_hash_hex);
    assert_eq!(derive_udot_v2(lower), derive_udot_v2(upper));
}

#[test]
fn malformed_hash_input_is_rejected_loudly() {
    let short = AuraHashBytes::from_hex("abcd").unwrap_err();
    assert!(matches!(
        short,
        UdotHashError::InvalidLength {
            expected: 64,
            actual: 4
        }
    ));

    let whitespace =
        AuraHashBytes::from_hex("14eda752a31094ed7cffb71864a880373b6cc24ec252f5bb70f4661ee61e91f ")
            .unwrap_err();
    assert!(matches!(
        whitespace,
        UdotHashError::InvalidWhitespace { .. }
    ));

    let prefixed =
        AuraHashBytes::from_hex("0xeda752a31094ed7cffb71864a880373b6cc24ec252f5bb70f4661ee61e91fd")
            .unwrap_err();
    assert!(matches!(prefixed, UdotHashError::InvalidCharacter { .. }));

    let lookalike = AuraHashBytes::from_hex(
        "14eda752a31094ed7cffb71864a880373b6cc24ec252f5bb70f4661ee61e91f〇",
    )
    .unwrap_err();
    assert!(matches!(lookalike, UdotHashError::InvalidCharacter { .. }));
}

#[test]
fn parser_and_validator_round_trip_canonical_forms_from_shared_fixture() {
    let fixture = load_fixture();

    for vector in &fixture.v2_vectors {
        let version = UdotVersion::from(vector.udot_version);
        let aura_hash = hash(&vector.input_aura_hash_hex);

        for artifact in &vector.artifacts {
            let kind = UdotArtifactKind::from(artifact.artifact_kind);
            let parsed = parse_udot_artifact(version, kind, &artifact.value).unwrap();
            let validated =
                validate_udot_artifact(version, kind, aura_hash, &artifact.value).unwrap();

            assert_eq!(parsed.to_string(), artifact.value);
            assert_eq!(validated.to_string(), artifact.value);
        }
    }

    let legacy = &fixture.legacy_v1_regression;
    let version = UdotVersion::from(legacy.udot_version);
    let aura_hash = hash(&legacy.input_aura_hash_hex);
    for artifact in &legacy.artifacts {
        let kind = UdotArtifactKind::from(artifact.artifact_kind);
        let parsed = parse_udot_artifact(version, kind, &artifact.value).unwrap();
        let validated = validate_udot_artifact(version, kind, aura_hash, &artifact.value).unwrap();

        assert_eq!(parsed.to_string(), artifact.value);
        assert_eq!(validated.to_string(), artifact.value);
    }
}

#[test]
fn malformed_glyph_inputs_are_rejected() {
    let invalid_v2_glyph = parse_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::SealLine,
        "x■•◦▣▣□○◦∘□◦◦▤▤□",
    )
    .unwrap_err();
    assert!(matches!(
        invalid_v2_glyph,
        UdotParseError::InvalidGlyph { .. }
    ));

    let invalid_v2_whitespace = parse_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::SealLine,
        "◇ ■•◦▣▣□○◦∘□◦◦▤▤□",
    )
    .unwrap_err();
    assert!(matches!(
        invalid_v2_whitespace,
        UdotParseError::InvalidLength { .. }
    ));

    let invalid_matrix_form = parse_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::MatrixForm,
        "∙◇□◆■◆ㅁ•\r\n◆▤∙◌•▣◦◈\n○◈■◈•∙◇◎\n■∙∘◎◆∙•⟡\nㅁ⟡ㅁ•■◈∘ㅁ\n○◈◦◈◎◎◇▤\n□○•□∙⟡◈□\n◦⟡•○ㅁ▤◌⟡",
    )
    .unwrap_err();
    assert!(matches!(
        invalid_matrix_form,
        UdotParseError::InvalidWhitespace { .. }
    ));

    let trailing_newline = parse_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::MatrixForm,
        "∙◇□◆■◆ㅁ•\n◆▤∙◌•▣◦◈\n○◈■◈•∙◇◎\n■∙∘◎◆∙•⟡\nㅁ⟡ㅁ•■◈∘ㅁ\n○◈◦◈◎◎◇▤\n□○•□∙⟡◈□\n◦⟡•○ㅁ▤◌⟡\n",
    )
    .unwrap_err();
    assert!(matches!(
        trailing_newline,
        UdotParseError::InvalidMatrixRowCount { .. }
    ));

    let unsupported = parse_udot_artifact(
        UdotVersion::V1Legacy,
        UdotArtifactKind::MatrixSequence,
        "ignored",
    )
    .unwrap_err();
    assert!(matches!(
        unsupported,
        UdotParseError::UnsupportedArtifactForVersion { .. }
    ));
}

#[test]
fn validation_requires_exact_semantic_match() {
    let fixture = load_fixture();
    let input = hash(&fixture.v2_vectors[0].input_aura_hash_hex);
    let v2 = derive_udot_v2(input);
    let validated = validate_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::SealLine,
        input,
        v2.seal_line.as_str(),
    )
    .unwrap();
    assert_eq!(validated.to_string(), v2.seal_line.to_string());

    let mismatch = validate_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::SealLine,
        input,
        "◦■•◦▣▣□○◦∘□◦◦▤▤□",
    )
    .unwrap_err();
    assert!(matches!(mismatch, UdotValidationError::Mismatch { .. }));
}

#[test]
fn deterministic_repeatability_holds() {
    let fixture = load_fixture();
    let input = hash(&fixture.v2_vectors[2].input_aura_hash_hex);
    let first = derive_udot_v2(input);
    let second = derive_udot_v2(input);
    let legacy_first = derive_udot_v1_legacy(input);
    let legacy_second = derive_udot_v1_legacy(input);

    assert_eq!(first, second);
    assert_eq!(legacy_first, legacy_second);
}

#[test]
fn cross_format_boundary_is_explicit() {
    let fixture = load_fixture();
    let input = hash(&fixture.legacy_v1_regression.input_aura_hash_hex);
    let legacy = derive_udot_v1_legacy(input);
    let active = derive_udot_v2(input);

    assert_ne!(legacy.seal_line.as_str(), active.seal_line.as_str());
    assert_ne!(legacy.crest.as_str(), active.crest.as_str());

    let syntactic_v2_parse = parse_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::SealLine,
        legacy.seal_line.as_str(),
    )
    .unwrap();
    assert_eq!(syntactic_v2_parse.to_string(), legacy.seal_line.to_string());

    let semantic_v2_validation = validate_udot_artifact(
        UdotVersion::V2,
        UdotArtifactKind::SealLine,
        input,
        legacy.seal_line.as_str(),
    )
    .unwrap_err();
    assert!(matches!(
        semantic_v2_validation,
        UdotValidationError::Mismatch { .. }
    ));
}

#[test]
fn unicode_glyphs_are_stable_exact_code_points() {
    let fixture = load_fixture();
    let artifacts = derive_udot_v2(hash(&fixture.v2_vectors[0].input_aura_hash_hex));

    let expected = [
        '◇', '■', '•', '◦', '▣', '▣', '□', '○', '◦', '∘', '□', '◦', '◦', '▤', '▤', '□',
    ];
    let actual: Vec<char> = artifacts.seal_line.as_str().chars().collect();
    assert_eq!(actual, expected);
}
