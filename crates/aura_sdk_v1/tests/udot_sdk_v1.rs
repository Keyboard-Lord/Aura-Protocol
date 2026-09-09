use aura_sdk_v1::{legacy::generate_udot_artifact_bundle_wire_v1, legacy::generate_udot_artifacts_v1, legacy::parse_udot_artifact_bundle_wire_v1, legacy::parse_udot_artifact_v1, legacy::parse_udot_artifact_wire_v1, legacy::validate_udot_artifact_v1, legacy::validate_udot_artifact_wire_v1, AuraSdkErrorV1, legacy::GenerateUdotArtifactBundleWireRequestV1, legacy::GenerateUdotArtifactsRequestV1, legacy::ParseUdotArtifactRequestV1, legacy::UdotArtifactBundleWireV1, legacy::UdotArtifactKind, legacy::UdotArtifactWireV1, UdotParseError, UdotValidationError, legacy::UdotVersion, legacy::ValidateUdotArtifactRequestV1, legacy::ValidateUdotArtifactWireRequestV1};
use serde_json;

#[path = "../../aura_udot_v2/tests/support/udot_fixture_v1.rs"]
mod udot_fixture_v1;

use udot_fixture_v1::{
    assert_udot_fixture_schema_v1, load_udot_fixture_v1, udot_artifact_value_by_kind_v1,
    FixtureArtifactKindV1,
};

fn load_fixture() -> udot_fixture_v1::FixtureFileV1 {
    load_udot_fixture_v1()
}

#[test]
fn shared_fixture_schema_is_pinned_for_sdk_consumer_boundary() {
    assert_udot_fixture_schema_v1(&load_fixture());
}

#[test]
fn v2_generation_works_through_sdk_boundary() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let generated = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V2,
        aura_hash_hex: &vector.input_aura_hash_hex,
    })
    .unwrap();

    assert_eq!(generated.udot_version, UdotVersion::V2);
    assert_eq!(generated.aura_hash_hex, vector.input_aura_hash_hex);
    assert_eq!(generated.seal_line.udot_version, UdotVersion::V2);
    assert_eq!(
        generated.seal_line.artifact_kind,
        UdotArtifactKind::SealLine
    );
    assert_eq!(
        generated.seal_line.as_str(),
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
    );
    assert_eq!(generated.crest.udot_version, UdotVersion::V2);
    assert_eq!(generated.crest.artifact_kind, UdotArtifactKind::Crest);
    assert_eq!(
        generated.crest.as_str(),
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::Crest)
    );
    assert_eq!(
        generated.matrix_sequence.as_ref().unwrap().as_str(),
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence)
    );
    assert_eq!(
        generated.matrix_form.as_ref().unwrap().as_str(),
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixForm)
    );
}

#[test]
fn legacy_v1_generation_only_occurs_when_explicitly_requested() {
    let fixture = load_fixture();
    let legacy_vector = &fixture.legacy_v1_regression;
    let active_vector = &fixture.v2_vectors[0];
    let legacy = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V1Legacy,
        aura_hash_hex: &legacy_vector.input_aura_hash_hex,
    })
    .unwrap();
    let active = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V2,
        aura_hash_hex: &active_vector.input_aura_hash_hex,
    })
    .unwrap();

    assert_eq!(legacy.udot_version, UdotVersion::V1Legacy);
    assert_eq!(
        legacy.seal_line.as_str(),
        udot_artifact_value_by_kind_v1(legacy_vector, FixtureArtifactKindV1::SealLine)
    );
    assert_eq!(
        legacy.crest.as_str(),
        udot_artifact_value_by_kind_v1(legacy_vector, FixtureArtifactKindV1::Crest)
    );
    assert!(legacy.matrix_sequence.is_none());
    assert!(legacy.matrix_form.is_none());
    assert_eq!(
        active.seal_line.as_str(),
        udot_artifact_value_by_kind_v1(active_vector, FixtureArtifactKindV1::SealLine)
    );
    assert_eq!(
        active.crest.as_str(),
        udot_artifact_value_by_kind_v1(active_vector, FixtureArtifactKindV1::Crest)
    );
    assert_ne!(legacy.seal_line.as_str(), active.seal_line.as_str());
    assert_ne!(legacy.crest.as_str(), active.crest.as_str());
}

#[test]
fn malformed_artifacts_are_rejected_through_sdk_parse_boundary() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let error = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
        udot_version: UdotVersion::V2,
        artifact_kind: UdotArtifactKind::SealLine,
        serialized_artifact: &format!(
            "x{}",
            udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
                .chars()
                .skip(1)
                .collect::<String>()
        ),
    })
    .unwrap_err();

    assert!(matches!(
        error,
        AuraSdkErrorV1::UdotArtifactParseFailed(UdotParseError::InvalidGlyph { .. })
    ));
}

#[test]
fn validation_rejects_version_mismatch_without_guessing() {
    let fixture = load_fixture();
    let legacy_vector = &fixture.legacy_v1_regression;
    let legacy = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V1Legacy,
        aura_hash_hex: &legacy_vector.input_aura_hash_hex,
    })
    .unwrap();

    let error = validate_udot_artifact_v1(ValidateUdotArtifactRequestV1 {
        udot_version: UdotVersion::V2,
        artifact_kind: UdotArtifactKind::SealLine,
        aura_hash_hex: &legacy_vector.input_aura_hash_hex,
        serialized_artifact: legacy.seal_line.as_str(),
    })
    .unwrap_err();

    assert!(matches!(
        error,
        AuraSdkErrorV1::UdotArtifactValidationFailed(UdotValidationError::Mismatch {
            version: UdotVersion::V2,
            kind: UdotArtifactKind::SealLine,
            ..
        })
    ));
}

#[test]
fn serialize_parse_validate_round_trip_succeeds_for_correct_version() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let generated = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V2,
        aura_hash_hex: &vector.input_aura_hash_hex,
    })
    .unwrap();

    let candidates = [
        &generated.seal_line,
        &generated.crest,
        generated.matrix_sequence.as_ref().unwrap(),
        generated.matrix_form.as_ref().unwrap(),
    ];

    for candidate in candidates {
        let parsed = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
            udot_version: candidate.udot_version,
            artifact_kind: candidate.artifact_kind,
            serialized_artifact: candidate.as_str(),
        })
        .unwrap();
        let validated = validate_udot_artifact_v1(ValidateUdotArtifactRequestV1 {
            udot_version: candidate.udot_version,
            artifact_kind: candidate.artifact_kind,
            aura_hash_hex: &vector.input_aura_hash_hex,
            serialized_artifact: candidate.as_str(),
        })
        .unwrap();

        assert_eq!(parsed, (*candidate).clone());
        assert_eq!(validated, (*candidate).clone());
    }
}

#[test]
fn generation_is_deterministic_through_sdk_boundary() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let first = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V2,
        aura_hash_hex: &vector.input_aura_hash_hex,
    })
    .unwrap();
    let second = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: UdotVersion::V2,
        aura_hash_hex: &vector.input_aura_hash_hex,
    })
    .unwrap();

    assert_eq!(first, second);
}

#[test]
fn wire_artifact_json_requires_explicit_version_and_kind() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let seal_line = udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine);

    let missing_version = serde_json::from_str::<UdotArtifactWireV1>(&format!(
        r#"{{"artifact_kind":"seal-line","value":"{seal_line}"}}"#
    ))
    .unwrap_err();
    assert!(missing_version
        .to_string()
        .contains("missing field `udot_version`"));

    let missing_kind = serde_json::from_str::<UdotArtifactWireV1>(&format!(
        r#"{{"udot_version":"v2","value":"{seal_line}"}}"#
    ))
    .unwrap_err();
    assert!(missing_kind
        .to_string()
        .contains("missing field `artifact_kind`"));
}

#[test]
fn v2_wire_bundle_round_trips_through_json_and_parse_boundary() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let generated =
        generate_udot_artifact_bundle_wire_v1(GenerateUdotArtifactBundleWireRequestV1 {
            udot_version: UdotVersion::V2,
            aura_hash_hex: vector.input_aura_hash_hex.clone(),
        })
        .unwrap();
    let encoded = serde_json::to_string(&generated).unwrap();
    let decoded: UdotArtifactBundleWireV1 = serde_json::from_str(&encoded).unwrap();
    let parsed = parse_udot_artifact_bundle_wire_v1(decoded).unwrap();

    assert_eq!(
        parsed,
        UdotArtifactBundleWireV1::V2 {
            aura_hash_hex: vector.input_aura_hash_hex.clone(),
            seal_line: udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::SealLine)
                .to_owned(),
            crest: udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::Crest).to_owned(),
            matrix_sequence: udot_artifact_value_by_kind_v1(
                vector,
                FixtureArtifactKindV1::MatrixSequence,
            )
            .to_owned(),
            matrix_form: udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixForm)
                .to_owned(),
        }
    );
}

#[test]
fn legacy_v1_wire_bundle_round_trips_through_json_and_parse_boundary() {
    let fixture = load_fixture();
    let legacy = &fixture.legacy_v1_regression;
    let generated =
        generate_udot_artifact_bundle_wire_v1(GenerateUdotArtifactBundleWireRequestV1 {
            udot_version: UdotVersion::V1Legacy,
            aura_hash_hex: legacy.input_aura_hash_hex.clone(),
        })
        .unwrap();
    let encoded = serde_json::to_string(&generated).unwrap();
    let decoded: UdotArtifactBundleWireV1 = serde_json::from_str(&encoded).unwrap();
    let parsed = parse_udot_artifact_bundle_wire_v1(decoded).unwrap();

    assert_eq!(
        parsed,
        UdotArtifactBundleWireV1::V1Legacy {
            aura_hash_hex: legacy.input_aura_hash_hex.clone(),
            seal_line: udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::SealLine)
                .to_owned(),
            crest: udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::Crest).to_owned(),
        }
    );
}

#[test]
fn wire_transport_rejects_matrix_artifacts_for_v1_legacy() {
    let fixture = load_fixture();
    let vector = &fixture.v2_vectors[0];
    let error = parse_udot_artifact_wire_v1(UdotArtifactWireV1 {
        udot_version: UdotVersion::V1Legacy,
        artifact_kind: UdotArtifactKind::MatrixSequence,
        value: udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence)
            .to_owned(),
    })
    .unwrap_err();

    assert!(matches!(
        error,
        AuraSdkErrorV1::UdotArtifactParseFailed(UdotParseError::UnsupportedArtifactForVersion {
            version: UdotVersion::V1Legacy,
            kind: UdotArtifactKind::MatrixSequence,
        })
    ));

    let legacy = &fixture.legacy_v1_regression;
    let bundle_error = serde_json::from_str::<UdotArtifactBundleWireV1>(&format!(
        r#"{{
            "udot_version":"v1-legacy",
            "aura_hash_hex":"{}",
            "seal_line":"{}",
            "crest":"{}",
            "matrix_sequence":"{}"
        }}"#,
        legacy.input_aura_hash_hex,
        udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::SealLine),
        udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::Crest),
        udot_artifact_value_by_kind_v1(vector, FixtureArtifactKindV1::MatrixSequence),
    ))
    .unwrap_err();
    assert!(bundle_error
        .to_string()
        .contains("unknown field `matrix_sequence`"));
}

#[test]
fn wire_validation_rejects_version_mismatch_without_guessing() {
    let fixture = load_fixture();
    let legacy = &fixture.legacy_v1_regression;
    let error = validate_udot_artifact_wire_v1(ValidateUdotArtifactWireRequestV1 {
        udot_version: UdotVersion::V2,
        artifact_kind: UdotArtifactKind::SealLine,
        aura_hash_hex: legacy.input_aura_hash_hex.clone(),
        value: udot_artifact_value_by_kind_v1(legacy, FixtureArtifactKindV1::SealLine).to_owned(),
    })
    .unwrap_err();

    assert!(matches!(
        error,
        AuraSdkErrorV1::UdotArtifactValidationFailed(UdotValidationError::Mismatch {
            version: UdotVersion::V2,
            kind: UdotArtifactKind::SealLine,
            ..
        })
    ));
}
