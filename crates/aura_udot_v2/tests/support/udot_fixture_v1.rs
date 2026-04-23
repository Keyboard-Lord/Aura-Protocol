use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureUdotVersionV1 {
    V2,
    V1Legacy,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureArtifactKindV1 {
    SealLine,
    Crest,
    MatrixSequence,
    MatrixForm,
}

#[derive(Debug, Deserialize)]
pub struct FixtureSourceOfTruthV1 {
    pub canonical_spec: String,
    pub status_doc: String,
}

#[derive(Debug, Deserialize)]
pub struct FixtureArtifactValueV1 {
    pub artifact_kind: FixtureArtifactKindV1,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct FixtureVectorV1 {
    pub name: String,
    pub udot_version: FixtureUdotVersionV1,
    pub input_aura_hash_hex: String,
    pub artifacts: Vec<FixtureArtifactValueV1>,
}

#[derive(Debug, Deserialize)]
pub struct FixtureFileV1 {
    pub version: u8,
    pub primitive: String,
    pub source_of_truth: FixtureSourceOfTruthV1,
    pub v2_vectors: Vec<FixtureVectorV1>,
    pub legacy_v1_regression: FixtureVectorV1,
}

pub fn load_udot_fixture_v1() -> FixtureFileV1 {
    let path = fixture_path_v1();
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

pub fn assert_udot_fixture_schema_v1(fixture: &FixtureFileV1) {
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.primitive, "aura_udot");
    assert_eq!(
        fixture.source_of_truth.canonical_spec,
        "docs/authoritative/AURA_UDOT_SPEC_V1.md"
    );
    assert_eq!(
        fixture.source_of_truth.status_doc,
        "docs/authoritative/AURA_VECTOR_MATRIX_V1.md"
    );
    assert_eq!(fixture.v2_vectors.len(), 3);
    assert_eq!(fixture.v2_vectors[0].name, "UDOT-V2-001");
    assert_eq!(fixture.v2_vectors[1].name, "UDOT-V2-002");
    assert_eq!(fixture.v2_vectors[2].name, "UDOT-V2-003");
    assert_eq!(fixture.legacy_v1_regression.name, "UDOT-V1-001");

    for vector in &fixture.v2_vectors {
        assert_eq!(vector.udot_version, FixtureUdotVersionV1::V2);
        assert_eq!(vector.input_aura_hash_hex.len(), 64);
        let kinds: Vec<FixtureArtifactKindV1> = vector
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                FixtureArtifactKindV1::SealLine,
                FixtureArtifactKindV1::Crest,
                FixtureArtifactKindV1::MatrixSequence,
                FixtureArtifactKindV1::MatrixForm,
            ]
        );
    }

    assert_eq!(
        fixture.legacy_v1_regression.udot_version,
        FixtureUdotVersionV1::V1Legacy
    );
    assert_eq!(fixture.legacy_v1_regression.input_aura_hash_hex.len(), 64);
    let legacy_kinds: Vec<FixtureArtifactKindV1> = fixture
        .legacy_v1_regression
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_kind)
        .collect();
    assert_eq!(
        legacy_kinds,
        vec![
            FixtureArtifactKindV1::SealLine,
            FixtureArtifactKindV1::Crest
        ]
    );
}

pub fn udot_artifact_value_by_kind_v1(
    vector: &FixtureVectorV1,
    kind: FixtureArtifactKindV1,
) -> &str {
    vector
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_kind == kind)
        .map(|artifact| artifact.value.as_str())
        .unwrap_or_else(|| panic!("{} missing artifact {:?}", vector.name, kind))
}

fn fixture_path_v1() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("udot_v1")
        .join("test_vectors.json")
}
