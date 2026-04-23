import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

export type UdotVersionFixtureV1 = "v2" | "v1-legacy";
export type UdotArtifactKindFixtureV1 =
  | "seal-line"
  | "crest"
  | "matrix-sequence"
  | "matrix-form";

export type UdotArtifactFixtureV1 = {
  artifact_kind: UdotArtifactKindFixtureV1;
  value: string;
};

export type UdotVectorFixtureV1 = {
  name: string;
  udot_version: UdotVersionFixtureV1;
  input_aura_hash_hex: string;
  artifacts: UdotArtifactFixtureV1[];
};

export type UdotTestVectorsFileV1 = {
  version: number;
  primitive: string;
  source_of_truth: {
    canonical_spec: string;
    status_doc: string;
  };
  v2_vectors: UdotVectorFixtureV1[];
  legacy_v1_regression: UdotVectorFixtureV1;
};

export function loadUdotTestVectorsV1(): UdotTestVectorsFileV1 {
  const contents = readFileSync(udotFixtureUrlV1(), "utf8");
  return JSON.parse(contents) as UdotTestVectorsFileV1;
}

export function assertUdotFixtureSchemaV1(
  fixture: UdotTestVectorsFileV1,
): void {
  assert.equal(fixture.version, 1);
  assert.equal(fixture.primitive, "aura_udot");
  assert.equal(
    fixture.source_of_truth.canonical_spec,
    "docs/authoritative/AURA_UDOT_SPEC_V1.md",
  );
  assert.equal(
    fixture.source_of_truth.status_doc,
    "docs/authoritative/AURA_VECTOR_MATRIX_V1.md",
  );
  assert.equal(fixture.v2_vectors.length, 3);
  assert.equal(fixture.v2_vectors[0]?.name, "UDOT-V2-001");
  assert.equal(fixture.v2_vectors[1]?.name, "UDOT-V2-002");
  assert.equal(fixture.v2_vectors[2]?.name, "UDOT-V2-003");
  assert.equal(fixture.legacy_v1_regression.name, "UDOT-V1-001");

  for (const vector of fixture.v2_vectors) {
    assert.equal(vector.udot_version, "v2");
    assert.equal(vector.input_aura_hash_hex.length, 64);
    assert.deepEqual(
      vector.artifacts.map(({ artifact_kind }) => artifact_kind),
      ["seal-line", "crest", "matrix-sequence", "matrix-form"],
    );
    assert.equal(Array.from(udotArtifactValueByKindV1(vector, "seal-line")).length, 16);
    assert.equal(Array.from(udotArtifactValueByKindV1(vector, "crest")).length, 8);
    assert.equal(
      Array.from(udotArtifactValueByKindV1(vector, "matrix-sequence")).length,
      64,
    );
    assert.equal(
      udotArtifactValueByKindV1(vector, "matrix-form").split("\n").length,
      8,
    );
  }

  assert.equal(fixture.legacy_v1_regression.udot_version, "v1-legacy");
  assert.equal(fixture.legacy_v1_regression.input_aura_hash_hex.length, 64);
  assert.deepEqual(
    fixture.legacy_v1_regression.artifacts.map(({ artifact_kind }) => artifact_kind),
    ["seal-line", "crest"],
  );
  assert.equal(
    Array.from(udotArtifactValueByKindV1(fixture.legacy_v1_regression, "seal-line"))
      .length,
    16,
  );
  assert.equal(
    Array.from(udotArtifactValueByKindV1(fixture.legacy_v1_regression, "crest")).length,
    8,
  );
}

export function udotArtifactValueByKindV1(
  vector: UdotVectorFixtureV1,
  artifactKind: UdotArtifactKindFixtureV1,
): string {
  const entry = vector.artifacts.find(
    ({ artifact_kind }) => artifact_kind === artifactKind,
  );

  assert.ok(entry, `${vector.name} missing artifact ${artifactKind}`);
  return entry.value;
}

function udotFixtureUrlV1(): URL {
  return new URL("../../fixtures/v1/udot_v1/test_vectors.json", import.meta.url);
}
