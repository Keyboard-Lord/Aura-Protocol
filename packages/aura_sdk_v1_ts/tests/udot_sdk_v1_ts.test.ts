import test from "node:test";
import assert from "node:assert/strict";

import { AuraSdkErrorV1, UdotHashError, UdotParseError, UdotValidationError } from "../src/index.ts";
import { generateUdotArtifactBundleWireV1, generateUdotArtifactsV1, parseUdotArtifactBundleWireV1, parseUdotArtifactV1, parseUdotArtifactWireV1, validateUdotArtifactWireV1, validateUdotArtifactV1 } from "../src/legacy/udot.ts";
import {
  assertUdotFixtureSchemaV1,
  loadUdotTestVectorsV1,
  udotArtifactValueByKindV1,
} from "../../test_support/udot_fixture_v1.ts";

const fixture = loadUdotTestVectorsV1();
const firstVector = fixture.v2_vectors[0]!;
const legacyRegression = fixture.legacy_v1_regression;

test("shared UDOT fixture schema stays pinned for TS parity tests", () => {
  assertUdotFixtureSchemaV1(fixture);
});

test("generateUdotArtifactsV1 matches all frozen V2 vectors with explicit version", async () => {
  for (const vector of fixture.v2_vectors) {
    const generated = await generateUdotArtifactsV1({
      udotVersion: "v2",
      auraHashHex: vector.input_aura_hash_hex,
    });

    assert.equal(generated.udotVersion, "v2");
    assert.equal(generated.auraHashHex, vector.input_aura_hash_hex);
    assert.equal(
      generated.sealLine.serializedArtifact,
      udotArtifactValueByKindV1(vector, "seal-line"),
    );
    assert.equal(
      generated.crest.serializedArtifact,
      udotArtifactValueByKindV1(vector, "crest"),
    );
    assert.equal(
      generated.matrixSequence?.serializedArtifact,
      udotArtifactValueByKindV1(vector, "matrix-sequence"),
    );
    assert.equal(
      generated.matrixForm?.serializedArtifact,
      udotArtifactValueByKindV1(vector, "matrix-form"),
    );
  }
});

test("generateUdotArtifactsV1 rejects uppercase aura hashes in canonical paths", async () => {
  await assert.rejects(
    generateUdotArtifactsV1({
      udotVersion: "v2",
      auraHashHex: firstVector.input_aura_hash_hex.toUpperCase(),
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotHashNormalizationFailed" &&
      error.cause instanceof UdotHashError &&
      error.cause.code === "NonCanonicalHex",
  );
});

test("generateUdotArtifactsV1 returns legacy artifacts only when explicitly requested", async () => {
  const generated = await generateUdotArtifactsV1({
    udotVersion: "v1-legacy",
    auraHashHex: legacyRegression.input_aura_hash_hex,
  });

  assert.equal(generated.udotVersion, "v1-legacy");
  assert.equal(generated.auraHashHex, legacyRegression.input_aura_hash_hex);
  assert.equal(
    generated.sealLine.serializedArtifact,
    udotArtifactValueByKindV1(legacyRegression, "seal-line"),
  );
  assert.equal(
    generated.crest.serializedArtifact,
    udotArtifactValueByKindV1(legacyRegression, "crest"),
  );
  assert.equal(generated.matrixSequence, undefined);
  assert.equal(generated.matrixForm, undefined);
});

test("parseUdotArtifactV1 rejects malformed glyph strings", () => {
  assert.throws(
    () =>
      parseUdotArtifactV1({
        udotVersion: "v2",
        artifactKind: "seal-line",
        serializedArtifact: `x${udotArtifactValueByKindV1(firstVector, "seal-line").slice(1)}`,
      }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactParseFailed" &&
      error.cause instanceof UdotParseError &&
      error.cause.code === "InvalidGlyph",
  );
});

test("validateUdotArtifactV1 rejects version mismatch", async () => {
  await assert.rejects(
    validateUdotArtifactV1({
      udotVersion: "v2",
      artifactKind: "seal-line",
      auraHashHex: legacyRegression.input_aura_hash_hex,
      serializedArtifact: udotArtifactValueByKindV1(legacyRegression, "seal-line"),
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactValidationFailed" &&
      error.cause instanceof UdotValidationError &&
      error.cause.code === "Mismatch",
  );
});

test("serialize parse validate round-trip succeeds for known-good V2 vectors", async () => {
  const generated = await generateUdotArtifactsV1({
    udotVersion: "v2",
    auraHashHex: firstVector.input_aura_hash_hex,
  });

  const candidates = [
    generated.sealLine,
    generated.crest,
    generated.matrixSequence!,
    generated.matrixForm!,
  ];

  for (const candidate of candidates) {
    const parsed = parseUdotArtifactV1({
      udotVersion: candidate.udotVersion,
      artifactKind: candidate.artifactKind,
      serializedArtifact: candidate.serializedArtifact,
    });
    const validated = await validateUdotArtifactV1({
      udotVersion: candidate.udotVersion,
      artifactKind: candidate.artifactKind,
      auraHashHex: firstVector.input_aura_hash_hex,
      serializedArtifact: candidate.serializedArtifact,
    });

    assert.deepEqual(parsed, candidate);
    assert.deepEqual(validated, candidate);
  }
});

test("matrix artifacts are rejected for legacy V1", () => {
  assert.throws(
    () =>
      parseUdotArtifactV1({
        udotVersion: "v1-legacy",
        artifactKind: "matrix-sequence",
        serializedArtifact: udotArtifactValueByKindV1(firstVector, "matrix-sequence"),
      }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactParseFailed" &&
      error.cause instanceof UdotParseError &&
      error.cause.code === "UnsupportedArtifactForVersion",
  );
});

test("no TypeScript UDOT API path silently defaults the version", async () => {
  await assert.rejects(
    generateUdotArtifactsV1({
      auraHashHex: firstVector.input_aura_hash_hex,
    } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'udotVersion must be "v2" or "v1-legacy"',
  );

  assert.throws(
    () =>
      parseUdotArtifactV1({
        artifactKind: "seal-line",
        serializedArtifact: udotArtifactValueByKindV1(firstVector, "seal-line"),
      } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'udotVersion must be "v2" or "v1-legacy"',
  );

  await assert.rejects(
    validateUdotArtifactV1({
      artifactKind: "seal-line",
      auraHashHex: firstVector.input_aura_hash_hex,
      serializedArtifact: udotArtifactValueByKindV1(firstVector, "seal-line"),
    } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'udotVersion must be "v2" or "v1-legacy"',
  );
});

test("validateUdotArtifactV1 rejects malformed inputs before semantic validation", async () => {
  await assert.rejects(
    validateUdotArtifactV1({
      udotVersion: "v2",
      artifactKind: "seal-line",
      auraHashHex: firstVector.input_aura_hash_hex,
      serializedArtifact: `x${udotArtifactValueByKindV1(firstVector, "seal-line").slice(1)}`,
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactValidationFailed" &&
      error.cause instanceof UdotValidationError &&
      error.cause.code === "Parse",
  );
});

test("parseUdotArtifactWireV1 requires explicit udot_version and artifact_kind", () => {
  assert.throws(
    () =>
      parseUdotArtifactWireV1({
        artifact_kind: "seal-line",
        value: udotArtifactValueByKindV1(firstVector, "seal-line"),
      } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'udot_version must be "v2" or "v1-legacy"',
  );

  assert.throws(
    () =>
      parseUdotArtifactWireV1({
        udot_version: "v2",
        value: udotArtifactValueByKindV1(firstVector, "seal-line"),
      } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message ===
        'artifact_kind must be "seal-line", "crest", "matrix-sequence", or "matrix-form"',
  );
});

test("generateUdotArtifactBundleWireV1 and parseUdotArtifactBundleWireV1 round-trip V2 JSON", async () => {
  const bundle = await generateUdotArtifactBundleWireV1({
    udot_version: "v2",
    aura_hash_hex: firstVector.input_aura_hash_hex,
  });
  const parsed = parseUdotArtifactBundleWireV1(JSON.parse(JSON.stringify(bundle)));

  assert.deepEqual(parsed, {
    udot_version: "v2",
    aura_hash_hex: firstVector.input_aura_hash_hex,
    seal_line: udotArtifactValueByKindV1(firstVector, "seal-line"),
    crest: udotArtifactValueByKindV1(firstVector, "crest"),
    matrix_sequence: udotArtifactValueByKindV1(firstVector, "matrix-sequence"),
    matrix_form: udotArtifactValueByKindV1(firstVector, "matrix-form"),
  });
});

test("generateUdotArtifactBundleWireV1 and parseUdotArtifactBundleWireV1 round-trip legacy V1 JSON", async () => {
  const bundle = await generateUdotArtifactBundleWireV1({
    udot_version: "v1-legacy",
    aura_hash_hex: legacyRegression.input_aura_hash_hex,
  });
  const parsed = parseUdotArtifactBundleWireV1(JSON.parse(JSON.stringify(bundle)));

  assert.deepEqual(parsed, {
    udot_version: "v1-legacy",
    aura_hash_hex: legacyRegression.input_aura_hash_hex,
    seal_line: udotArtifactValueByKindV1(legacyRegression, "seal-line"),
    crest: udotArtifactValueByKindV1(legacyRegression, "crest"),
  });
});

test("wire transport rejects legacy V1 matrix artifacts", () => {
  assert.throws(
    () =>
      parseUdotArtifactWireV1({
        udot_version: "v1-legacy",
        artifact_kind: "matrix-sequence",
        value: udotArtifactValueByKindV1(firstVector, "matrix-sequence"),
      }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactParseFailed" &&
      error.cause instanceof UdotParseError &&
      error.cause.code === "UnsupportedArtifactForVersion",
  );

  assert.throws(
    () =>
      parseUdotArtifactBundleWireV1({
        udot_version: "v1-legacy",
        aura_hash_hex: legacyRegression.input_aura_hash_hex,
        seal_line: udotArtifactValueByKindV1(legacyRegression, "seal-line"),
        crest: udotArtifactValueByKindV1(legacyRegression, "crest"),
        matrix_sequence: udotArtifactValueByKindV1(firstVector, "matrix-sequence"),
      } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'payload contains unexpected field "matrix_sequence"',
  );
});

test("validateUdotArtifactWireV1 rejects version mismatch", async () => {
  await assert.rejects(
    validateUdotArtifactWireV1({
      udot_version: "v2",
      artifact_kind: "seal-line",
      aura_hash_hex: legacyRegression.input_aura_hash_hex,
      value: udotArtifactValueByKindV1(legacyRegression, "seal-line"),
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactValidationFailed" &&
      error.cause instanceof UdotValidationError &&
      error.cause.code === "Mismatch",
  );
});
