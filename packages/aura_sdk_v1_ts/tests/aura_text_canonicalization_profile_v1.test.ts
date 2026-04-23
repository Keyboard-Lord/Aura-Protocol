import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  auraHashV1,
  canonicalMessageBytesV1,
  canonicalMessageHashPreimageV1,
  canonicalTextPayloadBytesV1,
  decodeHexBytesV1,
} from "../src/auraHashV1.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/v1/aura_text_canonicalization_profile_v1/canonical_text_profile_v1.json",
);
const FROZEN_AURA_TEXT_PROFILE_FIXTURE_SHA256 =
  "6d383343079e3f067ac1ea72726225cba21c3c5c697e50a2f764d61985588da4";

interface TextProfileCaseV1 {
  label: string;
  input_hex: string;
  normalized_text_utf8_hex: string;
  text_payload_bytes_hex: string;
  aura_hash_v1_canonical_message_bytes_hex: string;
  hash_preimage_hex: string;
  hash_hex: string;
}

interface TextModeSeparationCaseV1 {
  label: string;
  raw_input_hex: string;
  text_input_hex: string;
  text_payload_bytes_hex: string;
  raw_hash_hex: string;
  text_hash_hex: string;
}

interface TextRejectionCaseV1 {
  label: string;
  input_hex: string;
  reject_reason: string;
}

interface TextProfileFixtureV1 {
  profile: string;
  depends_on: string;
  cases: TextProfileCaseV1[];
  mode_separation_cases: TextModeSeparationCaseV1[];
  rejection_cases: TextRejectionCaseV1[];
}

test("typescript matches the shared aura text profile fixture", () => {
  const fixture = loadFixtureV1();
  assert.equal(fixture.profile, "AURA_TEXT_CANONICALIZATION_PROFILE_V1");
  assert.equal(fixture.depends_on, "AURA_HASH_V1");

  for (const fixtureCase of fixture.cases) {
    const input = decodeHexBytesV1(fixtureCase.input_hex, `${fixtureCase.label}.input_hex`);
    const expectedPayload = decodeHexBytesV1(
      fixtureCase.text_payload_bytes_hex,
      `${fixtureCase.label}.text_payload_bytes_hex`,
    );
    const expectedNormalized = decodeHexBytesV1(
      fixtureCase.normalized_text_utf8_hex,
      `${fixtureCase.label}.normalized_text_utf8_hex`,
    );
    const expectedCanonical = decodeHexBytesV1(
      fixtureCase.aura_hash_v1_canonical_message_bytes_hex,
      `${fixtureCase.label}.aura_hash_v1_canonical_message_bytes_hex`,
    );
    const expectedPreimage = decodeHexBytesV1(
      fixtureCase.hash_preimage_hex,
      `${fixtureCase.label}.hash_preimage_hex`,
    );
    const expectedHash = decodeHexBytesV1(fixtureCase.hash_hex, `${fixtureCase.label}.hash_hex`);

    assert.deepEqual(canonicalTextPayloadBytesV1(input), expectedPayload);
    assert.deepEqual(expectedPayload, expectedNormalized);
    assert.deepEqual(canonicalMessageBytesV1(expectedPayload), expectedCanonical);
    assert.deepEqual(canonicalMessageHashPreimageV1(expectedPayload), expectedPreimage);
    assert.deepEqual(auraHashV1(expectedPayload), expectedHash);
  }
});

test("text mode and raw mode remain distinct when bytes differ", () => {
  const fixture = loadFixtureV1();
  for (const fixtureCase of fixture.mode_separation_cases) {
    const rawInput = decodeHexBytesV1(fixtureCase.raw_input_hex, `${fixtureCase.label}.raw_input_hex`);
    const textInput = decodeHexBytesV1(
      fixtureCase.text_input_hex,
      `${fixtureCase.label}.text_input_hex`,
    );
    const expectedPayload = decodeHexBytesV1(
      fixtureCase.text_payload_bytes_hex,
      `${fixtureCase.label}.text_payload_bytes_hex`,
    );
    const expectedRawHash = decodeHexBytesV1(
      fixtureCase.raw_hash_hex,
      `${fixtureCase.label}.raw_hash_hex`,
    );
    const expectedTextHash = decodeHexBytesV1(
      fixtureCase.text_hash_hex,
      `${fixtureCase.label}.text_hash_hex`,
    );

    assert.deepEqual(canonicalTextPayloadBytesV1(textInput), expectedPayload);
    assert.deepEqual(auraHashV1(rawInput), expectedRawHash);
    assert.deepEqual(auraHashV1(expectedPayload), expectedTextHash);
    assert.notDeepEqual(expectedRawHash, expectedTextHash);
  }
});

test("text profile rejection cases fail closed", () => {
  const fixture = loadFixtureV1();
  for (const rejectionCase of fixture.rejection_cases) {
    const input = decodeHexBytesV1(rejectionCase.input_hex, `${rejectionCase.label}.input_hex`);
    assert.throws(
      () => canonicalTextPayloadBytesV1(input),
      new RegExp(rejectionReasonPatternV1(rejectionCase.reject_reason)),
    );
  }
});

test("aura text profile fixture is frozen", () => {
  const digest = createHash("sha256")
    .update(readFileSync(FIXTURE_PATH))
    .digest("hex");
  assert.equal(
    digest,
    FROZEN_AURA_TEXT_PROFILE_FIXTURE_SHA256,
    "aura_text_profile fixture changed; bump the fixture version instead of silently editing it",
  );
});

function loadFixtureV1(): TextProfileFixtureV1 {
  return JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as TextProfileFixtureV1;
}

function rejectionReasonPatternV1(rejectReason: string): string {
  switch (rejectReason) {
    case "message_contains_bom":
      return "contains a BOM codepoint";
    case "message_must_be_valid_utf8":
      return "must be valid UTF-8 text";
    default:
      throw new TypeError(`unsupported reject_reason in fixture: ${rejectReason}`);
  }
}
