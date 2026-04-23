import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AURA_HASH_V1_DOMAIN_SEPARATOR,
  AURA_HASH_V1_LENGTH_PREFIX_BYTES,
  auraHashV1,
  bytesToHexLowerV1,
  canonicalMessageBytesV1,
  canonicalMessageHashPreimageV1,
  canonicalTextPayloadBytesV1,
  decodeAndNormalizeMessageUtf8V1,
  decodeHexBytesV1,
  normalizeTextMessageV1,
} from "../src/auraHashV1.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../fixtures/v1/aura_hash_v1/canonical_message_hash_v1.json",
);
const FROZEN_AURA_HASH_V1_FIXTURE_SHA256 =
  "e9ee3cc1e9fa8e0eceb886bdf5826459242e0a2a289dedef445abb15a45575fc";

interface AuraHashFixtureCaseV1 {
  label: string;
  input_kind: "raw_bytes" | "text_utf8";
  input_hex: string;
  normalized_text_utf8_hex?: string;
  equivalent_normalized_input_hex?: string;
  canonical_message_bytes_hex: string;
  hash_preimage_hex: string;
  hash_hex: string;
}

interface AuraHashFixtureRejectionCaseV1 {
  label: string;
  input_kind: "text_utf8";
  input_hex: string;
  reject_reason: string;
}

interface AuraHashFixtureV1 {
  domain_separator_utf8: string;
  length_prefix_bytes: number;
  cases: AuraHashFixtureCaseV1[];
  rejection_cases: AuraHashFixtureRejectionCaseV1[];
}

test("typescript matches the shared aura_hash_v1 fixture", () => {
  const fixture = loadFixtureV1();
  assert.deepEqual(
    new Uint8Array(Buffer.from(fixture.domain_separator_utf8, "utf8")),
    AURA_HASH_V1_DOMAIN_SEPARATOR,
  );
  assert.equal(fixture.length_prefix_bytes, AURA_HASH_V1_LENGTH_PREFIX_BYTES);

  for (const fixtureCase of fixture.cases) {
    const input = decodeHexBytesV1(fixtureCase.input_hex, `${fixtureCase.label}.input_hex`);
    const expectedCanonical = decodeHexBytesV1(
      fixtureCase.canonical_message_bytes_hex,
      `${fixtureCase.label}.canonical_message_bytes_hex`,
    );
    const expectedPreimage = decodeHexBytesV1(
      fixtureCase.hash_preimage_hex,
      `${fixtureCase.label}.hash_preimage_hex`,
    );
    const expectedHash = decodeHexBytesV1(fixtureCase.hash_hex, `${fixtureCase.label}.hash_hex`);

    if (fixtureCase.input_kind === "raw_bytes") {
      assert.deepEqual(canonicalMessageBytesV1(input), expectedCanonical);
      assert.deepEqual(canonicalMessageHashPreimageV1(input), expectedPreimage);
      assert.deepEqual(auraHashV1(input), expectedHash);
      continue;
    }

    const payload = canonicalTextPayloadBytesV1(input);
    assert.deepEqual(canonicalMessageBytesV1(payload), expectedCanonical);
    assert.deepEqual(canonicalMessageHashPreimageV1(payload), expectedPreimage);
    assert.deepEqual(auraHashV1(payload), expectedHash);

    if (fixtureCase.normalized_text_utf8_hex) {
      assert.equal(
        bytesToHexLowerV1(
          new TextEncoder().encode(decodeAndNormalizeMessageUtf8V1(input)),
        ),
        fixtureCase.normalized_text_utf8_hex,
      );
    }

    if (fixtureCase.equivalent_normalized_input_hex) {
      const equivalent = decodeHexBytesV1(
        fixtureCase.equivalent_normalized_input_hex,
        `${fixtureCase.label}.equivalent_normalized_input_hex`,
      );
      assert.deepEqual(auraHashV1(canonicalTextPayloadBytesV1(equivalent)), expectedHash);
    }
  }
});

test("text helpers keep whitespace significant", () => {
  assert.equal(normalizeTextMessageV1("hello"), "hello");
  assert.equal(normalizeTextMessageV1("hello "), "hello ");
  assert.notDeepEqual(
    auraHashV1(canonicalTextPayloadBytesV1(new TextEncoder().encode("hello"))),
    auraHashV1(canonicalTextPayloadBytesV1(new TextEncoder().encode("hello "))),
  );
});

test("text rejection cases fail closed", () => {
  const fixture = loadFixtureV1();
  for (const rejectionCase of fixture.rejection_cases) {
    const input = decodeHexBytesV1(rejectionCase.input_hex, `${rejectionCase.label}.input_hex`);
    assert.throws(
      () => canonicalTextPayloadBytesV1(input),
      new RegExp(rejectionReasonPatternV1(rejectionCase.reject_reason)),
    );
  }
});

test("aura_hash_v1 fixture is frozen", () => {
  const digest = createHash("sha256")
    .update(readFileSync(FIXTURE_PATH))
    .digest("hex");
  assert.equal(
    digest,
    FROZEN_AURA_HASH_V1_FIXTURE_SHA256,
    "aura_hash_v1 fixture changed; bump the fixture version instead of silently editing it",
  );
});

function loadFixtureV1(): AuraHashFixtureV1 {
  return JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as AuraHashFixtureV1;
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
