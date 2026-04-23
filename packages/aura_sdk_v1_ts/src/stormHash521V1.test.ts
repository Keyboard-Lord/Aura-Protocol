import test from "node:test";
import assert from "node:assert/strict";

import {
  auraHash521V1,
  extractFirst9BitsMsbFirst,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
} from "./stormHash521V1.ts";

test("AURA_HASH521_V1 is deterministic and 66 bytes wide", () => {
  const first = auraHash521V1(new TextEncoder().encode("AURA_TEST_VECTOR"));
  const second = auraHash521V1(new TextEncoder().encode("AURA_TEST_VECTOR"));

  assert.equal(first.length, FIELD_ELEMENT_521_BYTE_LEN_V1);
  assert.deepEqual(first, second);
  assert.equal(first[0]! & 0xfe, 0);
});

test("first 9 bits are extracted MSB-first", () => {
  const bytes = new Uint8Array(64);
  bytes[0] = 0b1010_1100;
  bytes[1] = 0b1000_0000;

  assert.equal(extractFirst9BitsMsbFirst(bytes), 0b1010_1100_1);
});
