import test from "node:test";
import assert from "node:assert/strict";

import {
  auraHash521V1,
  extractFirst9BitsMsbFirst,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
} from "./stormHash521V1.ts";

test("active HASH_V2 retains the exact independent empty-message SHA3-512 vector", () => {
  assert.equal(Buffer.from(auraHash521V1(new Uint8Array())).toString("hex"),
    "0000a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615" +
    "b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
});

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
