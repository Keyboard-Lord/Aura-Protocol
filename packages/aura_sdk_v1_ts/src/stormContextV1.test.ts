import test from "node:test";
import assert from "node:assert/strict";

import {
  encodeStormContextV1,
  executionDomainV1,
  STORM_CONTEXT_V1_LEN,
  STORM_CONTEXT_V1_VERSION,
  validateStormContextBytesV1,
} from "./stormContextV1.ts";

test("storm context serializes to the fixed 209-byte shape", () => {
  const bytes = encodeStormContextV1({
    contextVersion: STORM_CONTEXT_V1_VERSION,
    networkId: new Uint8Array(32).fill(0x11),
    intentHash: new Uint8Array(32).fill(0x22),
    freshnessNonce: new Uint8Array(32).fill(0x33),
    validFrom: 10n,
    validUntil: 20n,
    controllerId: new Uint8Array(32).fill(0x44),
    routeTag: new Uint8Array(32).fill(0x55),
  });

  assert.equal(bytes.length, STORM_CONTEXT_V1_LEN);
  assert.deepEqual(bytes.subarray(33, 65), executionDomainV1());
  assert.deepEqual(validateStormContextBytesV1(bytes), bytes);
});
