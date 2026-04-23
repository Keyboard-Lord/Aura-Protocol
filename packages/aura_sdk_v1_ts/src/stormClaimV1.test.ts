import test from "node:test";
import assert from "node:assert/strict";

import {
  buildStormClaimV1,
  buildStormPublicInputsV1,
  STORM_CLAIM_521_V1_VERSION,
  STORM_MODULUS_ID_521_V1,
  validateStormClaimV1,
} from "./stormClaimV1.ts";
import { encodeStormContextV1, STORM_CONTEXT_V1_VERSION } from "./stormContextV1.ts";

function sampleInputs() {
  return {
    sideA: new Uint8Array(110).fill(0x11),
    sideB: new Uint8Array(110).fill(0x22),
    contextBytesV1: encodeStormContextV1({
      contextVersion: STORM_CONTEXT_V1_VERSION,
      networkId: new Uint8Array(32).fill(0x33),
      intentHash: new Uint8Array(32).fill(0x44),
      freshnessNonce: new Uint8Array(32).fill(0x55),
      validFrom: 12n,
      validUntil: 34n,
      controllerId: new Uint8Array(32).fill(0x66),
      routeTag: new Uint8Array(32).fill(0x77),
    }),
    iterationCount: 3n,
  };
}

test("storm claim validates and yields public inputs", () => {
  const claim = buildStormClaimV1(sampleInputs());
  const publicInputs = buildStormPublicInputsV1(claim);

  assert.equal(validateStormClaimV1(claim), claim);
  assert.equal(claim.version, STORM_CLAIM_521_V1_VERSION);
  assert.equal(claim.modulusId, STORM_MODULUS_ID_521_V1);
  assert.equal(publicInputs.traceRootHex, claim.traceRootHex);
});
