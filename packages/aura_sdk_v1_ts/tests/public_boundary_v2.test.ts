import test from "node:test";
import assert from "node:assert/strict";
import * as sdk from "../src/index.ts";

test("canonical SDK entry exposes v2 authorization and isolates retired wires", () => {
  for (const name of ["generateAuthorizationIntentV1", "generateStarkProofEnvelopeV1",
    "generateSolanaSettlementRequestV1", "buildSettlementPipelineFromPreparedProofV1",
    "generateSubmitProofRequestV1", "prepareSubmitProofFlowV1"]) {
    assert.equal(Object.hasOwn(sdk, name), false, name);
    assert.equal(typeof sdk.legacy[name as keyof typeof sdk.legacy], "function", name);
  }
  assert.equal(typeof sdk.signAuthorizationV2, "function");
  assert.equal(typeof sdk.verifyAuthorizationMaterialBindingV2, "function");
  assert.equal(typeof sdk.prepareBoundProofMaterialV1, "function");
});
