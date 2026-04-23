import test from "node:test";
import assert from "node:assert/strict";

import {
  buildStormTrace,
  deriveA,
  derivePhiN,
  derivePsiN,
  deriveX0,
  deriveY0,
  executeStormV1,
} from "./stormExecutionV1.ts";
import { encodeStormContextV1, STORM_CONTEXT_V1_VERSION } from "./stormContextV1.ts";

function sampleInputs() {
  return {
    sideA: new Uint8Array(110).fill(0xa5),
    sideB: new Uint8Array(110).fill(0x5a),
    contextBytesV1: encodeStormContextV1({
      contextVersion: STORM_CONTEXT_V1_VERSION,
      networkId: new Uint8Array(32).fill(0x10),
      intentHash: new Uint8Array(32).fill(0x20),
      freshnessNonce: new Uint8Array(32).fill(0x30),
      validFrom: 100n,
      validUntil: 200n,
      controllerId: new Uint8Array(32).fill(0x40),
      routeTag: new Uint8Array(32).fill(0x50),
    }),
    iterationCount: 4n,
  };
}

test("storm execution is deterministic from identical inputs", () => {
  const inputs = sampleInputs();

  assert.equal(deriveX0(inputs.sideA), deriveX0(inputs.sideA));
  assert.equal(deriveY0(inputs.sideB), deriveY0(inputs.sideB));
  assert.equal(deriveA(inputs.contextBytesV1), deriveA(inputs.contextBytesV1));
  assert.equal(
    derivePhiN(inputs.sideA, inputs.sideB, inputs.contextBytesV1, 2n),
    derivePhiN(inputs.sideA, inputs.sideB, inputs.contextBytesV1, 2n),
  );
  assert.equal(
    derivePsiN(inputs.sideA, inputs.sideB, inputs.contextBytesV1, 2n),
    derivePsiN(inputs.sideA, inputs.sideB, inputs.contextBytesV1, 2n),
  );
});

test("storm trace includes the initial state and each successive step", () => {
  const inputs = sampleInputs();
  const trace = buildStormTrace(inputs);
  const execution = executeStormV1(inputs);

  assert.equal(trace.length, Number(inputs.iterationCount) + 1);
  assert.deepEqual(execution.initialState, trace[0]);
  assert.deepEqual(execution.finalState, trace[trace.length - 1]);
});
