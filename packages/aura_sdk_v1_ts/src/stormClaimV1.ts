import { createHash } from "node:crypto";

import {
  bytesToHexLowerV1,
  concatBytesV1,
  decodeCanonicalFixedHexBytesV1,
} from "./stormHash521V1.ts";
import { STORM_CONTEXT_V1_LEN, validateStormContextBytesV1 } from "./stormContextV1.ts";
import { executeStormV1, STORM_SIDE_INPUT_LEN_V1 } from "./stormExecutionV1.ts";
import type { StormExecutionInputsV1 } from "./stormExecutionV1.ts";
import type { StormState521V1 } from "./stormStateV1.ts";
import { computeStormTraceRoot } from "./stormTraceCommitmentV1.ts";

export const STORM_CLAIM_521_V1_VERSION = 0x01;
export const STORM_MODULUS_ID_521_V1 = 0x01;

const AURA_STORM_SIDE_A_HASH_V1 = new TextEncoder().encode("AURA_STORM_SIDE_A_HASH_V1");
const AURA_STORM_SIDE_B_HASH_V1 = new TextEncoder().encode("AURA_STORM_SIDE_B_HASH_V1");
const AURA_STORM_CONTEXT_HASH_V1 = new TextEncoder().encode("AURA_STORM_CONTEXT_HASH_V1");

export type StormClaim521V1 = {
  version: number;
  modulusId: number;
  iterationCount: bigint;
  sideAHex: string;
  sideBHex: string;
  contextBytesHex: string;
  initialState: StormState521V1;
  finalState: StormState521V1;
  traceRootHex: string;
  legacyCommitmentRootHex: string;
  legacyTraceCommitmentHex: string;
};

export type StormPublicInputs521V1 = {
  version: number;
  modulusId: number;
  iterationCount: bigint;
  sideAHashHex: string;
  sideBHashHex: string;
  contextHashHex: string;
  initialState: StormState521V1;
  finalState: StormState521V1;
  traceRootHex: string;
};

export function buildStormClaimV1(
  inputs: StormExecutionInputsV1,
  legacyCommitmentRootHex = "00".repeat(32),
  legacyTraceCommitmentHex = "00".repeat(32),
): StormClaim521V1 {
  const execution = executeStormV1(inputs);
  const traceRootHex = bytesToHexLowerV1(computeStormTraceRoot(execution.trace));

  return {
    version: STORM_CLAIM_521_V1_VERSION,
    modulusId: STORM_MODULUS_ID_521_V1,
    iterationCount: inputs.iterationCount,
    sideAHex: bytesToHexLowerV1(requireSide(inputs.sideA, "storm claim sideA")),
    sideBHex: bytesToHexLowerV1(requireSide(inputs.sideB, "storm claim sideB")),
    contextBytesHex: bytesToHexLowerV1(validateStormContextBytesV1(inputs.contextBytesV1)),
    initialState: execution.initialState,
    finalState: execution.finalState,
    traceRootHex,
    legacyCommitmentRootHex: requireHashHex(legacyCommitmentRootHex, "legacyCommitmentRootHex"),
    legacyTraceCommitmentHex: requireHashHex(
      legacyTraceCommitmentHex,
      "legacyTraceCommitmentHex",
    ),
  };
}

export function validateStormClaimV1(claim: StormClaim521V1): StormClaim521V1 {
  if (claim.version !== STORM_CLAIM_521_V1_VERSION) {
    throw new TypeError(`storm claim version must be ${STORM_CLAIM_521_V1_VERSION}`);
  }
  if (claim.modulusId !== STORM_MODULUS_ID_521_V1) {
    throw new TypeError(`storm claim modulusId must be ${STORM_MODULUS_ID_521_V1}`);
  }

  const inputs: StormExecutionInputsV1 = {
    sideA: requireSide(
      decodeCanonicalFixedHexBytesV1(claim.sideAHex, STORM_SIDE_INPUT_LEN_V1, "storm claim sideAHex"),
      "storm claim sideAHex",
    ),
    sideB: requireSide(
      decodeCanonicalFixedHexBytesV1(claim.sideBHex, STORM_SIDE_INPUT_LEN_V1, "storm claim sideBHex"),
      "storm claim sideBHex",
    ),
    contextBytesV1: validateStormContextBytesV1(
      decodeCanonicalFixedHexBytesV1(
        claim.contextBytesHex,
        STORM_CONTEXT_V1_LEN,
        "storm claim contextBytesHex",
      ),
    ),
    iterationCount: claim.iterationCount,
  };
  const execution = executeStormV1(inputs);
  const expectedTraceRootHex = bytesToHexLowerV1(computeStormTraceRoot(execution.trace));

  if (claim.initialState.xHex66Be !== execution.initialState.xHex66Be
    || claim.initialState.yHex66Be !== execution.initialState.yHex66Be) {
    throw new TypeError("storm claim initialState does not match derived execution");
  }
  if (claim.finalState.xHex66Be !== execution.finalState.xHex66Be
    || claim.finalState.yHex66Be !== execution.finalState.yHex66Be) {
    throw new TypeError("storm claim finalState does not match derived execution");
  }
  if (requireHashHex(claim.traceRootHex, "storm claim traceRootHex") !== expectedTraceRootHex) {
    throw new TypeError("storm claim traceRootHex does not match derived execution");
  }

  requireHashHex(claim.legacyCommitmentRootHex, "storm claim legacyCommitmentRootHex");
  requireHashHex(claim.legacyTraceCommitmentHex, "storm claim legacyTraceCommitmentHex");

  return claim;
}

export function buildStormPublicInputsV1(claim: StormClaim521V1): StormPublicInputs521V1 {
  validateStormClaimV1(claim);

  return {
    version: claim.version,
    modulusId: claim.modulusId,
    iterationCount: claim.iterationCount,
    sideAHashHex: bytesToHexLowerV1(
      sha3_256(concatBytesV1(AURA_STORM_SIDE_A_HASH_V1, requireSideHex(claim.sideAHex, "sideAHex"))),
    ),
    sideBHashHex: bytesToHexLowerV1(
      sha3_256(concatBytesV1(AURA_STORM_SIDE_B_HASH_V1, requireSideHex(claim.sideBHex, "sideBHex"))),
    ),
    contextHashHex: bytesToHexLowerV1(
      sha3_256(
        concatBytesV1(
          AURA_STORM_CONTEXT_HASH_V1,
          validateStormContextBytesV1(
            decodeCanonicalFixedHexBytesV1(
              claim.contextBytesHex,
              STORM_CONTEXT_V1_LEN,
              "storm claim contextBytesHex",
            ),
          ),
        ),
      ),
    ),
    initialState: claim.initialState,
    finalState: claim.finalState,
    traceRootHex: claim.traceRootHex,
  };
}

function requireSide(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== STORM_SIDE_INPUT_LEN_V1) {
    throw new TypeError(`${fieldName} must be ${STORM_SIDE_INPUT_LEN_V1} bytes`);
  }

  return new Uint8Array(bytes);
}

function requireSideHex(value: string, fieldName: string): Uint8Array {
  return requireSide(
    decodeCanonicalFixedHexBytesV1(value, STORM_SIDE_INPUT_LEN_V1, fieldName),
    fieldName,
  );
}

function requireHashHex(value: string, fieldName: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`${fieldName} must be canonical lowercase 64-hex`);
  }
  return value;
}

function sha3_256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha3-256").update(bytes).digest());
}
