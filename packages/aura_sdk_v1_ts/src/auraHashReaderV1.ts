import {
  auraHash521V1,
  bytesToHexLowerV1,
  decodeCanonicalFixedHexBytesV1,
  extractFirst9BitsMsbFirst,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
  validateFieldElement521BytesV1,
} from "./stormHash521V1.ts";
import {
  buildStormPublicInputsV1,
  validateStormClaimV1,
  type StormClaim521V1,
  type StormPublicInputs521V1,
} from "./stormClaimV1.ts";
import { STORM_CONTEXT_V1_LEN, validateStormContextBytesV1 } from "./stormContextV1.ts";

export type AuraHash521InspectionV1 = {
  kind: "storm-h521-field-element";
  valid: true;
  algorithm: "H_521(m) = Reduce_N(SHA3-512(m))";
  modulus: "2^521 - 1";
  byteLength: 66;
  bitLength: number;
  hex: string;
  decimal: string;
  topNineBits: number;
  reversible: false;
  canDecodePreimage: false;
  preimageVerification?: {
    recomputedHashHex: string;
    matches: boolean;
  };
};

export type StormContextInspectionV1 = {
  version: 1;
  networkIdHex: string;
  executionDomainHex: string;
  intentHashHex: string;
  freshnessNonceHex: string;
  validFrom: string;
  validUntil: string;
  controllerIdHex: string;
  routeTagHex: string;
};

export type StormClaimReadV1 = {
  kind: "storm-claim-v1";
  valid: true;
  claimVerified: true;
  reversible: false;
  canDecodePreimage: false;
  version: number;
  modulusId: number;
  iterationCount: string;
  context: StormContextInspectionV1;
  initialState: {
    x: AuraHash521InspectionV1;
    y: AuraHash521InspectionV1;
  };
  finalState: {
    x: AuraHash521InspectionV1;
    y: AuraHash521InspectionV1;
  };
  traceRootHex: string;
  legacyCommitmentRootHex: string;
  legacyTraceCommitmentHex: string;
  publicInputs: StormPublicInputs521V1;
};

export type StormClaimWireForReaderV1 = {
  version: number;
  modulus_id: number;
  iteration_count: number;
  side_a_hex: string;
  side_b_hex: string;
  context_bytes_hex: string;
  initial_state: {
    x_hex_66_be: string;
    y_hex_66_be: string;
  };
  final_state: {
    x_hex_66_be: string;
    y_hex_66_be: string;
  };
  trace_root_hex: string;
  legacy_commitment_root_hex: string;
  legacy_trace_commitment_hex: string;
};

export function inspectAuraHash521V1(
  value: string | Uint8Array,
  options: { preimage?: Uint8Array } = {},
): AuraHash521InspectionV1 {
  const bytes = typeof value === "string"
    ? decodeCanonicalFixedHexBytesV1(value, FIELD_ELEMENT_521_BYTE_LEN_V1, "H_521 hex")
    : new Uint8Array(value);
  const fieldBytes = validateFieldElement521BytesV1(bytes, "H_521 field element");
  const hex = bytesToHexLowerV1(fieldBytes);
  const inspection: AuraHash521InspectionV1 = {
    kind: "storm-h521-field-element",
    valid: true,
    algorithm: "H_521(m) = Reduce_N(SHA3-512(m))",
    modulus: "2^521 - 1",
    byteLength: FIELD_ELEMENT_521_BYTE_LEN_V1,
    bitLength: fieldBitLengthV1(fieldBytes),
    hex,
    decimal: fieldBytesToBigIntV1(fieldBytes).toString(10),
    topNineBits: extractFirst9BitsMsbFirst(fieldBytes),
    reversible: false,
    canDecodePreimage: false,
  };

  if (options.preimage !== undefined) {
    const recomputedHashHex = bytesToHexLowerV1(auraHash521V1(options.preimage));
    inspection.preimageVerification = {
      recomputedHashHex,
      matches: recomputedHashHex === hex,
    };
  }

  return inspection;
}

export function inspectAuraHash521PreimageV1(
  preimage: Uint8Array,
  expectedHashHex: string,
): AuraHash521InspectionV1 {
  return inspectAuraHash521V1(expectedHashHex, { preimage });
}

export function readStormClaimV1(value: StormClaim521V1 | StormClaimWireForReaderV1): StormClaimReadV1 {
  const claim = validateStormClaimV1(stormClaimFromReaderInputV1(value));
  const contextBytes = validateStormContextBytesV1(
    decodeCanonicalFixedHexBytesV1(
      claim.contextBytesHex,
      STORM_CONTEXT_V1_LEN,
      "storm claim contextBytesHex",
    ),
  );

  return {
    kind: "storm-claim-v1",
    valid: true,
    claimVerified: true,
    reversible: false,
    canDecodePreimage: false,
    version: claim.version,
    modulusId: claim.modulusId,
    iterationCount: claim.iterationCount.toString(10),
    context: inspectStormContextBytesV1(contextBytes),
    initialState: {
      x: inspectAuraHash521V1(claim.initialState.xHex66Be),
      y: inspectAuraHash521V1(claim.initialState.yHex66Be),
    },
    finalState: {
      x: inspectAuraHash521V1(claim.finalState.xHex66Be),
      y: inspectAuraHash521V1(claim.finalState.yHex66Be),
    },
    traceRootHex: claim.traceRootHex,
    legacyCommitmentRootHex: claim.legacyCommitmentRootHex,
    legacyTraceCommitmentHex: claim.legacyTraceCommitmentHex,
    publicInputs: buildStormPublicInputsV1(claim),
  };
}

export function inspectStormContextBytesV1(bytes: Uint8Array): StormContextInspectionV1 {
  const context = validateStormContextBytesV1(bytes);
  return {
    version: 1,
    networkIdHex: bytesToHexLowerV1(context.subarray(1, 33)),
    executionDomainHex: bytesToHexLowerV1(context.subarray(33, 65)),
    intentHashHex: bytesToHexLowerV1(context.subarray(65, 97)),
    freshnessNonceHex: bytesToHexLowerV1(context.subarray(97, 129)),
    validFrom: decodeU64LeV1(context.subarray(129, 137)).toString(10),
    validUntil: decodeU64LeV1(context.subarray(137, 145)).toString(10),
    controllerIdHex: bytesToHexLowerV1(context.subarray(145, 177)),
    routeTagHex: bytesToHexLowerV1(context.subarray(177, 209)),
  };
}

function stormClaimFromReaderInputV1(
  value: StormClaim521V1 | StormClaimWireForReaderV1,
): StormClaim521V1 {
  const record = value as Partial<StormClaim521V1> & Partial<StormClaimWireForReaderV1>;
  if (record.modulusId !== undefined) {
    return value as StormClaim521V1;
  }

  return {
    version: requireNumberV1(record.version, "storm_claim.version"),
    modulusId: requireNumberV1(record.modulus_id, "storm_claim.modulus_id"),
    iterationCount: BigInt(requireNumberV1(record.iteration_count, "storm_claim.iteration_count")),
    sideAHex: requireStringV1(record.side_a_hex, "storm_claim.side_a_hex"),
    sideBHex: requireStringV1(record.side_b_hex, "storm_claim.side_b_hex"),
    contextBytesHex: requireStringV1(record.context_bytes_hex, "storm_claim.context_bytes_hex"),
    initialState: {
      xHex66Be: requireStringV1(
        record.initial_state?.x_hex_66_be,
        "storm_claim.initial_state.x_hex_66_be",
      ),
      yHex66Be: requireStringV1(
        record.initial_state?.y_hex_66_be,
        "storm_claim.initial_state.y_hex_66_be",
      ),
    },
    finalState: {
      xHex66Be: requireStringV1(
        record.final_state?.x_hex_66_be,
        "storm_claim.final_state.x_hex_66_be",
      ),
      yHex66Be: requireStringV1(
        record.final_state?.y_hex_66_be,
        "storm_claim.final_state.y_hex_66_be",
      ),
    },
    traceRootHex: requireStringV1(record.trace_root_hex, "storm_claim.trace_root_hex"),
    legacyCommitmentRootHex: requireStringV1(
      record.legacy_commitment_root_hex,
      "storm_claim.legacy_commitment_root_hex",
    ),
    legacyTraceCommitmentHex: requireStringV1(
      record.legacy_trace_commitment_hex,
      "storm_claim.legacy_trace_commitment_hex",
    ),
  };
}

function fieldBitLengthV1(bytes: Uint8Array): number {
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index] ?? 0;
    if (byte !== 0) {
      return ((bytes.length - index - 1) * 8) + byte.toString(2).length;
    }
  }

  return 0;
}

function fieldBytesToBigIntV1(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function decodeU64LeV1(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new TypeError("u64 little-endian field must be 8 bytes");
  }

  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

function requireNumberV1(value: unknown, fieldName: string): number {
  if (!Number.isInteger(value)) {
    throw new TypeError(`${fieldName} must be an integer`);
  }
  return value as number;
}

function requireStringV1(value: unknown, fieldName: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${fieldName} must be a string`);
  }
  return value;
}
