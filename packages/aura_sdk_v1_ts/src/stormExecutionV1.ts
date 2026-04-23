import {
  auraHash521V1,
  bytesToHexLowerV1,
  concatBytesV1,
  decodeCanonicalFixedHexBytesV1,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
  validateFieldElement521BytesV1,
} from "./stormHash521V1.ts";
import { validateStormContextBytesV1 } from "./stormContextV1.ts";
import type { StormState521V1 } from "./stormStateV1.ts";

export const STORM_SIDE_INPUT_LEN_V1 = 110;

const MODULUS_521_V1 = (1n << 521n) - 1n;
const AURA_X0_V1_DOMAIN_SEPARATOR = encodeAscii("AURA_X0_V1");
const AURA_Y0_V1_DOMAIN_SEPARATOR = encodeAscii("AURA_Y0_V1");
const AURA_C_A_V1_DOMAIN_SEPARATOR = encodeAscii("AURA_C_A_V1");
const AURA_C_B_V1_DOMAIN_SEPARATOR = encodeAscii("AURA_C_B_V1");
const AURA_STORM_X_V1_DOMAIN_SEPARATOR = encodeAscii("AURA_STORM_X_V1");
const AURA_STORM_Y_V1_DOMAIN_SEPARATOR = encodeAscii("AURA_STORM_Y_V1");

export type StormExecutionInputsV1 = {
  sideA: Uint8Array;
  sideB: Uint8Array;
  contextBytesV1: Uint8Array;
  iterationCount: bigint;
};

export type StormExecutionResultV1 = {
  initialState: StormState521V1;
  finalState: StormState521V1;
  aHex66Be: string;
  bHex66Be: string;
  trace: StormState521V1[];
};

export function deriveX0(sideA: Uint8Array): string {
  requireSide(sideA, "storm sideA");
  return bytesToHexLowerV1(auraHash521V1(concatBytesV1(AURA_X0_V1_DOMAIN_SEPARATOR, sideA)));
}

export function deriveY0(sideB: Uint8Array): string {
  requireSide(sideB, "storm sideB");
  return bytesToHexLowerV1(auraHash521V1(concatBytesV1(AURA_Y0_V1_DOMAIN_SEPARATOR, sideB)));
}

export function deriveA(contextBytesV1: Uint8Array): string {
  validateStormContextBytesV1(contextBytesV1);
  return bytesToHexLowerV1(
    auraHash521V1(concatBytesV1(AURA_C_A_V1_DOMAIN_SEPARATOR, contextBytesV1)),
  );
}

export function deriveB(contextBytesV1: Uint8Array): string {
  validateStormContextBytesV1(contextBytesV1);
  return bytesToHexLowerV1(
    auraHash521V1(concatBytesV1(AURA_C_B_V1_DOMAIN_SEPARATOR, contextBytesV1)),
  );
}

export function encodeStepU64Le(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffff_ffff_ffff_ffffn) {
    throw new TypeError("storm step index must fit u64");
  }

  const bytes = new Uint8Array(8);
  let remaining = n;
  for (let index = 0; index < 8; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

export function derivePhiN(
  sideA: Uint8Array,
  sideB: Uint8Array,
  contextBytesV1: Uint8Array,
  n: bigint,
): string {
  requireSide(sideA, "storm sideA");
  requireSide(sideB, "storm sideB");
  validateStormContextBytesV1(contextBytesV1);
  return bytesToHexLowerV1(
    auraHash521V1(
      concatBytesV1(
        AURA_STORM_X_V1_DOMAIN_SEPARATOR,
        sideA,
        sideB,
        contextBytesV1,
        encodeStepU64Le(n),
      ),
    ),
  );
}

export function derivePsiN(
  sideA: Uint8Array,
  sideB: Uint8Array,
  contextBytesV1: Uint8Array,
  n: bigint,
): string {
  requireSide(sideA, "storm sideA");
  requireSide(sideB, "storm sideB");
  validateStormContextBytesV1(contextBytesV1);
  return bytesToHexLowerV1(
    auraHash521V1(
      concatBytesV1(
        AURA_STORM_Y_V1_DOMAIN_SEPARATOR,
        sideA,
        sideB,
        contextBytesV1,
        encodeStepU64Le(n),
      ),
    ),
  );
}

export function stormStep(
  state: StormState521V1,
  aHex66Be: string,
  bHex66Be: string,
  phiHex66Be: string,
  psiHex66Be: string,
): StormState521V1 {
  const x = fieldHexToBigInt(state.xHex66Be, "storm state xHex66Be");
  const y = fieldHexToBigInt(state.yHex66Be, "storm state yHex66Be");
  const a = fieldHexToBigInt(aHex66Be, "storm aHex66Be");
  const b = fieldHexToBigInt(bHex66Be, "storm bHex66Be");
  const phi = fieldHexToBigInt(phiHex66Be, "storm phiHex66Be");
  const psi = fieldHexToBigInt(psiHex66Be, "storm psiHex66Be");

  const nextX = mod521(x * x - y * y + a + phi);
  const nextY = mod521(2n * x * y + b + psi);

  return {
    xHex66Be: bigIntToFieldHex(nextX),
    yHex66Be: bigIntToFieldHex(nextY),
  };
}

export function buildStormTrace(inputs: StormExecutionInputsV1): StormState521V1[] {
  validateInputs(inputs);

  const aHex66Be = deriveA(inputs.contextBytesV1);
  const bHex66Be = deriveB(inputs.contextBytesV1);
  let state: StormState521V1 = {
    xHex66Be: deriveX0(inputs.sideA),
    yHex66Be: deriveY0(inputs.sideB),
  };

  const trace: StormState521V1[] = [state];
  for (let step = 0n; step < inputs.iterationCount; step += 1n) {
    state = stormStep(
      state,
      aHex66Be,
      bHex66Be,
      derivePhiN(inputs.sideA, inputs.sideB, inputs.contextBytesV1, step),
      derivePsiN(inputs.sideA, inputs.sideB, inputs.contextBytesV1, step),
    );
    trace.push(state);
  }

  return trace;
}

export function executeStormV1(inputs: StormExecutionInputsV1): StormExecutionResultV1 {
  const trace = buildStormTrace(inputs);
  return {
    initialState: trace[0]!,
    finalState: trace[trace.length - 1]!,
    aHex66Be: deriveA(inputs.contextBytesV1),
    bHex66Be: deriveB(inputs.contextBytesV1),
    trace,
  };
}

function validateInputs(inputs: StormExecutionInputsV1): void {
  requireSide(inputs.sideA, "storm sideA");
  requireSide(inputs.sideB, "storm sideB");
  validateStormContextBytesV1(inputs.contextBytesV1);
  if (inputs.iterationCount < 0n || inputs.iterationCount > 0xffff_ffff_ffff_ffffn) {
    throw new TypeError("storm iterationCount must fit u64");
  }
}

function requireSide(bytes: Uint8Array, fieldName: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.length !== STORM_SIDE_INPUT_LEN_V1) {
    throw new TypeError(`${fieldName} must be exactly ${STORM_SIDE_INPUT_LEN_V1} bytes`);
  }
}

function fieldHexToBigInt(value: string, fieldName: string): bigint {
  const bytes = validateFieldElement521BytesV1(
    decodeCanonicalFixedHexBytesV1(value, FIELD_ELEMENT_521_BYTE_LEN_V1, fieldName),
    fieldName,
  );
  return bytesToBigInt(bytes);
}

function bigIntToFieldHex(value: bigint): string {
  return bytesToHexLowerV1(bigIntToFieldBytes(value));
}

function bigIntToFieldBytes(value: bigint): Uint8Array {
  const reduced = mod521(value);
  const bytes = new Uint8Array(FIELD_ELEMENT_521_BYTE_LEN_V1);
  let remaining = reduced;
  for (let index = FIELD_ELEMENT_521_BYTE_LEN_V1 - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return validateFieldElement521BytesV1(bytes, "storm field bytes");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function mod521(value: bigint): bigint {
  const reduced = value % MODULUS_521_V1;
  return reduced >= 0n ? reduced : reduced + MODULUS_521_V1;
}

function encodeAscii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
