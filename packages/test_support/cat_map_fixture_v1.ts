/*
Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
Matrix: [[1,1],[1,2]] mod (2^521-1)
Date: 2026-03-26
*/
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const FIELD_ELEMENT_521_BYTE_LEN_V1 = 66;
const DCM_STATE_521_CANONICAL_BYTE_LEN_V1 = FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;
const MODULUS_521_V1 = (1n << 521n) - 1n;
const BASE_FIELD_MODULUS_V1 = 340282366920938463463374557953744961537n;
const FIELD_MODULUS_521_BYTES_V1 = encodeBigIntFixedWidthV1(
  MODULUS_521_V1,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
);
const CHECKPOINTS_V1 = ["s1", "s2", "s3", "s5", "s8", "s16", "s32"] as const;
const DCM_AIR_REAL_STARK_DIGIT_COUNT_V1 = 75;

const AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR =
  utf8Bytes("AURA_CAT_521_V1_STATE_LEAF");
const AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR =
  utf8Bytes("AURA_CAT_521_V1_TRACE_COMMITMENT");
const AURA_DCM_521_V1_COMMITMENT_ROOT_DOMAIN_SEPARATOR =
  utf8Bytes("AURA_CAT_521_V1_COMMITMENT_ROOT");

const FORWARD_MATRIX_V1: MatrixV1 = {
  a11: 1n,
  a12: 1n,
  a21: 1n,
  a22: 2n,
};

const INVERSE_MATRIX_V1: MatrixV1 = {
  a11: 2n,
  a12: mod521V1(-1n),
  a21: mod521V1(-1n),
  a22: 1n,
};

const DCM_AIR_REAL_STARK_COMMITMENT_SEED_0_V1 = 0x415552415f4341545f524f4f545f3031n;
const DCM_AIR_REAL_STARK_COMMITMENT_SEED_1_V1 = 0x415552415f4341545f524f4f545f3032n;
const DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_0_V1 = 17n;
const DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_1_V1 = 29n;
const DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_0_V1 = 0x4341545f524f575f434f4d4d49545f30n;
const DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_1_V1 = 0x4341545f524f575f434f4d4d49545f31n;
const DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_0_V1 = 131n;
const DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_0_V1 = 137n;
const DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_1_V1 = 149n;
const DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_1_V1 = 151n;
const DCM_AIR_REAL_STARK_COMMITMENT_MIX_0_V1 = 17n;
const DCM_AIR_REAL_STARK_COMMITMENT_MIX_1_V1 = 19n;
const DCM_AIR_REAL_STARK_COMMITMENT_CONST_0_V1 = 0x524f4f545f4d49585f4341545f303031n;
const DCM_AIR_REAL_STARK_COMMITMENT_CONST_1_V1 = 0x524f4f545f4d49585f4341545f303032n;

type CheckpointKeyV1 = (typeof CHECKPOINTS_V1)[number];

type MatrixV1 = {
  a11: bigint;
  a12: bigint;
  a21: bigint;
  a22: bigint;
};

type StateHexFixtureV1 = {
  x: string;
  y: string;
};

type ProductionVectorFixtureV1 = {
  name: string;
  entropy_hex: string;
  challenge_hex: string;
  initial: StateHexFixtureV1;
  initial_state_encoding_hex: string;
  states: Record<CheckpointKeyV1, StateHexFixtureV1>;
  final_state_encoding_hex: string;
  final_state_hash: string;
  trace_commitment: string;
  commitment_root: string;
  notes?: string;
};

type ToyPrimeCycleSuiteFixtureV1 = {
  p: number;
  cycle_lengths: number[];
  representatives: [number, number][];
};

export type CatMapTestVectorsFileV1 = {
  version: number;
  primitive: string;
  modulus: {
    name: string;
    hex: string;
  };
  matrix: {
    forward: [[number, number], [number, number]];
    inverse: [[number, number], [number, number]];
  };
  encoding: {
    coordinate_encoding: string;
    state_encoding: string;
  };
  hashes: {
    final_state_hash: string;
    trace_commitment: string;
    commitment_root: string;
  };
  checkpoints: string[];
  production_vectors: ProductionVectorFixtureV1[];
  toy_prime_cycle_suites: ToyPrimeCycleSuiteFixtureV1[];
};

type StateV1 = {
  x: bigint;
  y: bigint;
};

type ToyAnalysisV1 = {
  stateCount: number;
  cycleLengths: number[];
  representatives: [number, number][];
};

export function loadCatMapTestVectorsV1(): CatMapTestVectorsFileV1 {
  const contents = readFileSync(catMapFixtureUrlV1(), "utf8");
  return JSON.parse(contents) as CatMapTestVectorsFileV1;
}

export function assertCatMapFixtureSchemaV1(
  fixture: CatMapTestVectorsFileV1,
): void {
  assert.equal(fixture.version, 1);
  assert.equal(fixture.primitive, "aura_cat_map_v1");
  assert.equal(fixture.modulus.name, "mersenne_521");
  assert.equal(
    fixture.modulus.hex,
    `0x${bytesToHexLowerV1(FIELD_MODULUS_521_BYTES_V1)}`,
  );
  assert.deepEqual(fixture.matrix.forward, [[1, 1], [1, 2]]);
  assert.deepEqual(fixture.matrix.inverse, [[2, -1], [-1, 1]]);
  assert.equal(fixture.encoding.coordinate_encoding, "66-byte big-endian");
  assert.equal(fixture.encoding.state_encoding, "x_bytes_66 || y_bytes_66");
  assert.equal(fixture.hashes.final_state_hash, "sha256(state_encoding)");
  assert.equal(fixture.hashes.trace_commitment, "derive_trace_commitment_521_v1");
  assert.equal(
    fixture.hashes.commitment_root,
    "derive_dcm_layer1_commitments_521_v1",
  );
  assert.deepEqual(fixture.checkpoints, [...CHECKPOINTS_V1]);
}

export function assertProductionVectorsMatchReferenceV1(
  fixture: CatMapTestVectorsFileV1,
): void {
  for (const vector of fixture.production_vectors) {
    const entropyBytes = decodeHexBytesV1(vector.entropy_hex);
    const challengeBytes = decodeHexBytesV1(vector.challenge_hex);
    const initialState = {
      x: reduceBytesMod521V1(entropyBytes),
      y: reduceBytesMod521V1(challengeBytes),
    };
    const materializedStates = materializeStatesV1(initialState, 32n);
    const jumpedFinalState = fastForwardStateV1(initialState, 32n);
    const rewoundInitialState = fastRewindStateV1(jumpedFinalState, 32n);

    assertStateHexEqualV1(initialState, vector.initial, `${vector.name} initial`);
    assert.equal(
      bytesToHexLowerV1(encodeStateV1(initialState)),
      vector.initial_state_encoding_hex,
      `${vector.name} initial_state_encoding_hex`,
    );

    for (const checkpoint of CHECKPOINTS_V1) {
      const stepCount = BigInt(Number.parseInt(checkpoint.slice(1), 10));
      const repeatedState = materializedStates[Number(stepCount)];
      const jumpedState = fastForwardStateV1(initialState, stepCount);

      assertStateHexEqualV1(
        repeatedState,
        vector.states[checkpoint],
        `${vector.name} ${checkpoint}`,
      );
      assert.deepEqual(
        encodeStateV1(repeatedState),
        encodeStateV1(jumpedState),
        `${vector.name} ${checkpoint} jump`,
      );
    }

    assert.deepEqual(
      encodeStateV1(jumpedFinalState),
      encodeStateV1(materializedStates[32]),
      `${vector.name} final jump`,
    );
    assert.deepEqual(
      encodeStateV1(rewoundInitialState),
      encodeStateV1(initialState),
      `${vector.name} rewind`,
    );
    assert.equal(
      bytesToHexLowerV1(encodeStateV1(jumpedFinalState)),
      vector.final_state_encoding_hex,
      `${vector.name} final_state_encoding_hex`,
    );
    assert.equal(
      bytesToHexLowerV1(sha256BytesV1(encodeStateV1(jumpedFinalState))),
      vector.final_state_hash,
      `${vector.name} final_state_hash`,
    );

    const traceCommitment = deriveTraceCommitment521V1(
      32n,
      initialState,
      materializedStates,
    );
    assert.equal(
      bytesToHexLowerV1(traceCommitment),
      vector.trace_commitment,
      `${vector.name} trace_commitment`,
    );

    const commitmentRoot = deriveCommitmentRoot521V1(
      32n,
      materializedStates,
    );
    assert.equal(
      bytesToHexLowerV1(commitmentRoot),
      vector.commitment_root,
      `${vector.name} commitment_root`,
    );

    const stepState = stepStateV1(initialState);
    const inverseState = inverseStepV1(stepState);
    assert.deepEqual(
      encodeStateV1(inverseState),
      encodeStateV1(initialState),
      `${vector.name} inverse(step(initial))`,
    );
  }
}

export function assertToyPrimeCycleSuitesV1(
  fixture: CatMapTestVectorsFileV1,
): void {
  for (const suite of fixture.toy_prime_cycle_suites) {
    const analysis = analyzeToyPrimeV1(suite.p);

    assert.equal(analysis.stateCount, suite.p * suite.p, `p=${suite.p} state_count`);
    assert.deepEqual(
      analysis.cycleLengths,
      suite.cycle_lengths,
      `p=${suite.p} cycle_lengths`,
    );
    assert.deepEqual(
      analysis.representatives,
      suite.representatives,
      `p=${suite.p} representatives`,
    );

    for (let x = 0; x < suite.p; x += 1) {
      for (let y = 0; y < suite.p; y += 1) {
        const state = { x, y };
        const successor = stepToyStateV1(state, suite.p);
        const predecessor = inverseStepToyStateV1(state, suite.p);

        assert.deepEqual(
          inverseStepToyStateV1(successor, suite.p),
          state,
          `p=${suite.p} inverse(step(${x},${y}))`,
        );
        assert.deepEqual(
          stepToyStateV1(predecessor, suite.p),
          state,
          `p=${suite.p} step(inverse(${x},${y}))`,
        );

        for (const jump of [0, 1, 2, 3, 5, 8, 13]) {
          let repeated = state;
          for (let index = 0; index < jump; index += 1) {
            repeated = stepToyStateV1(repeated, suite.p);
          }
          assert.deepEqual(
            fastForwardToyStateV1(state, BigInt(jump), suite.p),
            repeated,
            `p=${suite.p} jump=${jump} state=(${x},${y})`,
          );
        }
      }
    }
  }
}

function catMapFixtureUrlV1(): URL {
  return new URL("../../fixtures/v1/cat_map_v1/test_vectors.json", import.meta.url);
}

function assertStateHexEqualV1(
  actual: StateV1,
  expected: StateHexFixtureV1,
  label: string,
): void {
  assert.equal(bigIntToPrefixedHexV1(actual.x), expected.x, `${label} x`);
  assert.equal(bigIntToPrefixedHexV1(actual.y), expected.y, `${label} y`);
  assert.equal(encodeCoordinateV1(actual.x).length, FIELD_ELEMENT_521_BYTE_LEN_V1, `${label} x width`);
  assert.equal(encodeCoordinateV1(actual.y).length, FIELD_ELEMENT_521_BYTE_LEN_V1, `${label} y width`);
  assert.equal(encodeStateV1(actual).length, DCM_STATE_521_CANONICAL_BYTE_LEN_V1, `${label} state width`);
}

function reduceBytesMod521V1(bytes: Uint8Array): bigint {
  let reduced = 0n;
  for (const byte of bytes) {
    reduced = (reduced * 256n + BigInt(byte)) % MODULUS_521_V1;
  }
  return reduced;
}

function stepStateV1(state: StateV1): StateV1 {
  return {
    x: mod521V1(state.x + state.y),
    y: mod521V1(state.x + 2n * state.y),
  };
}

function inverseStepV1(state: StateV1): StateV1 {
  return {
    x: mod521V1(2n * state.x - state.y),
    y: mod521V1(-state.x + state.y),
  };
}

function fastForwardStateV1(state: StateV1, stepCount: bigint): StateV1 {
  return applyMatrixV1(matrixPowV1(FORWARD_MATRIX_V1, stepCount), state);
}

function fastRewindStateV1(state: StateV1, stepCount: bigint): StateV1 {
  return applyMatrixV1(matrixPowV1(INVERSE_MATRIX_V1, stepCount), state);
}

function materializeStatesV1(initialState: StateV1, iterationCount: bigint): StateV1[] {
  const states = [initialState];
  let current = initialState;

  for (let index = 0n; index < iterationCount; index += 1n) {
    current = stepStateV1(current);
    states.push(current);
  }

  return states;
}

function matrixPowV1(matrix: MatrixV1, exponent: bigint): MatrixV1 {
  let result = identityMatrixV1();
  let base = matrix;
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = multiplyMatricesV1(result, base);
    }
    base = multiplyMatricesV1(base, base);
    power >>= 1n;
  }

  return result;
}

function identityMatrixV1(): MatrixV1 {
  return {
    a11: 1n,
    a12: 0n,
    a21: 0n,
    a22: 1n,
  };
}

function multiplyMatricesV1(left: MatrixV1, right: MatrixV1): MatrixV1 {
  return {
    a11: mod521V1(left.a11 * right.a11 + left.a12 * right.a21),
    a12: mod521V1(left.a11 * right.a12 + left.a12 * right.a22),
    a21: mod521V1(left.a21 * right.a11 + left.a22 * right.a21),
    a22: mod521V1(left.a21 * right.a12 + left.a22 * right.a22),
  };
}

function applyMatrixV1(matrix: MatrixV1, state: StateV1): StateV1 {
  return {
    x: mod521V1(matrix.a11 * state.x + matrix.a12 * state.y),
    y: mod521V1(matrix.a21 * state.x + matrix.a22 * state.y),
  };
}

function encodeCoordinateV1(value: bigint): Uint8Array {
  return encodeBigIntFixedWidthV1(
    mod521V1(value),
    FIELD_ELEMENT_521_BYTE_LEN_V1,
  );
}

function encodeBigIntFixedWidthV1(value: bigint, byteLength: number): Uint8Array {
  const hex = value.toString(16).padStart(byteLength * 2, "0");
  return decodeHexBytesV1(hex);
}

function encodeStateV1(state: StateV1): Uint8Array {
  return concatBytesV1(encodeCoordinateV1(state.x), encodeCoordinateV1(state.y));
}

function deriveTraceCommitment521V1(
  iterationCount: bigint,
  initialState: StateV1,
  states: StateV1[],
): Uint8Array {
  const preimageParts: Uint8Array[] = [
    AURA_DCM_521_V1_TRACE_COMMITMENT_DOMAIN_SEPARATOR,
    FIELD_MODULUS_521_BYTES_V1,
    u64ToLeBytesV1(iterationCount),
    encodeCoordinateV1(initialState.x),
    encodeCoordinateV1(initialState.y),
    u64ToLeBytesV1(BigInt(states.length)),
  ];

  states.forEach((state, index) => {
    preimageParts.push(stateLeafHash521V1(BigInt(index), state));
  });

  return sha256BytesV1(concatBytesV1(...preimageParts));
}

function stateLeafHash521V1(index: bigint, state: StateV1): Uint8Array {
  return sha256BytesV1(
    concatBytesV1(
      AURA_DCM_521_V1_STATE_LEAF_DOMAIN_SEPARATOR,
      u64ToLeBytesV1(index),
      encodeStateV1(state),
    ),
  );
}

function deriveCommitmentRoot521V1(
  iterationCount: bigint,
  states: StateV1[],
): Uint8Array {
  let commitmentState = commitmentSeedV1(iterationCount);

  for (const state of states) {
    commitmentState = absorbCommitmentFromStateV1(commitmentState, state);
  }

  return commitmentRootBytesFromElementsV1(commitmentState);
}

function commitmentSeedV1(iterationCount: bigint): [bigint, bigint] {
  return [
    modBaseFieldV1(
      DCM_AIR_REAL_STARK_COMMITMENT_SEED_0_V1
        + iterationCount * DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_0_V1,
    ),
    modBaseFieldV1(
      DCM_AIR_REAL_STARK_COMMITMENT_SEED_1_V1
        + iterationCount * DCM_AIR_REAL_STARK_COMMITMENT_ITERATION_SCALE_1_V1,
    ),
  ];
}

function absorbCommitmentFromStateV1(
  previous: [bigint, bigint],
  state: StateV1,
): [bigint, bigint] {
  const [xDigits, yDigits] = stateCoordinateDigitsLeV1(state);
  return absorbCommitmentFromDigitsV1(previous, xDigits, yDigits);
}

function absorbCommitmentFromDigitsV1(
  previous: [bigint, bigint],
  xDigits: number[],
  yDigits: number[],
): [bigint, bigint] {
  const [rowLo, rowHi] = commitmentRowContributionFromDigitsV1(xDigits, yDigits);

  return [
    modBaseFieldV1(
      previous[0] * DCM_AIR_REAL_STARK_COMMITMENT_MIX_0_V1
        + previous[1] * previous[1]
        + rowLo
        + DCM_AIR_REAL_STARK_COMMITMENT_CONST_0_V1,
    ),
    modBaseFieldV1(
      previous[1] * DCM_AIR_REAL_STARK_COMMITMENT_MIX_1_V1
        + previous[0] * previous[0]
        + rowHi
        + DCM_AIR_REAL_STARK_COMMITMENT_CONST_1_V1,
    ),
  ];
}

function commitmentRowContributionFromDigitsV1(
  xDigits: number[],
  yDigits: number[],
): [bigint, bigint] {
  let accLo = DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_0_V1;
  let accHi = DCM_AIR_REAL_STARK_COMMITMENT_ROW_OFFSET_1_V1;
  let xPowerLo = 1n;
  let yPowerLo = 1n;
  let xPowerHi = 1n;
  let yPowerHi = 1n;

  for (let digitIndex = 0; digitIndex < DCM_AIR_REAL_STARK_DIGIT_COUNT_V1; digitIndex += 1) {
    const xDigit = BigInt(xDigits[digitIndex]!);
    const yDigit = BigInt(yDigits[digitIndex]!);
    accLo = modBaseFieldV1(accLo + xDigit * xPowerLo + yDigit * yPowerLo);
    accHi = modBaseFieldV1(accHi + xDigit * xPowerHi + yDigit * yPowerHi);
    xPowerLo = modBaseFieldV1(xPowerLo * DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_0_V1);
    yPowerLo = modBaseFieldV1(yPowerLo * DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_0_V1);
    xPowerHi = modBaseFieldV1(xPowerHi * DCM_AIR_REAL_STARK_COMMITMENT_X_BASE_1_V1);
    yPowerHi = modBaseFieldV1(yPowerHi * DCM_AIR_REAL_STARK_COMMITMENT_Y_BASE_1_V1);
  }

  return [accLo, accHi];
}

function stateCoordinateDigitsLeV1(state: StateV1): [number[], number[]] {
  return [digitsLeFromCoordinateV1(state.x), digitsLeFromCoordinateV1(state.y)];
}

function digitsLeFromCoordinateV1(value: bigint): number[] {
  const bytesLe = Array.from(encodeCoordinateV1(value)).reverse();
  const digits = new Array<number>(DCM_AIR_REAL_STARK_DIGIT_COUNT_V1).fill(0);
  let buffer = 0;
  let bitCount = 0;
  let digitIndex = 0;

  for (const byte of bytesLe) {
    buffer |= byte << bitCount;
    bitCount += 8;

    while (bitCount >= 7 && digitIndex < DCM_AIR_REAL_STARK_DIGIT_COUNT_V1) {
      digits[digitIndex] = buffer & 0x7f;
      buffer >>= 7;
      bitCount -= 7;
      digitIndex += 1;
    }
  }

  if (digitIndex < DCM_AIR_REAL_STARK_DIGIT_COUNT_V1) {
    digits[digitIndex] = buffer;
  }

  return digits;
}

function commitmentRootBytesFromElementsV1(elements: [bigint, bigint]): Uint8Array {
  return concatBytesV1(u128ToLeBytesV1(elements[0]), u128ToLeBytesV1(elements[1]));
}

function u128ToLeBytesV1(value: bigint): Uint8Array {
  const output = new Uint8Array(16);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number((value >> BigInt(index * 8)) & 0xffn);
  }

  return output;
}

function sha256BytesV1(payload: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(payload).digest());
}

function modBaseFieldV1(value: bigint): bigint {
  const reduced = value % BASE_FIELD_MODULUS_V1;
  return reduced >= 0n ? reduced : reduced + BASE_FIELD_MODULUS_V1;
}

function analyzeToyPrimeV1(modulus: number): ToyAnalysisV1 {
  const visited = new Set<string>();
  const cycles: { x: number; y: number }[][] = [];

  for (let x = 0; x < modulus; x += 1) {
    for (let y = 0; y < modulus; y += 1) {
      const key = toyStateKeyV1(x, y);
      if (visited.has(key)) {
        continue;
      }

      const cycle: { x: number; y: number }[] = [];
      let current = { x, y };
      while (!visited.has(toyStateKeyV1(current.x, current.y))) {
        visited.add(toyStateKeyV1(current.x, current.y));
        cycle.push(current);
        current = stepToyStateV1(current, modulus);
      }
      cycles.push(cycle);
    }
  }

  cycles.sort((left, right) => {
    if (left.length !== right.length) {
      return left.length - right.length;
    }
    if (left[0].x !== right[0].x) {
      return left[0].x - right[0].x;
    }
    return left[0].y - right[0].y;
  });

  return {
    stateCount: visited.size,
    cycleLengths: cycles.map((cycle) => cycle.length),
    representatives: cycles.map((cycle) => [cycle[0].x, cycle[0].y]),
  };
}

function stepToyStateV1(
  state: { x: number; y: number },
  modulus: number,
): { x: number; y: number } {
  return {
    x: modToyV1(state.x + state.y, modulus),
    y: modToyV1(state.x + 2 * state.y, modulus),
  };
}

function inverseStepToyStateV1(
  state: { x: number; y: number },
  modulus: number,
): { x: number; y: number } {
  return {
    x: modToyV1(2 * state.x - state.y, modulus),
    y: modToyV1(-state.x + state.y, modulus),
  };
}

function fastForwardToyStateV1(
  state: { x: number; y: number },
  stepCount: bigint,
  modulus: number,
): { x: number; y: number } {
  const matrix = matrixPowToyV1(
    {
      a11: 1,
      a12: 1,
      a21: 1,
      a22: 2,
    },
    stepCount,
    modulus,
  );
  return {
    x: modToyV1(matrix.a11 * state.x + matrix.a12 * state.y, modulus),
    y: modToyV1(matrix.a21 * state.x + matrix.a22 * state.y, modulus),
  };
}

function matrixPowToyV1(
  matrix: { a11: number; a12: number; a21: number; a22: number },
  exponent: bigint,
  modulus: number,
): { a11: number; a12: number; a21: number; a22: number } {
  let result = {
    a11: 1,
    a12: 0,
    a21: 0,
    a22: 1,
  };
  let base = matrix;
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = multiplyToyMatricesV1(result, base, modulus);
    }
    base = multiplyToyMatricesV1(base, base, modulus);
    power >>= 1n;
  }

  return result;
}

function multiplyToyMatricesV1(
  left: { a11: number; a12: number; a21: number; a22: number },
  right: { a11: number; a12: number; a21: number; a22: number },
  modulus: number,
): { a11: number; a12: number; a21: number; a22: number } {
  return {
    a11: modToyV1(left.a11 * right.a11 + left.a12 * right.a21, modulus),
    a12: modToyV1(left.a11 * right.a12 + left.a12 * right.a22, modulus),
    a21: modToyV1(left.a21 * right.a11 + left.a22 * right.a21, modulus),
    a22: modToyV1(left.a21 * right.a12 + left.a22 * right.a22, modulus),
  };
}

function toyStateKeyV1(x: number, y: number): string {
  return `${x},${y}`;
}

function mod521V1(value: bigint): bigint {
  const result = value % MODULUS_521_V1;
  return result >= 0n ? result : result + MODULUS_521_V1;
}

function modToyV1(value: number, modulus: number): number {
  const result = value % modulus;
  return result >= 0 ? result : result + modulus;
}

function u64ToLeBytesV1(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  let remaining = value;
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function decodeHexBytesV1(hex: string): Uint8Array {
  const normalized = normalizeHexV1(hex);
  assert.equal(normalized.length % 2, 0, `hex must be even-length: ${hex}`);
  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}

function normalizeHexV1(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

function bytesToHexLowerV1(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

function bigIntToPrefixedHexV1(value: bigint): string {
  const normalized = mod521V1(value);
  return normalized === 0n ? "0x0" : `0x${normalized.toString(16)}`;
}

function concatBytesV1(...parts: Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }

  return output;
}

function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
