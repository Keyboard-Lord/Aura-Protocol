import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  auraHash521V1,
  bytesToHexLowerV1,
  decodeCanonicalFixedHexBytesV1,
} from "../src/stormHash521V1.ts";
import {
  buildStormTrace,
  deriveA,
  deriveB,
  derivePhiN,
  derivePsiN,
  deriveX0,
  deriveY0,
} from "../src/stormExecutionV1.ts";
import { encodeStormRowBytesV1 } from "../src/stormStateV1.ts";
import {
  buildEncryptedEnvelopeV1,
  decryptPayloadV1,
  type AuraSessionEncryptionContextV1,
  type SessionPublicKeyV1,
  type SessionSecretKeyV1,
  type StormEncryptionBindingV1,
  validateEncryptedEnvelopeV1,
  SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
} from "../src/index.ts";

const PHASE_A_SAMPLE_COUNT_V1 = 100_000;
const PHASE_B_SAMPLE_COUNT_V1 = 128;
const PHASE_D_TRACE_STEPS_V1 = 64n;
const PHASE_E_TRACE_STEPS_V1 = 10_000n;
const FROZEN_STORM_FIXTURE_SHA256_V1 =
  "88dc1bfe22cd2ecb4c9afd6141a9b8e16b73d8c5c07f07170e3e4d342b3506a8";
const FROZEN_SESSION_FIXTURE_SHA256_V1 =
  "c881987228bb5c878c9bd9375d6e98ffedad87a19d479bc9802f7061dae5ef31";
const CONTEXT_MUTABLE_BYTE_RANGES_V1: Array<[number, number]> = [
  [1, 32],
  [65, 32],
  [97, 32],
  [129, 8],
  [137, 8],
  [145, 32],
  [177, 32],
];

type StormFixtureV1 = {
  aura_hash521_v1_message_hex: string;
  side_a_hex: string;
  side_b_hex: string;
  context_bytes_v1_hex: string;
  iteration_count: number;
  expected: {
    aura_hash521_v1_hex: string;
    x0_hex: string;
    y0_hex: string;
    a_hex: string;
    b_hex: string;
    phi_0_hex: string;
    psi_0_hex: string;
    phi_last_hex: string;
    psi_last_hex: string;
  };
};

type SessionFixtureV1 = {
  sender_secret_key_hex: string;
  sender_public_key_hex: string;
  receiver_secret_key_hex: string;
  receiver_public_key_hex: string;
  storm_claim_digest_hex: string;
  trace_root_hex: string;
  final_state_x_hex: string;
  final_state_y_hex: string;
  context_hash_hex: string;
  sender_id_hex: string;
  receiver_id_hex: string;
  freshness_nonce_hex: string;
  valid_from: number;
  valid_until: number;
  route_tag_hex: string;
  session_key_id_hex: string;
  nonce_hex: string;
  plaintext_hex: string;
  ciphertext_hex: string;
};

test("phase A distribution invariants hold and match the frozen vector", () => {
  const fixture = loadStormFixture();
  assert.equal(
    bytesToHexLowerV1(
      auraHash521V1(
        decodeCanonicalFixedHexBytesV1(
          fixture.aura_hash521_v1_message_hex,
          fixture.aura_hash521_v1_message_hex.length / 2,
          "aura_hash521_v1_message_hex",
        ),
      ),
    ),
    fixture.expected.aura_hash521_v1_hex,
  );

  const onesPerBit = new Array<number>(521).fill(0);
  const top9Counts = new Array<number>(512).fill(0);
  let zeroOutputs = 0;
  for (let sample = 0; sample < PHASE_A_SAMPLE_COUNT_V1; sample += 1) {
    const hash = auraHash521V1(deterministicBytesV1(sample, 40));
    for (let bit = 0; bit < 521; bit += 1) {
      onesPerBit[bit] += fieldBitV1(hash, bit);
    }
    top9Counts[top9BitsV1(hash)] += 1;
    if (hash.every((value) => value === 0)) {
      zeroOutputs += 1;
    }
  }

  const oneRatios = onesPerBit.map((count) => count / PHASE_A_SAMPLE_COUNT_V1);
  const avgOneRatio = oneRatios.reduce((sum, value) => sum + value, 0) / oneRatios.length;
  const maxBiasRatio = Math.max(...oneRatios.map((value) => Math.abs(value - 0.5)));
  assert.ok(avgOneRatio >= 0.499 && avgOneRatio <= 0.501, `expected mean one ratio near 0.5, got ${avgOneRatio}`);
  assert.ok(maxBiasRatio <= 0.006, `expected max per-bit skew <= 0.006, got ${maxBiasRatio}`);
  assert.equal(zeroOutputs, 0, "expected no zero outputs");
  assert.ok(Math.min(...top9Counts) > 0, "expected every top-9 bucket to appear at least once");
  assert.ok(Math.max(...top9Counts) < 300, `expected no top-9 bucket above 299, got ${Math.max(...top9Counts)}`);
});

test("phase B/C avalanche and domain separation invariants hold", () => {
  const fixture = loadStormFixture();
  const sideA = decodeCanonicalFixedHexBytesV1(fixture.side_a_hex, 110, "side_a_hex");
  const sideB = decodeCanonicalFixedHexBytesV1(fixture.side_b_hex, 110, "side_b_hex");
  const contextBytesV1 = decodeCanonicalFixedHexBytesV1(
    fixture.context_bytes_v1_hex,
    209,
    "context_bytes_v1_hex",
  );

  assert.equal(deriveX0(sideA), fixture.expected.x0_hex);
  assert.equal(deriveY0(sideB), fixture.expected.y0_hex);
  assert.equal(deriveA(contextBytesV1), fixture.expected.a_hex);
  assert.equal(deriveB(contextBytesV1), fixture.expected.b_hex);
  assert.equal(derivePhiN(sideA, sideB, contextBytesV1, 0n), fixture.expected.phi_0_hex);
  assert.equal(derivePsiN(sideA, sideB, contextBytesV1, 0n), fixture.expected.psi_0_hex);
  assert.equal(
    derivePhiN(sideA, sideB, contextBytesV1, BigInt(fixture.iteration_count - 1)),
    fixture.expected.phi_last_hex,
  );
  assert.equal(
    derivePsiN(sideA, sideB, contextBytesV1, BigInt(fixture.iteration_count - 1)),
    fixture.expected.psi_last_hex,
  );

  const baselineHash = auraHash521V1(deterministicBytesV1(42, 40));
  const changedBitCounts: number[] = [];
  for (let sample = 0; sample < PHASE_B_SAMPLE_COUNT_V1; sample += 1) {
    const mutated = deterministicBytesV1(42, 40);
    flipBitV1(mutated, sample);
    changedBitCounts.push(hammingDistanceV1(baselineHash, auraHash521V1(mutated)));
  }
  const avgChangedBits =
    changedBitCounts.reduce((sum, value) => sum + value, 0) / changedBitCounts.length;
  const avgChangedFraction = avgChangedBits / 521;
  assert.ok(
    avgChangedFraction >= 0.48 && avgChangedFraction <= 0.52,
    `expected average diffusion in [0.48, 0.52], got ${avgChangedFraction}`,
  );
  assert.ok(avgChangedBits >= 240 && avgChangedBits <= 280, `expected average changed bits in [240, 280], got ${avgChangedBits}`);
  assert.ok(Math.min(...changedBitCounts) >= 200, `expected min changed bits >= 200, got ${Math.min(...changedBitCounts)}`);
  assert.ok(Math.max(...changedBitCounts) <= 320, `expected max changed bits <= 320, got ${Math.max(...changedBitCounts)}`);

  const domainPayload = deterministicBytesV1(7, 96);
  const domains = [
    ["x0", new TextEncoder().encode("AURA_X0_V1")],
    ["y0", new TextEncoder().encode("AURA_Y0_V1")],
    ["a", new TextEncoder().encode("AURA_C_A_V1")],
    ["b", new TextEncoder().encode("AURA_C_B_V1")],
    ["phi", new TextEncoder().encode("AURA_STORM_X_V1")],
    ["psi", new TextEncoder().encode("AURA_STORM_Y_V1")],
  ] as const;
  let minDistance = Number.POSITIVE_INFINITY;
  for (let left = 0; left < domains.length; left += 1) {
    for (let right = left + 1; right < domains.length; right += 1) {
      const leftOut = auraHash521V1(concatBytesV1(domains[left][1], domainPayload));
      const rightOut = auraHash521V1(concatBytesV1(domains[right][1], domainPayload));
      minDistance = Math.min(minDistance, hammingDistanceV1(leftOut, rightOut));
      assert.notEqual(bytesToHexLowerV1(leftOut), bytesToHexLowerV1(rightOut));
    }
  }
  assert.ok(minDistance >= 200, `expected domain outputs to diverge by at least 200 bits, got ${minDistance}`);
});

test("phase D/E recurrence invariants hold", () => {
  const fixture = loadStormFixture();
  const baselineInputs = {
    sideA: decodeCanonicalFixedHexBytesV1(fixture.side_a_hex, 110, "side_a_hex"),
    sideB: decodeCanonicalFixedHexBytesV1(fixture.side_b_hex, 110, "side_b_hex"),
    contextBytesV1: decodeCanonicalFixedHexBytesV1(fixture.context_bytes_v1_hex, 209, "context_bytes_v1_hex"),
    iterationCount: PHASE_D_TRACE_STEPS_V1,
  };
  const baselineTrace = buildStormTrace(baselineInputs);

  const variants: Array<[string, typeof baselineInputs]> = [
    ["side_A", mutateSideABitV1(baselineInputs, 0)],
    ["side_B", mutateSideBBitV1(baselineInputs, 0)],
    ["context", mutateContextBitV1(baselineInputs, 0)],
  ];
  for (const [label, mutatedInputs] of variants) {
    const mutatedTrace = buildStormTrace(mutatedInputs);
    const distances = baselineTrace.map((state, index) =>
      hammingDistanceV1(encodeStormRowBytesV1(state), encodeStormRowBytesV1(mutatedTrace[index]!)),
    );
    const finalDistance = distances[distances.length - 1]!;
    assert.ok(finalDistance >= 500, `expected ${label} final divergence >= 500 bits, got ${finalDistance}`);
    assert.ok(Math.max(...distances) >= finalDistance, `expected ${label} peak divergence to dominate final divergence`);
    const firstNonZeroStep = distances.findIndex((value) => value > 0);
    assert.ok(firstNonZeroStep >= 0 && firstNonZeroStep <= 1, `expected ${label} to diverge immediately, got step ${firstNonZeroStep}`);
  }

  const longTrace = buildStormTrace({ ...baselineInputs, iterationCount: PHASE_E_TRACE_STEPS_V1 });
  const seen = new Set<string>();
  for (const state of longTrace) {
    const rowHex = bytesToHexLowerV1(encodeStormRowBytesV1(state));
    assert.ok(!seen.has(rowHex), "expected no repeated states inside the canonical long trace");
    seen.add(rowHex);
  }
  assert.equal(seen.size, longTrace.length);
});

test("phase G SDK binding mutations fail closed", () => {
  const fixture = loadSessionFixture();
  const senderSecretKey = secretKey(fixture.sender_secret_key_hex);
  const senderPublicKey = publicKey(fixture.sender_public_key_hex);
  const receiverSecretKey = secretKey(fixture.receiver_secret_key_hex);
  const receiverPublicKey = publicKey(fixture.receiver_public_key_hex);
  const context: AuraSessionEncryptionContextV1 = {
    version: SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
    stormClaimDigest: decodeCanonicalFixedHexBytesV1(fixture.storm_claim_digest_hex, 32, "storm_claim_digest_hex"),
    senderId: decodeCanonicalFixedHexBytesV1(fixture.sender_id_hex, 32, "sender_id_hex"),
    receiverId: decodeCanonicalFixedHexBytesV1(fixture.receiver_id_hex, 32, "receiver_id_hex"),
    freshnessNonce: decodeCanonicalFixedHexBytesV1(fixture.freshness_nonce_hex, 32, "freshness_nonce_hex"),
    validFrom: BigInt(fixture.valid_from),
    validUntil: BigInt(fixture.valid_until),
    routeTag: decodeCanonicalFixedHexBytesV1(fixture.route_tag_hex, 32, "route_tag_hex"),
    sessionKeyId: decodeCanonicalFixedHexBytesV1(fixture.session_key_id_hex, 32, "session_key_id_hex"),
  };
  const binding: StormEncryptionBindingV1 = {
    stormClaimDigest: decodeCanonicalFixedHexBytesV1(fixture.storm_claim_digest_hex, 32, "storm_claim_digest_hex"),
    traceRoot: decodeCanonicalFixedHexBytesV1(fixture.trace_root_hex, 32, "trace_root_hex"),
    finalStateX: decodeCanonicalFixedHexBytesV1(fixture.final_state_x_hex, 66, "final_state_x_hex"),
    finalStateY: decodeCanonicalFixedHexBytesV1(fixture.final_state_y_hex, 66, "final_state_y_hex"),
    contextHash: decodeCanonicalFixedHexBytesV1(fixture.context_hash_hex, 32, "context_hash_hex"),
    senderId: decodeCanonicalFixedHexBytesV1(fixture.sender_id_hex, 32, "sender_id_hex"),
    receiverId: decodeCanonicalFixedHexBytesV1(fixture.receiver_id_hex, 32, "receiver_id_hex"),
    sessionKeyId: decodeCanonicalFixedHexBytesV1(fixture.session_key_id_hex, 32, "session_key_id_hex"),
  };
  const nonce = decodeCanonicalFixedHexBytesV1(fixture.nonce_hex, 12, "nonce_hex");
  const plaintext = decodeCanonicalFixedHexBytesV1(
    fixture.plaintext_hex,
    fixture.plaintext_hex.length / 2,
    "plaintext_hex",
  );

  const envelope = buildEncryptedEnvelopeV1(
    senderSecretKey,
    receiverPublicKey,
    context,
    binding,
    plaintext,
    nonce,
  );
  assert.equal(bytesToHexLowerV1(envelope.ciphertext), fixture.ciphertext_hex);
  assert.equal(bytesToHexLowerV1(envelope.senderPublicKey.bytes), bytesToHexLowerV1(senderPublicKey.bytes));
  assert.equal(
    bytesToHexLowerV1(
      decryptPayloadV1(
        receiverSecretKey,
        envelope.senderPublicKey,
        context,
        binding,
        envelope.nonce,
        envelope.ciphertext,
      ),
    ),
    fixture.plaintext_hex,
  );

  const mutationCases: Array<[string, AuraSessionEncryptionContextV1, StormEncryptionBindingV1]> = [
    [
      "storm_claim_digest",
      { ...context, stormClaimDigest: flipLastBitV1(context.stormClaimDigest) },
      binding,
    ],
    [
      "trace_root",
      context,
      { ...binding, traceRoot: flipLastBitV1(binding.traceRoot) },
    ],
    [
      "final_state_x",
      context,
      { ...binding, finalStateX: flipLastBitV1(binding.finalStateX) },
    ],
    [
      "final_state_y",
      context,
      { ...binding, finalStateY: flipLastBitV1(binding.finalStateY) },
    ],
    [
      "context_hash",
      context,
      { ...binding, contextHash: flipLastBitV1(binding.contextHash) },
    ],
    [
      "route_tag",
      { ...context, routeTag: flipLastBitV1(context.routeTag) },
      binding,
    ],
    [
      "sender_id",
      context,
      { ...binding, senderId: flipLastBitV1(binding.senderId) },
    ],
    [
      "receiver_id",
      context,
      { ...binding, receiverId: flipLastBitV1(binding.receiverId) },
    ],
    [
      "session_key_id",
      context,
      { ...binding, sessionKeyId: flipLastBitV1(binding.sessionKeyId) },
    ],
  ];

  for (const [label, mutatedContext, mutatedBinding] of mutationCases) {
    assert.throws(
      () => validateEncryptedEnvelopeV1(envelope, mutatedContext, mutatedBinding),
      undefined,
      `expected validation to fail for ${label}`,
    );
    assert.throws(
      () =>
        decryptPayloadV1(
          receiverSecretKey,
          envelope.senderPublicKey,
          mutatedContext,
          mutatedBinding,
          envelope.nonce,
          envelope.ciphertext,
        ),
      undefined,
      `expected decrypt to fail for ${label}`,
    );
  }
});

test("canonical storm and session fixture hashes are frozen", () => {
  const stormBytes = readFileSync(
    new URL("../../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json", import.meta.url),
  );
  const sessionBytes = readFileSync(
    new URL("../../../fixtures/v1/session_encryption_v1/session_encryption_parity_vector_v1.json", import.meta.url),
  );
  assert.equal(sha256HexV1(stormBytes), FROZEN_STORM_FIXTURE_SHA256_V1);
  assert.equal(sha256HexV1(sessionBytes), FROZEN_SESSION_FIXTURE_SHA256_V1);
});

function loadStormFixture(): StormFixtureV1 {
  return JSON.parse(
    readFileSync(
      new URL("../../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json", import.meta.url),
      "utf8",
    ),
  ) as StormFixtureV1;
}

function loadSessionFixture(): SessionFixtureV1 {
  return JSON.parse(
    readFileSync(
      new URL("../../../fixtures/v1/session_encryption_v1/session_encryption_parity_vector_v1.json", import.meta.url),
      "utf8",
    ),
  ) as SessionFixtureV1;
}

function deterministicBytesV1(seed: number, len: number): Uint8Array {
  let state = BigInt(seed) ^ 0x9e3779b97f4a7c15n;
  const output = new Uint8Array(len);
  for (let index = 0; index < len; index += 1) {
    state ^= state >> 12n;
    state ^= state << 25n;
    state ^= state >> 27n;
    const mixed = (state * 0x2545f4914f6cdd1dn + BigInt(index)) & 0xffffffffffffffffn;
    output[index] = Number((mixed >> 56n) & 0xffn);
  }
  return output;
}

function fieldBitV1(bytes: Uint8Array, bitIndex: number): number {
  const targetBitIndex = 7 + bitIndex;
  return ((bytes[Math.floor(targetBitIndex / 8)] ?? 0) >> (7 - (targetBitIndex % 8))) & 1;
}

function top9BitsV1(bytes: Uint8Array): number {
  return (((bytes[0] ?? 0) & 0x01) << 8) | (bytes[1] ?? 0);
}

function hammingDistanceV1(left: Uint8Array, right: Uint8Array): number {
  assert.equal(left.length, right.length);
  let distance = 0;
  for (let index = 0; index < left.length; index += 1) {
    distance += popcount8V1((left[index] ?? 0) ^ (right[index] ?? 0));
  }
  return distance;
}

function popcount8V1(value: number): number {
  let current = value & 0xff;
  let count = 0;
  while (current !== 0) {
    count += current & 1;
    current >>= 1;
  }
  return count;
}

function flipBitV1(bytes: Uint8Array, bitIndex: number): void {
  const byteIndex = Math.floor(bitIndex / 8);
  const bitInByte = bitIndex % 8;
  bytes[byteIndex] ^= 1 << (7 - bitInByte);
}

function flipLastBitV1(bytes: Uint8Array): Uint8Array {
  const clone = new Uint8Array(bytes);
  clone[clone.length - 1] ^= 0x01;
  return clone;
}

function mutateSideABitV1(
  inputs: { sideA: Uint8Array; sideB: Uint8Array; contextBytesV1: Uint8Array; iterationCount: bigint },
  bitIndex: number,
): { sideA: Uint8Array; sideB: Uint8Array; contextBytesV1: Uint8Array; iterationCount: bigint } {
  const sideA = new Uint8Array(inputs.sideA);
  flipBitV1(sideA, bitIndex);
  return { ...inputs, sideA };
}

function mutateSideBBitV1(
  inputs: { sideA: Uint8Array; sideB: Uint8Array; contextBytesV1: Uint8Array; iterationCount: bigint },
  bitIndex: number,
): { sideA: Uint8Array; sideB: Uint8Array; contextBytesV1: Uint8Array; iterationCount: bigint } {
  const sideB = new Uint8Array(inputs.sideB);
  flipBitV1(sideB, bitIndex);
  return { ...inputs, sideB };
}

function mutateContextBitV1(
  inputs: { sideA: Uint8Array; sideB: Uint8Array; contextBytesV1: Uint8Array; iterationCount: bigint },
  bitIndex: number,
): { sideA: Uint8Array; sideB: Uint8Array; contextBytesV1: Uint8Array; iterationCount: bigint } {
  const contextBytesV1 = new Uint8Array(inputs.contextBytesV1);
  flipBitV1(contextBytesV1, contextMutableAbsoluteBitV1(bitIndex));
  return { ...inputs, contextBytesV1 };
}

function concatBytesV1(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left, 0);
  output.set(right, left.length);
  return output;
}

function contextMutableAbsoluteBitV1(bitIndex: number): number {
  let remaining = bitIndex % contextMutableBitCountV1();
  for (const [start, len] of CONTEXT_MUTABLE_BYTE_RANGES_V1) {
    const rangeBits = len * 8;
    if (remaining < rangeBits) {
      return start * 8 + remaining;
    }
    remaining -= rangeBits;
  }
  throw new TypeError("context mutable bit index fell outside the configured ranges");
}

function contextMutableBitCountV1(): number {
  return CONTEXT_MUTABLE_BYTE_RANGES_V1.reduce((sum, [, len]) => sum + len * 8, 0);
}

function sha256HexV1(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function publicKey(hex: string): SessionPublicKeyV1 {
  return { bytes: decodeCanonicalFixedHexBytesV1(hex, 32, "public key") };
}

function secretKey(hex: string): SessionSecretKeyV1 {
  return { bytes: decodeCanonicalFixedHexBytesV1(hex, 32, "secret key") };
}
