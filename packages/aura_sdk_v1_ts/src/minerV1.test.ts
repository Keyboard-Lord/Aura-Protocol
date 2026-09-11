// M2 codec/profile evidence only; no mining search, coordination or rewards.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1.js";
import {
  MINER_JOB_V1_BYTE_LEN, encodeMinerJobV1, decodeMinerJobV1, minerJobCommitmentV1,
  minerJobSigningDigestV1, signMinerJobV1, verifyMinerJobForPolicyV1, minerRouteTagV1,
  minerIntentCommitmentV1, buildMinerWorkV1, validateMinerWorkProfileV1,
  validateMinerClaimProfileV1, validateMinerHeadV1, validateMinerWindowV1, passesMinerHashFilterV1,
} from "./minerV1.ts";
import type { MinerJobV1, MinerJobPolicyV1 } from "./minerV1.ts";
import {
  decodeEconomicWorkV1, encodeEconomicWorkV1, economicGenesisHeadV2,
  validateEconomicHeadV2, verifyEconomicAdmissionSignaturesV1,
} from "./economicV1.ts";
import type { EconomicWorkV1 } from "./economicV1.ts";
import { encodeEconomicMeterV1 } from "../../aura_sdk_v0_ts/src/index.ts";
import { buildStormClaimV1, validateStormClaimV1 } from "./stormClaimV1.ts";
import { encodeStepU64Le } from "./stormExecutionV1.ts";

const v = JSON.parse(readFileSync(new URL("../../../fixtures/miner_v1/job_profile_vector_v1.json", import.meta.url), "utf8"));
const old = JSON.parse(readFileSync(new URL("../../../fixtures/economic_admission_v1/contract_vector.json", import.meta.url), "utf8"));
const bytes = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const digest = (s: string) => createHash("sha256").update(s).digest();
const limits = { maxWorkBytes: 100_000, maxMeterBytes: 90_000, maxIterations: 100n };
const max = (1n << 64n) - 1n;
const secret = bytes(v.test_only_operator_secret_hex);
const otherKey = schnorr.getPublicKey(bytes("00".repeat(31) + "02"));
function job(): MinerJobV1 {
  // Independently constructed API input, not only decoder/encoder agreement.
  const previous = decodeEconomicWorkV1(bytes(old.work_hex), limits);
  return { jobVersion: 1, network: "regtest", operatorKey: schnorr.getPublicKey(secret),
    journalNamespace: digest("RESEARCH_ONLY_MINER_NAMESPACE"), policyEpoch: 0n, roundNumber: 1n,
    priorHeadSequence: 0n, priorHeadHash: new Uint8Array(32), challenge: digest("RESEARCH_ONLY_JOB_CHALLENGE"),
    sideA: previous.storm.sideA, sideB: previous.storm.sideB, iterationCount: 64n,
    target: bytes("0f" + "ff".repeat(31)), maxWorkBytes: 100_000n, maxMeterBytes: 90_000n,
    openedAt: 2_000_000_000n, expiresAt: 2_000_000_600n, rewardSatoshis: 10_000n };
}
function policy(j: MinerJobV1): MinerJobPolicyV1 {
  const {network, operatorKey, journalNamespace, policyEpoch, iterationCount, target, maxWorkBytes, maxMeterBytes} = j;
  return {network, operatorKey, journalNamespace, policyEpoch, iterationCount, target, maxWorkBytes, maxMeterBytes};
}
const meter = () => decodeEconomicWorkV1(bytes(v.work_hex), limits).meter;
const work = () => buildMinerWorkV1(job(), meter(), bytes(v.nonce_hex));

test("miner: shared exact job, digest, signature, intent, route, context and W bytes", () => {
  const j = job(), w = work();
  assert.equal(MINER_JOB_V1_BYTE_LEN, 471);
  assert.equal(encodeMinerJobV1(j).length, 471);
  assert.equal(hex(encodeMinerJobV1(j)), v.job_hex);
  assert.equal(hex(encodeMinerJobV1(decodeMinerJobV1(bytes(v.job_hex)))), v.job_hex);
  assert.equal(hex(minerJobCommitmentV1(j)), v.job_commitment_hex);
  assert.equal(hex(minerJobSigningDigestV1(j)), v.job_signing_digest_hex);
  assert.equal(hex(schnorr.sign(minerJobSigningDigestV1(j), secret, new Uint8Array(32))), v.job_signature_hex);
  assert.doesNotThrow(() => verifyMinerJobForPolicyV1(j, bytes(v.job_signature_hex), policy(j), limits));
  assert.doesNotThrow(() => verifyMinerJobForPolicyV1(j, signMinerJobV1(j, secret), policy(j), limits));
  assert.throws(() => signMinerJobV1(j, bytes("00".repeat(31) + "02")));
  assert.equal(hex(minerIntentCommitmentV1(j, w.meter)), v.intent_commitment_hex);
  assert.equal(hex(minerRouteTagV1()), v.route_tag_hex);
  assert.equal(hex(w.storm.contextBytesV1), v.context_hex);
  assert.equal(hex(encodeEconomicMeterV1(w.meter)), v.meter_hex);
  assert.equal(hex(encodeEconomicWorkV1(w)), v.work_hex);
  assert.equal(hex(encodeEconomicWorkV1(decodeEconomicWorkV1(bytes(v.work_hex), limits))), v.work_hex);
  for (const variant of v.valid_job_variants)
    assert.equal(hex(encodeMinerJobV1(decodeMinerJobV1(bytes(variant.job_hex)))), variant.job_hex, variant.name);
});

test("miner: all 471 job bytes have shared decode outcomes and reject the old signature", () => {
  const original = bytes(v.job_hex), j = job(), p = policy(j);
  assert.equal(v.single_bit_mutation_decodes.length, 471);
  for (let i = 0; i < original.length; i++) {
    const b = original.slice(); b[i] ^= 1;
    let changed: MinerJobV1 | undefined;
    try { changed = decodeMinerJobV1(b); } catch { /* Expected malformed inputs stay rejected. */ }
    assert.equal(changed !== undefined, v.single_bit_mutation_decodes[i] === "1", `decode byte ${i}`);
    if (changed) {
      assert.equal(hex(encodeMinerJobV1(changed)), hex(b), `no normalization byte ${i}`);
      assert.notEqual(hex(minerJobCommitmentV1(changed)), v.job_commitment_hex);
      assert.notEqual(hex(minerJobSigningDigestV1(changed)), v.job_signing_digest_hex);
      assert.throws(() => verifyMinerJobForPolicyV1(changed!, bytes(v.job_signature_hex), p, limits), `signed byte ${i}`);
    }
  }
  for (let i = 0; i < 64; i++) {
    const sig = bytes(v.job_signature_hex); sig[i] ^= 1;
    assert.throws(() => verifyMinerJobForPolicyV1(j, sig, p, limits), `signature byte ${i}`);
  }
  for (const n of [0, 1, 32, 63, 65]) assert.throws(() => verifyMinerJobForPolicyV1(j, new Uint8Array(n), p, limits));
});

test("miner: truncation, trailing bytes, malformed fields and unsupported networks", () => {
  const b = bytes(v.job_hex);
  for (let n = 0; n < 471; n++) assert.throws(() => decodeMinerJobV1(b.slice(0, n)), `truncation ${n}`);
  for (const extra of [1, 32, 471]) assert.throws(() => decodeMinerJobV1(Buffer.concat([b, new Uint8Array(extra)])));
  for (const patch of v.invalid_job_patches) {
    const c = b.slice(); c.set(bytes(patch.replacement_hex), patch.offset);
    assert.throws(() => decodeMinerJobV1(c), patch.name);
  }
  for (let tag = 5; tag <= 255; tag++) { const c = b.slice(); c[18] = tag; assert.throws(() => decodeMinerJobV1(c)); }
});

test("miner: API input cannot infer defaults, normalize integers or accept a JSON job wire", () => {
  const j = job();
  for (const field of Object.keys(j)) {
    const missing = {...j}; delete missing[field];
    assert.throws(() => encodeMinerJobV1(missing));
    assert.throws(() => encodeMinerJobV1({...j, [field]: null}));
  }
  for (const field of ["policyEpoch", "roundNumber", "priorHeadSequence", "iterationCount", "maxWorkBytes", "maxMeterBytes", "openedAt", "expiresAt", "rewardSatoshis"])
    for (const value of [-1n, max + 1n, 1, "1", undefined]) assert.throws(() => encodeMinerJobV1({...j, [field]: value}));
  for (const field of ["operatorKey", "journalNamespace", "priorHeadHash", "challenge", "target", "sideA", "sideB"])
    for (const value of [[], "00", new Uint8Array(31), new Uint8Array(111)]) assert.throws(() => encodeMinerJobV1({...j, [field]: value}));
  for (const bad of [null, {}, [], {...j, candidateId: "second-id"}, {...j, [Symbol("hidden")]: 1}])
    assert.throws(() => encodeMinerJobV1(bad as MinerJobV1));
  const json = JSON.stringify(j, (_k, value) => typeof value === "bigint" ? value.toString() : value);
  assert.throws(() => decodeMinerJobV1(Buffer.from(json)));
  assert.throws(() => encodeMinerJobV1(JSON.parse(json)));
  for (const value of ["REGTEST", "bitcoin", 3, null]) assert.throws(() => encodeMinerJobV1({...j, network: value} as MinerJobV1));
});

test("miner: trusted epoch policy, host limits and half-open admission window", () => {
  const j = job(), p = policy(j), sig = bytes(v.job_signature_hex);
  for (const patch of [{network: "mainnet"}, {operatorKey: otherKey}, {journalNamespace: new Uint8Array(32)},
    {policyEpoch: 1n}, {iterationCount: 65n}, {target: bytes("01".repeat(32))}, {maxWorkBytes: 100_001n}, {maxMeterBytes: 90_001n}])
    assert.throws(() => verifyMinerJobForPolicyV1(j, sig, {...p, ...patch} as MinerJobPolicyV1, limits));
  for (const host of [{...limits, maxWorkBytes: 99_999}, {...limits, maxMeterBytes: 89_999}, {...limits, maxIterations: 63n},
    {...limits, maxWorkBytes: Number.MAX_SAFE_INTEGER + 1}, {...limits, maxMeterBytes: -1}, {...limits, maxIterations: -1n}])
    assert.throws(() => verifyMinerJobForPolicyV1(j, sig, p, host));
  for (const t of [j.openedAt, j.expiresAt - 1n]) assert.doesNotThrow(() => validateMinerWindowV1(j, t, 600n));
  for (const t of [j.openedAt - 1n, j.expiresAt, max]) assert.throws(() => validateMinerWindowV1(j, t, 600n));
  assert.throws(() => validateMinerWindowV1(j, j.openedAt, 599n));
});

test("miner: stale, malformed and overflowing predecessors reject", () => {
  const j = job(), genesis = economicGenesisHeadV2();
  assert.doesNotThrow(() => validateMinerHeadV1(j, genesis));
  assert.throws(() => validateMinerHeadV1({...j, priorHeadSequence: 1n}, genesis));
  assert.throws(() => validateMinerHeadV1({...j, priorHeadHash: bytes("01".repeat(32))}, genesis));
  assert.throws(() => validateMinerHeadV1(j, {...genesis, current_head_hash_hex: "01".repeat(32)}));
  const h = {...genesis, head_sequence_number: max.toString()};
  h.current_head_hash_hex = createHash("sha256").update("AURA_ECONOMIC_HEAD_V1").update(Uint8Array.of(2, 0, 0, 0))
    .update(encodeStepU64Le(max)).update(new Uint8Array(32)).digest("hex");
  assert.doesNotThrow(() => validateEconomicHeadV2(h));
  assert.throws(() => validateMinerHeadV1({...j, priorHeadSequence: max, priorHeadHash: bytes(h.current_head_hash_hex)}, h));
});

test("miner: every W byte is authenticated; changing the nonce never reuses old consent", () => {
  const j = job(), w = work(), a = v.binding_authorization, c = v.binding_consent, b = encodeEconomicWorkV1(w);
  assert.doesNotThrow(() => verifyEconomicAdmissionSignaturesV1(c, j.network, w, a));
  for (let i = 0; i < b.length; i++) {
    const changed = b.slice(); changed[i] ^= 1;
    assert.throws(() => verifyEconomicAdmissionSignaturesV1(c, j.network, decodeEconomicWorkV1(changed, limits), a), `W byte ${i}`);
  }
  for (let i = 0; i < 209; i++) {
    const changed = structuredClone(w); changed.storm.contextBytesV1[i] ^= 1;
    if (i >= 97 && i < 129) assert.doesNotThrow(() => validateMinerWorkProfileV1(j, changed), `nonce byte ${i}`);
    else assert.throws(() => validateMinerWorkProfileV1(j, changed), `fixed context byte ${i}`);
  }
  const nonce = bytes(v.nonce_hex); nonce[0] ^= 1;
  const changed = buildMinerWorkV1(j, meter(), nonce);
  assert.notEqual(hex(encodeEconomicWorkV1(changed)), v.work_hex);
  assert.throws(() => verifyEconomicAdmissionSignaturesV1(c, j.network, changed, a));
  const changedAuth = structuredClone(a); changedAuth.authorization_lineage.freshness_binding = hex(nonce);
  assert.throws(() => verifyEconomicAdmissionSignaturesV1(c, j.network, changed, changedAuth));
  for (const n of [0, 31, 33]) assert.throws(() => buildMinerWorkV1(j, meter(), new Uint8Array(n)));
});

test("miner: tuple, payer, intent, head linkage and exact work/meter caps", () => {
  const j = job(), w = work();
  const mutations: ((w: EconomicWorkV1) => void)[] = [
    w => {w.storm.sideA[0] ^= 1;}, w => {w.storm.sideB[0] ^= 1;}, w => {w.storm.iterationCount++;},
    w => {w.meter.ledger.payerAccountId = otherKey;}, w => {w.meter.batch.batchNumber++;},
    w => {w.meter.head.previousHeadHash[0] ^= 1;}, w => {w.meter.head.headSequenceNumber++;},
  ];
  for (const mutate of mutations) { const changed = structuredClone(w); mutate(changed); assert.throws(() => validateMinerWorkProfileV1(j, changed)); }
  const m = meter(); m.batch.batchNumber++;
  assert.notEqual(hex(minerIntentCommitmentV1(j, m)), v.intent_commitment_hex);
  assert.doesNotThrow(() => buildMinerWorkV1(j, m, bytes(v.nonce_hex)));
  for (const patch of [{headSequenceNumber: 2n}, {previousHeadHash: bytes("01".repeat(32))}, {settlementHeadVersion: 1}]) {
    const m = meter(); Object.assign(m.head, patch); assert.throws(() => buildMinerWorkV1(j, m, bytes(v.nonce_hex)));
  }
  const tight = {...j, maxWorkBytes: BigInt(encodeEconomicWorkV1(w).length), maxMeterBytes: BigInt(encodeEconomicMeterV1(w.meter).length)};
  assert.doesNotThrow(() => buildMinerWorkV1(tight, meter(), bytes(v.nonce_hex)));
  assert.throws(() => buildMinerWorkV1({...tight, maxWorkBytes: tight.maxWorkBytes - 1n}, meter(), bytes(v.nonce_hex)));
  assert.throws(() => buildMinerWorkV1({...tight, maxMeterBytes: tight.maxMeterBytes - 1n}, meter(), bytes(v.nonce_hex)));
});

test("miner: fixed claim slots and tuple validation never claim PoC acceptance", () => {
  const j = job(), w = work(), claim = buildStormClaimV1(w.storm);
  assert.doesNotThrow(() => validateMinerClaimProfileV1(j, w, claim, new Uint8Array()));
  assert.doesNotThrow(() => validateStormClaimV1(claim));
  for (const patch of [{version: 2}, {modulusId: 2}, {iterationCount: 65n}, {sideAHex: "00".repeat(110)},
    {sideBHex: "00".repeat(110)}, {contextBytesHex: "00".repeat(209)}, {legacyCommitmentRootHex: "01".repeat(32)},
    {legacyTraceCommitmentHex: "01".repeat(32)}])
    assert.throws(() => validateMinerClaimProfileV1(j, w, {...claim, ...patch}, new Uint8Array()));
  assert.throws(() => validateMinerClaimProfileV1(j, w, claim, Uint8Array.of(0)));
  const corrupt = {...claim, traceRootHex: "00".repeat(32)};
  assert.doesNotThrow(() => validateMinerClaimProfileV1(j, w, corrupt, new Uint8Array()));
  assert.equal(passesMinerHashFilterV1(j, new Uint8Array(32)), true);
  assert.throws(() => validateStormClaimV1(corrupt));
});

test("miner: shared unsigned BE target endpoints, endian and precision traps", () => {
  for (const c of v.target_cases)
    assert.equal(passesMinerHashFilterV1({...job(), target: bytes(c.target_hex)}, bytes(c.proof_hash_hex)), c.passes);
  for (const n of [0, 4, 31, 33, 64]) assert.throws(() => passesMinerHashFilterV1(job(), new Uint8Array(n)));
  for (const byte of [0, 255]) assert.throws(() => passesMinerHashFilterV1({...job(), target: new Uint8Array(32).fill(byte)}, new Uint8Array(32)));
});
