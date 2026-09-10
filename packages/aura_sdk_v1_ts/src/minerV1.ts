// Approved miner codecs/profile checks. No PoC verdict, admission or winner state.
import { createHash } from "node:crypto";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bitcoinNetworkTagV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import type { BitcoinNetworkV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import { encodeEconomicMeterV1 } from "../../aura_sdk_v0_ts/src/index.ts";
import type { EconomicMeterV1 } from "../../aura_sdk_v0_ts/src/index.ts";
import { encodeEconomicWorkV1, validateEconomicHeadV2 } from "./economicV1.ts";
import type { EconomicLimitsV1, EconomicWorkV1, EconomicHeadV2 } from "./economicV1.ts";
import { encodeStormContextV1, STORM_CONTEXT_V1_VERSION } from "./stormContextV1.ts";
import { encodeStepU64Le } from "./stormExecutionV1.ts";
import { STORM_CLAIM_521_V1_VERSION, STORM_MODULUS_ID_521_V1 } from "./stormClaimV1.ts";
import type { StormClaim521V1 } from "./stormClaimV1.ts";

export const MINER_JOB_V1_BYTE_LEN = 471;
const domain = Buffer.from("AURA_MINER_JOB_V1");
const u64Max = 0xffff_ffff_ffff_ffffn;
export type MinerJobV1 = {
  jobVersion: number; network: BitcoinNetworkV1; operatorKey: Uint8Array; journalNamespace: Uint8Array;
  policyEpoch: bigint; roundNumber: bigint; priorHeadSequence: bigint; priorHeadHash: Uint8Array;
  challenge: Uint8Array; sideA: Uint8Array; sideB: Uint8Array; iterationCount: bigint;
  target: Uint8Array; maxWorkBytes: bigint; maxMeterBytes: bigint;
  openedAt: bigint; expiresAt: bigint; rewardSatoshis: bigint;
};
/** Trusted local configuration, never inferred from an untrusted job or serialized as another wire. */
export type MinerJobPolicyV1 = Pick<MinerJobV1, "network" | "operatorKey" | "journalNamespace" |
  "policyEpoch" | "iterationCount" | "target" | "maxWorkBytes" | "maxMeterBytes">;
const policyFields = ["network", "operatorKey", "journalNamespace", "policyEpoch", "iterationCount", "target", "maxWorkBytes", "maxMeterBytes"] as const;
const integerFields = ["policyEpoch", "roundNumber", "priorHeadSequence", "iterationCount", "maxWorkBytes", "maxMeterBytes", "openedAt", "expiresAt", "rewardSatoshis"] as const;
const bytes32Fields = ["operatorKey", "journalNamespace", "priorHeadHash", "challenge", "target"] as const;
const jobFields = ["jobVersion", "network", ...bytes32Fields, ...integerFields, "sideA", "sideB"];
const hash = (...parts: Uint8Array[]) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const equal = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
function ensure(ok: boolean, message: string): asserts ok { if (!ok) throw new TypeError(message); }
function fields(value: unknown, keys: readonly string[]): void {
  ensure(typeof value === "object" && value !== null && !Array.isArray(value)
    && Reflect.ownKeys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), "noncanonical miner fields");
}
function fixed(value: unknown, n: number): asserts value is Uint8Array {
  ensure(value instanceof Uint8Array && value.length === n, "invalid miner byte width");
}
function u64(value: unknown): asserts value is bigint {
  ensure(typeof value === "bigint" && value >= 0n && value <= u64Max, "invalid miner u64");
}
function shape(job: MinerJobV1): void {
  fields(job, jobFields);
  ensure(job.jobVersion === 1, "unsupported miner job version");
  bitcoinNetworkTagV1(job.network);
  for (const k of integerFields) u64(job[k]);
  for (const k of bytes32Fields) fixed(job[k], 32);
  fixed(job.sideA, 110); fixed(job.sideB, 110);
  secp256k1.Point.fromHex(`02${hex(job.operatorKey)}`);
  ensure(job.iterationCount > 0n && job.iterationCount < u64Max, "invalid miner iteration count");
  ensure(!job.target.every(x => x === 0) && !job.target.every(x => x === 255), "invalid miner target");
  ensure(job.openedAt < job.expiresAt && job.rewardSatoshis > 0n, "invalid miner window or reward");
}

export function minerRouteTagV1(): Uint8Array { return hash(Buffer.from("AURA_MINER_PROTOCOL_V1")); }

/** The sole 471-byte job encoding. Object properties are API input, not a JSON wire. */
export function encodeMinerJobV1(job: MinerJobV1): Uint8Array {
  shape(job);
  return Buffer.concat([domain, Uint8Array.of(job.jobVersion, bitcoinNetworkTagV1(job.network)),
    job.operatorKey, job.journalNamespace, encodeStepU64Le(job.policyEpoch), encodeStepU64Le(job.roundNumber),
    encodeStepU64Le(job.priorHeadSequence), job.priorHeadHash, job.challenge, job.sideA, job.sideB,
    encodeStepU64Le(job.iterationCount), job.target, ...[job.maxWorkBytes, job.maxMeterBytes, job.openedAt, job.expiresAt, job.rewardSatoshis].map(encodeStepU64Le)]);
}

export function decodeMinerJobV1(bytes: Uint8Array): MinerJobV1 {
  fixed(bytes, MINER_JOB_V1_BYTE_LEN);
  ensure(equal(bytes.subarray(0, domain.length), domain), "invalid miner job domain");
  const b = Buffer.from(bytes); let offset = domain.length;
  const take = (n: number) => { const result = Uint8Array.from(b.subarray(offset, offset + n)); offset += n; return result; };
  const number = () => { const value = b.readBigUInt64LE(offset); offset += 8; return value; };
  const jobVersion = take(1)[0]!, tag = take(1)[0]!;
  // The Bitcoin owner defines tag values; this is enumeration, not another tag mapping.
  const network = (["mainnet", "testnet3", "signet", "regtest", "testnet4"] as const).find(n => bitcoinNetworkTagV1(n) === tag);
  ensure(network !== undefined, "unknown Bitcoin network");
  const job: MinerJobV1 = { jobVersion, network, operatorKey: take(32), journalNamespace: take(32),
    policyEpoch: number(), roundNumber: number(), priorHeadSequence: number(), priorHeadHash: take(32),
    challenge: take(32), sideA: take(110), sideB: take(110), iterationCount: number(), target: take(32),
    maxWorkBytes: number(), maxMeterBytes: number(), openedAt: number(), expiresAt: number(), rewardSatoshis: number() };
  ensure(offset === b.length && equal(encodeMinerJobV1(job), bytes), "noncanonical miner job");
  return job;
}

export function minerJobCommitmentV1(job: MinerJobV1): Uint8Array { return hash(encodeMinerJobV1(job)); }
export function minerJobSigningDigestV1(job: MinerJobV1): Uint8Array {
  const tag = hash(Buffer.from("AURA_MINER_JOB_SIGNATURE_V1"));
  return hash(tag, tag, encodeMinerJobV1(job));
}
/** Detached signature. The library obtains signing randomness; it is not the public mining nonce. */
export function signMinerJobV1(job: MinerJobV1, secretKey: Uint8Array): Uint8Array {
  const digest = minerJobSigningDigestV1(job);
  fixed(secretKey, 32);
  ensure(equal(schnorr.getPublicKey(secretKey), job.operatorKey), "miner job signer mismatch");
  return schnorr.sign(digest, secretKey);
}

/** Policy/signature checks only; no funding, publication, live head or round ownership verdict. */
export function verifyMinerJobForPolicyV1(job: MinerJobV1, signature: Uint8Array, policy: MinerJobPolicyV1, host: EconomicLimitsV1): void {
  shape(job); fixed(signature, 64); fields(policy, policyFields);
  ensure(Number.isSafeInteger(host.maxWorkBytes) && host.maxWorkBytes >= 0
    && Number.isSafeInteger(host.maxMeterBytes) && host.maxMeterBytes >= 0, "invalid host byte bounds");
  u64(host.maxIterations);
  for (const k of policyFields) {
    if (k === "operatorKey" || k === "journalNamespace" || k === "target") {
      fixed(policy[k], 32); ensure(equal(job[k], policy[k]), "miner trusted epoch policy mismatch");
    } else ensure(job[k] === policy[k], "miner trusted epoch policy mismatch");
  }
  ensure(job.iterationCount <= host.maxIterations && job.maxWorkBytes <= BigInt(host.maxWorkBytes)
    && job.maxMeterBytes <= BigInt(host.maxMeterBytes), "miner host limits exceeded");
  ensure(schnorr.verify(signature, minerJobSigningDigestV1(job), policy.operatorKey), "invalid miner job signature");
}

/** New-admission window only; an admitted retry must not be expired. */
export function validateMinerWindowV1(job: MinerJobV1, now: bigint, maxDuration: bigint): void {
  shape(job); u64(now); u64(maxDuration);
  ensure(now >= job.openedAt && now < job.expiresAt && job.expiresAt - job.openedAt <= maxDuration, "miner job outside admission window");
}
export function validateMinerHeadV1(job: MinerJobV1, current: EconomicHeadV2): void {
  shape(job); validateEconomicHeadV2(current);
  ensure(BigInt(current.head_sequence_number) === job.priorHeadSequence && job.priorHeadSequence < u64Max
    && current.current_head_hash_hex === hex(job.priorHeadHash), "miner predecessor mismatch or overflow");
}
export function minerIntentCommitmentV1(job: MinerJobV1, meter: EconomicMeterV1): Uint8Array {
  const m = encodeEconomicMeterV1(meter);
  return hash(Buffer.from("AURA_MINER_INTENT_V1"), minerJobCommitmentV1(job), encodeStepU64Le(BigInt(m.length)), m);
}
function context(job: MinerJobV1, meter: EconomicMeterV1, nonce: Uint8Array): Uint8Array {
  fixed(nonce, 32);
  return encodeStormContextV1({contextVersion: STORM_CONTEXT_V1_VERSION, networkId: job.journalNamespace,
    intentHash: minerIntentCommitmentV1(job, meter), freshnessNonce: nonce, validFrom: 0n, validUntil: 0n,
    controllerId: meter.ledger.payerAccountId, routeTag: minerRouteTagV1()});
}
/** Use freshNonceV2 for production nonces. No method can infer RNG quality from supplied bytes. */
export function buildMinerWorkV1(job: MinerJobV1, meter: EconomicMeterV1, nonce: Uint8Array): EconomicWorkV1 {
  const work = {meter, storm: {sideA: Uint8Array.from(job.sideA), sideB: Uint8Array.from(job.sideB),
    contextBytesV1: context(job, meter, nonce), iterationCount: job.iterationCount}};
  validateMinerWorkProfileV1(job, work);
  return work;
}
/** Structural binding only. Local execution/proof validation remain chargeable service work. */
export function validateMinerWorkProfileV1(job: MinerJobV1, work: EconomicWorkV1): void {
  shape(job);
  const w = encodeEconomicWorkV1(work), m = encodeEconomicMeterV1(work.meter), s = work.storm;
  ensure(BigInt(w.length) <= job.maxWorkBytes && BigInt(m.length) <= job.maxMeterBytes
    && equal(s.sideA, job.sideA) && equal(s.sideB, job.sideB) && s.iterationCount === job.iterationCount
    && equal(s.contextBytesV1, context(job, work.meter, s.contextBytesV1.slice(97, 129)))
    && work.meter.head.settlementHeadVersion === 2
    && equal(work.meter.head.previousHeadHash, job.priorHeadHash)
    && job.priorHeadSequence < u64Max && work.meter.head.headSequenceNumber === job.priorHeadSequence + 1n,
    "miner work does not match job profile");
}
/** Existing claim tuple/fixed-slot profile only. Does not validate states, root, witness or PoC. */
export function validateMinerClaimProfileV1(job: MinerJobV1, work: EconomicWorkV1, claim: StormClaim521V1, verificationKey: Uint8Array): void {
  validateMinerWorkProfileV1(job, work); fixed(verificationKey, 0);
  ensure(claim.version === STORM_CLAIM_521_V1_VERSION && claim.modulusId === STORM_MODULUS_ID_521_V1
    && claim.iterationCount === job.iterationCount && claim.sideAHex === hex(work.storm.sideA)
    && claim.sideBHex === hex(work.storm.sideB) && claim.contextBytesHex === hex(work.storm.contextBytesV1)
    && claim.legacyCommitmentRootHex === "00".repeat(32) && claim.legacyTraceCommitmentHex === "00".repeat(32),
    "unsupported miner claim profile or verification key");
}
/** Unverified low-hash filter, never valid PoW by itself. Raw 32-byte big-endian comparison. */
export function passesMinerHashFilterV1(job: MinerJobV1, proofHash: Uint8Array): boolean {
  shape(job); fixed(proofHash, 32);
  return Buffer.compare(proofHash, job.target) <= 0;
}
