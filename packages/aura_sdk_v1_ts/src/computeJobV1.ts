// C1 request codec/profile only. No funded admission, verdict or state mutation.
import { createHash } from "node:crypto";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bitcoinNetworkTagV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import type { BitcoinNetworkV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import { encodeMinerJobV1 } from "./minerV1.ts";
import type { MinerJobV1 } from "./minerV1.ts";

export const COMPUTE_JOB_V1_BYTE_LEN = 546;
const domain = Buffer.from("AURA_COMPUTE_JOB_V1", "ascii");
const u64Max = (1n << 64n) - 1n;
export type AuraComputeJobV1 = {
  jobVersion: number;
  network: BitcoinNetworkV1;
  coordinatorKey: Uint8Array;
  journalNamespace: Uint8Array;
  requesterKey: Uint8Array;
  jobNonce: Uint8Array;
  workloadClass: number;
  adapterContractCommitment: Uint8Array;
  inputCommitment: Uint8Array;
  programCommitment: Uint8Array;
  executionSpecCommitment: Uint8Array;
  outputSpecCommitment: Uint8Array;
  verificationClass: number;
  verificationSpecCommitment: Uint8Array;
  privacyClass: number;
  privacyPolicyCommitment: Uint8Array;
  hardwareRequirementsCommitment: Uint8Array;
  maxInputBytes: bigint;
  maxOutputBytes: bigint;
  maxEvidenceBytes: bigint;
  maxMemoryBytes: bigint;
  maxScratchBytes: bigint;
  maxExecutionMs: bigint;
  acceptUntil: bigint;
  completeBy: bigint;
  compensationSatoshis: bigint;
  paymentTermsCommitment: Uint8Array;
  dataRightsCommitment: Uint8Array;
  miningMode: number;
};
const jobFields = ["jobVersion", "network", "coordinatorKey", "journalNamespace", "requesterKey", "jobNonce", "workloadClass", "adapterContractCommitment", "inputCommitment", "programCommitment", "executionSpecCommitment", "outputSpecCommitment", "verificationClass", "verificationSpecCommitment", "privacyClass", "privacyPolicyCommitment", "hardwareRequirementsCommitment", "maxInputBytes", "maxOutputBytes", "maxEvidenceBytes", "maxMemoryBytes", "maxScratchBytes", "maxExecutionMs", "acceptUntil", "completeBy", "compensationSatoshis", "paymentTermsCommitment", "dataRightsCommitment", "miningMode"] as const;
const byteFields = ["coordinatorKey", "journalNamespace", "requesterKey", "jobNonce", "adapterContractCommitment", "inputCommitment", "programCommitment", "executionSpecCommitment", "outputSpecCommitment", "verificationSpecCommitment", "privacyPolicyCommitment", "hardwareRequirementsCommitment", "paymentTermsCommitment", "dataRightsCommitment"] as const;
const integerFields = ["maxInputBytes", "maxOutputBytes", "maxEvidenceBytes", "maxMemoryBytes", "maxScratchBytes", "maxExecutionMs", "acceptUntil", "completeBy", "compensationSatoshis"] as const;
const limitFields = ["maxInputBytes", "maxOutputBytes", "maxEvidenceBytes", "maxMemoryBytes", "maxScratchBytes", "maxExecutionMs"] as const;
export type ComputeCoordinatorV1 = Pick<AuraComputeJobV1, "network" | "coordinatorKey" | "journalNamespace">;
export type ComputeJobLimitsV1 = Pick<AuraComputeJobV1, typeof limitFields[number]>;
export type ComputeRetryV1 = "distinct_scope" | "idempotent" | "conflict";
export const COMPUTE_CONTENT_KINDS_V1 = ["ADAPTER_CONTRACT", "INPUT", "PROGRAM", "EXECUTION_SPEC", "OUTPUT_SPEC", "VERIFICATION_SPEC", "PRIVACY_POLICY", "HARDWARE_REQUIREMENTS", "PAYMENT_TERMS", "DATA_RIGHTS"] as const;
export type ComputeContentKindV1 = typeof COMPUTE_CONTENT_KINDS_V1[number];
const contentFields = {
  ADAPTER_CONTRACT: "adapterContractCommitment",
  INPUT: "inputCommitment",
  PROGRAM: "programCommitment",
  EXECUTION_SPEC: "executionSpecCommitment",
  OUTPUT_SPEC: "outputSpecCommitment",
  VERIFICATION_SPEC: "verificationSpecCommitment",
  PRIVACY_POLICY: "privacyPolicyCommitment",
  HARDWARE_REQUIREMENTS: "hardwareRequirementsCommitment",
  PAYMENT_TERMS: "paymentTermsCommitment",
  DATA_RIGHTS: "dataRightsCommitment",
} as const;
const sha = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest();
};
const equal = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
function ensure(value: boolean, message: string): asserts value { if (!value) throw new TypeError(message); }
function bytes(v: unknown, n?: number): asserts v is Uint8Array {
  ensure(v instanceof Uint8Array && (n === undefined || v.length === n), "invalid compute bytes");
}
function fields(v: unknown, keys: readonly string[]): void {
  ensure(typeof v === "object" && v !== null && !Array.isArray(v)
    && Reflect.ownKeys(v).length === keys.length && keys.every(k => {
      const descriptor=Object.getOwnPropertyDescriptor(v,k);
      return descriptor !== undefined && Object.hasOwn(descriptor,"value");
    }), "noncanonical compute fields");
}
function u64(v: unknown): asserts v is bigint {
  ensure(typeof v === "bigint" && v >= 0n && v <= u64Max, "invalid compute u64");
}
function le(v: bigint): Uint8Array { u64(v); const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b; }
function tag(v: unknown, maximum: number): asserts v is number {
  ensure(typeof v === "number" && Number.isInteger(v) && !Object.is(v, -0) && v >= 0 && v <= maximum, "unsupported compute tag");
}
function shape(j: AuraComputeJobV1): void {
  fields(j, jobFields); ensure(j.jobVersion === 1, "unsupported compute version");
  bitcoinNetworkTagV1(j.network);
  tag(j.workloadClass, 10); tag(j.verificationClass, 7); tag(j.privacyClass, 4); tag(j.miningMode, 1);
  for (const k of byteFields) bytes(j[k], 32);
  for (const k of integerFields) u64(j[k]);
  for (const k of [j.coordinatorKey, j.requesterKey]) secp256k1.Point.fromHex(`02${Buffer.from(k).toString("hex")}`);
  ensure(j.maxOutputBytes > 0n && j.maxEvidenceBytes > 0n && j.maxMemoryBytes > 0n && j.maxExecutionMs > 0n
    && j.acceptUntil > 0n && j.acceptUntil < j.completeBy && j.compensationSatoshis > 0n, "invalid compute limits/deadline/compensation");
}
/** The object is an API value, never an alternate JSON wire. */
export function encodeComputeJobV1(j: AuraComputeJobV1): Uint8Array {
  shape(j); const workload = Buffer.alloc(2); workload.writeUInt16LE(j.workloadClass);
  return Buffer.concat([domain,
    Uint8Array.of(j.jobVersion),
    Uint8Array.of(bitcoinNetworkTagV1(j.network)),
    j.coordinatorKey,
    j.journalNamespace,
    j.requesterKey,
    j.jobNonce,
    workload,
    j.adapterContractCommitment,
    j.inputCommitment,
    j.programCommitment,
    j.executionSpecCommitment,
    j.outputSpecCommitment,
    Uint8Array.of(j.verificationClass),
    j.verificationSpecCommitment,
    Uint8Array.of(j.privacyClass),
    j.privacyPolicyCommitment,
    j.hardwareRequirementsCommitment,
    le(j.maxInputBytes),
    le(j.maxOutputBytes),
    le(j.maxEvidenceBytes),
    le(j.maxMemoryBytes),
    le(j.maxScratchBytes),
    le(j.maxExecutionMs),
    le(j.acceptUntil),
    le(j.completeBy),
    le(j.compensationSatoshis),
    j.paymentTermsCommitment,
    j.dataRightsCommitment,
    Uint8Array.of(j.miningMode),
  ]);
}
export function decodeComputeJobV1(value: Uint8Array): AuraComputeJobV1 {
  bytes(value, COMPUTE_JOB_V1_BYTE_LEN);
  const b = Buffer.from(value); ensure(equal(b.subarray(0, domain.length), domain), "invalid compute domain");
  let p = domain.length;
  const take = (n: number): Uint8Array => { const r = Uint8Array.from(b.subarray(p, p + n)); p += n; return r; };
  const integer = (): bigint => { const r = b.readBigUInt64LE(p); p += 8; return r; };
  const network = (): BitcoinNetworkV1 => {
    const t = take(1)[0];
    const n = (["mainnet", "testnet3", "signet", "regtest", "testnet4"] as const).find(n => bitcoinNetworkTagV1(n) === t);
    ensure(n !== undefined, "unknown compute network"); return n;
  };
  const short = () => { const r = b.readUInt16LE(p); p += 2; return r; };
  const j: AuraComputeJobV1 = {
    jobVersion: take(1)[0]!,
    network: network(),
    coordinatorKey: take(32),
    journalNamespace: take(32),
    requesterKey: take(32),
    jobNonce: take(32),
    workloadClass: short(),
    adapterContractCommitment: take(32),
    inputCommitment: take(32),
    programCommitment: take(32),
    executionSpecCommitment: take(32),
    outputSpecCommitment: take(32),
    verificationClass: take(1)[0]!,
    verificationSpecCommitment: take(32),
    privacyClass: take(1)[0]!,
    privacyPolicyCommitment: take(32),
    hardwareRequirementsCommitment: take(32),
    maxInputBytes: integer(),
    maxOutputBytes: integer(),
    maxEvidenceBytes: integer(),
    maxMemoryBytes: integer(),
    maxScratchBytes: integer(),
    maxExecutionMs: integer(),
    acceptUntil: integer(),
    completeBy: integer(),
    compensationSatoshis: integer(),
    paymentTermsCommitment: take(32),
    dataRightsCommitment: take(32),
    miningMode: take(1)[0]!,
  };
  ensure(p === b.length && equal(encodeComputeJobV1(j), value), "noncanonical compute job"); return j;
}
export function computeJobCommitmentV1(j: AuraComputeJobV1): Uint8Array { return sha(encodeComputeJobV1(j)); }
export function computeJobSigningDigestV1(j: AuraComputeJobV1): Uint8Array {
  const t = sha(Buffer.from("AURA_COMPUTE_JOB_SIGNATURE_V1", "ascii")); return sha(t, t, encodeComputeJobV1(j));
}
/** Noble obtains fresh signing randomness; not the public job nonce. */
export function signComputeRequestV1(j: AuraComputeJobV1, key: Uint8Array): Uint8Array {
  const d = computeJobSigningDigestV1(j); bytes(key, 32);
  ensure(equal(schnorr.getPublicKey(key), j.requesterKey), "compute requester mismatch"); return schnorr.sign(d, key);
}
export function verifyComputeRequestV1(j: AuraComputeJobV1, signature: Uint8Array): void {
  bytes(signature, 64); ensure(schnorr.verify(signature, computeJobSigningDigestV1(j), j.requesterKey), "invalid compute request signature");
}
export function verifyComputeCoordinatorV1(j: AuraComputeJobV1, signature: Uint8Array, trusted: ComputeCoordinatorV1): void {
  fields(trusted, ["network", "coordinatorKey", "journalNamespace"]);
  bytes(trusted.coordinatorKey, 32); bytes(trusted.journalNamespace, 32);
  ensure(j.network === trusted.network && equal(j.coordinatorKey, trusted.coordinatorKey)
    && equal(j.journalNamespace, trusted.journalNamespace), "compute coordinator scope mismatch");
  verifyComputeRequestV1(j, signature);
}
/** Pure comparison, existing must be an authenticated stored request. No journal. */
export function classifyComputeRetryV1(existing: AuraComputeJobV1, incoming: AuraComputeJobV1, signature: Uint8Array): ComputeRetryV1 {
  shape(existing); verifyComputeRequestV1(incoming, signature);
  if (existing.network !== incoming.network || !["coordinatorKey", "journalNamespace", "requesterKey", "jobNonce"].every(k =>
    equal(existing[k as "coordinatorKey"], incoming[k as "coordinatorKey"]))) return "distinct_scope";
  return equal(encodeComputeJobV1(existing), encodeComputeJobV1(incoming)) ? "idempotent" : "conflict";
}
/** Assignment preflight only, not funding, support or resource enforcement. */
export function validateComputeAssignmentV1(j: AuraComputeJobV1, now: bigint, deliveryBudgetMs: bigint, host: ComputeJobLimitsV1): void {
  shape(j); u64(now); u64(deliveryBudgetMs); fields(host, limitFields);
  ensure(now < j.acceptUntil, "compute assignment deadline elapsed");
  for (const k of limitFields) { u64(host[k]); ensure(j[k] <= host[k], "compute host limit exceeded"); }
  ensure(j.maxExecutionMs + deliveryBudgetMs < (j.completeBy - now) * 1000n, "insufficient compute completion window");
}
export function computeContentCommitmentV1(kind: ComputeContentKindV1, payload: Uint8Array): Uint8Array {
  ensure(COMPUTE_CONTENT_KINDS_V1.includes(kind), "unsupported compute content kind"); bytes(payload);
  return sha(Buffer.from(`AURA_COMPUTE_${kind}_V1`, "ascii"), le(BigInt(payload.length)), payload);
}
export type ComputeFixedCorePolicyKindV1 = "PRIVACY_POLICY" | "HARDWARE_REQUIREMENTS" | "DATA_RIGHTS";
/** Each kind retains its existing independent content-commitment domain. */
export function computeFixedCorePolicyPayloadV1(kind: ComputeFixedCorePolicyKindV1): Uint8Array {
  ensure(kind === "PRIVACY_POLICY" || kind === "HARDWARE_REQUIREMENTS" || kind === "DATA_RIGHTS", "not a fixed compute core policy kind");
  return Uint8Array.of(1);
}
export function validateComputeFixedCorePolicyV1(kind: ComputeFixedCorePolicyKindV1, payload: Uint8Array): void {
  bytes(payload, 1);
  ensure(equal(payload, computeFixedCorePolicyPayloadV1(kind)), "unsupported compute core policy");
}
export const COMPUTE_PAYMENT_TERMS_V1_BYTE_LEN = 17;
export type ComputePaymentTermsV1 = { maxPaymentFeeSatoshis: bigint; resultAvailabilitySeconds: bigint };
export function encodeComputePaymentTermsV1(terms: ComputePaymentTermsV1): Uint8Array {
  fields(terms, ["maxPaymentFeeSatoshis", "resultAvailabilitySeconds"]);
  u64(terms.maxPaymentFeeSatoshis); u64(terms.resultAvailabilitySeconds);
  ensure(terms.resultAvailabilitySeconds > 0n, "compute result availability must be positive");
  return Buffer.concat([Uint8Array.of(1), le(terms.maxPaymentFeeSatoshis), le(terms.resultAvailabilitySeconds)]);
}
export function decodeComputePaymentTermsV1(payload: Uint8Array): ComputePaymentTermsV1 {
  bytes(payload, COMPUTE_PAYMENT_TERMS_V1_BYTE_LEN);
  ensure(payload[0] === 1, "unsupported compute payment profile");
  const b = Buffer.from(payload);
  const terms = { maxPaymentFeeSatoshis: b.readBigUInt64LE(1), resultAvailabilitySeconds: b.readBigUInt64LE(9) };
  ensure(equal(encodeComputePaymentTermsV1(terms), payload), "noncanonical compute payment terms");
  return terms;
}
export function computePaymentTermsCommitmentV1(terms: ComputePaymentTermsV1): Uint8Array {
  return computeContentCommitmentV1("PAYMENT_TERMS", encodeComputePaymentTermsV1(terms));
}
/** Zero permits exactly zero; fee validation never changes worker net pay. */
export function validateComputePublicationFeeV1(terms: ComputePaymentTermsV1, feeSatoshis: bigint): void {
  encodeComputePaymentTermsV1(terms); u64(feeSatoshis);
  ensure(feeSatoshis <= terms.maxPaymentFeeSatoshis, "compute payment fee exceeds signed ceiling");
}
export function verifyComputeContentV1(j: AuraComputeJobV1, kind: ComputeContentKindV1, payload: Uint8Array): void {
  shape(j); bytes(payload);
  const digest = computeContentCommitmentV1(kind, payload);
  if (kind === "INPUT") ensure(BigInt(payload.length) <= j.maxInputBytes, "compute input too large");
  ensure(equal(digest, j[contentFields[kind]]), "compute content commitment mismatch");
}
/** Approved core schemas/bindings only, not actual isolation, hardware or admission. */
export function verifyComputeCorePoliciesV1(j: AuraComputeJobV1, privacy: Uint8Array, hardware: Uint8Array, rights: Uint8Array, payment: Uint8Array): ComputePaymentTermsV1 {
  shape(j); ensure(j.privacyClass <= 1, "unsupported compute privacy class for profile 01");
  for (const [kind, payload] of [["PRIVACY_POLICY", privacy], ["HARDWARE_REQUIREMENTS", hardware], ["DATA_RIGHTS", rights]] as const) {
    validateComputeFixedCorePolicyV1(kind, payload); verifyComputeContentV1(j, kind, payload);
  }
  const terms = decodeComputePaymentTermsV1(payment);
  verifyComputeContentV1(j, "PAYMENT_TERMS", payment);
  return terms;
}
/** Result association only; cannot manufacture C2's verified result record. */
export function validateComputeMinerBindingV1(j: AuraComputeJobV1, miner: MinerJobV1, result: Uint8Array): void {
  shape(j); encodeMinerJobV1(miner);
  ensure(j.miningMode === 1, "compute mining mode disabled");
  ensure(equal(miner.sideA, computeMinerSideV1(result, 0)) && equal(miner.sideB, computeMinerSideV1(result, 1)), "compute result is not bound by signed miner inputs");
}
export function computeMinerSideV1(result: Uint8Array, lane: number): Uint8Array {
  bytes(result, 32); tag(lane, 1);
  const parts = [];
  for (let i = 0; i < 4; i++) {
    const counter = Buffer.alloc(4); counter.writeUInt32LE(i);
    parts.push(sha(Buffer.from("AURA_COMPUTE_MINER_SIDE_V1", "ascii"), Uint8Array.of(lane), result, counter));
  }
  return Uint8Array.from(Buffer.concat(parts).subarray(0, 110));
}
