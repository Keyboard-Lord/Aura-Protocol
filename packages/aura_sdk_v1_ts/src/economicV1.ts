import { createHash } from "node:crypto";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bitcoinNetworkTagV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import type { BitcoinNetworkV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import { decodeEconomicMeterV1, encodeEconomicMeterV1, computeEconomicMeterBurnV1,
  debitEconomicLedgerV1, economicLedgerCommitmentV1 } from "../../aura_sdk_v0_ts/src/index.ts";
import type { EconomicMeterV1, CanonicalPipelineLedgerPolicyV0 } from "../../aura_sdk_v0_ts/src/index.ts";
import { validateAuthorizationShapeV2, verifyAuthorizationSignatureV2 } from "./authorizationV2.ts";
import type { AuthorizationEnvelopeV2 } from "./authorizationV2.ts";
import { validateStormContextBytesV1 } from "./stormContextV1.ts";
import { encodeStepU64Le } from "./stormExecutionV1.ts";
import type { StormExecutionInputsV1 } from "./stormExecutionV1.ts";

export type EconomicWorkV1 = { meter: EconomicMeterV1; storm: StormExecutionInputsV1 };
export type EconomicLimitsV1 = { maxWorkBytes: number; maxMeterBytes: number; maxIterations: bigint };
export type EconomicConsentV1 = { economic_consent_version: "v1"; signature_hex: string };
const domain = Buffer.from("AURA_ECONOMIC_WORK_REQUEST_V1");
const zero = "00".repeat(32);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const hash = (...b: Uint8Array[]) => { const h = createHash("sha256"); for (const x of b) h.update(x); return h.digest(); };
function ensure(ok: boolean, message: string): asserts ok { if (!ok) throw new TypeError(message); }
function fixedHex(value: unknown, n: number): string {
  ensure(typeof value === "string" && value.length === n * 2 && /^[0-9a-f]+$/.test(value), "noncanonical economic hex");
  return value;
}
function fields(value: unknown, keys: string[]): Record<string, any> {
  ensure(typeof value === "object" && value !== null && !Array.isArray(value)
    && Reflect.ownKeys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), "noncanonical economic fields");
  return value as Record<string, any>;
}
const equal = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));

export function encodeEconomicWorkV1(work: EconomicWorkV1): Uint8Array {
  fields(work, ["meter", "storm"]);
  const s = work.storm;
  fields(s, ["sideA", "sideB", "contextBytesV1", "iterationCount"]);
  ensure(s.sideA instanceof Uint8Array && s.sideA.length === 110 && s.sideB instanceof Uint8Array && s.sideB.length === 110, "invalid Storm side input");
  validateStormContextBytesV1(s.contextBytesV1);
  const subject = s.contextBytesV1.slice(145, 177);
  secp256k1.Point.fromHex(`02${hex(subject)}`);
  ensure(equal(subject, work.meter.ledger.payerAccountId), "economic payer and controller mismatch");
  // Rust also requires iteration_count + 1 to fit its 64-bit host usize.
  ensure(typeof s.iterationCount === "bigint" && s.iterationCount < 0xffffffffffffffffn, "Storm iteration overflow");
  const m = encodeEconomicMeterV1(work.meter);
  return Buffer.concat([domain, encodeStepU64Le(BigInt(m.length)), m, s.sideA, s.sideB, s.contextBytesV1, encodeStepU64Le(s.iterationCount)]);
}

export function decodeEconomicWorkV1(bytes: Uint8Array, limits: EconomicLimitsV1): EconomicWorkV1 {
  ensure(bytes instanceof Uint8Array && Number.isSafeInteger(limits.maxWorkBytes) && limits.maxWorkBytes >= 0
    && Number.isSafeInteger(limits.maxMeterBytes) && limits.maxMeterBytes >= 0
    && typeof limits.maxIterations === "bigint" && limits.maxIterations >= 0n,
    "invalid economic bounds");
  ensure(bytes.length <= limits.maxWorkBytes && equal(bytes.slice(0, domain.length), domain) && bytes.length >= domain.length + 8, "invalid work domain or limit");
  const b = Buffer.from(bytes), prefix = domain.length + 8, len = b.readBigUInt64LE(domain.length);
  ensure(len <= BigInt(limits.maxMeterBytes) && BigInt(prefix) + len + 437n === BigInt(b.length), "invalid economic work framing");
  const end = prefix + Number(len), t = b.subarray(end);
  const work: EconomicWorkV1 = { meter: decodeEconomicMeterV1(Uint8Array.from(b.subarray(prefix, end)), limits.maxMeterBytes), storm: {
    sideA: Uint8Array.from(t.subarray(0, 110)), sideB: Uint8Array.from(t.subarray(110, 220)),
    contextBytesV1: Uint8Array.from(t.subarray(220, 429)), iterationCount: t.readBigUInt64LE(429),
  } };
  ensure(work.storm.iterationCount <= limits.maxIterations, "economic iteration limit exceeded");
  ensure(equal(encodeEconomicWorkV1(work), bytes), "noncanonical economic work");
  return work;
}

export function validateEconomicConsentV1(value: unknown): EconomicConsentV1 {
  const c = fields(value, ["economic_consent_version", "signature_hex"]);
  ensure(c.economic_consent_version === "v1", "unsupported economic consent version");
  return { economic_consent_version: "v1", signature_hex: fixedHex(c.signature_hex, 64) };
}

export function economicConsentSigningDigestV1(network: BitcoinNetworkV1, work: EconomicWorkV1, value: AuthorizationEnvelopeV2): Uint8Array {
  const auth = validateAuthorizationShapeV2(value), l = auth.authorization_lineage, ctx = work.storm.contextBytesV1;
  ensure(l.subject_binding === hex(ctx.slice(145, 177)) && l.freshness_binding === hex(ctx.slice(97, 129))
    && l.intent_commitment_hex === hex(ctx.slice(65, 97)), "economic work and authorization lineage mismatch");
  const w = encodeEconomicWorkV1(work), tag = hash(Buffer.from("AURA_ECONOMIC_CONSENT_V1"));
  return hash(tag, tag, Uint8Array.of(bitcoinNetworkTagV1(network)), encodeStepU64Le(computeEconomicMeterBurnV1(work.meter)), w, Buffer.from(auth.proof_hash_hex, "hex"));
}

export function signEconomicConsentV1(network: BitcoinNetworkV1, work: EconomicWorkV1, auth: AuthorizationEnvelopeV2, secretKey: Uint8Array): EconomicConsentV1 {
  ensure(equal(schnorr.getPublicKey(secretKey), work.storm.contextBytesV1.slice(145, 177)), "economic signer mismatch");
  return { economic_consent_version: "v1", signature_hex: hex(schnorr.sign(economicConsentSigningDigestV1(network, work, auth), secretKey)) };
}

/** Pre-admission only. Rust owns actual proof verification, debit and durable finalization. */
export function verifyEconomicAdmissionSignaturesV1(value: unknown, network: BitcoinNetworkV1, work: EconomicWorkV1, auth: AuthorizationEnvelopeV2): EconomicConsentV1 {
  const consent = validateEconomicConsentV1(value);
  ensure(schnorr.verify(Buffer.from(consent.signature_hex, "hex"), economicConsentSigningDigestV1(network, work, auth), work.storm.contextBytesV1.slice(145, 177)), "invalid economic consent signature");
  verifyAuthorizationSignatureV2(auth, network);
  return consent;
}

export type EconomicOutcomeV1 = "Accepted" | "ExecutionRejected" | "VerificationRejected" | "SettlementRejected";
export type EconomicHeadV2 = { settlement_head_version: 2; head_sequence_number: string;
  previous_head_hash_hex: string; canonical_head_commitment_hex: string; current_head_hash_hex: string };
export function economicGenesisHeadV2(): EconomicHeadV2 {
  return { settlement_head_version: 2, head_sequence_number: "0", previous_head_hash_hex: zero, canonical_head_commitment_hex: zero, current_head_hash_hex: zero };
}
const headHash = (sequence: bigint, commitment: string) => hex(hash(Buffer.from("AURA_ECONOMIC_HEAD_V1"), Uint8Array.of(2, 0, 0, 0), encodeStepU64Le(sequence), Buffer.from(commitment, "hex")));
export function validateEconomicHeadV2(value: unknown): EconomicHeadV2 {
  const h = fields(value, ["settlement_head_version", "head_sequence_number", "previous_head_hash_hex", "canonical_head_commitment_hex", "current_head_hash_hex"]);
  ensure(h.settlement_head_version === 2 && typeof h.head_sequence_number === "string" && /^(0|[1-9][0-9]*)$/.test(h.head_sequence_number), "noncanonical economic head version or sequence");
  const n = BigInt(h.head_sequence_number); encodeStepU64Le(n);
  for (const k of ["previous_head_hash_hex", "canonical_head_commitment_hex", "current_head_hash_hex"]) fixedHex(h[k], 32);
  if (n === 0n) ensure(h.previous_head_hash_hex === zero && h.canonical_head_commitment_hex === zero && h.current_head_hash_hex === zero, "invalid economic genesis");
  else ensure(headHash(n, h.canonical_head_commitment_hex) === h.current_head_hash_hex, "economic head hash mismatch");
  return { ...h } as EconomicHeadV2;
}

export function advanceEconomicHeadV2(prior: EconomicHeadV2, network: BitcoinNetworkV1, work: EconomicWorkV1,
  outcome: EconomicOutcomeV1, postDebit: CanonicalPipelineLedgerPolicyV0): EconomicHeadV2 {
  prior = validateEconomicHeadV2(prior);
  const n = BigInt(prior.head_sequence_number) + 1n; encodeStepU64Le(n);
  const linkage = work.meter.head;
  ensure(linkage.settlementHeadVersion === 2 && linkage.headSequenceNumber === n && hex(linkage.previousHeadHash) === prior.current_head_hash_hex, "metered head linkage mismatch");
  const w = encodeEconomicWorkV1(work), burn = computeEconomicMeterBurnV1(work.meter);
  const expected = debitEconomicLedgerV1(work.meter.ledger, burn);
  ensure(equal(economicLedgerCommitmentV1(expected), economicLedgerCommitmentV1(postDebit)), "economic post-debit ledger mismatch");
  const outcomeByte = ["Accepted", "ExecutionRejected", "VerificationRejected", "SettlementRejected"].indexOf(outcome);
  ensure(outcomeByte >= 0, "invalid economic outcome");
  const c = hex(hash(Buffer.from("AURA_ECONOMIC_HEAD_COMMITMENT_V1"), Uint8Array.of(2, 0, 0, 0),
    Uint8Array.of(bitcoinNetworkTagV1(network)), Buffer.from(prior.current_head_hash_hex, "hex"), encodeStepU64Le(n),
    encodeStepU64Le(BigInt(w.length)), w, Uint8Array.of(outcomeByte),
    economicLedgerCommitmentV1(work.meter.ledger), economicLedgerCommitmentV1(postDebit), encodeStepU64Le(burn)));
  return { settlement_head_version: 2, head_sequence_number: n.toString(), previous_head_hash_hex: prior.current_head_hash_hex,
    canonical_head_commitment_hex: c, current_head_hash_hex: headHash(n, c) };
}
