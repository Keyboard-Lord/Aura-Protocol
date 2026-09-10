import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1.js";
import { decodeEconomicWorkV1, encodeEconomicWorkV1, economicConsentSigningDigestV1,
  verifyEconomicAdmissionSignaturesV1, validateEconomicConsentV1, economicGenesisHeadV2,
  advanceEconomicHeadV2, validateEconomicHeadV2, signEconomicConsentV1 } from "./economicV1.ts";
import { computeEconomicMeterBurnV1, debitEconomicLedgerV1, economicLedgerCommitmentV1, encodeEconomicMeterV1 } from "../../aura_sdk_v0_ts/src/index.ts";
import { signAuthorizationV2 } from "./authorizationV2.ts";
import { encodeStepU64Le } from "./stormExecutionV1.ts";

const v = JSON.parse(readFileSync(new URL("../../../fixtures/economic_admission_v1/contract_vector.json", import.meta.url), "utf8"));
const limits = { maxWorkBytes: 100_000, maxMeterBytes: 90_000, maxIterations: 100n };
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const sample = () => decodeEconomicWorkV1(bytes(v.work_hex), limits);

test("economic: frozen Rust/TS W, charge, consent signature, ledger and all outcome heads", () => {
  const w = sample(), genesis = economicGenesisHeadV2();
  assert.equal(hex(encodeEconomicWorkV1(w)), v.work_hex);
  assert.equal(hex(encodeEconomicMeterV1(w.meter)), v.meter_hex);
  assert.equal(computeEconomicMeterBurnV1(w.meter).toString(), v.burn_units);
  const digest = economicConsentSigningDigestV1("regtest", w, v.authorization);
  assert.equal(hex(digest), v.signing_digest_hex);
  assert.equal(hex(schnorr.sign(digest, bytes(v.secret_key_hex), new Uint8Array(32))), v.consent.signature_hex);
  assert.deepEqual(verifyEconomicAdmissionSignaturesV1(v.consent, "regtest", w, v.authorization), v.consent);
  const post = debitEconomicLedgerV1(w.meter.ledger, BigInt(v.burn_units));
  assert.equal(hex(economicLedgerCommitmentV1(w.meter.ledger)), v.pre_ledger_commitment_hex);
  assert.equal(hex(economicLedgerCommitmentV1(post)), v.post_ledger_commitment_hex);
  assert.deepEqual(genesis, v.genesis);
  for (const { outcome, head } of v.heads) {
    assert.deepEqual(advanceEconomicHeadV2(genesis, "regtest", w, outcome, post), head);
    assert.deepEqual(validateEconomicHeadV2(head), head);
  }
});

test("economic: every signed work byte, target, lineage and network is bound", () => {
  const original = bytes(v.work_hex), w = sample();
  for (let i = 0; i < original.length; i++) {
    const b = original.slice(); b[i] ^= 1;
    assert.throws(() => verifyEconomicAdmissionSignaturesV1(v.consent, "regtest", decodeEconomicWorkV1(b, limits), v.authorization), `byte ${i}`);
  }
  assert.throws(() => verifyEconomicAdmissionSignaturesV1(v.consent, "mainnet", w, v.authorization));
  assert.throws(() => verifyEconomicAdmissionSignaturesV1(v.consent, "regtest", w, { ...v.authorization, proof_hash_hex: "aa".repeat(32) }));
  for (const k of ["subject_binding", "intent_commitment_hex", "freshness_binding"]) {
    const a = structuredClone(v.authorization); a.authorization_lineage[k] = "01".repeat(32);
    assert.throws(() => verifyEconomicAdmissionSignaturesV1(v.consent, "regtest", w, a));
  }
});

test("economic: framing, lengths, limits and exact consent shape reject malformed input", () => {
  const b = bytes(v.work_hex);
  for (let n = 0; n < b.length; n++) assert.throws(() => decodeEconomicWorkV1(b.slice(0, n), limits));
  assert.throws(() => decodeEconomicWorkV1(Uint8Array.from([...b, 0]), limits));
  const overflow = b.slice(), start = Buffer.byteLength("AURA_ECONOMIC_WORK_REQUEST_V1");
  overflow.fill(255, start, start + 8); assert.throws(() => decodeEconomicWorkV1(overflow, limits));
  for (const bound of [{ ...limits, maxIterations: 2n }, { ...limits, maxMeterBytes: 10 }, { ...limits, maxWorkBytes: 10 }])
    assert.throws(() => decodeEconomicWorkV1(b, bound));
  for (const c of [null, {}, { ...v.consent, proof_hash_hex: "00".repeat(32) }, { ...v.consent, economic_consent_version: "v2" },
    { ...v.consent, signature_hex: v.consent.signature_hex.toUpperCase() }]) assert.throws(() => validateEconomicConsentV1(c));
});

test("economic: valid economic consent does not assert actual proof authorization", () => {
  const w = sample(), key = bytes(v.secret_key_hex), l = v.authorization.authorization_lineage;
  const auth = signAuthorizationV2("regtest", "ee".repeat(32), l.intent_commitment_hex, l.freshness_binding, key);
  const consent = signEconomicConsentV1("regtest", w, auth, key);
  assert.doesNotThrow(() => verifyEconomicAdmissionSignaturesV1(consent, "regtest", w, auth));
  auth.signature_hex = "00".repeat(64);
  assert.throws(() => verifyEconomicAdmissionSignaturesV1(consent, "regtest", w, auth));
});

test("economic: head and debit reject stale, malformed, overflowing and inconsistent state", () => {
  const w = sample(), post = debitEconomicLedgerV1(w.meter.ledger, BigInt(v.burn_units)), head = v.heads[0].head;
  assert.throws(() => advanceEconomicHeadV2(head, "regtest", w, "Accepted", post));
  assert.throws(() => advanceEconomicHeadV2(v.genesis, "regtest", w, "Accepted", w.meter.ledger));
  for (const n of ["", "00", "01", "+1", "-1", "1.0", "18446744073709551616", 1])
    assert.throws(() => validateEconomicHeadV2({ ...head, head_sequence_number: n }));
  assert.throws(() => validateEconomicHeadV2({ ...v.genesis, current_head_hash_hex: "11".repeat(32) }));
  assert.throws(() => validateEconomicHeadV2({ ...head, extra: true }));
  const max = { ...head, head_sequence_number: "18446744073709551615" };
  max.current_head_hash_hex = createHash("sha256").update("AURA_ECONOMIC_HEAD_V1").update(Uint8Array.of(2, 0, 0, 0))
    .update(encodeStepU64Le(0xffffffffffffffffn)).update(bytes(head.canonical_head_commitment_hex)).digest("hex");
  assert.doesNotThrow(() => validateEconomicHeadV2(max));
  assert.throws(() => advanceEconomicHeadV2(max, "regtest", w, "Accepted", post));
  assert.throws(() => debitEconomicLedgerV1(w.meter.ledger, 1_000_001n));
});
