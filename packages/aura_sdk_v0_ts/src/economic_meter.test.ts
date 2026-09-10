import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  decodeEconomicMeterV1, encodeEconomicMeterV1, computeEconomicMeterBurnV1,
  legacyCanonicalPipelineMeterBytesV1, loadCanonicalPipelineRequestV0,
  computeCanonicalPipelineBurnUnitsV0,
} from "./index.ts";

const directory = new URL("../../../fixtures/economic_admission_v1/", import.meta.url);
const vectors = JSON.parse(readFileSync(new URL("meter_vectors.json", directory), "utf8"));
const legacy = JSON.parse(readFileSync(new URL("legacy_meter_bytes.json", directory), "utf8"));
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const decode = (b: Uint8Array) => decodeEconomicMeterV1(b, b.length);
const sample = (name = "execution") => decode(bytes(vectors.find(v => v.name === name).meter_hex));

test("meter: Rust/TS frozen M and burn parity", () => {
  for (const v of vectors) {
    const b = bytes(v.meter_hex), m = decode(b);
    assert.equal(hex(encodeEconomicMeterV1(m)), v.meter_hex, v.name);
    assert.equal(computeEconomicMeterBurnV1(m).toString(), v.burn_units, v.name);
  }
});

test("meter: all captured legacy bytes and burn units remain identical", () => {
  for (const v of legacy) {
    const file = new URL(`../../../fixtures/l2_canonical_pipeline_v1/${v.fixture}`, import.meta.url);
    const request = loadCanonicalPipelineRequestV0(file.pathname);
    assert.equal(hex(legacyCanonicalPipelineMeterBytesV1(request)), v.meter_hex, v.fixture);
    assert.equal(computeCanonicalPipelineBurnUnitsV0(request).toString(), v.burn_units, v.fixture);
    assert.throws(() => decode(bytes(v.meter_hex)), v.fixture);
  }
});

test("meter: truncation, trailing bytes, malformed UTF-8 and oversized length fail closed", () => {
  for (const v of vectors) {
    const b = bytes(v.meter_hex);
    for (let i = 0; i < b.length; i++) assert.throws(() => decode(b.slice(0, i)), `${v.name}:${i}`);
    assert.throws(() => decodeEconomicMeterV1(b, b.length - 1));
    assert.throws(() => decode(Uint8Array.from([...b, 0])));
    const wrong = b.slice(); wrong[0] ^= 1; assert.throws(() => decode(wrong));
    const start = Buffer.byteLength("AURA_L2_CANONICAL_PIPELINE_BURN_METERING_V1") + 4;
    const overflow = b.slice(); overflow.fill(255, start, start + 8); assert.throws(() => decode(overflow));
    const utf8 = b.slice(); utf8[start + 8] = 255; assert.throws(() => decode(utf8));
  }
});

test("meter: encoder rejects malformed typed values without sorting, dropping or coercing", () => {
  const mutations = [
    m => m.pipelineSchemaVersion++, m => m.pipelineId += "x", m => m.proofSystem = "mock",
    m => m.economic.economicPolicyVersion++, m => m.accounting.accountingPolicyVersion++,
    m => m.head.settlementHeadVersion = 1, m => m.head.headSequenceNumber = 0n,
    m => m.ledger.accounts.reverse(), m => m.ledger.accounts.push(m.ledger.accounts[0]),
    m => m.ledger.payerAccountId.fill(255), m => m.ledger.burnedSupply = 0xffffffffffffffffn,
    m => m.ledger.accounts[0].balance = 0xffffffffffffffffn, m => m.ledger.totalSupply++,
    m => m.accounts.reverse(), m => m.accounts.push(m.accounts[0]),
    m => m.batch.transactions[0].txVersion++, m => m.walletBinding.walletAddress = "0",
    m => { m.tokenAnchor.enforceExternalMatch = true; m.tokenAnchor.expectedExternalBalance = null; }, m => m.batch.transactions = [],
    m => m.fixtureName = "not canonical", m => m.economic.declaredFeeUnits = 99n,
    m => m.accounts[0].balance = Number(m.accounts[0].balance), m => m.batch.batchNumber = -1n,
    m => m.walletBinding.walletAddress = "\ud800",
  ];
  for (const mutate of mutations) {
    const m = sample(); mutate(m); assert.throws(() => encodeEconomicMeterV1(m), mutate.toString());
  }
  const m = sample("attestation");
  m.attestation.tamperStarkProofBytes = null;
  assert.throws(() => encodeEconomicMeterV1(m));
});

test("meter: noncanonical flags and duplicate evidence are rejected", () => {
  const m = sample("attestation"), b = encodeEconomicMeterV1(m);
  const start = Buffer.from(b).indexOf(Buffer.from([1, 2, 0, 0, 0, 45, 0, 0, 0, 0, 0, 0, 0]));
  assert(start > 0);
  const bad = b.slice(); bad[start] = 2; assert.throws(() => decode(bad));
  const tailLength = 32 + 8 + m.accounts.length * 48 + 8 + 32 + 8 + m.batch.transactions.length * 84;
  for (const offset of [b.length - tailLength - 2, b.length - tailLength - 1]) {
    for (const flag of [1, 2]) { const bad = b.slice(); bad[offset] = flag; assert.throws(() => decode(bad)); }
  }
  m.attestation.evidenceItems.push(m.attestation.evidenceItems[0]);
  assert.throws(() => encodeEconomicMeterV1(m));
  for (const v of legacy.filter(v => v.fixture.includes("tampered_stark"))) {
    // Legacy flags survive the adapter, but never enter the canonical type.
    assert.throws(() => decode(bytes(v.meter_hex)));
  }
});

test("meter: transfer and evidence failures stay chargeable; BOM and u64 bytes survive", () => {
  const m = sample();
  m.batch.transactions[0].senderNonce = 0xffffffffffffffffn;
  m.batch.transactions[0].amount = 0xffffffffffffffffn;
  assert.doesNotThrow(() => decode(encodeEconomicMeterV1(m)));
  const a = sample("signed_json");
  a.attestation.evidenceItems[0].evidencePayload.payloadUtf8 = "{bad json";
  assert.doesNotThrow(() => decode(encodeEconomicMeterV1(a)));
  const t = sample("text_contains");
  assert(t.attestation.claim.claimPayload.expectedSubstringUtf8.startsWith("\ufeff"));
  assert.equal(sample("signed_json").attestation.evidenceItems[0].provenance.timestampUnixSeconds, 0xffffffffffffffffn);
  const whitespace = sample("attestation");
  whitespace.attestation.evidenceItems[0].label = "\u0085";
  assert.throws(() => encodeEconomicMeterV1(whitespace));
  whitespace.attestation.evidenceItems[0].label = "\ufeff";
  assert.doesNotThrow(() => encodeEconomicMeterV1(whitespace));
});
