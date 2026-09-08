import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  validateBitcoinAnchorRequestV1, encodeBitcoinAnchorScriptV1,
  decodeBitcoinAnchorScriptV1, validateBitcoinAnchorOutputsV1,
} from "../src/index.ts";
import type { BitcoinAnchorRequestV1 } from "../src/index.ts";

const fixture = JSON.parse(readFileSync(new URL("../../../fixtures/bitcoin_v1/anchor_vectors_v1.json", import.meta.url), "utf8"));
const request = validateBitcoinAnchorRequestV1(fixture.vectors[3].request);
const output = (r: BitcoinAnchorRequestV1) => ({ value_sat: 0n, script_pubkey: encodeBitcoinAnchorScriptV1(r) });

test("shared vectors round-trip without changing the proof reference", () => {
  for (const vector of fixture.vectors) {
    const r = validateBitcoinAnchorRequestV1(vector.request);
    const script = encodeBitcoinAnchorScriptV1(r);
    assert.equal(Buffer.from(script).toString("hex"), vector.script_hex);
    assert.deepEqual(decodeBitcoinAnchorScriptV1(script), vector.request);
    assert.deepEqual(r, vector.request);
  }
});

test("shared malformed requests and scripts are rejected", () => {
  for (const invalid of fixture.invalid_requests) {
    assert.throws(() => validateBitcoinAnchorRequestV1(invalid), TypeError);
  }
  for (const invalid of fixture.invalid_scripts) {
    assert.throws(() => decodeBitcoinAnchorScriptV1(Buffer.from(invalid, "hex")), TypeError);
  }
});

test("requires exactly one zero-value matching anchor among change outputs", () => {
  const change = { value_sat: 1000n, script_pubkey: Uint8Array.of(0x51) };
  assert.equal(validateBitcoinAnchorOutputsV1([change, output(request)], request), 1);
  assert.throws(() => validateBitcoinAnchorOutputsV1([change], request));
  assert.throws(() => validateBitcoinAnchorOutputsV1([output(request), output(request)], request));
  assert.throws(() => validateBitcoinAnchorOutputsV1([{ ...output(request), value_sat: 1n }], request));
  for (const vector of fixture.vectors) {
    if (vector.request.network !== request.network) {
      assert.throws(() => validateBitcoinAnchorOutputsV1([output(vector.request)], request));
    }
  }
  assert.throws(() => validateBitcoinAnchorOutputsV1([output({ ...request, proof_hash_hex: "ff".repeat(32) })], request));
});

test("rejects nonminimal or malformed second Aura outputs", () => {
  for (const prefix of [[0x6a, 0x4c, 38], [0x6a, 0x4d, 38, 0], [0x6a, 0x4e, 38, 0, 0, 0]]) {
    const bad = { value_sat: 0n, script_pubkey: Uint8Array.from([...prefix, ...encodeBitcoinAnchorScriptV1(request).slice(2)]) };
    assert.throws(() => validateBitcoinAnchorOutputsV1([bad], request));
    assert.throws(() => validateBitcoinAnchorOutputsV1([output(request), bad], request));
    assert.throws(() => validateBitcoinAnchorOutputsV1([bad, output(request)], request));
  }
});
