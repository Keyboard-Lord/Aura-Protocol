import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  inspectAuraHash521PreimageV1,
  inspectAuraHash521V1,
  readStormClaimV1,
} from "../src/auraHashReaderV1.ts";
import {
  bytesToHexLowerV1,
  decodeCanonicalFixedHexBytesV1,
} from "../src/stormHash521V1.ts";

type StormFixtureV1 = {
  aura_hash521_v1_message_hex: string;
  expected: {
    aura_hash521_v1_hex: string;
    storm_claim_wire: {
      version: number;
      modulus_id: number;
      iteration_count: number;
      side_a_hex: string;
      side_b_hex: string;
      context_bytes_hex: string;
      initial_state: {
        x_hex_66_be: string;
        y_hex_66_be: string;
      };
      final_state: {
        x_hex_66_be: string;
        y_hex_66_be: string;
      };
      trace_root_hex: string;
      legacy_commitment_root_hex: string;
      legacy_trace_commitment_hex: string;
    };
  };
};

test("inspectAuraHash521V1 reads a raw H_521 field element without claiming reversibility", () => {
  const fixture = loadFixture();
  const inspection = inspectAuraHash521V1(fixture.expected.aura_hash521_v1_hex);

  assert.equal(inspection.kind, "storm-h521-field-element");
  assert.equal(inspection.valid, true);
  assert.equal(inspection.algorithm, "H_521(m) = Reduce_N(SHA3-512(m))");
  assert.equal(inspection.modulus, "2^521 - 1");
  assert.equal(inspection.byteLength, 66);
  assert.equal(inspection.hex, fixture.expected.aura_hash521_v1_hex);
  assert.equal(inspection.reversible, false);
  assert.equal(inspection.canDecodePreimage, false);
  assert.equal(typeof inspection.decimal, "string");
  assert.ok(inspection.bitLength > 0);
  assert.ok(inspection.bitLength <= 521);
  assert.ok(inspection.topNineBits >= 0);
  assert.ok(inspection.topNineBits <= 511);
});

test("inspectAuraHash521PreimageV1 verifies whether a supplied preimage produced the hash", () => {
  const fixture = loadFixture();
  const preimage = decodeCanonicalFixedHexBytesV1(
    fixture.aura_hash521_v1_message_hex,
    fixture.aura_hash521_v1_message_hex.length / 2,
    "aura_hash521_v1_message_hex",
  );
  const inspection = inspectAuraHash521PreimageV1(
    preimage,
    fixture.expected.aura_hash521_v1_hex,
  );

  assert.deepEqual(inspection.preimageVerification, {
    recomputedHashHex: fixture.expected.aura_hash521_v1_hex,
    matches: true,
  });

  const mismatch = inspectAuraHash521PreimageV1(
    new Uint8Array([...preimage, 0x00]),
    fixture.expected.aura_hash521_v1_hex,
  );
  assert.equal(mismatch.preimageVerification?.matches, false);
});

test("readStormClaimV1 reads and verifies the frozen storm claim wire artifact", () => {
  const fixture = loadFixture();
  const read = readStormClaimV1(fixture.expected.storm_claim_wire);

  assert.equal(read.kind, "storm-claim-v1");
  assert.equal(read.valid, true);
  assert.equal(read.claimVerified, true);
  assert.equal(read.reversible, false);
  assert.equal(read.canDecodePreimage, false);
  assert.equal(read.version, 1);
  assert.equal(read.modulusId, 1);
  assert.equal(read.iterationCount, String(fixture.expected.storm_claim_wire.iteration_count));
  assert.equal(read.traceRootHex, fixture.expected.storm_claim_wire.trace_root_hex);
  assert.equal(read.context.version, 1);
  assert.equal(read.context.intentHashHex.length, 64);
  assert.equal(read.initialState.x.hex, fixture.expected.storm_claim_wire.initial_state.x_hex_66_be);
  assert.equal(read.finalState.y.hex, fixture.expected.storm_claim_wire.final_state.y_hex_66_be);
  assert.equal(read.publicInputs.traceRootHex, fixture.expected.storm_claim_wire.trace_root_hex);
});

test("readStormClaimV1 rejects tampered claim state instead of reading it as valid", () => {
  const fixture = loadFixture();
  const tampered = structuredClone(fixture.expected.storm_claim_wire);
  tampered.final_state.x_hex_66_be = tampered.final_state.x_hex_66_be.replace(/.$/, "0");

  assert.throws(
    () => readStormClaimV1(tampered),
    /finalState does not match derived execution|field element/,
  );
});

test("inspectAuraHash521V1 rejects non-canonical or out-of-range field text", () => {
  assert.throws(
    () => inspectAuraHash521V1("AB"),
    /lowercase hex|132 lowercase hex/,
  );

  assert.throws(
    () => inspectAuraHash521V1(bytesToHexLowerV1(new Uint8Array(66).fill(0xff))),
    /invalid top bits|out of range/,
  );
});

function loadFixture(): StormFixtureV1 {
  return JSON.parse(
    readFileSync(
      new URL(
        "../../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as StormFixtureV1;
}
