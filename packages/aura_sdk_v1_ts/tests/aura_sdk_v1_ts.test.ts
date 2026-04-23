import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  AuraSdkErrorV1,
  prepareSubmitProofFlowV1,
} from "../src/index.ts";

const subjectBytes = hexToBytes(readTextFixture("subject_pubkey.hex"));
const challengeBytes = hexToBytes(readTextFixture("challenge_account_pubkey.hex"));
const proofBlobBytes = new Uint8Array(readFileSync(fixtureUrl("proof_blob.bin")));
const publicInputsBytes = new Uint8Array(readFileSync(fixtureUrl("public_inputs.bin")));
const verificationKeyBytes = new Uint8Array(readFileSync(fixtureUrl("verification_key.bin")));

const expectedVectors = {
  proofBlobHash: readTextFixture("proof_blob_hash.hex"),
  publicInputsHash: readTextFixture("public_inputs_hash.hex"),
  verificationKeyHash: readTextFixture("verification_key_hash.hex"),
  proofMaterialHash: readTextFixture("proof_material_hash.hex"),
  proofHash: readTextFixture("proof_hash.hex"),
} as const;

test("prepareSubmitProofFlowV1 matches the frozen Rust sample vectors", async () => {
  const prepared = await prepareSubmitProofFlowV1(
    subjectBytes,
    challengeBytes,
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );

  assert.equal(hexLower(prepared.proofMaterial.proofBlobHash), expectedVectors.proofBlobHash);
  assert.equal(
    hexLower(prepared.proofMaterial.publicInputsHash),
    expectedVectors.publicInputsHash,
  );
  assert.equal(
    hexLower(prepared.proofMaterial.verificationKeyHash),
    expectedVectors.verificationKeyHash,
  );
  assert.equal(hexLower(prepared.proofMaterialHash), expectedVectors.proofMaterialHash);
  assert.equal(hexLower(prepared.proofHash), expectedVectors.proofHash);

  assert.equal(prepared.proofMaterial.proofMaterialVersion, 1);
  assert.equal(prepared.proofMaterial.proofMaterialType, 0x0001);
  assert.equal(prepared.fractalKey.fractalKeyVersion, 1);
  assert.equal(prepared.fractalKey.componentCount, 3);
  assert.equal(prepared.fractalKey.components[0].componentType, 0x0001);
  assert.equal(prepared.fractalKey.components[1].componentType, 0x0002);
  assert.equal(prepared.fractalKey.components[2].componentType, 0x0003);
  assert.equal(hexLower(prepared.fractalKey.components[0].payload32), hexLower(subjectBytes));
  assert.equal(
    hexLower(prepared.fractalKey.components[1].payload32),
    hexLower(challengeBytes),
  );
  assert.equal(
    hexLower(prepared.fractalKey.components[2].payload32),
    expectedVectors.proofMaterialHash,
  );
});

test("prepareSubmitProofFlowV1 is deterministic across repeated runs", async () => {
  const preparedA = await prepareSubmitProofFlowV1(
    subjectBytes,
    challengeBytes,
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );
  const preparedB = await prepareSubmitProofFlowV1(
    subjectBytes,
    challengeBytes,
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );

  assert.equal(hexLower(preparedA.proofMaterialHash), hexLower(preparedB.proofMaterialHash));
  assert.equal(hexLower(preparedA.proofHash), hexLower(preparedB.proofHash));
  assert.equal(
    hexLower(preparedA.proofMaterial.proofBlobHash),
    hexLower(preparedB.proofMaterial.proofBlobHash),
  );
});

test("prepareSubmitProofFlowV1 rejects a subject that is not 32 bytes", async () => {
  await assert.rejects(
    prepareSubmitProofFlowV1(
      new Uint8Array(31).fill(0x11),
      challengeBytes,
      proofBlobBytes,
      publicInputsBytes,
      verificationKeyBytes,
    ),
    (error: unknown) =>
      error instanceof RangeError &&
      error.message === "subjectPubkeyBytes must be exactly 32 bytes",
  );
});

test("prepareSubmitProofFlowV1 rejects a proof blob that is not a Uint8Array", async () => {
  await assert.rejects(
    prepareSubmitProofFlowV1(
      subjectBytes,
      challengeBytes,
      5 as unknown as Uint8Array,
      publicInputsBytes,
      verificationKeyBytes,
    ),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === "proofBlobBytes must be a Uint8Array",
  );
});

test("returned errors stay within the SDK error surface", async () => {
  const prepared = await prepareSubmitProofFlowV1(
    subjectBytes,
    challengeBytes,
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );

  assert.ok(!(prepared instanceof AuraSdkErrorV1));
});

function fixtureUrl(name: string): URL {
  return new URL(`../../../fixtures/v1/canonical_prepare/${name}`, import.meta.url);
}

function readTextFixture(name: string): string {
  return readFileSync(fixtureUrl(name), "utf8").trim();
}

function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
}

function hexLower(bytes: Uint8Array): string {
  let output = "";

  for (const byte of bytes) {
    output += byte.toString(16).padStart(2, "0");
  }

  return output;
}
