import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  AuraSdkErrorV1,
  buildSubmitProofRequestWireV1,
  prepareSubmitProofFlowV1,
  proofHashHexFromWalletVisualV1,
  validateSubmitProofRequestWireV1,
  type PreparedSubmitProofV1,
} from "../src/index.ts";
import {
  loadCanonicalPipelineFixtureJsonV1,
  loadCanonicalPipelineFixtureTextV1,
} from "../../test_support/canonical_pipeline_fixture_v1.ts";

const subjectBytes = hexToBytes(readTextFixture("subject_pubkey.hex"));
const challengeBytes = hexToBytes(readTextFixture("challenge_account_pubkey.hex"));
const proofBlobBytes = new Uint8Array(readFileSync(fixtureUrl("proof_blob.bin")));
const publicInputsBytes = new Uint8Array(readFileSync(fixtureUrl("public_inputs.bin")));
const verificationKeyBytes = new Uint8Array(readFileSync(fixtureUrl("verification_key.bin")));

test("buildSubmitProofRequestWireV1 emits the canonical wallet-locked submission envelope", async () => {
  const prepared = await canonicalPreparedProofV1();
  const fixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
    proof_hash_hex: string;
    wallet_visual_v1: string;
  }>("submit_proof_request_v1.json");

  const request = await buildSubmitProofRequestWireV1(canonicalSubmitRequest(prepared));

  assert.deepEqual(request, fixture);
  assert.equal(
    JSON.stringify(request),
    loadCanonicalPipelineFixtureTextV1("submit_proof_request_v1.json"),
  );
  assert.equal(
    proofHashHexFromWalletVisualV1(request.wallet_visual_v1),
    request.proof_hash_hex,
  );
  assertWalletVisualShape(request.wallet_visual_v1);
});

test("buildSubmitProofRequestWireV1 rejects deprecated wallet-version knobs", async () => {
  const prepared = await canonicalPreparedProofV1();

  await assert.rejects(
    buildSubmitProofRequestWireV1({
      ...canonicalSubmitRequest(prepared),
      udotVersion: "v2",
    } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'request contains unexpected field "udotVersion"',
  );
});

test("validateSubmitProofRequestWireV1 rejects alternate wallet peer fields", async () => {
  const fixture = loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
    "submit_proof_request_v1.json",
  );

  await assert.rejects(
    validateSubmitProofRequestWireV1({
      ...fixture,
      seal_line: "forbidden",
    } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'payload contains unexpected field "seal_line"',
  );

  await assert.rejects(
    validateSubmitProofRequestWireV1({
      ...fixture,
      udot_bundle: {
        seal_line: "forbidden",
      },
    } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'payload contains unexpected field "udot_bundle"',
  );
});

test("validateSubmitProofRequestWireV1 rejects malformed wallet visuals", async () => {
  const fixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
    proof_hash_hex: string;
    wallet_visual_v1: string;
  }>("submit_proof_request_v1.json");
  const rows = fixture.wallet_visual_v1.split("\n");

  await assert.rejects(
    validateSubmitProofRequestWireV1({
      ...fixture,
      wallet_visual_v1: `${rows[0]!.slice(0, 7)}\n${rows.slice(1).join("\n")}`,
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactValidationFailed" &&
      error.message.includes("row length"),
  );
});

test("validateSubmitProofRequestWireV1 rejects non-round-trippable wallet visuals", async () => {
  const fixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
    proof_hash_hex: string;
    wallet_visual_v1: string;
  }>("submit_proof_request_v1.json");

  await assert.rejects(
    validateSubmitProofRequestWireV1({
      ...fixture,
      wallet_visual_v1: fixture.wallet_visual_v1.replace("○", "◌"),
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotArtifactValidationFailed" &&
      error.message.includes("mismatch"),
  );
});

function fixtureUrl(name: string): URL {
  return new URL(`../../../fixtures/v1/canonical_prepare/${name}`, import.meta.url);
}

function readTextFixture(name: string): string {
  return readFileSync(fixtureUrl(name), "utf8").trim();
}

async function canonicalPreparedProofV1(): Promise<PreparedSubmitProofV1> {
  return prepareSubmitProofFlowV1(
    subjectBytes,
    challengeBytes,
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );
}

function canonicalSubmitRequest(preparedSubmitProof: PreparedSubmitProofV1) {
  const fixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
  }>("submit_proof_request_v1.json");

  return {
    preparedSubmitProof,
    programIdBase58: fixture.program_id_base58,
    submitterPubkeyBase58: fixture.submitter_pubkey_base58,
    challengePubkeyBase58: fixture.challenge_pubkey_base58,
  } as const;
}

function assertWalletVisualShape(walletVisualV1: string): void {
  const rows = walletVisualV1.split("\n");
  assert.equal(rows.length, 8);
  for (const row of rows) {
    assert.equal(Array.from(row).length, 8);
  }
  assert.equal(walletVisualV1.endsWith("\n"), false);
}

function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
}
