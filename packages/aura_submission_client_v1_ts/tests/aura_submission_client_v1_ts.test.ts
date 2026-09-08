import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { AuraSubmissionClientErrorV1, AuraSubmissionWireErrorV1, deriveProofRecordAddressV1, parseSubmitProofRequestWireV1, prepareSubmitProofInstructionFromWireV1, prepareSubmitProofTransactionFromWireV1, submitProofFromWireV1 } from "../src/index.ts";
import { proofHashHexFromWalletVisualV1 } from "../../aura_sdk_v1_ts/src/index.ts";
import { buildSubmitProofRequestWireV1, buildSettlementPipelineFromPreparedProofV1, prepareSubmitProofFlowV1 } from "../../aura_sdk_v1_ts/src/legacy/solana.ts";
import {
  loadCanonicalPipelineFixtureJsonV1,
  loadCanonicalPipelineFixtureTextV1,
} from "../../test_support/canonical_pipeline_fixture_v1.ts";

const submitterSeedBytes = new Uint8Array(32).fill(0x11);
const submitterPubkeyBytes = hexToBytes(
  "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
);
const submitterKeypairBytes = concatBytes(submitterSeedBytes, submitterPubkeyBytes);
const challengeBytes = new Uint8Array(32).fill(0x22);
const programIdBytes = new Uint8Array(32).fill(0x33);
const recentBlockhashBytes = new Uint8Array(32).fill(0x44);

test("parseSubmitProofRequestWireV1 round-trips the canonical wallet surface", () => {
  const parsed = parseSubmitProofRequestWireV1(sampleSubmitProofRequestWireV1());
  const roundTrip = parseSubmitProofRequestWireV1(JSON.parse(JSON.stringify(parsed)));

  assert.deepEqual(roundTrip, parsed);
  assert.equal(
    proofHashHexFromWalletVisualV1(roundTrip.wallet_visual_v1),
    roundTrip.proof_hash_hex,
  );
  assert.equal(
    JSON.stringify(parsed),
    loadCanonicalPipelineFixtureTextV1("submit_proof_request_v1.json"),
  );
});

test("parseSubmitProofRequestWireV1 rejects alternate wallet peer fields", () => {
  const request = sampleSubmitProofRequestWireV1();

  assert.throws(
    () =>
      parseSubmitProofRequestWireV1({
        ...request,
        seal_line: "forbidden",
      } as never),
    (error: unknown) =>
      error instanceof AuraSubmissionWireErrorV1 &&
      error.message === 'payload contains unexpected field "seal_line"',
  );

  assert.throws(
    () =>
      parseSubmitProofRequestWireV1({
        ...request,
        udot_bundle: {
          seal_line: "forbidden",
        },
      } as never),
    (error: unknown) =>
      error instanceof AuraSubmissionWireErrorV1 &&
      error.message === 'payload contains unexpected field "udot_bundle"',
  );
});

test("parseSubmitProofRequestWireV1 rejects wallet visuals that do not round-trip to proof_hash_hex", () => {
  const request = sampleSubmitProofRequestWireV1();

  assert.throws(
    () =>
      parseSubmitProofRequestWireV1({
        ...request,
        proof_hash_hex:
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      }),
    (error: unknown) =>
      error instanceof AuraSubmissionWireErrorV1 &&
      error.code === "InvalidWalletVisual" &&
      error.message.includes("round-trip"),
  );
});

test("prepareSubmitProofInstructionFromWireV1 preserves canonical proof_hash bytes", () => {
  const prepared = prepareSubmitProofInstructionFromWireV1(sampleSubmitProofRequestWireV1());

  assert.equal(
    hexLower(prepared.instruction.data),
    `02${sampleSubmitProofRequestWireV1().proof_hash_hex}`,
  );
});

test("SDK-built prepared-proof pipeline feeds the submission-client boundary unchanged", async () => {
  const preparedSubmitProof = await prepareSubmitProofFlowV1(
    hexToBytes(readCanonicalPrepareTextFixture("subject_pubkey.hex")),
    hexToBytes(readCanonicalPrepareTextFixture("challenge_account_pubkey.hex")),
    new Uint8Array(readFileSync(canonicalPrepareFixtureUrl("proof_blob.bin"))),
    new Uint8Array(readFileSync(canonicalPrepareFixtureUrl("public_inputs.bin"))),
    new Uint8Array(readFileSync(canonicalPrepareFixtureUrl("verification_key.bin"))),
  );
  const submitFixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
  }>("submit_proof_request_v1.json");
  const authorizationFixture = loadCanonicalPipelineFixtureJsonV1<{
    intent_id_hex: string;
  }>("authorization_intent_v1.json");
  const proofFixture = loadCanonicalPipelineFixtureJsonV1<{
    proof_session_id_hex: string;
    storm_claim: {
      version: number;
      modulus_id: number;
      iteration_count: number;
      side_a_hex: string;
      side_b_hex: string;
      context_bytes_hex: string;
      initial_state: { x_hex_66_be: string; y_hex_66_be: string };
      final_state: { x_hex_66_be: string; y_hex_66_be: string };
      trace_root_hex: string;
      legacy_commitment_root_hex: string;
      legacy_trace_commitment_hex: string;
    };
    legacy_dcm_claim: {
      iteration_count: number;
      initial_state: string;
      final_state: string;
      commitment_root: string;
    };
  }>("stark_proof_envelope_v1.json");
  const settlementFixture = loadCanonicalPipelineFixtureJsonV1<{
    solana_rpc_url: string | null;
    commitment_config: "processed" | "confirmed" | "finalized";
  }>("solana_settlement_request_v1.json");
  const pipeline = await buildSettlementPipelineFromPreparedProofV1({
    preparedSubmitProof,
    programIdBase58: submitFixture.program_id_base58,
    submitterPubkeyBase58: submitFixture.submitter_pubkey_base58,
    challengePubkeyBase58: submitFixture.challenge_pubkey_base58,
    intentIdHex: authorizationFixture.intent_id_hex,
    proofSessionIdHex: proofFixture.proof_session_id_hex,
    stormClaim: stormClaimFromFixture(proofFixture.storm_claim),
    legacyDcmClaim: proofFixture.legacy_dcm_claim,
    solanaRpcUrl: settlementFixture.solana_rpc_url,
    commitmentConfig: settlementFixture.commitment_config,
  });
  const prepared = prepareSubmitProofInstructionFromWireV1(pipeline.submit_proof_request_wire);

  assert.deepEqual(
    parseSubmitProofRequestWireV1(pipeline.submit_proof_request_wire),
    pipeline.submit_proof_request_wire,
  );
  assert.equal(prepared.instruction.data[0], 2);
  assert.equal(
    proofHashHexFromWalletVisualV1(pipeline.submit_proof_request_wire.wallet_visual_v1),
    pipeline.submit_proof_request_wire.proof_hash_hex,
  );
});

test("prepareSubmitProofTransactionFromWireV1 rejects a mismatched submitter keypair", () => {
  assert.throws(
    () =>
      prepareSubmitProofTransactionFromWireV1(
        submitterKeypairBytes,
        {
          ...sampleSubmitProofRequestWireV1(),
          submitter_pubkey_base58: encodeBase58(new Uint8Array(32).fill(0x55)),
        },
        recentBlockhashBytes,
      ),
    (error: unknown) =>
      error instanceof AuraSubmissionWireErrorV1 &&
      error.code === "SubmitterPubkeyMismatch",
  );
});

test("submitProofFromWireV1 accepts the canonical wallet surface", async () => {
  const rpcClient = {
    async getLatestBlockhash() {
      return "5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5";
    },
    async sendAndConfirmTransaction() {
      return "mock-signature-v1";
    },
  };

  const submitted = await submitProofFromWireV1(
    rpcClient,
    submitterKeypairBytes,
    sampleRuntimeSubmitProofRequestWireV1(),
  );

  assert.equal(
    encodeBase58(submitted.proofRecordAddress),
    "3h4Q789Cf1PwghYTQu2Q218TkRX1iEpViTFPS8eaNHbQ",
  );
  assert.equal(submitted.signature, "mock-signature-v1");
});

test("deriveProofRecordAddressV1 matches the frozen Rust demo PDA", () => {
  const derived = deriveProofRecordAddressV1(
    programIdBytes,
    challengeBytes,
    submitterPubkeyBytes,
  );

  assert.equal(
    encodeBase58(derived.proofRecordAddress),
    "3h4Q789Cf1PwghYTQu2Q218TkRX1iEpViTFPS8eaNHbQ",
  );
  assert.equal(derived.bump, 254);
});

function sampleSubmitProofRequestWireV1() {
  return loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
    proof_hash_hex: string;
    wallet_visual_v1: string;
  }>("submit_proof_request_v1.json");
}

function sampleRuntimeSubmitProofRequestWireV1() {
  const request = sampleSubmitProofRequestWireV1();
  return {
    ...request,
    program_id_base58: encodeBase58(programIdBytes),
    submitter_pubkey_base58: encodeBase58(submitterPubkeyBytes),
    challenge_pubkey_base58: encodeBase58(challengeBytes),
  };
}

function canonicalPrepareFixtureUrl(name: string): URL {
  return new URL(`../../../fixtures/v1/canonical_prepare/${name}`, import.meta.url);
}

function readCanonicalPrepareTextFixture(name: string): string {
  return readFileSync(canonicalPrepareFixtureUrl(name), "utf8").trim();
}

function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
}

function hexLower(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left, 0);
  output.set(right, left.length);
  return output;
}

function encodeBase58(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  if (bytes.length === 0) {
    return "";
  }

  const digits = [0];
  for (const value of bytes) {
    let carry = value;
    for (let index = 0; index < digits.length; index += 1) {
      const product = digits[index]! * 256 + carry;
      digits[index] = product % 58;
      carry = Math.floor(product / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let result = "";
  for (const value of bytes) {
    if (value === 0) {
      result += alphabet[0];
    } else {
      break;
    }
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    result += alphabet[digits[index]!];
  }
  return result;
}

function stormClaimFromFixture(fixture: {
  version: number;
  modulus_id: number;
  iteration_count: number;
  side_a_hex: string;
  side_b_hex: string;
  context_bytes_hex: string;
  initial_state: { x_hex_66_be: string; y_hex_66_be: string };
  final_state: { x_hex_66_be: string; y_hex_66_be: string };
  trace_root_hex: string;
  legacy_commitment_root_hex: string;
  legacy_trace_commitment_hex: string;
}) {
  return {
    version: fixture.version,
    modulusId: fixture.modulus_id,
    iterationCount: BigInt(fixture.iteration_count),
    sideAHex: fixture.side_a_hex,
    sideBHex: fixture.side_b_hex,
    contextBytesHex: fixture.context_bytes_hex,
    initialState: {
      xHex66Be: fixture.initial_state.x_hex_66_be,
      yHex66Be: fixture.initial_state.y_hex_66_be,
    },
    finalState: {
      xHex66Be: fixture.final_state.x_hex_66_be,
      yHex66Be: fixture.final_state.y_hex_66_be,
    },
    traceRootHex: fixture.trace_root_hex,
    legacyCommitmentRootHex: fixture.legacy_commitment_root_hex,
    legacyTraceCommitmentHex: fixture.legacy_trace_commitment_hex,
  } as const;
}
