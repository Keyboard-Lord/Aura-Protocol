import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { AuraSdkErrorV1, proofHashHexFromWalletVisualV1, type StormClaim521V1 } from "../src/index.ts";
import type { PreparedSubmitProofV1 } from "../src/legacy/solana.ts";
import { buildSettlementPipelineFromPreparedProofV1, prepareSubmitProofFlowV1 } from "../src/legacy/solana.ts";
import {
  loadCanonicalPipelineFixtureJsonV1,
  loadCanonicalPipelineFixtureTextV1,
} from "../../test_support/canonical_pipeline_fixture_v1.ts";

const subjectBytes = hexToBytes(readTextFixture("subject_pubkey.hex"));
const challengeBytes = hexToBytes(readTextFixture("challenge_account_pubkey.hex"));
const proofBlobBytes = new Uint8Array(readFileSync(fixtureUrl("proof_blob.bin")));
const publicInputsBytes = new Uint8Array(readFileSync(fixtureUrl("public_inputs.bin")));
const verificationKeyBytes = new Uint8Array(readFileSync(fixtureUrl("verification_key.bin")));

test("buildSettlementPipelineFromPreparedProofV1 emits the frozen wallet-locked pipeline", async () => {
  const prepared = await canonicalPreparedProofV1();
  const submitFixture = loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
    "submit_proof_request_v1.json",
  );
  const authorizationFixture = loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
    "authorization_intent_v1.json",
  );
  const starkFixture = loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
    "stark_proof_envelope_v1.json",
  );
  const settlementFixture = loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
    "solana_settlement_request_v1.json",
  );

  const pipeline = await buildSettlementPipelineFromPreparedProofV1(
    canonicalPipelineRequest(prepared),
  );

  assert.deepEqual(pipeline.submit_proof_request_wire, submitFixture);
  assert.deepEqual(pipeline.authorization_intent_envelope, authorizationFixture);
  assert.deepEqual(pipeline.stark_proof_envelope, starkFixture);
  assert.deepEqual(pipeline.solana_settlement_request_wire, settlementFixture);
  assert.equal(
    JSON.stringify(pipeline.solana_settlement_request_wire),
    loadCanonicalPipelineFixtureTextV1("solana_settlement_request_v1.json"),
  );
  assert.equal(
    proofHashHexFromWalletVisualV1(pipeline.submit_proof_request_wire.wallet_visual_v1),
    pipeline.submit_proof_request_wire.proof_hash_hex,
  );
  assert.deepEqual(
    pipeline.authorization_intent_envelope.submit_proof_request,
    pipeline.submit_proof_request_wire,
  );
  assert.deepEqual(
    pipeline.stark_proof_envelope.authorization_intent,
    pipeline.authorization_intent_envelope,
  );
  assert.deepEqual(
    pipeline.solana_settlement_request_wire.stark_proof_envelope,
    pipeline.stark_proof_envelope,
  );
});

test("buildSettlementPipelineFromPreparedProofV1 rejects removed wallet-version inputs", async () => {
  const prepared = await canonicalPreparedProofV1();

  await assert.rejects(
    buildSettlementPipelineFromPreparedProofV1({
      ...canonicalPipelineRequest(prepared),
      udotVersion: "v2",
    } as never),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'request contains unexpected field "udotVersion"',
  );
});

test("buildSettlementPipelineFromPreparedProofV1 keeps wallet visuals nested only at submit surfaces", async () => {
  const prepared = await canonicalPreparedProofV1();
  const pipeline = await buildSettlementPipelineFromPreparedProofV1(
    canonicalPipelineRequest(prepared),
  );
  const settlement = pipeline.solana_settlement_request_wire as Record<string, unknown>;

  assert.equal("wallet_visual_v1" in settlement, false);
  assert.equal("udot_bundle" in settlement, false);
  assert.equal(
    (
      ((
        ((settlement.stark_proof_envelope as Record<string, unknown>).authorization_intent as Record<
          string,
          unknown
        >).submit_proof_request as Record<string, unknown>
      ).wallet_visual_v1 as string)
    ),
    pipeline.submit_proof_request_wire.wallet_visual_v1,
  );
});

test("buildSettlementPipelineFromPreparedProofV1 rejects malformed prepared proof input", async () => {
  const prepared = await canonicalPreparedProofV1();

  await assert.rejects(
    buildSettlementPipelineFromPreparedProofV1({
      ...canonicalPipelineRequest({
        ...prepared,
        proofHash: new Uint8Array(31),
      } as PreparedSubmitProofV1),
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "SubmitProofPreparationFailed" &&
      error.message.includes("preparedSubmitProof.proofHash"),
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

function canonicalPipelineRequest(preparedSubmitProof: PreparedSubmitProofV1) {
  const submitFixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
  }>("submit_proof_request_v1.json");
  const authorizationFixture = loadCanonicalPipelineFixtureJsonV1<{
    intent_id_hex: string;
  }>("authorization_intent_v1.json");
  const starkFixture = loadCanonicalPipelineFixtureJsonV1<{
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

  return {
    preparedSubmitProof,
    programIdBase58: submitFixture.program_id_base58,
    submitterPubkeyBase58: submitFixture.submitter_pubkey_base58,
    challengePubkeyBase58: submitFixture.challenge_pubkey_base58,
    intentIdHex: authorizationFixture.intent_id_hex,
    proofSessionIdHex: starkFixture.proof_session_id_hex,
    stormClaim: stormClaimFromFixture(starkFixture.storm_claim),
    legacyDcmClaim: starkFixture.legacy_dcm_claim,
    solanaRpcUrl: settlementFixture.solana_rpc_url,
    commitmentConfig: settlementFixture.commitment_config,
  } as const;
}

function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
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
}): StormClaim521V1 {
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
  };
}
