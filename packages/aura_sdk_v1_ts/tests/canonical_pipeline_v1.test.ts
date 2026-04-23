import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  AuraSdkErrorV1,
  generateAuthorizationIntentV1,
  generateSolanaSettlementRequestV1,
  generateStarkProofEnvelopeV1,
  generateSubmitProofRequestV1,
  prepareSubmitProofFlowV1,
  proofHashHexFromWalletVisualV1,
  type SolanaSettlementRequestWireV1,
  type StormClaim521V1,
  UdotHashError,
  validateSolanaSettlementRequestV1,
} from "../src/index.ts";
import {
  loadCanonicalPipelineFixtureJsonV1,
  loadCanonicalPipelineFixtureTextV1,
  parseCanonicalPipelineFixtureJsonV1,
} from "../../test_support/canonical_pipeline_fixture_v1.ts";

test("canonical pipeline fixtures stay byte-exact under the wallet identity lock", async () => {
  const subjectBytes = hexToBytes(readCanonicalPrepareTextFixture("subject_pubkey.hex"));
  const challengeBytes = hexToBytes(
    readCanonicalPrepareTextFixture("challenge_account_pubkey.hex"),
  );
  const proofBlobBytes = new Uint8Array(readFileSync(canonicalPrepareFixtureUrl("proof_blob.bin")));
  const publicInputsBytes = new Uint8Array(
    readFileSync(canonicalPrepareFixtureUrl("public_inputs.bin")),
  );
  const verificationKeyBytes = new Uint8Array(
    readFileSync(canonicalPrepareFixtureUrl("verification_key.bin")),
  );
  const prepared = await prepareSubmitProofFlowV1(
    subjectBytes,
    challengeBytes,
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );
  const proofHashHex = hexLower(prepared.proofHash);
  const submitFixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
    proof_hash_hex: string;
    wallet_visual_v1: string;
  }>("submit_proof_request_v1.json");
  const intentFixture = loadCanonicalPipelineFixtureJsonV1<{
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

  assert.equal(proofHashHex, readCanonicalPrepareTextFixture("proof_hash.hex"));

  const submit = await generateSubmitProofRequestV1({
    programIdBase58: submitFixture.program_id_base58,
    submitterPubkeyBase58: submitFixture.submitter_pubkey_base58,
    challengePubkeyBase58: submitFixture.challenge_pubkey_base58,
    proofHashHex,
  });
  assert.equal(
    JSON.stringify(submit),
    loadCanonicalPipelineFixtureTextV1("submit_proof_request_v1.json"),
  );
  assert.equal(proofHashHexFromWalletVisualV1(submit.wallet_visual_v1), proofHashHex);

  const intent = await generateAuthorizationIntentV1({
    intentIdHex: intentFixture.intent_id_hex,
    submitProofRequest: {
      programIdBase58: submitFixture.program_id_base58,
      submitterPubkeyBase58: submitFixture.submitter_pubkey_base58,
      challengePubkeyBase58: submitFixture.challenge_pubkey_base58,
      proofHashHex,
    },
  });
  assert.equal(
    JSON.stringify(intent),
    loadCanonicalPipelineFixtureTextV1("authorization_intent_v1.json"),
  );

  const proof = await generateStarkProofEnvelopeV1({
    proofSessionIdHex: proofFixture.proof_session_id_hex,
    stormClaim: stormClaimFromFixture(proofFixture.storm_claim),
    legacyDcmClaim: proofFixture.legacy_dcm_claim,
    authorizationIntent: {
      intentIdHex: intentFixture.intent_id_hex,
      submitProofRequest: {
        programIdBase58: submitFixture.program_id_base58,
        submitterPubkeyBase58: submitFixture.submitter_pubkey_base58,
        challengePubkeyBase58: submitFixture.challenge_pubkey_base58,
        proofHashHex,
      },
    },
  });
  assert.equal(
    JSON.stringify(proof),
    loadCanonicalPipelineFixtureTextV1("stark_proof_envelope_v1.json"),
  );

  const settlement = await generateSolanaSettlementRequestV1({
    solanaRpcUrl: "https://rpc.aura.invalid",
    commitmentConfig: "finalized",
    starkProofEnvelope: {
      proofSessionIdHex: proofFixture.proof_session_id_hex,
      stormClaim: stormClaimFromFixture(proofFixture.storm_claim),
      legacyDcmClaim: proofFixture.legacy_dcm_claim,
      authorizationIntent: {
        intentIdHex: intentFixture.intent_id_hex,
        submitProofRequest: {
          programIdBase58: submitFixture.program_id_base58,
          submitterPubkeyBase58: submitFixture.submitter_pubkey_base58,
          challengePubkeyBase58: submitFixture.challenge_pubkey_base58,
          proofHashHex,
        },
      },
    },
  });
  assert.equal(
    JSON.stringify(settlement),
    loadCanonicalPipelineFixtureTextV1("solana_settlement_request_v1.json"),
  );

  const reparsed = await validateSolanaSettlementRequestV1(
    loadCanonicalPipelineFixtureJsonV1<SolanaSettlementRequestWireV1>(
      "solana_settlement_request_v1.json",
    ),
  );
  assert.deepEqual(reparsed, settlement);
});

test("generateSubmitProofRequestV1 rejects uppercase proof hashes without normalization", async () => {
  const fixture = loadCanonicalPipelineFixtureJsonV1<{
    program_id_base58: string;
    submitter_pubkey_base58: string;
    challenge_pubkey_base58: string;
    proof_hash_hex: string;
  }>("submit_proof_request_v1.json");

  await assert.rejects(
    generateSubmitProofRequestV1({
      programIdBase58: fixture.program_id_base58,
      submitterPubkeyBase58: fixture.submitter_pubkey_base58,
      challengePubkeyBase58: fixture.challenge_pubkey_base58,
      proofHashHex: fixture.proof_hash_hex.toUpperCase(),
    }),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "UdotHashNormalizationFailed" &&
      error.cause instanceof UdotHashError &&
      error.cause.code === "NonCanonicalHex",
  );
});

test("canonical pipeline fixture parser rejects alternate wallet peers", () => {
  assert.throws(
    () =>
      parseCanonicalPipelineFixtureJsonV1("submit_proof_request_v1.json", {
        ...loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
          "submit_proof_request_v1.json",
        ),
        seal_line: "forbidden",
      }),
    /submit_proof_request_v1\.json/,
  );
});

test("validateSolanaSettlementRequestV1 requires explicit solana_rpc_url presence", async () => {
  const value = loadCanonicalPipelineFixtureJsonV1<Record<string, unknown>>(
    "solana_settlement_request_v1.json",
  );
  delete value.solana_rpc_url;

  await assert.rejects(
    validateSolanaSettlementRequestV1(value as never),
    (error: unknown) =>
      error instanceof AuraSdkErrorV1 &&
      error.code === "SettlementFieldInvalid" &&
      error.message.includes("solana_rpc_url"),
  );
});

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

function hexLower(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}
