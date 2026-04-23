import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

export type CanonicalPipelineFixtureNameV1 =
  | "submit_proof_request_v1.json"
  | "authorization_intent_v1.json"
  | "stark_proof_envelope_v1.json"
  | "solana_settlement_request_v1.json";

type CanonicalPipelineFixtureValueV1 =
  | SubmitProofRequestFixtureV1
  | AuthorizationIntentFixtureV1
  | StarkProofEnvelopeFixtureV1
  | SolanaSettlementRequestFixtureV1;

type SubmitProofRequestFixtureV1 = {
  program_id_base58: string;
  submitter_pubkey_base58: string;
  challenge_pubkey_base58: string;
  proof_hash_hex: string;
  wallet_visual_v1: string;
};

type AuthorizationLineageFixtureV1 = {
  subject_binding_type: "submitter-pubkey-base58";
  subject_binding: string;
  intent_type: "opaque-intent-hash-32";
  intent_commitment_hex: string;
  freshness_binding_type: "challenge-pubkey-base58";
  freshness_binding: string;
};

type AuthorizationIntentFixtureV1 = {
  intent_version: "v1";
  intent_id_hex: string;
  authorization_lineage: AuthorizationLineageFixtureV1;
  submit_proof_request: SubmitProofRequestFixtureV1;
};

type DcmClaimFixtureV1 = {
  iteration_count: number;
  initial_state: string;
  final_state: string;
  commitment_root: string;
};

type StormStateFixtureV1 = {
  x_hex_66_be: string;
  y_hex_66_be: string;
};

type StormClaimFixtureV1 = {
  version: number;
  modulus_id: number;
  iteration_count: number;
  side_a_hex: string;
  side_b_hex: string;
  context_bytes_hex: string;
  initial_state: StormStateFixtureV1;
  final_state: StormStateFixtureV1;
  trace_root_hex: string;
  legacy_commitment_root_hex: string;
  legacy_trace_commitment_hex: string;
};

type StarkProofEnvelopeFixtureV1 = {
  proof_version: "v1";
  proof_session_id_hex: string;
  storm_claim: StormClaimFixtureV1;
  legacy_dcm_claim: DcmClaimFixtureV1;
  authorization_intent: AuthorizationIntentFixtureV1;
};

type SolanaSettlementRequestFixtureV1 = {
  settlement_version: "v1";
  solana_rpc_url: string | null;
  commitment_config: "processed" | "confirmed" | "finalized";
  stark_proof_envelope: StarkProofEnvelopeFixtureV1;
};

export function loadCanonicalPipelineFixtureTextV1(
  name: CanonicalPipelineFixtureNameV1,
): string {
  return readFileSync(canonicalPipelineFixtureUrlV1(name), "utf8").trimEnd();
}

export function loadCanonicalPipelineFixtureJsonV1<T>(
  name: CanonicalPipelineFixtureNameV1,
): T {
  const text = loadCanonicalPipelineFixtureTextV1(name);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`canonical pipeline fixture ${name} is not valid JSON`, {
      cause: error instanceof Error ? error : undefined,
    });
  }
  return parseCanonicalPipelineFixtureJsonV1(name, parsed) as T;
}

export function parseCanonicalPipelineFixtureJsonV1(
  name: CanonicalPipelineFixtureNameV1,
  value: unknown,
): CanonicalPipelineFixtureValueV1 {
  switch (name) {
    case "submit_proof_request_v1.json":
      return assertSubmitProofRequestFixtureV1(value, name);
    case "authorization_intent_v1.json":
      return assertAuthorizationIntentFixtureV1(value, name);
    case "stark_proof_envelope_v1.json":
      return assertStarkProofEnvelopeFixtureV1(value, name);
    case "solana_settlement_request_v1.json":
      return assertSolanaSettlementRequestFixtureV1(value, name);
    default: {
      const unreachable: never = name;
      throw new Error(`unsupported canonical pipeline fixture: ${unreachable}`);
    }
  }
}

function canonicalPipelineFixtureUrlV1(name: CanonicalPipelineFixtureNameV1): URL {
  return new URL(`../../fixtures/v1/canonical_pipeline_v1/${name}`, import.meta.url);
}

function assertSubmitProofRequestFixtureV1(
  value: unknown,
  label: string,
): SubmitProofRequestFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    [
      "program_id_base58",
      "submitter_pubkey_base58",
      "challenge_pubkey_base58",
      "proof_hash_hex",
      "wallet_visual_v1",
    ],
    label,
  );
  return {
    program_id_base58: stringFieldV1(record, "program_id_base58", label),
    submitter_pubkey_base58: stringFieldV1(record, "submitter_pubkey_base58", label),
    challenge_pubkey_base58: stringFieldV1(record, "challenge_pubkey_base58", label),
    proof_hash_hex: stringFieldV1(record, "proof_hash_hex", label),
    wallet_visual_v1: stringFieldV1(record, "wallet_visual_v1", label),
  };
}

function assertAuthorizationIntentFixtureV1(
  value: unknown,
  label: string,
): AuthorizationIntentFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    ["intent_version", "intent_id_hex", "authorization_lineage", "submit_proof_request"],
    label,
  );
  const intentVersion = stringFieldV1(record, "intent_version", label);
  assert.equal(intentVersion, "v1", `${label}.intent_version`);
  return {
    intent_version: "v1",
    intent_id_hex: stringFieldV1(record, "intent_id_hex", label),
    authorization_lineage: assertAuthorizationLineageFixtureV1(
      record.authorization_lineage,
      `${label}.authorization_lineage`,
    ),
    submit_proof_request: assertSubmitProofRequestFixtureV1(
      record.submit_proof_request,
      `${label}.submit_proof_request`,
    ),
  };
}

function assertAuthorizationLineageFixtureV1(
  value: unknown,
  label: string,
): AuthorizationLineageFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    [
      "subject_binding_type",
      "subject_binding",
      "intent_type",
      "intent_commitment_hex",
      "freshness_binding_type",
      "freshness_binding",
    ],
    label,
  );
  assert.equal(
    stringFieldV1(record, "subject_binding_type", label),
    "submitter-pubkey-base58",
    `${label}.subject_binding_type`,
  );
  assert.equal(
    stringFieldV1(record, "intent_type", label),
    "opaque-intent-hash-32",
    `${label}.intent_type`,
  );
  assert.equal(
    stringFieldV1(record, "freshness_binding_type", label),
    "challenge-pubkey-base58",
    `${label}.freshness_binding_type`,
  );
  return {
    subject_binding_type: "submitter-pubkey-base58",
    subject_binding: stringFieldV1(record, "subject_binding", label),
    intent_type: "opaque-intent-hash-32",
    intent_commitment_hex: stringFieldV1(record, "intent_commitment_hex", label),
    freshness_binding_type: "challenge-pubkey-base58",
    freshness_binding: stringFieldV1(record, "freshness_binding", label),
  };
}

function assertStarkProofEnvelopeFixtureV1(
  value: unknown,
  label: string,
): StarkProofEnvelopeFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    [
      "proof_version",
      "proof_session_id_hex",
      "storm_claim",
      "legacy_dcm_claim",
      "authorization_intent",
    ],
    label,
  );
  const proofVersion = stringFieldV1(record, "proof_version", label);
  assert.equal(proofVersion, "v1", `${label}.proof_version`);
  return {
    proof_version: "v1",
    proof_session_id_hex: stringFieldV1(record, "proof_session_id_hex", label),
    storm_claim: assertStormClaimFixtureV1(record.storm_claim, `${label}.storm_claim`),
    legacy_dcm_claim: assertDcmClaimFixtureV1(
      record.legacy_dcm_claim,
      `${label}.legacy_dcm_claim`,
    ),
    authorization_intent: assertAuthorizationIntentFixtureV1(
      record.authorization_intent,
      `${label}.authorization_intent`,
    ),
  };
}

function assertStormClaimFixtureV1(value: unknown, label: string): StormClaimFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    [
      "version",
      "modulus_id",
      "iteration_count",
      "side_a_hex",
      "side_b_hex",
      "context_bytes_hex",
      "initial_state",
      "final_state",
      "trace_root_hex",
      "legacy_commitment_root_hex",
      "legacy_trace_commitment_hex",
    ],
    label,
  );
  return {
    version: numberFieldV1(record, "version", label),
    modulus_id: numberFieldV1(record, "modulus_id", label),
    iteration_count: numberFieldV1(record, "iteration_count", label),
    side_a_hex: stringFieldV1(record, "side_a_hex", label),
    side_b_hex: stringFieldV1(record, "side_b_hex", label),
    context_bytes_hex: stringFieldV1(record, "context_bytes_hex", label),
    initial_state: assertStormStateFixtureV1(record.initial_state, `${label}.initial_state`),
    final_state: assertStormStateFixtureV1(record.final_state, `${label}.final_state`),
    trace_root_hex: stringFieldV1(record, "trace_root_hex", label),
    legacy_commitment_root_hex: stringFieldV1(record, "legacy_commitment_root_hex", label),
    legacy_trace_commitment_hex: stringFieldV1(record, "legacy_trace_commitment_hex", label),
  };
}

function assertStormStateFixtureV1(value: unknown, label: string): StormStateFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(record, ["x_hex_66_be", "y_hex_66_be"], label);
  return {
    x_hex_66_be: stringFieldV1(record, "x_hex_66_be", label),
    y_hex_66_be: stringFieldV1(record, "y_hex_66_be", label),
  };
}

function assertDcmClaimFixtureV1(value: unknown, label: string): DcmClaimFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    ["iteration_count", "initial_state", "final_state", "commitment_root"],
    label,
  );
  return {
    iteration_count: numberFieldV1(record, "iteration_count", label),
    initial_state: stringFieldV1(record, "initial_state", label),
    final_state: stringFieldV1(record, "final_state", label),
    commitment_root: stringFieldV1(record, "commitment_root", label),
  };
}

function assertSolanaSettlementRequestFixtureV1(
  value: unknown,
  label: string,
): SolanaSettlementRequestFixtureV1 {
  const record = objectRecordV1(value, label);
  assertExactKeysV1(
    record,
    ["settlement_version", "solana_rpc_url", "commitment_config", "stark_proof_envelope"],
    label,
  );
  const settlementVersion = stringFieldV1(record, "settlement_version", label);
  assert.equal(settlementVersion, "v1", `${label}.settlement_version`);
  const solanaRpcUrl = record.solana_rpc_url;
  assert.ok(
    typeof solanaRpcUrl === "string" || solanaRpcUrl === null,
    `${label}.solana_rpc_url`,
  );
  const commitmentConfig = stringFieldV1(record, "commitment_config", label);
  assert.ok(
    commitmentConfig === "processed" ||
      commitmentConfig === "confirmed" ||
      commitmentConfig === "finalized",
    `${label}.commitment_config`,
  );
  return {
    settlement_version: "v1",
    solana_rpc_url: solanaRpcUrl,
    commitment_config: commitmentConfig,
    stark_proof_envelope: assertStarkProofEnvelopeFixtureV1(
      record.stark_proof_envelope,
      `${label}.stark_proof_envelope`,
    ),
  };
}

function objectRecordV1(value: unknown, label: string): Record<string, unknown> {
  assert.ok(typeof value === "object" && value !== null && !Array.isArray(value), label);
  return value as Record<string, unknown>;
}

function assertExactKeysV1(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
  label: string,
): void {
  const keys = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  assert.deepEqual(keys, expected, label);
}

function stringFieldV1(
  record: Record<string, unknown>,
  field: string,
  label: string,
): string {
  const value = record[field];
  assert.equal(typeof value, "string", `${label}.${field}`);
  return value;
}

function numberFieldV1(
  record: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = record[field];
  assert.equal(typeof value, "number", `${label}.${field}`);
  assert.ok(Number.isFinite(value), `${label}.${field}`);
  return value;
}
