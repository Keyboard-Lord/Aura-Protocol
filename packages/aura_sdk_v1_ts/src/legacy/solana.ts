// Retired Solana submission wires; never canonical v2 authorization input.
import { validateStormClaimV1 } from "../stormClaimV1.ts";
import type { StormClaim521V1 } from "../stormClaimV1.ts";
import { AuraSdkErrorV1, generateWalletVisualV1, validateWalletVisualV1, validatePreparedSubmitProofInputV1, requireCanonicalHashHexV1, requireObjectRecord, requireString, rejectUnknownKeysV1, decodeHexNibbleV1, hexLowerV1, hexToBytes, isWhitespaceCharV1 } from "../sdkCoreV1.ts";
import type { PreparedSubmitProofV1 } from "../sdkCoreV1.ts";
export { prepareBoundProofMaterialV1 as prepareSubmitProofFlowV1 } from "../sdkCoreV1.ts";
export interface GenerateSubmitProofRequestV1 {
  programIdBase58: string;
  submitterPubkeyBase58: string;
  challengePubkeyBase58: string;
  proofHashHex: string;
}

export interface SubmitProofRequestWireV1 {
  program_id_base58: string;
  submitter_pubkey_base58: string;
  challenge_pubkey_base58: string;
  proof_hash_hex: string;
  wallet_visual_v1: string;
}

export interface BuildSubmitProofRequestWireRequestV1 {
  preparedSubmitProof: PreparedSubmitProofV1;
  programIdBase58: string;
  submitterPubkeyBase58: string;
  challengePubkeyBase58: string;
}

export interface GenerateAuthorizationIntentV1 {
  intentIdHex: string;
  submitProofRequest: GenerateSubmitProofRequestV1;
}

export type AuthorizationIntentVersionV1 = "v1";
export type AuthorizationSubjectBindingTypeV1 = "submitter-pubkey-base58";
export type AuthorizationIntentTypeV1 = "opaque-intent-hash-32";
export type AuthorizationFreshnessBindingTypeV1 = "challenge-pubkey-base58";

export interface AuthorizationLineageBindingV1 {
  subject_binding_type: AuthorizationSubjectBindingTypeV1;
  subject_binding: string;
  intent_type: AuthorizationIntentTypeV1;
  intent_commitment_hex: string;
  freshness_binding_type: AuthorizationFreshnessBindingTypeV1;
  freshness_binding: string;
}

export interface AuthorizationIntentEnvelopeV1 {
  intent_version: AuthorizationIntentVersionV1;
  intent_id_hex: string;
  authorization_lineage: AuthorizationLineageBindingV1;
  submit_proof_request: SubmitProofRequestWireV1;
}

export interface GenerateStarkProofEnvelopeV1 {
  proofSessionIdHex: string;
  stormClaim: StormClaim521V1;
  legacyDcmClaim: DcmClaimWireV1;
  authorizationIntent: GenerateAuthorizationIntentV1;
}

export type StarkProofVersionV1 = "v1";

export interface DcmClaimWireV1 {
  iteration_count: number;
  initial_state: string;
  final_state: string;
  commitment_root: string;
}

export interface StormStateWireV1 {
  x_hex_66_be: string;
  y_hex_66_be: string;
}

export interface StormClaimWireV1 {
  version: number;
  modulus_id: number;
  iteration_count: number;
  side_a_hex: string;
  side_b_hex: string;
  context_bytes_hex: string;
  initial_state: StormStateWireV1;
  final_state: StormStateWireV1;
  trace_root_hex: string;
  legacy_commitment_root_hex: string;
  legacy_trace_commitment_hex: string;
}

export interface StarkProofEnvelopeV1 {
  proof_version: StarkProofVersionV1;
  proof_session_id_hex: string;
  storm_claim: StormClaimWireV1;
  legacy_dcm_claim: DcmClaimWireV1;
  authorization_intent: AuthorizationIntentEnvelopeV1;
}

export interface GenerateSolanaSettlementRequestV1 {
  solanaRpcUrl: string | null;
  commitmentConfig: SolanaCommitmentConfigV1;
  starkProofEnvelope: GenerateStarkProofEnvelopeV1;
}

export type SolanaSettlementVersionV1 = "v1";
export type SolanaCommitmentConfigV1 = "processed" | "confirmed" | "finalized";

export interface SolanaSettlementRequestWireV1 {
  settlement_version: SolanaSettlementVersionV1;
  solana_rpc_url: string | null;
  commitment_config: SolanaCommitmentConfigV1;
  stark_proof_envelope: StarkProofEnvelopeV1;
}

export interface BuildSettlementPipelineFromPreparedProofRequestV1 {
  preparedSubmitProof: PreparedSubmitProofV1;
  programIdBase58: string;
  submitterPubkeyBase58: string;
  challengePubkeyBase58: string;
  intentIdHex: string;
  proofSessionIdHex: string;
  stormClaim: StormClaim521V1;
  legacyDcmClaim: DcmClaimWireV1;
  solanaRpcUrl?: string | null | undefined;
  commitmentConfig: SolanaCommitmentConfigV1;
}

export interface SettlementPipelineFromPreparedProofV1 {
  submit_proof_request_wire: SubmitProofRequestWireV1;
  authorization_intent_envelope: AuthorizationIntentEnvelopeV1;
  stark_proof_envelope: StarkProofEnvelopeV1;
  solana_settlement_request_wire: SolanaSettlementRequestWireV1;
}


export async function generateSubmitProofRequestV1(
  request: GenerateSubmitProofRequestV1,
): Promise<SubmitProofRequestWireV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", [
    "programIdBase58",
    "submitterPubkeyBase58",
    "challengePubkeyBase58",
    "proofHashHex",
  ]);

  const proofHashHex = requireCanonicalHashHexV1(
    requireString(requestRecord.proofHashHex, "proofHashHex"),
    "proofHashHex",
  );
  const walletVisualV1 = await generateWalletVisualV1(proofHashHex);

  return validateSubmitProofRequestWireV1({
    program_id_base58: requireString(requestRecord.programIdBase58, "programIdBase58"),
    submitter_pubkey_base58: requireString(
      requestRecord.submitterPubkeyBase58,
      "submitterPubkeyBase58",
    ),
    challenge_pubkey_base58: requireString(
      requestRecord.challengePubkeyBase58,
      "challengePubkeyBase58",
    ),
    proof_hash_hex: proofHashHex,
    wallet_visual_v1: walletVisualV1,
  });
}

export async function validateSubmitProofRequestWireV1(
  payload: SubmitProofRequestWireV1,
): Promise<SubmitProofRequestWireV1> {
  const payloadRecord = requireObjectRecord(payload, "payload");
  rejectUnknownKeysV1(payloadRecord, "payload", [
    "program_id_base58",
    "submitter_pubkey_base58",
    "challenge_pubkey_base58",
    "proof_hash_hex",
    "wallet_visual_v1",
  ]);

  const proofHashHex = requireCanonicalHashHexV1(
    requireString(payloadRecord.proof_hash_hex, "proof_hash_hex"),
    "proof_hash_hex",
  );
  const walletVisualV1 = await validateWalletVisualV1(
    proofHashHex,
    requireString(payloadRecord.wallet_visual_v1, "wallet_visual_v1"),
  );

  return {
    program_id_base58: requireString(payloadRecord.program_id_base58, "program_id_base58"),
    submitter_pubkey_base58: requireString(
      payloadRecord.submitter_pubkey_base58,
      "submitter_pubkey_base58",
    ),
    challenge_pubkey_base58: requireString(
      payloadRecord.challenge_pubkey_base58,
      "challenge_pubkey_base58",
    ),
    proof_hash_hex: proofHashHex,
    wallet_visual_v1: walletVisualV1,
  };
}

export async function buildSubmitProofRequestWireV1(
  request: BuildSubmitProofRequestWireRequestV1,
): Promise<SubmitProofRequestWireV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", [
    "preparedSubmitProof",
    "programIdBase58",
    "submitterPubkeyBase58",
    "challengePubkeyBase58",
  ]);

  const preparedSubmitProof = await validatePreparedSubmitProofInputV1(
    requestRecord.preparedSubmitProof,
  );

  return generateSubmitProofRequestV1({
    programIdBase58: requireString(requestRecord.programIdBase58, "programIdBase58"),
    submitterPubkeyBase58: requireString(
      requestRecord.submitterPubkeyBase58,
      "submitterPubkeyBase58",
    ),
    challengePubkeyBase58: requireString(
      requestRecord.challengePubkeyBase58,
      "challengePubkeyBase58",
    ),
    proofHashHex: hexLowerV1(preparedSubmitProof.proofHash),
  });
}

export async function generateAuthorizationIntentV1(
  request: GenerateAuthorizationIntentV1,
): Promise<AuthorizationIntentEnvelopeV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", ["intentIdHex", "submitProofRequest"]);

  const intentIdHex = requireCanonicalHashHexV1(
    requireString(requestRecord.intentIdHex, "intentIdHex"),
    "intentIdHex",
  );
  const submitProofRequest = await generateSubmitProofRequestV1(
    requestRecord.submitProofRequest as GenerateSubmitProofRequestV1,
  );

  return validateAuthorizationIntentEnvelopeV1({
    intent_version: "v1",
    intent_id_hex: intentIdHex,
    authorization_lineage: {
      subject_binding_type: "submitter-pubkey-base58",
      subject_binding: submitProofRequest.submitter_pubkey_base58,
      intent_type: "opaque-intent-hash-32",
      intent_commitment_hex: intentIdHex,
      freshness_binding_type: "challenge-pubkey-base58",
      freshness_binding: submitProofRequest.challenge_pubkey_base58,
    },
    submit_proof_request: submitProofRequest,
  });
}

export async function validateAuthorizationIntentEnvelopeV1(
  payload: AuthorizationIntentEnvelopeV1,
): Promise<AuthorizationIntentEnvelopeV1> {
  const payloadRecord = requireObjectRecord(payload, "payload");
  rejectUnknownKeysV1(payloadRecord, "payload", [
    "intent_version",
    "intent_id_hex",
    "authorization_lineage",
    "submit_proof_request",
  ]);

  const intentIdHex = requireCanonicalHashHexV1(
    requireString(payloadRecord.intent_id_hex, "intent_id_hex"),
    "intent_id_hex",
  );
  const submitProofRequest = await validateSubmitProofRequestWireV1(
    payloadRecord.submit_proof_request as SubmitProofRequestWireV1,
  );
  const authorizationLineage = validateAuthorizationLineageBindingV1(
    payloadRecord.authorization_lineage,
    intentIdHex,
    submitProofRequest,
  );

  return {
    intent_version: requireAuthorizationIntentVersionV1(
      payloadRecord.intent_version,
      "intent_version",
    ),
    intent_id_hex: intentIdHex,
    authorization_lineage: authorizationLineage,
    submit_proof_request: submitProofRequest,
  };
}

export async function generateStarkProofEnvelopeV1(
  request: GenerateStarkProofEnvelopeV1,
): Promise<StarkProofEnvelopeV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", [
    "proofSessionIdHex",
    "stormClaim",
    "legacyDcmClaim",
    "authorizationIntent",
  ]);

  const proofSessionIdHex = requireCanonicalHashHexV1(
    requireString(requestRecord.proofSessionIdHex, "proofSessionIdHex"),
    "proofSessionIdHex",
  );
  const authorizationIntent = await generateAuthorizationIntentV1(
    requestRecord.authorizationIntent as GenerateAuthorizationIntentV1,
  );
  const stormClaim = normalizeStormClaimWireV1(
    requestRecord.stormClaim as StormClaim521V1,
    "stormClaim",
  );
  const legacyDcmClaim = validateDcmClaimWireV1(
    requestRecord.legacyDcmClaim as DcmClaimWireV1,
    "legacyDcmClaim",
  );
  ensureStormLegacyCompatibilityV1(stormClaim, legacyDcmClaim, "stormClaim");

  return validateStarkProofEnvelopeV1({
    proof_version: "v1",
    proof_session_id_hex: proofSessionIdHex,
    storm_claim: stormClaim,
    legacy_dcm_claim: legacyDcmClaim,
    authorization_intent: authorizationIntent,
  });
}

export async function validateStarkProofEnvelopeV1(
  payload: StarkProofEnvelopeV1,
): Promise<StarkProofEnvelopeV1> {
  const payloadRecord = requireObjectRecord(payload, "payload");
  rejectUnknownKeysV1(payloadRecord, "payload", [
    "proof_version",
    "proof_session_id_hex",
    "storm_claim",
    "legacy_dcm_claim",
    "authorization_intent",
  ]);

  const stormClaim = validateStormClaimWireV1(
    payloadRecord.storm_claim as StormClaimWireV1,
    "storm_claim",
  );
  const legacyDcmClaim = validateDcmClaimWireV1(
    payloadRecord.legacy_dcm_claim as DcmClaimWireV1,
    "legacy_dcm_claim",
  );
  ensureStormLegacyCompatibilityV1(stormClaim, legacyDcmClaim, "storm_claim");

  return {
    proof_version: requireStarkProofVersionV1(payloadRecord.proof_version, "proof_version"),
    proof_session_id_hex: requireCanonicalHashHexV1(
      requireString(payloadRecord.proof_session_id_hex, "proof_session_id_hex"),
      "proof_session_id_hex",
    ),
    storm_claim: stormClaim,
    legacy_dcm_claim: legacyDcmClaim,
    authorization_intent: await validateAuthorizationIntentEnvelopeV1(
      payloadRecord.authorization_intent as AuthorizationIntentEnvelopeV1,
    ),
  };
}

export async function generateSolanaSettlementRequestV1(
  request: GenerateSolanaSettlementRequestV1,
): Promise<SolanaSettlementRequestWireV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", [
    "solanaRpcUrl",
    "commitmentConfig",
    "starkProofEnvelope",
  ]);

  return validateSolanaSettlementRequestV1({
    settlement_version: "v1",
    solana_rpc_url: normalizeSolanaRpcUrlV1(requestRecord.solanaRpcUrl, "solanaRpcUrl"),
    commitment_config: requireSolanaCommitmentConfigV1(
      requestRecord.commitmentConfig,
      "commitmentConfig",
    ),
    stark_proof_envelope: await generateStarkProofEnvelopeV1(
      requestRecord.starkProofEnvelope as GenerateStarkProofEnvelopeV1,
    ),
  });
}

export async function validateSolanaSettlementRequestV1(
  payload: SolanaSettlementRequestWireV1,
): Promise<SolanaSettlementRequestWireV1> {
  const payloadRecord = requireObjectRecord(payload, "payload");
  rejectUnknownKeysV1(payloadRecord, "payload", [
    "settlement_version",
    "solana_rpc_url",
    "commitment_config",
    "stark_proof_envelope",
  ]);

  return {
    settlement_version: requireSolanaSettlementVersionV1(
      payloadRecord.settlement_version,
      "settlement_version",
    ),
    solana_rpc_url: normalizeSolanaRpcUrlV1(payloadRecord.solana_rpc_url, "solana_rpc_url"),
    commitment_config: requireSolanaCommitmentConfigV1(
      payloadRecord.commitment_config,
      "commitment_config",
    ),
    stark_proof_envelope: await validateStarkProofEnvelopeV1(
      payloadRecord.stark_proof_envelope as StarkProofEnvelopeV1,
    ),
  };
}

export async function buildSettlementPipelineFromPreparedProofV1(
  request: BuildSettlementPipelineFromPreparedProofRequestV1,
): Promise<SettlementPipelineFromPreparedProofV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", [
    "preparedSubmitProof",
    "programIdBase58",
    "submitterPubkeyBase58",
    "challengePubkeyBase58",
    "intentIdHex",
    "proofSessionIdHex",
    "stormClaim",
    "legacyDcmClaim",
    "solanaRpcUrl",
    "commitmentConfig",
  ]);

  const submitProofRequestWire = await buildSubmitProofRequestWireV1({
    preparedSubmitProof: requestRecord.preparedSubmitProof as PreparedSubmitProofV1,
    programIdBase58: requireString(requestRecord.programIdBase58, "programIdBase58"),
    submitterPubkeyBase58: requireString(
      requestRecord.submitterPubkeyBase58,
      "submitterPubkeyBase58",
    ),
    challengePubkeyBase58: requireString(
      requestRecord.challengePubkeyBase58,
      "challengePubkeyBase58",
    ),
  });
  const intentIdHex = requireCanonicalHashHexV1(
    requireString(requestRecord.intentIdHex, "intentIdHex"),
    "intentIdHex",
  );
  const authorizationIntentEnvelope = await validateAuthorizationIntentEnvelopeV1({
    intent_version: "v1",
    intent_id_hex: intentIdHex,
    authorization_lineage: {
      subject_binding_type: "submitter-pubkey-base58",
      subject_binding: submitProofRequestWire.submitter_pubkey_base58,
      intent_type: "opaque-intent-hash-32",
      intent_commitment_hex: intentIdHex,
      freshness_binding_type: "challenge-pubkey-base58",
      freshness_binding: submitProofRequestWire.challenge_pubkey_base58,
    },
    submit_proof_request: submitProofRequestWire,
  });
  const starkProofEnvelope = await validateStarkProofEnvelopeV1({
    proof_version: "v1",
    proof_session_id_hex: requireCanonicalHashHexV1(
      requireString(requestRecord.proofSessionIdHex, "proofSessionIdHex"),
      "proofSessionIdHex",
    ),
    storm_claim: normalizeStormClaimWireV1(
      requestRecord.stormClaim as StormClaim521V1,
      "stormClaim",
    ),
    legacy_dcm_claim: validateDcmClaimWireV1(
      requestRecord.legacyDcmClaim as DcmClaimWireV1,
      "legacyDcmClaim",
    ),
    authorization_intent: authorizationIntentEnvelope,
  });
  const solanaSettlementRequestWire = await validateSolanaSettlementRequestV1({
    settlement_version: "v1",
    solana_rpc_url: requestRecord.solanaRpcUrl ?? null,
    commitment_config: requireSolanaCommitmentConfigV1(
      requestRecord.commitmentConfig,
      "commitmentConfig",
    ),
    stark_proof_envelope: starkProofEnvelope,
  });

  return {
    submit_proof_request_wire: submitProofRequestWire,
    authorization_intent_envelope: authorizationIntentEnvelope,
    stark_proof_envelope: starkProofEnvelope,
    solana_settlement_request_wire: solanaSettlementRequestWire,
  };
}


function validateAuthorizationLineageBindingV1(
  value: unknown,
  intentIdHex: string,
  submitProofRequest: SubmitProofRequestWireV1,
): AuthorizationLineageBindingV1 {
  const record = requireObjectRecord(value, "authorization_lineage");
  rejectUnknownKeysV1(record, "authorization_lineage", [
    "subject_binding_type",
    "subject_binding",
    "intent_type",
    "intent_commitment_hex",
    "freshness_binding_type",
    "freshness_binding",
  ]);

  const subjectBinding = requireString(record.subject_binding, "authorization_lineage.subject_binding");
  if (subjectBinding !== submitProofRequest.submitter_pubkey_base58) {
    throw invalidAuthorizationFieldV1(
      "authorization_lineage.subject_binding",
      submitProofRequest.submitter_pubkey_base58,
      subjectBinding,
    );
  }

  const intentCommitmentHex = requireCanonicalHashHexV1(
    requireString(record.intent_commitment_hex, "authorization_lineage.intent_commitment_hex"),
    "authorization_lineage.intent_commitment_hex",
  );
  if (intentCommitmentHex !== intentIdHex) {
    throw invalidAuthorizationFieldV1(
      "authorization_lineage.intent_commitment_hex",
      intentIdHex,
      intentCommitmentHex,
    );
  }

  const freshnessBinding = requireString(
    record.freshness_binding,
    "authorization_lineage.freshness_binding",
  );
  if (freshnessBinding !== submitProofRequest.challenge_pubkey_base58) {
    throw invalidAuthorizationFieldV1(
      "authorization_lineage.freshness_binding",
      submitProofRequest.challenge_pubkey_base58,
      freshnessBinding,
    );
  }

  return {
    subject_binding_type: requireAuthorizationSubjectBindingTypeV1(
      record.subject_binding_type,
      "authorization_lineage.subject_binding_type",
    ),
    subject_binding: submitProofRequest.submitter_pubkey_base58,
    intent_type: requireAuthorizationIntentTypeV1(
      record.intent_type,
      "authorization_lineage.intent_type",
    ),
    intent_commitment_hex: intentIdHex,
    freshness_binding_type: requireAuthorizationFreshnessBindingTypeV1(
      record.freshness_binding_type,
      "authorization_lineage.freshness_binding_type",
    ),
    freshness_binding: submitProofRequest.challenge_pubkey_base58,
  };
}

function validateDcmClaimWireV1(value: unknown, fieldName = "dcm_claim"): DcmClaimWireV1 {
  const record = requireObjectRecord(value, fieldName);
  rejectUnknownKeysV1(record, fieldName, [
    "iteration_count",
    "initial_state",
    "final_state",
    "commitment_root",
  ]);

  return {
    iteration_count: requireU64NumberV1(record.iteration_count, `${fieldName}.iteration_count`),
    initial_state: normalizeDcmStateHexV1(
      requireString(record.initial_state, `${fieldName}.initial_state`),
      `${fieldName}.initial_state`,
    ),
    final_state: normalizeDcmStateHexV1(
      requireString(record.final_state, `${fieldName}.final_state`),
      `${fieldName}.final_state`,
    ),
    commitment_root: requireCanonicalHashHexV1(
      requireString(record.commitment_root, `${fieldName}.commitment_root`),
      `${fieldName}.commitment_root`,
    ),
  };
}

function validateStormClaimWireV1(
  value: unknown,
  fieldName = "storm_claim",
): StormClaimWireV1 {
  const record = requireObjectRecord(value, fieldName);
  rejectUnknownKeysV1(record, fieldName, [
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
  ]);

  const normalized: StormClaimWireV1 = {
    version: requireByteNumberV1(record.version, `${fieldName}.version`),
    modulus_id: requireByteNumberV1(record.modulus_id, `${fieldName}.modulus_id`),
    iteration_count: requireU64NumberV1(record.iteration_count, `${fieldName}.iteration_count`),
    side_a_hex: normalizeFixedHexV1(record.side_a_hex, 110, `${fieldName}.side_a_hex`),
    side_b_hex: normalizeFixedHexV1(record.side_b_hex, 110, `${fieldName}.side_b_hex`),
    context_bytes_hex: normalizeFixedHexV1(
      record.context_bytes_hex,
      209,
      `${fieldName}.context_bytes_hex`,
    ),
    initial_state: validateStormStateWireV1(record.initial_state, `${fieldName}.initial_state`),
    final_state: validateStormStateWireV1(record.final_state, `${fieldName}.final_state`),
    trace_root_hex: requireCanonicalHashHexV1(
      requireString(record.trace_root_hex, `${fieldName}.trace_root_hex`),
      `${fieldName}.trace_root_hex`,
    ),
    legacy_commitment_root_hex: requireCanonicalHashHexV1(
      requireString(record.legacy_commitment_root_hex, `${fieldName}.legacy_commitment_root_hex`),
      `${fieldName}.legacy_commitment_root_hex`,
    ),
    legacy_trace_commitment_hex: requireCanonicalHashHexV1(
      requireString(record.legacy_trace_commitment_hex, `${fieldName}.legacy_trace_commitment_hex`),
      `${fieldName}.legacy_trace_commitment_hex`,
    ),
  };

  validateStormClaimV1(stormClaimFromWireV1(normalized));
  return normalized;
}

function normalizeStormClaimWireV1(
  value: StormClaim521V1,
  fieldName: string,
): StormClaimWireV1 {
  return stormClaimToWireV1(validateStormClaimV1(value), fieldName);
}

function ensureStormLegacyCompatibilityV1(
  stormClaim: StormClaimWireV1,
  legacyDcmClaim: DcmClaimWireV1,
  fieldName: string,
): void {
  if (stormClaim.legacy_commitment_root_hex !== legacyDcmClaim.commitment_root) {
    throw invalidProofFieldV1(
      `${fieldName}.legacy_commitment_root_hex`,
      `must match legacy dcm commitment root ${legacyDcmClaim.commitment_root}`,
    );
  }
}

function validateStormStateWireV1(value: unknown, fieldName: string): StormStateWireV1 {
  const record = requireObjectRecord(value, fieldName);
  rejectUnknownKeysV1(record, fieldName, ["x_hex_66_be", "y_hex_66_be"]);
  return {
    x_hex_66_be: normalizeFieldElementHex66V1(record.x_hex_66_be, `${fieldName}.x_hex_66_be`),
    y_hex_66_be: normalizeFieldElementHex66V1(record.y_hex_66_be, `${fieldName}.y_hex_66_be`),
  };
}

function stormClaimToWireV1(claim: StormClaim521V1, fieldName: string): StormClaimWireV1 {
  return {
    version: requireByteNumberV1(claim.version, `${fieldName}.version`),
    modulus_id: requireByteNumberV1(claim.modulusId, `${fieldName}.modulus_id`),
    iteration_count: requireU64BigIntAsNumberV1(claim.iterationCount, `${fieldName}.iteration_count`),
    side_a_hex: normalizeFixedHexV1(claim.sideAHex, 110, `${fieldName}.side_a_hex`),
    side_b_hex: normalizeFixedHexV1(claim.sideBHex, 110, `${fieldName}.side_b_hex`),
    context_bytes_hex: normalizeFixedHexV1(claim.contextBytesHex, 209, `${fieldName}.context_bytes_hex`),
    initial_state: stormStateToWireV1(claim.initialState, `${fieldName}.initial_state`),
    final_state: stormStateToWireV1(claim.finalState, `${fieldName}.final_state`),
    trace_root_hex: requireCanonicalHashHexV1(claim.traceRootHex, `${fieldName}.trace_root_hex`),
    legacy_commitment_root_hex: requireCanonicalHashHexV1(
      claim.legacyCommitmentRootHex,
      `${fieldName}.legacy_commitment_root_hex`,
    ),
    legacy_trace_commitment_hex: requireCanonicalHashHexV1(
      claim.legacyTraceCommitmentHex,
      `${fieldName}.legacy_trace_commitment_hex`,
    ),
  };
}

function stormClaimFromWireV1(wire: StormClaimWireV1): StormClaim521V1 {
  return {
    version: wire.version,
    modulusId: wire.modulus_id,
    iterationCount: BigInt(wire.iteration_count),
    sideAHex: wire.side_a_hex,
    sideBHex: wire.side_b_hex,
    contextBytesHex: wire.context_bytes_hex,
    initialState: {
      xHex66Be: wire.initial_state.x_hex_66_be,
      yHex66Be: wire.initial_state.y_hex_66_be,
    },
    finalState: {
      xHex66Be: wire.final_state.x_hex_66_be,
      yHex66Be: wire.final_state.y_hex_66_be,
    },
    traceRootHex: wire.trace_root_hex,
    legacyCommitmentRootHex: wire.legacy_commitment_root_hex,
    legacyTraceCommitmentHex: wire.legacy_trace_commitment_hex,
  };
}

function stormStateToWireV1(
  state: { xHex66Be: string; yHex66Be: string },
  fieldName: string,
): StormStateWireV1 {
  return {
    x_hex_66_be: normalizeFieldElementHex66V1(state.xHex66Be, `${fieldName}.x_hex_66_be`),
    y_hex_66_be: normalizeFieldElementHex66V1(state.yHex66Be, `${fieldName}.y_hex_66_be`),
  };
}

function requireAuthorizationIntentVersionV1(
  value: unknown,
  fieldName: string,
): AuthorizationIntentVersionV1 {
  if (value === "v1") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "v1"`);
}

function requireAuthorizationSubjectBindingTypeV1(
  value: unknown,
  fieldName: string,
): AuthorizationSubjectBindingTypeV1 {
  if (value === "submitter-pubkey-base58") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "submitter-pubkey-base58"`);
}

function requireAuthorizationIntentTypeV1(
  value: unknown,
  fieldName: string,
): AuthorizationIntentTypeV1 {
  if (value === "opaque-intent-hash-32") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "opaque-intent-hash-32"`);
}

function requireAuthorizationFreshnessBindingTypeV1(
  value: unknown,
  fieldName: string,
): AuthorizationFreshnessBindingTypeV1 {
  if (value === "challenge-pubkey-base58") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "challenge-pubkey-base58"`);
}

function requireStarkProofVersionV1(value: unknown, fieldName: string): StarkProofVersionV1 {
  if (value === "v1") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "v1"`);
}

function requireSolanaSettlementVersionV1(
  value: unknown,
  fieldName: string,
): SolanaSettlementVersionV1 {
  if (value === "v1") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "v1"`);
}

function requireSolanaCommitmentConfigV1(
  value: unknown,
  fieldName: string,
): SolanaCommitmentConfigV1 {
  if (value === "processed" || value === "confirmed" || value === "finalized") {
    return value;
  }

  throw new TypeError(`${fieldName} must be "processed", "confirmed", or "finalized"`);
}

function requireU64NumberV1(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw invalidProofFieldV1(fieldName, "must be a non-negative safe integer");
  }

  return value;
}

function requireU64BigIntAsNumberV1(value: unknown, fieldName: string): number {
  if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw invalidProofFieldV1(fieldName, "must be a u64 bigint");
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidProofFieldV1(fieldName, "must fit a safe integer for JSON wire encoding");
  }

  return Number(value);
}

function requireByteNumberV1(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xff) {
    throw invalidProofFieldV1(fieldName, "must be a byte value");
  }

  return value;
}

function normalizeFixedHexV1(value: unknown, expectedBytes: number, fieldName: string): string {
  const decoded = decodeCanonicalFixedHexBytesV1(
    requireString(value, fieldName),
    expectedBytes,
    fieldName,
  );
  return hexLowerV1(decoded);
}

function normalizeFieldElementHex66V1(value: unknown, fieldName: string): string {
  const decoded = decodeCanonicalFixedHexBytesV1(
    requireString(value, fieldName),
    FIELD_ELEMENT_521_BYTE_LEN_V1,
    fieldName,
  );
  validateFieldElement521BytesV1(decoded, fieldName);
  return hexLowerV1(decoded);
}

function normalizeDcmStateHexV1(value: string, fieldName: string): string {
  const decoded = decodeCanonicalFixedHexBytesV1(
    value,
    DCM_STATE_521_CANONICAL_BYTE_LEN_V1,
    fieldName,
  );
  validateFieldElement521BytesV1(
    decoded.subarray(0, FIELD_ELEMENT_521_BYTE_LEN_V1),
    fieldName,
  );
  validateFieldElement521BytesV1(
    decoded.subarray(FIELD_ELEMENT_521_BYTE_LEN_V1),
    fieldName,
  );

  return hexLowerV1(decoded);
}

function decodeCanonicalFixedHexBytesV1(
  value: string,
  expectedBytes: number,
  fieldName: string,
): Uint8Array {
  const chars = Array.from(value);
  const expectedChars = expectedBytes * 2;

  if (chars.length !== expectedChars) {
    throw invalidProofFieldV1(
      fieldName,
      `expected ${expectedChars} hex characters, got ${chars.length}`,
    );
  }

  const output = new Uint8Array(expectedBytes);
  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index]!;
    if (isWhitespaceCharV1(char)) {
      throw invalidProofFieldV1(fieldName, `invalid whitespace at index ${index}`);
    }

    if (decodeHexNibbleV1(char) === undefined) {
      throw invalidProofFieldV1(fieldName, `invalid hex character at index ${index}`);
    }
  }

  for (let index = 0; index < expectedBytes; index += 1) {
    const high = decodeHexNibbleV1(chars[index * 2]!) as number;
    const low = decodeHexNibbleV1(chars[index * 2 + 1]!) as number;
    output[index] = (high << 4) | low;
  }

  const canonical = hexLowerV1(output);
  if (value !== canonical) {
    throw invalidProofFieldV1(
      fieldName,
      `expected canonical lowercase hex ${canonical}, got ${value}`,
    );
  }

  return output;
}

function validateFieldElement521BytesV1(bytes: Uint8Array, fieldName: string): void {
  if (bytes.length !== FIELD_ELEMENT_521_BYTE_LEN_V1) {
    throw invalidProofFieldV1(fieldName, "field element byte length mismatch");
  }

  if ((bytes[0] & 0xfe) !== 0) {
    throw invalidProofFieldV1(
      fieldName,
      "invalid top bits: top 7 bits of byte 0 must be zero",
    );
  }

  if (compareBytesLexV1(bytes, FIELD_MODULUS_521_BYTES_V1) >= 0) {
    throw invalidProofFieldV1(fieldName, "field element value out of range");
  }
}

function compareBytesLexV1(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] < right[index]) {
      return -1;
    }
    if (left[index] > right[index]) {
      return 1;
    }
  }

  return 0;
}

function normalizeSolanaRpcUrlV1(value: unknown, fieldName: string): string | null {
  if (value === undefined) {
    throw invalidSettlementFieldV1(
      fieldName,
      "must be present; use null for explicit absence",
    );
  }

  if (value === null) {
    return null;
  }

  if (typeof value !== "string") {
    throw invalidSettlementFieldV1(fieldName, "must be a string or null");
  }

  if (value.length === 0) {
    throw invalidSettlementFieldV1(fieldName, "must not be empty when present");
  }

  for (let index = 0; index < value.length; index += 1) {
    if (isWhitespaceCharV1(value[index]!)) {
      throw invalidSettlementFieldV1(
        fieldName,
        `contains whitespace at index ${index}`,
      );
    }
  }

  return value;
}

function invalidAuthorizationFieldV1(
  field: string,
  expected: string,
  actual: string,
): AuraSdkErrorV1 {
  return new AuraSdkErrorV1(
    "AuthorizationIntentFieldMismatch",
    `authorization intent field ${field} value ${actual} does not match expected ${expected}`,
  );
}

function invalidProofFieldV1(field: string, reason: string): AuraSdkErrorV1 {
  return new AuraSdkErrorV1(
    "ProofEnvelopeFieldInvalid",
    `proof envelope field ${field} invalid: ${reason}`,
  );
}

function invalidSettlementFieldV1(field: string, reason: string): AuraSdkErrorV1 {
  return new AuraSdkErrorV1(
    "SettlementFieldInvalid",
    `settlement field ${field} invalid: ${reason}`,
  );
}


const FIELD_ELEMENT_521_BYTE_LEN_V1 = 66;
const DCM_STATE_521_CANONICAL_BYTE_LEN_V1 = FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;
const FIELD_MODULUS_521_HEX_V1 = `01${"ff".repeat(FIELD_ELEMENT_521_BYTE_LEN_V1 - 1)}`;
const FIELD_MODULUS_521_BYTES_V1 = hexToBytes(FIELD_MODULUS_521_HEX_V1);

