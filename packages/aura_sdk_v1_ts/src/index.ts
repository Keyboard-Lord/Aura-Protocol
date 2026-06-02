// Active canonical protocol surfaces (AURA_HASH_V2)
export * from "./stormHash521V1.ts";
export * from "./stormContextV1.ts";
export * from "./stormStateV1.ts";
export * from "./stormExecutionV1.ts";
export * from "./stormTraceCommitmentV1.ts";
export * from "./stormClaimV1.ts";
export * from "./auraHashReaderV1.ts";
export * from "./stormEncryptionBindingV1.ts";
export * from "./sessionKeyV1.ts";
export * from "./sessionEncryptionContextV1.ts";
export * from "./symmetricEnvelopeV1.ts";

/**
 * Legacy protocol interfaces for historical compatibility only.
 * 
 * These implement deprecated protocol versions and are NOT part of the active
 * canonical protocol. Active implementations MUST use the storm_* surfaces.
 * 
 * @deprecated Use the storm_* surfaces (AURA_HASH_V2) instead.
 */
export * as legacy from "./legacy/index.ts";

import { validateStormClaimV1 } from "./stormClaimV1.ts";
import type { StormClaim521V1 } from "./stormClaimV1.ts";

const textEncoder = new TextEncoder();

const PROOF_MATERIAL_VERSION_V1 = 1;
const PROOF_MATERIAL_TYPE_CANONICAL_VERIFIER_BUNDLE_V1 = 0x0001;
const PROOF_MATERIAL_DOMAIN_SEPARATOR_V1 = textEncoder.encode("AURA_PROOF_MATERIAL_V1");

const FRACTAL_KEY_VERSION_V1 = 1;
const FRACTAL_COMPONENT_COUNT_V1 = 3;
const FRACTAL_COMPONENT_TYPE_SUBJECT_BINDING_V1 = 0x0001;
const FRACTAL_COMPONENT_TYPE_CHALLENGE_BINDING_V1 = 0x0002;
const FRACTAL_COMPONENT_TYPE_PROOF_MATERIAL_HASH_V1 = 0x0003;
const FRACTAL_KEY_DOMAIN_SEPARATOR_V1 = textEncoder.encode("AURA_FRACTAL_KEY_V1");
const FRACTAL_COMPONENT_ORDERED_TYPES_V1 = [
  FRACTAL_COMPONENT_TYPE_SUBJECT_BINDING_V1,
  FRACTAL_COMPONENT_TYPE_CHALLENGE_BINDING_V1,
  FRACTAL_COMPONENT_TYPE_PROOF_MATERIAL_HASH_V1,
] as const;

const AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_UDOT_SEAL_LINE_V1",
);
const AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1 = textEncoder.encode("AURA_UDOT_SEAL_V1");
const AURA_UDOT_MATRIX_DOMAIN_SEPARATOR_V1 = textEncoder.encode("AURA_UDOT_MATRIX_V1");

const FIELD_ELEMENT_521_BYTE_LEN_V1 = 66;
const DCM_STATE_521_CANONICAL_BYTE_LEN_V1 = FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;
const FIELD_MODULUS_521_HEX_V1 = `01${"ff".repeat(FIELD_ELEMENT_521_BYTE_LEN_V1 - 1)}`;
const FIELD_MODULUS_521_BYTES_V1 = hexToBytes(FIELD_MODULUS_521_HEX_V1);

const UDOT_V1_GLYPHS = ["∘", "•", "∙", "⟡", "◦", "◎", "○", "◌"] as const;
const UDOT_V2_GLYPHS = [
  "◦",
  "◌",
  "∘",
  "○",
  "⟡",
  "◎",
  "•",
  "∙",
  "◈",
  "◇",
  "◆",
  "ㅁ",
  "■",
  "□",
  "▣",
  "▤",
] as const;

export interface ProofMaterialV1 {
  proofMaterialVersion: number;
  proofMaterialType: number;
  proofBlobHash: Uint8Array;
  publicInputsHash: Uint8Array;
  verificationKeyHash: Uint8Array;
}

export interface FractalComponentV1 {
  componentType: number;
  payload32: Uint8Array;
}

export interface FractalKeyV1 {
  fractalKeyVersion: number;
  componentCount: number;
  components: [FractalComponentV1, FractalComponentV1, FractalComponentV1];
}

export interface PreparedSubmitProofV1 {
  proofMaterial: ProofMaterialV1;
  proofMaterialHash: Uint8Array;
  fractalKey: FractalKeyV1;
  proofHash: Uint8Array;
}

export type UdotVersion = "v2" | "v1-legacy";
export type UdotArtifactKind =
  | "seal-line"
  | "crest"
  | "matrix-sequence"
  | "matrix-form";

export interface GenerateUdotArtifactsRequestV1 {
  udotVersion: UdotVersion;
  auraHashHex: string;
}

export interface ParseUdotArtifactRequestV1 {
  udotVersion: UdotVersion;
  artifactKind: UdotArtifactKind;
  serializedArtifact: string;
}

export interface ValidateUdotArtifactRequestV1 {
  udotVersion: UdotVersion;
  artifactKind: UdotArtifactKind;
  auraHashHex: string;
  serializedArtifact: string;
}

export interface UdotArtifactEnvelopeV1 {
  udotVersion: UdotVersion;
  artifactKind: UdotArtifactKind;
  serializedArtifact: string;
}

export interface GeneratedUdotArtifactsV1 {
  udotVersion: UdotVersion;
  auraHashHex: string;
  sealLine: UdotArtifactEnvelopeV1;
  crest: UdotArtifactEnvelopeV1;
  matrixSequence?: UdotArtifactEnvelopeV1;
  matrixForm?: UdotArtifactEnvelopeV1;
}

export interface GenerateUdotArtifactBundleWireRequestV1 {
  udot_version: UdotVersion;
  aura_hash_hex: string;
}

export interface UdotArtifactWireV1 {
  udot_version: UdotVersion;
  artifact_kind: UdotArtifactKind;
  value: string;
}

export type UdotArtifactBundleWireV1 =
  | {
      udot_version: "v1-legacy";
      aura_hash_hex: string;
      seal_line: string;
      crest: string;
    }
  | {
      udot_version: "v2";
      aura_hash_hex: string;
      seal_line: string;
      crest: string;
      matrix_sequence: string;
      matrix_form: string;
    };

export interface ValidateUdotArtifactWireRequestV1 {
  udot_version: UdotVersion;
  artifact_kind: UdotArtifactKind;
  aura_hash_hex: string;
  value: string;
}

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

type ProofMaterialV1ErrorCode =
  | "InvalidVersion"
  | "InvalidProofMaterialType"
  | "ProofBlobHashMismatch"
  | "PublicInputsHashMismatch"
  | "VerificationKeyHashMismatch"
  | "ProofMaterialHashMismatch";

type FractalKeyV1ErrorCode =
  | "InvalidVersion"
  | "InvalidComponentCount"
  | "MissingComponent"
  | "DuplicateComponent"
  | "UnexpectedComponentType"
  | "InvalidComponentOrder"
  | "SubjectBindingMismatch"
  | "ChallengeBindingMismatch"
  | "ProofMaterialHashMismatch"
  | "ProofHashMismatch";

type AuraSdkErrorCode =
  | "ProofMaterialVerificationFailed"
  | "SubmitProofPreparationFailed"
  | "UdotHashNormalizationFailed"
  | "UdotArtifactParseFailed"
  | "UdotArtifactValidationFailed"
  | "UdotBundleHashMismatch"
  | "AuthorizationIntentFieldMismatch"
  | "ProofEnvelopeFieldInvalid"
  | "SettlementFieldInvalid";

type UdotHashErrorCode =
  | "InvalidLength"
  | "InvalidWhitespace"
  | "InvalidCharacter"
  | "NonCanonicalHex";

type UdotParseErrorCode =
  | "UnsupportedArtifactForVersion"
  | "InvalidLength"
  | "InvalidWhitespace"
  | "InvalidGlyph"
  | "InvalidMatrixRowCount"
  | "InvalidMatrixRowLength";

type UdotValidationErrorCode = "Parse" | "Mismatch";

export class ProofMaterialV1Error extends Error {
  readonly code: ProofMaterialV1ErrorCode;

  constructor(code: ProofMaterialV1ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ProofMaterialV1Error";
    this.code = code;
  }
}

export class FractalKeyV1Error extends Error {
  readonly code: FractalKeyV1ErrorCode;

  constructor(code: FractalKeyV1ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "FractalKeyV1Error";
    this.code = code;
  }
}

export class SubmitProofIntegrationErrorV1 extends Error {
  readonly code = "VerificationFailed";

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SubmitProofIntegrationErrorV1";
  }
}

export class AuraSdkErrorV1 extends Error {
  readonly code: AuraSdkErrorCode;

  constructor(code: AuraSdkErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuraSdkErrorV1";
    this.code = code;
  }
}

export class UdotHashError extends Error {
  readonly code: UdotHashErrorCode;
  readonly expected?: number | string;
  readonly actual?: number | string;
  readonly index?: number;
  readonly value?: string;

  constructor(
    code: UdotHashErrorCode,
    message: string,
    details: {
      expected?: number | string;
      actual?: number | string;
      index?: number;
      value?: string;
    } = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "UdotHashError";
    this.code = code;
    this.expected = details.expected;
    this.actual = details.actual;
    this.index = details.index;
    this.value = details.value;
  }
}

export class UdotParseError extends Error {
  readonly code: UdotParseErrorCode;
  readonly udotVersion?: UdotVersion;
  readonly artifactKind?: UdotArtifactKind;
  readonly expected?: number;
  readonly actual?: number;
  readonly index?: number;
  readonly value?: string;
  readonly row?: number;

  constructor(
    code: UdotParseErrorCode,
    message: string,
    details: {
      udotVersion?: UdotVersion;
      artifactKind?: UdotArtifactKind;
      expected?: number;
      actual?: number;
      index?: number;
      value?: string;
      row?: number;
    } = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "UdotParseError";
    this.code = code;
    this.udotVersion = details.udotVersion;
    this.artifactKind = details.artifactKind;
    this.expected = details.expected;
    this.actual = details.actual;
    this.index = details.index;
    this.value = details.value;
    this.row = details.row;
  }
}

export class UdotValidationError extends Error {
  readonly code: UdotValidationErrorCode;
  readonly udotVersion?: UdotVersion;
  readonly artifactKind?: UdotArtifactKind;
  readonly expected?: string;
  readonly actual?: string;

  constructor(
    code: UdotValidationErrorCode,
    message: string,
    details: {
      udotVersion?: UdotVersion;
      artifactKind?: UdotArtifactKind;
      expected?: string;
      actual?: string;
    } = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "UdotValidationError";
    this.code = code;
    this.udotVersion = details.udotVersion;
    this.artifactKind = details.artifactKind;
    this.expected = details.expected;
    this.actual = details.actual;
  }
}

export async function prepareSubmitProofFlowV1(
  subjectPubkeyBytes: Uint8Array,
  challengeAccountPubkeyBytes: Uint8Array,
  proofBlobBytes: Uint8Array,
  publicInputsBytes: Uint8Array,
  verificationKeyBytes: Uint8Array,
): Promise<PreparedSubmitProofV1> {
  const subjectBinding = copyBytes32("subjectPubkeyBytes", subjectPubkeyBytes);
  const challengeBinding = copyBytes32(
    "challengeAccountPubkeyBytes",
    challengeAccountPubkeyBytes,
  );

  const proofMaterial = await buildProofMaterialV1(
    proofBlobBytes,
    publicInputsBytes,
    verificationKeyBytes,
  );
  const proofMaterialHash = await proofMaterialHashV1(proofMaterial);

  try {
    await verifyProofMaterialV1(
      proofMaterial,
      proofBlobBytes,
      publicInputsBytes,
      verificationKeyBytes,
      proofMaterialHash,
    );
  } catch (error) {
    throw new AuraSdkErrorV1(
      "ProofMaterialVerificationFailed",
      `proof material verification failed: ${messageFromError(error)}`,
      { cause: error },
    );
  }

  try {
    const preparation = await prepareSubmitProofV1(
      subjectBinding,
      challengeBinding,
      proofMaterialHash,
    );

    return {
      proofMaterial,
      proofMaterialHash,
      fractalKey: preparation.fractalKey,
      proofHash: preparation.proofHash,
    };
  } catch (error) {
    throw new AuraSdkErrorV1(
      "SubmitProofPreparationFailed",
      `submit-proof preparation failed: ${messageFromError(error)}`,
      { cause: error },
    );
  }
}

export async function generateUdotArtifactsV1(
  request: GenerateUdotArtifactsRequestV1,
): Promise<GeneratedUdotArtifactsV1> {
  const requestRecord = requireObjectRecord(request, "request");
  const udotVersion = requireUdotVersion(
    requestRecord.udotVersion,
    "udotVersion",
  );
  const auraHashHex = requireCanonicalHashHexV1(
    requireString(requestRecord.auraHashHex, "auraHashHex"),
    "auraHashHex",
  );
  const normalizedHash = normalizeUdotHashHexV1(auraHashHex);

  if (udotVersion === "v1-legacy") {
    const legacy = await deriveUdotLegacyV1(normalizedHash.bytes);
    return {
      udotVersion,
      auraHashHex: normalizedHash.hexLower,
      sealLine: artifactEnvelopeV1(udotVersion, "seal-line", legacy.sealLine),
      crest: artifactEnvelopeV1(udotVersion, "crest", legacy.crest),
    };
  }

  const active = await deriveUdotV2(normalizedHash.bytes);
  return {
    udotVersion,
    auraHashHex: normalizedHash.hexLower,
    sealLine: artifactEnvelopeV1(udotVersion, "seal-line", active.sealLine),
    crest: artifactEnvelopeV1(udotVersion, "crest", active.crest),
    matrixSequence: artifactEnvelopeV1(
      udotVersion,
      "matrix-sequence",
      active.matrixSequence,
    ),
    matrixForm: artifactEnvelopeV1(udotVersion, "matrix-form", active.matrixForm),
  };
}

export function parseUdotArtifactV1(
  request: ParseUdotArtifactRequestV1,
): UdotArtifactEnvelopeV1 {
  const requestRecord = requireObjectRecord(request, "request");
  const udotVersion = requireUdotVersion(
    requestRecord.udotVersion,
    "udotVersion",
  );
  const artifactKind = requireUdotArtifactKind(
    requestRecord.artifactKind,
    "artifactKind",
  );
  const serializedArtifact = requireString(
    requestRecord.serializedArtifact,
    "serializedArtifact",
  );

  try {
    parseUdotArtifactCanonicalV1(udotVersion, artifactKind, serializedArtifact);
  } catch (error) {
    throw new AuraSdkErrorV1(
      "UdotArtifactParseFailed",
      `udot artifact parse failed: ${messageFromError(error)}`,
      { cause: error },
    );
  }

  return artifactEnvelopeV1(udotVersion, artifactKind, serializedArtifact);
}

export async function validateUdotArtifactV1(
  request: ValidateUdotArtifactRequestV1,
): Promise<UdotArtifactEnvelopeV1> {
  const requestRecord = requireObjectRecord(request, "request");
  const udotVersion = requireUdotVersion(
    requestRecord.udotVersion,
    "udotVersion",
  );
  const artifactKind = requireUdotArtifactKind(
    requestRecord.artifactKind,
    "artifactKind",
  );
  const auraHashHex = requireCanonicalHashHexV1(
    requireString(requestRecord.auraHashHex, "auraHashHex"),
    "auraHashHex",
  );
  const serializedArtifact = requireString(
    requestRecord.serializedArtifact,
    "serializedArtifact",
  );
  const normalizedHash = normalizeUdotHashHexV1(auraHashHex);

  try {
    parseUdotArtifactCanonicalV1(udotVersion, artifactKind, serializedArtifact);

    const expected = await expectedUdotArtifactV1(
      udotVersion,
      artifactKind,
      normalizedHash.bytes,
    );

    if (serializedArtifact !== expected.serializedArtifact) {
      throw new UdotValidationError(
        "Mismatch",
        `${formatArtifactKindMessageV1(artifactKind)} mismatch for ${formatUdotVersionMessageV1(udotVersion)}: expected ${JSON.stringify(expected.serializedArtifact)}, got ${JSON.stringify(serializedArtifact)}`,
        {
          udotVersion,
          artifactKind,
          expected: expected.serializedArtifact,
          actual: serializedArtifact,
        },
      );
    }

    return artifactEnvelopeV1(udotVersion, artifactKind, serializedArtifact);
  } catch (error) {
    const wrapped =
      error instanceof UdotValidationError
        ? error
        : new UdotValidationError("Parse", messageFromError(error), {}, { cause: error });

    throw new AuraSdkErrorV1(
      "UdotArtifactValidationFailed",
      `udot artifact validation failed: ${wrapped.message}`,
      { cause: wrapped },
    );
  }
}

export async function generateUdotArtifactBundleWireV1(
  request: GenerateUdotArtifactBundleWireRequestV1,
): Promise<UdotArtifactBundleWireV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", ["udot_version", "aura_hash_hex"]);
  const udotVersion = requireUdotVersion(requestRecord.udot_version, "udot_version");
  const auraHashHex = requireString(requestRecord.aura_hash_hex, "aura_hash_hex");

  const generated = await generateUdotArtifactsV1({
    udotVersion,
    auraHashHex,
  });

  return artifactBundleWireV1(generated);
}

export function parseUdotArtifactWireV1(
  payload: UdotArtifactWireV1,
): UdotArtifactWireV1 {
  const payloadRecord = requireObjectRecord(payload, "payload");
  rejectUnknownKeysV1(payloadRecord, "payload", ["udot_version", "artifact_kind", "value"]);
  const udotVersion = requireUdotVersion(payloadRecord.udot_version, "udot_version");
  const artifactKind = requireUdotArtifactKind(payloadRecord.artifact_kind, "artifact_kind");
  const value = requireString(payloadRecord.value, "value");
  const parsed = parseUdotArtifactV1({
    udotVersion,
    artifactKind,
    serializedArtifact: value,
  });

  return artifactWireV1(parsed.udotVersion, parsed.artifactKind, parsed.serializedArtifact);
}

export function parseUdotArtifactBundleWireV1(
  payload: UdotArtifactBundleWireV1,
): UdotArtifactBundleWireV1 {
  const payloadRecord = requireObjectRecord(payload, "payload");
  const udotVersion = requireUdotVersion(payloadRecord.udot_version, "udot_version");

  switch (udotVersion) {
    case "v1-legacy": {
      rejectUnknownKeysV1(payloadRecord, "payload", [
        "udot_version",
        "aura_hash_hex",
        "seal_line",
        "crest",
      ]);
      const auraHashHex = requireCanonicalHashHexV1(
        requireString(payloadRecord.aura_hash_hex, "aura_hash_hex"),
        "aura_hash_hex",
      );
      const sealLine = parseUdotArtifactV1({
        udotVersion,
        artifactKind: "seal-line",
        serializedArtifact: requireString(payloadRecord.seal_line, "seal_line"),
      }).serializedArtifact;
      const crest = parseUdotArtifactV1({
        udotVersion,
        artifactKind: "crest",
        serializedArtifact: requireString(payloadRecord.crest, "crest"),
      }).serializedArtifact;

      return {
        udot_version: udotVersion,
        aura_hash_hex: auraHashHex,
        seal_line: sealLine,
        crest,
      };
    }
    case "v2": {
      rejectUnknownKeysV1(payloadRecord, "payload", [
        "udot_version",
        "aura_hash_hex",
        "seal_line",
        "crest",
        "matrix_sequence",
        "matrix_form",
      ]);
      const auraHashHex = requireCanonicalHashHexV1(
        requireString(payloadRecord.aura_hash_hex, "aura_hash_hex"),
        "aura_hash_hex",
      );
      const sealLine = parseUdotArtifactV1({
        udotVersion,
        artifactKind: "seal-line",
        serializedArtifact: requireString(payloadRecord.seal_line, "seal_line"),
      }).serializedArtifact;
      const crest = parseUdotArtifactV1({
        udotVersion,
        artifactKind: "crest",
        serializedArtifact: requireString(payloadRecord.crest, "crest"),
      }).serializedArtifact;
      const matrixSequence = parseUdotArtifactV1({
        udotVersion,
        artifactKind: "matrix-sequence",
        serializedArtifact: requireString(payloadRecord.matrix_sequence, "matrix_sequence"),
      }).serializedArtifact;
      const matrixForm = parseUdotArtifactV1({
        udotVersion,
        artifactKind: "matrix-form",
        serializedArtifact: requireString(payloadRecord.matrix_form, "matrix_form"),
      }).serializedArtifact;

      return {
        udot_version: udotVersion,
        aura_hash_hex: auraHashHex,
        seal_line: sealLine,
        crest,
        matrix_sequence: matrixSequence,
        matrix_form: matrixForm,
      };
    }
  }
}

export async function validateUdotArtifactWireV1(
  request: ValidateUdotArtifactWireRequestV1,
): Promise<UdotArtifactWireV1> {
  const requestRecord = requireObjectRecord(request, "request");
  rejectUnknownKeysV1(requestRecord, "request", [
    "udot_version",
    "artifact_kind",
    "aura_hash_hex",
    "value",
  ]);
  const udotVersion = requireUdotVersion(requestRecord.udot_version, "udot_version");
  const artifactKind = requireUdotArtifactKind(requestRecord.artifact_kind, "artifact_kind");
  const auraHashHex = requireString(requestRecord.aura_hash_hex, "aura_hash_hex");
  const value = requireString(requestRecord.value, "value");

  const validated = await validateUdotArtifactV1({
    udotVersion,
    artifactKind,
    auraHashHex,
    serializedArtifact: value,
  });

  return artifactWireV1(
    validated.udotVersion,
    validated.artifactKind,
    validated.serializedArtifact,
  );
}

export async function validateUdotArtifactBundleWireV1(
  payload: UdotArtifactBundleWireV1,
  expectedAuraHashHex: string,
): Promise<UdotArtifactBundleWireV1> {
  const canonicalExpectedAuraHashHex = requireCanonicalHashHexV1(
    expectedAuraHashHex,
    "expectedAuraHashHex",
  );
  const bundle = parseUdotArtifactBundleWireV1(payload);

  if (bundle.aura_hash_hex !== canonicalExpectedAuraHashHex) {
    throw new AuraSdkErrorV1(
      "UdotBundleHashMismatch",
      `udot bundle aura_hash_hex ${bundle.aura_hash_hex} does not match expected aura_hash_hex ${canonicalExpectedAuraHashHex}`,
    );
  }

  if (bundle.udot_version === "v1-legacy") {
    return {
      udot_version: "v1-legacy",
      aura_hash_hex: bundle.aura_hash_hex,
      seal_line: (
        await validateUdotArtifactWireV1({
          udot_version: "v1-legacy",
          artifact_kind: "seal-line",
          aura_hash_hex: bundle.aura_hash_hex,
          value: bundle.seal_line,
        })
      ).value,
      crest: (
        await validateUdotArtifactWireV1({
          udot_version: "v1-legacy",
          artifact_kind: "crest",
          aura_hash_hex: bundle.aura_hash_hex,
          value: bundle.crest,
        })
      ).value,
    };
  }

  return {
    udot_version: "v2",
    aura_hash_hex: bundle.aura_hash_hex,
    seal_line: (
      await validateUdotArtifactWireV1({
        udot_version: "v2",
        artifact_kind: "seal-line",
        aura_hash_hex: bundle.aura_hash_hex,
        value: bundle.seal_line,
      })
    ).value,
    crest: (
      await validateUdotArtifactWireV1({
        udot_version: "v2",
        artifact_kind: "crest",
        aura_hash_hex: bundle.aura_hash_hex,
        value: bundle.crest,
      })
    ).value,
    matrix_sequence: (
      await validateUdotArtifactWireV1({
        udot_version: "v2",
        artifact_kind: "matrix-sequence",
        aura_hash_hex: bundle.aura_hash_hex,
        value: bundle.matrix_sequence,
      })
    ).value,
    matrix_form: (
      await validateUdotArtifactWireV1({
        udot_version: "v2",
        artifact_kind: "matrix-form",
        aura_hash_hex: bundle.aura_hash_hex,
        value: bundle.matrix_form,
      })
    ).value,
  };
}

export async function generateWalletVisualV1(proofHashHex: string): Promise<string> {
  const canonicalProofHashHex = requireCanonicalHashHexV1(proofHashHex, "proofHashHex");
  return deriveWalletVisualV1(normalizeUdotHashHexV1(canonicalProofHashHex).bytes);
}

export function parseWalletVisualV1(walletVisualV1: string): string {
  return parseUdotArtifactV1({
    udotVersion: "v2",
    artifactKind: "matrix-form",
    serializedArtifact: walletVisualV1,
  }).serializedArtifact;
}

export async function validateWalletVisualV1(
  proofHashHex: string,
  walletVisualV1: string,
): Promise<string> {
  return (
    await validateUdotArtifactV1({
      udotVersion: "v2",
      artifactKind: "matrix-form",
      auraHashHex: proofHashHex,
      serializedArtifact: walletVisualV1,
    })
  ).serializedArtifact;
}

export function proofHashHexFromWalletVisualV1(walletVisualV1: string): string {
  return hexLowerV1(decodeWalletVisualToBytesV1(walletVisualV1));
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

async function buildProofMaterialV1(
  proofBlobBytes: Uint8Array,
  publicInputsBytes: Uint8Array,
  verificationKeyBytes: Uint8Array,
): Promise<ProofMaterialV1> {
  const [proofBlobHash, publicInputsHash, verificationKeyHash] = await Promise.all([
    sha256Bytes(copyBytes(proofBlobBytes, "proofBlobBytes")),
    sha256Bytes(copyBytes(publicInputsBytes, "publicInputsBytes")),
    sha256Bytes(copyBytes(verificationKeyBytes, "verificationKeyBytes")),
  ]);

  return {
    proofMaterialVersion: PROOF_MATERIAL_VERSION_V1,
    proofMaterialType: PROOF_MATERIAL_TYPE_CANONICAL_VERIFIER_BUNDLE_V1,
    proofBlobHash,
    publicInputsHash,
    verificationKeyHash,
  };
}

async function proofMaterialHashV1(proofMaterial: ProofMaterialV1): Promise<Uint8Array> {
  return sha256Bytes(proofMaterialCanonicalBytes(proofMaterial));
}

async function verifyProofMaterialV1(
  proofMaterial: ProofMaterialV1,
  proofBlobBytes: Uint8Array,
  publicInputsBytes: Uint8Array,
  verificationKeyBytes: Uint8Array,
  expectedProofMaterialHash: Uint8Array,
): Promise<Uint8Array> {
  verifyProofMaterialStructure(proofMaterial);

  const [proofBlobHash, publicInputsHash, verificationKeyHash] = await Promise.all([
    sha256Bytes(copyBytes(proofBlobBytes, "proofBlobBytes")),
    sha256Bytes(copyBytes(publicInputsBytes, "publicInputsBytes")),
    sha256Bytes(copyBytes(verificationKeyBytes, "verificationKeyBytes")),
  ]);

  if (!bytesEqual(proofMaterial.proofBlobHash, proofBlobHash)) {
    throw new ProofMaterialV1Error(
      "ProofBlobHashMismatch",
      "proof blob hash mismatch",
    );
  }

  if (!bytesEqual(proofMaterial.publicInputsHash, publicInputsHash)) {
    throw new ProofMaterialV1Error(
      "PublicInputsHashMismatch",
      "public inputs hash mismatch",
    );
  }

  if (!bytesEqual(proofMaterial.verificationKeyHash, verificationKeyHash)) {
    throw new ProofMaterialV1Error(
      "VerificationKeyHashMismatch",
      "verification key hash mismatch",
    );
  }

  const recomputedProofMaterialHash = await proofMaterialHashV1(proofMaterial);
  if (!bytesEqual(recomputedProofMaterialHash, expectedProofMaterialHash)) {
    throw new ProofMaterialV1Error(
      "ProofMaterialHashMismatch",
      "proof material hash mismatch",
    );
  }

  return recomputedProofMaterialHash;
}

function verifyProofMaterialStructure(proofMaterial: ProofMaterialV1): void {
  if (proofMaterial.proofMaterialVersion !== PROOF_MATERIAL_VERSION_V1) {
    throw new ProofMaterialV1Error(
      "InvalidVersion",
      `invalid version: expected ${PROOF_MATERIAL_VERSION_V1}, got ${proofMaterial.proofMaterialVersion}`,
    );
  }

  if (
    proofMaterial.proofMaterialType !== PROOF_MATERIAL_TYPE_CANONICAL_VERIFIER_BUNDLE_V1
  ) {
    throw new ProofMaterialV1Error(
      "InvalidProofMaterialType",
      `invalid proof material type: expected ${formatU16Hex(PROOF_MATERIAL_TYPE_CANONICAL_VERIFIER_BUNDLE_V1)}, got ${formatU16Hex(proofMaterial.proofMaterialType)}`,
    );
  }
}

async function prepareSubmitProofV1(
  subjectPubkeyBytes: Uint8Array,
  challengeAccountPubkeyBytes: Uint8Array,
  proofMaterialHash: Uint8Array,
): Promise<{ fractalKey: FractalKeyV1; proofHash: Uint8Array }> {
  const fractalKey = buildFractalKeyV1(
    subjectPubkeyBytes,
    challengeAccountPubkeyBytes,
    proofMaterialHash,
  );
  const proofHash = await proofHashV1(fractalKey);

  await verifyPreSubmitV1(
    fractalKey,
    subjectPubkeyBytes,
    challengeAccountPubkeyBytes,
    proofMaterialHash,
    proofHash,
  );

  return {
    fractalKey,
    proofHash,
  };
}

function buildFractalKeyV1(
  subjectBinding: Uint8Array,
  challengeBinding: Uint8Array,
  proofMaterialHash: Uint8Array,
): FractalKeyV1 {
  return {
    fractalKeyVersion: FRACTAL_KEY_VERSION_V1,
    componentCount: FRACTAL_COMPONENT_COUNT_V1,
    components: [
      {
        componentType: FRACTAL_COMPONENT_TYPE_SUBJECT_BINDING_V1,
        payload32: copyBytes32("subjectBinding", subjectBinding),
      },
      {
        componentType: FRACTAL_COMPONENT_TYPE_CHALLENGE_BINDING_V1,
        payload32: copyBytes32("challengeBinding", challengeBinding),
      },
      {
        componentType: FRACTAL_COMPONENT_TYPE_PROOF_MATERIAL_HASH_V1,
        payload32: copyBytes32("proofMaterialHash", proofMaterialHash),
      },
    ],
  };
}

async function proofHashV1(fractalKey: FractalKeyV1): Promise<Uint8Array> {
  return sha256Bytes(fractalKeyCanonicalBytes(fractalKey));
}

async function validatePreparedSubmitProofInputV1(
  value: unknown,
): Promise<PreparedSubmitProofV1> {
  const record = requireObjectRecord(value, "preparedSubmitProof");
  rejectUnknownKeysV1(record, "preparedSubmitProof", [
    "proofMaterial",
    "proofMaterialHash",
    "fractalKey",
    "proofHash",
  ]);

  try {
    const proofMaterialRecord = requireObjectRecord(
      record.proofMaterial,
      "preparedSubmitProof.proofMaterial",
    );
    rejectUnknownKeysV1(
      proofMaterialRecord,
      "preparedSubmitProof.proofMaterial",
      [
        "proofMaterialVersion",
        "proofMaterialType",
        "proofBlobHash",
        "publicInputsHash",
        "verificationKeyHash",
      ],
    );
    const proofMaterial: ProofMaterialV1 = {
      proofMaterialVersion: proofMaterialRecord.proofMaterialVersion as number,
      proofMaterialType: proofMaterialRecord.proofMaterialType as number,
      proofBlobHash: copyBytes32(
        "preparedSubmitProof.proofMaterial.proofBlobHash",
        proofMaterialRecord.proofBlobHash as Uint8Array,
      ),
      publicInputsHash: copyBytes32(
        "preparedSubmitProof.proofMaterial.publicInputsHash",
        proofMaterialRecord.publicInputsHash as Uint8Array,
      ),
      verificationKeyHash: copyBytes32(
        "preparedSubmitProof.proofMaterial.verificationKeyHash",
        proofMaterialRecord.verificationKeyHash as Uint8Array,
      ),
    };
    verifyProofMaterialStructure(proofMaterial);

    const proofMaterialHash = copyBytes32(
      "preparedSubmitProof.proofMaterialHash",
      record.proofMaterialHash as Uint8Array,
    );
    const recomputedProofMaterialHash = await proofMaterialHashV1(proofMaterial);
    if (!bytesEqual(recomputedProofMaterialHash, proofMaterialHash)) {
      throw new ProofMaterialV1Error(
        "ProofMaterialHashMismatch",
        "proof material hash mismatch",
      );
    }

    const fractalKeyRecord = requireObjectRecord(
      record.fractalKey,
      "preparedSubmitProof.fractalKey",
    );
    rejectUnknownKeysV1(fractalKeyRecord, "preparedSubmitProof.fractalKey", [
      "fractalKeyVersion",
      "componentCount",
      "components",
    ]);
    if (!Array.isArray(fractalKeyRecord.components) || fractalKeyRecord.components.length !== 3) {
      throw new FractalKeyV1Error(
        "InvalidComponentCount",
        `invalid component count: expected ${FRACTAL_COMPONENT_COUNT_V1}, got ${Array.isArray(fractalKeyRecord.components) ? fractalKeyRecord.components.length : "non-array"}`,
      );
    }

    const components = fractalKeyRecord.components.map((component, index) => {
      const componentRecord = requireObjectRecord(
        component,
        `preparedSubmitProof.fractalKey.components[${index}]`,
      );
      rejectUnknownKeysV1(
        componentRecord,
        `preparedSubmitProof.fractalKey.components[${index}]`,
        ["componentType", "payload32"],
      );

      return {
        componentType: componentRecord.componentType as number,
        payload32: copyBytes32(
          `preparedSubmitProof.fractalKey.components[${index}].payload32`,
          componentRecord.payload32 as Uint8Array,
        ),
      };
    }) as [FractalComponentV1, FractalComponentV1, FractalComponentV1];

    const fractalKey: FractalKeyV1 = {
      fractalKeyVersion: fractalKeyRecord.fractalKeyVersion as number,
      componentCount: fractalKeyRecord.componentCount as number,
      components,
    };
    const proofHash = copyBytes32("preparedSubmitProof.proofHash", record.proofHash as Uint8Array);

    await verifyFractalKeyV1(
      fractalKey,
      fractalKey.components[0].payload32,
      fractalKey.components[1].payload32,
      proofMaterialHash,
      proofHash,
    );

    return {
      proofMaterial,
      proofMaterialHash,
      fractalKey,
      proofHash,
    };
  } catch (error) {
    throw new AuraSdkErrorV1(
      "SubmitProofPreparationFailed",
      `preparedSubmitProof invalid: ${messageFromError(error)}`,
      { cause: error },
    );
  }
}

async function verifyPreSubmitV1(
  fractalKey: FractalKeyV1,
  subjectPubkeyBytes: Uint8Array,
  challengeAccountPubkeyBytes: Uint8Array,
  proofMaterialHash: Uint8Array,
  expectedProofHash: Uint8Array,
): Promise<void> {
  try {
    await verifyFractalKeyV1(
      fractalKey,
      subjectPubkeyBytes,
      challengeAccountPubkeyBytes,
      proofMaterialHash,
      expectedProofHash,
    );
  } catch (error) {
    throw new SubmitProofIntegrationErrorV1(
      `fractal key verification failed: ${messageFromError(error)}`,
      { cause: error },
    );
  }
}

async function verifyFractalKeyV1(
  fractalKey: FractalKeyV1,
  expectedSubjectBinding: Uint8Array,
  expectedChallengeBinding: Uint8Array,
  expectedProofMaterialHash: Uint8Array,
  expectedProofHash: Uint8Array,
): Promise<Uint8Array> {
  verifyFractalKeyStructure(fractalKey);

  if (!bytesEqual(fractalKey.components[0].payload32, expectedSubjectBinding)) {
    throw new FractalKeyV1Error(
      "SubjectBindingMismatch",
      "subject binding mismatch",
    );
  }

  if (!bytesEqual(fractalKey.components[1].payload32, expectedChallengeBinding)) {
    throw new FractalKeyV1Error(
      "ChallengeBindingMismatch",
      "challenge binding mismatch",
    );
  }

  if (!bytesEqual(fractalKey.components[2].payload32, expectedProofMaterialHash)) {
    throw new FractalKeyV1Error(
      "ProofMaterialHashMismatch",
      "proof-material hash mismatch",
    );
  }

  const recomputedProofHash = await proofHashV1(fractalKey);
  if (!bytesEqual(recomputedProofHash, expectedProofHash)) {
    throw new FractalKeyV1Error("ProofHashMismatch", "proof hash mismatch");
  }

  return recomputedProofHash;
}

function verifyFractalKeyStructure(fractalKey: FractalKeyV1): void {
  if (fractalKey.fractalKeyVersion !== FRACTAL_KEY_VERSION_V1) {
    throw new FractalKeyV1Error(
      "InvalidVersion",
      `invalid version: expected ${FRACTAL_KEY_VERSION_V1}, got ${fractalKey.fractalKeyVersion}`,
    );
  }

  if (fractalKey.componentCount !== FRACTAL_COMPONENT_COUNT_V1) {
    throw new FractalKeyV1Error(
      "InvalidComponentCount",
      `invalid component count: expected ${FRACTAL_COMPONENT_COUNT_V1}, got ${fractalKey.componentCount}`,
    );
  }

  const seen = new Map<number, number>();
  for (const component of fractalKey.components) {
    if (!FRACTAL_COMPONENT_ORDERED_TYPES_V1.includes(component.componentType as never)) {
      throw new FractalKeyV1Error(
        "UnexpectedComponentType",
        `unexpected component type: ${formatU16Hex(component.componentType)}`,
      );
    }

    seen.set(component.componentType, (seen.get(component.componentType) ?? 0) + 1);
  }

  for (const componentType of FRACTAL_COMPONENT_ORDERED_TYPES_V1) {
    const seenCount = seen.get(componentType) ?? 0;

    if (seenCount === 0) {
      throw new FractalKeyV1Error(
        "MissingComponent",
        `missing required component: ${formatU16Hex(componentType)}`,
      );
    }

    if (seenCount > 1) {
      throw new FractalKeyV1Error(
        "DuplicateComponent",
        `duplicate component: ${formatU16Hex(componentType)}`,
      );
    }
  }

  fractalKey.components.forEach((component, index) => {
    if (component.componentType !== FRACTAL_COMPONENT_ORDERED_TYPES_V1[index]) {
      throw new FractalKeyV1Error(
        "InvalidComponentOrder",
        "invalid component order",
      );
    }
  });
}

function proofMaterialCanonicalBytes(proofMaterial: ProofMaterialV1): Uint8Array {
  return concatBytes(
    PROOF_MATERIAL_DOMAIN_SEPARATOR_V1,
    Uint8Array.of(proofMaterial.proofMaterialVersion),
    u16ToLeBytes(proofMaterial.proofMaterialType),
    proofMaterial.proofBlobHash,
    proofMaterial.publicInputsHash,
    proofMaterial.verificationKeyHash,
  );
}

function fractalKeyCanonicalBytes(fractalKey: FractalKeyV1): Uint8Array {
  return concatBytes(
    FRACTAL_KEY_DOMAIN_SEPARATOR_V1,
    Uint8Array.of(fractalKey.fractalKeyVersion, fractalKey.componentCount),
    fractalComponentCanonicalBytes(fractalKey.components[0]),
    fractalComponentCanonicalBytes(fractalKey.components[1]),
    fractalComponentCanonicalBytes(fractalKey.components[2]),
  );
}

function fractalComponentCanonicalBytes(component: FractalComponentV1): Uint8Array {
  return concatBytes(u16ToLeBytes(component.componentType), component.payload32);
}

async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

function copyBytes32(name: string, bytes: Uint8Array): Uint8Array {
  assertUint8Array(name, bytes);

  if (bytes.length !== 32) {
    throw new RangeError(`${name} must be exactly 32 bytes`);
  }

  return new Uint8Array(bytes);
}

function copyBytes(bytes: Uint8Array, name = "bytes"): Uint8Array {
  assertUint8Array(name, bytes);
  return new Uint8Array(bytes);
}

function assertUint8Array(name: string, bytes: Uint8Array): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);

  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }

  return output;
}

function u16ToLeBytes(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff, (value >> 8) & 0xff);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }

  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }

  return true;
}

function formatU16Hex(value: number): string {
  return `0x${value.toString(16).padStart(4, "0")}`;
}

function messageFromError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function requireCanonicalHashHexV1(value: string, fieldName: string): string {
  let normalized: NormalizedUdotHashV1;

  try {
    normalized = normalizeUdotHashHexV1(value);
  } catch (error) {
    throw new AuraSdkErrorV1(
      "UdotHashNormalizationFailed",
      `udot hash normalization failed: ${messageFromError(error)}`,
      { cause: error },
    );
  }

  if (value !== normalized.hexLower) {
    const error = new UdotHashError(
      "NonCanonicalHex",
      `${fieldName} must be canonical lowercase 64-hex: expected ${normalized.hexLower}, got ${value}`,
      { expected: normalized.hexLower, actual: value },
    );
    throw new AuraSdkErrorV1(
      "UdotHashNormalizationFailed",
      `udot hash normalization failed: ${error.message}`,
      { cause: error },
    );
  }

  return normalized.hexLower;
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

type NormalizedUdotHashV1 = {
  bytes: Uint8Array;
  hexLower: string;
};

type DerivedUdotLegacyV1 = {
  sealLine: string;
  crest: string;
};

type DerivedUdotV2 = {
  sealLine: string;
  crest: string;
  matrixSequence: string;
  matrixForm: string;
};

function requireObjectRecord(
  value: unknown,
  name: string,
): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    throw new TypeError(`${name} must be an object`);
  }

  return value as Record<string, unknown>;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }

  return value;
}

function rejectUnknownKeysV1(
  record: Record<string, unknown>,
  name: string,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys);

  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new TypeError(`${name} contains unexpected field ${JSON.stringify(key)}`);
    }
  }
}

function requireUdotVersion(value: unknown, name: string): UdotVersion {
  if (value === "v2" || value === "v1-legacy") {
    return value;
  }

  throw new TypeError(`${name} must be "v2" or "v1-legacy"`);
}

function requireUdotArtifactKind(
  value: unknown,
  name: string,
): UdotArtifactKind {
  if (
    value === "seal-line" ||
    value === "crest" ||
    value === "matrix-sequence" ||
    value === "matrix-form"
  ) {
    return value;
  }

  throw new TypeError(
    `${name} must be "seal-line", "crest", "matrix-sequence", or "matrix-form"`,
  );
}

function artifactEnvelopeV1(
  udotVersion: UdotVersion,
  artifactKind: UdotArtifactKind,
  serializedArtifact: string,
): UdotArtifactEnvelopeV1 {
  return {
    udotVersion,
    artifactKind,
    serializedArtifact,
  };
}

function artifactWireV1(
  udotVersion: UdotVersion,
  artifactKind: UdotArtifactKind,
  value: string,
): UdotArtifactWireV1 {
  return {
    udot_version: udotVersion,
    artifact_kind: artifactKind,
    value,
  };
}

function artifactBundleWireV1(
  generated: GeneratedUdotArtifactsV1,
): UdotArtifactBundleWireV1 {
  if (generated.udotVersion === "v1-legacy") {
    return {
      udot_version: generated.udotVersion,
      aura_hash_hex: generated.auraHashHex,
      seal_line: generated.sealLine.serializedArtifact,
      crest: generated.crest.serializedArtifact,
    };
  }

  return {
    udot_version: generated.udotVersion,
    aura_hash_hex: generated.auraHashHex,
    seal_line: generated.sealLine.serializedArtifact,
    crest: generated.crest.serializedArtifact,
    matrix_sequence: generated.matrixSequence!.serializedArtifact,
    matrix_form: generated.matrixForm!.serializedArtifact,
  };
}

function normalizeUdotWireHashHexV1(auraHashHex: string): string {
  try {
    return normalizeUdotHashHexV1(auraHashHex).hexLower;
  } catch (error) {
    throw new AuraSdkErrorV1(
      "UdotHashNormalizationFailed",
      `udot hash normalization failed: ${messageFromError(error)}`,
      { cause: error },
    );
  }
}

function normalizeUdotHashHexV1(input: string): NormalizedUdotHashV1 {
  const chars = Array.from(input);

  for (let index = 0; index < chars.length; index += 1) {
    const value = chars[index]!;

    if (isWhitespaceCharV1(value)) {
      throw new UdotHashError(
        "InvalidWhitespace",
        `invalid Aura hash whitespace at index ${index}: ${JSON.stringify(value)}`,
        { index, value },
      );
    }

    if (decodeHexNibbleV1(value) === undefined) {
      throw new UdotHashError(
        "InvalidCharacter",
        `invalid Aura hash character at index ${index}: ${JSON.stringify(value)}`,
        { index, value },
      );
    }
  }

  if (chars.length !== 64) {
    throw new UdotHashError(
      "InvalidLength",
      `invalid Aura hash text length: expected 64, got ${chars.length}`,
      { expected: 64, actual: chars.length },
    );
  }

  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    const high = decodeHexNibbleV1(chars[index * 2]!);
    const low = decodeHexNibbleV1(chars[index * 2 + 1]!);
    bytes[index] = ((high as number) << 4) | (low as number);
  }

  return {
    bytes,
    hexLower: bytesToHexLowerV1(bytes),
  };
}

function parseUdotArtifactCanonicalV1(
  udotVersion: UdotVersion,
  artifactKind: UdotArtifactKind,
  serializedArtifact: string,
): void {
  switch (udotVersion) {
    case "v1-legacy":
      switch (artifactKind) {
        case "seal-line":
          parseSequenceV1(udotVersion, artifactKind, serializedArtifact, 16, UDOT_V1_GLYPHS);
          return;
        case "crest":
          parseSequenceV1(udotVersion, artifactKind, serializedArtifact, 8, UDOT_V1_GLYPHS);
          return;
        default:
          throw unsupportedArtifactForVersionErrorV1(udotVersion, artifactKind);
      }
    case "v2":
      switch (artifactKind) {
        case "seal-line":
          parseSequenceV1(udotVersion, artifactKind, serializedArtifact, 16, UDOT_V2_GLYPHS);
          return;
        case "crest":
          parseSequenceV1(udotVersion, artifactKind, serializedArtifact, 8, UDOT_V2_GLYPHS);
          return;
        case "matrix-sequence":
          parseSequenceV1(udotVersion, artifactKind, serializedArtifact, 64, UDOT_V2_GLYPHS);
          return;
        case "matrix-form":
          parseMatrixFormV1(serializedArtifact);
          return;
      }
  }
}

function parseSequenceV1(
  udotVersion: UdotVersion,
  artifactKind: UdotArtifactKind,
  input: string,
  expectedLength: number,
  allowedGlyphs: readonly string[],
): void {
  const chars = Array.from(input);
  if (chars.length !== expectedLength) {
    throw new UdotParseError(
      "InvalidLength",
      `invalid ${formatArtifactKindMessageV1(artifactKind)} length for ${formatUdotVersionMessageV1(udotVersion)}: expected ${expectedLength}, got ${chars.length}`,
      {
        udotVersion,
        artifactKind,
        expected: expectedLength,
        actual: chars.length,
      },
    );
  }

  for (let index = 0; index < chars.length; index += 1) {
    const value = chars[index]!;

    if (isWhitespaceCharV1(value)) {
      throw new UdotParseError(
        "InvalidWhitespace",
        `invalid whitespace in ${formatArtifactKindMessageV1(artifactKind)} for ${formatUdotVersionMessageV1(udotVersion)} at index ${index}: ${JSON.stringify(value)}`,
        { udotVersion, artifactKind, index, value },
      );
    }

    if (!allowedGlyphs.includes(value)) {
      throw new UdotParseError(
        "InvalidGlyph",
        `invalid glyph in ${formatArtifactKindMessageV1(artifactKind)} for ${formatUdotVersionMessageV1(udotVersion)} at index ${index}: ${JSON.stringify(value)}`,
        { udotVersion, artifactKind, index, value },
      );
    }
  }
}

function parseMatrixFormV1(input: string): void {
  const chars = Array.from(input);

  for (let index = 0; index < chars.length; index += 1) {
    const value = chars[index]!;
    if (isWhitespaceCharV1(value) && value !== "\n") {
      throw new UdotParseError(
        "InvalidWhitespace",
        `invalid whitespace in matrix_form for ${formatUdotVersionMessageV1("v2")} at index ${index}: ${JSON.stringify(value)}`,
        {
          udotVersion: "v2",
          artifactKind: "matrix-form",
          index,
          value,
        },
      );
    }
  }

  const rows = input.split("\n");
  if (rows.length !== 8) {
    throw new UdotParseError(
      "InvalidMatrixRowCount",
      `invalid matrix_form row count: expected 8, got ${rows.length}`,
      { expected: 8, actual: rows.length },
    );
  }

  for (let rowIndex = 0; rowIndex < rows.length; rowIndex += 1) {
    const row = rows[rowIndex]!;
    const glyphs = Array.from(row);
    if (glyphs.length !== 8) {
      throw new UdotParseError(
        "InvalidMatrixRowLength",
        `invalid matrix_form row length at row ${rowIndex}: expected 8, got ${glyphs.length}`,
        { row: rowIndex, expected: 8, actual: glyphs.length },
      );
    }

    for (let columnIndex = 0; columnIndex < glyphs.length; columnIndex += 1) {
      const value = glyphs[columnIndex]!;
      if (!UDOT_V2_GLYPHS.includes(value)) {
        throw new UdotParseError(
          "InvalidGlyph",
          `invalid glyph in matrix_form for ${formatUdotVersionMessageV1("v2")} at index ${rowIndex * 9 + columnIndex}: ${JSON.stringify(value)}`,
          {
            udotVersion: "v2",
            artifactKind: "matrix-form",
            index: rowIndex * 9 + columnIndex,
            value,
          },
        );
      }
    }
  }
}

async function expectedUdotArtifactV1(
  udotVersion: UdotVersion,
  artifactKind: UdotArtifactKind,
  auraHashBytes: Uint8Array,
): Promise<UdotArtifactEnvelopeV1> {
  if (udotVersion === "v1-legacy") {
    const legacy = await deriveUdotLegacyV1(auraHashBytes);
    switch (artifactKind) {
      case "seal-line":
        return artifactEnvelopeV1(udotVersion, artifactKind, legacy.sealLine);
      case "crest":
        return artifactEnvelopeV1(udotVersion, artifactKind, legacy.crest);
      default:
        throw unsupportedArtifactForVersionErrorV1(udotVersion, artifactKind);
    }
  }

  const active = await deriveUdotV2(auraHashBytes);
  switch (artifactKind) {
    case "seal-line":
      return artifactEnvelopeV1(udotVersion, artifactKind, active.sealLine);
    case "crest":
      return artifactEnvelopeV1(udotVersion, artifactKind, active.crest);
    case "matrix-sequence":
      return artifactEnvelopeV1(udotVersion, artifactKind, active.matrixSequence);
    case "matrix-form":
      return artifactEnvelopeV1(udotVersion, artifactKind, active.matrixForm);
  }
}

async function deriveUdotLegacyV1(
  auraHashBytes: Uint8Array,
): Promise<DerivedUdotLegacyV1> {
  const lineDigest = await sha256Bytes(
    concatBytes(AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1, auraHashBytes),
  );
  const crestDigest = await sha256Bytes(
    concatBytes(AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1, auraHashBytes),
  );

  return {
    sealLine: mapTripletsToV1Glyphs(lineDigest, 16),
    crest: mapTripletsToV1Glyphs(crestDigest, 8),
  };
}

async function deriveUdotV2(auraHashBytes: Uint8Array): Promise<DerivedUdotV2> {
  const lineDigest = await sha256Bytes(
    concatBytes(AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1, auraHashBytes),
  );
  const crestDigest = await sha256Bytes(
    concatBytes(AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1, auraHashBytes),
  );
  const matrixSequence = mapNibblesToV2Glyphs(auraHashBytes, 64);

  return {
    sealLine: mapNibblesToV2Glyphs(lineDigest, 16),
    crest: mapNibblesToV2Glyphs(crestDigest, 8),
    matrixSequence,
    matrixForm: matrixFormFromSequenceV1(matrixSequence),
  };
}

function deriveWalletVisualV1(auraHashBytes: Uint8Array): string {
  return matrixFormFromSequenceV1(mapNibblesToV2Glyphs(auraHashBytes, 64));
}

function mapTripletsToV1Glyphs(digest: Uint8Array, groupCount: number): string {
  let output = "";

  for (let groupIndex = 0; groupIndex < groupCount; groupIndex += 1) {
    let value = 0;
    const startBit = groupIndex * 3;

    for (let offset = 0; offset < 3; offset += 1) {
      const bitIndex = startBit + offset;
      const byte = digest[Math.floor(bitIndex / 8)]!;
      const shift = 7 - (bitIndex % 8);
      value = (value << 1) | ((byte >> shift) & 0x01);
    }

    output += UDOT_V1_GLYPHS[value]!;
  }

  return output;
}

function mapNibblesToV2Glyphs(digest: Uint8Array, glyphCount: number): string {
  let output = "";

  for (let glyphIndex = 0; glyphIndex < glyphCount; glyphIndex += 1) {
    const byte = digest[Math.floor(glyphIndex / 2)]!;
    const nibble = glyphIndex % 2 === 0 ? byte >> 4 : byte & 0x0f;
    output += UDOT_V2_GLYPHS[nibble]!;
  }

  return output;
}

function matrixFormFromSequenceV1(sequence: string): string {
  const glyphs = Array.from(sequence);
  const rows: string[] = [];

  for (let rowIndex = 0; rowIndex < 8; rowIndex += 1) {
    rows.push(glyphs.slice(rowIndex * 8, rowIndex * 8 + 8).join(""));
  }

  return rows.join("\n");
}

function decodeWalletVisualToBytesV1(walletVisualV1: string): Uint8Array {
  parseUdotArtifactCanonicalV1("v2", "matrix-form", walletVisualV1);
  const matrixSequence = walletVisualV1.split("\n").join("");
  const output = new Uint8Array(32);

  for (let index = 0; index < matrixSequence.length; index += 1) {
    const glyph = matrixSequence[index]!;
    const nibble = UDOT_V2_GLYPHS.indexOf(glyph as (typeof UDOT_V2_GLYPHS)[number]);

    if (nibble < 0) {
      throw new UdotParseError(
        "InvalidGlyph",
        `invalid glyph in matrix_form for ${formatUdotVersionMessageV1("v2")} at index ${index}: ${JSON.stringify(glyph)}`,
        { udotVersion: "v2", artifactKind: "matrix-form", index, value: glyph },
      );
    }

    const byteIndex = Math.floor(index / 2);
    if (index % 2 === 0) {
      output[byteIndex] = nibble << 4;
    } else {
      output[byteIndex] |= nibble;
    }
  }

  return output;
}

function unsupportedArtifactForVersionErrorV1(
  udotVersion: UdotVersion,
  artifactKind: UdotArtifactKind,
): UdotParseError {
  return new UdotParseError(
    "UnsupportedArtifactForVersion",
    `${formatArtifactKindMessageV1(artifactKind)} is not defined for ${formatUdotVersionMessageV1(udotVersion)}`,
    { udotVersion, artifactKind },
  );
}

function formatUdotVersionMessageV1(udotVersion: UdotVersion): string {
  switch (udotVersion) {
    case "v2":
      return "UDOT V2";
    case "v1-legacy":
      return "UDOT V1 legacy";
  }
}

function formatArtifactKindMessageV1(artifactKind: UdotArtifactKind): string {
  switch (artifactKind) {
    case "seal-line":
      return "seal_line";
    case "crest":
      return "crest";
    case "matrix-sequence":
      return "matrix_sequence";
    case "matrix-form":
      return "matrix_form";
  }
}

function decodeHexNibbleV1(value: string): number | undefined {
  if (value >= "0" && value <= "9") {
    return value.charCodeAt(0) - 0x30;
  }

  if (value >= "a" && value <= "f") {
    return value.charCodeAt(0) - 0x61 + 10;
  }

  if (value >= "A" && value <= "F") {
    return value.charCodeAt(0) - 0x41 + 10;
  }

  return undefined;
}

function bytesToHexLowerV1(bytes: Uint8Array): string {
  let output = "";

  for (const byte of bytes) {
    output += byte.toString(16).padStart(2, "0");
  }

  return output;
}

function hexLowerV1(bytes: Uint8Array): string {
  return bytesToHexLowerV1(bytes);
}

function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
}

function isWhitespaceCharV1(value: string): boolean {
  return /^\s$/u.test(value);
}
