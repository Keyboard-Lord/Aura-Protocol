//! Shared byte-level proof preparation and UDOT implementation.
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

export async function prepareBoundProofMaterialV1(
  subjectBindingBytes: Uint8Array,
  freshnessBindingBytes: Uint8Array,
  proofBlobBytes: Uint8Array,
  publicInputsBytes: Uint8Array,
  verificationKeyBytes: Uint8Array,
): Promise<PreparedSubmitProofV1> {
  const subjectBinding = copyBytes32("subjectBindingBytes", subjectBindingBytes);
  const challengeBinding = copyBytes32(
    "freshnessBindingBytes",
    freshnessBindingBytes,
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

/** Legacy Solana preparation adapter; canonical code uses the binding-oriented entry. */


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

export async function validatePreparedSubmitProofInputV1(
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

export function requireCanonicalHashHexV1(value: string, fieldName: string): string {
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

export function requireObjectRecord(
  value: unknown,
  name: string,
): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    throw new TypeError(`${name} must be an object`);
  }

  return value as Record<string, unknown>;
}

export function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }

  return value;
}

export function rejectUnknownKeysV1(
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

export function decodeHexNibbleV1(value: string): number | undefined {
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

export function hexLowerV1(bytes: Uint8Array): string {
  return bytesToHexLowerV1(bytes);
}

export function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
}

export function isWhitespaceCharV1(value: string): boolean {
  return /^\s$/u.test(value);
}

// Successor canonical authorization; the v1 account-bound APIs above are legacy.

