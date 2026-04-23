import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
} from "node:crypto";
import {
  parseWalletVisualV1,
  proofHashHexFromWalletVisualV1,
  type SubmitProofRequestWireV1,
} from "../../aura_sdk_v1_ts/src/index.ts";

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_MAP = new Map(
  Array.from(BASE58_ALPHABET, (char, index) => [char, index] as const),
);

const textEncoder = new TextEncoder();

const PROOF_RECORD_SEED_V1 = textEncoder.encode("proof-record");
const PROGRAM_DERIVED_ADDRESS_MARKER_V1 = textEncoder.encode("ProgramDerivedAddress");
const SUBMIT_PROOF_TAG_V1 = 2;

const SYSTEM_PROGRAM_ID_V1 = new Uint8Array(32);
const CLOCK_SYSVAR_ID_V1 = decodeBase58("SysvarC1ock11111111111111111111111111111111");

const ED25519_PKCS8_PREFIX = hexToBytes("302e020100300506032b657004220420");
const ED25519_SPKI_PREFIX = hexToBytes("302a300506032b6570032100");

const ED25519_FIELD_P = (1n << 255n) - 19n;
const ED25519_D =
  mod(-121665n * modInverse(121666n, ED25519_FIELD_P), ED25519_FIELD_P);
const ED25519_I = modPow(2n, (ED25519_FIELD_P - 1n) / 4n, ED25519_FIELD_P);

export interface AccountMetaV1 {
  pubkey: Uint8Array;
  isSigner: boolean;
  isWritable: boolean;
}

export interface InstructionV1 {
  programId: Uint8Array;
  accounts: AccountMetaV1[];
  data: Uint8Array;
}

export interface PreparedSubmitProofInstructionV1 {
  proofRecordAddress: Uint8Array;
  instruction: InstructionV1;
}

export interface MessageHeaderV1 {
  numRequiredSignatures: number;
  numReadonlySignedAccounts: number;
  numReadonlyUnsignedAccounts: number;
}

export interface CompiledInstructionV1 {
  programIdIndex: number;
  accountIndices: Uint8Array;
  data: Uint8Array;
}

export interface LegacyMessageV1 {
  header: MessageHeaderV1;
  accountKeys: Uint8Array[];
  recentBlockhash: Uint8Array;
  instructions: CompiledInstructionV1[];
  serializedMessage: Uint8Array;
}

export interface LegacyTransactionV1 {
  signatures: Uint8Array[];
  message: LegacyMessageV1;
  serializedTransaction: Uint8Array;
  serializedTransactionBase64: string;
}

export interface PreparedSubmitProofTransactionV1 {
  proofRecordAddress: Uint8Array;
  transaction: LegacyTransactionV1;
}

export interface SubmitProofSubmissionV1 {
  proofRecordAddress: Uint8Array;
  signature: string;
}

export interface AuraSubmissionRpcClientV1 {
  getLatestBlockhash(): Promise<string>;
  sendAndConfirmTransaction(serializedTransactionBase64: string): Promise<string>;
}

export class AuraSubmissionClientErrorV1 extends Error {
  readonly code = "Rpc";

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuraSubmissionClientErrorV1";
  }
}

type AuraSubmissionWireErrorCodeV1 =
  | "InvalidPubkey"
  | "InvalidProofHashHex"
  | "InvalidWalletVisual"
  | "SubmitterPubkeyMismatch";

export class AuraSubmissionWireErrorV1 extends Error {
  readonly code: AuraSubmissionWireErrorCodeV1;

  constructor(code: AuraSubmissionWireErrorCodeV1, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuraSubmissionWireErrorV1";
    this.code = code;
  }
}

export function deriveProofRecordAddressV1(
  programIdBytes: Uint8Array,
  challengeBytes: Uint8Array,
  submitterPubkeyBytes: Uint8Array,
): { proofRecordAddress: Uint8Array; bump: number } {
  const programId = copyBytes32("programIdBytes", programIdBytes);
  const challenge = copyBytes32("challengeBytes", challengeBytes);
  const submitter = copyBytes32("submitterPubkeyBytes", submitterPubkeyBytes);

  for (let bump = 255; bump >= 0; bump -= 1) {
    const candidate = sha256Bytes(
      concatBytes(
        PROOF_RECORD_SEED_V1,
        challenge,
        submitter,
        Uint8Array.of(bump),
        programId,
        PROGRAM_DERIVED_ADDRESS_MARKER_V1,
      ),
    );

    if (!isOnEd25519Curve(candidate)) {
      return {
        proofRecordAddress: candidate,
        bump,
      };
    }
  }

  throw new Error("unable to derive proof record address");
}

export function prepareSubmitProofInstructionV1(
  programIdBytes: Uint8Array,
  submitterPubkeyBytes: Uint8Array,
  challengeBytes: Uint8Array,
  proofHashBytes: Uint8Array,
): PreparedSubmitProofInstructionV1 {
  const programId = copyBytes32("programIdBytes", programIdBytes);
  const submitter = copyBytes32("submitterPubkeyBytes", submitterPubkeyBytes);
  const challenge = copyBytes32("challengeBytes", challengeBytes);
  const proofHash = copyBytes32("proofHashBytes", proofHashBytes);

  const { proofRecordAddress } = deriveProofRecordAddressV1(
    programId,
    challenge,
    submitter,
  );

  return {
    proofRecordAddress,
    instruction: {
      programId,
      accounts: [
        { pubkey: submitter, isSigner: true, isWritable: true },
        { pubkey: challenge, isSigner: false, isWritable: true },
        { pubkey: proofRecordAddress, isSigner: false, isWritable: true },
        { pubkey: copyBytes(SYSTEM_PROGRAM_ID_V1), isSigner: false, isWritable: false },
        { pubkey: copyBytes(CLOCK_SYSVAR_ID_V1), isSigner: false, isWritable: false },
      ],
      data: concatBytes(Uint8Array.of(SUBMIT_PROOF_TAG_V1), proofHash),
    },
  };
}

export function parseSubmitProofRequestWireV1(
  payload: SubmitProofRequestWireV1,
): SubmitProofRequestWireV1 {
  const payloadRecord = toRecordV1(payload, "payload");
  rejectUnknownKeysV1(payloadRecord, "payload", [
    "program_id_base58",
    "submitter_pubkey_base58",
    "challenge_pubkey_base58",
    "proof_hash_hex",
    "wallet_visual_v1",
  ]);

  const programId = parsePubkeyBase58V1(
    requireString(payloadRecord.program_id_base58, "program_id_base58"),
    "program_id_base58",
  );
  const submitterPubkey = parsePubkeyBase58V1(
    requireString(payloadRecord.submitter_pubkey_base58, "submitter_pubkey_base58"),
    "submitter_pubkey_base58",
  );
  const challengePubkey = parsePubkeyBase58V1(
    requireString(payloadRecord.challenge_pubkey_base58, "challenge_pubkey_base58"),
    "challenge_pubkey_base58",
  );
  const proofHashHex = normalizeProofHashHexV1(
    requireString(payloadRecord.proof_hash_hex, "proof_hash_hex"),
  );

  let walletVisualV1: string;
  try {
    walletVisualV1 = parseWalletVisualV1(
      requireString(payloadRecord.wallet_visual_v1, "wallet_visual_v1"),
    );
  } catch (error) {
    throw new AuraSubmissionWireErrorV1(
      "InvalidWalletVisual",
      `invalid wallet_visual_v1: ${messageFromError(error)}`,
      { cause: error },
    );
  }

  if (proofHashHexFromWalletVisualV1(walletVisualV1) !== proofHashHex) {
    throw new AuraSubmissionWireErrorV1(
      "InvalidWalletVisual",
      `wallet_visual_v1 does not round-trip to proof_hash_hex ${proofHashHex}`,
    );
  }

  return {
    program_id_base58: encodeBase58(programId),
    submitter_pubkey_base58: encodeBase58(submitterPubkey),
    challenge_pubkey_base58: encodeBase58(challengePubkey),
    proof_hash_hex: proofHashHex,
    wallet_visual_v1: walletVisualV1,
  };
}

export function prepareSubmitProofInstructionFromWireV1(
  payload: SubmitProofRequestWireV1,
): PreparedSubmitProofInstructionV1 {
  const parsed = parseSubmitProofRequestWireV1(payload);

  return prepareSubmitProofInstructionV1(
    decodeBase58(parsed.program_id_base58),
    decodeBase58(parsed.submitter_pubkey_base58),
    decodeBase58(parsed.challenge_pubkey_base58),
    proofHashHexToBytesV1(parsed.proof_hash_hex),
  );
}

export function prepareSubmitProofTransactionV1(
  submitterKeypairBytes: Uint8Array,
  programIdBytes: Uint8Array,
  challengeBytes: Uint8Array,
  proofHashBytes: Uint8Array,
  recentBlockhashBytes: Uint8Array,
): PreparedSubmitProofTransactionV1 {
  const submitter = parseKeypairBytesV1(submitterKeypairBytes);
  const recentBlockhash = copyBytes32("recentBlockhashBytes", recentBlockhashBytes);
  const preparedInstruction = prepareSubmitProofInstructionV1(
    programIdBytes,
    submitter.publicKeyBytes,
    challengeBytes,
    proofHashBytes,
  );

  const accountKeys = [
    copyBytes(submitter.publicKeyBytes),
    copyBytes(preparedInstruction.instruction.accounts[1].pubkey),
    copyBytes(preparedInstruction.instruction.accounts[2].pubkey),
    copyBytes(SYSTEM_PROGRAM_ID_V1),
    copyBytes(CLOCK_SYSVAR_ID_V1),
    copyBytes(preparedInstruction.instruction.programId),
  ];

  const compiledInstruction: CompiledInstructionV1 = {
    programIdIndex: 5,
    accountIndices: Uint8Array.of(0, 1, 2, 3, 4),
    data: copyBytes(preparedInstruction.instruction.data),
  };

  const message: LegacyMessageV1 = {
    header: {
      numRequiredSignatures: 1,
      numReadonlySignedAccounts: 0,
      numReadonlyUnsignedAccounts: 3,
    },
    accountKeys,
    recentBlockhash,
    instructions: [compiledInstruction],
    serializedMessage: new Uint8Array(),
  };

  message.serializedMessage = serializeLegacyMessageV1(message);

  const signature = signMessageV1(submitter.privateSeedBytes, message.serializedMessage);
  const serializedTransaction = concatBytes(
    encodeShortVecLength(1),
    signature,
    message.serializedMessage,
  );

  return {
    proofRecordAddress: copyBytes(preparedInstruction.proofRecordAddress),
    transaction: {
      signatures: [signature],
      message,
      serializedTransaction,
      serializedTransactionBase64: Buffer.from(serializedTransaction).toString("base64"),
    },
  };
}

export function prepareSubmitProofTransactionFromWireV1(
  submitterKeypairBytes: Uint8Array,
  payload: SubmitProofRequestWireV1,
  recentBlockhashBytes: Uint8Array,
): PreparedSubmitProofTransactionV1 {
  const parsed = parseSubmitProofRequestWireV1(payload);
  const submitter = parseKeypairBytesV1(submitterKeypairBytes);
  const actualSubmitterPubkeyBase58 = encodeBase58(submitter.publicKeyBytes);

  if (actualSubmitterPubkeyBase58 !== parsed.submitter_pubkey_base58) {
    throw new AuraSubmissionWireErrorV1(
      "SubmitterPubkeyMismatch",
      `submitter keypair pubkey ${actualSubmitterPubkeyBase58} does not match request submitter_pubkey_base58 ${parsed.submitter_pubkey_base58}`,
    );
  }

  return prepareSubmitProofTransactionV1(
    submitterKeypairBytes,
    decodeBase58(parsed.program_id_base58),
    decodeBase58(parsed.challenge_pubkey_base58),
    proofHashHexToBytesV1(parsed.proof_hash_hex),
    recentBlockhashBytes,
  );
}

export async function submitProofV1(
  rpcClient: AuraSubmissionRpcClientV1,
  submitterKeypairBytes: Uint8Array,
  programIdBytes: Uint8Array,
  challengeBytes: Uint8Array,
  proofHashBytes: Uint8Array,
): Promise<SubmitProofSubmissionV1> {
  let recentBlockhashBase58: string;
  try {
    recentBlockhashBase58 = await rpcClient.getLatestBlockhash();
  } catch (error) {
    throw rpcErrorV1(error);
  }

  let recentBlockhashBytes: Uint8Array;
  try {
    recentBlockhashBytes = copyBytes32(
      "recentBlockhash",
      decodeBase58(recentBlockhashBase58),
    );
  } catch (error) {
    throw rpcErrorV1(error);
  }

  const preparedTransaction = prepareSubmitProofTransactionV1(
    submitterKeypairBytes,
    programIdBytes,
    challengeBytes,
    proofHashBytes,
    recentBlockhashBytes,
  );

  try {
    const signature = await rpcClient.sendAndConfirmTransaction(
      preparedTransaction.transaction.serializedTransactionBase64,
    );

    return {
      proofRecordAddress: copyBytes(preparedTransaction.proofRecordAddress),
      signature,
    };
  } catch (error) {
    throw rpcErrorV1(error);
  }
}

export async function submitProofFromWireV1(
  rpcClient: AuraSubmissionRpcClientV1,
  submitterKeypairBytes: Uint8Array,
  payload: SubmitProofRequestWireV1,
): Promise<SubmitProofSubmissionV1> {
  const parsed = parseSubmitProofRequestWireV1(payload);
  const submitter = parseKeypairBytesV1(submitterKeypairBytes);
  const actualSubmitterPubkeyBase58 = encodeBase58(submitter.publicKeyBytes);

  if (actualSubmitterPubkeyBase58 !== parsed.submitter_pubkey_base58) {
    throw new AuraSubmissionWireErrorV1(
      "SubmitterPubkeyMismatch",
      `submitter keypair pubkey ${actualSubmitterPubkeyBase58} does not match request submitter_pubkey_base58 ${parsed.submitter_pubkey_base58}`,
    );
  }

  return submitProofV1(
    rpcClient,
    submitterKeypairBytes,
    decodeBase58(parsed.program_id_base58),
    decodeBase58(parsed.challenge_pubkey_base58),
    proofHashHexToBytesV1(parsed.proof_hash_hex),
  );
}

function parseKeypairBytesV1(
  submitterKeypairBytes: Uint8Array,
): { privateSeedBytes: Uint8Array; publicKeyBytes: Uint8Array } {
  const keypairBytes = copyBytes64("submitterKeypairBytes", submitterKeypairBytes);
  const privateSeedBytes = keypairBytes.slice(0, 32);
  const publicKeyBytes = keypairBytes.slice(32);
  const derivedPublicKeyBytes = deriveEd25519PublicKeyBytes(privateSeedBytes);

  if (!bytesEqual(publicKeyBytes, derivedPublicKeyBytes)) {
    throw new Error(
      "submitterKeypairBytes public key does not match private key seed",
    );
  }

  return {
    privateSeedBytes,
    publicKeyBytes,
  };
}

function deriveEd25519PublicKeyBytes(privateSeedBytes: Uint8Array): Uint8Array {
  const privateKey = createPrivateKey({
    key: Buffer.from(concatBytes(ED25519_PKCS8_PREFIX, privateSeedBytes)),
    format: "der",
    type: "pkcs8",
  });
  const publicKeySpki = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });

  return new Uint8Array(publicKeySpki.subarray(ED25519_SPKI_PREFIX.length));
}

function signMessageV1(privateSeedBytes: Uint8Array, messageBytes: Uint8Array): Uint8Array {
  const privateKey = createPrivateKey({
    key: Buffer.from(concatBytes(ED25519_PKCS8_PREFIX, privateSeedBytes)),
    format: "der",
    type: "pkcs8",
  });

  return new Uint8Array(signEd25519(null, Buffer.from(messageBytes), privateKey));
}

function serializeLegacyMessageV1(message: LegacyMessageV1): Uint8Array {
  const accountKeyBytes = message.accountKeys.flatMap((accountKey) => Array.from(accountKey));
  const instructionBytes = message.instructions.flatMap((instruction) =>
    Array.from(serializeCompiledInstructionV1(instruction)),
  );

  return concatBytes(
    Uint8Array.of(
      message.header.numRequiredSignatures,
      message.header.numReadonlySignedAccounts,
      message.header.numReadonlyUnsignedAccounts,
    ),
    encodeShortVecLength(message.accountKeys.length),
    Uint8Array.from(accountKeyBytes),
    message.recentBlockhash,
    encodeShortVecLength(message.instructions.length),
    Uint8Array.from(instructionBytes),
  );
}

function serializeCompiledInstructionV1(
  instruction: CompiledInstructionV1,
): Uint8Array {
  return concatBytes(
    Uint8Array.of(instruction.programIdIndex),
    encodeShortVecLength(instruction.accountIndices.length),
    instruction.accountIndices,
    encodeShortVecLength(instruction.data.length),
    instruction.data,
  );
}

function rpcErrorV1(error: unknown): AuraSubmissionClientErrorV1 {
  return new AuraSubmissionClientErrorV1(
    `rpc client error: ${messageFromError(error)}`,
    { cause: error },
  );
}

function parsePubkeyBase58V1(text: string, fieldName: string): Uint8Array {
  try {
    return copyBytes32(fieldName, decodeBase58(text));
  } catch (error) {
    throw new AuraSubmissionWireErrorV1(
      "InvalidPubkey",
      `invalid ${fieldName}: ${messageFromError(error)}`,
      { cause: error },
    );
  }
}

function copyBytes32(label: string, bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Uint8Array`);
  }

  if (bytes.length !== 32) {
    throw new RangeError(`${label} must be exactly 32 bytes`);
  }

  return new Uint8Array(bytes);
}

function copyBytes64(label: string, bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Uint8Array`);
  }

  if (bytes.length !== 64) {
    throw new RangeError(`${label} must be exactly 64 bytes`);
  }

  return new Uint8Array(bytes);
}

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }

  return output;
}

function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function encodeShortVecLength(value: number): Uint8Array {
  const output: number[] = [];
  let remaining = value >>> 0;

  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining > 0) {
      byte |= 0x80;
    }
    output.push(byte);
  } while (remaining > 0);

  return Uint8Array.from(output);
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

function messageFromError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function toRecordV1(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AuraSubmissionWireErrorV1(
      "InvalidUdotBundle",
      `${name} must be an object`,
    );
  }

  return value as Record<string, unknown>;
}

function rejectUnknownKeysV1(
  value: Record<string, unknown>,
  name: string,
  allowedKeys: string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) {
      throw new AuraSubmissionWireErrorV1(
        "InvalidUdotBundle",
        `${name} contains unexpected field ${JSON.stringify(key)}`,
      );
    }
  }
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new AuraSubmissionWireErrorV1(
      "InvalidUdotBundle",
      `${name} must be a string`,
    );
  }

  return value;
}

function decodeBase58(text: string): Uint8Array {
  if (text.length === 0) {
    return new Uint8Array();
  }

  const bytes: number[] = [0];

  for (const char of text) {
    const value = BASE58_MAP.get(char);
    if (value === undefined) {
      throw new Error(`invalid base58 character: ${char}`);
    }

    let carry = value;
    for (let index = 0; index < bytes.length; index += 1) {
      carry += bytes[index] * 58;
      bytes[index] = carry & 0xff;
      carry >>= 8;
    }

    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  let leadingZeroCount = 0;
  while (leadingZeroCount < text.length && text[leadingZeroCount] === "1") {
    leadingZeroCount += 1;
  }

  const output = new Uint8Array(leadingZeroCount + bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    output[output.length - 1 - index] = bytes[index];
  }

  return output;
}

function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return "";
  }

  let leadingZeroCount = 0;
  while (leadingZeroCount < bytes.length && bytes[leadingZeroCount] === 0) {
    leadingZeroCount += 1;
  }

  if (leadingZeroCount === bytes.length) {
    return "1".repeat(leadingZeroCount);
  }

  const digits: number[] = [0];

  for (const value of bytes.subarray(leadingZeroCount)) {
    let carry = value;
    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index] << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }

    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let output = "";
  output += "1".repeat(leadingZeroCount);
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    output += BASE58_ALPHABET[digits[index]];
  }

  return output;
}

function hexToBytes(hex: string): Uint8Array {
  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return output;
}

function normalizeProofHashHexV1(value: string): string {
  if (value.length !== 64) {
    throw new AuraSubmissionWireErrorV1(
      "InvalidProofHashHex",
      `invalid proof_hash_hex: expected 64 hex characters, got ${value.length}`,
    );
  }

  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    const pair = value.slice(index * 2, index * 2 + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      throw new AuraSubmissionWireErrorV1(
        "InvalidProofHashHex",
        "invalid proof_hash_hex: contains a non-hex character",
      );
    }
    bytes[index] = Number.parseInt(pair, 16);
  }

  const canonical = hexLowerV1(bytes);
  if (value !== canonical) {
    throw new AuraSubmissionWireErrorV1(
      "InvalidProofHashHex",
      `invalid proof_hash_hex: expected canonical lowercase 64-hex ${canonical}, got ${value}`,
    );
  }

  return canonical;
}

function proofHashHexToBytesV1(value: string): Uint8Array {
  return hexToBytes(normalizeProofHashHexV1(value));
}

function hexLowerV1(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}

function isOnEd25519Curve(candidate: Uint8Array): boolean {
  if (candidate.length !== 32) {
    return false;
  }

  const signBit = (candidate[31] & 0x80) >>> 7;
  const yBytes = copyBytes(candidate);
  yBytes[31] &= 0x7f;
  const y = littleEndianBytesToBigInt(yBytes);

  if (y >= ED25519_FIELD_P) {
    return false;
  }

  const ySquared = mod(y * y, ED25519_FIELD_P);
  const numerator = mod(ySquared - 1n, ED25519_FIELD_P);
  const denominator = mod(ED25519_D * ySquared + 1n, ED25519_FIELD_P);

  if (denominator === 0n) {
    return false;
  }

  const xSquared = mod(numerator * modInverse(denominator, ED25519_FIELD_P), ED25519_FIELD_P);
  let x = modPow(xSquared, (ED25519_FIELD_P + 3n) / 8n, ED25519_FIELD_P);

  if (mod(x * x - xSquared, ED25519_FIELD_P) !== 0n) {
    x = mod(x * ED25519_I, ED25519_FIELD_P);
  }

  if (mod(x * x - xSquared, ED25519_FIELD_P) !== 0n) {
    return false;
  }

  if (x === 0n && signBit === 1) {
    return false;
  }

  if (Number(x & 1n) !== signBit) {
    x = ED25519_FIELD_P - x;
  }

  return mod((-x * x + ySquared - 1n - ED25519_D * x * x * ySquared), ED25519_FIELD_P) === 0n;
}

function littleEndianBytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;

  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) + BigInt(bytes[index]);
  }

  return value;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = mod(base, modulus);
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = mod(result * factor, modulus);
    }

    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }

  return result;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let nextT = 1n;
  let r = modulus;
  let nextR = mod(value, modulus);

  while (nextR !== 0n) {
    const quotient = r / nextR;
    [t, nextT] = [nextT, t - quotient * nextT];
    [r, nextR] = [nextR, r - quotient * nextR];
  }

  if (r !== 1n) {
    throw new Error("value is not invertible");
  }

  return mod(t, modulus);
}

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}
