import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

import {
  deriveSessionPublicKeyV1,
  deriveSessionSymmetricKeyV1,
  deriveSharedSecretV1,
  type SessionPublicKeyV1,
  type SessionSecretKeyV1,
} from "./sessionKeyV1.ts";
import {
  encodeSessionEncryptionContextV1,
  validateSessionEncryptionContextV1,
  type AuraSessionEncryptionContextV1,
} from "./sessionEncryptionContextV1.ts";
import {
  encodeStormEncryptionBindingV1,
  validateStormEncryptionBindingV1,
  type StormEncryptionBindingV1,
} from "./stormEncryptionBindingV1.ts";

export const ENCRYPTED_ENVELOPE_V1_VERSION = 0x01;
export const ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID = 0x01;
export const ENCRYPTED_ENVELOPE_V1_NONCE_LEN = 12;
export const ENCRYPTED_ENVELOPE_V1_TAG_LEN = 16;
export const AURA_SESSION_ENCRYPTION_AAD_CONTEXT_HASH_V1_DOMAIN_SEPARATOR = new TextEncoder().encode(
  "AURA_SESSION_ENCRYPTION_AAD_CONTEXT_HASH_V1",
);

export type AuraEncryptedEnvelopeV1 = {
  version: number;
  algorithmId: number;
  senderPublicKey: SessionPublicKeyV1;
  receiverPublicKey: SessionPublicKeyV1;
  nonce: Uint8Array;
  aadContextHash: Uint8Array;
  ciphertext: Uint8Array;
  sessionKeyId: Uint8Array;
};

export function encryptPayloadV1(
  senderSecretKey: SessionSecretKeyV1,
  receiverPublicKey: SessionPublicKeyV1,
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const sharedSecret = deriveSharedSecretV1(senderSecretKey, receiverPublicKey);
  const sessionKey = deriveSessionSymmetricKeyV1({
    sharedSecret,
    sessionEncryptionContext,
    stormEncryptionBinding,
  });
  const aadMaterial = buildAadMaterialV1(sessionEncryptionContext, stormEncryptionBinding);
  const cipher = createCipheriv(
    "chacha20-poly1305",
    Buffer.from(sessionKey.bytes),
    Buffer.from(requireNonceV1(nonce)),
    { authTagLength: ENCRYPTED_ENVELOPE_V1_TAG_LEN },
  );
  cipher.setAAD(Buffer.from(aadMaterial));

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(cloneBytesV1(plaintext, "plaintext"))),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return new Uint8Array(ciphertext);
}

export function decryptPayloadV1(
  receiverSecretKey: SessionSecretKeyV1,
  senderPublicKey: SessionPublicKeyV1,
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const payload = cloneBytesV1(ciphertext, "ciphertext");
  if (payload.length < ENCRYPTED_ENVELOPE_V1_TAG_LEN) {
    throw new TypeError(
      `ciphertext must be at least ${ENCRYPTED_ENVELOPE_V1_TAG_LEN} bytes to include the AEAD tag`,
    );
  }

  const sharedSecret = deriveSharedSecretV1(receiverSecretKey, senderPublicKey);
  const sessionKey = deriveSessionSymmetricKeyV1({
    sharedSecret,
    sessionEncryptionContext,
    stormEncryptionBinding,
  });
  const aadMaterial = buildAadMaterialV1(sessionEncryptionContext, stormEncryptionBinding);
  const decipher = createDecipheriv(
    "chacha20-poly1305",
    Buffer.from(sessionKey.bytes),
    Buffer.from(requireNonceV1(nonce)),
    { authTagLength: ENCRYPTED_ENVELOPE_V1_TAG_LEN },
  );
  decipher.setAAD(Buffer.from(aadMaterial));
  decipher.setAuthTag(Buffer.from(payload.subarray(payload.length - ENCRYPTED_ENVELOPE_V1_TAG_LEN)));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.subarray(0, payload.length - ENCRYPTED_ENVELOPE_V1_TAG_LEN))),
    decipher.final(),
  ]);
  return new Uint8Array(plaintext);
}

export function buildEncryptedEnvelopeV1(
  senderSecretKey: SessionSecretKeyV1,
  receiverPublicKey: SessionPublicKeyV1,
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): AuraEncryptedEnvelopeV1 {
  const envelopeNonce = nonce === undefined
    ? new Uint8Array(randomBytes(ENCRYPTED_ENVELOPE_V1_NONCE_LEN))
    : requireNonceV1(nonce);
  const envelope: AuraEncryptedEnvelopeV1 = {
    version: ENCRYPTED_ENVELOPE_V1_VERSION,
    algorithmId: ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
    senderPublicKey: deriveSessionPublicKeyV1(senderSecretKey),
    receiverPublicKey: {
      bytes: cloneBytes32V1(receiverPublicKey.bytes, "receiverPublicKey.bytes"),
    },
    nonce: envelopeNonce,
    aadContextHash: deriveAadContextHashV1(sessionEncryptionContext, stormEncryptionBinding),
    ciphertext: encryptPayloadV1(
      senderSecretKey,
      receiverPublicKey,
      sessionEncryptionContext,
      stormEncryptionBinding,
      envelopeNonce,
      plaintext,
    ),
    sessionKeyId: cloneBytes32V1(sessionEncryptionContext.sessionKeyId, "sessionEncryptionContext.sessionKeyId"),
  };

  return validateEncryptedEnvelopeV1(envelope, sessionEncryptionContext, stormEncryptionBinding);
}

export function validateEncryptedEnvelopeV1(
  envelope: AuraEncryptedEnvelopeV1,
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
): AuraEncryptedEnvelopeV1 {
  if (envelope.version !== ENCRYPTED_ENVELOPE_V1_VERSION) {
    throw new TypeError(
      `encrypted envelope version must be ${ENCRYPTED_ENVELOPE_V1_VERSION}, got ${envelope.version}`,
    );
  }

  if (envelope.algorithmId !== ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID) {
    throw new TypeError(
      `encrypted envelope algorithmId must be ${ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID}, got ${envelope.algorithmId}`,
    );
  }

  validateSessionEncryptionContextV1(sessionEncryptionContext);
  validateStormEncryptionBindingV1(stormEncryptionBinding);

  const senderPublicKey = cloneBytes32V1(envelope.senderPublicKey.bytes, "senderPublicKey.bytes");
  const receiverPublicKey = cloneBytes32V1(envelope.receiverPublicKey.bytes, "receiverPublicKey.bytes");
  const sessionKeyId = cloneBytes32V1(envelope.sessionKeyId, "sessionKeyId");
  const contextSessionKeyId = cloneBytes32V1(
    sessionEncryptionContext.sessionKeyId,
    "sessionEncryptionContext.sessionKeyId",
  );
  const bindingSessionKeyId = cloneBytes32V1(
    stormEncryptionBinding.sessionKeyId,
    "stormEncryptionBinding.sessionKeyId",
  );
  const aadContextHash = cloneBytes32V1(envelope.aadContextHash, "aadContextHash");

  if (isAllZeroV1(senderPublicKey)) {
    throw new TypeError("senderPublicKey.bytes must not be all zero");
  }

  if (isAllZeroV1(receiverPublicKey)) {
    throw new TypeError("receiverPublicKey.bytes must not be all zero");
  }

  if (isAllZeroV1(sessionKeyId) || isAllZeroV1(contextSessionKeyId) || isAllZeroV1(bindingSessionKeyId)) {
    throw new TypeError("session key ids must not be all zero");
  }

  if (!equalBytesV1(sessionKeyId, contextSessionKeyId)) {
    throw new TypeError("envelope sessionKeyId does not match the supplied encryption context");
  }

  if (!equalBytesV1(sessionKeyId, bindingSessionKeyId)) {
    throw new TypeError("envelope sessionKeyId does not match the supplied storm encryption binding");
  }

  if (cloneBytesV1(envelope.ciphertext, "ciphertext").length < ENCRYPTED_ENVELOPE_V1_TAG_LEN) {
    throw new TypeError(
      `ciphertext must be at least ${ENCRYPTED_ENVELOPE_V1_TAG_LEN} bytes to include the AEAD tag`,
    );
  }

  const expectedAadContextHash = deriveAadContextHashV1(
    sessionEncryptionContext,
    stormEncryptionBinding,
  );
  if (!equalBytesV1(aadContextHash, expectedAadContextHash)) {
    throw new TypeError("aadContextHash does not match the supplied encryption context and storm binding");
  }

  return {
    version: envelope.version,
    algorithmId: envelope.algorithmId,
    senderPublicKey: { bytes: senderPublicKey },
    receiverPublicKey: { bytes: receiverPublicKey },
    nonce: requireNonceV1(envelope.nonce),
    aadContextHash,
    ciphertext: cloneBytesV1(envelope.ciphertext, "ciphertext"),
    sessionKeyId,
  };
}

export function deriveAadContextHashV1(
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
): Uint8Array {
  const aadMaterial = buildAadMaterialV1(sessionEncryptionContext, stormEncryptionBinding);
  return new Uint8Array(
    createHash("sha256")
      .update(AURA_SESSION_ENCRYPTION_AAD_CONTEXT_HASH_V1_DOMAIN_SEPARATOR)
      .update(aadMaterial)
      .digest(),
  );
}

function buildAadMaterialV1(
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
): Uint8Array {
  return concatBytesV1(
    encodeSessionEncryptionContextV1(sessionEncryptionContext),
    encodeStormEncryptionBindingV1(stormEncryptionBinding),
  );
}

function requireNonceV1(nonce: Uint8Array): Uint8Array {
  if (!(nonce instanceof Uint8Array) || nonce.length !== ENCRYPTED_ENVELOPE_V1_NONCE_LEN) {
    throw new TypeError(`nonce must be ${ENCRYPTED_ENVELOPE_V1_NONCE_LEN} bytes`);
  }
  return new Uint8Array(nonce);
}

function cloneBytes32V1(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new TypeError(`${fieldName} must be 32 bytes`);
  }
  return new Uint8Array(bytes);
}

function cloneBytesV1(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError(`${fieldName} must be bytes`);
  }
  return new Uint8Array(bytes);
}

function equalBytesV1(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if ((left[index] ?? 0) !== (right[index] ?? 0)) {
      return false;
    }
  }
  return true;
}

function isAllZeroV1(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

function concatBytesV1(...parts: Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
