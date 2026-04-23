import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
} from "node:crypto";

import {
  encodeSessionEncryptionContextV1,
  type AuraSessionEncryptionContextV1,
} from "./sessionEncryptionContextV1.ts";
import {
  encodeStormEncryptionBindingV1,
  type StormEncryptionBindingV1,
} from "./stormEncryptionBindingV1.ts";

export const SESSION_KEY_MATERIAL_V1_LEN = 32;
export const AURA_SESSION_KEY_ID_V1_DOMAIN_SEPARATOR = new TextEncoder().encode(
  "AURA_SESSION_KEY_ID_V1",
);
export const AURA_SESSION_SYMMETRIC_KEY_V1_DOMAIN_SEPARATOR = new TextEncoder().encode(
  "AURA_SESSION_SYMMETRIC_KEY_V1",
);
export const AURA_SESSION_SYMMETRIC_KEY_V1_INFO_LABEL = new TextEncoder().encode(
  "AURA_SESSION_SYMMETRIC_KEY_V1_INFO",
);

export type SessionPublicKeyV1 = {
  bytes: Uint8Array;
};

export type SessionSecretKeyV1 = {
  bytes: Uint8Array;
};

export type SharedSecretV1 = {
  bytes: Uint8Array;
};

export type SessionKeyDerivationInputV1 = {
  sharedSecret: SharedSecretV1;
  sessionEncryptionContext: AuraSessionEncryptionContextV1;
  stormEncryptionBinding: StormEncryptionBindingV1;
};

export type SessionSymmetricKeyV1 = {
  bytes: Uint8Array;
};

const X25519_PUBLIC_KEY_DER_PREFIX_V1 = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PRIVATE_KEY_DER_PREFIX_V1 = Buffer.from("302e020100300506032b656e04220420", "hex");

export function generateSessionKeypairV1(): {
  secretKey: SessionSecretKeyV1;
  publicKey: SessionPublicKeyV1;
} {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return {
    secretKey: { bytes: extractRawPrivateKeyV1(privateKey.export({ format: "der", type: "pkcs8" })) },
    publicKey: { bytes: extractRawPublicKeyV1(publicKey.export({ format: "der", type: "spki" })) },
  };
}

export function deriveSharedSecretV1(
  localSecretKey: SessionSecretKeyV1,
  peerPublicKey: SessionPublicKeyV1,
): SharedSecretV1 {
  const publicBytes = requireBytes32(peerPublicKey.bytes, "peerPublicKey.bytes");
  if (isAllZeroV1(publicBytes)) {
    throw new TypeError("peerPublicKey.bytes must not be all zero");
  }

  const secretBytes = requireBytes32(localSecretKey.bytes, "localSecretKey.bytes");
  const sharedSecret = new Uint8Array(
    diffieHellman({
      privateKey: createPrivateKey({
        key: Buffer.concat([X25519_PRIVATE_KEY_DER_PREFIX_V1, Buffer.from(secretBytes)]),
        format: "der",
        type: "pkcs8",
      }),
      publicKey: createPublicKey({
        key: Buffer.concat([X25519_PUBLIC_KEY_DER_PREFIX_V1, Buffer.from(publicBytes)]),
        format: "der",
        type: "spki",
      }),
    }),
  );

  if (isAllZeroV1(sharedSecret)) {
    throw new TypeError("shared secret must not resolve to the identity");
  }

  return { bytes: sharedSecret };
}

export function deriveSessionKeyIdV1(
  sharedSecret: SharedSecretV1,
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
): Uint8Array {
  validateContextAndBindingAlignmentV1(sessionEncryptionContext, stormEncryptionBinding);

  const normalizedContext = {
    ...sessionEncryptionContext,
    sessionKeyId: new Uint8Array(32),
  } satisfies AuraSessionEncryptionContextV1;
  const normalizedBinding = {
    ...stormEncryptionBinding,
    sessionKeyId: new Uint8Array(32),
  } satisfies StormEncryptionBindingV1;
  const contextBytes = encodeSessionEncryptionContextV1(normalizedContext);
  const bindingBytes = encodeStormEncryptionBindingV1(normalizedBinding);
  return new Uint8Array(
    createHash("sha256")
      .update(AURA_SESSION_KEY_ID_V1_DOMAIN_SEPARATOR)
      .update(requireBytes32(sharedSecret.bytes, "sharedSecret.bytes"))
      .update(contextBytes)
      .update(bindingBytes)
      .digest(),
  );
}

export function deriveSessionSymmetricKeyV1(
  input: SessionKeyDerivationInputV1,
): SessionSymmetricKeyV1 {
  validateContextAndBindingAlignmentV1(
    input.sessionEncryptionContext,
    input.stormEncryptionBinding,
  );

  const expectedSessionKeyId = deriveSessionKeyIdV1(
    input.sharedSecret,
    input.sessionEncryptionContext,
    input.stormEncryptionBinding,
  );
  const actualContextSessionKeyId = requireBytes32(
    input.sessionEncryptionContext.sessionKeyId,
    "sessionEncryptionContext.sessionKeyId",
  );
  const actualBindingSessionKeyId = requireBytes32(
    input.stormEncryptionBinding.sessionKeyId,
    "stormEncryptionBinding.sessionKeyId",
  );
  if (!equalBytesV1(expectedSessionKeyId, actualContextSessionKeyId)) {
    throw new TypeError("sessionEncryptionContext.sessionKeyId does not match derived session key id");
  }
  if (!equalBytesV1(expectedSessionKeyId, actualBindingSessionKeyId)) {
    throw new TypeError("stormEncryptionBinding.sessionKeyId does not match derived session key id");
  }

  const contextBytes = encodeSessionEncryptionContextV1(input.sessionEncryptionContext);
  const bindingBytes = encodeStormEncryptionBindingV1(input.stormEncryptionBinding);
  const ikm = Buffer.concat([
    Buffer.from(requireBytes32(input.sharedSecret.bytes, "sharedSecret.bytes")),
    Buffer.from(contextBytes),
    Buffer.from(bindingBytes),
  ]);
  const okm = hkdfSync(
    "sha256",
    ikm,
    Buffer.from(AURA_SESSION_SYMMETRIC_KEY_V1_DOMAIN_SEPARATOR),
    Buffer.concat([
      Buffer.from(AURA_SESSION_SYMMETRIC_KEY_V1_INFO_LABEL),
      Buffer.from(contextBytes),
      Buffer.from(bindingBytes),
    ]),
    SESSION_KEY_MATERIAL_V1_LEN,
  );
  return { bytes: new Uint8Array(Buffer.from(okm)) };
}

export function deriveSessionPublicKeyV1(secretKey: SessionSecretKeyV1): SessionPublicKeyV1 {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      X25519_PRIVATE_KEY_DER_PREFIX_V1,
      Buffer.from(requireBytes32(secretKey.bytes, "secretKey.bytes")),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { bytes: extractRawPublicKeyV1(publicDer) };
}

function extractRawPublicKeyV1(der: Buffer | string): Uint8Array {
  const buffer = Buffer.isBuffer(der) ? der : Buffer.from(der);
  if (buffer.length !== X25519_PUBLIC_KEY_DER_PREFIX_V1.length + SESSION_KEY_MATERIAL_V1_LEN) {
    throw new TypeError("unexpected X25519 public key length");
  }
  return new Uint8Array(buffer.subarray(X25519_PUBLIC_KEY_DER_PREFIX_V1.length));
}

function extractRawPrivateKeyV1(der: Buffer | string): Uint8Array {
  const buffer = Buffer.isBuffer(der) ? der : Buffer.from(der);
  if (buffer.length !== X25519_PRIVATE_KEY_DER_PREFIX_V1.length + SESSION_KEY_MATERIAL_V1_LEN) {
    throw new TypeError("unexpected X25519 private key length");
  }
  return new Uint8Array(buffer.subarray(X25519_PRIVATE_KEY_DER_PREFIX_V1.length));
}

function requireBytes32(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new TypeError(`${fieldName} must be 32 bytes`);
  }
  return new Uint8Array(bytes);
}

function validateContextAndBindingAlignmentV1(
  sessionEncryptionContext: AuraSessionEncryptionContextV1,
  stormEncryptionBinding: StormEncryptionBindingV1,
): void {
  if (!equalBytesV1(sessionEncryptionContext.stormClaimDigest, stormEncryptionBinding.stormClaimDigest)) {
    throw new TypeError("stormEncryptionBinding.stormClaimDigest must match sessionEncryptionContext.stormClaimDigest");
  }
  if (!equalBytesV1(sessionEncryptionContext.senderId, stormEncryptionBinding.senderId)) {
    throw new TypeError("stormEncryptionBinding.senderId must match sessionEncryptionContext.senderId");
  }
  if (!equalBytesV1(sessionEncryptionContext.receiverId, stormEncryptionBinding.receiverId)) {
    throw new TypeError("stormEncryptionBinding.receiverId must match sessionEncryptionContext.receiverId");
  }
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
