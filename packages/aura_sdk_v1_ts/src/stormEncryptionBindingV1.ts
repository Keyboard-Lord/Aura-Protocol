import { createHash } from "node:crypto";

import type { StormClaim521V1, StormPublicInputs521V1 } from "./stormClaimV1.ts";
import {
  bytesToHexLowerV1,
  concatBytesV1,
  decodeCanonicalFixedHexBytesV1,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
  validateFieldElement521BytesV1,
} from "./stormHash521V1.ts";

export const HASH_LEN_V1 = 32;
export const STORM_ENCRYPTION_BINDING_V1_LEN = HASH_LEN_V1 * 6 + FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;
export const AURA_STORM_ENCRYPTION_BINDING_V1_DOMAIN_SEPARATOR = new TextEncoder().encode(
  "AURA_STORM_ENCRYPTION_BINDING_V1",
);

export type StormEncryptionBindingV1 = {
  stormClaimDigest: Uint8Array;
  traceRoot: Uint8Array;
  finalStateX: Uint8Array;
  finalStateY: Uint8Array;
  contextHash: Uint8Array;
  senderId: Uint8Array;
  receiverId: Uint8Array;
  sessionKeyId: Uint8Array;
};

export function buildStormEncryptionBindingV1(
  lowerLayerClaim: StormClaim521V1,
  lowerLayerPublicInputs: StormPublicInputs521V1,
  stormClaimDigest: Uint8Array,
  senderId: Uint8Array,
  receiverId: Uint8Array,
  sessionKeyId: Uint8Array,
): StormEncryptionBindingV1 {
  return {
    stormClaimDigest: cloneBytes32V1(stormClaimDigest, "stormClaimDigest"),
    traceRoot: decodeCanonicalFixedHexBytesV1(lowerLayerClaim.traceRootHex, HASH_LEN_V1, "traceRootHex"),
    finalStateX: decodeFieldElementBytesV1(lowerLayerClaim.finalState.xHex66Be, "finalState.xHex66Be"),
    finalStateY: decodeFieldElementBytesV1(lowerLayerClaim.finalState.yHex66Be, "finalState.yHex66Be"),
    contextHash: decodeCanonicalFixedHexBytesV1(
      lowerLayerPublicInputs.contextHashHex,
      HASH_LEN_V1,
      "contextHashHex",
    ),
    senderId: cloneBytes32V1(senderId, "senderId"),
    receiverId: cloneBytes32V1(receiverId, "receiverId"),
    sessionKeyId: cloneBytes32V1(sessionKeyId, "sessionKeyId"),
  };
}

export function validateStormEncryptionBindingV1(
  binding: StormEncryptionBindingV1,
): StormEncryptionBindingV1 {
  return {
    stormClaimDigest: cloneBytes32V1(binding.stormClaimDigest, "stormClaimDigest"),
    traceRoot: cloneBytes32V1(binding.traceRoot, "traceRoot"),
    finalStateX: validateFieldElement521BytesV1(binding.finalStateX, "finalStateX"),
    finalStateY: validateFieldElement521BytesV1(binding.finalStateY, "finalStateY"),
    contextHash: cloneBytes32V1(binding.contextHash, "contextHash"),
    senderId: cloneBytes32V1(binding.senderId, "senderId"),
    receiverId: cloneBytes32V1(binding.receiverId, "receiverId"),
    sessionKeyId: cloneBytes32V1(binding.sessionKeyId, "sessionKeyId"),
  };
}

export function encodeStormEncryptionBindingV1(
  binding: StormEncryptionBindingV1,
): Uint8Array {
  const canonical = validateStormEncryptionBindingV1(binding);
  return concatBytesV1(
    canonical.stormClaimDigest,
    canonical.traceRoot,
    canonical.finalStateX,
    canonical.finalStateY,
    canonical.contextHash,
    canonical.senderId,
    canonical.receiverId,
    canonical.sessionKeyId,
  );
}

export function deriveStormEncryptionBindingHashV1(
  binding: StormEncryptionBindingV1,
): Uint8Array {
  return new Uint8Array(
    createHash("sha256")
      .update(AURA_STORM_ENCRYPTION_BINDING_V1_DOMAIN_SEPARATOR)
      .update(encodeStormEncryptionBindingV1(binding))
      .digest(),
  );
}

function cloneBytes32V1(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== HASH_LEN_V1) {
    throw new TypeError(`${fieldName} must be ${HASH_LEN_V1} bytes`);
  }
  return new Uint8Array(bytes);
}

function decodeFieldElementBytesV1(value: string, fieldName: string): Uint8Array {
  return validateFieldElement521BytesV1(
    decodeCanonicalFixedHexBytesV1(value, FIELD_ELEMENT_521_BYTE_LEN_V1, fieldName),
    fieldName,
  );
}

export function stormEncryptionBindingToDebugHexV1(
  binding: StormEncryptionBindingV1,
): Record<string, string> {
  const canonical = validateStormEncryptionBindingV1(binding);
  return {
    stormClaimDigestHex: bytesToHexLowerV1(canonical.stormClaimDigest),
    traceRootHex: bytesToHexLowerV1(canonical.traceRoot),
    finalStateXHex: bytesToHexLowerV1(canonical.finalStateX),
    finalStateYHex: bytesToHexLowerV1(canonical.finalStateY),
    contextHashHex: bytesToHexLowerV1(canonical.contextHash),
    senderIdHex: bytesToHexLowerV1(canonical.senderId),
    receiverIdHex: bytesToHexLowerV1(canonical.receiverId),
    sessionKeyIdHex: bytesToHexLowerV1(canonical.sessionKeyId),
  };
}
