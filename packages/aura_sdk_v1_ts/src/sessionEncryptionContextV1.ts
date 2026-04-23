import { concatBytesV1 } from "./stormHash521V1.ts";
import { validateStormContextBytesV1 } from "./stormContextV1.ts";

export const SESSION_ENCRYPTION_CONTEXT_V1_VERSION = 0x01;
export const SESSION_ENCRYPTION_CONTEXT_V1_LEN = 209;

export type AuraSessionEncryptionContextV1 = {
  version: number;
  stormClaimDigest: Uint8Array;
  senderId: Uint8Array;
  receiverId: Uint8Array;
  freshnessNonce: Uint8Array;
  validFrom: bigint;
  validUntil: bigint;
  routeTag: Uint8Array;
  sessionKeyId: Uint8Array;
};

export type StormSessionEncryptionFieldsV1 = {
  freshnessNonce: Uint8Array;
  validFrom: bigint;
  validUntil: bigint;
  routeTag: Uint8Array;
};

export function encodeSessionEncryptionContextV1(
  context: AuraSessionEncryptionContextV1,
): Uint8Array {
  validateSessionEncryptionContextV1(context);
  return concatBytesV1(
    Uint8Array.of(context.version),
    cloneBytes32(context.stormClaimDigest, "stormClaimDigest"),
    cloneBytes32(context.senderId, "senderId"),
    cloneBytes32(context.receiverId, "receiverId"),
    cloneBytes32(context.freshnessNonce, "freshnessNonce"),
    encodeU64Le(context.validFrom, "validFrom"),
    encodeU64Le(context.validUntil, "validUntil"),
    cloneBytes32(context.routeTag, "routeTag"),
    cloneBytes32(context.sessionKeyId, "sessionKeyId"),
  );
}

export function validateSessionEncryptionContextV1(
  context: AuraSessionEncryptionContextV1,
): AuraSessionEncryptionContextV1 {
  requireByte(context.version, "session encryption context version");
  cloneBytes32(context.stormClaimDigest, "stormClaimDigest");
  cloneBytes32(context.senderId, "senderId");
  cloneBytes32(context.receiverId, "receiverId");
  cloneBytes32(context.freshnessNonce, "freshnessNonce");
  cloneBytes32(context.routeTag, "routeTag");
  cloneBytes32(context.sessionKeyId, "sessionKeyId");

  if (context.version !== SESSION_ENCRYPTION_CONTEXT_V1_VERSION) {
    throw new TypeError(
      `session encryption context version must be ${SESSION_ENCRYPTION_CONTEXT_V1_VERSION}, got ${context.version}`,
    );
  }

  if (context.validFrom > context.validUntil) {
    throw new TypeError("session encryption context validFrom must not exceed validUntil");
  }

  return context;
}

export function extractStormSessionEncryptionFieldsV1(
  stormContextBytes: Uint8Array,
): StormSessionEncryptionFieldsV1 {
  const canonical = validateStormContextBytesV1(stormContextBytes);

  return {
    freshnessNonce: canonical.slice(97, 129),
    validFrom: decodeU64Le(canonical.subarray(129, 137)),
    validUntil: decodeU64Le(canonical.subarray(137, 145)),
    routeTag: canonical.slice(177, 209),
  };
}

function cloneBytes32(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new TypeError(`${fieldName} must be 32 bytes`);
  }
  return new Uint8Array(bytes);
}

function requireByte(value: number, fieldName: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new TypeError(`${fieldName} must be a u8`);
  }
}

function encodeU64Le(value: bigint, fieldName: string): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new TypeError(`${fieldName} must fit u64`);
  }

  const bytes = new Uint8Array(8);
  let remaining = value;
  for (let index = 0; index < 8; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function decodeU64Le(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new TypeError("u64 byte slice must be 8 bytes");
  }

  let value = 0n;
  for (let index = 7; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}
