/**
 * @fileoverview Legacy byte encoding and SHA-256 root for Aura messages - DEPRECATED.
 * 
 * @deprecated This module implements AURA_HASH_V1 which uses SHA-256 and produces 256-bit output.
 * The active protocol uses AURA_HASH_V2 (H_521 with SHA3-512) via `stormHash521V1`.
 * 
 * Use `stormHash521V1` from `./stormHash521V1.ts` for all new implementations.
 * 
 * This module is preserved only for historical compatibility and testing against
 * known vectors. It will be removed in a future release.
 */

import { createHash } from "node:crypto";

const textEncoder = new TextEncoder();
const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export const AURA_HASH_V1_DOMAIN_SEPARATOR = textEncoder.encode("AURA_HASH_V1");
export const AURA_HASH_V1_LENGTH_PREFIX_BYTES = 8;
export const AURA_HASH_V1_BOM_CODEPOINT = "\uFEFF";

export function canonicalMessageBytesV1(messageBytes: Uint8Array): Uint8Array {
  const bytes = requireUint8ArrayV1(messageBytes, "messageBytes");
  const canonical = new Uint8Array(AURA_HASH_V1_LENGTH_PREFIX_BYTES + bytes.length);
  const view = new DataView(canonical.buffer, canonical.byteOffset, canonical.byteLength);
  view.setBigUint64(0, BigInt(bytes.length), true);
  canonical.set(bytes, AURA_HASH_V1_LENGTH_PREFIX_BYTES);
  return canonical;
}

export function canonicalMessageHashPreimageV1(messageBytes: Uint8Array): Uint8Array {
  return concatBytesV1(AURA_HASH_V1_DOMAIN_SEPARATOR, canonicalMessageBytesV1(messageBytes));
}

export function auraHashV1(messageBytes: Uint8Array): Uint8Array {
  return sha256BytesV1(canonicalMessageHashPreimageV1(messageBytes));
}

export function normalizeTextMessageV1(message: string): string {
  requireNoUnpairedSurrogatesV1(message, "message");
  const normalized = message.normalize("NFC").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const bomIndex = normalized.indexOf(AURA_HASH_V1_BOM_CODEPOINT);
  if (bomIndex !== -1) {
    throw new TypeError(`message contains a BOM codepoint at character index ${bomIndex}`);
  }
  return normalized;
}

export function decodeAndNormalizeMessageUtf8V1(messageUtf8: Uint8Array): string {
  const bytes = requireUint8ArrayV1(messageUtf8, "messageUtf8");
  let decoded: string;
  try {
    decoded = fatalUtf8Decoder.decode(bytes);
  } catch {
    throw new TypeError("message must be valid UTF-8 text");
  }
  return normalizeTextMessageV1(decoded);
}

export function canonicalTextPayloadBytesFromTextV1(message: string): Uint8Array {
  return textEncoder.encode(normalizeTextMessageV1(message));
}

export function canonicalTextPayloadBytesV1(messageUtf8: Uint8Array): Uint8Array {
  return textEncoder.encode(decodeAndNormalizeMessageUtf8V1(messageUtf8));
}

export function bytesToHexLowerV1(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function decodeHexBytesV1(value: string, fieldName: string): Uint8Array {
  if (value.length % 2 !== 0) {
    throw new TypeError(`${fieldName} must be even-length lowercase hex`);
  }
  if (!/^[0-9a-f]*$/.test(value)) {
    throw new TypeError(`${fieldName} must be canonical lowercase hex`);
  }
  return new Uint8Array(Buffer.from(value, "hex"));
}

function sha256BytesV1(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(Buffer.from(bytes)).digest());
}

function concatBytesV1(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function requireUint8ArrayV1(bytes: Uint8Array, fieldName: string): Uint8Array {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError(`${fieldName} must be a Uint8Array`);
  }
  return new Uint8Array(bytes);
}

function requireNoUnpairedSurrogatesV1(value: string, fieldName: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${fieldName} contains an unpaired high surrogate at index ${index}`);
      }
      index += 1;
      continue;
    }
    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(`${fieldName} contains an unpaired low surrogate at index ${index}`);
    }
  }
}
