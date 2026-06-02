import { createHash } from "node:crypto";

/**
 * Canonical SHA3-based 521-bit hash construction for the storm lower layer.
 * 
 * Implements the canonical identity function per AURA_HASH_V2:
 * H_521(m) = Reduce_N(SHA3-512(m)) where N = 2^521 - 1
 */

export const AURA_HASH521_V1_OUTPUT_BITS = 521;
export const AURA_HASH521_V1_OUTPUT_BYTES = 66;
export const FIELD_ELEMENT_521_BYTE_LEN_V1 = 66;

/** Field modulus 2^521 - 1 as big-endian bytes */
export const FIELD_MODULUS_521_BYTES_V1 = (() => {
  const bytes = new Uint8Array(FIELD_ELEMENT_521_BYTE_LEN_V1);
  bytes[0] = 0x01;
  bytes.fill(0xff, 1);
  return bytes;
})();

/**
 * Canonical H_521 hash function per AURA_HASH_V2 specification.
 * 
 * H_521(m) = Reduce_N(SHA3-512(m)) where N = 2^521 - 1
 * 
 * The SHA3-512 output (512 bits) is interpreted as a big-endian integer
 * and reduced into the 521-bit field. This is the sole canonical identity
 * construction for the active Aura protocol.
 */
export function auraHash521V1(msg: Uint8Array): Uint8Array {
  const hashBytes = sha3_512_bytes(msg);
  return reduceBytesMod521(hashBytes);
}

export function auraHash521V1ToHex(msg: Uint8Array): string {
  return bytesToHexLowerV1(auraHash521V1(msg));
}

function sha3_512_bytes(msg: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha3-512").update(Buffer.from(msg)).digest());
}

/** Reduce arbitrary bytes modulo 2^521 - 1 */
function reduceBytesMod521(bytes: Uint8Array): Uint8Array {
  const MODULUS_521_V1 = (1n << 521n) - 1n;
  
  // Interpret bytes as big-endian integer
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  
  // Reduce modulo 2^521 - 1
  const reduced = value % MODULUS_521_V1;
  
  const result = fieldBigIntToRustBytesV1(reduced);
  
  return validateFieldElement521BytesV1(result, "H_521 output");
}

function fieldBigIntToRustBytesV1(value: bigint): Uint8Array {
  const result = new Uint8Array(FIELD_ELEMENT_521_BYTE_LEN_V1);
  let remaining = value;
  const limbs: number[] = [];

  for (let index = 0; index < 17; index += 1) {
    limbs.push(Number(remaining & 0xffff_ffffn));
    remaining >>= 32n;
  }

  for (let limbIndex = 0; limbIndex < 16; limbIndex += 1) {
    const limb = limbs[limbIndex] ?? 0;
    const start = FIELD_ELEMENT_521_BYTE_LEN_V1 - ((limbIndex + 1) * 4);
    result[start] = (limb >>> 24) & 0xff;
    result[start + 1] = (limb >>> 16) & 0xff;
    result[start + 2] = (limb >>> 8) & 0xff;
    result[start + 3] = limb & 0xff;
  }

  const top = limbs[16] ?? 0;
  result[0] = (top >>> 8) & 0xff;
  result[1] = top & 0xff;

  return result;
}

export function bytesToHexLowerV1(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function decodeCanonicalFixedHexBytesV1(
  value: string,
  expectedBytes: number,
  fieldName: string,
): Uint8Array {
  if (value.length !== expectedBytes * 2) {
    throw new TypeError(`${fieldName} must be ${expectedBytes * 2} lowercase hex characters`);
  }

  if (!/^[0-9a-f]+$/.test(value)) {
    throw new TypeError(`${fieldName} must be canonical lowercase hex`);
  }

  const bytes = new Uint8Array(Buffer.from(value, "hex"));
  if (bytesToHexLowerV1(bytes) !== value) {
    throw new TypeError(`${fieldName} must be canonical lowercase hex`);
  }

  return bytes;
}

export function validateFieldElement521BytesV1(bytes: Uint8Array, fieldName: string): Uint8Array {
  requireLength(bytes, FIELD_ELEMENT_521_BYTE_LEN_V1, fieldName);

  if ((bytes[0] ?? 0) & 0xfe) {
    throw new TypeError(`${fieldName} has invalid top bits`);
  }

  if (compareBytesLexV1(bytes, FIELD_MODULUS_521_BYTES_V1) >= 0) {
    throw new TypeError(`${fieldName} is out of range for 2^521 - 1`);
  }

  return new Uint8Array(bytes);
}

export function compareBytesLexV1(left: Uint8Array, right: Uint8Array): number {
  requireLength(left, right.length, "byte comparison left");
  for (let index = 0; index < left.length; index += 1) {
    const lhs = left[index] ?? 0;
    const rhs = right[index] ?? 0;
    if (lhs < rhs) {
      return -1;
    }
    if (lhs > rhs) {
      return 1;
    }
  }

  return 0;
}

export function extractFirst9BitsMsbFirst(bytes: Uint8Array): number {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2) {
    throw new TypeError("first 9-bit extraction requires at least 2 bytes");
  }

  return ((bytes[0] ?? 0) << 1) | ((bytes[1] ?? 0) >> 7);
}

export function concatBytesV1(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }

  return output;
}

function requireLength(bytes: Uint8Array, expected: number, fieldName: string): void {
  if (bytes.length !== expected) {
    throw new TypeError(`${fieldName} must be ${expected} bytes, got ${bytes.length}`);
  }
}
