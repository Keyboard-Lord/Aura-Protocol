import { createHash } from "node:crypto";

import { concatBytesV1 } from "./stormHash521V1.ts";

export const STORM_CONTEXT_V1_LEN = 209;
export const STORM_CONTEXT_V1_VERSION = 0x01;

export type StormContextV1 = {
  contextVersion: number;
  networkId: Uint8Array;
  intentHash: Uint8Array;
  freshnessNonce: Uint8Array;
  validFrom: bigint;
  validUntil: bigint;
  controllerId: Uint8Array;
  routeTag: Uint8Array;
};

export function executionDomainV1(): Uint8Array {
  return new Uint8Array(
    createHash("sha3-512").update("AURA_STORM_EXECUTION_V1").digest().subarray(0, 32),
  );
}

export function encodeStormContextV1(ctx: StormContextV1): Uint8Array {
  requireByte(ctx.contextVersion, "storm context version");
  requireBytes32(ctx.networkId, "storm context networkId");
  requireBytes32(ctx.intentHash, "storm context intentHash");
  requireBytes32(ctx.freshnessNonce, "storm context freshnessNonce");
  requireBytes32(ctx.controllerId, "storm context controllerId");
  requireBytes32(ctx.routeTag, "storm context routeTag");

  if (ctx.contextVersion !== STORM_CONTEXT_V1_VERSION) {
    throw new TypeError(
      `storm context version must be ${STORM_CONTEXT_V1_VERSION}, got ${ctx.contextVersion}`,
    );
  }

  return concatBytesV1(
    Uint8Array.of(ctx.contextVersion),
    ctx.networkId,
    executionDomainV1(),
    ctx.intentHash,
    ctx.freshnessNonce,
    encodeU64Le(ctx.validFrom, "storm context validFrom"),
    encodeU64Le(ctx.validUntil, "storm context validUntil"),
    ctx.controllerId,
    ctx.routeTag,
  );
}

export function validateStormContextBytesV1(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== STORM_CONTEXT_V1_LEN) {
    throw new TypeError(`storm context bytes must be ${STORM_CONTEXT_V1_LEN} bytes`);
  }

  if ((bytes[0] ?? 0) !== STORM_CONTEXT_V1_VERSION) {
    throw new TypeError(
      `storm context version byte must be ${STORM_CONTEXT_V1_VERSION}, got ${bytes[0] ?? 0}`,
    );
  }

  const expectedExecutionDomain = executionDomainV1();
  const actualExecutionDomain = bytes.subarray(33, 65);
  for (let index = 0; index < 32; index += 1) {
    if ((actualExecutionDomain[index] ?? 0) !== (expectedExecutionDomain[index] ?? 0)) {
      throw new TypeError("storm context execution domain mismatch");
    }
  }

  return new Uint8Array(bytes);
}

function requireByte(value: number, fieldName: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new TypeError(`${fieldName} must be a u8`);
  }
}

function requireBytes32(bytes: Uint8Array, fieldName: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new TypeError(`${fieldName} must be 32 bytes`);
  }
}

function encodeU64Le(value: bigint, fieldName: string): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new TypeError(`${fieldName} must fit u64`);
  }

  const output = new Uint8Array(8);
  let remaining = value;
  for (let index = 0; index < 8; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}
