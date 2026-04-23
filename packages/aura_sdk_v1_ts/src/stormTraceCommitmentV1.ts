import { createHash } from "node:crypto";

import type { StormState521V1 } from "./stormStateV1.ts";
import { encodeStormRowBytesV1 } from "./stormStateV1.ts";

export function stormLeafHash(rowBytes: Uint8Array): Uint8Array {
  if (rowBytes.length !== 132) {
    throw new TypeError("storm row bytes must be 132 bytes");
  }

  return sha3_256(rowBytes);
}

export function merkleParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== 32 || right.length !== 32) {
    throw new TypeError("Merkle parents require two 32-byte nodes");
  }

  const payload = new Uint8Array(64);
  payload.set(left, 0);
  payload.set(right, 32);
  return sha3_256(payload);
}

export function computeStormTraceRoot(trace: StormState521V1[]): Uint8Array {
  if (trace.length === 0) {
    throw new TypeError("storm trace must contain at least the initial state");
  }

  let level = trace.map((state) => stormLeafHash(encodeStormRowBytesV1(state)));
  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level = [...level, level[level.length - 1]!];
    }

    const next: Uint8Array[] = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(merkleParent(level[index]!, level[index + 1]!));
    }
    level = next;
  }

  return level[0]!;
}

function sha3_256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha3-256").update(bytes).digest());
}
