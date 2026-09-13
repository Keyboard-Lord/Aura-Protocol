// Shared content framing. Only the owning C1/C2 registries select domains.
import { createHash } from 'node:crypto';
export function computeContentDigest(domain: string, payload: Uint8Array): Uint8Array {
  if (!(payload instanceof Uint8Array)) throw new Error('compute content must be bytes');
  const length=Buffer.alloc(8);length.writeBigUInt64LE(BigInt(payload.length));
  return createHash('sha256').update(Buffer.from(domain,'ascii')).update(length).update(payload).digest();
}
