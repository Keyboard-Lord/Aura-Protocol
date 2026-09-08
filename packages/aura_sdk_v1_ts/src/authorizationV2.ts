import { prepareBoundProofMaterialV1 } from "./sdkCoreV1.ts";
import { createHash, randomBytes } from "node:crypto";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bitcoinNetworkTagV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";
import type { BitcoinNetworkV1 } from "../../aura_bitcoin_v1_ts/src/index.ts";

export type AuthorizationLineageV2 = {
  subject_binding_type: "bip340-xonly-pubkey-hex";
  subject_binding: string;
  intent_type: "opaque-intent-hash-32";
  intent_commitment_hex: string;
  freshness_binding_type: "nonce-32-hex";
  freshness_binding: string;
};
export type AuthorizationEnvelopeV2 = {
  authorization_version: "v2";
  proof_hash_hex: string;
  authorization_lineage: AuthorizationLineageV2;
  signature_hex: string;
};

function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || Reflect.ownKeys(value).length !== keys.length || !keys.every(k => Object.hasOwn(value, k))) {
    throw new TypeError("non-canonical authorization fields");
  }
  return value as Record<string, unknown>;
}
function hex(value: unknown, bytes: number): string {
  if (typeof value !== "string" || value.length !== bytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    throw new TypeError("non-canonical authorization hex");
  }
  return value;
}

export function validateAuthorizationShapeV2(value: unknown): AuthorizationEnvelopeV2 {
  const { authorization_version, proof_hash_hex, authorization_lineage, signature_hex } = record(value,
    ["authorization_version", "proof_hash_hex", "authorization_lineage", "signature_hex"]);
  const l = record(authorization_lineage, ["subject_binding_type", "subject_binding", "intent_type",
    "intent_commitment_hex", "freshness_binding_type", "freshness_binding"]);
  const { subject_binding_type, subject_binding, intent_type, intent_commitment_hex, freshness_binding_type, freshness_binding } = l;
  if (authorization_version !== "v2" || subject_binding_type !== "bip340-xonly-pubkey-hex"
    || intent_type !== "opaque-intent-hash-32" || freshness_binding_type !== "nonce-32-hex") {
    throw new TypeError("unsupported authorization version or lineage type");
  }
  const subject = hex(subject_binding, 32);
  secp256k1.Point.fromHex(`02${subject}`);
  return { authorization_version, proof_hash_hex: hex(proof_hash_hex, 32), authorization_lineage: {
    subject_binding_type, subject_binding: subject, intent_type, intent_commitment_hex: hex(intent_commitment_hex, 32),
    freshness_binding_type, freshness_binding: hex(freshness_binding, 32),
  }, signature_hex: hex(signature_hex, 64) };
}

export function authorizationSigningDigestV2(value: AuthorizationEnvelopeV2, network: BitcoinNetworkV1): Uint8Array {
  const envelope = validateAuthorizationShapeV2(value);
  const tag = createHash("sha256").update("AURA_AUTHORIZATION_V2").digest();
  return createHash("sha256").update(tag).update(tag).update(Uint8Array.of(bitcoinNetworkTagV1(network)))
    .update(Buffer.from(envelope.proof_hash_hex, "hex"))
    .update(Buffer.from(envelope.authorization_lineage.intent_commitment_hex, "hex")).digest();
}

/** Signature validation only; durable acceptance and actual proof verification belong to Rust. */
export function verifyAuthorizationSignatureV2(value: unknown, network: BitcoinNetworkV1): AuthorizationEnvelopeV2 {
  const envelope = validateAuthorizationShapeV2(value);
  if (!schnorr.verify(Buffer.from(envelope.signature_hex, "hex"), authorizationSigningDigestV2(envelope, network),
    Buffer.from(envelope.authorization_lineage.subject_binding, "hex"))) throw new Error("invalid authorization signature");
  return envelope;
}

export function freshNonceV2(): Uint8Array { return randomBytes(32); }

export function signAuthorizationV2(
  network: BitcoinNetworkV1, proofHashHex: string, intentCommitmentHex: string, nonceHex: string, secretKey: Uint8Array,
): AuthorizationEnvelopeV2 {
  const envelope = validateAuthorizationShapeV2({ authorization_version: "v2", proof_hash_hex: proofHashHex,
    authorization_lineage: { subject_binding_type: "bip340-xonly-pubkey-hex",
      subject_binding: Buffer.from(schnorr.getPublicKey(secretKey)).toString("hex"), intent_type: "opaque-intent-hash-32",
      intent_commitment_hex: intentCommitmentHex, freshness_binding_type: "nonce-32-hex", freshness_binding: nonceHex },
    signature_hex: "00".repeat(64) });
  envelope.signature_hex = Buffer.from(schnorr.sign(authorizationSigningDigestV2(envelope, network), secretKey)).toString("hex");
  return envelope;
}

/** Checks material identity, not proof soundness or replay state; Rust owns acceptance. */
export async function verifyAuthorizationMaterialBindingV2(
  value: unknown, network: BitcoinNetworkV1, proofBytes: Uint8Array, publicInputsBytes: Uint8Array,
): Promise<AuthorizationEnvelopeV2> {
  const envelope = verifyAuthorizationSignatureV2(value, network);
  const prepared = await prepareBoundProofMaterialV1(
    Buffer.from(envelope.authorization_lineage.subject_binding, "hex"),
    Buffer.from(envelope.authorization_lineage.freshness_binding, "hex"),
    proofBytes, publicInputsBytes, new Uint8Array(),
  );
  if (Buffer.from(prepared.proofHash).toString("hex") !== envelope.proof_hash_hex) {
    throw new Error("proof material binding mismatch");
  }
  return envelope;
}
