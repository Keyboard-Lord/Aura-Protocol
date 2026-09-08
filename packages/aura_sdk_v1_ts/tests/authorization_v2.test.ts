import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  authorizationSigningDigestV2, validateAuthorizationShapeV2,
  verifyAuthorizationSignatureV2, verifyAuthorizationMaterialBindingV2,
  signAuthorizationV2, freshNonceV2,
} from "../src/authorizationV2.ts";

const vector = JSON.parse(readFileSync(new URL("../../../fixtures/authorization_v2/authorization_vector_v2.json", import.meta.url), "utf8"));
const envelope = vector.authorization;
const bytes = (value: string) => Buffer.from(value, "hex");

test("Rust BIP340 vector and unchanged proof material agree", async () => {
  assert.equal(Buffer.from(authorizationSigningDigestV2(envelope, "regtest")).toString("hex"), vector.signing_digest_hex);
  assert.deepEqual(verifyAuthorizationSignatureV2(envelope, "regtest"), envelope);
  assert.deepEqual(await verifyAuthorizationMaterialBindingV2(envelope, "regtest", bytes(vector.proof_bytes_hex), bytes(vector.public_inputs_hex)), envelope);
  const signed = signAuthorizationV2("regtest", envelope.proof_hash_hex,
    envelope.authorization_lineage.intent_commitment_hex, envelope.authorization_lineage.freshness_binding,
    bytes(vector.test_only_secret_key_hex));
  verifyAuthorizationSignatureV2(signed, "regtest");
  assert.equal(signed.authorization_lineage.subject_binding, envelope.authorization_lineage.subject_binding);
  assert.equal(freshNonceV2().length, 32);
});

test("authorization rejects legacy, missing, extra and malformed fields", () => {
  for (const mutate of [
    (e: any) => { e.intent_id_hex = "44".repeat(32); },
    (e: any) => { delete e.signature_hex; },
    (e: any) => { e.authorization_version = "v1"; },
    (e: any) => { e.signature_hex = e.signature_hex.toUpperCase(); },
    (e: any) => { e.authorization_lineage.subject_binding = "ff".repeat(32); },
    (e: any) => { e.authorization_lineage.extra = true; },
    (e: any) => { e.authorization_lineage.freshness_binding = "00"; },
  ]) {
    const changed = structuredClone(envelope); mutate(changed);
    assert.throws(() => validateAuthorizationShapeV2(changed));
  }
});

test("signature binds network, intent, proof reference and subject", () => {
  assert.throws(() => verifyAuthorizationSignatureV2(envelope, "mainnet"));
  for (const mutate of [
    (e: any) => { e.proof_hash_hex = "ff".repeat(32); },
    (e: any) => { e.authorization_lineage.intent_commitment_hex = "ff".repeat(32); },
    (e: any) => { e.signature_hex = "00".repeat(64); },
    (e: any) => { e.authorization_lineage.subject_binding = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; },
  ]) {
    const changed = structuredClone(envelope); mutate(changed);
    assert.throws(() => verifyAuthorizationSignatureV2(changed, "regtest"));
  }
});

test("nonce and actual material mutations fail binding", async () => {
  const changed = structuredClone(envelope);
  changed.authorization_lineage.freshness_binding = "ee".repeat(32);
  await assert.rejects(verifyAuthorizationMaterialBindingV2(changed, "regtest", bytes(vector.proof_bytes_hex), bytes(vector.public_inputs_hex)), /material binding/);
  const proof = bytes(vector.proof_bytes_hex); proof[20] ^= 1;
  await assert.rejects(verifyAuthorizationMaterialBindingV2(envelope, "regtest", proof, bytes(vector.public_inputs_hex)), /material binding/);
  const inputs = bytes(vector.public_inputs_hex); inputs[20] ^= 1;
  await assert.rejects(verifyAuthorizationMaterialBindingV2(envelope, "regtest", bytes(vector.proof_bytes_hex), inputs), /material binding/);
});
