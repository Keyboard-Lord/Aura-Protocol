import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { buildEncryptedEnvelopeV1, decryptPayloadV1, deriveAadContextHashV1, deriveSessionKeyIdV1, deriveSessionPublicKeyV1, deriveSessionSymmetricKeyV1, deriveSharedSecretV1, encodeSessionEncryptionContextV1, encodeStormEncryptionBindingV1, validateEncryptedEnvelopeV1, type AuraEncryptedEnvelopeV1, type AuraSessionEncryptionContextV1, type SessionPublicKeyV1, type SessionSecretKeyV1, type StormEncryptionBindingV1, ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID, ENCRYPTED_ENVELOPE_V1_NONCE_LEN, ENCRYPTED_ENVELOPE_V1_TAG_LEN, ENCRYPTED_ENVELOPE_V1_VERSION, SESSION_ENCRYPTION_CONTEXT_V1_VERSION } from "../src/index.ts";
import { bytesToHexLowerV1, decodeCanonicalFixedHexBytesV1 } from "../src/stormHash521V1.ts";

type SessionEncryptionParityFixtureV1 = {
  contract: string;
  fixture_name: string;
  proof_session_id_hex: string;
  storm_claim_digest_hex: string;
  trace_root_hex: string;
  final_state_x_hex: string;
  final_state_y_hex: string;
  context_hash_hex: string;
  sender_secret_key_hex: string;
  sender_public_key_hex: string;
  receiver_secret_key_hex: string;
  receiver_public_key_hex: string;
  sender_id_hex: string;
  receiver_id_hex: string;
  freshness_nonce_hex: string;
  valid_from: number;
  valid_until: number;
  route_tag_hex: string;
  session_key_id_hex: string;
  encoded_context_hex: string;
  encoded_binding_hex: string;
  shared_secret_hex: string;
  session_symmetric_key_hex: string;
  aad_context_hash_hex: string;
  nonce_hex: string;
  plaintext_hex: string;
  decrypt_result_hex: string;
  ciphertext_hex: string;
};

test("shared secret agreement is symmetric", () => {
  const fixture = loadFixture();
  const senderSecretKey = secretKey(fixture.sender_secret_key_hex);
  const receiverSecretKey = secretKey(fixture.receiver_secret_key_hex);
  const senderPublicKey = publicKey(fixture.sender_public_key_hex);
  const receiverPublicKey = publicKey(fixture.receiver_public_key_hex);

  assert.equal(bytesToHexLowerV1(deriveSessionPublicKeyV1(senderSecretKey).bytes), fixture.sender_public_key_hex);
  assert.equal(bytesToHexLowerV1(deriveSessionPublicKeyV1(receiverSecretKey).bytes), fixture.receiver_public_key_hex);

  const left = deriveSharedSecretV1(senderSecretKey, receiverPublicKey);
  const right = deriveSharedSecretV1(receiverSecretKey, senderPublicKey);

  assert.equal(bytesToHexLowerV1(left.bytes), fixture.shared_secret_hex);
  assert.equal(bytesToHexLowerV1(right.bytes), fixture.shared_secret_hex);
});

test("session symmetric key derivation matches the frozen parity vector", () => {
  const fixture = loadFixture();
  const parity = canonicalParityMaterial(fixture);

  assert.equal(bytesToHexLowerV1(parity.context.stormClaimDigest), fixture.storm_claim_digest_hex);
  assert.equal(bytesToHexLowerV1(parity.binding.traceRoot), fixture.trace_root_hex);
  assert.equal(bytesToHexLowerV1(parity.binding.finalStateX), fixture.final_state_x_hex);
  assert.equal(bytesToHexLowerV1(parity.binding.finalStateY), fixture.final_state_y_hex);
  assert.equal(bytesToHexLowerV1(parity.binding.contextHash), fixture.context_hash_hex);
  assert.equal(bytesToHexLowerV1(encodeSessionEncryptionContextV1(parity.context)), fixture.encoded_context_hex);
  assert.equal(bytesToHexLowerV1(encodeStormEncryptionBindingV1(parity.binding)), fixture.encoded_binding_hex);
  assert.equal(bytesToHexLowerV1(parity.context.sessionKeyId), fixture.session_key_id_hex);
  assert.equal(bytesToHexLowerV1(parity.sharedSecret.bytes), fixture.shared_secret_hex);
  assert.equal(bytesToHexLowerV1(parity.symmetricKey.bytes), fixture.session_symmetric_key_hex);
  assert.equal(
    bytesToHexLowerV1(deriveAadContextHashV1(parity.context, parity.binding)),
    fixture.aad_context_hash_hex,
  );
});

test("encrypt then decrypt round trip matches the frozen vector", () => {
  const fixture = loadFixture();
  const parity = canonicalParityMaterial(fixture);
  const envelope = buildEncryptedEnvelopeV1(
    parity.senderSecretKey,
    parity.receiverPublicKey,
    parity.context,
    parity.binding,
    decodeCanonicalFixedHexBytesV1(fixture.plaintext_hex, fixture.plaintext_hex.length / 2, "plaintext_hex"),
    decodeCanonicalFixedHexBytesV1(fixture.nonce_hex, ENCRYPTED_ENVELOPE_V1_NONCE_LEN, "nonce_hex"),
  );

  assert.equal(envelope.version, ENCRYPTED_ENVELOPE_V1_VERSION);
  assert.equal(envelope.algorithmId, ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID);
  assert.equal(bytesToHexLowerV1(envelope.ciphertext), fixture.ciphertext_hex);

  const plaintext = decryptPayloadV1(
    parity.receiverSecretKey,
    envelope.senderPublicKey,
    parity.context,
    parity.binding,
    envelope.nonce,
    envelope.ciphertext,
  );
  assert.equal(bytesToHexLowerV1(plaintext), fixture.decrypt_result_hex);
  assert.equal(bytesToHexLowerV1(plaintext), fixture.plaintext_hex);
});

test("wrong context fails validation", () => {
  const fixture = loadFixture();
  const parity = canonicalParityMaterial(fixture);
  const envelope = canonicalEnvelopeFromFixture(fixture, parity.context);
  const wrongContext: AuraSessionEncryptionContextV1 = {
    ...parity.context,
    routeTag: parity.context.routeTag.map((value, index) => (index === 0 ? value ^ 0xff : value)),
  };

  assert.throws(
    () => validateEncryptedEnvelopeV1(envelope, wrongContext, parity.binding),
    /aadContextHash does not match the supplied encryption context and storm binding/,
  );
});

test("wrong nonce and wrong session material fail", () => {
  const fixture = loadFixture();
  const parity = canonicalParityMaterial(fixture);
  const envelope = canonicalEnvelopeFromFixture(fixture, parity.context);
  const wrongNonce = envelope.nonce.slice();
  wrongNonce[0] ^= 0x01;

  assert.throws(
    () =>
      decryptPayloadV1(
        parity.receiverSecretKey,
        envelope.senderPublicKey,
        parity.context,
        parity.binding,
        wrongNonce,
        envelope.ciphertext,
      ),
    /Unsupported state or unable to authenticate data/,
  );

  const wrongBinding: StormEncryptionBindingV1 = {
    ...parity.binding,
    traceRoot: parity.binding.traceRoot.map((value, index) => (index === 0 ? value ^ 0x80 : value)),
  };
  assert.throws(
    () =>
      decryptPayloadV1(
        parity.receiverSecretKey,
        envelope.senderPublicKey,
        parity.context,
        wrongBinding,
        envelope.nonce,
        envelope.ciphertext,
      ),
    /sessionEncryptionContext\.sessionKeyId does not match derived session key id/,
  );
});

test("wrong receiver fails", () => {
  const fixture = loadFixture();
  const parity = canonicalParityMaterial(fixture);
  const envelope = canonicalEnvelopeFromFixture(fixture, parity.context);
  const wrongReceiverSecretKey = secretKey("83".repeat(32));

  assert.throws(
    () =>
      decryptPayloadV1(
        wrongReceiverSecretKey,
        envelope.senderPublicKey,
        parity.context,
        parity.binding,
        envelope.nonce,
        envelope.ciphertext,
      ),
    /sessionEncryptionContext\.sessionKeyId does not match derived session key id/,
  );
});

test("envelope validation rejects malformed fields", () => {
  const fixture = loadFixture();
  const parity = canonicalParityMaterial(fixture);
  const envelope = canonicalEnvelopeFromFixture(fixture, parity.context);

  assert.throws(
    () => validateEncryptedEnvelopeV1({ ...envelope, version: envelope.version ^ 0xff }, parity.context, parity.binding),
    /encrypted envelope version must be/,
  );
  assert.throws(
    () =>
      validateEncryptedEnvelopeV1(
        { ...envelope, algorithmId: envelope.algorithmId ^ 0xff },
        parity.context,
        parity.binding,
      ),
    /encrypted envelope algorithmId must be/,
  );
  assert.throws(
    () =>
      validateEncryptedEnvelopeV1(
        { ...envelope, ciphertext: new Uint8Array(ENCRYPTED_ENVELOPE_V1_TAG_LEN - 1) },
        parity.context,
        parity.binding,
      ),
    /ciphertext must be at least/,
  );
});

function canonicalParityMaterial(fixture: SessionEncryptionParityFixtureV1): {
  senderSecretKey: SessionSecretKeyV1;
  receiverSecretKey: SessionSecretKeyV1;
  receiverPublicKey: SessionPublicKeyV1;
  sharedSecret: { bytes: Uint8Array };
  symmetricKey: { bytes: Uint8Array };
  context: AuraSessionEncryptionContextV1;
  binding: StormEncryptionBindingV1;
} {
  const senderSecretKey = secretKey(fixture.sender_secret_key_hex);
  const receiverSecretKey = secretKey(fixture.receiver_secret_key_hex);
  const receiverPublicKey = publicKey(fixture.receiver_public_key_hex);
  const sharedSecret = deriveSharedSecretV1(senderSecretKey, receiverPublicKey);

  const baseContext: AuraSessionEncryptionContextV1 = {
    version: SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
    stormClaimDigest: decodeCanonicalFixedHexBytesV1(
      fixture.storm_claim_digest_hex,
      32,
      "storm_claim_digest_hex",
    ),
    senderId: decodeCanonicalFixedHexBytesV1(fixture.sender_id_hex, 32, "sender_id_hex"),
    receiverId: decodeCanonicalFixedHexBytesV1(fixture.receiver_id_hex, 32, "receiver_id_hex"),
    freshnessNonce: decodeCanonicalFixedHexBytesV1(
      fixture.freshness_nonce_hex,
      32,
      "freshness_nonce_hex",
    ),
    validFrom: BigInt(fixture.valid_from),
    validUntil: BigInt(fixture.valid_until),
    routeTag: decodeCanonicalFixedHexBytesV1(fixture.route_tag_hex, 32, "route_tag_hex"),
    sessionKeyId: new Uint8Array(32),
  };
  const baseBinding: StormEncryptionBindingV1 = {
    stormClaimDigest: decodeCanonicalFixedHexBytesV1(
      fixture.storm_claim_digest_hex,
      32,
      "storm_claim_digest_hex",
    ),
    traceRoot: decodeCanonicalFixedHexBytesV1(fixture.trace_root_hex, 32, "trace_root_hex"),
    finalStateX: decodeCanonicalFixedHexBytesV1(fixture.final_state_x_hex, 66, "final_state_x_hex"),
    finalStateY: decodeCanonicalFixedHexBytesV1(fixture.final_state_y_hex, 66, "final_state_y_hex"),
    contextHash: decodeCanonicalFixedHexBytesV1(fixture.context_hash_hex, 32, "context_hash_hex"),
    senderId: decodeCanonicalFixedHexBytesV1(fixture.sender_id_hex, 32, "sender_id_hex"),
    receiverId: decodeCanonicalFixedHexBytesV1(fixture.receiver_id_hex, 32, "receiver_id_hex"),
    sessionKeyId: new Uint8Array(32),
  };
  const sessionKeyId = deriveSessionKeyIdV1(sharedSecret, baseContext, baseBinding);
  const context: AuraSessionEncryptionContextV1 = {
    ...baseContext,
    sessionKeyId,
  };
  const binding: StormEncryptionBindingV1 = {
    ...baseBinding,
    sessionKeyId,
  };
  const symmetricKey = deriveSessionSymmetricKeyV1({
    sharedSecret,
    sessionEncryptionContext: context,
    stormEncryptionBinding: binding,
  });

  return {
    senderSecretKey,
    receiverSecretKey,
    receiverPublicKey,
    sharedSecret,
    symmetricKey,
    context,
    binding,
  };
}

function canonicalEnvelopeFromFixture(
  fixture: SessionEncryptionParityFixtureV1,
  context: AuraSessionEncryptionContextV1,
): AuraEncryptedEnvelopeV1 {
  return {
    version: ENCRYPTED_ENVELOPE_V1_VERSION,
    algorithmId: ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
    senderPublicKey: publicKey(fixture.sender_public_key_hex),
    receiverPublicKey: publicKey(fixture.receiver_public_key_hex),
    nonce: decodeCanonicalFixedHexBytesV1(fixture.nonce_hex, ENCRYPTED_ENVELOPE_V1_NONCE_LEN, "nonce_hex"),
    aadContextHash: decodeCanonicalFixedHexBytesV1(
      fixture.aad_context_hash_hex,
      32,
      "aad_context_hash_hex",
    ),
    ciphertext: decodeCanonicalFixedHexBytesV1(
      fixture.ciphertext_hex,
      fixture.ciphertext_hex.length / 2,
      "ciphertext_hex",
    ),
    sessionKeyId: context.sessionKeyId,
  };
}

function publicKey(hex: string): SessionPublicKeyV1 {
  return { bytes: decodeCanonicalFixedHexBytesV1(hex, 32, "public key") };
}

function secretKey(hex: string): SessionSecretKeyV1 {
  return { bytes: decodeCanonicalFixedHexBytesV1(hex, 32, "secret key") };
}

function loadFixture(): SessionEncryptionParityFixtureV1 {
  return JSON.parse(
    readFileSync(
      new URL("../../../fixtures/v1/session_encryption_v1/session_encryption_parity_vector_v1.json", import.meta.url),
      "utf8",
    ),
  ) as SessionEncryptionParityFixtureV1;
}
