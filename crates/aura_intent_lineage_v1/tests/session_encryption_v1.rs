mod support;

use std::{fs, path::PathBuf};

use aura_intent_lineage_v1::{
    build_encrypted_envelope_v1, build_storm_encryption_binding_from_proof_session_v1,
    decrypt_payload_v1, derive_aad_context_hash_v1, derive_session_key_id_v1,
    derive_session_public_key_v1, derive_session_symmetric_key_v1, derive_shared_secret_v1,
    encode_session_encryption_context_v1, encode_storm_encryption_binding_v1,
    extract_storm_session_encryption_fields_v1, package_proof_session_v1,
    validate_encrypted_envelope_v1, AuraEncryptedEnvelopeV1, AuraSessionEncryptionContextV1,
    SessionKeyDerivationInputV1, SessionPublicKeyV1, SessionSecretKeyV1,
    StormEncryptionBindingV1, SymmetricEnvelopeErrorV1, ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
    ENCRYPTED_ENVELOPE_V1_NONCE_LEN, ENCRYPTED_ENVELOPE_V1_TAG_LEN, ENCRYPTED_ENVELOPE_V1_VERSION,
    FIELD_ELEMENT_521_BYTE_LEN_V1, HASH_LEN_V1, SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
};
use serde::Deserialize;

use support::canonical_layer3_input;

#[derive(Debug, Deserialize)]
struct SessionEncryptionParityFixtureV1 {
    contract: String,
    fixture_name: String,
    proof_session_id_hex: String,
    storm_claim_digest_hex: String,
    trace_root_hex: String,
    final_state_x_hex: String,
    final_state_y_hex: String,
    context_hash_hex: String,
    sender_secret_key_hex: String,
    sender_public_key_hex: String,
    receiver_secret_key_hex: String,
    receiver_public_key_hex: String,
    sender_id_hex: String,
    receiver_id_hex: String,
    freshness_nonce_hex: String,
    valid_from: u64,
    valid_until: u64,
    route_tag_hex: String,
    session_key_id_hex: String,
    encoded_context_hex: String,
    encoded_binding_hex: String,
    shared_secret_hex: String,
    session_symmetric_key_hex: String,
    aad_context_hash_hex: String,
    nonce_hex: String,
    plaintext_hex: String,
    decrypt_result_hex: String,
    ciphertext_hex: String,
}

#[test]
fn shared_secret_agreement_is_symmetric() {
    let fixture = load_fixture();
    assert_eq!(fixture.contract, "AURA_SESSION_ENCRYPTION_V1_PARITY_VECTOR");
    assert_eq!(fixture.fixture_name, "session_encryption_parity_vector_v1");
    let sender_secret_key = secret_key(&fixture.sender_secret_key_hex);
    let sender_public_key = public_key(&fixture.sender_public_key_hex);
    let receiver_secret_key = secret_key(&fixture.receiver_secret_key_hex);
    let receiver_public_key = public_key(&fixture.receiver_public_key_hex);

    assert_eq!(
        derive_session_public_key_v1(&sender_secret_key),
        sender_public_key
    );
    assert_eq!(
        derive_session_public_key_v1(&receiver_secret_key),
        receiver_public_key
    );

    let sender_shared_secret =
        derive_shared_secret_v1(&sender_secret_key, &receiver_public_key).unwrap();
    let receiver_shared_secret =
        derive_shared_secret_v1(&receiver_secret_key, &sender_public_key).unwrap();

    assert_eq!(sender_shared_secret, receiver_shared_secret);
    assert_eq!(
        encode_hex(sender_shared_secret.bytes),
        fixture.shared_secret_hex
    );
}

#[test]
fn session_symmetric_key_derivation_matches_the_frozen_parity_vector() {
    let fixture = load_fixture();
    let parity = canonical_parity_material(&fixture);

    assert_eq!(
        encode_hex(parity.context.storm_claim_digest),
        fixture.storm_claim_digest_hex
    );
    assert_eq!(encode_hex(parity.binding.trace_root), fixture.trace_root_hex);
    assert_eq!(
        encode_hex(parity.binding.final_state_x),
        fixture.final_state_x_hex
    );
    assert_eq!(
        encode_hex(parity.binding.final_state_y),
        fixture.final_state_y_hex
    );
    assert_eq!(
        encode_hex(parity.binding.context_hash),
        fixture.context_hash_hex
    );
    assert_eq!(
        encode_hex(encode_session_encryption_context_v1(&parity.context).unwrap()),
        fixture.encoded_context_hex
    );
    assert_eq!(
        encode_hex(encode_storm_encryption_binding_v1(&parity.binding).unwrap()),
        fixture.encoded_binding_hex
    );
    assert_eq!(
        encode_hex(parity.context.session_key_id),
        fixture.session_key_id_hex
    );
    assert_eq!(
        encode_hex(parity.shared_secret.bytes),
        fixture.shared_secret_hex
    );
    assert_eq!(
        encode_hex(parity.symmetric_key.bytes),
        fixture.session_symmetric_key_hex
    );
    assert_eq!(
        encode_hex(derive_aad_context_hash_v1(&parity.context, &parity.binding).unwrap()),
        fixture.aad_context_hash_hex
    );
}

#[test]
fn encrypt_then_decrypt_round_trip_matches_the_frozen_vector() {
    let fixture = load_fixture();
    let parity = canonical_parity_material(&fixture);
    let plaintext = decode_hex(&fixture.plaintext_hex);
    let nonce = decode_fixed_hex::<ENCRYPTED_ENVELOPE_V1_NONCE_LEN>(&fixture.nonce_hex);

    let envelope = build_encrypted_envelope_v1(
        &parity.sender_secret_key,
        &parity.receiver_public_key,
        &parity.context,
        &parity.binding,
        &plaintext,
        Some(nonce),
    )
    .unwrap();

    validate_encrypted_envelope_v1(&envelope, &parity.context, &parity.binding).unwrap();
    assert_eq!(envelope.version, ENCRYPTED_ENVELOPE_V1_VERSION);
    assert_eq!(envelope.algorithm_id, ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID);
    assert_eq!(
        encode_hex(envelope.ciphertext.as_slice()),
        fixture.ciphertext_hex
    );

    let decrypted = decrypt_payload_v1(
        &parity.receiver_secret_key,
        &envelope.sender_public_key,
        &parity.context,
        &parity.binding,
        envelope.nonce,
        &envelope.ciphertext,
    )
    .unwrap();

    assert_eq!(encode_hex(&decrypted), fixture.decrypt_result_hex);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_context_fails_validation() {
    let fixture = load_fixture();
    let parity = canonical_parity_material(&fixture);
    let envelope = canonical_envelope_from_fixture(&parity, &fixture);
    let mut wrong_context = parity.context;
    wrong_context.route_tag[0] ^= 0xff;

    assert_eq!(
        validate_encrypted_envelope_v1(&envelope, &wrong_context, &parity.binding).unwrap_err(),
        SymmetricEnvelopeErrorV1::AadContextHashMismatch {
            expected: derive_aad_context_hash_v1(&wrong_context, &parity.binding).unwrap(),
            actual: envelope.aad_context_hash,
        }
    );
}

#[test]
fn wrong_nonce_and_wrong_session_material_fail() {
    let fixture = load_fixture();
    let parity = canonical_parity_material(&fixture);
    let envelope = canonical_envelope_from_fixture(&parity, &fixture);

    let mut wrong_nonce = envelope.nonce;
    wrong_nonce[0] ^= 0x01;
    assert_eq!(
        decrypt_payload_v1(
            &parity.receiver_secret_key,
            &envelope.sender_public_key,
            &parity.context,
            &parity.binding,
            wrong_nonce,
            &envelope.ciphertext,
        )
        .unwrap_err(),
        SymmetricEnvelopeErrorV1::DecryptFailed
    );

    let mut wrong_binding = parity.binding;
    wrong_binding.trace_root[0] ^= 0x80;
    assert!(matches!(
        decrypt_payload_v1(
            &parity.receiver_secret_key,
            &envelope.sender_public_key,
            &parity.context,
            &wrong_binding,
            envelope.nonce,
            &envelope.ciphertext,
        )
        .unwrap_err(),
        SymmetricEnvelopeErrorV1::InvalidSessionKey(_)
    ));
}

#[test]
fn wrong_receiver_fails() {
    let fixture = load_fixture();
    let parity = canonical_parity_material(&fixture);
    let envelope = canonical_envelope_from_fixture(&parity, &fixture);
    let wrong_receiver_secret_key = SessionSecretKeyV1 { bytes: [0x83; 32] };

    assert!(matches!(
        decrypt_payload_v1(
            &wrong_receiver_secret_key,
            &envelope.sender_public_key,
            &parity.context,
            &parity.binding,
            envelope.nonce,
            &envelope.ciphertext,
        )
        .unwrap_err(),
        SymmetricEnvelopeErrorV1::InvalidSessionKey(_)
    ));
}

#[test]
fn malformed_envelope_fields_are_rejected() {
    let fixture = load_fixture();
    let parity = canonical_parity_material(&fixture);
    let envelope = canonical_envelope_from_fixture(&parity, &fixture);

    let mut bad_version = envelope.clone();
    bad_version.version ^= 0xff;
    assert_eq!(
        validate_encrypted_envelope_v1(&bad_version, &parity.context, &parity.binding)
            .unwrap_err(),
        SymmetricEnvelopeErrorV1::InvalidEnvelopeVersion {
            expected: ENCRYPTED_ENVELOPE_V1_VERSION,
            actual: bad_version.version,
        }
    );

    let mut bad_algorithm = envelope.clone();
    bad_algorithm.algorithm_id ^= 0xff;
    assert_eq!(
        validate_encrypted_envelope_v1(&bad_algorithm, &parity.context, &parity.binding)
            .unwrap_err(),
        SymmetricEnvelopeErrorV1::UnsupportedAlgorithm {
            expected: ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
            actual: bad_algorithm.algorithm_id,
        }
    );

    let mut short_ciphertext = envelope.clone();
    short_ciphertext.ciphertext = vec![0u8; ENCRYPTED_ENVELOPE_V1_TAG_LEN - 1];
    assert_eq!(
        validate_encrypted_envelope_v1(&short_ciphertext, &parity.context, &parity.binding)
            .unwrap_err(),
        SymmetricEnvelopeErrorV1::InvalidCiphertextLength {
            minimum: ENCRYPTED_ENVELOPE_V1_TAG_LEN,
            actual: ENCRYPTED_ENVELOPE_V1_TAG_LEN - 1,
        }
    );
}

struct CanonicalParityMaterialV1 {
    sender_secret_key: SessionSecretKeyV1,
    receiver_secret_key: SessionSecretKeyV1,
    receiver_public_key: SessionPublicKeyV1,
    shared_secret: aura_intent_lineage_v1::SharedSecretV1,
    symmetric_key: aura_intent_lineage_v1::SessionSymmetricKeyV1,
    context: AuraSessionEncryptionContextV1,
    binding: StormEncryptionBindingV1,
}

fn canonical_parity_material(
    fixture: &SessionEncryptionParityFixtureV1,
) -> CanonicalParityMaterialV1 {
    let package = package_proof_session_v1(&canonical_layer3_input()).unwrap();
    assert_eq!(
        encode_hex(package.session_id.bytes),
        fixture.proof_session_id_hex
    );

    let storm_fields = extract_storm_session_encryption_fields_v1(
        &package
            .verifier_input_bundle
            .lower_layer_claim
            .context_bytes_v1,
    )
    .unwrap();
    assert_eq!(
        encode_hex(storm_fields.freshness_nonce),
        fixture.freshness_nonce_hex
    );
    assert_eq!(storm_fields.valid_from, fixture.valid_from);
    assert_eq!(storm_fields.valid_until, fixture.valid_until);
    assert_eq!(encode_hex(storm_fields.route_tag), fixture.route_tag_hex);

    let sender_id = decode_fixed_hex::<HASH_LEN_V1>(&fixture.sender_id_hex);
    let receiver_id = decode_fixed_hex::<HASH_LEN_V1>(&fixture.receiver_id_hex);
    let sender_secret_key = secret_key(&fixture.sender_secret_key_hex);
    let receiver_secret_key = secret_key(&fixture.receiver_secret_key_hex);
    let receiver_public_key = public_key(&fixture.receiver_public_key_hex);
    let shared_secret = derive_shared_secret_v1(&sender_secret_key, &receiver_public_key).unwrap();

    let base_binding = build_storm_encryption_binding_from_proof_session_v1(
        &package,
        sender_id,
        receiver_id,
        [0u8; HASH_LEN_V1],
    );
    let base_context = AuraSessionEncryptionContextV1 {
        version: SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
        storm_claim_digest: base_binding.storm_claim_digest,
        sender_id,
        receiver_id,
        freshness_nonce: storm_fields.freshness_nonce,
        valid_from: storm_fields.valid_from,
        valid_until: storm_fields.valid_until,
        route_tag: storm_fields.route_tag,
        session_key_id: [0u8; HASH_LEN_V1],
    };
    let session_key_id =
        derive_session_key_id_v1(&shared_secret, &base_context, &base_binding).unwrap();
    let context = AuraSessionEncryptionContextV1 {
        session_key_id,
        ..base_context
    };
    let binding = StormEncryptionBindingV1 {
        session_key_id,
        ..base_binding
    };
    let symmetric_key = derive_session_symmetric_key_v1(&SessionKeyDerivationInputV1 {
        shared_secret,
        session_encryption_context: context,
        storm_encryption_binding: binding,
    })
    .unwrap();

    CanonicalParityMaterialV1 {
        sender_secret_key,
        receiver_secret_key,
        receiver_public_key,
        shared_secret,
        symmetric_key,
        context,
        binding,
    }
}

fn canonical_envelope_from_fixture(
    parity: &CanonicalParityMaterialV1,
    fixture: &SessionEncryptionParityFixtureV1,
) -> AuraEncryptedEnvelopeV1 {
    AuraEncryptedEnvelopeV1 {
        version: ENCRYPTED_ENVELOPE_V1_VERSION,
        algorithm_id: ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
        sender_public_key: public_key(&fixture.sender_public_key_hex),
        receiver_public_key: public_key(&fixture.receiver_public_key_hex),
        nonce: decode_fixed_hex::<ENCRYPTED_ENVELOPE_V1_NONCE_LEN>(&fixture.nonce_hex),
        aad_context_hash: decode_fixed_hex::<HASH_LEN_V1>(&fixture.aad_context_hash_hex),
        ciphertext: decode_hex(&fixture.ciphertext_hex),
        session_key_id: parity.context.session_key_id,
    }
}

fn load_fixture() -> SessionEncryptionParityFixtureV1 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/session_encryption_v1/session_encryption_parity_vector_v1.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn public_key(hex: &str) -> SessionPublicKeyV1 {
    SessionPublicKeyV1 {
        bytes: decode_fixed_hex::<32>(hex),
    }
}

fn secret_key(hex: &str) -> SessionSecretKeyV1 {
    SessionSecretKeyV1 {
        bytes: decode_fixed_hex::<32>(hex),
    }
}

fn decode_fixed_hex<const N: usize>(hex: &str) -> [u8; N] {
    let decoded = decode_hex(hex);
    assert_eq!(decoded.len(), N);
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(&decoded);
    bytes
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    let mut output = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).unwrap();
        output.push(u8::from_str_radix(pair, 16).unwrap());
    }
    output
}

fn encode_hex<T: AsRef<[u8]>>(bytes: T) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[allow(dead_code)]
fn _assert_field_element_hex_len(hex: &str) {
    assert_eq!(hex.len(), FIELD_ELEMENT_521_BYTE_LEN_V1 * 2);
}
