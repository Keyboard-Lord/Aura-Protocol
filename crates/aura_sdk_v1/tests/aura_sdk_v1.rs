use aura_fractal_key_integration_v1::prepare_bound_proof_reference_v1;
use aura_proof_material_v1::ProofMaterialV1;
use aura_sdk_v1::{prepare_bound_proof_material_v1, PreparedBoundProofMaterialV1};
use std::fs;
use std::path::{Path, PathBuf};

struct CanonicalPrepareFixture {
    subject: [u8; 32],
    challenge: [u8; 32],
    proof_blob: Vec<u8>,
    public_inputs: Vec<u8>,
    verification_key: Vec<u8>,
    proof_blob_hash_hex: String,
    public_inputs_hash_hex: String,
    verification_key_hash_hex: String,
    proof_material_hash_hex: String,
    proof_hash_hex: String,
}

fn canonical_fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("v1")
        .join("canonical_prepare")
        .join(name)
}

fn canonical_prepare_fixture() -> CanonicalPrepareFixture {
    CanonicalPrepareFixture {
        subject: decode_hex_32(&load_hex_fixture("subject_pubkey.hex")),
        challenge: decode_hex_32(&load_hex_fixture("challenge_account_pubkey.hex")),
        proof_blob: fs::read(canonical_fixture_path("proof_blob.bin")).unwrap(),
        public_inputs: fs::read(canonical_fixture_path("public_inputs.bin")).unwrap(),
        verification_key: fs::read(canonical_fixture_path("verification_key.bin")).unwrap(),
        proof_blob_hash_hex: load_hex_fixture("proof_blob_hash.hex"),
        public_inputs_hash_hex: load_hex_fixture("public_inputs_hash.hex"),
        verification_key_hash_hex: load_hex_fixture("verification_key_hash.hex"),
        proof_material_hash_hex: load_hex_fixture("proof_material_hash.hex"),
        proof_hash_hex: load_hex_fixture("proof_hash.hex"),
    }
}

fn load_hex_fixture(name: &str) -> String {
    fs::read_to_string(canonical_fixture_path(name))
        .unwrap()
        .trim()
        .to_string()
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut output = [0u8; 32];

    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(chunk[0]) << 4) | decode_nibble(chunk[1]);
    }

    output
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex fixture"),
    }
}

fn expected_prepared_flow() -> PreparedBoundProofMaterialV1 {
    let fixture = canonical_prepare_fixture();
    let proof_material = ProofMaterialV1::build(
        &fixture.proof_blob,
        &fixture.public_inputs,
        &fixture.verification_key,
    );
    let proof_material_hash = proof_material.proof_material_hash();
    let preparation =
        prepare_bound_proof_reference_v1(fixture.subject, fixture.challenge, proof_material_hash).unwrap();

    PreparedBoundProofMaterialV1 {
        proof_material,
        proof_material_hash,
        fractal_key: preparation.fractal_key,
        proof_hash: preparation.proof_hash,
    }
}

#[test]
fn prepare_bound_proof_material_v1_matches_existing_layers() {
    let fixture = canonical_prepare_fixture();
    let prepared = prepare_bound_proof_material_v1(
        fixture.subject,
        fixture.challenge,
        &fixture.proof_blob,
        &fixture.public_inputs,
        &fixture.verification_key,
    )
    .unwrap();

    assert_eq!(prepared, expected_prepared_flow());
}

#[test]
fn prepare_bound_proof_material_v1_is_deterministic() {
    let fixture = canonical_prepare_fixture();
    let prepared_a = prepare_bound_proof_material_v1(
        fixture.subject,
        fixture.challenge,
        &fixture.proof_blob,
        &fixture.public_inputs,
        &fixture.verification_key,
    )
    .unwrap();
    let prepared_b = prepare_bound_proof_material_v1(
        fixture.subject,
        fixture.challenge,
        &fixture.proof_blob,
        &fixture.public_inputs,
        &fixture.verification_key,
    )
    .unwrap();

    assert_eq!(prepared_a, prepared_b);
    assert_eq!(
        prepared_a.proof_material.proof_material_hash(),
        prepared_a.proof_material_hash
    );
    assert_eq!(prepared_a.fractal_key.proof_hash(), prepared_a.proof_hash);
}

#[test]
fn prepare_bound_proof_material_v1_matches_canonical_cross_surface_hashes() {
    let fixture = canonical_prepare_fixture();
    let prepared = prepare_bound_proof_material_v1(
        fixture.subject,
        fixture.challenge,
        &fixture.proof_blob,
        &fixture.public_inputs,
        &fixture.verification_key,
    )
    .unwrap();

    assert_eq!(
        encode_hex_lower(&prepared.proof_material.proof_blob_hash),
        fixture.proof_blob_hash_hex
    );
    assert_eq!(
        encode_hex_lower(&prepared.proof_material.public_inputs_hash),
        fixture.public_inputs_hash_hex
    );
    assert_eq!(
        encode_hex_lower(&prepared.proof_material.verification_key_hash),
        fixture.verification_key_hash_hex
    );
    assert_eq!(
        encode_hex_lower(&prepared.proof_material_hash),
        fixture.proof_material_hash_hex
    );
    assert_eq!(
        encode_hex_lower(&prepared.proof_hash),
        fixture.proof_hash_hex
    );
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
