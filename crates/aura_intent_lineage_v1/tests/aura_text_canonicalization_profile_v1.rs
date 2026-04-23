use std::{fs, path::PathBuf};

use aura_intent_lineage_v1::{
    canonical_message_bytes_v1, canonical_text_payload_bytes_v1,
};
#[allow(deprecated)]
use aura_intent_lineage_v1::legacy::aura_hash_v1::{
    aura_hash_v1, canonical_message_hash_preimage_v1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FROZEN_AURA_TEXT_PROFILE_FIXTURE_SHA256: &str =
    "6d383343079e3f067ac1ea72726225cba21c3c5c697e50a2f764d61985588da4";

#[derive(Deserialize)]
struct TextProfileFixtureV1 {
    profile: String,
    depends_on: String,
    cases: Vec<TextProfileCaseV1>,
    mode_separation_cases: Vec<TextModeSeparationCaseV1>,
    rejection_cases: Vec<TextRejectionCaseV1>,
}

#[derive(Deserialize)]
struct TextProfileCaseV1 {
    label: String,
    input_hex: String,
    normalized_text_utf8_hex: String,
    text_payload_bytes_hex: String,
    aura_hash_v1_canonical_message_bytes_hex: String,
    hash_preimage_hex: String,
    hash_hex: String,
}

#[derive(Deserialize)]
struct TextModeSeparationCaseV1 {
    label: String,
    raw_input_hex: String,
    text_input_hex: String,
    text_payload_bytes_hex: String,
    raw_hash_hex: String,
    text_hash_hex: String,
}

#[derive(Deserialize)]
struct TextRejectionCaseV1 {
    label: String,
    input_hex: String,
    reject_reason: String,
}

#[test]
fn rust_matches_the_shared_aura_text_profile_fixture() {
    let fixture = load_fixture_v1();
    assert_eq!(fixture.profile, "AURA_TEXT_CANONICALIZATION_PROFILE_V1");
    assert_eq!(fixture.depends_on, "AURA_HASH_V1");

    for case in fixture.cases {
        let input = decode_hex(&case.input_hex);
        let expected_payload = decode_hex(&case.text_payload_bytes_hex);
        let expected_normalized = decode_hex(&case.normalized_text_utf8_hex);
        let expected_canonical = decode_hex(&case.aura_hash_v1_canonical_message_bytes_hex);
        let expected_preimage = decode_hex(&case.hash_preimage_hex);
        let expected_hash = decode_fixed_32(&case.hash_hex);

        assert_eq!(
            canonical_text_payload_bytes_v1(&input).unwrap(),
            expected_payload,
            "text payload drifted for {}",
            case.label
        );
        assert_eq!(
            expected_payload, expected_normalized,
            "normalized text bytes must match text payload bytes for {}",
            case.label
        );
        assert_eq!(
            canonical_message_bytes_v1(&expected_payload).unwrap(),
            expected_canonical,
            "hash-layer canonical bytes drifted for {}",
            case.label
        );
        assert_eq!(
            canonical_message_hash_preimage_v1(&expected_payload).unwrap(),
            expected_preimage,
            "hash preimage drifted for {}",
            case.label
        );
        assert_eq!(
            aura_hash_v1(&expected_payload).unwrap(),
            expected_hash,
            "text hash drifted for {}",
            case.label
        );
    }
}

#[test]
fn text_mode_and_raw_mode_remain_distinct_when_bytes_differ() {
    let fixture = load_fixture_v1();
    for case in fixture.mode_separation_cases {
        let raw_input = decode_hex(&case.raw_input_hex);
        let text_input = decode_hex(&case.text_input_hex);
        let expected_payload = decode_hex(&case.text_payload_bytes_hex);
        let expected_raw_hash = decode_fixed_32(&case.raw_hash_hex);
        let expected_text_hash = decode_fixed_32(&case.text_hash_hex);

        assert_eq!(
            canonical_text_payload_bytes_v1(&text_input).unwrap(),
            expected_payload,
            "text payload drifted for {}",
            case.label
        );
        assert_eq!(
            aura_hash_v1(&raw_input).unwrap(),
            expected_raw_hash,
            "raw hash drifted for {}",
            case.label
        );
        assert_eq!(
            aura_hash_v1(&expected_payload).unwrap(),
            expected_text_hash,
            "text hash drifted for {}",
            case.label
        );
        assert_ne!(
            expected_raw_hash, expected_text_hash,
            "raw and text mode must remain distinct for {}",
            case.label
        );
    }
}

#[test]
fn text_profile_rejection_cases_fail_closed() {
    let fixture = load_fixture_v1();
    for case in fixture.rejection_cases {
        let input = decode_hex(&case.input_hex);
        let error = canonical_text_payload_bytes_v1(&input).unwrap_err();
        assert_eq!(
            error.reject_reason(),
            case.reject_reason,
            "unexpected rejection reason for {}",
            case.label
        );
    }
}

#[test]
fn aura_text_profile_fixture_is_frozen() {
    let path = fixture_path_v1();
    let digest = Sha256::digest(fs::read(&path).unwrap());
    assert_eq!(
        encode_hex(&digest),
        FROZEN_AURA_TEXT_PROFILE_FIXTURE_SHA256,
        "aura_text_profile fixture changed; bump the fixture version instead of silently editing it"
    );
}

fn load_fixture_v1() -> TextProfileFixtureV1 {
    let path = fixture_path_v1();
    serde_json::from_str(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn fixture_path_v1() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../fixtures/v1/aura_text_canonicalization_profile_v1/canonical_text_profile_v1.json",
    )
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex must be even-length");
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = decode_hex_nibble(chunk[0]);
            let low = decode_hex_nibble(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

fn decode_fixed_32(hex: &str) -> [u8; 32] {
    let bytes = decode_hex(hex);
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn decode_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid hex nibble: {value}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
