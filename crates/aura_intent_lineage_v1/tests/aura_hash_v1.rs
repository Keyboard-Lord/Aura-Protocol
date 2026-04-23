use std::{fs, path::PathBuf};

use aura_intent_lineage_v1::{
    canonical_message_bytes_v1, canonical_text_payload_bytes_v1, 
    decode_and_normalize_message_utf8_v1, normalize_text_message_v1,
};
#[allow(deprecated)]
use aura_intent_lineage_v1::legacy::aura_hash_v1::{
    aura_hash_v1, canonical_message_hash_preimage_v1,
    AURA_HASH_V1_DOMAIN_SEPARATOR, AURA_HASH_V1_LENGTH_PREFIX_BYTES,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FROZEN_AURA_HASH_V1_FIXTURE_SHA256: &str =
    "e9ee3cc1e9fa8e0eceb886bdf5826459242e0a2a289dedef445abb15a45575fc";

#[derive(Deserialize)]
struct AuraHashFixtureV1 {
    domain_separator_utf8: String,
    length_prefix_bytes: usize,
    cases: Vec<AuraHashFixtureCaseV1>,
    rejection_cases: Vec<AuraHashFixtureRejectionCaseV1>,
}

#[derive(Deserialize)]
struct AuraHashFixtureCaseV1 {
    label: String,
    input_kind: String,
    input_hex: String,
    normalized_text_utf8_hex: Option<String>,
    equivalent_normalized_input_hex: Option<String>,
    canonical_message_bytes_hex: String,
    hash_preimage_hex: String,
    hash_hex: String,
}

#[derive(Deserialize)]
struct AuraHashFixtureRejectionCaseV1 {
    label: String,
    input_kind: String,
    input_hex: String,
    reject_reason: String,
}

#[test]
fn rust_matches_the_shared_aura_hash_v1_fixture() {
    let fixture = load_fixture_v1();
    assert_eq!(
        fixture.domain_separator_utf8.as_bytes(),
        AURA_HASH_V1_DOMAIN_SEPARATOR
    );
    assert_eq!(fixture.length_prefix_bytes, AURA_HASH_V1_LENGTH_PREFIX_BYTES);

    for case in fixture.cases {
        let input = decode_hex(&case.input_hex);
        let expected_canonical_message_bytes = decode_hex(&case.canonical_message_bytes_hex);
        let expected_hash_preimage = decode_hex(&case.hash_preimage_hex);
        let expected_hash = decode_fixed_32(&case.hash_hex);

        match case.input_kind.as_str() {
            "raw_bytes" => {
                assert_eq!(
                    canonical_message_bytes_v1(&input).unwrap(),
                    expected_canonical_message_bytes,
                    "canonical bytes drifted for {}",
                    case.label
                );
                assert_eq!(
                    canonical_message_hash_preimage_v1(&input).unwrap(),
                    expected_hash_preimage,
                    "hash preimage drifted for {}",
                    case.label
                );
                assert_eq!(
                    aura_hash_v1(&input).unwrap(),
                    expected_hash,
                    "hash drifted for {}",
                    case.label
                );
            }
            "text_utf8" => {
                let payload_bytes = canonical_text_payload_bytes_v1(&input).unwrap();
                assert_eq!(
                    canonical_message_bytes_v1(&payload_bytes).unwrap(),
                    expected_canonical_message_bytes,
                    "canonical text bytes drifted for {}",
                    case.label
                );
                assert_eq!(
                    canonical_message_hash_preimage_v1(&payload_bytes).unwrap(),
                    expected_hash_preimage,
                    "text hash preimage drifted for {}",
                    case.label
                );
                assert_eq!(
                    aura_hash_v1(&payload_bytes).unwrap(),
                    expected_hash,
                    "text hash drifted for {}",
                    case.label
                );

                if let Some(normalized_hex) = &case.normalized_text_utf8_hex {
                    let normalized = decode_and_normalize_message_utf8_v1(&input).unwrap();
                    assert_eq!(
                        normalized.as_bytes(),
                        decode_hex(normalized_hex),
                        "normalized UTF-8 drifted for {}",
                        case.label
                    );
                }

                if let Some(equivalent_hex) = &case.equivalent_normalized_input_hex {
                    let equivalent = decode_hex(equivalent_hex);
                    let equivalent_payload = canonical_text_payload_bytes_v1(&equivalent).unwrap();
                    assert_eq!(
                        aura_hash_v1(&equivalent_payload).unwrap(),
                        expected_hash,
                        "normalized-equivalent text hash drifted for {}",
                        case.label
                    );
                }
            }
            other => panic!("unsupported input kind in fixture: {other}"),
        }
    }
}

#[test]
fn text_helpers_keep_whitespace_significant() {
    assert_eq!(normalize_text_message_v1("hello").unwrap(), "hello");
    assert_eq!(normalize_text_message_v1("hello ").unwrap(), "hello ");
    assert_ne!(
        aura_hash_v1(&canonical_text_payload_bytes_v1(b"hello").unwrap()).unwrap(),
        aura_hash_v1(&canonical_text_payload_bytes_v1(b"hello ").unwrap()).unwrap()
    );
}

#[test]
fn text_rejection_cases_fail_closed() {
    let fixture = load_fixture_v1();
    for case in fixture.rejection_cases {
        assert_eq!(case.input_kind, "text_utf8");
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
fn aura_hash_v1_fixture_is_frozen() {
    let path = fixture_path_v1();
    let digest = Sha256::digest(fs::read(&path).unwrap());
    assert_eq!(
        encode_hex(&digest),
        FROZEN_AURA_HASH_V1_FIXTURE_SHA256,
        "aura_hash_v1 fixture changed; bump the fixture version instead of silently editing it"
    );
}

fn load_fixture_v1() -> AuraHashFixtureV1 {
    let path = fixture_path_v1();
    serde_json::from_str(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn fixture_path_v1() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/aura_hash_v1/canonical_message_hash_v1.json")
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
