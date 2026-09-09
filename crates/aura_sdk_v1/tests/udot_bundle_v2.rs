use aura_sdk_v1::{generate_udot_bundle_v2, validate_udot_bundle_v2, UdotBundleV2, UdotBundleV2Error};
use serde_json::{json, Value};

fn vectors() -> Vec<UdotBundleV2> {
    serde_json::from_str(include_str!("../../../fixtures/udot_v2/bundles.json")).unwrap()
}

#[test]
fn canonical_bundles_preserve_frozen_glyphs_and_round_trip() {
    let historical: Value = serde_json::from_str(include_str!("../../../fixtures/v1/udot_v1/test_vectors.json")).unwrap();
    let vectors = vectors();
    assert_eq!(vectors.len(), 3);
    for (expected, old) in vectors.iter().zip(historical["v2_vectors"].as_array().unwrap()) {
        let generated = generate_udot_bundle_v2(&expected.proof_hash_hex).unwrap();
        assert_eq!(&generated, expected);
        assert_eq!(generated, generate_udot_bundle_v2(&expected.proof_hash_hex).unwrap());
        let json = serde_json::to_string(&generated).unwrap();
        let decoded: UdotBundleV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(validate_udot_bundle_v2(&decoded, &expected.proof_hash_hex).unwrap(), *expected);
        assert_eq!(old["input_aura_hash_hex"], expected.proof_hash_hex);
        for (kind, actual) in [("seal-line", &expected.seal_line), ("crest", &expected.crest), ("matrix-sequence", &expected.matrix_sequence)] {
            let artifact = old["artifacts"].as_array().unwrap().iter().find(|a| a["artifact_kind"] == kind).unwrap();
            assert_eq!(artifact["value"], *actual);
        }
    }
}

#[test]
fn wire_rejects_missing_extra_legacy_and_wrong_type_fields() {
    let bundle = &vectors()[0];
    let value = serde_json::to_value(bundle).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 4);
    for field in ["proof_hash_hex", "seal_line", "crest", "matrix_sequence"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<UdotBundleV2>(missing).is_err());
        for invalid in [Value::Null, json!(42), json!([])] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert!(serde_json::from_value::<UdotBundleV2>(changed).is_err());
        }
    }
    for field in ["aura_hash_hex", "proofHashHex", "udot_version", "matrix_form", "extra"] {
        let mut extra = value.clone();
        extra[field] = Value::Null;
        assert!(serde_json::from_value::<UdotBundleV2>(extra).is_err());
    }
    let encoded = serde_json::to_string(bundle).unwrap();
    let duplicate = format!("{{\"proof_hash_hex\":\"{}\",{}", bundle.proof_hash_hex, &encoded[1..]);
    assert!(serde_json::from_str::<UdotBundleV2>(&duplicate).is_err());
}

#[test]
fn canonical_hashes_are_required_without_normalization() {
    let bundle = &vectors()[0];
    for hash in ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33), "g".repeat(64), format!("0x{}", "ab".repeat(32)), format!("{}\n", "ab".repeat(32))] {
        assert!(generate_udot_bundle_v2(&hash).is_err());
        assert!(validate_udot_bundle_v2(bundle, &hash).is_err());
        let mut changed = bundle.clone();
        changed.proof_hash_hex = hash;
        assert!(validate_udot_bundle_v2(&changed, &bundle.proof_hash_hex).is_err());
    }
}

#[test]
fn every_glyph_position_and_proof_reference_are_bound() {
    let bundle = &vectors()[0];
    for field in ["seal_line", "crest", "matrix_sequence"] {
        let original = serde_json::to_value(bundle).unwrap();
        let glyphs: Vec<char> = original[field].as_str().unwrap().chars().collect();
        for index in 0..glyphs.len() {
            let mut changed_glyphs = glyphs.clone();
            changed_glyphs[index] = if glyphs[index] == '◦' { '◌' } else { '◦' };
            let mut changed = original.clone();
            changed[field] = json!(changed_glyphs.iter().collect::<String>());
            let changed: UdotBundleV2 = serde_json::from_value(changed).unwrap();
            assert!(matches!(validate_udot_bundle_v2(&changed, &bundle.proof_hash_hex), Err(UdotBundleV2Error::ArtifactMismatch { .. })));
        }
    }
    assert_eq!(validate_udot_bundle_v2(bundle, &"00".repeat(32)), Err(UdotBundleV2Error::ProofHashMismatch));
    let mut changed = bundle.clone();
    changed.proof_hash_hex = "00".repeat(32);
    assert!(validate_udot_bundle_v2(&changed, &changed.proof_hash_hex).is_err());
}
