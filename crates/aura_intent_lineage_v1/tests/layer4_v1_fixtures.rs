mod support;

use aura_intent_lineage_v1::{AuraLayer4IntentHashV1Error, AuthorizationLineageV1Error};

use support::{
    build_intent, build_lineage, encode_hex, load_fixture, IntentFixtureFile,
    IntentRejectFixtureFile, LineageFixtureFile, LineageRejectFixtureFile,
};

#[test]
fn canonical_intent_success_matches_fixture_byte_for_byte() {
    let fixture: IntentFixtureFile = load_fixture("intent_canonical_v1.json");
    assert_eq!(fixture.contract, "AURA_LAYER4_INTENT_HASH_V1");
    assert_eq!(fixture.fixture_name, "intent_canonical_v1");
    assert_eq!(fixture.domain_separator_ascii, "AURA_LAYER4_INTENT_HASH_V1");

    let intent = build_intent(&fixture.intent);
    let body = intent.canonical_serialized_body().unwrap();
    let preimage = intent.canonical_hash_preimage().unwrap();
    let hash = intent.intent_hash().unwrap();

    assert_eq!(encode_hex(&body), fixture.expected_serialized_body_hex);
    assert_eq!(encode_hex(&preimage), fixture.expected_hash_preimage_hex);
    assert_eq!(encode_hex(&hash), fixture.expected_intent_hash_hex);
}

#[test]
fn canonical_lineage_success_matches_fixture_byte_for_byte() {
    let fixture: LineageFixtureFile = load_fixture("authorization_lineage_canonical_v1.json");
    assert_eq!(fixture.contract, "AURA_AUTHORIZATION_LINEAGE_SCHEMA_V1");
    assert_eq!(fixture.fixture_name, "authorization_lineage_canonical_v1");
    assert_eq!(
        fixture.domain_separator_ascii.as_deref().unwrap(),
        "AURA_AUTHORIZATION_LINEAGE_V1"
    );

    let lineage = build_lineage(&fixture.lineage);
    let preimage = lineage.canonical_preimage().unwrap();
    let serialized_object = lineage.serialized_object().unwrap();
    let lineage_hash = lineage.lineage_hash().unwrap();

    assert_eq!(
        encode_hex(&preimage),
        fixture.expected_lineage_preimage_hex.as_deref().unwrap()
    );
    assert_eq!(
        encode_hex(&serialized_object),
        fixture.expected_serialized_object_hex.as_deref().unwrap()
    );
    assert_eq!(encode_hex(&lineage_hash), fixture.expected_lineage_hash_hex);
}

#[test]
fn malformed_intent_rejects_for_exact_reserved_flags_class() {
    let fixture: IntentRejectFixtureFile = load_fixture("intent_reject_reserved_flags_v1.json");
    assert_eq!(fixture.contract, "AURA_LAYER4_INTENT_HASH_V1");
    assert_eq!(fixture.fixture_name, "intent_reject_reserved_flags_v1");

    let error = build_intent(&fixture.intent).intent_hash().unwrap_err();
    assert_eq!(error.reject_reason(), fixture.expected_reject_reason);
    assert_eq!(
        error,
        AuraLayer4IntentHashV1Error::IntentFlagsReservedBitsNonZero { actual: 2 }
    );
}

#[test]
fn malformed_lineage_rejects_for_exact_reserved_flags_class() {
    let fixture: LineageRejectFixtureFile =
        load_fixture("authorization_lineage_reject_reserved_flags_v1.json");
    assert_eq!(fixture.contract, "AURA_AUTHORIZATION_LINEAGE_SCHEMA_V1");
    assert_eq!(
        fixture.fixture_name,
        "authorization_lineage_reject_reserved_flags_v1"
    );

    let error = build_lineage(&fixture.lineage).lineage_hash().unwrap_err();
    assert_eq!(error.reject_reason(), fixture.expected_reject_reason);
    assert_eq!(
        error,
        AuthorizationLineageV1Error::LineageFlagsReservedBitsNonZero { actual: 16 }
    );
}
