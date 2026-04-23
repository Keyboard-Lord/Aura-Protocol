mod support;

use aura_intent_lineage_v1::{
    AuthorizationEnvelopeFreshnessContextV1, AuthorizationEnvelopeV1Decision,
    AuthorizationEnvelopeV1Error, AuthorizationLineageV1, DcmCommitmentKindV1, FreshnessModeV1,
    IntentTypeV1, SubjectBindingTypeV1,
};

use support::{
    build_lineage, canonical_inline_envelope, hex32, load_fixture, LineageFixtureFile,
    LineageRejectFixtureFile,
};

#[test]
fn canonical_lineage_accepts_under_native_inline_envelope() {
    let fixture: LineageFixtureFile = load_fixture("authorization_lineage_canonical_v1.json");
    assert_eq!(fixture.contract, "AURA_AUTHORIZATION_LINEAGE_SCHEMA_V1");
    assert_eq!(fixture.fixture_name, "authorization_lineage_canonical_v1");

    let lineage = build_lineage(&fixture.lineage);
    let envelope = canonical_inline_envelope(lineage, hex32(&fixture.expected_lineage_hash_hex));

    let decision = envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default());
    assert_eq!(
        decision,
        AuthorizationEnvelopeV1Decision::Accept {
            lineage_hash: hex32(&fixture.expected_lineage_hash_hex),
        }
    );
}

#[test]
fn reserved_flags_lineage_rejects_under_native_inline_envelope() {
    let fixture: LineageRejectFixtureFile =
        load_fixture("authorization_lineage_reject_reserved_flags_v1.json");
    assert_eq!(fixture.contract, "AURA_AUTHORIZATION_LINEAGE_SCHEMA_V1");
    assert_eq!(
        fixture.fixture_name,
        "authorization_lineage_reject_reserved_flags_v1"
    );

    let lineage = build_lineage(&fixture.lineage);
    let envelope = canonical_inline_envelope(lineage, [0u8; 32]);

    let decision = envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default());
    assert_eq!(
        decision,
        AuthorizationEnvelopeV1Decision::Reject(
            AuthorizationEnvelopeV1Error::ReservedFlagsNonZero {
                field: "lineage_flags",
                actual: 16,
            }
        )
    );

    if let AuthorizationEnvelopeV1Decision::Reject(error) = decision {
        assert_eq!(
            error.to_string(),
            "lineage_flags reserved bits non-zero: 0x0010"
        );
        assert_eq!(
            fixture.expected_reject_reason,
            "lineage_flags_reserved_bits_non_zero"
        );
    } else {
        panic!("expected reject");
    }
}

#[test]
fn canonical_lineage_with_wrong_hash_rejects() {
    let fixture: LineageFixtureFile = load_fixture("authorization_lineage_canonical_v1.json");
    let lineage = build_lineage(&fixture.lineage);
    let wrong_hash = [0x99; 32];
    let envelope = canonical_inline_envelope(lineage, wrong_hash);

    let decision = envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default());
    assert_eq!(
        decision,
        AuthorizationEnvelopeV1Decision::Reject(AuthorizationEnvelopeV1Error::HashMismatch {
            expected: wrong_hash,
            actual: hex32(&fixture.expected_lineage_hash_hex),
        })
    );
}

#[test]
fn legacy_compatible_lineage_rejects_as_mode_conflict() {
    let fixture: LineageFixtureFile = load_fixture("authorization_lineage_canonical_v1.json");
    let legacy_lineage = AuthorizationLineageV1 {
        version: 1,
        lineage_flags: 0x000c,
        dcm_commitment_kind: DcmCommitmentKindV1::LegacyV1CompatibilityOnly,
        dcm_commitment_root: [0u8; 32],
        dcm_trace_commitment: [0u8; 32],
        subject_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
        subject_id: hex32(&fixture.lineage.subject_id_hex),
        subject_public_key: [0u8; 32],
        intent_type: IntentTypeV1::LegacyV1ChallengeContext,
        intent_hash: hex32(&fixture.lineage.intent_hash_hex),
        freshness_mode: FreshnessModeV1::LegacyV1ChallengeFreshness,
        freshness_nonce: hex32(&fixture.lineage.freshness_nonce_hex),
        freshness_reference: fixture.lineage.freshness_reference,
        proof_material_v1_hash: [0x77; 32],
        fractal_key_v1_hash: [0x88; 32],
    };
    let lineage_hash = legacy_lineage.lineage_hash().unwrap();
    let envelope = canonical_inline_envelope(legacy_lineage, lineage_hash);

    let decision = envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default());
    assert_eq!(
        decision,
        AuthorizationEnvelopeV1Decision::Reject(AuthorizationEnvelopeV1Error::ModeConflict {
            reason: "legacy_dcm_commitment_kind_not_allowed",
        })
    );
}
