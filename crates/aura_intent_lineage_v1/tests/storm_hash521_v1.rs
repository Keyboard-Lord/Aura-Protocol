use aura_intent_lineage_v1::{aura_hash521_v1, AURA_HASH521_V1_OUTPUT_BYTES};

#[test]
fn storm_hash521_v1_is_deterministic_at_crate_boundary() {
    let first = aura_hash521_v1(b"AURA_INTEGRATION_VECTOR");
    let second = aura_hash521_v1(b"AURA_INTEGRATION_VECTOR");

    assert_eq!(first, second);
    assert_eq!(first.to_bytes().len(), AURA_HASH521_V1_OUTPUT_BYTES);
}
