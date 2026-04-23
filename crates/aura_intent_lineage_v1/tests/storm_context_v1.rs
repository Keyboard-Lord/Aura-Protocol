use aura_intent_lineage_v1::{
    execution_domain_v1, validate_context_bytes_v1, StormContextV1, STORM_CONTEXT_V1_LEN,
    STORM_CONTEXT_V1_VERSION,
};

#[test]
fn storm_context_v1_serializes_with_derived_execution_domain() {
    let context = StormContextV1 {
        context_version: STORM_CONTEXT_V1_VERSION,
        network_id: [0x11; 32],
        intent_hash: [0x22; 32],
        freshness_nonce: [0x33; 32],
        valid_from: 1,
        valid_until: 2,
        controller_id: [0x44; 32],
        route_tag: [0x55; 32],
    };

    let bytes = context.to_bytes();
    assert_eq!(bytes.len(), STORM_CONTEXT_V1_LEN);
    assert_eq!(&bytes[33..65], execution_domain_v1().as_slice());
    assert_eq!(validate_context_bytes_v1(&bytes).unwrap(), bytes);
}
