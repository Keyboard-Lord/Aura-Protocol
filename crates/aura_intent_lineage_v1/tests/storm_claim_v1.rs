use aura_intent_lineage_v1::{
    build_storm_claim_v1, build_storm_public_inputs_v1, StormContextV1, StormExecutionInputsV1,
    STORM_CONTEXT_V1_VERSION,
};

fn sample_inputs() -> StormExecutionInputsV1 {
    StormExecutionInputsV1 {
        side_a: [0x11; 110],
        side_b: [0x22; 110],
        context_bytes_v1: StormContextV1 {
            context_version: STORM_CONTEXT_V1_VERSION,
            network_id: [0x33; 32],
            intent_hash: [0x44; 32],
            freshness_nonce: [0x55; 32],
            valid_from: 12,
            valid_until: 34,
            controller_id: [0x66; 32],
            route_tag: [0x77; 32],
        }
        .to_bytes(),
        iteration_count: 3,
    }
}

#[test]
fn storm_claim_v1_validates_and_emits_public_inputs() {
    let claim = build_storm_claim_v1(&sample_inputs(), [0u8; 32], [0u8; 32]);
    let public_inputs = build_storm_public_inputs_v1(&claim);

    claim.validate().unwrap();
    assert_eq!(public_inputs.trace_root, claim.trace_root);
}
