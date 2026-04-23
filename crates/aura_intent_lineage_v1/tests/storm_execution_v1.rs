use aura_intent_lineage_v1::{
    build_storm_trace, execute_storm_v1, StormContextV1, StormExecutionInputsV1,
    STORM_CONTEXT_V1_VERSION,
};

fn sample_inputs() -> StormExecutionInputsV1 {
    StormExecutionInputsV1 {
        side_a: [0xa5; 110],
        side_b: [0x5a; 110],
        context_bytes_v1: StormContextV1 {
            context_version: STORM_CONTEXT_V1_VERSION,
            network_id: [0x10; 32],
            intent_hash: [0x20; 32],
            freshness_nonce: [0x30; 32],
            valid_from: 100,
            valid_until: 200,
            controller_id: [0x40; 32],
            route_tag: [0x50; 32],
        }
        .to_bytes(),
        iteration_count: 4,
    }
}

#[test]
fn storm_execution_v1_reproduces_boundary_states() {
    let inputs = sample_inputs();
    let trace = build_storm_trace(&inputs);
    let execution = execute_storm_v1(&inputs);

    assert_eq!(trace.len(), 5);
    assert_eq!(execution.initial_state, trace[0]);
    assert_eq!(execution.final_state, *trace.last().unwrap());
}
