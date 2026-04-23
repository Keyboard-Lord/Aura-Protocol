// RESEARCH / SUPPORTING TESTS ONLY
//
// These tests validate deterministic behavior of the EMA -> (x0, y0) bridge.
// They do NOT validate or modify the active proving pipeline.

use std::array;

use aura_intent_lineage_research_v1::{
    bridge_research_ema_network_state_to_seed_v1, compile_research_ema_seed_bridge_v1,
    derive_research_ema_lineage_hash_v1, research_dodecahedral_neighbors_v1,
    run_research_ema_network_v1, ResearchEmaAlphaV1, ResearchEmaRoundInputsV1,
    RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1, RESEARCH_EMA_NETWORK_SERIALIZATION_VERSION_V1,
    RESEARCH_EMA_NETWORK_STATE_CANONICAL_BYTE_LEN_V1,
    RESEARCH_EMA_NETWORK_STATE_HEADER_BYTE_LEN_V1, RESEARCH_EMA_NODE_CANONICAL_BYTE_LEN_V1,
};
use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1,
    package_dcm_air_proof_session_v1, validate_dcm_air_v1, DcmAirTraceV1, DcmConfig521V1,
    DcmExecution521V1, HASH_LEN_V1,
};

#[test]
fn same_rounds_and_alpha_produce_the_same_seed() {
    let alpha = sample_alpha();
    let rounds = sample_rounds();

    let first = compile_research_ema_seed_bridge_v1(alpha, &rounds);
    let second = compile_research_ema_seed_bridge_v1(alpha, &rounds);

    assert_eq!(first.dcm_input, second.dcm_input);
    assert_eq!(first.x_hash, second.x_hash);
    assert_eq!(first.y_hash, second.y_hash);
    assert_eq!(
        first.canonical_network_state,
        second.canonical_network_state
    );
}

#[test]
fn mutating_a_single_shard_changes_the_seed() {
    let alpha = sample_alpha();
    let baseline = compile_research_ema_seed_bridge_v1(alpha, &sample_rounds());

    let mut mutated_rounds = sample_rounds();
    mutated_rounds[1].shards[7].push(0xaa);
    let mutated = compile_research_ema_seed_bridge_v1(alpha, &mutated_rounds);

    assert_ne!(baseline.dcm_input, mutated.dcm_input);
    assert_ne!(baseline.x_hash, mutated.x_hash);
    assert_ne!(
        baseline.canonical_network_state,
        mutated.canonical_network_state
    );
}

#[test]
fn canonical_serialization_is_stable_and_index_ordered() {
    let state = run_research_ema_network_v1(sample_alpha(), &sample_rounds());
    let bytes = state.canonical_bytes();

    assert_eq!(
        bytes.len(),
        RESEARCH_EMA_NETWORK_STATE_CANONICAL_BYTE_LEN_V1
    );
    assert_eq!(bytes[0], RESEARCH_EMA_NETWORK_SERIALIZATION_VERSION_V1);
    assert_eq!(bytes[1], RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1 as u8);
    assert_eq!(&bytes[3..11], &state.completed_rounds.to_le_bytes());
    assert_eq!(&bytes[11..19], &state.alpha.numerator.to_le_bytes());
    assert_eq!(&bytes[19..27], &state.alpha.denominator.to_le_bytes());

    for node_index in 0..RESEARCH_DODECAHEDRAL_EMA_NODE_COUNT_V1 {
        let offset = RESEARCH_EMA_NETWORK_STATE_HEADER_BYTE_LEN_V1
            + node_index * RESEARCH_EMA_NODE_CANONICAL_BYTE_LEN_V1;
        assert_eq!(bytes[offset], node_index as u8);
    }

    assert_eq!(bytes, state.canonical_bytes());
}

#[test]
fn canonical_neighbor_order_is_frozen_and_order_sensitive() {
    let alpha = sample_alpha();
    let empty_rounds: Vec<ResearchEmaRoundInputsV1> = Vec::new();
    let genesis_state = run_research_ema_network_v1(alpha, &empty_rounds);
    let neighbors = research_dodecahedral_neighbors_v1(0).unwrap();

    assert_eq!(neighbors, [1, 9, 10]);
    assert_eq!(research_dodecahedral_neighbors_v1(10).unwrap(), [0, 12, 18]);
    assert_eq!(research_dodecahedral_neighbors_v1(19).unwrap(), [9, 11, 17]);

    let canonical_hashes =
        neighbors.map(|neighbor_index| genesis_state.nodes[neighbor_index].lineage_hash);
    let reordered_hashes = [
        canonical_hashes[1],
        canonical_hashes[0],
        canonical_hashes[2],
    ];

    assert_ne!(
        derive_research_ema_lineage_hash_v1(b"node-zero", &canonical_hashes),
        derive_research_ema_lineage_hash_v1(b"node-zero", &reordered_hashes)
    );
}

#[test]
fn tampering_with_a_hashed_lineage_changes_the_bridge_output() {
    let state = run_research_ema_network_v1(sample_alpha(), &sample_rounds());
    let baseline = bridge_research_ema_network_state_to_seed_v1(&state);

    let mut tampered_state = state.clone();
    tampered_state.nodes[3].lineage_hash[0] ^= 0x01;
    let tampered = bridge_research_ema_network_state_to_seed_v1(&tampered_state);

    assert_ne!(baseline.dcm_input, tampered.dcm_input);
    assert_ne!(baseline.y_hash, tampered.y_hash);
    assert_ne!(
        baseline.canonical_network_state,
        tampered.canonical_network_state
    );
}

#[test]
fn bridge_output_is_compatible_with_the_existing_cat_map_air_path() {
    let bridge = compile_research_ema_seed_bridge_v1(sample_alpha(), &sample_rounds());
    let config = DcmConfig521V1 { iteration_count: 8 };
    let execution = DcmExecution521V1::run(&config, &bridge.dcm_input).unwrap();
    let trace = DcmAirTraceV1::new(execution.states.clone());
    let claim = build_dcm_claim_521_v1(&config, &bridge.dcm_input, &execution);
    let public_inputs = dcm_air_public_inputs_from_claim_521_v1(&claim);
    let evaluation = validate_dcm_air_v1(&public_inputs, &trace).unwrap();
    let proof_session = package_dcm_air_proof_session_v1(&public_inputs, &trace).unwrap();

    assert_eq!(evaluation.row_count, trace.row_count());
    assert_eq!(
        proof_session.session_metadata().row_count(),
        trace.row_count()
    );
    assert_eq!(
        proof_session.verifier_input().public_inputs(),
        &public_inputs
    );
}

fn sample_alpha() -> ResearchEmaAlphaV1 {
    ResearchEmaAlphaV1::new(3, 5).unwrap()
}

fn sample_rounds() -> Vec<ResearchEmaRoundInputsV1> {
    vec![
        make_round_inputs(b"round-000"),
        make_round_inputs(b"round-001"),
        make_round_inputs(b"round-002"),
    ]
}

fn make_round_inputs(round_tag: &[u8]) -> ResearchEmaRoundInputsV1 {
    ResearchEmaRoundInputsV1 {
        shards: array::from_fn(|node_index| {
            let mut shard = Vec::with_capacity(round_tag.len() + 1 + 1 + 8 + HASH_LEN_V1);
            shard.extend_from_slice(round_tag);
            shard.push(0xff);
            shard.push(node_index as u8);
            shard.extend_from_slice(&(node_index as u64).to_le_bytes());

            let mut trailer = [0u8; HASH_LEN_V1];
            trailer[0] = round_tag[round_tag.len() - 1];
            trailer[1] = node_index as u8;
            trailer[HASH_LEN_V1 - 1] = round_tag[0];
            shard.extend_from_slice(&trailer);
            shard
        }),
    }
}
