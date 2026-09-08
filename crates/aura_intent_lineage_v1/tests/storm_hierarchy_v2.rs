use aura_intent_lineage_v1::storm_hierarchy_v2::{
    build_storm_hierarchy_v2, compute_hierarchy_root_v2, execute_storm_hierarchy_v2,
};
use aura_intent_lineage_v1::{
    aura_hash521_v1, build_storm_trace, compute_storm_trace_root, FieldElement521V1,
    StormExecutionInputsV1,
};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/experimental/storm_hierarchy_v2/parity_vector_v2.json"
    ))
    .unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
fn inputs(n: u64) -> StormExecutionInputsV1 {
    let v = fixture();
    StormExecutionInputsV1 {
        side_a: decode(v["side_a_hex"].as_str().unwrap()),
        side_b: decode(v["side_b_hex"].as_str().unwrap()),
        context_bytes_v1: decode(v["context_bytes_v1_hex"].as_str().unwrap()),
        iteration_count: n,
    }
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[test]
fn boundaries_zero_transition_and_shared_rows() {
    for n in [0, 1, 63, 64, 65, 128, 129] {
        let input = inputs(n);
        let trace = build_storm_trace(&input);
        let saved = trace.clone();
        let result = build_storm_hierarchy_v2(&input.context_bytes_v1, &trace).unwrap();
        assert_eq!(
            result.epoch_count,
            if n == 0 { 1 } else { (n - 1) / 64 + 1 }
        );
        assert_eq!(result.iteration_count, n);
        for (k, e) in result.epochs.iter().enumerate() {
            assert_eq!(e.epoch_index, k as u64);
            assert_eq!(e.start_step, k as u64 * 64);
            assert_eq!(e.transition_count, (n - e.start_step).min(64));
            let end = (e.start_step + e.transition_count) as usize;
            assert_eq!(e.initial_state, trace[e.start_step as usize]);
            assert_eq!(e.final_state, trace[end]);
            assert_eq!(
                e.epoch_trace_root,
                compute_storm_trace_root(&trace[e.start_step as usize..=end])
            );
        }
        for pair in result.epochs.windows(2) {
            assert_eq!(
                pair[0].final_state.encode_row_bytes(),
                pair[1].initial_state.encode_row_bytes()
            );
            assert_eq!(pair[0].macro_state_after, pair[1].macro_state_before);
        }
        assert_eq!(trace, saved);
        if n == 0 {
            assert_eq!(result.epochs[0].initial_state, result.epochs[0].final_state);
            assert_ne!(result.initial_macro_state, result.final_macro_state);
        }
    }
}

#[test]
fn deterministic_execution_matches_frozen_experimental_vector() {
    let input = inputs(129);
    let a = execute_storm_hierarchy_v2(&input).unwrap();
    assert_eq!(a, execute_storm_hierarchy_v2(&input).unwrap());
    let v = fixture();
    assert_eq!(a.epoch_count, v["epoch_count"].as_u64().unwrap());
    assert_eq!(
        hex(&a.initial_macro_state.to_bytes()),
        v["initial_macro_state_hex"]
    );
    assert_eq!(
        hex(&a.final_macro_state.to_bytes()),
        v["final_macro_state_hex"]
    );
    assert_eq!(hex(&a.hierarchy_root), v["hierarchy_root_hex"]);
    assert_eq!(
        hex(&compute_storm_trace_root(&build_storm_trace(&input))),
        v["v1_trace_root_hex"]
    );
    for (e, expected) in a.epochs.iter().zip(v["epochs"].as_array().unwrap()) {
        assert_eq!(e.start_step, expected["start_step"].as_u64().unwrap());
        assert_eq!(
            e.transition_count,
            expected["transition_count"].as_u64().unwrap()
        );
        assert_eq!(
            hex(&e.initial_state.x.to_bytes()),
            expected["initial_state"]["xHex66Be"]
        );
        assert_eq!(
            hex(&e.initial_state.y.to_bytes()),
            expected["initial_state"]["yHex66Be"]
        );
        assert_eq!(
            hex(&e.final_state.x.to_bytes()),
            expected["final_state"]["xHex66Be"]
        );
        assert_eq!(
            hex(&e.final_state.y.to_bytes()),
            expected["final_state"]["yHex66Be"]
        );
        assert_eq!(hex(&e.epoch_trace_root), expected["epoch_trace_root_hex"]);
        assert_eq!(hex(&e.epoch_commitment), expected["epoch_commitment_hex"]);
        assert_eq!(
            hex(&e.macro_state_before.to_bytes()),
            expected["macro_state_before_hex"]
        );
        assert_eq!(
            hex(&e.macro_state_after.to_bytes()),
            expected["macro_state_after_hex"]
        );
    }
}

#[test]
fn commitments_pin_encoding_order_and_duplicate_last_hierarchy_nodes() {
    let a = execute_storm_hierarchy_v2(&inputs(129)).unwrap();
    let e = &a.epochs[1];
    assert_eq!(
        e.epoch_commitment,
        hash(
            b"AURA_STORM_EPOCH_COMMITMENT_V2",
            &[
                &1u64.to_le_bytes(),
                &64u64.to_le_bytes(),
                &64u64.to_le_bytes(),
                &e.initial_state.encode_row_bytes(),
                &e.final_state.encode_row_bytes(),
                &e.epoch_trace_root
            ]
        )
    );
    let commitments: Vec<_> = a.epochs.iter().map(|e| e.epoch_commitment).collect();
    let leaves: Vec<_> = commitments
        .iter()
        .map(|c| hash(b"AURA_STORM_HIERARCHY_LEAF_V2", &[c]))
        .collect();
    let left = hash(b"AURA_STORM_HIERARCHY_PARENT_V2", &[&leaves[0], &leaves[1]]);
    let right = hash(b"AURA_STORM_HIERARCHY_PARENT_V2", &[&leaves[2], &leaves[2]]);
    assert_eq!(
        a.hierarchy_root,
        hash(b"AURA_STORM_HIERARCHY_PARENT_V2", &[&left, &right])
    );
    let mut reversed = commitments.clone();
    reversed.reverse();
    assert_ne!(
        a.hierarchy_root,
        compute_hierarchy_root_v2(&reversed).unwrap()
    );
    assert_eq!(
        compute_hierarchy_root_v2(&commitments[..1]).unwrap(),
        leaves[0]
    );
    assert!(compute_hierarchy_root_v2(&[]).is_err());
}

#[test]
fn every_row_and_coordinate_is_committed_in_each_containing_epoch() {
    let input = inputs(65);
    let trace = build_storm_trace(&input);
    let base = build_storm_hierarchy_v2(&input.context_bytes_v1, &trace).unwrap();
    for i in 0..trace.len() {
        for coordinate in 0..2 {
            let mut changed = trace.clone();
            let field = if coordinate == 0 {
                &mut changed[i].x
            } else {
                &mut changed[i].y
            };
            *field = field.add_mod(&FieldElement521V1::from_u64(1));
            let result = build_storm_hierarchy_v2(&input.context_bytes_v1, &changed).unwrap();
            for (old, new) in base.epochs.iter().zip(&result.epochs) {
                if (old.start_step..=old.start_step + old.transition_count).contains(&(i as u64)) {
                    assert_ne!(old.epoch_commitment, new.epoch_commitment);
                } else {
                    assert_eq!(old.epoch_commitment, new.epoch_commitment);
                }
            }
        }
    }
}

#[test]
fn macro_uses_canonical_field_arithmetic_and_endpoint_changes_propagate() {
    let input = inputs(129);
    let trace = build_storm_trace(&input);
    let base = build_storm_hierarchy_v2(&input.context_bytes_v1, &trace).unwrap();
    let alpha = aura_hash521_v1(b"AURA_STORM_MACRO_ALPHA_V2");
    let beta = aura_hash521_v1(b"AURA_STORM_MACRO_BETA_V2");
    for e in &base.epochs {
        let mut msg = b"AURA_STORM_MACRO_RHO_V2".to_vec();
        msg.extend_from_slice(&input.context_bytes_v1);
        msg.extend_from_slice(&e.epoch_index.to_le_bytes());
        let expected = e
            .macro_state_before
            .square_mod()
            .add_mod(&alpha.mul_mod(&e.final_state.x))
            .add_mod(&beta.mul_mod(&e.final_state.y))
            .add_mod(&aura_hash521_v1(&msg));
        assert_eq!(e.macro_state_after, expected);
        let mut changed = trace.clone();
        let i = (e.start_step + e.transition_count) as usize;
        changed[i].x = changed[i].x.add_mod(&FieldElement521V1::from_u64(1));
        assert_ne!(
            base.final_macro_state,
            build_storm_hierarchy_v2(&input.context_bytes_v1, &changed)
                .unwrap()
                .final_macro_state
        );
    }
    let mut interior = trace.clone();
    interior[1].x = interior[1].x.add_mod(&FieldElement521V1::from_u64(1));
    let changed = build_storm_hierarchy_v2(&input.context_bytes_v1, &interior).unwrap();
    assert_ne!(
        base.epochs[0].epoch_commitment,
        changed.epochs[0].epoch_commitment
    );
    assert_eq!(base.final_macro_state, changed.final_macro_state); // prescribed endpoint-only recurrence
    assert!(build_storm_hierarchy_v2(&input.context_bytes_v1, &[]).is_err());
}
