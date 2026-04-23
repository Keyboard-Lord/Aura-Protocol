use aura_intent_lineage_v1::{
    compute_storm_trace_root, FieldElement521V1, StormState521V1,
};

#[test]
fn storm_trace_commitment_v1_is_order_sensitive() {
    let first = [
        StormState521V1 {
            x: FieldElement521V1::from_u64(1),
            y: FieldElement521V1::from_u64(2),
        },
        StormState521V1 {
            x: FieldElement521V1::from_u64(3),
            y: FieldElement521V1::from_u64(4),
        },
    ];
    let second = [first[1], first[0]];

    assert_ne!(compute_storm_trace_root(&first), compute_storm_trace_root(&second));
}
