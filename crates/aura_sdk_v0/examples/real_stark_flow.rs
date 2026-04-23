use aura_sdk_v0::{
    encode_hex_v0, run_flow_v0, BatchBuilderV0, GenesisBuilderV0, ProofSystemV0, ZERO32_V0,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rollup_id = [0xAA; 32];
    let state = GenesisBuilderV0::new()
        .account([0x11; 32], 90, 0)
        .account([0x22; 32], 10, 0)
        .build_state()?;
    let batch = BatchBuilderV0::new(0)
        .with_parent_batch_commitment(ZERO32_V0)
        .transfer([0x11; 32], [0x22; 32], 0, 9)
        .build();

    let completed = run_flow_v0(&state, rollup_id, &batch, ProofSystemV0::Stark)?;
    println!("proof_system=stark");
    println!(
        "transition_binding_hash={}",
        encode_hex_v0(&completed.accepted_transition.transition_binding_hash)
    );
    println!(
        "new_state_root={}",
        encode_hex_v0(&completed.accepted_transition.new_state_root)
    );
    Ok(())
}
// Non-canonical compatibility example. The active authority path is run-canonical-pipeline.
