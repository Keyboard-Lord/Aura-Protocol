use aura_sdk_v0::{
    execute_batch_v0, export_public_input_bytes_v0, prove_stark_v0, verify_stark_v0,
    BatchBuilderV0, GenesisBuilderV0, ZERO32_V0,
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
    let executed = execute_batch_v0(&state, rollup_id, &batch)?;
    let public_inputs = export_public_input_bytes_v0(&executed);
    let mut proof = prove_stark_v0(&executed)?;
    proof.proof_binding_digest[0] ^= 0x01;

    match verify_stark_v0(&public_inputs, &proof) {
        Ok(_) => {
            eprintln!("unexpected acceptance of tampered proof");
            std::process::exit(1);
        }
        Err(error) => {
            println!("tampered_transition_rejected={error}");
        }
    }

    Ok(())
}
// Non-canonical compatibility example. The active authority path is run-canonical-pipeline.
