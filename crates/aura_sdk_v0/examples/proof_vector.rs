use std::path::PathBuf;

use aura_sdk_v0::{run_proof_vector_v0, verify_proof_vector_v0, ScenarioResultV0};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let vector = repo_root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");

    let run_report = run_proof_vector_v0(&vector)?;
    let verify_report = verify_proof_vector_v0(&vector)?;

    assert_eq!(run_report.actual_result, ScenarioResultV0::Accepted);
    assert_eq!(verify_report.actual_result, ScenarioResultV0::Accepted);

    println!("fixture_name: {}", run_report.fixture_name);
    println!("proof_system: {:?}", run_report.proof_system);
    println!("actual_result: {:?}", run_report.actual_result);
    Ok(())
}
// Non-canonical reproducibility example. The active authority path is run-canonical-pipeline.
