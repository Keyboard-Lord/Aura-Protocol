use aura_reference_demo_v1::{render_reference_demo_report_v1, run_reference_demo_v1};
use std::process::Command;

#[test]
fn demo_flow_uses_expected_account_order_and_payer() {
    let artifacts = run_reference_demo_v1().unwrap();
    let instruction = &artifacts.prepared_instruction.instruction;
    let transaction = &artifacts.prepared_transaction.transaction;

    assert_eq!(
        artifacts.prepared_instruction.proof_record_address,
        artifacts.prepared_transaction.proof_record_address
    );
    assert_eq!(instruction.program_id, artifacts.program_id);
    assert_eq!(instruction.accounts.len(), 5);
    assert_eq!(instruction.accounts[0].pubkey, artifacts.submitter_pubkey);
    assert!(instruction.accounts[0].is_signer);
    assert!(instruction.accounts[0].is_writable);
    assert_eq!(instruction.accounts[1].pubkey, artifacts.challenge_pubkey);
    assert!(instruction.accounts[1].is_writable);
    assert_eq!(
        instruction.accounts[2].pubkey,
        artifacts.prepared_instruction.proof_record_address
    );
    assert!(instruction.accounts[2].is_writable);
    assert_eq!(
        transaction.message.account_keys[0],
        artifacts.submitter_pubkey
    );
}

#[test]
fn demo_report_is_deterministic_for_fixed_sample() {
    let artifacts = run_reference_demo_v1().unwrap();
    let expected = "\
Aura v1 Reference Demo
sample: built-in-v1

off_chain_preparation
proof_blob_hash: 25af3f8f6b844446831b9487a84191310719de8451ab7119a25e1f07327f43ff
public_inputs_hash: 4df23ee93f45c414fbe40bade6146fd064c55edf2f7d6141963f66b0ac3af013
verification_key_hash: 24140c4c00c0dd501311c20bc00f76feca11f9b23f5fca4756e3b2ed49e862fe
proof_material_type: 0x0001
proof_material_hash: 06282bdcdc841789bf045d139d760358de72a9001d58c3d2899fc60236ddeacc
fractal_key_version: 1
fractal_component_count: 3
fractal_component_1_subject_binding: d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737
fractal_component_2_challenge_binding: 2222222222222222222222222222222222222222222222222222222222222222
fractal_component_3_proof_material_hash: 06282bdcdc841789bf045d139d760358de72a9001d58c3d2899fc60236ddeacc
proof_hash: 10166f084ab6f26a37cbcc36d90461bb63073e2f971b67a8f6bbaf1d229aecfc

transaction_assembly
program_id: 4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4
submitter_pubkey: F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4
challenge_pubkey: 3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3
proof_record_pda: 3h4Q789Cf1PwghYTQu2Q218TkRX1iEpViTFPS8eaNHbQ
recent_blockhash: 5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5
instruction_data: 0210166f084ab6f26a37cbcc36d90461bb63073e2f971b67a8f6bbaf1d229aecfc
account_1: F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4 signer writable
account_2: 3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3 writable
account_3: 3h4Q789Cf1PwghYTQu2Q218TkRX1iEpViTFPS8eaNHbQ writable
account_4: 11111111111111111111111111111111 readonly
account_5: SysvarC1ock11111111111111111111111111111111 readonly
transaction_payer: F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4
transaction_signature: 2rA1bnhqNnWfRVx7KzMjJaoHdpYCGhKQMNtBsRCpfsskFwL6GMQGbdS8VjP2vWQQADx4RmxFapVAVMmSFmNcAiod
";

    assert_eq!(render_reference_demo_report_v1(&artifacts), expected);
}

#[test]
fn demo_binary_output_matches_library_report() {
    let artifacts = run_reference_demo_v1().unwrap();
    let expected = render_reference_demo_report_v1(&artifacts);

    let output = Command::new(env!("CARGO_BIN_EXE_aura_reference_demo_v1"))
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}
