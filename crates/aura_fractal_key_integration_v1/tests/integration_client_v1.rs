use aura_fractal_key_integration_v1::{
    derive_submit_proof_hash_v1, prepare_submit_proof_v1, verify_pre_submit_v1,
    SubmitProofIntegrationErrorV1, SubmitProofIntegrationInputV1,
};
use aura_fractal_key_v1::{
    FractalKeyBuilderInputV1, FractalKeyV1, FractalKeyV1Error, FRACTAL_COMPONENT_PAYLOAD_LEN_V1,
};

type Bytes32 = [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1];

fn sample_input() -> SubmitProofIntegrationInputV1 {
    SubmitProofIntegrationInputV1 {
        subject_pubkey_bytes: [0x11; 32],
        challenge_account_pubkey_bytes: [0x22; 32],
        proof_material_hash: [0x33; 32],
    }
}

fn sample_fractal_key(input: SubmitProofIntegrationInputV1) -> FractalKeyV1 {
    FractalKeyV1::build(FractalKeyBuilderInputV1 {
        subject_binding: input.subject_pubkey_bytes,
        challenge_binding: input.challenge_account_pubkey_bytes,
        proof_material_hash: input.proof_material_hash,
    })
}

fn expected_proof_hash(input: SubmitProofIntegrationInputV1) -> Bytes32 {
    sample_fractal_key(input).proof_hash()
}

#[test]
fn prepare_submit_proof_v1_success() {
    let input = sample_input();
    let preparation = prepare_submit_proof_v1(
        input.subject_pubkey_bytes,
        input.challenge_account_pubkey_bytes,
        input.proof_material_hash,
    )
    .unwrap();

    assert_eq!(preparation.fractal_key, sample_fractal_key(input));
    assert_eq!(preparation.proof_hash, expected_proof_hash(input));
}

#[test]
fn derive_submit_proof_hash_v1_success() {
    let input = sample_input();
    let proof_hash = derive_submit_proof_hash_v1(
        input.subject_pubkey_bytes,
        input.challenge_account_pubkey_bytes,
        input.proof_material_hash,
    )
    .unwrap();

    assert_eq!(proof_hash, expected_proof_hash(input));
}

#[test]
fn deterministic_proof_hash_output() {
    let input = sample_input();

    let proof_hash_a = derive_submit_proof_hash_v1(
        input.subject_pubkey_bytes,
        input.challenge_account_pubkey_bytes,
        input.proof_material_hash,
    )
    .unwrap();
    let proof_hash_b = derive_submit_proof_hash_v1(
        input.subject_pubkey_bytes,
        input.challenge_account_pubkey_bytes,
        input.proof_material_hash,
    )
    .unwrap();

    assert_eq!(proof_hash_a, proof_hash_b);
    assert_eq!(proof_hash_a, expected_proof_hash(input));
}

#[test]
fn verify_pre_submit_v1_success() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();

    assert_eq!(
        verify_pre_submit_v1(&fractal_key, &input, proof_hash),
        Ok(())
    );
}

#[test]
fn verification_failure_propagates_subject_binding_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();
    let mismatched_input = SubmitProofIntegrationInputV1 {
        subject_pubkey_bytes: [0x91; 32],
        ..input
    };

    assert_eq!(
        verify_pre_submit_v1(&fractal_key, &mismatched_input, proof_hash),
        Err(SubmitProofIntegrationErrorV1::VerificationFailed(
            FractalKeyV1Error::SubjectBindingMismatch
        ))
    );
}

#[test]
fn verification_failure_propagates_challenge_binding_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();
    let mismatched_input = SubmitProofIntegrationInputV1 {
        challenge_account_pubkey_bytes: [0x92; 32],
        ..input
    };

    assert_eq!(
        verify_pre_submit_v1(&fractal_key, &mismatched_input, proof_hash),
        Err(SubmitProofIntegrationErrorV1::VerificationFailed(
            FractalKeyV1Error::ChallengeBindingMismatch
        ))
    );
}

#[test]
fn verification_failure_propagates_proof_material_hash_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();
    let mismatched_input = SubmitProofIntegrationInputV1 {
        proof_material_hash: [0x93; 32],
        ..input
    };

    assert_eq!(
        verify_pre_submit_v1(&fractal_key, &mismatched_input, proof_hash),
        Err(SubmitProofIntegrationErrorV1::VerificationFailed(
            FractalKeyV1Error::ProofMaterialHashMismatch
        ))
    );
}

#[test]
fn verification_failure_propagates_expected_proof_hash_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);

    assert_eq!(
        verify_pre_submit_v1(&fractal_key, &input, [0x94; 32]),
        Err(SubmitProofIntegrationErrorV1::VerificationFailed(
            FractalKeyV1Error::ProofHashMismatch
        ))
    );
}
