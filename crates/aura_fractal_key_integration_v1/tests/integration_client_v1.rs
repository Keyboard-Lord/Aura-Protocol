use aura_fractal_key_integration_v1::{
    derive_bound_proof_hash_v1, prepare_bound_proof_reference_v1, verify_bound_proof_reference_v1,
    FractalKeyBindingErrorV1, FractalKeyBindingInputV1,
};
use aura_fractal_key_v1::{
    FractalKeyBuilderInputV1, FractalKeyV1, FractalKeyV1Error, FRACTAL_COMPONENT_PAYLOAD_LEN_V1,
};

type Bytes32 = [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1];

fn sample_input() -> FractalKeyBindingInputV1 {
    FractalKeyBindingInputV1 {
        subject_binding: [0x11; 32],
        freshness_binding: [0x22; 32],
        proof_material_hash: [0x33; 32],
    }
}

fn sample_fractal_key(input: FractalKeyBindingInputV1) -> FractalKeyV1 {
    FractalKeyV1::build(FractalKeyBuilderInputV1 {
        subject_binding: input.subject_binding,
        challenge_binding: input.freshness_binding,
        proof_material_hash: input.proof_material_hash,
    })
}

fn expected_proof_hash(input: FractalKeyBindingInputV1) -> Bytes32 {
    sample_fractal_key(input).proof_hash()
}

#[test]
fn prepare_bound_proof_reference_v1_success() {
    let input = sample_input();
    let preparation = prepare_bound_proof_reference_v1(
        input.subject_binding,
        input.freshness_binding,
        input.proof_material_hash,
    )
    .unwrap();

    assert_eq!(preparation.fractal_key, sample_fractal_key(input));
    assert_eq!(preparation.proof_hash, expected_proof_hash(input));
}

#[test]
fn derive_bound_proof_hash_v1_success() {
    let input = sample_input();
    let proof_hash = derive_bound_proof_hash_v1(
        input.subject_binding,
        input.freshness_binding,
        input.proof_material_hash,
    )
    .unwrap();

    assert_eq!(proof_hash, expected_proof_hash(input));
}

#[test]
fn deterministic_proof_hash_output() {
    let input = sample_input();

    let proof_hash_a = derive_bound_proof_hash_v1(
        input.subject_binding,
        input.freshness_binding,
        input.proof_material_hash,
    )
    .unwrap();
    let proof_hash_b = derive_bound_proof_hash_v1(
        input.subject_binding,
        input.freshness_binding,
        input.proof_material_hash,
    )
    .unwrap();

    assert_eq!(proof_hash_a, proof_hash_b);
    assert_eq!(proof_hash_a, expected_proof_hash(input));
}

#[test]
fn verify_bound_proof_reference_v1_success() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();

    assert_eq!(
        verify_bound_proof_reference_v1(&fractal_key, &input, proof_hash),
        Ok(())
    );
}

#[test]
fn verification_failure_propagates_subject_binding_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();
    let mismatched_input = FractalKeyBindingInputV1 {
        subject_binding: [0x91; 32],
        ..input
    };

    assert_eq!(
        verify_bound_proof_reference_v1(&fractal_key, &mismatched_input, proof_hash),
        Err(FractalKeyBindingErrorV1::VerificationFailed(
            FractalKeyV1Error::SubjectBindingMismatch
        ))
    );
}

#[test]
fn verification_failure_propagates_freshness_binding_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();
    let mismatched_input = FractalKeyBindingInputV1 {
        freshness_binding: [0x92; 32],
        ..input
    };

    assert_eq!(
        verify_bound_proof_reference_v1(&fractal_key, &mismatched_input, proof_hash),
        Err(FractalKeyBindingErrorV1::VerificationFailed(
            FractalKeyV1Error::ChallengeBindingMismatch
        ))
    );
}

#[test]
fn verification_failure_propagates_proof_material_hash_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);
    let proof_hash = fractal_key.proof_hash();
    let mismatched_input = FractalKeyBindingInputV1 {
        proof_material_hash: [0x93; 32],
        ..input
    };

    assert_eq!(
        verify_bound_proof_reference_v1(&fractal_key, &mismatched_input, proof_hash),
        Err(FractalKeyBindingErrorV1::VerificationFailed(
            FractalKeyV1Error::ProofMaterialHashMismatch
        ))
    );
}

#[test]
fn verification_failure_propagates_expected_proof_hash_mismatch() {
    let input = sample_input();
    let fractal_key = sample_fractal_key(input);

    assert_eq!(
        verify_bound_proof_reference_v1(&fractal_key, &input, [0x94; 32]),
        Err(FractalKeyBindingErrorV1::VerificationFailed(
            FractalKeyV1Error::ProofHashMismatch
        ))
    );
}

#[test]
fn explicit_legacy_adapters_preserve_binding_results() {
    use aura_fractal_key_integration_v1::legacy;

    let input = sample_input();
    let bound = prepare_bound_proof_reference_v1(
        input.subject_binding,
        input.freshness_binding,
        input.proof_material_hash,
    )
    .unwrap();
    let legacy_input = legacy::SubmitProofIntegrationInputV1 {
        subject_pubkey_bytes: input.subject_binding,
        challenge_account_pubkey_bytes: input.freshness_binding,
        proof_material_hash: input.proof_material_hash,
    };

    assert_eq!(FractalKeyBindingInputV1::from(legacy_input), input);
    assert_eq!(
        legacy::prepare_submit_proof_v1(
            legacy_input.subject_pubkey_bytes,
            legacy_input.challenge_account_pubkey_bytes,
            legacy_input.proof_material_hash,
        ),
        Ok(bound)
    );
    assert_eq!(
        legacy::derive_submit_proof_hash_v1(
            legacy_input.subject_pubkey_bytes,
            legacy_input.challenge_account_pubkey_bytes,
            legacy_input.proof_material_hash,
        ),
        Ok(bound.proof_hash)
    );
    assert_eq!(
        legacy::verify_pre_submit_v1(&bound.fractal_key, &legacy_input, bound.proof_hash),
        verify_bound_proof_reference_v1(&bound.fractal_key, &input, bound.proof_hash)
    );
    assert_eq!(
        legacy::verify_pre_submit_v1(&bound.fractal_key, &legacy_input, [0x94; 32]),
        verify_bound_proof_reference_v1(&bound.fractal_key, &input, [0x94; 32])
    );
}
