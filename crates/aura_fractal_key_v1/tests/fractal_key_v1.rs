use aura_fractal_key_v1::{
    FractalComponentTypeV1, FractalComponentV1, FractalKeyBuilderInputV1, FractalKeyV1,
    FractalKeyV1Error, FractalKeyVerifierInputV1, FRACTAL_COMPONENT_COUNT_V1,
    FRACTAL_KEY_DOMAIN_SEPARATOR_V1, FRACTAL_KEY_VERSION_V1,
};
use sha2::{Digest, Sha256};

fn sample_builder_input() -> FractalKeyBuilderInputV1 {
    FractalKeyBuilderInputV1 {
        subject_binding: [0x11; 32],
        challenge_binding: [0x22; 32],
        proof_material_hash: [0x33; 32],
    }
}

fn sample_key() -> FractalKeyV1 {
    FractalKeyV1::build(sample_builder_input())
}

fn sample_verifier_input() -> FractalKeyVerifierInputV1 {
    let input = sample_builder_input();
    let key = sample_key();

    FractalKeyVerifierInputV1 {
        expected_subject_binding: input.subject_binding,
        expected_challenge_binding: input.challenge_binding,
        expected_proof_material_hash: input.proof_material_hash,
        expected_proof_hash: key.proof_hash(),
    }
}

fn expected_canonical_bytes() -> Vec<u8> {
    let input = sample_builder_input();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(FRACTAL_KEY_DOMAIN_SEPARATOR_V1);
    bytes.push(FRACTAL_KEY_VERSION_V1);
    bytes.push(FRACTAL_COMPONENT_COUNT_V1);
    bytes.extend_from_slice(
        &FractalComponentTypeV1::SubjectBinding
            .as_u16()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&input.subject_binding);
    bytes.extend_from_slice(
        &FractalComponentTypeV1::ChallengeBinding
            .as_u16()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&input.challenge_binding);
    bytes.extend_from_slice(
        &FractalComponentTypeV1::ProofMaterialHash
            .as_u16()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&input.proof_material_hash);
    bytes
}

#[test]
fn build_success() {
    let input = sample_builder_input();
    let key = FractalKeyV1::build(input);

    assert_eq!(key.fractal_key_version, FRACTAL_KEY_VERSION_V1);
    assert_eq!(key.component_count, FRACTAL_COMPONENT_COUNT_V1);
    assert_eq!(
        key.components[0],
        FractalComponentV1::new(
            FractalComponentTypeV1::SubjectBinding,
            input.subject_binding
        )
    );
    assert_eq!(
        key.components[1],
        FractalComponentV1::new(
            FractalComponentTypeV1::ChallengeBinding,
            input.challenge_binding,
        )
    );
    assert_eq!(
        key.components[2],
        FractalComponentV1::new(
            FractalComponentTypeV1::ProofMaterialHash,
            input.proof_material_hash,
        )
    );
    assert_eq!(key.verify(&sample_verifier_input()), Ok(key.proof_hash()));
}

#[test]
fn canonical_bytes_stability() {
    let key = sample_key();
    let expected = expected_canonical_bytes();

    assert_eq!(key.canonical_bytes(), expected);
    assert_eq!(key.canonical_bytes(), expected_canonical_bytes());
}

#[test]
fn proof_hash_determinism() {
    let key = sample_key();
    let expected_bytes = expected_canonical_bytes();
    let expected_digest = Sha256::digest(expected_bytes);

    assert_eq!(key.proof_hash(), key.proof_hash());
    assert_eq!(key.proof_hash().as_slice(), expected_digest.as_slice());
}

#[test]
fn invalid_version() {
    let mut key = sample_key();
    key.fractal_key_version = 2;

    assert_eq!(
        key.verify(&sample_verifier_input()),
        Err(FractalKeyV1Error::InvalidVersion {
            expected: FRACTAL_KEY_VERSION_V1,
            actual: 2,
        })
    );
}

#[test]
fn invalid_component_count() {
    let mut key = sample_key();
    key.component_count = 2;

    assert_eq!(
        key.verify(&sample_verifier_input()),
        Err(FractalKeyV1Error::InvalidComponentCount {
            expected: FRACTAL_COMPONENT_COUNT_V1,
            actual: 2,
        })
    );
}

#[test]
fn duplicate_component() {
    let input = sample_builder_input();
    let key = FractalKeyV1 {
        fractal_key_version: FRACTAL_KEY_VERSION_V1,
        component_count: FRACTAL_COMPONENT_COUNT_V1,
        components: [
            FractalComponentV1::new(
                FractalComponentTypeV1::SubjectBinding,
                input.subject_binding,
            ),
            FractalComponentV1::new(
                FractalComponentTypeV1::ChallengeBinding,
                input.challenge_binding,
            ),
            FractalComponentV1::new(
                FractalComponentTypeV1::ChallengeBinding,
                input.proof_material_hash,
            ),
        ],
    };

    assert_eq!(
        key.verify(&sample_verifier_input()),
        Err(FractalKeyV1Error::DuplicateComponent {
            component_type: FractalComponentTypeV1::ChallengeBinding.as_u16(),
        })
    );
}

#[test]
fn missing_component() {
    let input = sample_builder_input();
    let key = FractalKeyV1 {
        fractal_key_version: FRACTAL_KEY_VERSION_V1,
        component_count: FRACTAL_COMPONENT_COUNT_V1,
        components: [
            FractalComponentV1::new(
                FractalComponentTypeV1::ChallengeBinding,
                input.challenge_binding,
            ),
            FractalComponentV1::new(
                FractalComponentTypeV1::ProofMaterialHash,
                input.proof_material_hash,
            ),
            FractalComponentV1::new(FractalComponentTypeV1::ProofMaterialHash, [0x44; 32]),
        ],
    };

    assert_eq!(
        key.verify(&sample_verifier_input()),
        Err(FractalKeyV1Error::MissingComponent {
            component_type: FractalComponentTypeV1::SubjectBinding.as_u16(),
        })
    );
}

#[test]
fn unexpected_component_type() {
    let input = sample_builder_input();
    let key = FractalKeyV1 {
        fractal_key_version: FRACTAL_KEY_VERSION_V1,
        component_count: FRACTAL_COMPONENT_COUNT_V1,
        components: [
            FractalComponentV1::new(
                FractalComponentTypeV1::SubjectBinding,
                input.subject_binding,
            ),
            FractalComponentV1::new(
                FractalComponentTypeV1::ChallengeBinding,
                input.challenge_binding,
            ),
            FractalComponentV1 {
                component_type: 0x9999,
                payload32: input.proof_material_hash,
            },
        ],
    };

    assert_eq!(
        key.verify(&sample_verifier_input()),
        Err(FractalKeyV1Error::UnexpectedComponentType {
            component_type: 0x9999,
        })
    );
}

#[test]
fn invalid_component_order() {
    let input = sample_builder_input();
    let key = FractalKeyV1 {
        fractal_key_version: FRACTAL_KEY_VERSION_V1,
        component_count: FRACTAL_COMPONENT_COUNT_V1,
        components: [
            FractalComponentV1::new(
                FractalComponentTypeV1::ChallengeBinding,
                input.challenge_binding,
            ),
            FractalComponentV1::new(
                FractalComponentTypeV1::SubjectBinding,
                input.subject_binding,
            ),
            FractalComponentV1::new(
                FractalComponentTypeV1::ProofMaterialHash,
                input.proof_material_hash,
            ),
        ],
    };

    assert_eq!(
        key.verify(&sample_verifier_input()),
        Err(FractalKeyV1Error::InvalidComponentOrder)
    );
}

#[test]
fn subject_binding_mismatch() {
    let key = sample_key();
    let mut verifier_input = sample_verifier_input();
    verifier_input.expected_subject_binding = [0x91; 32];

    assert_eq!(
        key.verify(&verifier_input),
        Err(FractalKeyV1Error::SubjectBindingMismatch)
    );
}

#[test]
fn challenge_binding_mismatch() {
    let key = sample_key();
    let mut verifier_input = sample_verifier_input();
    verifier_input.expected_challenge_binding = [0x92; 32];

    assert_eq!(
        key.verify(&verifier_input),
        Err(FractalKeyV1Error::ChallengeBindingMismatch)
    );
}

#[test]
fn proof_material_hash_mismatch() {
    let key = sample_key();
    let mut verifier_input = sample_verifier_input();
    verifier_input.expected_proof_material_hash = [0x93; 32];

    assert_eq!(
        key.verify(&verifier_input),
        Err(FractalKeyV1Error::ProofMaterialHashMismatch)
    );
}

#[test]
fn proof_hash_mismatch() {
    let key = sample_key();
    let mut verifier_input = sample_verifier_input();
    verifier_input.expected_proof_hash = [0x94; 32];

    assert_eq!(
        key.verify(&verifier_input),
        Err(FractalKeyV1Error::ProofHashMismatch)
    );
}
