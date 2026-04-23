use aura_proof_material_v1::{
    proof_blob_hash_v1, public_inputs_hash_v1, verification_key_hash_v1, ProofMaterialTypeV1,
    ProofMaterialV1, ProofMaterialV1Error, PROOF_MATERIAL_DOMAIN_SEPARATOR_V1,
    PROOF_MATERIAL_VERSION_V1,
};

fn sample_proof_blob_bytes() -> &'static [u8] {
    b"proof-blob-v1"
}

fn sample_public_inputs_bytes() -> &'static [u8] {
    b"public-inputs-v1"
}

fn sample_verification_key_bytes() -> &'static [u8] {
    b"verification-key-v1"
}

fn sample_proof_material() -> ProofMaterialV1 {
    ProofMaterialV1::build(
        sample_proof_blob_bytes(),
        sample_public_inputs_bytes(),
        sample_verification_key_bytes(),
    )
}

#[test]
fn build_success() {
    let proof_material = sample_proof_material();
    let proof_blob_hash = proof_blob_hash_v1(sample_proof_blob_bytes());
    let public_inputs_hash = public_inputs_hash_v1(sample_public_inputs_bytes());
    let verification_key_hash = verification_key_hash_v1(sample_verification_key_bytes());

    assert_eq!(
        proof_material.proof_material_version,
        PROOF_MATERIAL_VERSION_V1
    );
    assert_eq!(
        proof_material.proof_material_type,
        ProofMaterialTypeV1::CanonicalVerifierBundle.as_u16()
    );
    assert_eq!(proof_material.proof_blob_hash, proof_blob_hash);
    assert_eq!(proof_material.public_inputs_hash, public_inputs_hash);
    assert_eq!(proof_material.verification_key_hash, verification_key_hash);
    assert_eq!(
        proof_material.verify(
            sample_proof_blob_bytes(),
            sample_public_inputs_bytes(),
            sample_verification_key_bytes(),
            proof_material.proof_material_hash(),
        ),
        Ok(proof_material.proof_material_hash())
    );
}

#[test]
fn canonical_bytes_stability() {
    let proof_material = sample_proof_material();
    let mut expected = Vec::new();
    expected.extend_from_slice(PROOF_MATERIAL_DOMAIN_SEPARATOR_V1);
    expected.push(PROOF_MATERIAL_VERSION_V1);
    expected.extend_from_slice(
        &ProofMaterialTypeV1::CanonicalVerifierBundle
            .as_u16()
            .to_le_bytes(),
    );
    expected.extend_from_slice(&proof_blob_hash_v1(sample_proof_blob_bytes()));
    expected.extend_from_slice(&public_inputs_hash_v1(sample_public_inputs_bytes()));
    expected.extend_from_slice(&verification_key_hash_v1(sample_verification_key_bytes()));

    assert_eq!(proof_material.canonical_bytes(), expected);
    assert_eq!(
        proof_material.canonical_bytes(),
        proof_material.canonical_bytes()
    );
}

#[test]
fn proof_blob_hash_determinism() {
    let hash_a = proof_blob_hash_v1(sample_proof_blob_bytes());
    let hash_b = proof_blob_hash_v1(sample_proof_blob_bytes());

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a, sample_proof_material().proof_blob_hash);
}

#[test]
fn public_inputs_hash_determinism() {
    let hash_a = public_inputs_hash_v1(sample_public_inputs_bytes());
    let hash_b = public_inputs_hash_v1(sample_public_inputs_bytes());

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a, sample_proof_material().public_inputs_hash);
}

#[test]
fn verification_key_hash_determinism() {
    let hash_a = verification_key_hash_v1(sample_verification_key_bytes());
    let hash_b = verification_key_hash_v1(sample_verification_key_bytes());

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a, sample_proof_material().verification_key_hash);
}

#[test]
fn final_proof_material_hash_determinism() {
    let proof_material = sample_proof_material();

    assert_eq!(
        proof_material.proof_material_hash(),
        proof_material.proof_material_hash()
    );
    assert_eq!(
        proof_material.proof_material_hash(),
        sample_proof_material().proof_material_hash()
    );
}

#[test]
fn invalid_version() {
    let mut proof_material = sample_proof_material();
    proof_material.proof_material_version = 2;

    assert_eq!(
        proof_material.verify(
            sample_proof_blob_bytes(),
            sample_public_inputs_bytes(),
            sample_verification_key_bytes(),
            proof_material.proof_material_hash(),
        ),
        Err(ProofMaterialV1Error::InvalidVersion {
            expected: PROOF_MATERIAL_VERSION_V1,
            actual: 2,
        })
    );
}

#[test]
fn invalid_proof_material_type() {
    let mut proof_material = sample_proof_material();
    proof_material.proof_material_type = 0x9999;

    assert_eq!(
        proof_material.verify(
            sample_proof_blob_bytes(),
            sample_public_inputs_bytes(),
            sample_verification_key_bytes(),
            proof_material.proof_material_hash(),
        ),
        Err(ProofMaterialV1Error::InvalidProofMaterialType {
            expected: ProofMaterialTypeV1::CanonicalVerifierBundle.as_u16(),
            actual: 0x9999,
        })
    );
}

#[test]
fn proof_blob_hash_mismatch() {
    let proof_material = sample_proof_material();

    assert_eq!(
        proof_material.verify(
            b"proof-blob-v1-mismatch",
            sample_public_inputs_bytes(),
            sample_verification_key_bytes(),
            proof_material.proof_material_hash(),
        ),
        Err(ProofMaterialV1Error::ProofBlobHashMismatch)
    );
}

#[test]
fn public_inputs_hash_mismatch() {
    let proof_material = sample_proof_material();

    assert_eq!(
        proof_material.verify(
            sample_proof_blob_bytes(),
            b"public-inputs-v1-mismatch",
            sample_verification_key_bytes(),
            proof_material.proof_material_hash(),
        ),
        Err(ProofMaterialV1Error::PublicInputsHashMismatch)
    );
}

#[test]
fn verification_key_hash_mismatch() {
    let proof_material = sample_proof_material();

    assert_eq!(
        proof_material.verify(
            sample_proof_blob_bytes(),
            sample_public_inputs_bytes(),
            b"verification-key-v1-mismatch",
            proof_material.proof_material_hash(),
        ),
        Err(ProofMaterialV1Error::VerificationKeyHashMismatch)
    );
}

#[test]
fn proof_material_hash_mismatch() {
    let proof_material = sample_proof_material();

    assert_eq!(
        proof_material.verify(
            sample_proof_blob_bytes(),
            sample_public_inputs_bytes(),
            sample_verification_key_bytes(),
            [0x77; 32],
        ),
        Err(ProofMaterialV1Error::ProofMaterialHashMismatch)
    );
}
