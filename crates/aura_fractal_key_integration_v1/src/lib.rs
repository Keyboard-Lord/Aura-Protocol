//! Frozen Aura v1 integration between proof-material preparation and FractalKey binding.

use aura_fractal_key_v1::{
    FractalKeyBuilderInputV1, FractalKeyV1, FractalKeyV1Error, FractalKeyVerifierInputV1,
    FRACTAL_COMPONENT_PAYLOAD_LEN_V1,
};
use core::fmt;

pub type ProofHashV1 = [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitProofIntegrationInputV1 {
    pub subject_pubkey_bytes: ProofHashV1,
    pub challenge_account_pubkey_bytes: ProofHashV1,
    pub proof_material_hash: ProofHashV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitProofPreparationV1 {
    pub fractal_key: FractalKeyV1,
    pub proof_hash: ProofHashV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitProofIntegrationErrorV1 {
    VerificationFailed(FractalKeyV1Error),
}

impl fmt::Display for SubmitProofIntegrationErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed(error) => {
                write!(f, "fractal key verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for SubmitProofIntegrationErrorV1 {}

pub fn prepare_submit_proof_v1(
    subject_pubkey_bytes: ProofHashV1,
    challenge_account_pubkey_bytes: ProofHashV1,
    proof_material_hash: ProofHashV1,
) -> Result<SubmitProofPreparationV1, SubmitProofIntegrationErrorV1> {
    let input = SubmitProofIntegrationInputV1 {
        subject_pubkey_bytes,
        challenge_account_pubkey_bytes,
        proof_material_hash,
    };
    let fractal_key = FractalKeyV1::build(FractalKeyBuilderInputV1 {
        subject_binding: input.subject_pubkey_bytes,
        challenge_binding: input.challenge_account_pubkey_bytes,
        proof_material_hash: input.proof_material_hash,
    });
    let proof_hash = fractal_key.proof_hash();

    verify_pre_submit_v1(&fractal_key, &input, proof_hash)?;

    Ok(SubmitProofPreparationV1 {
        fractal_key,
        proof_hash,
    })
}

pub fn derive_submit_proof_hash_v1(
    subject_pubkey_bytes: ProofHashV1,
    challenge_account_pubkey_bytes: ProofHashV1,
    proof_material_hash: ProofHashV1,
) -> Result<ProofHashV1, SubmitProofIntegrationErrorV1> {
    Ok(prepare_submit_proof_v1(
        subject_pubkey_bytes,
        challenge_account_pubkey_bytes,
        proof_material_hash,
    )?
    .proof_hash)
}

pub fn verify_pre_submit_v1(
    fractal_key: &FractalKeyV1,
    input: &SubmitProofIntegrationInputV1,
    expected_proof_hash: ProofHashV1,
) -> Result<(), SubmitProofIntegrationErrorV1> {
    fractal_key
        .verify(&FractalKeyVerifierInputV1 {
            expected_subject_binding: input.subject_pubkey_bytes,
            expected_challenge_binding: input.challenge_account_pubkey_bytes,
            expected_proof_material_hash: input.proof_material_hash,
            expected_proof_hash,
        })
        .map(|_| ())
        .map_err(SubmitProofIntegrationErrorV1::VerificationFailed)
}
