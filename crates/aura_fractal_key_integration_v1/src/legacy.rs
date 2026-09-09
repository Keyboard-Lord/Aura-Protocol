//! Explicit adapters for the retired Solana account-oriented integration API.
//!
//! These adapters preserve historical binding bytes. They do not authenticate
//! or convert legacy objects into canonical Bitcoin authorization objects.

use crate::{
    derive_bound_proof_hash_v1, prepare_bound_proof_reference_v1, verify_bound_proof_reference_v1,
    BoundProofReferenceV1, FractalKeyBindingErrorV1, FractalKeyBindingInputV1, ProofHashV1,
};
use aura_fractal_key_v1::FractalKeyV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitProofIntegrationInputV1 {
    pub subject_pubkey_bytes: ProofHashV1,
    pub challenge_account_pubkey_bytes: ProofHashV1,
    pub proof_material_hash: ProofHashV1,
}

impl From<SubmitProofIntegrationInputV1> for FractalKeyBindingInputV1 {
    fn from(input: SubmitProofIntegrationInputV1) -> Self {
        Self {
            subject_binding: input.subject_pubkey_bytes,
            freshness_binding: input.challenge_account_pubkey_bytes,
            proof_material_hash: input.proof_material_hash,
        }
    }
}

pub type SubmitProofPreparationV1 = BoundProofReferenceV1;
pub type SubmitProofIntegrationErrorV1 = FractalKeyBindingErrorV1;

pub fn prepare_submit_proof_v1(
    subject_pubkey_bytes: ProofHashV1,
    challenge_account_pubkey_bytes: ProofHashV1,
    proof_material_hash: ProofHashV1,
) -> Result<SubmitProofPreparationV1, SubmitProofIntegrationErrorV1> {
    prepare_bound_proof_reference_v1(
        subject_pubkey_bytes,
        challenge_account_pubkey_bytes,
        proof_material_hash,
    )
}

pub fn derive_submit_proof_hash_v1(
    subject_pubkey_bytes: ProofHashV1,
    challenge_account_pubkey_bytes: ProofHashV1,
    proof_material_hash: ProofHashV1,
) -> Result<ProofHashV1, SubmitProofIntegrationErrorV1> {
    derive_bound_proof_hash_v1(
        subject_pubkey_bytes,
        challenge_account_pubkey_bytes,
        proof_material_hash,
    )
}

pub fn verify_pre_submit_v1(
    fractal_key: &FractalKeyV1,
    input: &SubmitProofIntegrationInputV1,
    expected_proof_hash: ProofHashV1,
) -> Result<(), SubmitProofIntegrationErrorV1> {
    verify_bound_proof_reference_v1(fractal_key, &(*input).into(), expected_proof_hash)
}
