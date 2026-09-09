//! Chain-neutral Aura v1 integration between proof-material preparation and FractalKey binding.

pub mod legacy;

use aura_fractal_key_v1::{
    FractalKeyBuilderInputV1, FractalKeyV1, FractalKeyV1Error, FractalKeyVerifierInputV1,
    FRACTAL_COMPONENT_PAYLOAD_LEN_V1,
};
use core::fmt;

pub type ProofHashV1 = [u8; FRACTAL_COMPONENT_PAYLOAD_LEN_V1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FractalKeyBindingInputV1 {
    pub subject_binding: ProofHashV1,
    pub freshness_binding: ProofHashV1,
    pub proof_material_hash: ProofHashV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundProofReferenceV1 {
    pub fractal_key: FractalKeyV1,
    pub proof_hash: ProofHashV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FractalKeyBindingErrorV1 {
    VerificationFailed(FractalKeyV1Error),
}

impl fmt::Display for FractalKeyBindingErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed(error) => {
                write!(f, "fractal key verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for FractalKeyBindingErrorV1 {}

pub fn prepare_bound_proof_reference_v1(
    subject_binding: ProofHashV1,
    freshness_binding: ProofHashV1,
    proof_material_hash: ProofHashV1,
) -> Result<BoundProofReferenceV1, FractalKeyBindingErrorV1> {
    let input = FractalKeyBindingInputV1 {
        subject_binding,
        freshness_binding,
        proof_material_hash,
    };
    let fractal_key = FractalKeyV1::build(FractalKeyBuilderInputV1 {
        subject_binding: input.subject_binding,
        challenge_binding: input.freshness_binding,
        proof_material_hash: input.proof_material_hash,
    });
    let proof_hash = fractal_key.proof_hash();

    verify_bound_proof_reference_v1(&fractal_key, &input, proof_hash)?;

    Ok(BoundProofReferenceV1 {
        fractal_key,
        proof_hash,
    })
}

pub fn derive_bound_proof_hash_v1(
    subject_binding: ProofHashV1,
    freshness_binding: ProofHashV1,
    proof_material_hash: ProofHashV1,
) -> Result<ProofHashV1, FractalKeyBindingErrorV1> {
    Ok(
        prepare_bound_proof_reference_v1(subject_binding, freshness_binding, proof_material_hash)?
            .proof_hash,
    )
}

pub fn verify_bound_proof_reference_v1(
    fractal_key: &FractalKeyV1,
    input: &FractalKeyBindingInputV1,
    expected_proof_hash: ProofHashV1,
) -> Result<(), FractalKeyBindingErrorV1> {
    fractal_key
        .verify(&FractalKeyVerifierInputV1 {
            expected_subject_binding: input.subject_binding,
            expected_challenge_binding: input.freshness_binding,
            expected_proof_material_hash: input.proof_material_hash,
            expected_proof_hash,
        })
        .map(|_| ())
        .map_err(FractalKeyBindingErrorV1::VerificationFailed)
}
