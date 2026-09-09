//! Chain-neutral proof preparation, canonical authorization and Aura presentation.

pub mod authorization;
pub mod legacy;
mod udot;
mod udot_bundle_v2;

use aura_fractal_key_integration_v1::{prepare_bound_proof_reference_v1, FractalKeyBindingErrorV1};
use aura_fractal_key_v1::FractalKeyV1;
use aura_proof_material_v1::{ProofMaterialV1, ProofMaterialV1Error};
use core::fmt;

use aura_udot_v2::{UdotArtifactKind, UdotVersion};
pub use aura_udot_v2::{UdotHashError, UdotParseError, UdotValidationError};
pub use udot::{
    generate_wallet_visual_v1, parse_wallet_visual_v1,
    proof_hash_hex_from_wallet_visual_v1, validate_wallet_visual_v1,
};
pub use udot_bundle_v2::{
    generate_udot_bundle_v2, validate_udot_bundle_v2, UdotBundleV2, UdotBundleV2Error,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedBoundProofMaterialV1 {
    pub proof_material: ProofMaterialV1,
    pub proof_material_hash: [u8; 32],
    pub fractal_key: FractalKeyV1,
    pub proof_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuraSdkErrorV1 {
    ProofMaterialVerificationFailed(ProofMaterialV1Error),
    SubmitProofPreparationFailed(FractalKeyBindingErrorV1),
    UdotHashNormalizationFailed(UdotHashError),
    UdotArtifactParseFailed(UdotParseError),
    UdotArtifactValidationFailed(UdotValidationError),
    UdotBundleHashMismatch {
        expected_aura_hash_hex: String,
        bundle_aura_hash_hex: String,
    },
    AuthorizationIntentFieldMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    ProofEnvelopeFieldInvalid {
        field: &'static str,
        reason: String,
    },
    SettlementFieldInvalid {
        field: &'static str,
        reason: String,
    },
}

impl fmt::Display for AuraSdkErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofMaterialVerificationFailed(error) => {
                write!(f, "proof material verification failed: {error}")
            }
            Self::SubmitProofPreparationFailed(error) => {
                write!(f, "submit-proof preparation failed: {error}")
            }
            Self::UdotHashNormalizationFailed(error) => {
                write!(f, "udot hash normalization failed: {error}")
            }
            Self::UdotArtifactParseFailed(error) => {
                write!(f, "udot artifact parse failed: {error}")
            }
            Self::UdotArtifactValidationFailed(error) => {
                write!(f, "udot artifact validation failed: {error}")
            }
            Self::UdotBundleHashMismatch {
                expected_aura_hash_hex,
                bundle_aura_hash_hex,
            } => write!(
                f,
                "udot bundle aura_hash_hex {bundle_aura_hash_hex} does not match expected aura_hash_hex {expected_aura_hash_hex}"
            ),
            Self::AuthorizationIntentFieldMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "authorization intent field {field} value {actual} does not match expected {expected}"
            ),
            Self::ProofEnvelopeFieldInvalid { field, reason } => {
                write!(f, "proof envelope field {field} invalid: {reason}")
            }
            Self::SettlementFieldInvalid { field, reason } => {
                write!(f, "settlement field {field} invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for AuraSdkErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProofMaterialVerificationFailed(error) => Some(error),
            Self::SubmitProofPreparationFailed(error) => Some(error),
            Self::UdotHashNormalizationFailed(error) => Some(error),
            Self::UdotArtifactParseFailed(error) => Some(error),
            Self::UdotArtifactValidationFailed(error) => Some(error),
            Self::UdotBundleHashMismatch { .. }
            | Self::AuthorizationIntentFieldMismatch { .. }
            | Self::ProofEnvelopeFieldInvalid { .. }
            | Self::SettlementFieldInvalid { .. } => None,
        }
    }
}

/// Bind proof material using existing canonical bytes. This does not verify the
/// Aura proof or authorize an action; canonical admission owns those checks.
/// Historical account-oriented names are available only under `legacy`.
///
/// ```compile_fail
/// use aura_sdk_v1::prepare_submit_proof_flow_v1;
/// ```
pub fn prepare_bound_proof_material_v1(
    subject_binding_bytes: [u8; 32],
    freshness_binding_bytes: [u8; 32],
    proof_blob_bytes: &[u8],
    public_inputs_bytes: &[u8],
    verification_key_bytes: &[u8],
) -> Result<PreparedBoundProofMaterialV1, AuraSdkErrorV1> {
    let proof_material = ProofMaterialV1::build(
        proof_blob_bytes,
        public_inputs_bytes,
        verification_key_bytes,
    );
    let proof_material_hash = proof_material.proof_material_hash();

    proof_material
        .verify(
            proof_blob_bytes,
            public_inputs_bytes,
            verification_key_bytes,
            proof_material_hash,
        )
        .map_err(AuraSdkErrorV1::ProofMaterialVerificationFailed)?;

    let preparation = prepare_bound_proof_reference_v1(
        subject_binding_bytes,
        freshness_binding_bytes,
        proof_material_hash,
    )
    .map_err(AuraSdkErrorV1::SubmitProofPreparationFailed)?;

    Ok(PreparedBoundProofMaterialV1 {
        proof_material,
        proof_material_hash,
        fractal_key: preparation.fractal_key,
        proof_hash: preparation.proof_hash,
    })
}
