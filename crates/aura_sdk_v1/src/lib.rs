//! Rust SDK for the frozen Aura v1 proof-preparation flow.

pub mod authorization;
pub mod legacy;
mod udot;

use aura_fractal_key_integration_v1::{prepare_submit_proof_v1, SubmitProofIntegrationErrorV1};
use aura_fractal_key_v1::FractalKeyV1;
use aura_proof_material_v1::{ProofMaterialV1, ProofMaterialV1Error};
use core::fmt;

pub use aura_udot_v2::{
    UdotArtifactKind, UdotHashError, UdotParseError, UdotValidationError, UdotVersion,
};
pub use udot::{
    generate_udot_artifact_bundle_wire_v1, generate_udot_artifacts_v1,
    generate_wallet_visual_v1,
    parse_udot_artifact_bundle_wire_v1, parse_udot_artifact_v1, parse_udot_artifact_wire_v1,
    parse_wallet_visual_v1, proof_hash_hex_from_wallet_visual_v1,
    validate_udot_artifact_bundle_wire_v1, validate_udot_artifact_v1,
    validate_udot_artifact_wire_v1, validate_wallet_visual_v1,
    GenerateUdotArtifactBundleWireRequestV1,
    GenerateUdotArtifactsRequestV1, GeneratedUdotArtifactsV1, ParseUdotArtifactRequestV1,
    UdotArtifactBundleWireV1, UdotArtifactEnvelopeV1, UdotArtifactWireV1,
    ValidateUdotArtifactRequestV1, ValidateUdotArtifactWireRequestV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedSubmitProofV1 {
    pub proof_material: ProofMaterialV1,
    pub proof_material_hash: [u8; 32],
    pub fractal_key: FractalKeyV1,
    pub proof_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuraSdkErrorV1 {
    ProofMaterialVerificationFailed(ProofMaterialV1Error),
    SubmitProofPreparationFailed(SubmitProofIntegrationErrorV1),
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

pub fn prepare_submit_proof_flow_v1(
    subject_pubkey_bytes: [u8; 32],
    challenge_account_pubkey_bytes: [u8; 32],
    proof_blob_bytes: &[u8],
    public_inputs_bytes: &[u8],
    verification_key_bytes: &[u8],
) -> Result<PreparedSubmitProofV1, AuraSdkErrorV1> {
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

    let preparation = prepare_submit_proof_v1(
        subject_pubkey_bytes,
        challenge_account_pubkey_bytes,
        proof_material_hash,
    )
    .map_err(AuraSdkErrorV1::SubmitProofPreparationFailed)?;

    Ok(PreparedSubmitProofV1 {
        proof_material,
        proof_material_hash,
        fractal_key: preparation.fractal_key,
        proof_hash: preparation.proof_hash,
    })
}
