//! Aura's chain-neutral Storm execution, claim and witness-verification core.
//!
//! The crate root exposes canonical message preparation, 521-bit field arithmetic,
//! Storm derivation/execution, trace commitments, claims, compact public inputs,
//! and the existing witness proof codec and verifier. The witness backend replays
//! the nonlinear Storm relation; it is not a succinct STARK.
//!
//! Historical cat-map execution and Winterfell proofs are available only through
//! [`legacy::catmap_v1`]. Mixed claim/session wrappers and the former layered
//! authorization proof pipeline are retained under [`legacy::proof_pipeline_v1`].
//! Their acceptance does not establish Bitcoin Authorization V2 acceptance, which
//! is owned by `aura_sdk_v1`. Research overlays live in
//! `aura_intent_lineage_research_v1` or the explicit experimental
//! [`storm_hierarchy_v2`] module.
//!
//! # Public boundary
//!
//! Canonical Storm entry points remain available directly:
//! ```
//! use aura_intent_lineage_v1::{
//!     StormClaim521V1, StormAirRealProofArtifactV1,
//!     prove_storm_air_real_v1, verify_storm_air_real_v1,
//! };
//! ```
//! Historical claims and verifiers require an explicit legacy path:
//! ```
//! use aura_intent_lineage_v1::legacy::{
//!     catmap_v1::{DcmClaim521V1, prove_dcm_air_real_stark_v1},
//!     proof_pipeline_v1::{AuthorizationEnvelopeV1, AuraLayer4PrototypeStateV1,
//!         ProofSessionPackageV1, PublicClaimV1},
//! };
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::DcmClaim521V1;
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::prove_dcm_air_real_stark_v1;
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::verify_dcm_air_mock_proof_v1;
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::ProofSessionPackageV1;
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::PublicClaimV1;
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::AuthorizationEnvelopeV1;
//! ```
//! ```compile_fail
//! use aura_intent_lineage_v1::AuraLayer4PrototypeStateV1;
//! ```

use core::fmt;
use sha2::{Digest, Sha256};

mod commitment_521_v1;
mod aura_hash_v1;
mod dcm_air_adapter_v1;
mod dcm_air_v1;
mod dcm_v1;
mod field_521_v1;
mod legacy_authorization_v1;
mod layer1_layer2_bridge_v1;
mod layer2_object_v1;
mod layer3_authorization_lineage_consumer_v1;
mod layer3_authorization_lineage_proof_v1;
mod layer3_claim_v1;
mod layer3_layer4_verified_authorization_ingress_v1;
mod lower_layer_execution_commitment_v2;
mod mock_prover_v1;
mod mock_verifier_v1;
mod proof_session_v1;
mod proof_transcript_v1;
mod recurrence_constraints_v1;
mod session_encryption_context_v1;
mod session_key_v1;
mod stark_prover_v1;
mod stark_trace_commitment_v1;
mod stark_transcript_v1;
mod stark_verifier_v1;
mod state_engine_v1;
mod storm_air_v1;
mod storm_claim_v1;
mod storm_context_v1;
mod storm_encryption_binding_v1;
mod storm_execution_v1;
mod storm_hash521_v1;
/// Experimental research overlay; excluded from canonical claims and wires.
pub mod storm_hierarchy_v2;
mod storm_state_v1;
mod storm_trace_commitment_v1;
mod symmetric_envelope_v1;

pub(crate) use commitment_521_v1::*;
// Shared canonical message preparation; historical identity hashing stays in legacy.
pub use aura_hash_v1::{
    canonical_message_bytes_v1, canonical_text_payload_bytes_v1,
    canonical_text_payload_bytes_from_text_v1, decode_and_normalize_message_utf8_v1,
    normalize_text_message_v1, AuraHashV1Error, AURA_HASH_V1_BOM_CODEPOINT,
    AURA_HASH_V1_LENGTH_PREFIX_BYTES,
};
pub(crate) use dcm_air_adapter_v1::*;
pub(crate) use dcm_air_v1::*;
pub(crate) use dcm_v1::*;
pub use field_521_v1::*;
pub(crate) use layer1_layer2_bridge_v1::*;
pub(crate) use layer2_object_v1::*;
pub(crate) use layer3_authorization_lineage_consumer_v1::*;
pub(crate) use layer3_authorization_lineage_proof_v1::*;
pub(crate) use layer3_claim_v1::*;
pub(crate) use mock_prover_v1::*;
pub(crate) use mock_verifier_v1::*;
pub(crate) use proof_transcript_v1::*;
pub(crate) use recurrence_constraints_v1::*;
pub use session_encryption_context_v1::*;
pub use session_key_v1::*;
pub(crate) use stark_prover_v1::*;
pub use stark_prover_v1::{
    STORM_AIR_REAL_PROOF_VERSION_V1,
    STORM_AIR_REAL_PROOF_BACKEND_WITNESS_V1,
    STORM_AIR_REAL_PROOF_TRACE_WIDTH_V1,
    STORM_AIR_REAL_PROOF_CONSTRAINT_COUNT_V1,
    AURA_STORM_AIR_REAL_PUBLIC_INPUT_DIGEST_V1_DOMAIN_SEPARATOR,
    AURA_STORM_AIR_REAL_PROOF_BYTES_V1_DOMAIN_SEPARATOR,
    AURA_STORM_AIR_REAL_PROOF_BINDING_V1_DOMAIN_SEPARATOR,
    StormAirRealProofArtifactV1,
    StormAirRealProverErrorV1,
    prove_storm_air_real_v1,
    decode_storm_air_real_artifact_v1,
    StormAirRealProofDecodeErrorV1,
};
pub(crate) use stark_trace_commitment_v1::*;
pub(crate) use stark_transcript_v1::*;
pub(crate) use stark_verifier_v1::*;
pub use stark_verifier_v1::{
    StormAirRealVerifierAcceptanceV1,
    StormAirRealVerifierErrorV1,
    verify_storm_air_real_v1,
};
pub(crate) use legacy_authorization_v1::*;
pub use storm_air_v1::*;
pub use storm_claim_v1::*;
pub use storm_context_v1::*;
pub use storm_encryption_binding_v1::*;
pub use storm_execution_v1::*;
pub use storm_hash521_v1::*;
pub use storm_state_v1::*;
pub use storm_trace_commitment_v1::*;
pub use symmetric_envelope_v1::*;

/// Historical compatibility and research evidence, outside canonical pipeline entry.
///
/// These namespaces preserve the former implementations and their bytes. They do
/// not perform implicit conversion into Storm claims or Bitcoin authorization.
pub mod legacy {
    /// Historical SHA-256 identity function. Shared message canonicalization stays
    /// available at the crate root; the active 521-bit identity uses AURA_HASH521_V1.
    #[deprecated(since = "2.0.0", note = "Use AURA_HASH521_V1 for the active 521-bit identity.")]
    pub mod aura_hash_v1 {
        pub use crate::aura_hash_v1::*;
    }

    /// Historical cat-map execution, commitments, mock/scaffold and Winterfell proofs.
    /// These proofs do not establish the nonlinear Storm relation.
    pub mod catmap_v1 {
        pub use crate::commitment_521_v1::*;
        pub use crate::dcm_air_adapter_v1::*;
        pub use crate::dcm_air_v1::*;
        pub use crate::dcm_v1::*;
        pub use crate::mock_prover_v1::*;
        pub use crate::mock_verifier_v1::*;
        pub use crate::recurrence_constraints_v1::*;
        pub use crate::stark_trace_commitment_v1::*;
        pub use crate::stark_transcript_v1::*;
        pub use crate::stark_prover_v1::{
            DCM_AIR_STARK_PROOF_SCAFFOLD_VERSION_V1,
            AURA_DCM_AIR_STARK_PROOF_SCAFFOLD_V1_DOMAIN_SEPARATOR,
            DcmAirStarkOpeningMetadataV1,
            DcmAirStarkTransitionOpeningsV1,
            DcmAirStarkProofArtifactV1,
            DcmAirStarkProverErrorV1,
            prove_dcm_air_stark_scaffold_v1,
            DCM_AIR_REAL_STARK_PROOF_VERSION_V1,
            DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1,
            AURA_DCM_AIR_REAL_STARK_PROOF_BYTES_DOMAIN_SEPARATOR,
            AURA_DCM_AIR_REAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR,
            DCM_AIR_REAL_STARK_TRACE_WIDTH_V1,
            DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1,
            DcmAirWinterfellPublicInputsV1,
            derive_dcm_air_commitment_root_521_v1,
            DcmAirRealStarkProofArtifactV1,
            DcmAirRealStarkProverErrorV1,
            prove_dcm_air_real_stark_v1,
        };
        pub use crate::stark_verifier_v1::{
            DcmAirStarkVerifierAcceptanceV1,
            DcmAirStarkVerifierErrorV1,
            verify_dcm_air_stark_scaffold_v1,
            DcmAirRealStarkVerifierAcceptanceV1,
            DcmAirRealStarkVerifierErrorV1,
            verify_dcm_air_real_stark_v1,
        };
    }

    /// Former layered authorization, duplicated claims and mixed proof sessions.
    /// Retained consumers must choose this compatibility boundary explicitly.
    pub mod proof_pipeline_v1 {
        pub use crate::legacy_authorization_v1::*;
        pub use crate::state_engine_v1::*;
        pub use crate::layer1_layer2_bridge_v1::*;
        pub use crate::layer2_object_v1::*;
        pub use crate::layer3_authorization_lineage_consumer_v1::*;
        pub use crate::layer3_authorization_lineage_proof_v1::*;
        pub use crate::layer3_claim_v1::*;
        pub use crate::layer3_layer4_verified_authorization_ingress_v1::*;
        pub use crate::lower_layer_execution_commitment_v2::*;
        pub use crate::proof_session_v1::*;
        pub use crate::proof_transcript_v1::*;
    }
}

pub const HASH_LEN_V1: usize = 32;
pub(crate) struct LowerHex32<'a>(pub(crate) &'a [u8; HASH_LEN_V1]);

impl fmt::Display for LowerHex32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(crate) struct LowerHex521<'a>(pub(crate) &'a DeterministicCommitment521V1);

impl fmt::Display for LowerHex521<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(crate) fn sha256_domain_separated(
    domain_separator: &[u8],
    payload: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(domain_separator.len() + payload.len());
    preimage.extend_from_slice(domain_separator);
    preimage.extend_from_slice(payload);
    sha256_bytes(&preimage)
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; HASH_LEN_V1] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; HASH_LEN_V1];
    hash.copy_from_slice(&digest);
    hash
}
