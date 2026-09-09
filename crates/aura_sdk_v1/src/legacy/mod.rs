//! Retired Solana SDK wires. Historical evidence only; never canonical v2 input.
// Explicit compatibility names; byte preparation has one chain-neutral owner.
pub use crate::{
    prepare_bound_proof_material_v1 as prepare_submit_proof_flow_v1,
    PreparedBoundProofMaterialV1 as PreparedSubmitProofV1,
};

mod authorization;
mod pipeline;
mod proof;
mod settlement;
mod submission;

pub use authorization::{
    generate_authorization_intent_v1, validate_authorization_intent_envelope_v1,
    AuthorizationFreshnessBindingTypeV1, AuthorizationIntentEnvelopeV1, AuthorizationIntentTypeV1,
    AuthorizationIntentVersionV1, AuthorizationLineageBindingV1, AuthorizationSubjectBindingTypeV1,
    GenerateAuthorizationIntentV1,
};
pub use pipeline::{
    build_settlement_pipeline_from_prepared_proof_v1,
    BuildSettlementPipelineFromPreparedProofRequestV1, SettlementPipelineFromPreparedProofV1,
};
pub use proof::{
    generate_stark_proof_envelope_v1, validate_stark_proof_envelope_v1, DcmClaimWireV1,
    GenerateStarkProofEnvelopeV1, StarkProofEnvelopeV1, StarkProofVersionV1,
};
pub use settlement::{
    generate_solana_settlement_request_v1, validate_solana_settlement_request_v1,
    GenerateSolanaSettlementRequestV1, SolanaCommitmentConfigV1, SolanaSettlementRequestWireV1,
    SolanaSettlementVersionV1,
};
pub use submission::{
    build_submit_proof_request_wire_v1, generate_submit_proof_request_v1,
    validate_submit_proof_request_wire_v1, BuildSubmitProofRequestWireRequestV1,
    GenerateSubmitProofRequestV1, SubmitProofRequestWireV1,
};

// Versioned UDOT objects are compatibility inputs, never the canonical V2 bundle.
pub use aura_udot_v2::{UdotArtifactKind, UdotVersion};
pub use crate::udot::{
    generate_udot_artifact_bundle_wire_v1, generate_udot_artifacts_v1,
    parse_udot_artifact_bundle_wire_v1, parse_udot_artifact_v1, parse_udot_artifact_wire_v1,
    validate_udot_artifact_bundle_wire_v1, validate_udot_artifact_v1,
    validate_udot_artifact_wire_v1, GenerateUdotArtifactBundleWireRequestV1,
    GenerateUdotArtifactsRequestV1, GeneratedUdotArtifactsV1, ParseUdotArtifactRequestV1,
    UdotArtifactBundleWireV1, UdotArtifactEnvelopeV1, UdotArtifactWireV1,
    ValidateUdotArtifactRequestV1, ValidateUdotArtifactWireRequestV1,
};
