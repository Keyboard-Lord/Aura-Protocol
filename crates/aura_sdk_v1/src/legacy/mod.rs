//! Retired Solana SDK wires. Historical evidence only; never canonical v2 input.
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
