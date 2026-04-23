//! Runnable Aura Local Proving Chain v0.
//!
//! This crate provides the active local developer flow for:
//!
//! - loading a versioned canonical pipeline request
//! - executing an ordered transfer batch
//! - deriving frozen public inputs
//! - generating either a mock or real STARK proof artifact
//! - verifying that artifact
//! - accepting or rejecting the transition locally
//!
//! The canonical executable surface is `run-canonical-pipeline`, which consumes
//! one request file and produces one versioned bridge report. Legacy scenario
//! and proof-vector commands remain for compatibility and reproducibility only;
//! they are not the canonical active-system pipeline.
//!
//! The mock and real STARK boundaries are both explicit and honest. For
//! repository navigation, see `AURA_ENGINEERING_START_HERE_V1.md` and
//! `AURA_ACTIVE_SYSTEM_MAP_V1.md` at the repo root.

use core::fmt;
use std::{collections::BTreeSet, fs, path::Path};

use aura_intent_lineage_v1::{
    dcm_air_public_inputs_from_claim_521_v1, derive_dcm_air_stark_public_input_digest_v1,
    prove_dcm_air_real_stark_v1, verify_dcm_air_real_stark_v1, DcmAirPublicInputsV1,
    DcmAirRealStarkProofArtifactV1, DcmConfig521V1, DcmExecution521V1, DcmInput521V1,
    HASH_LEN_V1 as DCM_HASH_LEN_V1,
};
use aura_l2_execution_v1::{
    derive_outcomes_commitment_v1, derive_touched_accounts_commitment_v1,
    derive_transactions_commitment_v1, derive_transfer_result_commitment_v1,
    execute_transfer_batch_v1, AppliedTransferStepV1, BatchExecutionRequestV1, ExecutionOutcomeV1,
    LocalAccountV1, LocalExecutionConfigV1, LocalExecutionErrorV1, LocalFeeSummaryV1, LocalStateV1,
    TransferTransactionV1, BATCH_VERSION_V1, EXECUTION_MODEL_VERSION_V1,
    EXECUTION_OUTCOME_STATUS_APPLIED_V1, TRANSFER_TX_VERSION_V1, TRANSITION_BINDING_VERSION_V1,
    ZERO_FEE_PER_TRANSFER_V1,
};
use aura_l2_local_settlement_v1::{
    accept_transition_v1, LocalSettlementErrorV1, LocalSettlementStateV1,
};
use aura_l2_prover_v1::{
    derive_mock_proof_binding_digest_v1, derive_stark_proof_binding_digest_v1,
    prove_executed_batch_with_mock_prover_v1, prove_executed_batch_with_stark_prover_v1,
    LocalProofArtifactV1, LocalProverErrorV1, LocalStarkProofArtifactV1,
    LOCAL_MOCK_PROOF_VERSION_V1, LOCAL_PROVER_KIND_MOCK_V1, LOCAL_PROVER_KIND_STARK_V1,
    LOCAL_STARK_PROOF_VERSION_V1,
};
use aura_l2_public_input_v1::TransitionEnvelopeV1;
use aura_l2_verifier_v1::{verify_proof_artifact_v1, LocalVerifierErrorV1};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioResultV1 {
    Accepted,
    ExecutionRejected,
    VerificationRejected,
    SettlementRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSystemSelectionV1 {
    Mock,
    Stark,
}

const GENESIS_FIXTURE_NAME_V1: &str = "genesis_state";
const GENESIS_FIXTURE_SCHEMA_VERSION_V1: u32 = 1;
const SCENARIO_FIXTURE_SCHEMA_VERSION_V1: u32 = 1;
const PROOF_VECTOR_FIXTURE_SCHEMA_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_ID_V1: &str = "aura_local_pipeline_v1";
pub const CANONICAL_PIPELINE_SCHEMA_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_ECONOMIC_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_BURN_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_ACCOUNTING_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_ATTESTATION_SCHEMA_VERSION_V2: u32 = 2;
pub const CANONICAL_PIPELINE_ATTESTATION_NORMALIZATION_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_LEDGER_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_SETTLEMENT_HEAD_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_WALLET_BINDING_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_TOKEN_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_PROVENANCE_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_STARK_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_ATTESTATION_PROOF_MOCK_POLICY_VERSION_V1: u32 = 1;
pub const CANONICAL_PIPELINE_ATTESTATION_STARK_ITERATION_COUNT_V1: u64 = 4;
const CANONICAL_PIPELINE_ATTESTATION_STARK_X_SEED_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_STARK_X_SEED_V1";
const CANONICAL_PIPELINE_ATTESTATION_STARK_Y_SEED_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_STARK_Y_SEED_V1";
const CANONICAL_PIPELINE_GENESIS_ACCOUNTS_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_LEDGER_ACCOUNTS_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_TRANSACTIONS_EXPANSION_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_OUTCOMES_EXPANSION_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_BATCH_CONTEXT_EXPANSION_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_FEE_SUMMARY_EXPANSION_VERSION_V1: u32 = 1;
const PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1: usize = 284;
const PROOF_BINDING_DIGEST_LEN_V1: usize = 32;
const TRANSITION_BINDING_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_L2_TRANSITION_BINDING_V1";
const CANONICAL_PIPELINE_REQUEST_BINDING_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_REQUEST_V1";
const CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_BURN_METERING_V1";
const CANONICAL_PIPELINE_GENESIS_ACCOUNTS_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_V1";
const CANONICAL_PIPELINE_LEDGER_ACCOUNTS_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_LEDGER_ACCOUNTS_V1";
const CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_LEDGER_STATE_V1";
const CANONICAL_PIPELINE_TRANSACTIONS_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_TRANSACTIONS_V1";
const CANONICAL_PIPELINE_ATTESTATION_CLAIM_DIGEST_DOMAIN_SEPARATOR_V2: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_CLAIM_V2";
const CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_DIGEST_DOMAIN_SEPARATOR_V2: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_V2";
const CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_ROOT_DIGEST_DOMAIN_SEPARATOR_V2: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_ROOT_V2";
const CANONICAL_PIPELINE_PROVENANCE_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_PROVENANCE_V1";
const CANONICAL_PIPELINE_PROVENANCE_ITEM_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_PROVENANCE_ITEM_V1";
const CANONICAL_PIPELINE_ATTESTATION_TUPLE_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_TUPLE_V1";
const CANONICAL_PIPELINE_HEAD_TRANSITION_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_HEAD_TRANSITION_V1";
const CANONICAL_PIPELINE_HEAD_HASH_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_HEAD_HASH_V1";
const CANONICAL_PIPELINE_REPORT_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_REPORT_DIGEST_V1";
const CANONICAL_PIPELINE_WALLET_BINDING_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_WALLET_BINDING_V1";
const CANONICAL_PIPELINE_TOKEN_ANCHOR_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_TOKEN_ANCHOR_V1";
const CANONICAL_PIPELINE_HEAD_STATE_FILE_VERSION_V1: u32 = 1;
const CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_MESSAGE_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_L2_CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_V1";
const CANONICAL_PIPELINE_BURN_BASE_UNITS_V1: u64 = 10;
const CANONICAL_PIPELINE_BURN_EXECUTION_KIND_UNITS_V1: u64 = 5;
const CANONICAL_PIPELINE_BURN_ATTESTATION_KIND_UNITS_V1: u64 = 2;
const CANONICAL_PIPELINE_BURN_STARK_UNITS_V1: u64 = 3;
const CANONICAL_PIPELINE_BURN_MOCK_UNITS_V1: u64 = 1;
const CANONICAL_PIPELINE_BURN_TRANSACTION_UNITS_V1: u64 = 4;
const CANONICAL_PIPELINE_BURN_SIZE_CHUNK_BYTES_V1: u64 = 32;
const CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V1: [u8; 32] = [
    0x8a, 0x2c, 0xe8, 0x70, 0xaa, 0x1e, 0xf4, 0x7b, 0x5e, 0x78, 0x11, 0x6d, 0xc9, 0x59, 0x13, 0x63,
    0xd1, 0x22, 0x49, 0x32, 0x89, 0x3d, 0x44, 0x57, 0x19, 0xa1, 0xbe, 0x2d, 0xf7, 0x32, 0x71, 0x0f,
];

impl ProofSystemSelectionV1 {
    pub fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "MOCK" => Ok(Self::Mock),
            "STARK" => Ok(Self::Stark),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported proof system: {value}"
            ))),
        }
    }

    pub fn as_fixture_str(self) -> &'static str {
        match self {
            Self::Mock => "MOCK",
            Self::Stark => "STARK",
        }
    }
}

impl ScenarioResultV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "ACCEPTED" => Ok(Self::Accepted),
            "EXECUTION_REJECTED" => Ok(Self::ExecutionRejected),
            "VERIFICATION_REJECTED" => Ok(Self::VerificationRejected),
            "SETTLEMENT_REJECTED" => Ok(Self::SettlementRejected),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported expected_result: {value}"
            ))),
        }
    }

    fn as_fixture_str(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::ExecutionRejected => "EXECUTION_REJECTED",
            Self::VerificationRejected => "VERIFICATION_REJECTED",
            Self::SettlementRejected => "SETTLEMENT_REJECTED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineRequestKindV1 {
    Execution,
    Attestation,
}

impl CanonicalPipelineRequestKindV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "execution" => Ok(Self::Execution),
            "attestation" => Ok(Self::Attestation),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline request_kind: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Attestation => "attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineBurnIntentV1 {
    CanonicalReport,
}

impl CanonicalPipelineBurnIntentV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "canonical_report" => Ok(Self::CanonicalReport),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline burn_intent: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalReport => "canonical_report",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelinePaymentIntentV1 {
    BurnToProduceCanonicalTruth,
}

impl CanonicalPipelinePaymentIntentV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "burn_to_produce_canonical_truth" => Ok(Self::BurnToProduceCanonicalTruth),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline payment_intent: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::BurnToProduceCanonicalTruth => "burn_to_produce_canonical_truth",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineSettlementIntentV1 {
    RecordCanonicalOutcome,
}

impl CanonicalPipelineSettlementIntentV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "record_canonical_outcome" => Ok(Self::RecordCanonicalOutcome),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline settlement_intent: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::RecordCanonicalOutcome => "record_canonical_outcome",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineBurnReasonV1 {
    ProduceCanonicalTruthArtifact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineBurnCategoryV1 {
    ExecutionTruthProduction,
    AttestationTruthProduction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineFeeDispositionV1 {
    BurnedForCanonicalTruth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineHeadAuthorityModeV1 {
    AuthoritativePersistent,
    StatelessNonAuthoritative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineFutureTokenBindingStatusV1 {
    PendingExternalAnchor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineNetworkModeV1 {
    Local,
    Bridged,
}

impl CanonicalPipelineNetworkModeV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "local" => Ok(Self::Local),
            "bridged" => Ok(Self::Bridged),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline network_mode: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Bridged => "bridged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineSettlementAnchorTypeV1 {
    Local,
    Simulated,
    External,
}

impl CanonicalPipelineSettlementAnchorTypeV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "local" => Ok(Self::Local),
            "simulated" => Ok(Self::Simulated),
            "external" => Ok(Self::External),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline settlement_anchor_type: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Simulated => "simulated",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineExternalAnchorVerificationStatusV1 {
    NotRequested,
    Accepted,
    Rejected,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineEvidenceProvenanceTypeV1 {
    Inline,
    HashReference,
    SignedBlob,
    AnchoredExternal,
}

impl CanonicalPipelineEvidenceProvenanceTypeV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "inline" => Ok(Self::Inline),
            "hash_reference" => Ok(Self::HashReference),
            "signed_blob" => Ok(Self::SignedBlob),
            "anchored_external" => Ok(Self::AnchoredExternal),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline evidence_provenance_type: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::HashReference => "hash_reference",
            Self::SignedBlob => "signed_blob",
            Self::AnchoredExternal => "anchored_external",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationProofKindV1 {
    Mock,
    Stark,
}

impl CanonicalPipelineAttestationProofKindV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "MOCK" => Ok(Self::Mock),
            "STARK" => Ok(Self::Stark),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline attestation_proof_kind: {value}"
            ))),
        }
    }

    fn as_fixture_str(self) -> &'static str {
        match self {
            Self::Mock => "MOCK",
            Self::Stark => "STARK",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineSettlementReasonV1 {
    AcceptedAndCommitted,
    NotRunExecutionRejected,
    RejectedVerificationMismatch,
    RejectedLocalSettlement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineTruthArtifactKindV1 {
    ExecutionReport,
    AttestationReport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineFailureStageV1 {
    None,
    Request,
    Execution,
    Verification,
    Settlement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineFailureReasonCodeV1 {
    None,
    TransferExecutionRejected,
    UnsupportedAttestationMode,
    AttestationMalformedEvidence,
    AttestationNormalizationFailure,
    AttestationConsistencyMismatch,
    SettlementHeadMismatch,
    WalletBindingMismatch,
    UnsupportedProvenanceType,
    ProvenanceSignatureInvalid,
    AttestationProofVerificationRejected,
    VerificationLayerMismatch,
    SettlementAcceptanceRejected,
}

impl CanonicalPipelineFailureReasonCodeV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TransferExecutionRejected => "transfer_execution_rejected",
            Self::UnsupportedAttestationMode => "unsupported_attestation_mode",
            Self::AttestationMalformedEvidence => "attestation_malformed_evidence",
            Self::AttestationNormalizationFailure => "attestation_normalization_failure",
            Self::AttestationConsistencyMismatch => "attestation_consistency_mismatch",
            Self::SettlementHeadMismatch => "settlement_head_mismatch",
            Self::WalletBindingMismatch => "wallet_binding_mismatch",
            Self::UnsupportedProvenanceType => "unsupported_provenance_type",
            Self::ProvenanceSignatureInvalid => "provenance_signature_invalid",
            Self::AttestationProofVerificationRejected => "attestation_proof_verification_rejected",
            Self::VerificationLayerMismatch => "verification_layer_mismatch",
            Self::SettlementAcceptanceRejected => "settlement_acceptance_rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationScopeV1 {
    ClaimConsistencyWithProvidedEvidenceOnly,
}

impl CanonicalPipelineAttestationScopeV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "claim_consistency_with_provided_evidence_only" => {
                Ok(Self::ClaimConsistencyWithProvidedEvidenceOnly)
            }
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline attestation_scope: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ClaimConsistencyWithProvidedEvidenceOnly => {
                "claim_consistency_with_provided_evidence_only"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationClaimKindV1 {
    EvidenceRootDigest,
    NormalizedEvidenceDigest,
    NormalizedTextContainsUtf8,
    NormalizedJsonFieldEqualsUtf8,
}

impl CanonicalPipelineAttestationClaimKindV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "evidence_root_digest" => Ok(Self::EvidenceRootDigest),
            "normalized_evidence_digest" => Ok(Self::NormalizedEvidenceDigest),
            "normalized_text_contains_utf8" => Ok(Self::NormalizedTextContainsUtf8),
            "normalized_json_field_equals_utf8" => Ok(Self::NormalizedJsonFieldEqualsUtf8),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline attestation claim_kind: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceRootDigest => "evidence_root_digest",
            Self::NormalizedEvidenceDigest => "normalized_evidence_digest",
            Self::NormalizedTextContainsUtf8 => "normalized_text_contains_utf8",
            Self::NormalizedJsonFieldEqualsUtf8 => "normalized_json_field_equals_utf8",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationEvidenceKindV1 {
    InlineUtf8,
    InlineJsonUtf8,
}

impl CanonicalPipelineAttestationEvidenceKindV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "inline_utf8" => Ok(Self::InlineUtf8),
            "inline_json_utf8" => Ok(Self::InlineJsonUtf8),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline attestation evidence_kind: {value}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::InlineUtf8 => "inline_utf8",
            Self::InlineJsonUtf8 => "inline_json_utf8",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationNormalizedFormV1 {
    Utf8Text,
    CanonicalJsonUtf8,
}

impl CanonicalPipelineAttestationNormalizedFormV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Utf8Text => "utf8_text",
            Self::CanonicalJsonUtf8 => "canonical_json_utf8",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationConsistencyRelationV1 {
    EvidenceRootDigestEquals,
    NormalizedEvidenceDigestEquals,
    NormalizedTextContainsUtf8,
    NormalizedJsonFieldEqualsUtf8,
}

impl CanonicalPipelineAttestationConsistencyRelationV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceRootDigestEquals => "evidence_root_digest_equals",
            Self::NormalizedEvidenceDigestEquals => "normalized_evidence_digest_equals",
            Self::NormalizedTextContainsUtf8 => "normalized_text_contains_utf8",
            Self::NormalizedJsonFieldEqualsUtf8 => "normalized_json_field_equals_utf8",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationDecisionV1 {
    ConsistencyEstablished,
    ConsistencyMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationStatusV1 {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationFailureReasonV1 {
    None,
    UnsupportedAttestationMode,
    MalformedEvidence,
    NormalizationFailure,
    ConsistencyMismatch,
    UnsupportedProvenanceType,
    ProvenanceSignatureInvalid,
    VerificationLayerFailure,
    AttestationProofVerificationFailure,
    SettlementLayerFailure,
}

#[derive(Debug)]
pub enum LocalChainErrorV1 {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidFixture(String),
    ProofVectorMismatch(String),
    Execution(LocalExecutionErrorV1),
    Prover(LocalProverErrorV1),
    Verifier(LocalVerifierErrorV1),
    Settlement(LocalSettlementErrorV1),
    UnexpectedResult {
        expected: ScenarioResultV1,
        actual: ScenarioResultV1,
    },
}

impl fmt::Display for LocalChainErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::InvalidFixture(error) => write!(f, "invalid fixture: {error}"),
            Self::ProofVectorMismatch(error) => write!(f, "proof vector mismatch: {error}"),
            Self::Execution(error) => write!(f, "execution error: {error}"),
            Self::Prover(error) => write!(f, "prover error: {error}"),
            Self::Verifier(error) => write!(f, "verifier error: {error}"),
            Self::Settlement(error) => write!(f, "settlement error: {error}"),
            Self::UnexpectedResult { expected, actual } => {
                write!(
                    f,
                    "unexpected result: expected {expected:?}, got {actual:?}"
                )
            }
        }
    }
}

impl std::error::Error for LocalChainErrorV1 {}

impl From<std::io::Error> for LocalChainErrorV1 {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for LocalChainErrorV1 {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<LocalExecutionErrorV1> for LocalChainErrorV1 {
    fn from(value: LocalExecutionErrorV1) -> Self {
        Self::Execution(value)
    }
}

impl From<LocalProverErrorV1> for LocalChainErrorV1 {
    fn from(value: LocalProverErrorV1) -> Self {
        Self::Prover(value)
    }
}

impl From<LocalVerifierErrorV1> for LocalChainErrorV1 {
    fn from(value: LocalVerifierErrorV1) -> Self {
        Self::Verifier(value)
    }
}

impl From<LocalSettlementErrorV1> for LocalChainErrorV1 {
    fn from(value: LocalSettlementErrorV1) -> Self {
        Self::Settlement(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioReportV1 {
    pub fixture_name: String,
    pub expected_result: ScenarioResultV1,
    pub actual_result: ScenarioResultV1,
    pub pre_state_root: [u8; 32],
    pub post_state_root: Option<[u8; 32]>,
    pub transition_binding_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorReportV1 {
    pub fixture_name: String,
    pub proof_system: ProofSystemSelectionV1,
    pub expected_result: ScenarioResultV1,
    pub actual_result: ScenarioResultV1,
    pub pre_state_root: [u8; 32],
    pub post_state_root: Option<[u8; 32]>,
    pub transition_binding_hash: [u8; 32],
    pub public_inputs_hash: [u8; 32],
    pub trace_digest: [u8; 32],
    pub trace_layout_digest: [u8; 32],
    pub proof_binding_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineExecutionStatusV1 {
    Applied,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineVerificationStatusV1 {
    Passed,
    Rejected,
    NotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineSettlementStatusV1 {
    Accepted,
    Rejected,
    NotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelinePublicInputsDecodeStatusV1 {
    Decoded,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineProofBindingInputKindV1 {
    WitnessDigest,
    ProofBytesHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineTamperAuditV1 {
    pub byte_offset: usize,
    pub xor_with: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineRequestAuditV1 {
    pub request_binding_hash: [u8; 32],
    pub genesis_accounts_digest: [u8; 32],
    pub ledger_accounts_digest: [u8; 32],
    pub transactions_digest: [u8; 32],
    pub rollup_id: [u8; 32],
    pub genesis_account_count: u64,
    pub ledger_account_count: u64,
    pub ledger_payer_account_id: [u8; 32],
    pub ledger_total_supply: u64,
    pub ledger_burned_supply: u64,
    pub batch_number: u64,
    pub tx_count: u64,
    pub parent_batch_commitment: [u8; 32],
    pub tamper_public_inputs: Option<CanonicalPipelineTamperAuditV1>,
    pub tamper_proof_binding_digest: Option<CanonicalPipelineTamperAuditV1>,
    pub tamper_attestation_stark_public_inputs_digest: Option<CanonicalPipelineTamperAuditV1>,
    pub tamper_attestation_stark_proof_bytes: Option<CanonicalPipelineTamperAuditV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAccountingPolicyV1 {
    pub accounting_policy_version: u32,
    pub payment_intent: CanonicalPipelinePaymentIntentV1,
    pub settlement_intent: CanonicalPipelineSettlementIntentV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineLedgerAccountV1 {
    pub account_id: [u8; 32],
    pub balance: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineLedgerPolicyV1 {
    pub ledger_policy_version: u32,
    pub payer_account_id: [u8; 32],
    pub total_supply: u64,
    pub burned_supply: u64,
    pub accounts: Vec<CanonicalPipelineLedgerAccountV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineEconomicPolicyV1 {
    pub economic_policy_version: u32,
    pub request_kind: CanonicalPipelineRequestKindV1,
    pub burn_intent: CanonicalPipelineBurnIntentV1,
    pub declared_fee_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationClaimV1 {
    pub claim_kind: CanonicalPipelineAttestationClaimKindV1,
    pub claim_payload: CanonicalPipelineAttestationClaimPayloadV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationClaimPayloadV1 {
    EvidenceRootDigest {
        expected_evidence_root_digest: [u8; 32],
    },
    NormalizedEvidenceDigest {
        target_label: String,
        expected_evidence_digest: [u8; 32],
    },
    NormalizedTextContainsUtf8 {
        target_label: String,
        expected_substring_utf8: String,
    },
    NormalizedJsonFieldEqualsUtf8 {
        target_label: String,
        field_path: Vec<String>,
        expected_value_utf8: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationEvidenceItemV1 {
    pub label: String,
    pub evidence_kind: CanonicalPipelineAttestationEvidenceKindV1,
    pub evidence_payload: CanonicalPipelineAttestationEvidencePayloadV1,
    pub provenance: CanonicalPipelineEvidenceProvenanceV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineAttestationEvidencePayloadV1 {
    InlineUtf8 { payload_utf8: String },
    InlineJsonUtf8 { payload_utf8: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationConstraintsV1 {
    pub require_unique_labels: bool,
    pub max_evidence_items: u64,
    pub max_total_normalized_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationRequestV1 {
    pub attestation_schema_version: u32,
    pub attestation_scope: CanonicalPipelineAttestationScopeV1,
    pub attestation_proof_kind: CanonicalPipelineAttestationProofKindV1,
    pub normalization_policy_version: u32,
    pub attestation_constraints: CanonicalPipelineAttestationConstraintsV1,
    pub claim: CanonicalPipelineAttestationClaimV1,
    pub evidence_items: Vec<CanonicalPipelineAttestationEvidenceItemV1>,
    pub tamper_stark_public_inputs_digest: Option<ByteTamperFixtureV1>,
    pub tamper_stark_proof_bytes: Option<ByteTamperFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineSettlementHeadRequestV1 {
    pub settlement_head_version: u32,
    pub previous_head_hash: [u8; 32],
    pub head_sequence_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineWalletBindingV1 {
    pub wallet_binding_version: u32,
    pub account_id: [u8; 32],
    pub wallet_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineExternalBalanceReferenceV1 {
    pub reference_id: String,
    pub observed_balance: Option<u64>,
    pub observed_slot: Option<u64>,
    pub connected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineTokenAnchorV1 {
    pub token_policy_version: u32,
    pub network_mode: CanonicalPipelineNetworkModeV1,
    pub settlement_anchor_type: CanonicalPipelineSettlementAnchorTypeV1,
    pub external_balance_reference: Option<CanonicalPipelineExternalBalanceReferenceV1>,
    pub enforce_external_match: bool,
    pub expected_external_balance: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineEvidenceSignatureV1 {
    pub signer_public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineEvidenceProvenanceV1 {
    pub provenance_policy_version: u32,
    pub provenance_type: CanonicalPipelineEvidenceProvenanceTypeV1,
    pub source_type: String,
    pub source_identifier: String,
    pub signature: Option<CanonicalPipelineEvidenceSignatureV1>,
    pub timestamp_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationEvidenceSummaryItemV1 {
    pub label: String,
    pub evidence_kind: CanonicalPipelineAttestationEvidenceKindV1,
    pub original_payload_utf8: String,
    pub original_payload_size_bytes: u64,
    pub normalized_form: CanonicalPipelineAttestationNormalizedFormV1,
    pub normalized_payload_utf8: String,
    pub normalized_payload_size_bytes: u64,
    pub evidence_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationEvidenceSummaryV1 {
    pub evidence_item_count: u64,
    pub evidence_items: Vec<CanonicalPipelineAttestationEvidenceSummaryItemV1>,
    pub evidence_root_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationNormalizationSummaryV1 {
    pub normalization_policy_version: u32,
    pub normalized_evidence_count: u64,
    pub total_normalized_bytes: u64,
    pub normalization_succeeded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationConsistencyResultV1 {
    pub relation: CanonicalPipelineAttestationConsistencyRelationV1,
    pub target_label: Option<String>,
    pub consistent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineProvenanceSummaryItemV1 {
    pub label: String,
    pub provenance_policy_version: u32,
    pub provenance_type: CanonicalPipelineEvidenceProvenanceTypeV1,
    pub source_type: String,
    pub source_identifier: String,
    pub signature_present: bool,
    pub signature_valid: bool,
    pub signer_public_key: Option<[u8; 32]>,
    pub signature: Option<[u8; 64]>,
    pub timestamp_unix_seconds: Option<u64>,
    pub provenance_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineProvenanceSummaryV1 {
    pub provenance_item_count: u64,
    pub items: Vec<CanonicalPipelineProvenanceSummaryItemV1>,
    pub provenance_root_digest: [u8; 32],
    pub all_signature_checks_passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationProofSummaryV1 {
    pub proof_kind: CanonicalPipelineAttestationProofKindV1,
    pub attestation_tuple_digest: [u8; 32],
    pub verification_passed: bool,
    pub mock_policy_version: Option<u32>,
    pub stark_policy_version: Option<u32>,
    pub stark_public_inputs_digest: Option<[u8; 32]>,
    pub stark_proof_bytes_digest: Option<[u8; 32]>,
    pub stark_proof_binding_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineHeadTransitionSummaryV1 {
    pub settlement_head_version: u32,
    pub authority_mode: CanonicalPipelineHeadAuthorityModeV1,
    pub head_sequence_number: u64,
    pub previous_head_hash: [u8; 32],
    pub current_head_hash: [u8; 32],
    pub canonical_head_commitment: [u8; 32],
    pub request_canonical_digest: [u8; 32],
    pub report_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineWalletBindingSummaryV1 {
    pub wallet_binding_version: u32,
    pub account_id: [u8; 32],
    pub wallet_address: String,
    pub wallet_binding_digest: [u8; 32],
    pub binding_consistent_with_account: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineTokenAnchorSummaryV1 {
    pub token_policy_version: u32,
    pub network_mode: CanonicalPipelineNetworkModeV1,
    pub settlement_anchor_type: CanonicalPipelineSettlementAnchorTypeV1,
    pub anchor_verification_status: CanonicalPipelineExternalAnchorVerificationStatusV1,
    pub external_balance_reference: Option<CanonicalPipelineExternalBalanceReferenceV1>,
    pub expected_external_balance: Option<u64>,
    pub token_anchor_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationFailureAuditV1 {
    pub reason: CanonicalPipelineAttestationFailureReasonV1,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAttestationSummaryV1 {
    pub attestation_schema_version: u32,
    pub attestation_scope: CanonicalPipelineAttestationScopeV1,
    pub attestation_proof_kind: CanonicalPipelineAttestationProofKindV1,
    pub normalization_policy_version: u32,
    pub attestation_constraints: CanonicalPipelineAttestationConstraintsV1,
    pub claim: CanonicalPipelineAttestationClaimV1,
    pub claim_digest: [u8; 32],
    pub evidence_summary: CanonicalPipelineAttestationEvidenceSummaryV1,
    pub normalization_summary: CanonicalPipelineAttestationNormalizationSummaryV1,
    pub consistency_result: CanonicalPipelineAttestationConsistencyResultV1,
    pub attestation_status: CanonicalPipelineAttestationStatusV1,
    pub attestation_failure_reason: CanonicalPipelineAttestationFailureAuditV1,
    pub proof_scope_honesty_note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineBurnPolicyV1 {
    pub burn_policy_version: u32,
    pub base_units: u64,
    pub execution_request_kind_units: u64,
    pub attestation_request_kind_units: u64,
    pub mock_proof_system_units: u64,
    pub stark_proof_system_units: u64,
    pub transaction_units_per_item: u64,
    pub metered_request_size_chunk_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineBurnDerivationInputsV1 {
    pub tx_count: u64,
    pub metered_request_size_bytes: u64,
    pub request_kind: CanonicalPipelineRequestKindV1,
    pub proof_system: ProofSystemSelectionV1,
    pub attestation_evidence_items: u64,
    pub attestation_claim_bytes: u64,
    pub attestation_evidence_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineBurnFailureSemanticsV1 {
    pub execution_rejected_burns_full_amount: bool,
    pub verification_rejected_burns_full_amount: bool,
    pub settlement_rejected_burns_full_amount: bool,
    pub partial_burn_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineBurnSummaryV1 {
    pub burn_policy_version: u32,
    pub burn_policy: CanonicalPipelineBurnPolicyV1,
    pub burn_reason: CanonicalPipelineBurnReasonV1,
    pub burn_category: CanonicalPipelineBurnCategoryV1,
    pub request_kind: CanonicalPipelineRequestKindV1,
    pub burn_intent: CanonicalPipelineBurnIntentV1,
    pub declared_fee_units: u64,
    pub computed_burn_units: u64,
    pub consumed_burn_units: u64,
    pub burn_derivation_inputs: CanonicalPipelineBurnDerivationInputsV1,
    pub request_declares_correct_burn: bool,
    pub recomputed_burn_matches_report: bool,
    pub burn_consumed: bool,
    pub failure_semantics: CanonicalPipelineBurnFailureSemanticsV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineBurnRecordV1 {
    pub burn_reason: CanonicalPipelineBurnReasonV1,
    pub burn_category: CanonicalPipelineBurnCategoryV1,
    pub fee_disposition: CanonicalPipelineFeeDispositionV1,
    pub account_id: [u8; 32],
    pub pre_balance: u64,
    pub post_balance: u64,
    pub burned_amount: u64,
    pub declared_fee_units: u64,
    pub computed_burn_units: u64,
    pub consumed_burn_units: u64,
    pub report_pipeline_id: String,
    pub report_request_binding_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineSettlementRecordV1 {
    pub settlement_intent: CanonicalPipelineSettlementIntentV1,
    pub settlement_status: CanonicalPipelineSettlementStatusV1,
    pub settlement_reason: CanonicalPipelineSettlementReasonV1,
    pub committed_state_root: Option<[u8; 32]>,
    pub future_token_binding_status: CanonicalPipelineFutureTokenBindingStatusV1,
    pub future_token_binding_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineAccountingSummaryV1 {
    pub accounting_policy_version: u32,
    pub payment_intent: CanonicalPipelinePaymentIntentV1,
    pub settlement_intent: CanonicalPipelineSettlementIntentV1,
    pub declared_fee_units: u64,
    pub computed_burn_units: u64,
    pub consumed_burn_units: u64,
    pub burn_record: CanonicalPipelineBurnRecordV1,
    pub settlement_record: CanonicalPipelineSettlementRecordV1,
    pub accounting_consistent_with_burn: bool,
    pub accounting_consistent_with_outcome: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineLedgerAccountsV1 {
    pub material_version: u32,
    pub ordered_accounts: Vec<CanonicalPipelineLedgerAccountV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineLedgerStateCommitmentV1 {
    pub commitment_version: u32,
    pub pre_ledger_state_commitment: [u8; 32],
    pub post_ledger_state_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineLedgerSummaryV1 {
    pub ledger_policy_version: u32,
    pub payer_account_id: [u8; 32],
    pub total_supply: u64,
    pub burned_supply_before: u64,
    pub burned_supply_after: u64,
    pub ledger_account_count: u64,
    pub circulating_supply_before: u64,
    pub circulating_supply_after: u64,
    pub ledger_consistent_with_request: bool,
    pub ledger_consistent_with_burn: bool,
    pub ledger_consistent_with_supply: bool,
    pub ledger_state_commitment: CanonicalPipelineLedgerStateCommitmentV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineGenesisAccountsV1 {
    pub material_version: u32,
    pub ordered_accounts: Vec<LocalAccountV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineTransactionsCommitmentExpansionV1 {
    pub expansion_version: u32,
    pub transactions_commitment: [u8; 32],
    pub ordered_transactions: Vec<TransferTransactionV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineOutcomesCommitmentExpansionV1 {
    pub expansion_version: u32,
    pub outcomes_commitment: [u8; 32],
    pub outcomes: Vec<ExecutionOutcomeV1>,
    pub applied_steps: Vec<AppliedTransferStepV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalPipelineValidityReferenceKindV1 {
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineFeeParametersExpansionV1 {
    pub fee_per_transfer: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineValidityReferenceExpansionV1 {
    pub kind: CanonicalPipelineValidityReferenceKindV1,
    pub none_marker: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineExecutionConstantsExpansionV1 {
    pub transfer_tx_version: u32,
    pub transition_binding_version: u32,
    pub applied_status: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineBatchContextCommitmentExpansionV1 {
    pub expansion_version: u32,
    pub batch_context_commitment: [u8; 32],
    pub transition_binding_version: u32,
    pub system_config: LocalExecutionConfigV1,
    pub fee_parameters: CanonicalPipelineFeeParametersExpansionV1,
    pub validity_reference: CanonicalPipelineValidityReferenceExpansionV1,
    pub execution_constants: CanonicalPipelineExecutionConstantsExpansionV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineFeeSummaryCommitmentExpansionV1 {
    pub expansion_version: u32,
    pub fee_summary_commitment: [u8; 32],
    pub fee_summary: LocalFeeSummaryV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineCommitmentExpansionsV1 {
    pub transactions: CanonicalPipelineTransactionsCommitmentExpansionV1,
    pub outcomes: Option<CanonicalPipelineOutcomesCommitmentExpansionV1>,
    pub batch_context: CanonicalPipelineBatchContextCommitmentExpansionV1,
    pub fee_summary: CanonicalPipelineFeeSummaryCommitmentExpansionV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineStageOutcomesV1 {
    pub execution_status: CanonicalPipelineExecutionStatusV1,
    pub verification_status: CanonicalPipelineVerificationStatusV1,
    pub settlement_status: CanonicalPipelineSettlementStatusV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineStatusExplanationV1 {
    pub truth_artifact_kind: CanonicalPipelineTruthArtifactKindV1,
    pub request_kind: CanonicalPipelineRequestKindV1,
    pub final_status: ScenarioResultV1,
    pub failure_stage: CanonicalPipelineFailureStageV1,
    pub failure_reason_code: CanonicalPipelineFailureReasonCodeV1,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineDecodedPublicInputsV1 {
    pub transition_binding_version: u32,
    pub rollup_id: [u8; 32],
    pub execution_model_version: u32,
    pub batch_version: u32,
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; 32],
    pub tx_count: u64,
    pub fee_summary_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub transactions_commitment: [u8; 32],
    pub outcomes_commitment: [u8; 32],
    pub batch_context_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineRequestSummaryConsistencyAuditV1 {
    pub transition_binding_version_supported: bool,
    pub execution_model_version_supported: bool,
    pub batch_version_supported: bool,
    pub rollup_id_matches_request_audit: bool,
    pub batch_number_matches_request_audit: bool,
    pub tx_count_matches_request_audit: bool,
    pub parent_batch_commitment_matches_request_audit: bool,
    pub fee_summary_commitment_matches_expansion: bool,
    pub pre_state_root_matches_report: bool,
    pub post_state_root_matches_report: bool,
    pub transactions_commitment_matches_expansion: bool,
    pub outcomes_commitment_matches_expansion: bool,
    pub batch_context_commitment_matches_expansion: bool,
    pub decoded_bytes_round_trip: bool,
    pub all_fields_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelinePublicInputsAuditV1 {
    pub decode_status: CanonicalPipelinePublicInputsDecodeStatusV1,
    pub public_input_bytes: [u8; PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1],
    pub public_inputs_hash: [u8; 32],
    pub transition_binding_hash: [u8; 32],
    pub request_summary_consistency: Option<CanonicalPipelineRequestSummaryConsistencyAuditV1>,
    pub decoded_public_inputs: Option<CanonicalPipelineDecodedPublicInputsV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineProofArtifactConsistencyAuditV1 {
    pub public_inputs_hash_matches_report: bool,
    pub prover_kind_matches_proof_system: bool,
    pub proof_version_supported: bool,
    pub proof_binding_input_kind_matches_proof_system: bool,
    pub recomputed_proof_binding_digest: [u8; 32],
    pub proof_binding_digest_matches_recomputed: bool,
    pub all_fields_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineProofArtifactAuditV1 {
    pub prover_kind: u32,
    pub proof_version: u32,
    pub public_inputs_hash: [u8; 32],
    pub trace_digest: [u8; 32],
    pub trace_layout_digest: [u8; 32],
    pub proof_binding_digest: [u8; 32],
    pub proof_binding_input_kind: CanonicalPipelineProofBindingInputKindV1,
    pub proof_binding_input_digest: [u8; 32],
    pub consistency: CanonicalPipelineProofArtifactConsistencyAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalPipelineRequestV1 {
    pipeline_id: String,
    fixture_name: String,
    proof_system: ProofSystemSelectionV1,
    economic: CanonicalPipelineEconomicPolicyV1,
    accounting: CanonicalPipelineAccountingPolicyV1,
    ledger: CanonicalPipelineLedgerPolicyV1,
    head: CanonicalPipelineSettlementHeadRequestV1,
    wallet_binding: CanonicalPipelineWalletBindingV1,
    token_anchor: CanonicalPipelineTokenAnchorV1,
    attestation: Option<CanonicalPipelineAttestationRequestV1>,
    rollup_id: [u8; 32],
    accounts: Vec<LocalAccountV1>,
    batch_number: u64,
    parent_batch_commitment: [u8; 32],
    transactions: Vec<TransferTransactionV1>,
    tamper_public_inputs: Option<ByteTamperFixtureV1>,
    tamper_proof_binding_digest: Option<ByteTamperFixtureV1>,
    expected_result: ScenarioResultV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineReportV1 {
    pub pipeline_schema_version: u32,
    pub pipeline_id: String,
    pub fixture_name: String,
    pub proof_system: ProofSystemSelectionV1,
    pub expected_result: ScenarioResultV1,
    pub actual_result: ScenarioResultV1,
    pub pre_state_root: [u8; 32],
    pub executed_post_state_root: Option<[u8; 32]>,
    pub settlement_committed_state_root: Option<[u8; 32]>,
    pub burn_summary: CanonicalPipelineBurnSummaryV1,
    pub accounting_summary: CanonicalPipelineAccountingSummaryV1,
    pub ledger_summary: CanonicalPipelineLedgerSummaryV1,
    pub head_transition_summary: CanonicalPipelineHeadTransitionSummaryV1,
    pub wallet_binding_summary: CanonicalPipelineWalletBindingSummaryV1,
    pub token_anchor_summary: CanonicalPipelineTokenAnchorSummaryV1,
    pub request_audit: CanonicalPipelineRequestAuditV1,
    pub genesis_accounts: CanonicalPipelineGenesisAccountsV1,
    pub ledger_accounts: CanonicalPipelineLedgerAccountsV1,
    pub commitment_expansions: CanonicalPipelineCommitmentExpansionsV1,
    pub stage_outcomes: CanonicalPipelineStageOutcomesV1,
    pub status_explanation: CanonicalPipelineStatusExplanationV1,
    pub attestation_summary: Option<CanonicalPipelineAttestationSummaryV1>,
    pub attestation_proof_summary: Option<CanonicalPipelineAttestationProofSummaryV1>,
    pub provenance_summary: Option<CanonicalPipelineProvenanceSummaryV1>,
    pub public_inputs: Option<CanonicalPipelinePublicInputsAuditV1>,
    pub proof_artifact: Option<CanonicalPipelineProofArtifactAuditV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisFixtureFileV1 {
    fixture_schema_version: u32,
    fixture_name: String,
    rollup_id_hex: String,
    accounts: Vec<AccountFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioFixtureFileV1 {
    fixture_schema_version: u32,
    fixture_name: String,
    batch_number: u64,
    parent_batch_commitment_hex: String,
    transactions: Vec<TransferFixtureV1>,
    tamper_public_inputs: Option<ByteTamperFixtureV1>,
    tamper_proof_binding_digest: Option<ByteTamperFixtureV1>,
    expected_result: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineRequestFileV1 {
    pipeline_schema_version: u32,
    pipeline_id: String,
    fixture_name: String,
    proof_system: String,
    economic: CanonicalPipelineEconomicPolicyFileV1,
    accounting: CanonicalPipelineAccountingPolicyFileV1,
    ledger: CanonicalPipelineLedgerFileV1,
    head: CanonicalPipelineSettlementHeadFileV1,
    wallet_binding: CanonicalPipelineWalletBindingFileV1,
    token_anchor: CanonicalPipelineTokenAnchorFileV1,
    attestation: Option<CanonicalPipelineAttestationFileV1>,
    genesis: CanonicalPipelineGenesisFileV1,
    batch: CanonicalPipelineBatchFileV1,
    tamper_public_inputs: Option<ByteTamperFixtureV1>,
    tamper_proof_binding_digest: Option<ByteTamperFixtureV1>,
    expected_result: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineGenesisFileV1 {
    rollup_id_hex: String,
    accounts: Vec<AccountFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineEconomicPolicyFileV1 {
    economic_policy_version: u32,
    request_kind: String,
    burn_intent: String,
    declared_fee_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAccountingPolicyFileV1 {
    accounting_policy_version: u32,
    payment_intent: String,
    settlement_intent: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineLedgerFileV1 {
    ledger_policy_version: u32,
    payer_account_id_hex: String,
    total_supply: u64,
    burned_supply: u64,
    accounts: Vec<CanonicalPipelineLedgerAccountFileV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineLedgerAccountFileV1 {
    account_id_hex: String,
    balance: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationFileV1 {
    attestation_schema_version: u32,
    attestation_scope: String,
    attestation_proof_kind: String,
    normalization_policy_version: u32,
    attestation_constraints: CanonicalPipelineAttestationConstraintsFileV1,
    claim: CanonicalPipelineAttestationClaimFileV1,
    evidence_items: Vec<CanonicalPipelineAttestationEvidenceItemFileV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tamper_stark_public_inputs_digest: Option<ByteTamperFixtureV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tamper_stark_proof_bytes: Option<ByteTamperFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationClaimFileV1 {
    claim_kind: String,
    claim_payload: CanonicalPipelineAttestationClaimPayloadFileV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationClaimPayloadFileV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_evidence_root_digest_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_evidence_digest_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_substring_utf8: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field_path: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_value_utf8: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationConstraintsFileV1 {
    require_unique_labels: bool,
    max_evidence_items: u64,
    max_total_normalized_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationEvidenceItemFileV1 {
    label: String,
    evidence_kind: String,
    evidence_payload: CanonicalPipelineAttestationEvidencePayloadFileV1,
    provenance: CanonicalPipelineEvidenceProvenanceFileV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineSettlementHeadFileV1 {
    settlement_head_version: u32,
    previous_head_hash_hex: String,
    head_sequence_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineWalletBindingFileV1 {
    wallet_binding_version: u32,
    account_id_hex: String,
    wallet_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineTokenAnchorFileV1 {
    token_policy_version: u32,
    network_mode: String,
    settlement_anchor_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_balance_reference: Option<CanonicalPipelineExternalBalanceReferenceFileV1>,
    enforce_external_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_external_balance: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineExternalBalanceReferenceFileV1 {
    reference_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_balance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_slot: Option<u64>,
    connected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineEvidenceProvenanceFileV1 {
    provenance_policy_version: u32,
    provenance_type: String,
    source_type: String,
    source_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<CanonicalPipelineEvidenceSignatureFileV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineEvidenceSignatureFileV1 {
    signer_public_key_hex: String,
    signature_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationEvidencePayloadFileV1 {
    payload_utf8: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBatchFileV1 {
    batch_number: u64,
    parent_batch_commitment_hex: String,
    transactions: Vec<TransferFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountFixtureV1 {
    account_id_hex: String,
    balance: u64,
    nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferFixtureV1 {
    sender_account_id_hex: String,
    recipient_account_id_hex: String,
    sender_nonce: u64,
    amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ByteTamperFixtureV1 {
    byte_offset: usize,
    xor_with: u8,
}

impl From<&ByteTamperFixtureV1> for CanonicalPipelineTamperAuditV1 {
    fn from(value: &ByteTamperFixtureV1) -> Self {
        Self {
            byte_offset: value.byte_offset,
            xor_with: value.xor_with,
        }
    }
}

impl From<&CanonicalPipelineTamperAuditV1> for ByteTamperFixtureV1 {
    fn from(value: &CanonicalPipelineTamperAuditV1) -> Self {
        Self {
            byte_offset: value.byte_offset,
            xor_with: value.xor_with,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVectorTamperTargetV1 {
    ProofBytes,
    ProofBindingDigest,
}

impl ProofVectorTamperTargetV1 {
    fn from_str(value: &str) -> Result<Self, LocalChainErrorV1> {
        match value {
            "PROOF_BYTES" => Ok(Self::ProofBytes),
            "PROOF_BINDING_DIGEST" => Ok(Self::ProofBindingDigest),
            _ => Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported proof tamper target: {value}"
            ))),
        }
    }

    fn as_fixture_str(self) -> &'static str {
        match self {
            Self::ProofBytes => "PROOF_BYTES",
            Self::ProofBindingDigest => "PROOF_BINDING_DIGEST",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorTamperV1 {
    pub target: ProofVectorTamperTargetV1,
    pub byte_offset: usize,
    pub xor_with: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorGenesisV1 {
    pub rollup_id: [u8; 32],
    pub accounts: Vec<LocalAccountV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorBatchV1 {
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; 32],
    pub transactions: Vec<TransferTransactionV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorExpectedOutcomeV1 {
    pub tx_index: u64,
    pub sender_account_id: [u8; 32],
    pub consumed_nonce: u64,
    pub fee_charged: u64,
    pub touched_accounts_commitment: [u8; 32],
    pub operation_result_commitment: [u8; 32],
    pub status: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorExpectedTransitionV1 {
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub transactions_commitment: [u8; 32],
    pub outcomes_commitment: [u8; 32],
    pub batch_context_commitment: [u8; 32],
    pub fee_summary_commitment: [u8; 32],
    pub post_state_accounts: Vec<LocalAccountV1>,
    pub outcomes: Vec<ProofVectorExpectedOutcomeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorExpectedPublicInputsV1 {
    pub transition_binding_version: u32,
    pub rollup_id: [u8; 32],
    pub execution_model_version: u32,
    pub batch_version: u32,
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; 32],
    pub tx_count: u64,
    pub fee_summary_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub transactions_commitment: [u8; 32],
    pub outcomes_commitment: [u8; 32],
    pub batch_context_commitment: [u8; 32],
    pub public_input_bytes: [u8; 284],
    pub transition_binding_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorCanonicalStarkArtifactV1 {
    pub prover_kind: u32,
    pub proof_version: u32,
    pub public_inputs_hash: [u8; 32],
    pub trace_digest: [u8; 32],
    pub trace_layout_digest: [u8; 32],
    pub proof_binding_digest: [u8; 32],
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofVectorFixtureV1 {
    pub fixture_name: String,
    pub proof_system: ProofSystemSelectionV1,
    pub genesis: ProofVectorGenesisV1,
    pub batch: ProofVectorBatchV1,
    pub expected_transition: ProofVectorExpectedTransitionV1,
    pub expected_public_inputs: ProofVectorExpectedPublicInputsV1,
    pub canonical_stark_proof_artifact: ProofVectorCanonicalStarkArtifactV1,
    pub proof_tamper: Option<ProofVectorTamperV1>,
    pub expected_result: ScenarioResultV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorFixtureFileV1 {
    fixture_schema_version: u32,
    fixture_name: String,
    proof_system: String,
    genesis: ProofVectorGenesisFileV1,
    batch: ProofVectorBatchFileV1,
    expected_transition: ProofVectorExpectedTransitionFileV1,
    expected_public_inputs: ProofVectorExpectedPublicInputsFileV1,
    canonical_stark_proof_artifact: ProofVectorCanonicalStarkArtifactFileV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_tamper: Option<ProofVectorTamperFileV1>,
    expected_result: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorGenesisFileV1 {
    rollup_id_hex: String,
    accounts: Vec<AccountFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorBatchFileV1 {
    batch_number: u64,
    parent_batch_commitment_hex: String,
    transactions: Vec<TransferFixtureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorExpectedOutcomeFileV1 {
    tx_index: u64,
    sender_account_id_hex: String,
    consumed_nonce: u64,
    fee_charged: u64,
    touched_accounts_commitment_hex: String,
    operation_result_commitment_hex: String,
    status: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorExpectedTransitionFileV1 {
    pre_state_root_hex: String,
    post_state_root_hex: String,
    transactions_commitment_hex: String,
    outcomes_commitment_hex: String,
    batch_context_commitment_hex: String,
    fee_summary_commitment_hex: String,
    post_state_accounts: Vec<AccountFixtureV1>,
    outcomes: Vec<ProofVectorExpectedOutcomeFileV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorExpectedPublicInputsFileV1 {
    transition_binding_version: u32,
    rollup_id_hex: String,
    execution_model_version: u32,
    batch_version: u32,
    batch_number: u64,
    parent_batch_commitment_hex: String,
    tx_count: u64,
    fee_summary_commitment_hex: String,
    pre_state_root_hex: String,
    post_state_root_hex: String,
    transactions_commitment_hex: String,
    outcomes_commitment_hex: String,
    batch_context_commitment_hex: String,
    public_input_bytes_hex: String,
    transition_binding_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorCanonicalStarkArtifactFileV1 {
    prover_kind: u32,
    proof_version: u32,
    public_inputs_hash_hex: String,
    trace_digest_hex: String,
    trace_layout_digest_hex: String,
    proof_binding_digest_hex: String,
    proof_bytes_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorTamperFileV1 {
    target: String,
    byte_offset: usize,
    xor_with: u8,
}

pub fn run_scenario_from_paths<P: AsRef<Path>, Q: AsRef<Path>>(
    genesis_path: P,
    scenario_path: Q,
) -> Result<ScenarioReportV1, LocalChainErrorV1> {
    run_scenario_from_paths_with_proof_system(
        genesis_path,
        scenario_path,
        ProofSystemSelectionV1::Mock,
    )
}

pub fn run_scenario_from_paths_with_proof_system<P: AsRef<Path>, Q: AsRef<Path>>(
    genesis_path: P,
    scenario_path: Q,
    proof_system: ProofSystemSelectionV1,
) -> Result<ScenarioReportV1, LocalChainErrorV1> {
    let genesis = load_genesis_fixture(genesis_path)?;
    let scenario = load_scenario_fixture(scenario_path)?;
    let request =
        CanonicalPipelineRequestV1::from_legacy_fixtures(genesis, scenario, proof_system)?;
    Ok(ScenarioReportV1::from(&run_canonical_pipeline_request(
        &request,
    )?))
}

pub fn run_canonical_pipeline_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<CanonicalPipelineReportV1, LocalChainErrorV1> {
    run_canonical_pipeline_from_path_with_options(path, &CanonicalPipelineRunOptionsV1::default())
}

pub fn run_canonical_pipeline_from_path_with_options<P: AsRef<Path>>(
    path: P,
    options: &CanonicalPipelineRunOptionsV1,
) -> Result<CanonicalPipelineReportV1, LocalChainErrorV1> {
    let request = load_canonical_pipeline_request(path)?;
    run_canonical_pipeline_request_with_options(&request, options)
}

fn run_canonical_pipeline_request(
    request: &CanonicalPipelineRequestV1,
) -> Result<CanonicalPipelineReportV1, LocalChainErrorV1> {
    run_canonical_pipeline_request_with_options(request, &CanonicalPipelineRunOptionsV1::default())
}

fn run_canonical_pipeline_request_with_options(
    request: &CanonicalPipelineRequestV1,
    options: &CanonicalPipelineRunOptionsV1,
) -> Result<CanonicalPipelineReportV1, LocalChainErrorV1> {
    let pre_state = LocalStateV1::new(request.accounts.clone())?;
    let ordered_accounts = pre_state.ordered_accounts();
    validate_canonical_pipeline_request_semantics_v1(request, &ordered_accounts)?;
    let genesis_accounts = canonical_pipeline_genesis_accounts_v1(&ordered_accounts);
    let ledger_accounts = canonical_pipeline_ledger_accounts_v1(request);
    let config = LocalExecutionConfigV1::new(request.rollup_id);
    let batch = BatchExecutionRequestV1 {
        batch_number: request.batch_number,
        parent_batch_commitment: request.parent_batch_commitment,
        transactions: request.transactions.clone(),
    };
    let tx_count = u64::try_from(batch.transactions.len()).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "transaction count exceeds u64 range for canonical pipeline".to_string(),
        )
    })?;
    let genesis_account_count = u64::try_from(ordered_accounts.len()).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "genesis account count exceeds u64 range for canonical pipeline".to_string(),
        )
    })?;
    let ledger_account_count = u64::try_from(request.ledger.accounts.len()).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "ledger account count exceeds u64 range for canonical pipeline".to_string(),
        )
    })?;
    let pre_state_root = pre_state.state_root();
    let request_binding_hash =
        canonical_pipeline_request_binding_hash_v1(request, &ordered_accounts);
    let request_audit = CanonicalPipelineRequestAuditV1 {
        request_binding_hash,
        genesis_accounts_digest: canonical_pipeline_genesis_accounts_digest_v1(&ordered_accounts),
        ledger_accounts_digest: canonical_pipeline_ledger_accounts_digest_v1(
            &request.ledger.accounts,
        ),
        transactions_digest: canonical_pipeline_transactions_digest_v1(&request.transactions),
        rollup_id: request.rollup_id,
        genesis_account_count,
        ledger_account_count,
        ledger_payer_account_id: request.ledger.payer_account_id,
        ledger_total_supply: request.ledger.total_supply,
        ledger_burned_supply: request.ledger.burned_supply,
        batch_number: request.batch_number,
        tx_count,
        parent_batch_commitment: request.parent_batch_commitment,
        tamper_public_inputs: request
            .tamper_public_inputs
            .as_ref()
            .map(CanonicalPipelineTamperAuditV1::from),
        tamper_proof_binding_digest: request
            .tamper_proof_binding_digest
            .as_ref()
            .map(CanonicalPipelineTamperAuditV1::from),
        tamper_attestation_stark_public_inputs_digest: request
            .attestation
            .as_ref()
            .and_then(|attestation| attestation.tamper_stark_public_inputs_digest.as_ref())
            .map(CanonicalPipelineTamperAuditV1::from),
        tamper_attestation_stark_proof_bytes: request
            .attestation
            .as_ref()
            .and_then(|attestation| attestation.tamper_stark_proof_bytes.as_ref())
            .map(CanonicalPipelineTamperAuditV1::from),
    };
    let authority_mode = canonical_pipeline_authority_mode_v1(options);
    let wallet_binding_summary = canonical_pipeline_wallet_binding_summary_v1(request);
    let token_anchor_summary = canonical_pipeline_token_anchor_summary_v1(request);
    let burn_summary = canonical_pipeline_burn_summary_v1(request, &ordered_accounts)?;
    let (burn_record, ledger_summary) =
        canonical_pipeline_ledger_transition_v1(request, &burn_summary, request_binding_hash)?;
    let prepared_attestation = request
        .attestation
        .as_ref()
        .map(canonical_pipeline_prepare_attestation_v1)
        .transpose()?;
    let mut commitment_expansions = CanonicalPipelineCommitmentExpansionsV1 {
        transactions: canonical_pipeline_transactions_commitment_expansion_v1(
            &request.transactions,
        ),
        outcomes: None,
        batch_context: canonical_pipeline_batch_context_commitment_expansion_v1(&config),
        fee_summary: canonical_pipeline_fee_summary_commitment_expansion_v1(
            &LocalFeeSummaryV1::new(tx_count),
        ),
    };
    if canonical_pipeline_pre_execution_rejection_reason_v1(request, prepared_attestation.as_ref())
        .is_some()
    {
        let actual = ScenarioResultV1::ExecutionRejected;
        let (failure_reason_code, detail) = canonical_pipeline_execution_rejection_reason_v1(
            request,
            prepared_attestation.as_ref(),
            None,
        );
        let status_explanation = canonical_pipeline_status_explanation_v1(
            request.economic.request_kind,
            actual,
            failure_reason_code,
            detail,
        );
        let accounting_summary = canonical_pipeline_accounting_summary_v1(
            request,
            &burn_summary,
            &burn_record,
            actual,
            None,
        );
        let attestation_summary = canonical_pipeline_attestation_summary_v1(request, actual)?;
        let attestation_proof_summary = canonical_pipeline_attestation_proof_summary_v1(
            request,
            prepared_attestation.as_ref(),
            None,
            None,
            false,
        )?;
        let report = CanonicalPipelineReportV1 {
            pipeline_schema_version: CANONICAL_PIPELINE_SCHEMA_VERSION_V1,
            pipeline_id: request.pipeline_id.clone(),
            fixture_name: request.fixture_name.clone(),
            proof_system: request.proof_system,
            expected_result: request.expected_result,
            actual_result: actual,
            pre_state_root,
            executed_post_state_root: None,
            settlement_committed_state_root: None,
            burn_summary,
            accounting_summary,
            ledger_summary,
            head_transition_summary: canonical_pipeline_placeholder_head_transition_summary_v1(
                request,
                authority_mode,
                request_binding_hash,
            ),
            wallet_binding_summary,
            token_anchor_summary,
            request_audit,
            genesis_accounts,
            ledger_accounts,
            commitment_expansions,
            stage_outcomes: stage_outcomes_for_actual_result_v1(actual),
            status_explanation,
            attestation_summary,
            attestation_proof_summary,
            provenance_summary: prepared_attestation
                .as_ref()
                .map(|prepared| prepared.provenance_summary.clone()),
            public_inputs: None,
            proof_artifact: None,
        };
        return finalize_canonical_pipeline_report_v1(
            request,
            options,
            &burn_record,
            prepared_attestation.as_ref(),
            report,
        );
    }
    let executed = match execute_transfer_batch_v1(&pre_state, &config, &batch) {
        Ok(executed) => executed,
        Err(error) => {
            let actual = ScenarioResultV1::ExecutionRejected;
            let (failure_reason_code, detail) = canonical_pipeline_execution_rejection_reason_v1(
                request,
                prepared_attestation.as_ref(),
                Some(&error),
            );
            let status_explanation = canonical_pipeline_status_explanation_v1(
                request.economic.request_kind,
                actual,
                failure_reason_code,
                detail,
            );
            let accounting_summary = canonical_pipeline_accounting_summary_v1(
                request,
                &burn_summary,
                &burn_record,
                actual,
                None,
            );
            let attestation_summary = canonical_pipeline_attestation_summary_v1(request, actual)?;
            let attestation_proof_summary = canonical_pipeline_attestation_proof_summary_v1(
                request,
                prepared_attestation.as_ref(),
                None,
                None,
                false,
            )?;
            let report = CanonicalPipelineReportV1 {
                pipeline_schema_version: CANONICAL_PIPELINE_SCHEMA_VERSION_V1,
                pipeline_id: request.pipeline_id.clone(),
                fixture_name: request.fixture_name.clone(),
                proof_system: request.proof_system,
                expected_result: request.expected_result,
                actual_result: actual,
                pre_state_root,
                executed_post_state_root: None,
                settlement_committed_state_root: None,
                burn_summary,
                accounting_summary,
                ledger_summary,
                head_transition_summary: canonical_pipeline_placeholder_head_transition_summary_v1(
                    request,
                    authority_mode,
                    request_binding_hash,
                ),
                wallet_binding_summary,
                token_anchor_summary,
                request_audit,
                genesis_accounts,
                ledger_accounts,
                commitment_expansions,
                stage_outcomes: stage_outcomes_for_actual_result_v1(actual),
                status_explanation,
                attestation_summary,
                attestation_proof_summary,
                provenance_summary: prepared_attestation
                    .as_ref()
                    .map(|prepared| prepared.provenance_summary.clone()),
                public_inputs: None,
                proof_artifact: None,
            };
            return finalize_canonical_pipeline_report_v1(
                request,
                options,
                &burn_record,
                prepared_attestation.as_ref(),
                report,
            );
        }
    };
    let executed_post_state_root = executed.post_state_root;
    commitment_expansions.outcomes = Some(canonical_pipeline_outcomes_commitment_expansion_v1(
        &executed,
    ));
    commitment_expansions.fee_summary =
        canonical_pipeline_fee_summary_commitment_expansion_v1(&executed.fee_summary);

    let envelope = TransitionEnvelopeV1::from_executed_batch(&executed);
    let mut public_input_bytes = envelope.encode_bytes();
    let mut proof = match request.proof_system {
        ProofSystemSelectionV1::Mock => {
            LocalProofArtifactV1::Mock(prove_executed_batch_with_mock_prover_v1(&executed)?)
        }
        ProofSystemSelectionV1::Stark => {
            LocalProofArtifactV1::Stark(prove_executed_batch_with_stark_prover_v1(&executed)?)
        }
    };

    if let Some(tamper) = &request.tamper_public_inputs {
        let byte = public_input_bytes
            .get_mut(tamper.byte_offset)
            .ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(format!(
                    "public-input tamper offset {} out of range",
                    tamper.byte_offset
                ))
            })?;
        *byte ^= tamper.xor_with;
    }
    if let Some(tamper) = &request.tamper_proof_binding_digest {
        match &mut proof {
            LocalProofArtifactV1::Mock(mock) => {
                let byte = mock
                    .proof_binding_digest
                    .get_mut(tamper.byte_offset)
                    .ok_or_else(|| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "mock proof_binding_digest tamper offset {} out of range",
                            tamper.byte_offset
                        ))
                    })?;
                *byte ^= tamper.xor_with;
            }
            LocalProofArtifactV1::Stark(stark) => {
                let byte = stark
                    .proof_binding_digest
                    .get_mut(tamper.byte_offset)
                    .ok_or_else(|| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "stark proof_binding_digest tamper offset {} out of range",
                            tamper.byte_offset
                        ))
                    })?;
                *byte ^= tamper.xor_with;
            }
        }
    }

    let mut public_inputs =
        CanonicalPipelinePublicInputsAuditV1::from_public_input_bytes(public_input_bytes);
    public_inputs.request_summary_consistency =
        canonical_pipeline_request_summary_consistency_audit_v1(
            &public_inputs,
            &request_audit,
            &commitment_expansions,
            pre_state_root,
            executed_post_state_root,
        );
    let verification_result = verify_proof_artifact_v1(&public_input_bytes, &proof);
    let (
        attestation_stark_material,
        attestation_stark_public_inputs_digest,
        attestation_stark_error,
    ) = if let (Some(attestation), Some(prepared)) =
        (request.attestation.as_ref(), prepared_attestation.as_ref())
    {
        if attestation.attestation_proof_kind == CanonicalPipelineAttestationProofKindV1::Stark {
            let mut material = canonical_pipeline_build_attestation_stark_material_v1(prepared)?;
            let mut public_inputs_digest = material.public_inputs_digest;
            if let Some(tamper) = &attestation.tamper_stark_public_inputs_digest {
                let byte = public_inputs_digest
                    .get_mut(tamper.byte_offset)
                    .ok_or_else(|| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "attestation stark public_inputs_digest tamper offset {} out of range",
                            tamper.byte_offset
                        ))
                    })?;
                *byte ^= tamper.xor_with;
            }
            if let Some(tamper) = &attestation.tamper_stark_proof_bytes {
                let byte = material
                    .proof_artifact
                    .proof_bytes
                    .get_mut(tamper.byte_offset)
                    .ok_or_else(|| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "attestation stark proof_bytes tamper offset {} out of range",
                            tamper.byte_offset
                        ))
                    })?;
                *byte ^= tamper.xor_with;
            }
            let attestation_error = if public_inputs_digest
                != derive_dcm_air_stark_public_input_digest_v1(&material.public_inputs)
            {
                Some("attestation stark public inputs digest mismatch".to_string())
            } else {
                verify_dcm_air_real_stark_v1(&material.public_inputs, &material.proof_artifact)
                    .err()
                    .map(|error| error.to_string())
            };
            (
                Some(material),
                Some(public_inputs_digest),
                attestation_error,
            )
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    let (actual_result, settlement_committed_state_root, failure_reason_code, failure_detail) =
        if let Some(attestation_error) = attestation_stark_error.as_ref() {
            (
                ScenarioResultV1::VerificationRejected,
                None,
                CanonicalPipelineFailureReasonCodeV1::AttestationProofVerificationRejected,
                attestation_error.clone(),
            )
        } else if let Err(verification_error) = verification_result.as_ref() {
            (
                ScenarioResultV1::VerificationRejected,
                None,
                CanonicalPipelineFailureReasonCodeV1::VerificationLayerMismatch,
                verification_error.to_string(),
            )
        } else {
            let mut settlement = LocalSettlementStateV1::new(request.rollup_id, pre_state_root);
            match accept_transition_v1(&mut settlement, &public_input_bytes, &proof) {
                Ok(accepted) => {
                    if let Some((failure_reason_code, failure_detail)) =
                        canonical_pipeline_settlement_override_v1(request, &token_anchor_summary)
                    {
                        (
                            ScenarioResultV1::SettlementRejected,
                            None,
                            failure_reason_code,
                            failure_detail,
                        )
                    } else {
                        (
                            ScenarioResultV1::Accepted,
                            Some(accepted.new_state_root),
                            CanonicalPipelineFailureReasonCodeV1::None,
                            "canonical report accepted and locally committed".to_string(),
                        )
                    }
                }
                Err(error) => (
                    ScenarioResultV1::SettlementRejected,
                    None,
                    CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected,
                    error.to_string(),
                ),
            }
        };
    let mut proof_artifact = CanonicalPipelineProofArtifactAuditV1::from_proof_artifact(&proof);
    proof_artifact.consistency = canonical_pipeline_proof_artifact_consistency_audit_v1(
        &proof_artifact,
        public_inputs.public_inputs_hash,
        request.proof_system,
    )?;
    let status_explanation = canonical_pipeline_status_explanation_v1(
        request.economic.request_kind,
        actual_result,
        failure_reason_code,
        failure_detail,
    );
    let accounting_summary = canonical_pipeline_accounting_summary_v1(
        request,
        &burn_summary,
        &burn_record,
        actual_result,
        settlement_committed_state_root,
    );
    let attestation_summary = canonical_pipeline_attestation_summary_v1(request, actual_result)?;
    let attestation_proof_summary = canonical_pipeline_attestation_proof_summary_v1(
        request,
        prepared_attestation.as_ref(),
        attestation_stark_material.as_ref(),
        attestation_stark_public_inputs_digest,
        attestation_stark_error.is_none()
            && request.attestation.as_ref().is_some_and(|attestation| {
                attestation.attestation_proof_kind == CanonicalPipelineAttestationProofKindV1::Mock
                    || attestation.attestation_proof_kind
                        == CanonicalPipelineAttestationProofKindV1::Stark
            }),
    )?;

    let report = CanonicalPipelineReportV1 {
        pipeline_schema_version: CANONICAL_PIPELINE_SCHEMA_VERSION_V1,
        pipeline_id: request.pipeline_id.clone(),
        fixture_name: request.fixture_name.clone(),
        proof_system: request.proof_system,
        expected_result: request.expected_result,
        actual_result,
        pre_state_root,
        executed_post_state_root: Some(executed_post_state_root),
        settlement_committed_state_root,
        burn_summary,
        accounting_summary,
        ledger_summary,
        head_transition_summary: canonical_pipeline_placeholder_head_transition_summary_v1(
            request,
            authority_mode,
            request_binding_hash,
        ),
        wallet_binding_summary,
        token_anchor_summary,
        request_audit,
        genesis_accounts,
        ledger_accounts,
        commitment_expansions,
        stage_outcomes: stage_outcomes_for_actual_result_v1(actual_result),
        status_explanation,
        attestation_summary,
        attestation_proof_summary,
        provenance_summary: prepared_attestation
            .as_ref()
            .map(|prepared| prepared.provenance_summary.clone()),
        public_inputs: Some(public_inputs),
        proof_artifact: Some(proof_artifact),
    };
    finalize_canonical_pipeline_report_v1(
        request,
        options,
        &burn_record,
        prepared_attestation.as_ref(),
        report,
    )
}

pub fn load_proof_vector_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<ProofVectorFixtureV1, LocalChainErrorV1> {
    let bytes = fs::read(path)?;
    let file: ProofVectorFixtureFileV1 = serde_json::from_slice(&bytes)?;
    ProofVectorFixtureV1::from_file(file)
}

pub fn write_proof_vector_to_path<P: AsRef<Path>>(
    path: P,
    fixture: &ProofVectorFixtureV1,
) -> Result<(), LocalChainErrorV1> {
    validate_loaded_proof_vector(fixture)?;
    let file = fixture.to_file();
    let bytes = serde_json::to_vec_pretty(&file)?;
    fs::write(path, bytes)?;
    Ok(())
}

pub fn build_proof_vector_from_paths_with_proof_system<P: AsRef<Path>, Q: AsRef<Path>>(
    genesis_path: P,
    scenario_path: Q,
    proof_system: ProofSystemSelectionV1,
) -> Result<ProofVectorFixtureV1, LocalChainErrorV1> {
    let genesis = load_genesis_fixture(genesis_path)?;
    let scenario = load_scenario_fixture(scenario_path)?;
    build_proof_vector_from_fixtures(genesis, scenario, proof_system)
}

pub fn build_and_write_proof_vector_from_paths_with_proof_system<
    P: AsRef<Path>,
    Q: AsRef<Path>,
    R: AsRef<Path>,
>(
    genesis_path: P,
    scenario_path: Q,
    output_path: R,
    proof_system: ProofSystemSelectionV1,
) -> Result<ProofVectorFixtureV1, LocalChainErrorV1> {
    let fixture =
        build_proof_vector_from_paths_with_proof_system(genesis_path, scenario_path, proof_system)?;
    write_proof_vector_to_path(output_path, &fixture)?;
    Ok(fixture)
}

pub fn run_proof_vector_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<ProofVectorReportV1, LocalChainErrorV1> {
    let fixture = load_proof_vector_from_path(path)?;
    let prepared = prepare_proof_vector_runtime(&fixture)?;
    let canonical_proof = match fixture.proof_system {
        ProofSystemSelectionV1::Stark => {
            prove_executed_batch_with_stark_prover_v1(&prepared.executed)?
        }
        ProofSystemSelectionV1::Mock => {
            return Err(LocalChainErrorV1::InvalidFixture(
                "proof vectors currently support only STARK-backed fixtures".to_string(),
            ))
        }
    };

    assert_stark_artifact_matches_expected(
        &canonical_proof,
        &fixture.canonical_stark_proof_artifact,
    )?;

    let final_proof = apply_proof_vector_tamper(canonical_proof, fixture.proof_tamper.as_ref())?;
    finalize_proof_vector_report(
        &fixture,
        &prepared.public_input_bytes,
        prepared.pre_state_root,
        final_proof,
    )
}

pub fn verify_proof_vector_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<ProofVectorReportV1, LocalChainErrorV1> {
    let fixture = load_proof_vector_from_path(path)?;
    let prepared = prepare_proof_vector_runtime(&fixture)?;
    let canonical_proof = fixture.canonical_stark_proof_artifact.to_runtime_artifact();
    let final_proof = apply_proof_vector_tamper(canonical_proof, fixture.proof_tamper.as_ref())?;
    finalize_proof_vector_report(
        &fixture,
        &prepared.public_input_bytes,
        prepared.pre_state_root,
        final_proof,
    )
}

impl From<&CanonicalPipelineReportV1> for ScenarioReportV1 {
    fn from(value: &CanonicalPipelineReportV1) -> Self {
        Self {
            fixture_name: value.fixture_name.clone(),
            expected_result: value.expected_result,
            actual_result: value.actual_result,
            pre_state_root: value.pre_state_root,
            post_state_root: value.executed_post_state_root,
            transition_binding_hash: value
                .public_inputs
                .as_ref()
                .map(|audit| audit.transition_binding_hash),
        }
    }
}

impl CanonicalPipelineRequestV1 {
    fn from_legacy_fixtures(
        genesis: GenesisFixtureFileV1,
        scenario: ScenarioFixtureFileV1,
        proof_system: ProofSystemSelectionV1,
    ) -> Result<Self, LocalChainErrorV1> {
        let accounts = genesis
            .accounts
            .iter()
            .map(parse_account_fixture)
            .collect::<Result<Vec<_>, _>>()?;
        let transactions = scenario
            .transactions
            .iter()
            .map(parse_transfer_fixture)
            .collect::<Result<Vec<_>, _>>()?;
        let request_kind = if transactions.is_empty() {
            CanonicalPipelineRequestKindV1::Attestation
        } else {
            CanonicalPipelineRequestKindV1::Execution
        };
        let ordered_accounts = LocalStateV1::new(accounts.clone())?.ordered_accounts();
        let ledger = canonical_pipeline_default_ledger_policy_v1(&ordered_accounts)?;
        let wallet_binding = canonical_pipeline_default_wallet_binding_v1(&ledger)?;
        let mut request = Self {
            pipeline_id: CANONICAL_PIPELINE_ID_V1.to_string(),
            fixture_name: scenario.fixture_name.clone(),
            proof_system,
            economic: CanonicalPipelineEconomicPolicyV1 {
                economic_policy_version: CANONICAL_PIPELINE_ECONOMIC_POLICY_VERSION_V1,
                request_kind,
                burn_intent: CanonicalPipelineBurnIntentV1::CanonicalReport,
                declared_fee_units: 0,
            },
            accounting: CanonicalPipelineAccountingPolicyV1 {
                accounting_policy_version: CANONICAL_PIPELINE_ACCOUNTING_POLICY_VERSION_V1,
                payment_intent: CanonicalPipelinePaymentIntentV1::BurnToProduceCanonicalTruth,
                settlement_intent: CanonicalPipelineSettlementIntentV1::RecordCanonicalOutcome,
            },
            ledger,
            head: CanonicalPipelineSettlementHeadRequestV1 {
                settlement_head_version: CANONICAL_PIPELINE_SETTLEMENT_HEAD_VERSION_V1,
                previous_head_hash: CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V1,
                head_sequence_number: 1,
            },
            wallet_binding,
            token_anchor: canonical_pipeline_default_token_anchor_v1(),
            attestation: None,
            rollup_id: decode_hex_32_field(&genesis.rollup_id_hex, "genesis.rollup_id_hex")?,
            accounts,
            batch_number: scenario.batch_number,
            parent_batch_commitment: decode_hex_32_field(
                &scenario.parent_batch_commitment_hex,
                "scenario.parent_batch_commitment_hex",
            )?,
            transactions,
            tamper_public_inputs: scenario.tamper_public_inputs.clone(),
            tamper_proof_binding_digest: scenario.tamper_proof_binding_digest.clone(),
            expected_result: ScenarioResultV1::from_str(&scenario.expected_result)?,
        };
        request.economic.declared_fee_units =
            compute_canonical_pipeline_burn_units_v1(&request, &ordered_accounts)?;
        validate_canonical_pipeline_request_semantics_v1(&request, &ordered_accounts)?;
        Ok(request)
    }

    fn from_file(file: CanonicalPipelineRequestFileV1) -> Result<Self, LocalChainErrorV1> {
        if file.pipeline_schema_version != CANONICAL_PIPELINE_SCHEMA_VERSION_V1 {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline schema version: expected {}, got {}",
                CANONICAL_PIPELINE_SCHEMA_VERSION_V1, file.pipeline_schema_version
            )));
        }
        if file.pipeline_id != CANONICAL_PIPELINE_ID_V1 {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline id: {}",
                file.pipeline_id
            )));
        }
        if file.fixture_name.trim().is_empty() {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline fixture_name must not be empty".to_string(),
            ));
        }
        if let Some(tamper) = &file.tamper_public_inputs {
            validate_byte_tamper_offset(
                tamper.byte_offset,
                PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1,
                "public-input",
                "284-byte schema",
            )?;
        }
        if let Some(tamper) = &file.tamper_proof_binding_digest {
            validate_byte_tamper_offset(
                tamper.byte_offset,
                PROOF_BINDING_DIGEST_LEN_V1,
                "proof_binding_digest",
                "32-byte digest",
            )?;
        }
        if let Some(attestation) = &file.attestation {
            if let Some(tamper) = &attestation.tamper_stark_public_inputs_digest {
                validate_byte_tamper_offset(
                    tamper.byte_offset,
                    DCM_HASH_LEN_V1,
                    "attestation_stark_public_inputs_digest",
                    "32-byte digest",
                )?;
            }
        }

        let accounts = file
            .genesis
            .accounts
            .iter()
            .map(parse_account_fixture)
            .collect::<Result<Vec<_>, _>>()?;
        let transactions = file
            .batch
            .transactions
            .iter()
            .map(parse_transfer_fixture)
            .collect::<Result<Vec<_>, _>>()?;
        let request = Self {
            pipeline_id: file.pipeline_id,
            fixture_name: file.fixture_name,
            proof_system: ProofSystemSelectionV1::from_str(&file.proof_system)?,
            economic: CanonicalPipelineEconomicPolicyV1 {
                economic_policy_version: file.economic.economic_policy_version,
                request_kind: CanonicalPipelineRequestKindV1::from_str(
                    &file.economic.request_kind,
                )?,
                burn_intent: CanonicalPipelineBurnIntentV1::from_str(&file.economic.burn_intent)?,
                declared_fee_units: file.economic.declared_fee_units,
            },
            accounting: CanonicalPipelineAccountingPolicyV1 {
                accounting_policy_version: file.accounting.accounting_policy_version,
                payment_intent: CanonicalPipelinePaymentIntentV1::from_str(
                    &file.accounting.payment_intent,
                )?,
                settlement_intent: CanonicalPipelineSettlementIntentV1::from_str(
                    &file.accounting.settlement_intent,
                )?,
            },
            ledger: parse_canonical_pipeline_ledger_file_v1(file.ledger)?,
            head: parse_canonical_pipeline_head_file_v1(file.head)?,
            wallet_binding: parse_canonical_pipeline_wallet_binding_file_v1(file.wallet_binding)?,
            token_anchor: parse_canonical_pipeline_token_anchor_file_v1(file.token_anchor)?,
            attestation: file
                .attestation
                .map(parse_canonical_pipeline_attestation_file_v1)
                .transpose()?,
            rollup_id: decode_hex_32_field(
                &file.genesis.rollup_id_hex,
                "canonical_pipeline.genesis.rollup_id_hex",
            )?,
            accounts,
            batch_number: file.batch.batch_number,
            parent_batch_commitment: decode_hex_32_field(
                &file.batch.parent_batch_commitment_hex,
                "canonical_pipeline.batch.parent_batch_commitment_hex",
            )?,
            transactions,
            tamper_public_inputs: file.tamper_public_inputs,
            tamper_proof_binding_digest: file.tamper_proof_binding_digest,
            expected_result: ScenarioResultV1::from_str(&file.expected_result)?,
        };
        let ordered_accounts = LocalStateV1::new(request.accounts.clone())?.ordered_accounts();
        validate_canonical_pipeline_request_semantics_v1(&request, &ordered_accounts)?;
        Ok(request)
    }
}

fn parse_canonical_pipeline_attestation_file_v1(
    value: CanonicalPipelineAttestationFileV1,
) -> Result<CanonicalPipelineAttestationRequestV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineAttestationRequestV1 {
        attestation_schema_version: value.attestation_schema_version,
        attestation_scope: CanonicalPipelineAttestationScopeV1::from_str(&value.attestation_scope)?,
        attestation_proof_kind: CanonicalPipelineAttestationProofKindV1::from_str(
            &value.attestation_proof_kind,
        )?,
        normalization_policy_version: value.normalization_policy_version,
        attestation_constraints: CanonicalPipelineAttestationConstraintsV1 {
            require_unique_labels: value.attestation_constraints.require_unique_labels,
            max_evidence_items: value.attestation_constraints.max_evidence_items,
            max_total_normalized_bytes: value.attestation_constraints.max_total_normalized_bytes,
        },
        claim: parse_canonical_pipeline_attestation_claim_file_v1(value.claim)?,
        evidence_items: value
            .evidence_items
            .into_iter()
            .map(parse_canonical_pipeline_attestation_evidence_item_file_v1)
            .collect::<Result<Vec<_>, LocalChainErrorV1>>()?,
        tamper_stark_public_inputs_digest: value.tamper_stark_public_inputs_digest,
        tamper_stark_proof_bytes: value.tamper_stark_proof_bytes,
    })
}

fn parse_canonical_pipeline_head_file_v1(
    value: CanonicalPipelineSettlementHeadFileV1,
) -> Result<CanonicalPipelineSettlementHeadRequestV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineSettlementHeadRequestV1 {
        settlement_head_version: value.settlement_head_version,
        previous_head_hash: decode_hex_32_field(
            &value.previous_head_hash_hex,
            "canonical_pipeline.head.previous_head_hash_hex",
        )?,
        head_sequence_number: value.head_sequence_number,
    })
}

fn parse_canonical_pipeline_wallet_binding_file_v1(
    value: CanonicalPipelineWalletBindingFileV1,
) -> Result<CanonicalPipelineWalletBindingV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineWalletBindingV1 {
        wallet_binding_version: value.wallet_binding_version,
        account_id: decode_hex_32_field(
            &value.account_id_hex,
            "canonical_pipeline.wallet_binding.account_id_hex",
        )?,
        wallet_address: value.wallet_address,
    })
}

fn parse_canonical_pipeline_external_balance_reference_file_v1(
    value: CanonicalPipelineExternalBalanceReferenceFileV1,
) -> Result<CanonicalPipelineExternalBalanceReferenceV1, LocalChainErrorV1> {
    if value.reference_id.trim().is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline token_anchor.external_balance_reference.reference_id must not be empty"
                .to_string(),
        ));
    }
    Ok(CanonicalPipelineExternalBalanceReferenceV1 {
        reference_id: value.reference_id,
        observed_balance: value.observed_balance,
        observed_slot: value.observed_slot,
        connected: value.connected,
    })
}

fn parse_canonical_pipeline_token_anchor_file_v1(
    value: CanonicalPipelineTokenAnchorFileV1,
) -> Result<CanonicalPipelineTokenAnchorV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineTokenAnchorV1 {
        token_policy_version: value.token_policy_version,
        network_mode: CanonicalPipelineNetworkModeV1::from_str(&value.network_mode)?,
        settlement_anchor_type: CanonicalPipelineSettlementAnchorTypeV1::from_str(
            &value.settlement_anchor_type,
        )?,
        external_balance_reference: value
            .external_balance_reference
            .map(parse_canonical_pipeline_external_balance_reference_file_v1)
            .transpose()?,
        enforce_external_match: value.enforce_external_match,
        expected_external_balance: value.expected_external_balance,
    })
}

fn parse_canonical_pipeline_evidence_signature_file_v1(
    value: CanonicalPipelineEvidenceSignatureFileV1,
) -> Result<CanonicalPipelineEvidenceSignatureV1, LocalChainErrorV1> {
    let signer_public_key = decode_hex_32_field(
        &value.signer_public_key_hex,
        "canonical_pipeline.attestation.evidence_items[].provenance.signature.signer_public_key_hex",
    )?;
    let signature_bytes = decode_hex_vec_v1(
        &value.signature_hex,
        "canonical_pipeline.attestation.evidence_items[].provenance.signature.signature_hex",
    )?;
    let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline provenance signature_hex must decode to 64 bytes".to_string(),
        )
    })?;
    Ok(CanonicalPipelineEvidenceSignatureV1 {
        signer_public_key,
        signature,
    })
}

fn parse_canonical_pipeline_evidence_provenance_file_v1(
    value: CanonicalPipelineEvidenceProvenanceFileV1,
) -> Result<CanonicalPipelineEvidenceProvenanceV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineEvidenceProvenanceV1 {
        provenance_policy_version: value.provenance_policy_version,
        provenance_type: CanonicalPipelineEvidenceProvenanceTypeV1::from_str(
            &value.provenance_type,
        )?,
        source_type: value.source_type,
        source_identifier: value.source_identifier,
        signature: value
            .signature
            .map(parse_canonical_pipeline_evidence_signature_file_v1)
            .transpose()?,
        timestamp_unix_seconds: value.timestamp_unix_seconds,
    })
}

fn parse_canonical_pipeline_attestation_claim_file_v1(
    value: CanonicalPipelineAttestationClaimFileV1,
) -> Result<CanonicalPipelineAttestationClaimV1, LocalChainErrorV1> {
    let claim_kind = CanonicalPipelineAttestationClaimKindV1::from_str(&value.claim_kind)?;
    let claim_payload = match claim_kind {
        CanonicalPipelineAttestationClaimKindV1::EvidenceRootDigest => {
            let expected = value
                .claim_payload
                .expected_evidence_root_digest_hex
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.expected_evidence_root_digest_hex is required for claim_kind evidence_root_digest"
                            .to_string(),
                    )
                })?;
            if value.claim_payload.target_label.is_some()
                || value.claim_payload.expected_evidence_digest_hex.is_some()
                || value.claim_payload.expected_substring_utf8.is_some()
                || value.claim_payload.field_path.is_some()
                || value.claim_payload.expected_value_utf8.is_some()
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation.claim.claim_payload has unsupported fields for claim_kind evidence_root_digest"
                        .to_string(),
                ));
            }
            CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest {
                expected_evidence_root_digest: decode_hex_32_field(
                    &expected,
                    "canonical_pipeline.attestation.claim.claim_payload.expected_evidence_root_digest_hex",
                )?,
            }
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedEvidenceDigest => {
            let target_label = value
                .claim_payload
                .target_label
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.target_label is required for claim_kind normalized_evidence_digest"
                            .to_string(),
                    )
                })?;
            let expected = value
                .claim_payload
                .expected_evidence_digest_hex
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.expected_evidence_digest_hex is required for claim_kind normalized_evidence_digest"
                            .to_string(),
                    )
                })?;
            if value
                .claim_payload
                .expected_evidence_root_digest_hex
                .is_some()
                || value.claim_payload.expected_substring_utf8.is_some()
                || value.claim_payload.field_path.is_some()
                || value.claim_payload.expected_value_utf8.is_some()
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation.claim.claim_payload has unsupported fields for claim_kind normalized_evidence_digest"
                        .to_string(),
                ));
            }
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
                target_label,
                expected_evidence_digest: decode_hex_32_field(
                    &expected,
                    "canonical_pipeline.attestation.claim.claim_payload.expected_evidence_digest_hex",
                )?,
            }
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedTextContainsUtf8 => {
            let target_label = value
                .claim_payload
                .target_label
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.target_label is required for claim_kind normalized_text_contains_utf8"
                            .to_string(),
                    )
                })?;
            let expected_substring_utf8 = value
                .claim_payload
                .expected_substring_utf8
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.expected_substring_utf8 is required for claim_kind normalized_text_contains_utf8"
                            .to_string(),
                    )
                })?;
            if value
                .claim_payload
                .expected_evidence_root_digest_hex
                .is_some()
                || value.claim_payload.expected_evidence_digest_hex.is_some()
                || value.claim_payload.field_path.is_some()
                || value.claim_payload.expected_value_utf8.is_some()
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation.claim.claim_payload has unsupported fields for claim_kind normalized_text_contains_utf8"
                        .to_string(),
                ));
            }
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
                target_label,
                expected_substring_utf8,
            }
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedJsonFieldEqualsUtf8 => {
            let target_label = value
                .claim_payload
                .target_label
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.target_label is required for claim_kind normalized_json_field_equals_utf8"
                            .to_string(),
                    )
                })?;
            let field_path = value.claim_payload.field_path.ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation.claim.claim_payload.field_path is required for claim_kind normalized_json_field_equals_utf8"
                        .to_string(),
                )
            })?;
            let expected_value_utf8 = value
                .claim_payload
                .expected_value_utf8
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation.claim.claim_payload.expected_value_utf8 is required for claim_kind normalized_json_field_equals_utf8"
                            .to_string(),
                    )
                })?;
            if value
                .claim_payload
                .expected_evidence_root_digest_hex
                .is_some()
                || value.claim_payload.expected_evidence_digest_hex.is_some()
                || value.claim_payload.expected_substring_utf8.is_some()
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation.claim.claim_payload has unsupported fields for claim_kind normalized_json_field_equals_utf8"
                        .to_string(),
                ));
            }
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
                target_label,
                field_path,
                expected_value_utf8,
            }
        }
    };
    Ok(CanonicalPipelineAttestationClaimV1 {
        claim_kind,
        claim_payload,
    })
}

fn parse_canonical_pipeline_attestation_evidence_item_file_v1(
    item: CanonicalPipelineAttestationEvidenceItemFileV1,
) -> Result<CanonicalPipelineAttestationEvidenceItemV1, LocalChainErrorV1> {
    let evidence_kind = CanonicalPipelineAttestationEvidenceKindV1::from_str(&item.evidence_kind)?;
    let evidence_payload = match evidence_kind {
        CanonicalPipelineAttestationEvidenceKindV1::InlineUtf8 => {
            CanonicalPipelineAttestationEvidencePayloadV1::InlineUtf8 {
                payload_utf8: item.evidence_payload.payload_utf8,
            }
        }
        CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8 => {
            CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 {
                payload_utf8: item.evidence_payload.payload_utf8,
            }
        }
    };
    Ok(CanonicalPipelineAttestationEvidenceItemV1 {
        label: item.label,
        evidence_kind,
        evidence_payload,
        provenance: parse_canonical_pipeline_evidence_provenance_file_v1(item.provenance)?,
    })
}

fn canonical_pipeline_default_ledger_policy_v1(
    ordered_accounts: &[LocalAccountV1],
) -> Result<CanonicalPipelineLedgerPolicyV1, LocalChainErrorV1> {
    let payer_account_id = ordered_accounts
        .first()
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline legacy fixture synthesis requires at least one genesis account"
                    .to_string(),
            )
        })?
        .account_id;
    let accounts = ordered_accounts
        .iter()
        .map(|account| CanonicalPipelineLedgerAccountV1 {
            account_id: account.account_id,
            balance: account.balance,
        })
        .collect::<Vec<_>>();
    Ok(CanonicalPipelineLedgerPolicyV1 {
        ledger_policy_version: CANONICAL_PIPELINE_LEDGER_POLICY_VERSION_V1,
        payer_account_id,
        total_supply: canonical_pipeline_ledger_total_balance_v1(&accounts)?,
        burned_supply: 0,
        accounts,
    })
}

fn canonical_pipeline_default_wallet_binding_v1(
    ledger: &CanonicalPipelineLedgerPolicyV1,
) -> Result<CanonicalPipelineWalletBindingV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineWalletBindingV1 {
        wallet_binding_version: CANONICAL_PIPELINE_WALLET_BINDING_VERSION_V1,
        account_id: ledger.payer_account_id,
        wallet_address: encode_base58_like_wallet_v1(&ledger.payer_account_id),
    })
}

fn canonical_pipeline_default_token_anchor_v1() -> CanonicalPipelineTokenAnchorV1 {
    CanonicalPipelineTokenAnchorV1 {
        token_policy_version: CANONICAL_PIPELINE_TOKEN_POLICY_VERSION_V1,
        network_mode: CanonicalPipelineNetworkModeV1::Local,
        settlement_anchor_type: CanonicalPipelineSettlementAnchorTypeV1::Local,
        external_balance_reference: None,
        enforce_external_match: false,
        expected_external_balance: None,
    }
}

fn parse_canonical_pipeline_ledger_file_v1(
    value: CanonicalPipelineLedgerFileV1,
) -> Result<CanonicalPipelineLedgerPolicyV1, LocalChainErrorV1> {
    Ok(CanonicalPipelineLedgerPolicyV1 {
        ledger_policy_version: value.ledger_policy_version,
        payer_account_id: decode_hex_32_field(
            &value.payer_account_id_hex,
            "canonical_pipeline.ledger.payer_account_id_hex",
        )?,
        total_supply: value.total_supply,
        burned_supply: value.burned_supply,
        accounts: value
            .accounts
            .into_iter()
            .enumerate()
            .map(|(index, account)| {
                Ok(CanonicalPipelineLedgerAccountV1 {
                    account_id: decode_hex_32_field(
                        &account.account_id_hex,
                        Box::leak(
                            format!("canonical_pipeline.ledger.accounts[{index}].account_id_hex")
                                .into_boxed_str(),
                        ),
                    )?,
                    balance: account.balance,
                })
            })
            .collect::<Result<Vec<_>, LocalChainErrorV1>>()?,
    })
}

fn canonical_pipeline_ledger_total_balance_v1(
    accounts: &[CanonicalPipelineLedgerAccountV1],
) -> Result<u64, LocalChainErrorV1> {
    accounts.iter().try_fold(0u64, |acc, account| {
        acc.checked_add(account.balance).ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline ledger balances overflow total supply".to_string(),
            )
        })
    })
}

fn canonical_pipeline_ledger_circulating_supply_v1(
    total_supply: u64,
    burned_supply: u64,
) -> Result<u64, LocalChainErrorV1> {
    total_supply.checked_sub(burned_supply).ok_or_else(|| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline ledger burned_supply exceeds total_supply".to_string(),
        )
    })
}

fn validate_canonical_pipeline_ledger_policy_v1(
    request: &CanonicalPipelineRequestV1,
) -> Result<(), LocalChainErrorV1> {
    if request.ledger.ledger_policy_version != CANONICAL_PIPELINE_LEDGER_POLICY_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline ledger_policy_version: expected {}, got {}",
            CANONICAL_PIPELINE_LEDGER_POLICY_VERSION_V1, request.ledger.ledger_policy_version
        )));
    }
    if request.ledger.accounts.is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline ledger.accounts must not be empty".to_string(),
        ));
    }
    let mut previous_account_id = None;
    let mut payer_found = false;
    for (index, account) in request.ledger.accounts.iter().enumerate() {
        if let Some(previous) = previous_account_id {
            if account.account_id <= previous {
                return Err(LocalChainErrorV1::InvalidFixture(format!(
                    "canonical pipeline ledger.accounts must be strictly ordered and duplicate-free at index {index}"
                )));
            }
        }
        if account.account_id == request.ledger.payer_account_id {
            payer_found = true;
        }
        previous_account_id = Some(account.account_id);
    }
    if !payer_found {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline ledger payer_account_id must exist in ledger.accounts".to_string(),
        ));
    }
    let total_account_balances =
        canonical_pipeline_ledger_total_balance_v1(&request.ledger.accounts)?;
    let expected_total_supply = total_account_balances
        .checked_add(request.ledger.burned_supply)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline ledger total_supply overflowed".to_string(),
            )
        })?;
    if request.ledger.total_supply != expected_total_supply {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical pipeline ledger total_supply must equal sum(accounts.balance) + burned_supply: expected {}, got {}",
            expected_total_supply, request.ledger.total_supply
        )));
    }
    let _ = canonical_pipeline_ledger_circulating_supply_v1(
        request.ledger.total_supply,
        request.ledger.burned_supply,
    )?;
    Ok(())
}

fn canonical_pipeline_ledger_payer_account_v1<'a>(
    request: &'a CanonicalPipelineRequestV1,
) -> Result<&'a CanonicalPipelineLedgerAccountV1, LocalChainErrorV1> {
    request
        .ledger
        .accounts
        .iter()
        .find(|account| account.account_id == request.ledger.payer_account_id)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline ledger payer_account_id must exist in ledger.accounts"
                    .to_string(),
            )
        })
}

fn validate_canonical_pipeline_head_request_v1(
    request: &CanonicalPipelineRequestV1,
) -> Result<(), LocalChainErrorV1> {
    if request.head.settlement_head_version != CANONICAL_PIPELINE_SETTLEMENT_HEAD_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline settlement_head_version: expected {}, got {}",
            CANONICAL_PIPELINE_SETTLEMENT_HEAD_VERSION_V1, request.head.settlement_head_version
        )));
    }
    if request.head.head_sequence_number == 0 {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline head.head_sequence_number must start at 1".to_string(),
        ));
    }
    Ok(())
}

fn validate_canonical_pipeline_wallet_binding_v1(
    request: &CanonicalPipelineRequestV1,
) -> Result<(), LocalChainErrorV1> {
    if request.wallet_binding.wallet_binding_version != CANONICAL_PIPELINE_WALLET_BINDING_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline wallet_binding_version: expected {}, got {}",
            CANONICAL_PIPELINE_WALLET_BINDING_VERSION_V1,
            request.wallet_binding.wallet_binding_version
        )));
    }
    if !wallet_address_is_base58_v1(&request.wallet_binding.wallet_address) {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline wallet_binding.wallet_address must be a non-empty base58 string"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_canonical_pipeline_token_anchor_v1(
    request: &CanonicalPipelineRequestV1,
) -> Result<(), LocalChainErrorV1> {
    if request.token_anchor.token_policy_version != CANONICAL_PIPELINE_TOKEN_POLICY_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline token_policy_version: expected {}, got {}",
            CANONICAL_PIPELINE_TOKEN_POLICY_VERSION_V1, request.token_anchor.token_policy_version
        )));
    }
    if request.token_anchor.network_mode == CanonicalPipelineNetworkModeV1::Local
        && request.token_anchor.settlement_anchor_type
            != CanonicalPipelineSettlementAnchorTypeV1::Local
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline local network_mode requires settlement_anchor_type local"
                .to_string(),
        ));
    }
    if request.token_anchor.network_mode == CanonicalPipelineNetworkModeV1::Bridged
        && request.token_anchor.settlement_anchor_type
            == CanonicalPipelineSettlementAnchorTypeV1::Local
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline bridged network_mode must not use settlement_anchor_type local"
                .to_string(),
        ));
    }
    if request.token_anchor.enforce_external_match
        && request.token_anchor.expected_external_balance.is_none()
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline token_anchor expected_external_balance is required when enforce_external_match is true"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_canonical_pipeline_request_semantics_v1(
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) -> Result<(), LocalChainErrorV1> {
    if request.economic.economic_policy_version != CANONICAL_PIPELINE_ECONOMIC_POLICY_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline economic_policy_version: expected {}, got {}",
            CANONICAL_PIPELINE_ECONOMIC_POLICY_VERSION_V1, request.economic.economic_policy_version
        )));
    }
    if request.accounting.accounting_policy_version
        != CANONICAL_PIPELINE_ACCOUNTING_POLICY_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline accounting_policy_version: expected {}, got {}",
            CANONICAL_PIPELINE_ACCOUNTING_POLICY_VERSION_V1,
            request.accounting.accounting_policy_version
        )));
    }
    validate_canonical_pipeline_ledger_policy_v1(request)?;
    validate_canonical_pipeline_head_request_v1(request)?;
    validate_canonical_pipeline_wallet_binding_v1(request)?;
    validate_canonical_pipeline_token_anchor_v1(request)?;
    if request.economic.burn_intent != CanonicalPipelineBurnIntentV1::CanonicalReport {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline burn_intent must be canonical_report".to_string(),
        ));
    }
    if request.accounting.payment_intent
        != CanonicalPipelinePaymentIntentV1::BurnToProduceCanonicalTruth
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline payment_intent must be burn_to_produce_canonical_truth".to_string(),
        ));
    }
    if request.accounting.settlement_intent
        != CanonicalPipelineSettlementIntentV1::RecordCanonicalOutcome
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline settlement_intent must be record_canonical_outcome".to_string(),
        ));
    }
    match request.economic.request_kind {
        CanonicalPipelineRequestKindV1::Execution if request.transactions.is_empty() => {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline request_kind execution requires at least one transaction"
                    .to_string(),
            ))
        }
        CanonicalPipelineRequestKindV1::Execution if request.attestation.is_some() => {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline request_kind execution must not carry attestation material"
                    .to_string(),
            ))
        }
        CanonicalPipelineRequestKindV1::Attestation if request.attestation.is_none() => {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline request_kind attestation requires attestation material"
                    .to_string(),
            ))
        }
        CanonicalPipelineRequestKindV1::Attestation if !request.transactions.is_empty() => {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline request_kind attestation requires zero transactions"
                    .to_string(),
            ))
        }
        CanonicalPipelineRequestKindV1::Execution | CanonicalPipelineRequestKindV1::Attestation => {
        }
    }
    if let Some(attestation) = &request.attestation {
        if attestation.attestation_scope
            != CanonicalPipelineAttestationScopeV1::ClaimConsistencyWithProvidedEvidenceOnly
        {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline attestation_scope must be claim_consistency_with_provided_evidence_only"
                    .to_string(),
            ));
        }
        if let Some(tamper) = &attestation.tamper_stark_public_inputs_digest {
            validate_byte_tamper_offset(
                tamper.byte_offset,
                DCM_HASH_LEN_V1,
                "attestation_stark_public_inputs_digest",
                "32-byte digest",
            )?;
        }
        let _ = canonical_pipeline_prepare_attestation_v1(attestation)?;
    }
    let computed_burn_units = compute_canonical_pipeline_burn_units_v1(request, ordered_accounts)?;
    if request.economic.declared_fee_units != computed_burn_units {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical pipeline economic.declared_fee_units must equal computed burn units: expected {}, got {}",
            computed_burn_units, request.economic.declared_fee_units
        )));
    }
    let payer = canonical_pipeline_ledger_payer_account_v1(request)?;
    if payer.balance < computed_burn_units {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical pipeline ledger payer balance is insufficient for computed burn: balance {}, required {}",
            payer.balance, computed_burn_units
        )));
    }
    Ok(())
}

fn canonical_pipeline_burn_failure_semantics_v1() -> CanonicalPipelineBurnFailureSemanticsV1 {
    CanonicalPipelineBurnFailureSemanticsV1 {
        execution_rejected_burns_full_amount: true,
        verification_rejected_burns_full_amount: true,
        settlement_rejected_burns_full_amount: true,
        partial_burn_allowed: false,
    }
}

fn canonical_pipeline_burn_policy_v1() -> CanonicalPipelineBurnPolicyV1 {
    CanonicalPipelineBurnPolicyV1 {
        burn_policy_version: CANONICAL_PIPELINE_BURN_POLICY_VERSION_V1,
        base_units: CANONICAL_PIPELINE_BURN_BASE_UNITS_V1,
        execution_request_kind_units: CANONICAL_PIPELINE_BURN_EXECUTION_KIND_UNITS_V1,
        attestation_request_kind_units: CANONICAL_PIPELINE_BURN_ATTESTATION_KIND_UNITS_V1,
        mock_proof_system_units: CANONICAL_PIPELINE_BURN_MOCK_UNITS_V1,
        stark_proof_system_units: CANONICAL_PIPELINE_BURN_STARK_UNITS_V1,
        transaction_units_per_item: CANONICAL_PIPELINE_BURN_TRANSACTION_UNITS_V1,
        metered_request_size_chunk_bytes: CANONICAL_PIPELINE_BURN_SIZE_CHUNK_BYTES_V1,
    }
}

fn canonical_pipeline_burn_category_v1(
    request_kind: CanonicalPipelineRequestKindV1,
) -> CanonicalPipelineBurnCategoryV1 {
    match request_kind {
        CanonicalPipelineRequestKindV1::Execution => {
            CanonicalPipelineBurnCategoryV1::ExecutionTruthProduction
        }
        CanonicalPipelineRequestKindV1::Attestation => {
            CanonicalPipelineBurnCategoryV1::AttestationTruthProduction
        }
    }
}

fn canonical_pipeline_burn_derivation_inputs_v1(
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) -> Result<CanonicalPipelineBurnDerivationInputsV1, LocalChainErrorV1> {
    let (attestation_evidence_items, attestation_claim_bytes, attestation_evidence_bytes) =
        if let Some(attestation) = &request.attestation {
            (
                u64::try_from(attestation.evidence_items.len()).map_err(|_| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation evidence count exceeds u64 range"
                            .to_string(),
                    )
                })?,
                canonical_pipeline_attestation_claim_metered_len_v1(&attestation.claim)?,
                canonical_pipeline_attestation_evidence_metered_len_v1(
                    &attestation.evidence_items,
                )?,
            )
        } else {
            (0, 0, 0)
        };
    Ok(CanonicalPipelineBurnDerivationInputsV1 {
        tx_count: u64::try_from(request.transactions.len()).map_err(|_| {
            LocalChainErrorV1::InvalidFixture(
                "transaction count exceeds u64 range for canonical pipeline burn".to_string(),
            )
        })?,
        metered_request_size_bytes: u64::try_from(
            canonical_pipeline_burn_metered_bytes_v1(request, ordered_accounts).len(),
        )
        .map_err(|_| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline burn metered request exceeds u64 range".to_string(),
            )
        })?,
        request_kind: request.economic.request_kind,
        proof_system: request.proof_system,
        attestation_evidence_items,
        attestation_claim_bytes,
        attestation_evidence_bytes,
    })
}

fn extend_canonical_pipeline_attestation_claim_payload_bytes_v1(
    bytes: &mut Vec<u8>,
    claim_payload: &CanonicalPipelineAttestationClaimPayloadV1,
) {
    match claim_payload {
        CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest {
            expected_evidence_root_digest,
        } => {
            bytes.extend_from_slice(expected_evidence_root_digest);
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
            target_label,
            expected_evidence_digest,
        } => {
            extend_len_prefixed_bytes_v1(bytes, target_label.as_bytes());
            bytes.extend_from_slice(expected_evidence_digest);
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
            target_label,
            expected_substring_utf8,
        } => {
            extend_len_prefixed_bytes_v1(bytes, target_label.as_bytes());
            extend_len_prefixed_bytes_v1(bytes, expected_substring_utf8.as_bytes());
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
            target_label,
            field_path,
            expected_value_utf8,
        } => {
            extend_len_prefixed_bytes_v1(bytes, target_label.as_bytes());
            bytes.extend_from_slice(
                &u64::try_from(field_path.len())
                    .expect("attestation field_path length fits in u64")
                    .to_le_bytes(),
            );
            for segment in field_path {
                extend_len_prefixed_bytes_v1(bytes, segment.as_bytes());
            }
            extend_len_prefixed_bytes_v1(bytes, expected_value_utf8.as_bytes());
        }
    }
}

fn extend_canonical_pipeline_attestation_claim_bytes_v1(
    bytes: &mut Vec<u8>,
    claim: &CanonicalPipelineAttestationClaimV1,
) {
    extend_len_prefixed_bytes_v1(bytes, claim.claim_kind.as_str().as_bytes());
    extend_canonical_pipeline_attestation_claim_payload_bytes_v1(bytes, &claim.claim_payload);
}

fn extend_canonical_pipeline_attestation_evidence_payload_bytes_v1(
    bytes: &mut Vec<u8>,
    evidence_payload: &CanonicalPipelineAttestationEvidencePayloadV1,
) {
    match evidence_payload {
        CanonicalPipelineAttestationEvidencePayloadV1::InlineUtf8 { payload_utf8 }
        | CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 { payload_utf8 } => {
            extend_len_prefixed_bytes_v1(bytes, payload_utf8.as_bytes());
        }
    }
}

fn extend_optional_canonical_pipeline_evidence_signature_bytes_v1(
    bytes: &mut Vec<u8>,
    signature: Option<&CanonicalPipelineEvidenceSignatureV1>,
) {
    match signature {
        Some(signature) => {
            bytes.push(1);
            bytes.extend_from_slice(&signature.signer_public_key);
            bytes.extend_from_slice(&signature.signature);
        }
        None => bytes.push(0),
    }
}

fn extend_canonical_pipeline_provenance_bytes_v1(
    bytes: &mut Vec<u8>,
    provenance: &CanonicalPipelineEvidenceProvenanceV1,
) {
    bytes.extend_from_slice(&provenance.provenance_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, provenance.provenance_type.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(bytes, provenance.source_type.as_bytes());
    extend_len_prefixed_bytes_v1(bytes, provenance.source_identifier.as_bytes());
    extend_optional_canonical_pipeline_evidence_signature_bytes_v1(
        bytes,
        provenance.signature.as_ref(),
    );
    match provenance.timestamp_unix_seconds {
        Some(timestamp) => {
            bytes.push(1);
            bytes.extend_from_slice(&timestamp.to_le_bytes());
        }
        None => bytes.push(0),
    }
}

fn extend_canonical_pipeline_attestation_evidence_item_bytes_v1(
    bytes: &mut Vec<u8>,
    item: &CanonicalPipelineAttestationEvidenceItemV1,
) {
    extend_len_prefixed_bytes_v1(bytes, item.label.as_bytes());
    extend_len_prefixed_bytes_v1(bytes, item.evidence_kind.as_str().as_bytes());
    extend_canonical_pipeline_attestation_evidence_payload_bytes_v1(bytes, &item.evidence_payload);
    extend_canonical_pipeline_provenance_bytes_v1(bytes, &item.provenance);
}

fn canonical_pipeline_attestation_claim_metered_len_v1(
    claim: &CanonicalPipelineAttestationClaimV1,
) -> Result<u64, LocalChainErrorV1> {
    let mut bytes = Vec::new();
    extend_canonical_pipeline_attestation_claim_bytes_v1(&mut bytes, claim);
    u64::try_from(bytes.len()).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline attestation claim length exceeds u64 range".to_string(),
        )
    })
}

fn canonical_pipeline_attestation_evidence_metered_len_v1(
    evidence_items: &[CanonicalPipelineAttestationEvidenceItemV1],
) -> Result<u64, LocalChainErrorV1> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u64::try_from(evidence_items.len())
            .map_err(|_| {
                LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation evidence count exceeds u64 range".to_string(),
                )
            })?
            .to_le_bytes(),
    );
    for item in evidence_items {
        extend_canonical_pipeline_attestation_evidence_item_bytes_v1(&mut bytes, item);
    }
    u64::try_from(bytes.len()).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline attestation evidence length exceeds u64 range".to_string(),
        )
    })
}

fn compute_canonical_pipeline_burn_units_from_inputs_v1(
    inputs: &CanonicalPipelineBurnDerivationInputsV1,
) -> Result<u64, LocalChainErrorV1> {
    let request_kind_units = match inputs.request_kind {
        CanonicalPipelineRequestKindV1::Execution => {
            CANONICAL_PIPELINE_BURN_EXECUTION_KIND_UNITS_V1
        }
        CanonicalPipelineRequestKindV1::Attestation => {
            CANONICAL_PIPELINE_BURN_ATTESTATION_KIND_UNITS_V1
        }
    };
    let proof_system_units = match inputs.proof_system {
        ProofSystemSelectionV1::Mock => CANONICAL_PIPELINE_BURN_MOCK_UNITS_V1,
        ProofSystemSelectionV1::Stark => CANONICAL_PIPELINE_BURN_STARK_UNITS_V1,
    };
    let transaction_units = inputs
        .tx_count
        .checked_mul(CANONICAL_PIPELINE_BURN_TRANSACTION_UNITS_V1)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline burn transaction units overflowed".to_string(),
            )
        })?;
    let size_units = inputs
        .metered_request_size_bytes
        .checked_add(CANONICAL_PIPELINE_BURN_SIZE_CHUNK_BYTES_V1 - 1)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline burn metered request size overflowed".to_string(),
            )
        })?
        / CANONICAL_PIPELINE_BURN_SIZE_CHUNK_BYTES_V1;
    CANONICAL_PIPELINE_BURN_BASE_UNITS_V1
        .checked_add(request_kind_units)
        .and_then(|value| value.checked_add(proof_system_units))
        .and_then(|value| value.checked_add(transaction_units))
        .and_then(|value| value.checked_add(size_units))
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline burn units overflowed".to_string(),
            )
        })
}

fn compute_canonical_pipeline_burn_units_v1(
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) -> Result<u64, LocalChainErrorV1> {
    let inputs = canonical_pipeline_burn_derivation_inputs_v1(request, ordered_accounts)?;
    compute_canonical_pipeline_burn_units_from_inputs_v1(&inputs)
}

fn canonical_pipeline_burn_summary_v1(
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) -> Result<CanonicalPipelineBurnSummaryV1, LocalChainErrorV1> {
    let derivation_inputs =
        canonical_pipeline_burn_derivation_inputs_v1(request, ordered_accounts)?;
    let computed_burn_units =
        compute_canonical_pipeline_burn_units_from_inputs_v1(&derivation_inputs)?;
    Ok(CanonicalPipelineBurnSummaryV1 {
        burn_policy_version: CANONICAL_PIPELINE_BURN_POLICY_VERSION_V1,
        burn_policy: canonical_pipeline_burn_policy_v1(),
        burn_reason: CanonicalPipelineBurnReasonV1::ProduceCanonicalTruthArtifact,
        burn_category: canonical_pipeline_burn_category_v1(request.economic.request_kind),
        request_kind: request.economic.request_kind,
        burn_intent: request.economic.burn_intent,
        declared_fee_units: request.economic.declared_fee_units,
        computed_burn_units,
        consumed_burn_units: computed_burn_units,
        burn_derivation_inputs: derivation_inputs,
        request_declares_correct_burn: request.economic.declared_fee_units == computed_burn_units,
        recomputed_burn_matches_report: true,
        burn_consumed: true,
        failure_semantics: canonical_pipeline_burn_failure_semantics_v1(),
    })
}

fn canonical_pipeline_truth_artifact_kind_v1(
    request_kind: CanonicalPipelineRequestKindV1,
) -> CanonicalPipelineTruthArtifactKindV1 {
    match request_kind {
        CanonicalPipelineRequestKindV1::Execution => {
            CanonicalPipelineTruthArtifactKindV1::ExecutionReport
        }
        CanonicalPipelineRequestKindV1::Attestation => {
            CanonicalPipelineTruthArtifactKindV1::AttestationReport
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalPipelinePreparedAttestationV1 {
    claim_digest: [u8; 32],
    evidence_summary: CanonicalPipelineAttestationEvidenceSummaryV1,
    normalization_summary: CanonicalPipelineAttestationNormalizationSummaryV1,
    consistency_result: CanonicalPipelineAttestationConsistencyResultV1,
    provenance_summary: CanonicalPipelineProvenanceSummaryV1,
    attestation_tuple_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalPipelineAttestationStarkMaterialV1 {
    public_inputs: DcmAirPublicInputsV1,
    public_inputs_digest: [u8; DCM_HASH_LEN_V1],
    proof_artifact: DcmAirRealStarkProofArtifactV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineHeadStateFileV1 {
    state_file_version: u32,
    settlement_head_version: u32,
    current_head_hash_hex: String,
    head_sequence_number: u64,
    canonical_head_commitment_hex: String,
    request_canonical_digest_hex: String,
    report_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPipelineRunOptionsV1 {
    pub head_state_path: Option<String>,
    pub stateless: bool,
}

impl Default for CanonicalPipelineRunOptionsV1 {
    fn default() -> Self {
        Self {
            head_state_path: None,
            stateless: true,
        }
    }
}

fn canonical_pipeline_supported_attestation_constraints_v1(
) -> CanonicalPipelineAttestationConstraintsV1 {
    CanonicalPipelineAttestationConstraintsV1 {
        require_unique_labels: true,
        max_evidence_items: 16,
        max_total_normalized_bytes: 16_384,
    }
}

fn canonical_pipeline_attestation_payload_utf8_v1(
    item: &CanonicalPipelineAttestationEvidenceItemV1,
) -> &str {
    match &item.evidence_payload {
        CanonicalPipelineAttestationEvidencePayloadV1::InlineUtf8 { payload_utf8 }
        | CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 { payload_utf8 } => {
            payload_utf8
        }
    }
}

fn canonical_pipeline_provenance_signature_message_v1(
    label: &str,
    evidence_digest: [u8; 32],
    provenance: &CanonicalPipelineEvidenceProvenanceV1,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_MESSAGE_DOMAIN_SEPARATOR_V1);
    extend_len_prefixed_bytes_v1(&mut bytes, label.as_bytes());
    bytes.extend_from_slice(&evidence_digest);
    bytes.extend_from_slice(&provenance.provenance_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, provenance.provenance_type.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, provenance.source_type.as_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, provenance.source_identifier.as_bytes());
    match provenance.timestamp_unix_seconds {
        Some(timestamp) => {
            bytes.push(1);
            bytes.extend_from_slice(&timestamp.to_le_bytes());
        }
        None => bytes.push(0),
    }
    bytes
}

fn canonical_pipeline_provenance_digest_v1(
    label: &str,
    evidence_digest: [u8; 32],
    provenance: &CanonicalPipelineEvidenceProvenanceV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_PROVENANCE_DIGEST_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&canonical_pipeline_provenance_signature_message_v1(
        label,
        evidence_digest,
        provenance,
    ));
    if let Some(signature) = &provenance.signature {
        bytes.extend_from_slice(&signature.signer_public_key);
        bytes.extend_from_slice(&signature.signature);
    } else {
        bytes.push(0);
    }
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_verify_provenance_signature_v1(
    label: &str,
    evidence_digest: [u8; 32],
    provenance: &CanonicalPipelineEvidenceProvenanceV1,
) -> Result<bool, LocalChainErrorV1> {
    let Some(signature) = &provenance.signature else {
        return Ok(true);
    };
    let public_key = PublicKey::from_bytes(&signature.signer_public_key).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline provenance signer_public_key is not a valid ed25519 key"
                .to_string(),
        )
    })?;
    let signature = Signature::from_bytes(&signature.signature).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline provenance signature is not a valid ed25519 signature".to_string(),
        )
    })?;
    Ok(public_key
        .verify(
            &canonical_pipeline_provenance_signature_message_v1(label, evidence_digest, provenance),
            &signature,
        )
        .is_ok())
}

fn canonical_pipeline_build_provenance_summary_v1(
    items: &[CanonicalPipelineAttestationEvidenceItemV1],
    evidence_items: &[CanonicalPipelineAttestationEvidenceSummaryItemV1],
) -> Result<CanonicalPipelineProvenanceSummaryV1, LocalChainErrorV1> {
    let mut summary_items = Vec::with_capacity(items.len());
    let mut all_signature_checks_passed = true;
    for (item, evidence_summary) in items.iter().zip(evidence_items.iter()) {
        let provenance = &item.provenance;
        let signature_valid = canonical_pipeline_verify_provenance_signature_v1(
            &item.label,
            evidence_summary.evidence_digest,
            provenance,
        )?;
        all_signature_checks_passed &= signature_valid;
        summary_items.push(CanonicalPipelineProvenanceSummaryItemV1 {
            label: item.label.clone(),
            provenance_policy_version: provenance.provenance_policy_version,
            provenance_type: provenance.provenance_type,
            source_type: provenance.source_type.clone(),
            source_identifier: provenance.source_identifier.clone(),
            signature_present: provenance.signature.is_some(),
            signature_valid,
            signer_public_key: provenance
                .signature
                .as_ref()
                .map(|signature| signature.signer_public_key),
            signature: provenance
                .signature
                .as_ref()
                .map(|signature| signature.signature),
            timestamp_unix_seconds: provenance.timestamp_unix_seconds,
            provenance_digest: canonical_pipeline_provenance_digest_v1(
                &item.label,
                evidence_summary.evidence_digest,
                provenance,
            ),
        });
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_PROVENANCE_ITEM_DIGEST_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(
        &u64::try_from(summary_items.len())
            .expect("provenance item count fits in u64")
            .to_le_bytes(),
    );
    for item in &summary_items {
        extend_len_prefixed_bytes_v1(&mut bytes, item.label.as_bytes());
        bytes.extend_from_slice(&item.provenance_policy_version.to_le_bytes());
        extend_len_prefixed_bytes_v1(&mut bytes, item.provenance_type.as_str().as_bytes());
        extend_len_prefixed_bytes_v1(&mut bytes, item.source_type.as_bytes());
        extend_len_prefixed_bytes_v1(&mut bytes, item.source_identifier.as_bytes());
        bytes.push(u8::from(item.signature_present));
        bytes.push(u8::from(item.signature_valid));
        match (item.signer_public_key, item.signature) {
            (Some(public_key), Some(signature)) => {
                bytes.push(1);
                bytes.extend_from_slice(&public_key);
                bytes.extend_from_slice(&signature);
            }
            _ => bytes.push(0),
        }
        match item.timestamp_unix_seconds {
            Some(timestamp) => {
                bytes.push(1);
                bytes.extend_from_slice(&timestamp.to_le_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&item.provenance_digest);
    }
    Ok(CanonicalPipelineProvenanceSummaryV1 {
        provenance_item_count: u64::try_from(summary_items.len())
            .expect("provenance item count fits in u64"),
        provenance_root_digest: sha256_digest_v1(&bytes),
        items: summary_items,
        all_signature_checks_passed,
    })
}

fn canonical_pipeline_attestation_tuple_digest_v1(
    claim_digest: [u8; 32],
    evidence_root_digest: [u8; 32],
    provenance_root_digest: [u8; 32],
    consistency_result: &CanonicalPipelineAttestationConsistencyResultV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_TUPLE_DIGEST_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&claim_digest);
    bytes.extend_from_slice(&evidence_root_digest);
    bytes.extend_from_slice(&provenance_root_digest);
    extend_len_prefixed_bytes_v1(&mut bytes, consistency_result.relation.as_str().as_bytes());
    if let Some(target_label) = &consistency_result.target_label {
        bytes.push(1);
        extend_len_prefixed_bytes_v1(&mut bytes, target_label.as_bytes());
    } else {
        bytes.push(0);
    }
    bytes.push(u8::from(consistency_result.consistent));
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_build_attestation_stark_material_v1(
    prepared: &CanonicalPipelinePreparedAttestationV1,
) -> Result<CanonicalPipelineAttestationStarkMaterialV1, LocalChainErrorV1> {
    let mut x_seed_preimage = Vec::with_capacity(96);
    x_seed_preimage
        .extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_STARK_X_SEED_DOMAIN_SEPARATOR_V1);
    x_seed_preimage.extend_from_slice(&prepared.claim_digest);
    x_seed_preimage.extend_from_slice(&prepared.attestation_tuple_digest);
    let x_seed_digest = sha256_digest_v1(&x_seed_preimage);
    let x_seed = u64::from_le_bytes(
        x_seed_digest[..8]
            .try_into()
            .expect("sha256 digest prefix is exactly 8 bytes"),
    );

    let mut y_seed_preimage = Vec::with_capacity(96);
    y_seed_preimage
        .extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_STARK_Y_SEED_DOMAIN_SEPARATOR_V1);
    y_seed_preimage.extend_from_slice(&prepared.evidence_summary.evidence_root_digest);
    y_seed_preimage.extend_from_slice(&prepared.provenance_summary.provenance_root_digest);
    y_seed_preimage.extend_from_slice(&prepared.attestation_tuple_digest);
    let y_seed_digest = sha256_digest_v1(&y_seed_preimage);
    let y_seed = u64::from_le_bytes(
        y_seed_digest[..8]
            .try_into()
            .expect("sha256 digest prefix is exactly 8 bytes"),
    );

    let input = DcmInput521V1::from_u64(x_seed, y_seed);
    let config = DcmConfig521V1 {
        iteration_count: CANONICAL_PIPELINE_ATTESTATION_STARK_ITERATION_COUNT_V1,
    };
    let execution = DcmExecution521V1::run(&config, &input)
        .map_err(|error| LocalChainErrorV1::InvalidFixture(error.to_string()))?;
    let claim = aura_intent_lineage_v1::build_dcm_claim_521_v1(&config, &input, &execution);
    let public_inputs = dcm_air_public_inputs_from_claim_521_v1(&claim);
    let public_inputs_digest = derive_dcm_air_stark_public_input_digest_v1(&public_inputs);
    let proof_artifact = prove_dcm_air_real_stark_v1(
        &public_inputs,
        &aura_intent_lineage_v1::DcmAirTraceV1::new(execution.states),
    )
    .map_err(|error| LocalChainErrorV1::InvalidFixture(error.to_string()))?;
    Ok(CanonicalPipelineAttestationStarkMaterialV1 {
        public_inputs,
        public_inputs_digest,
        proof_artifact,
    })
}

fn canonical_pipeline_normalize_utf8_text_v1(payload: &str) -> String {
    let normalized_line_endings = payload.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = normalized_line_endings
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']).to_string())
        .collect::<Vec<_>>();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

fn canonical_pipeline_canonicalize_json_value_v1(
    value: &serde_json::Value,
) -> Result<String, LocalChainErrorV1> {
    Ok(match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(text) => serde_json::to_string(text)?,
        serde_json::Value::Array(values) => {
            let rendered = values
                .iter()
                .map(canonical_pipeline_canonicalize_json_value_v1)
                .collect::<Result<Vec<_>, _>>()?;
            format!("[{}]", rendered.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let rendered = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(&key)?,
                        canonical_pipeline_canonicalize_json_value_v1(
                            map.get(&key).expect("sorted key must exist"),
                        )?
                    ))
                })
                .collect::<Result<Vec<_>, LocalChainErrorV1>>()?;
            format!("{{{}}}", rendered.join(","))
        }
    })
}

fn canonical_pipeline_attestation_evidence_digest_v1(
    evidence_kind: CanonicalPipelineAttestationEvidenceKindV1,
    normalized_form: CanonicalPipelineAttestationNormalizedFormV1,
    normalized_payload_utf8: &str,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_DIGEST_DOMAIN_SEPARATOR_V2);
    extend_len_prefixed_bytes_v1(&mut bytes, evidence_kind.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, normalized_form.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, normalized_payload_utf8.as_bytes());
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_attestation_evidence_root_digest_v1(
    items: &[CanonicalPipelineAttestationEvidenceSummaryItemV1],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes
        .extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_ROOT_DIGEST_DOMAIN_SEPARATOR_V2);
    bytes.extend_from_slice(
        &u64::try_from(items.len())
            .expect("attestation evidence count fits in u64")
            .to_le_bytes(),
    );
    for item in items {
        extend_len_prefixed_bytes_v1(&mut bytes, item.label.as_bytes());
        extend_len_prefixed_bytes_v1(&mut bytes, item.evidence_kind.as_str().as_bytes());
        bytes.extend_from_slice(&item.evidence_digest);
    }
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_attestation_claim_digest_v1(
    claim: &CanonicalPipelineAttestationClaimV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_ATTESTATION_CLAIM_DIGEST_DOMAIN_SEPARATOR_V2);
    extend_len_prefixed_bytes_v1(&mut bytes, claim.claim_kind.as_str().as_bytes());
    match &claim.claim_payload {
        CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest {
            expected_evidence_root_digest,
        } => {
            bytes.extend_from_slice(expected_evidence_root_digest);
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
            target_label,
            expected_evidence_digest,
        } => {
            extend_len_prefixed_bytes_v1(&mut bytes, target_label.as_bytes());
            bytes.extend_from_slice(expected_evidence_digest);
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
            target_label,
            expected_substring_utf8,
        } => {
            extend_len_prefixed_bytes_v1(&mut bytes, target_label.as_bytes());
            extend_len_prefixed_bytes_v1(&mut bytes, expected_substring_utf8.as_bytes());
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
            target_label,
            field_path,
            expected_value_utf8,
        } => {
            extend_len_prefixed_bytes_v1(&mut bytes, target_label.as_bytes());
            bytes.extend_from_slice(
                &u64::try_from(field_path.len())
                    .expect("attestation field_path length fits in u64")
                    .to_le_bytes(),
            );
            for segment in field_path {
                extend_len_prefixed_bytes_v1(&mut bytes, segment.as_bytes());
            }
            extend_len_prefixed_bytes_v1(&mut bytes, expected_value_utf8.as_bytes());
        }
    }
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_attestation_target_label_v1(
    claim: &CanonicalPipelineAttestationClaimV1,
) -> Option<&str> {
    match &claim.claim_payload {
        CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest { .. } => None,
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
            target_label,
            ..
        }
        | CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
            target_label,
            ..
        }
        | CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
            target_label,
            ..
        } => Some(target_label.as_str()),
    }
}

fn canonical_pipeline_attestation_find_summary_item_v1<'a>(
    evidence_summary: &'a CanonicalPipelineAttestationEvidenceSummaryV1,
    target_label: &str,
) -> Result<&'a CanonicalPipelineAttestationEvidenceSummaryItemV1, LocalChainErrorV1> {
    evidence_summary
        .evidence_items
        .iter()
        .find(|item| item.label == target_label)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation claim references unknown target_label: {target_label}"
            ))
        })
}

fn canonical_pipeline_attestation_extract_json_field_v1(
    normalized_payload_utf8: &str,
    field_path: &[String],
) -> Result<Option<String>, LocalChainErrorV1> {
    let mut cursor = serde_json::from_str::<serde_json::Value>(normalized_payload_utf8)?;
    for segment in field_path {
        match cursor {
            serde_json::Value::Object(map) => {
                let Some(next) = map.get(segment) else {
                    return Ok(None);
                };
                cursor = next.clone();
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(match cursor {
        serde_json::Value::String(text) => text,
        other => canonical_pipeline_canonicalize_json_value_v1(&other)?,
    }))
}

fn canonical_pipeline_prepare_attestation_v1(
    attestation: &CanonicalPipelineAttestationRequestV1,
) -> Result<CanonicalPipelinePreparedAttestationV1, LocalChainErrorV1> {
    let supported_constraints = canonical_pipeline_supported_attestation_constraints_v1();
    if attestation.attestation_schema_version != CANONICAL_PIPELINE_ATTESTATION_SCHEMA_VERSION_V2 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline attestation_schema_version: expected {}, got {}",
            CANONICAL_PIPELINE_ATTESTATION_SCHEMA_VERSION_V2,
            attestation.attestation_schema_version
        )));
    }
    if attestation.normalization_policy_version
        != CANONICAL_PIPELINE_ATTESTATION_NORMALIZATION_POLICY_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical pipeline normalization_policy_version: expected {}, got {}",
            CANONICAL_PIPELINE_ATTESTATION_NORMALIZATION_POLICY_VERSION_V1,
            attestation.normalization_policy_version
        )));
    }
    if attestation.attestation_constraints != supported_constraints {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline attestation_constraints must match the supported attestation contract"
                .to_string(),
        ));
    }
    if attestation.evidence_items.is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical pipeline attestation evidence_items must not be empty".to_string(),
        ));
    }
    if u64::try_from(attestation.evidence_items.len()).map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline attestation evidence item count exceeds u64 range".to_string(),
        )
    })? > attestation.attestation_constraints.max_evidence_items
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical pipeline attestation evidence_items exceeds max_evidence_items {}",
            attestation.attestation_constraints.max_evidence_items
        )));
    }
    let mut seen_labels = BTreeSet::new();
    let mut evidence_items = Vec::new();
    let mut total_normalized_bytes = 0u64;
    for (index, item) in attestation.evidence_items.iter().enumerate() {
        if item.label.trim().is_empty() {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation evidence_items[{index}].label must not be empty"
            )));
        }
        if item.provenance.provenance_policy_version
            != CANONICAL_PIPELINE_PROVENANCE_POLICY_VERSION_V1
        {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported canonical pipeline provenance_policy_version: expected {}, got {}",
                CANONICAL_PIPELINE_PROVENANCE_POLICY_VERSION_V1,
                item.provenance.provenance_policy_version
            )));
        }
        if item.provenance.source_type.trim().is_empty()
            || item.provenance.source_identifier.trim().is_empty()
        {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation evidence_items[{index}].provenance source_type and source_identifier must not be empty"
            )));
        }
        if item.provenance.provenance_type == CanonicalPipelineEvidenceProvenanceTypeV1::SignedBlob
            && item.provenance.signature.is_none()
        {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation evidence_items[{index}].provenance signed_blob requires signature material"
            )));
        }
        if attestation.attestation_constraints.require_unique_labels
            && !seen_labels.insert(item.label.as_str())
        {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation evidence_items contains duplicate label: {}",
                item.label
            )));
        }
        let original_payload_utf8 = canonical_pipeline_attestation_payload_utf8_v1(item);
        if original_payload_utf8.is_empty() {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation evidence_items[{index}].evidence_payload.payload_utf8 must not be empty"
            )));
        }
        let (normalized_form, normalized_payload_utf8) = match item.evidence_kind {
            CanonicalPipelineAttestationEvidenceKindV1::InlineUtf8 => (
                CanonicalPipelineAttestationNormalizedFormV1::Utf8Text,
                canonical_pipeline_normalize_utf8_text_v1(original_payload_utf8),
            ),
            CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8 => {
                let parsed = serde_json::from_str::<serde_json::Value>(original_payload_utf8)
                    .map_err(|error| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "canonical pipeline attestation evidence_items[{index}] malformed inline_json_utf8 payload: {error}"
                        ))
                    })?;
                (
                    CanonicalPipelineAttestationNormalizedFormV1::CanonicalJsonUtf8,
                    canonical_pipeline_canonicalize_json_value_v1(&parsed)?,
                )
            }
        };
        let original_payload_size_bytes =
            u64::try_from(original_payload_utf8.len()).map_err(|_| {
                LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation original payload length exceeds u64 range"
                        .to_string(),
                )
            })?;
        let normalized_payload_size_bytes =
            u64::try_from(normalized_payload_utf8.len()).map_err(|_| {
                LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation normalized payload length exceeds u64 range"
                        .to_string(),
                )
            })?;
        total_normalized_bytes = total_normalized_bytes
            .checked_add(normalized_payload_size_bytes)
            .ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "canonical pipeline attestation normalized payload length overflowed"
                        .to_string(),
                )
            })?;
        let evidence_digest = canonical_pipeline_attestation_evidence_digest_v1(
            item.evidence_kind,
            normalized_form,
            &normalized_payload_utf8,
        );
        evidence_items.push(CanonicalPipelineAttestationEvidenceSummaryItemV1 {
            label: item.label.clone(),
            evidence_kind: item.evidence_kind,
            original_payload_utf8: original_payload_utf8.to_string(),
            original_payload_size_bytes,
            normalized_form,
            normalized_payload_utf8: normalized_payload_utf8.clone(),
            normalized_payload_size_bytes,
            evidence_digest,
            provenance_digest: canonical_pipeline_provenance_digest_v1(
                &item.label,
                evidence_digest,
                &item.provenance,
            ),
        });
    }
    if total_normalized_bytes
        > attestation
            .attestation_constraints
            .max_total_normalized_bytes
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical pipeline attestation normalized evidence bytes exceeds max_total_normalized_bytes {}",
            attestation.attestation_constraints.max_total_normalized_bytes
        )));
    }
    let evidence_summary = CanonicalPipelineAttestationEvidenceSummaryV1 {
        evidence_item_count: u64::try_from(evidence_items.len()).map_err(|_| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline attestation evidence item count exceeds u64 range".to_string(),
            )
        })?,
        evidence_root_digest: canonical_pipeline_attestation_evidence_root_digest_v1(
            &evidence_items,
        ),
        evidence_items,
    };
    let provenance_summary = canonical_pipeline_build_provenance_summary_v1(
        &attestation.evidence_items,
        &evidence_summary.evidence_items,
    )?;
    if let Some(target_label) = canonical_pipeline_attestation_target_label_v1(&attestation.claim) {
        let target_item =
            canonical_pipeline_attestation_find_summary_item_v1(&evidence_summary, target_label)?;
        if attestation.claim.claim_kind
            == CanonicalPipelineAttestationClaimKindV1::NormalizedJsonFieldEqualsUtf8
            && target_item.normalized_form
                != CanonicalPipelineAttestationNormalizedFormV1::CanonicalJsonUtf8
        {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical pipeline attestation claim_kind normalized_json_field_equals_utf8 requires inline_json_utf8 evidence for target_label {target_label}"
            )));
        }
    }
    if let CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
        expected_substring_utf8,
        ..
    } = &attestation.claim.claim_payload
    {
        if expected_substring_utf8.is_empty() {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline attestation claim_payload.expected_substring_utf8 must not be empty"
                    .to_string(),
            ));
        }
    }
    if let CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
        field_path,
        expected_value_utf8,
        ..
    } = &attestation.claim.claim_payload
    {
        if field_path.is_empty() || field_path.iter().any(|segment| segment.trim().is_empty()) {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline attestation claim_payload.field_path must contain only non-empty segments"
                    .to_string(),
            ));
        }
        if expected_value_utf8.is_empty() {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical pipeline attestation claim_payload.expected_value_utf8 must not be empty"
                    .to_string(),
            ));
        }
    }
    let consistency_result = match &attestation.claim.claim_payload {
        CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest {
            expected_evidence_root_digest,
        } => CanonicalPipelineAttestationConsistencyResultV1 {
            relation: CanonicalPipelineAttestationConsistencyRelationV1::EvidenceRootDigestEquals,
            target_label: None,
            consistent: *expected_evidence_root_digest == evidence_summary.evidence_root_digest,
        },
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
            target_label,
            expected_evidence_digest,
        } => {
            let target_item = canonical_pipeline_attestation_find_summary_item_v1(
                &evidence_summary,
                target_label,
            )?;
            CanonicalPipelineAttestationConsistencyResultV1 {
                relation:
                    CanonicalPipelineAttestationConsistencyRelationV1::NormalizedEvidenceDigestEquals,
                target_label: Some(target_label.clone()),
                consistent: *expected_evidence_digest == target_item.evidence_digest,
            }
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
            target_label,
            expected_substring_utf8,
        } => {
            let target_item = canonical_pipeline_attestation_find_summary_item_v1(
                &evidence_summary,
                target_label,
            )?;
            CanonicalPipelineAttestationConsistencyResultV1 {
                relation:
                    CanonicalPipelineAttestationConsistencyRelationV1::NormalizedTextContainsUtf8,
                target_label: Some(target_label.clone()),
                consistent: target_item
                    .normalized_payload_utf8
                    .contains(expected_substring_utf8),
            }
        }
        CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
            target_label,
            field_path,
            expected_value_utf8,
        } => {
            let target_item = canonical_pipeline_attestation_find_summary_item_v1(
                &evidence_summary,
                target_label,
            )?;
            let extracted_value = canonical_pipeline_attestation_extract_json_field_v1(
                &target_item.normalized_payload_utf8,
                field_path,
            )?;
            CanonicalPipelineAttestationConsistencyResultV1 {
                relation:
                    CanonicalPipelineAttestationConsistencyRelationV1::NormalizedJsonFieldEqualsUtf8,
                target_label: Some(target_label.clone()),
                consistent: extracted_value.as_deref() == Some(expected_value_utf8.as_str()),
            }
        }
    };
    let claim_digest = canonical_pipeline_attestation_claim_digest_v1(&attestation.claim);
    let evidence_root_digest = evidence_summary.evidence_root_digest;
    let provenance_root_digest = provenance_summary.provenance_root_digest;
    Ok(CanonicalPipelinePreparedAttestationV1 {
        claim_digest,
        evidence_summary,
        normalization_summary: CanonicalPipelineAttestationNormalizationSummaryV1 {
            normalization_policy_version: attestation.normalization_policy_version,
            normalized_evidence_count: u64::try_from(attestation.evidence_items.len()).map_err(
                |_| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical pipeline attestation evidence item count exceeds u64 range"
                            .to_string(),
                    )
                },
            )?,
            total_normalized_bytes,
            normalization_succeeded: true,
        },
        consistency_result: consistency_result.clone(),
        provenance_summary: provenance_summary.clone(),
        attestation_tuple_digest: canonical_pipeline_attestation_tuple_digest_v1(
            claim_digest,
            evidence_root_digest,
            provenance_root_digest,
            &consistency_result,
        ),
    })
}

fn canonical_pipeline_attestation_failure_detail_v1(
    request: &CanonicalPipelineRequestV1,
    prepared: &CanonicalPipelinePreparedAttestationV1,
    actual_result: ScenarioResultV1,
) -> CanonicalPipelineAttestationFailureAuditV1 {
    match actual_result {
        ScenarioResultV1::Accepted => CanonicalPipelineAttestationFailureAuditV1 {
            reason: CanonicalPipelineAttestationFailureReasonV1::None,
            detail: "attestation consistency was established under the supported normalization and evidence rules".to_string(),
        },
        ScenarioResultV1::ExecutionRejected
            if !prepared.provenance_summary.all_signature_checks_passed =>
        {
            CanonicalPipelineAttestationFailureAuditV1 {
                reason: CanonicalPipelineAttestationFailureReasonV1::ProvenanceSignatureInvalid,
                detail:
                    "attestation provenance carried signature material that failed deterministic verification"
                        .to_string(),
            }
        }
        ScenarioResultV1::ExecutionRejected if !prepared.consistency_result.consistent => {
            CanonicalPipelineAttestationFailureAuditV1 {
                reason: CanonicalPipelineAttestationFailureReasonV1::ConsistencyMismatch,
                detail: "attestation claim was not consistent with the normalized evidence derived from the supplied canonical evidence set".to_string(),
            }
        }
        ScenarioResultV1::ExecutionRejected => CanonicalPipelineAttestationFailureAuditV1 {
            reason: CanonicalPipelineAttestationFailureReasonV1::MalformedEvidence,
            detail: "attestation request was rejected before proof production".to_string(),
        },
        ScenarioResultV1::VerificationRejected => CanonicalPipelineAttestationFailureAuditV1 {
            reason: if request
                .attestation
                .as_ref()
                .is_some_and(|attestation| {
                    attestation.attestation_proof_kind
                        == CanonicalPipelineAttestationProofKindV1::Stark
                }) {
                CanonicalPipelineAttestationFailureReasonV1::AttestationProofVerificationFailure
            } else {
                CanonicalPipelineAttestationFailureReasonV1::VerificationLayerFailure
            },
            detail: "verification-layer mismatch rejected an otherwise normalized and evaluated attestation".to_string(),
        },
        ScenarioResultV1::SettlementRejected => CanonicalPipelineAttestationFailureAuditV1 {
            reason: CanonicalPipelineAttestationFailureReasonV1::SettlementLayerFailure,
            detail: "local settlement rejected an otherwise verified attestation transition".to_string(),
        },
    }
}

fn canonical_pipeline_attestation_summary_v1(
    request: &CanonicalPipelineRequestV1,
    actual_result: ScenarioResultV1,
) -> Result<Option<CanonicalPipelineAttestationSummaryV1>, LocalChainErrorV1> {
    let Some(attestation) = &request.attestation else {
        return Ok(None);
    };
    let prepared = canonical_pipeline_prepare_attestation_v1(attestation)?;
    Ok(Some(CanonicalPipelineAttestationSummaryV1 {
        attestation_schema_version: attestation.attestation_schema_version,
        attestation_scope: attestation.attestation_scope,
        attestation_proof_kind: attestation.attestation_proof_kind,
        normalization_policy_version: attestation.normalization_policy_version,
        attestation_constraints: attestation.attestation_constraints.clone(),
        claim: attestation.claim.clone(),
        claim_digest: prepared.claim_digest,
        evidence_summary: prepared.evidence_summary.clone(),
        normalization_summary: prepared.normalization_summary.clone(),
        consistency_result: prepared.consistency_result.clone(),
        attestation_status: if actual_result == ScenarioResultV1::Accepted {
            CanonicalPipelineAttestationStatusV1::Accepted
        } else {
            CanonicalPipelineAttestationStatusV1::Rejected
        },
        attestation_failure_reason: canonical_pipeline_attestation_failure_detail_v1(
            request,
            &prepared,
            actual_result,
        ),
        proof_scope_honesty_note: "Aura only attests to claim consistency with the provided evidence set and typed provenance descriptor after deterministic normalization; it does not prove external real-world truth.".to_string(),
    }))
}

fn canonical_pipeline_attestation_proof_summary_v1(
    request: &CanonicalPipelineRequestV1,
    prepared: Option<&CanonicalPipelinePreparedAttestationV1>,
    stark_material: Option<&CanonicalPipelineAttestationStarkMaterialV1>,
    stark_public_inputs_digest: Option<[u8; 32]>,
    verification_passed: bool,
) -> Result<Option<CanonicalPipelineAttestationProofSummaryV1>, LocalChainErrorV1> {
    let Some(attestation) = &request.attestation else {
        return Ok(None);
    };
    let prepared = prepared.ok_or_else(|| {
        LocalChainErrorV1::InvalidFixture(
            "attestation proof summary requires prepared attestation material".to_string(),
        )
    })?;
    Ok(Some(CanonicalPipelineAttestationProofSummaryV1 {
        proof_kind: attestation.attestation_proof_kind,
        attestation_tuple_digest: prepared.attestation_tuple_digest,
        verification_passed,
        mock_policy_version: (attestation.attestation_proof_kind
            == CanonicalPipelineAttestationProofKindV1::Mock)
            .then_some(CANONICAL_PIPELINE_ATTESTATION_PROOF_MOCK_POLICY_VERSION_V1),
        stark_policy_version: (attestation.attestation_proof_kind
            == CanonicalPipelineAttestationProofKindV1::Stark)
            .then_some(CANONICAL_PIPELINE_STARK_POLICY_VERSION_V1),
        stark_public_inputs_digest,
        stark_proof_bytes_digest: stark_material
            .map(|material| material.proof_artifact.proof_bytes_digest),
        stark_proof_binding_digest: stark_material
            .map(|material| material.proof_artifact.proof_binding_digest),
    }))
}

fn canonical_pipeline_pre_execution_rejection_reason_v1(
    _request: &CanonicalPipelineRequestV1,
    prepared_attestation: Option<&CanonicalPipelinePreparedAttestationV1>,
) -> Option<(CanonicalPipelineFailureReasonCodeV1, String)> {
    if let Some(prepared) = prepared_attestation {
        if !prepared.provenance_summary.all_signature_checks_passed {
            return Some((
                CanonicalPipelineFailureReasonCodeV1::ProvenanceSignatureInvalid,
                "attestation provenance carried signature material that failed deterministic verification"
                    .to_string(),
            ));
        }
        if !prepared.consistency_result.consistent {
            return Some((
                CanonicalPipelineFailureReasonCodeV1::AttestationConsistencyMismatch,
                "attestation claim was not consistent with the normalized evidence derived from the supplied canonical evidence set".to_string(),
            ));
        }
    }
    None
}

fn canonical_pipeline_execution_rejection_reason_v1(
    request: &CanonicalPipelineRequestV1,
    prepared_attestation: Option<&CanonicalPipelinePreparedAttestationV1>,
    execution_error: Option<&LocalExecutionErrorV1>,
) -> (CanonicalPipelineFailureReasonCodeV1, String) {
    if let Some(reason) =
        canonical_pipeline_pre_execution_rejection_reason_v1(request, prepared_attestation)
    {
        return reason;
    }
    (
        CanonicalPipelineFailureReasonCodeV1::TransferExecutionRejected,
        execution_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "canonical execution rejected before proof production".to_string()),
    )
}

fn canonical_pipeline_status_explanation_v1(
    request_kind: CanonicalPipelineRequestKindV1,
    final_status: ScenarioResultV1,
    failure_reason_code: CanonicalPipelineFailureReasonCodeV1,
    detail: impl Into<String>,
) -> CanonicalPipelineStatusExplanationV1 {
    let failure_stage = match final_status {
        ScenarioResultV1::Accepted => CanonicalPipelineFailureStageV1::None,
        ScenarioResultV1::ExecutionRejected => CanonicalPipelineFailureStageV1::Execution,
        ScenarioResultV1::VerificationRejected => CanonicalPipelineFailureStageV1::Verification,
        ScenarioResultV1::SettlementRejected => CanonicalPipelineFailureStageV1::Settlement,
    };
    CanonicalPipelineStatusExplanationV1 {
        truth_artifact_kind: canonical_pipeline_truth_artifact_kind_v1(request_kind),
        request_kind,
        final_status,
        failure_stage,
        failure_reason_code,
        detail: detail.into(),
    }
}

fn canonical_pipeline_accepted_status_explanation_v1(
    request_kind: CanonicalPipelineRequestKindV1,
) -> CanonicalPipelineStatusExplanationV1 {
    canonical_pipeline_status_explanation_v1(
        request_kind,
        ScenarioResultV1::Accepted,
        CanonicalPipelineFailureReasonCodeV1::None,
        "canonical report accepted and locally committed",
    )
}

fn canonical_pipeline_settlement_reason_v1(
    actual_result: ScenarioResultV1,
) -> CanonicalPipelineSettlementReasonV1 {
    match actual_result {
        ScenarioResultV1::Accepted => CanonicalPipelineSettlementReasonV1::AcceptedAndCommitted,
        ScenarioResultV1::ExecutionRejected => {
            CanonicalPipelineSettlementReasonV1::NotRunExecutionRejected
        }
        ScenarioResultV1::VerificationRejected => {
            CanonicalPipelineSettlementReasonV1::RejectedVerificationMismatch
        }
        ScenarioResultV1::SettlementRejected => {
            CanonicalPipelineSettlementReasonV1::RejectedLocalSettlement
        }
    }
}

fn canonical_pipeline_accounting_summary_v1(
    request: &CanonicalPipelineRequestV1,
    burn_summary: &CanonicalPipelineBurnSummaryV1,
    burn_record: &CanonicalPipelineBurnRecordV1,
    actual_result: ScenarioResultV1,
    settlement_committed_state_root: Option<[u8; 32]>,
) -> CanonicalPipelineAccountingSummaryV1 {
    let settlement_record = CanonicalPipelineSettlementRecordV1 {
        settlement_intent: request.accounting.settlement_intent,
        settlement_status: stage_outcomes_for_actual_result_v1(actual_result).settlement_status,
        settlement_reason: canonical_pipeline_settlement_reason_v1(actual_result),
        committed_state_root: settlement_committed_state_root,
        future_token_binding_status:
            CanonicalPipelineFutureTokenBindingStatusV1::PendingExternalAnchor,
        future_token_binding_units: burn_summary.consumed_burn_units,
    };
    CanonicalPipelineAccountingSummaryV1 {
        accounting_policy_version: request.accounting.accounting_policy_version,
        payment_intent: request.accounting.payment_intent,
        settlement_intent: request.accounting.settlement_intent,
        declared_fee_units: burn_summary.declared_fee_units,
        computed_burn_units: burn_summary.computed_burn_units,
        consumed_burn_units: burn_summary.consumed_burn_units,
        burn_record: burn_record.clone(),
        settlement_record,
        accounting_consistent_with_burn: burn_summary.request_declares_correct_burn
            && burn_summary.recomputed_burn_matches_report
            && burn_summary.burn_consumed
            && burn_summary.consumed_burn_units == burn_summary.computed_burn_units
            && burn_record.declared_fee_units == burn_summary.declared_fee_units
            && burn_record.computed_burn_units == burn_summary.computed_burn_units
            && burn_record.consumed_burn_units == burn_summary.consumed_burn_units
            && burn_record.burned_amount == burn_summary.consumed_burn_units
            && burn_record.post_balance + burn_record.consumed_burn_units
                == burn_record.pre_balance,
        accounting_consistent_with_outcome: match actual_result {
            ScenarioResultV1::Accepted => settlement_committed_state_root.is_some(),
            ScenarioResultV1::ExecutionRejected
            | ScenarioResultV1::VerificationRejected
            | ScenarioResultV1::SettlementRejected => settlement_committed_state_root.is_none(),
        },
    }
}

fn build_proof_vector_from_fixtures(
    genesis: GenesisFixtureFileV1,
    scenario: ScenarioFixtureFileV1,
    proof_system: ProofSystemSelectionV1,
) -> Result<ProofVectorFixtureV1, LocalChainErrorV1> {
    if proof_system != ProofSystemSelectionV1::Stark {
        return Err(LocalChainErrorV1::InvalidFixture(
            "proof vectors currently support only the real STARK path".to_string(),
        ));
    }
    if scenario.tamper_public_inputs.is_some() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "proof vectors do not support public-input tampering".to_string(),
        ));
    }
    validate_scenario_fixture(&scenario)?;
    let expected_result = ScenarioResultV1::from_str(&scenario.expected_result)?;
    validate_proof_vector_expected_result(expected_result)?;
    if genesis.fixture_name != "genesis_state" {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unexpected genesis fixture name: {}",
            genesis.fixture_name
        )));
    }

    let genesis_runtime = parse_proof_vector_genesis(&genesis)?;
    let batch_runtime = parse_proof_vector_batch_from_scenario(&scenario)?;
    let pre_state = LocalStateV1::new(genesis_runtime.accounts.clone())?;
    let config = LocalExecutionConfigV1::new(genesis_runtime.rollup_id);
    let request = BatchExecutionRequestV1 {
        batch_number: batch_runtime.batch_number,
        parent_batch_commitment: batch_runtime.parent_batch_commitment,
        transactions: batch_runtime.transactions.clone(),
    };
    let executed = execute_transfer_batch_v1(&pre_state, &config, &request)?;
    let envelope = TransitionEnvelopeV1::from_executed_batch(&executed);
    let public_input_bytes = envelope.encode_bytes();
    let canonical_proof = prove_executed_batch_with_stark_prover_v1(&executed)?;

    Ok(ProofVectorFixtureV1 {
        fixture_name: scenario.fixture_name,
        proof_system,
        genesis: genesis_runtime,
        batch: batch_runtime,
        expected_transition: ProofVectorExpectedTransitionV1::from_executed_batch(&executed),
        expected_public_inputs: ProofVectorExpectedPublicInputsV1::from_envelope(
            &envelope,
            public_input_bytes,
        ),
        canonical_stark_proof_artifact: ProofVectorCanonicalStarkArtifactV1::from_runtime_artifact(
            &canonical_proof,
        ),
        proof_tamper: scenario
            .tamper_proof_binding_digest
            .map(|tamper| ProofVectorTamperV1 {
                target: ProofVectorTamperTargetV1::ProofBindingDigest,
                byte_offset: tamper.byte_offset,
                xor_with: tamper.xor_with,
            }),
        expected_result,
    })
}

fn stage_outcomes_for_actual_result_v1(
    actual_result: ScenarioResultV1,
) -> CanonicalPipelineStageOutcomesV1 {
    match actual_result {
        ScenarioResultV1::Accepted => CanonicalPipelineStageOutcomesV1 {
            execution_status: CanonicalPipelineExecutionStatusV1::Applied,
            verification_status: CanonicalPipelineVerificationStatusV1::Passed,
            settlement_status: CanonicalPipelineSettlementStatusV1::Accepted,
        },
        ScenarioResultV1::ExecutionRejected => CanonicalPipelineStageOutcomesV1 {
            execution_status: CanonicalPipelineExecutionStatusV1::Rejected,
            verification_status: CanonicalPipelineVerificationStatusV1::NotRun,
            settlement_status: CanonicalPipelineSettlementStatusV1::NotRun,
        },
        ScenarioResultV1::VerificationRejected => CanonicalPipelineStageOutcomesV1 {
            execution_status: CanonicalPipelineExecutionStatusV1::Applied,
            verification_status: CanonicalPipelineVerificationStatusV1::Rejected,
            settlement_status: CanonicalPipelineSettlementStatusV1::Rejected,
        },
        ScenarioResultV1::SettlementRejected => CanonicalPipelineStageOutcomesV1 {
            execution_status: CanonicalPipelineExecutionStatusV1::Applied,
            verification_status: CanonicalPipelineVerificationStatusV1::Passed,
            settlement_status: CanonicalPipelineSettlementStatusV1::Rejected,
        },
    }
}

fn canonical_pipeline_request_binding_hash_v1(
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_REQUEST_BINDING_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_request_binding_payload_v1(&mut bytes, request, ordered_accounts);
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_burn_metered_bytes_v1(
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_burn_metering_payload_v1(&mut bytes, request, ordered_accounts);
    bytes
}

fn extend_canonical_pipeline_request_binding_payload_v1(
    bytes: &mut Vec<u8>,
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) {
    extend_canonical_pipeline_burn_metering_payload_v1(bytes, request, ordered_accounts);
    extend_len_prefixed_bytes_v1(bytes, request.fixture_name.as_bytes());
    extend_optional_tamper_bytes_v1(bytes, request.tamper_public_inputs.as_ref());
    extend_optional_tamper_bytes_v1(bytes, request.tamper_proof_binding_digest.as_ref());
    extend_len_prefixed_bytes_v1(bytes, request.expected_result.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&request.economic.declared_fee_units.to_le_bytes());
}

fn extend_canonical_pipeline_burn_metering_payload_v1(
    bytes: &mut Vec<u8>,
    request: &CanonicalPipelineRequestV1,
    ordered_accounts: &[LocalAccountV1],
) {
    bytes.extend_from_slice(&CANONICAL_PIPELINE_SCHEMA_VERSION_V1.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.pipeline_id.as_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.proof_system.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&request.economic.economic_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.economic.request_kind.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.economic.burn_intent.as_str().as_bytes());
    bytes.extend_from_slice(&request.accounting.accounting_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.accounting.payment_intent.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(
        bytes,
        request.accounting.settlement_intent.as_str().as_bytes(),
    );
    bytes.extend_from_slice(&request.ledger.ledger_policy_version.to_le_bytes());
    bytes.extend_from_slice(&request.ledger.payer_account_id);
    bytes.extend_from_slice(&request.ledger.total_supply.to_le_bytes());
    bytes.extend_from_slice(&request.ledger.burned_supply.to_le_bytes());
    extend_canonical_pipeline_ledger_accounts_bytes_v1(bytes, &request.ledger.accounts);
    extend_canonical_pipeline_head_bytes_v1(bytes, &request.head);
    extend_canonical_pipeline_wallet_binding_bytes_v1(bytes, &request.wallet_binding);
    extend_canonical_pipeline_token_anchor_bytes_v1(bytes, &request.token_anchor);
    extend_optional_canonical_pipeline_attestation_bytes_v1(bytes, request.attestation.as_ref());
    bytes.extend_from_slice(&request.rollup_id);
    extend_canonical_pipeline_genesis_accounts_bytes_v1(bytes, ordered_accounts);
    bytes.extend_from_slice(&request.batch_number.to_le_bytes());
    bytes.extend_from_slice(&request.parent_batch_commitment);
    extend_canonical_pipeline_transactions_bytes_v1(bytes, &request.transactions);
}

fn canonical_pipeline_genesis_accounts_digest_v1(ordered_accounts: &[LocalAccountV1]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_GENESIS_ACCOUNTS_DIGEST_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_genesis_accounts_bytes_v1(&mut bytes, ordered_accounts);
    sha256_digest_v1(&bytes)
}

fn extend_canonical_pipeline_genesis_accounts_bytes_v1(
    bytes: &mut Vec<u8>,
    ordered_accounts: &[LocalAccountV1],
) {
    bytes.extend_from_slice(
        &u64::try_from(ordered_accounts.len())
            .expect("ordered account length fits in u64")
            .to_le_bytes(),
    );
    for account in ordered_accounts {
        bytes.extend_from_slice(&account.account_id);
        bytes.extend_from_slice(&account.balance.to_le_bytes());
        bytes.extend_from_slice(&account.nonce.to_le_bytes());
    }
}

fn canonical_pipeline_ledger_accounts_v1(
    request: &CanonicalPipelineRequestV1,
) -> CanonicalPipelineLedgerAccountsV1 {
    CanonicalPipelineLedgerAccountsV1 {
        material_version: CANONICAL_PIPELINE_LEDGER_ACCOUNTS_VERSION_V1,
        ordered_accounts: request.ledger.accounts.clone(),
    }
}

fn canonical_pipeline_ledger_accounts_digest_v1(
    ordered_accounts: &[CanonicalPipelineLedgerAccountV1],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_LEDGER_ACCOUNTS_DIGEST_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_ledger_accounts_bytes_v1(&mut bytes, ordered_accounts);
    sha256_digest_v1(&bytes)
}

fn extend_canonical_pipeline_ledger_accounts_bytes_v1(
    bytes: &mut Vec<u8>,
    ordered_accounts: &[CanonicalPipelineLedgerAccountV1],
) {
    bytes.extend_from_slice(
        &u64::try_from(ordered_accounts.len())
            .expect("ordered ledger account length fits in u64")
            .to_le_bytes(),
    );
    for account in ordered_accounts {
        bytes.extend_from_slice(&account.account_id);
        bytes.extend_from_slice(&account.balance.to_le_bytes());
    }
}

fn extend_canonical_pipeline_ledger_state_bytes_v1(
    bytes: &mut Vec<u8>,
    ledger_policy_version: u32,
    payer_account_id: [u8; 32],
    total_supply: u64,
    burned_supply: u64,
    ordered_accounts: &[CanonicalPipelineLedgerAccountV1],
) {
    bytes.extend_from_slice(&ledger_policy_version.to_le_bytes());
    bytes.extend_from_slice(&payer_account_id);
    bytes.extend_from_slice(&total_supply.to_le_bytes());
    bytes.extend_from_slice(&burned_supply.to_le_bytes());
    extend_canonical_pipeline_ledger_accounts_bytes_v1(bytes, ordered_accounts);
}

fn canonical_pipeline_ledger_state_commitment_digest_v1(
    ledger_policy_version: u32,
    payer_account_id: [u8; 32],
    total_supply: u64,
    burned_supply: u64,
    ordered_accounts: &[CanonicalPipelineLedgerAccountV1],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_ledger_state_bytes_v1(
        &mut bytes,
        ledger_policy_version,
        payer_account_id,
        total_supply,
        burned_supply,
        ordered_accounts,
    );
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_ledger_transition_v1(
    request: &CanonicalPipelineRequestV1,
    burn_summary: &CanonicalPipelineBurnSummaryV1,
    request_binding_hash: [u8; 32],
) -> Result<
    (
        CanonicalPipelineBurnRecordV1,
        CanonicalPipelineLedgerSummaryV1,
    ),
    LocalChainErrorV1,
> {
    let payer = canonical_pipeline_ledger_payer_account_v1(request)?;
    let pre_balance = payer.balance;
    let burned_amount = burn_summary.consumed_burn_units;
    let post_balance = pre_balance.checked_sub(burned_amount).ok_or_else(|| {
        LocalChainErrorV1::InvalidFixture(
            "canonical pipeline ledger payer balance underflowed during burn".to_string(),
        )
    })?;
    let mut post_accounts = request.ledger.accounts.clone();
    let payer_index = post_accounts
        .iter()
        .position(|account| account.account_id == request.ledger.payer_account_id)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline ledger payer_account_id must exist in ledger.accounts"
                    .to_string(),
            )
        })?;
    post_accounts[payer_index].balance = post_balance;
    let burned_supply_after = request
        .ledger
        .burned_supply
        .checked_add(burned_amount)
        .ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline ledger burned_supply overflowed".to_string(),
            )
        })?;
    let circulating_supply_before = canonical_pipeline_ledger_circulating_supply_v1(
        request.ledger.total_supply,
        request.ledger.burned_supply,
    )?;
    let circulating_supply_after = canonical_pipeline_ledger_circulating_supply_v1(
        request.ledger.total_supply,
        burned_supply_after,
    )?;
    let pre_commitment = canonical_pipeline_ledger_state_commitment_digest_v1(
        request.ledger.ledger_policy_version,
        request.ledger.payer_account_id,
        request.ledger.total_supply,
        request.ledger.burned_supply,
        &request.ledger.accounts,
    );
    let post_commitment = canonical_pipeline_ledger_state_commitment_digest_v1(
        request.ledger.ledger_policy_version,
        request.ledger.payer_account_id,
        request.ledger.total_supply,
        burned_supply_after,
        &post_accounts,
    );
    let burn_record = CanonicalPipelineBurnRecordV1 {
        burn_reason: burn_summary.burn_reason,
        burn_category: burn_summary.burn_category,
        fee_disposition: CanonicalPipelineFeeDispositionV1::BurnedForCanonicalTruth,
        account_id: request.ledger.payer_account_id,
        pre_balance,
        post_balance,
        burned_amount,
        declared_fee_units: burn_summary.declared_fee_units,
        computed_burn_units: burn_summary.computed_burn_units,
        consumed_burn_units: burn_summary.consumed_burn_units,
        report_pipeline_id: request.pipeline_id.clone(),
        report_request_binding_hash: request_binding_hash,
    };
    let ledger_consistent_with_supply =
        canonical_pipeline_ledger_total_balance_v1(&request.ledger.accounts)?
            == circulating_supply_before
            && canonical_pipeline_ledger_total_balance_v1(&post_accounts)?
                == circulating_supply_after;
    let ledger_summary = CanonicalPipelineLedgerSummaryV1 {
        ledger_policy_version: request.ledger.ledger_policy_version,
        payer_account_id: request.ledger.payer_account_id,
        total_supply: request.ledger.total_supply,
        burned_supply_before: request.ledger.burned_supply,
        burned_supply_after,
        ledger_account_count: u64::try_from(request.ledger.accounts.len()).map_err(|_| {
            LocalChainErrorV1::InvalidFixture(
                "canonical pipeline ledger account count exceeds u64 range".to_string(),
            )
        })?,
        circulating_supply_before,
        circulating_supply_after,
        ledger_consistent_with_request: burn_record.report_pipeline_id == request.pipeline_id
            && burn_record.report_request_binding_hash == request_binding_hash
            && burn_record.account_id == request.ledger.payer_account_id,
        ledger_consistent_with_burn: burn_record.burned_amount == burn_summary.consumed_burn_units
            && burn_record.computed_burn_units == burn_summary.computed_burn_units
            && burn_record.declared_fee_units == burn_summary.declared_fee_units
            && burn_record.pre_balance >= burn_record.consumed_burn_units
            && burn_record.post_balance + burn_record.consumed_burn_units
                == burn_record.pre_balance,
        ledger_consistent_with_supply,
        ledger_state_commitment: CanonicalPipelineLedgerStateCommitmentV1 {
            commitment_version: CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_VERSION_V1,
            pre_ledger_state_commitment: pre_commitment,
            post_ledger_state_commitment: post_commitment,
        },
    };
    Ok((burn_record, ledger_summary))
}

fn canonical_pipeline_wallet_binding_digest_v1(
    wallet_binding: &CanonicalPipelineWalletBindingV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_WALLET_BINDING_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_wallet_binding_bytes_v1(&mut bytes, wallet_binding);
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_wallet_binding_summary_v1(
    request: &CanonicalPipelineRequestV1,
) -> CanonicalPipelineWalletBindingSummaryV1 {
    CanonicalPipelineWalletBindingSummaryV1 {
        wallet_binding_version: request.wallet_binding.wallet_binding_version,
        account_id: request.wallet_binding.account_id,
        wallet_address: request.wallet_binding.wallet_address.clone(),
        wallet_binding_digest: canonical_pipeline_wallet_binding_digest_v1(&request.wallet_binding),
        binding_consistent_with_account: request.wallet_binding.account_id
            == request.ledger.payer_account_id,
    }
}

fn canonical_pipeline_wallet_binding_mismatch_detail_v1(
    request: &CanonicalPipelineRequestV1,
) -> Option<String> {
    (request.wallet_binding.account_id != request.ledger.payer_account_id).then(|| {
        format!(
            "wallet_binding.account_id {} does not match ledger.payer_account_id {}",
            encode_hex(&request.wallet_binding.account_id),
            encode_hex(&request.ledger.payer_account_id)
        )
    })
}

fn canonical_pipeline_token_anchor_digest_v1(
    token_anchor: &CanonicalPipelineTokenAnchorV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_TOKEN_ANCHOR_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_token_anchor_bytes_v1(&mut bytes, token_anchor);
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_token_anchor_summary_v1(
    request: &CanonicalPipelineRequestV1,
) -> CanonicalPipelineTokenAnchorSummaryV1 {
    let anchor_verification_status = match (
        request.token_anchor.external_balance_reference.as_ref(),
        request.token_anchor.enforce_external_match,
        request.token_anchor.expected_external_balance,
    ) {
        (None, _, _) => CanonicalPipelineExternalAnchorVerificationStatusV1::NotRequested,
        (Some(reference), _, _) if !reference.connected => {
            CanonicalPipelineExternalAnchorVerificationStatusV1::Disconnected
        }
        (Some(reference), true, Some(expected)) if reference.observed_balance != Some(expected) => {
            CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
        }
        (Some(_), true, Some(_)) | (Some(_), false, _) => {
            CanonicalPipelineExternalAnchorVerificationStatusV1::Accepted
        }
        (Some(_), true, None) => CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected,
    };
    CanonicalPipelineTokenAnchorSummaryV1 {
        token_policy_version: request.token_anchor.token_policy_version,
        network_mode: request.token_anchor.network_mode,
        settlement_anchor_type: request.token_anchor.settlement_anchor_type,
        anchor_verification_status,
        external_balance_reference: request.token_anchor.external_balance_reference.clone(),
        expected_external_balance: request.token_anchor.expected_external_balance,
        token_anchor_digest: canonical_pipeline_token_anchor_digest_v1(&request.token_anchor),
    }
}

fn canonical_pipeline_external_anchor_rejection_detail_v1() -> String {
    "external token anchor verification rejected the otherwise verified canonical transition"
        .to_string()
}

fn canonical_pipeline_settlement_override_v1(
    request: &CanonicalPipelineRequestV1,
    token_anchor_summary: &CanonicalPipelineTokenAnchorSummaryV1,
) -> Option<(CanonicalPipelineFailureReasonCodeV1, String)> {
    canonical_pipeline_wallet_binding_mismatch_detail_v1(request)
        .map(|detail| {
            (
                CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch,
                detail,
            )
        })
        .or_else(|| {
            (token_anchor_summary.anchor_verification_status
                == CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected)
                .then(|| {
                    (
                        CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected,
                        canonical_pipeline_external_anchor_rejection_detail_v1(),
                    )
                })
        })
}

fn canonical_pipeline_authority_mode_v1(
    options: &CanonicalPipelineRunOptionsV1,
) -> CanonicalPipelineHeadAuthorityModeV1 {
    if !options.stateless && options.head_state_path.is_some() {
        CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent
    } else {
        CanonicalPipelineHeadAuthorityModeV1::StatelessNonAuthoritative
    }
}

fn canonical_pipeline_load_head_state_v1(
    path: &str,
) -> Result<Option<CanonicalPipelineHeadStateFileV1>, LocalChainErrorV1> {
    if !Path::new(path).is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let file: CanonicalPipelineHeadStateFileV1 = serde_json::from_slice(&bytes)?;
    if file.state_file_version != CANONICAL_PIPELINE_HEAD_STATE_FILE_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported head state_file_version: expected {}, got {}",
            CANONICAL_PIPELINE_HEAD_STATE_FILE_VERSION_V1, file.state_file_version
        )));
    }
    Ok(Some(file))
}

fn canonical_pipeline_write_head_state_v1(
    path: &str,
    summary: &CanonicalPipelineHeadTransitionSummaryV1,
) -> Result<(), LocalChainErrorV1> {
    let file = CanonicalPipelineHeadStateFileV1 {
        state_file_version: CANONICAL_PIPELINE_HEAD_STATE_FILE_VERSION_V1,
        settlement_head_version: summary.settlement_head_version,
        current_head_hash_hex: encode_hex(&summary.current_head_hash),
        head_sequence_number: summary.head_sequence_number,
        canonical_head_commitment_hex: encode_hex(&summary.canonical_head_commitment),
        request_canonical_digest_hex: encode_hex(&summary.request_canonical_digest),
        report_digest_hex: encode_hex(&summary.report_digest),
    };
    let bytes = serde_json::to_vec_pretty(&file)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn canonical_pipeline_report_digest_v1(report: &CanonicalPipelineReportV1) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_REPORT_DIGEST_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&report.pipeline_schema_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, report.pipeline_id.as_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, report.fixture_name.as_bytes());
    extend_len_prefixed_bytes_v1(&mut bytes, report.proof_system.as_fixture_str().as_bytes());
    extend_len_prefixed_bytes_v1(
        &mut bytes,
        report.expected_result.as_fixture_str().as_bytes(),
    );
    extend_len_prefixed_bytes_v1(&mut bytes, report.actual_result.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&report.pre_state_root);
    match report.executed_post_state_root {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value);
        }
        None => bytes.push(0),
    }
    match report.settlement_committed_state_root {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&report.request_audit.request_binding_hash);
    bytes.extend_from_slice(
        &report
            .ledger_summary
            .ledger_state_commitment
            .pre_ledger_state_commitment,
    );
    bytes.extend_from_slice(
        &report
            .ledger_summary
            .ledger_state_commitment
            .post_ledger_state_commitment,
    );
    bytes.extend_from_slice(&report.accounting_summary.burn_record.account_id);
    bytes.extend_from_slice(
        &report
            .accounting_summary
            .burn_record
            .pre_balance
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &report
            .accounting_summary
            .burn_record
            .post_balance
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &report
            .accounting_summary
            .burn_record
            .burned_amount
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&report.wallet_binding_summary.wallet_binding_digest);
    bytes.extend_from_slice(&report.token_anchor_summary.token_anchor_digest);
    extend_len_prefixed_bytes_v1(
        &mut bytes,
        report
            .status_explanation
            .failure_reason_code
            .as_str()
            .as_bytes(),
    );
    if let Some(attestation_summary) = &report.attestation_summary {
        bytes.push(1);
        bytes.extend_from_slice(&attestation_summary.claim_digest);
        bytes.extend_from_slice(&attestation_summary.evidence_summary.evidence_root_digest);
        bytes.push(u8::from(attestation_summary.consistency_result.consistent));
    } else {
        bytes.push(0);
    }
    if let Some(attestation_proof_summary) = &report.attestation_proof_summary {
        bytes.push(1);
        bytes.extend_from_slice(&attestation_proof_summary.attestation_tuple_digest);
        bytes.push(u8::from(attestation_proof_summary.verification_passed));
        if let Some(digest) = attestation_proof_summary.stark_public_inputs_digest {
            bytes.push(1);
            bytes.extend_from_slice(&digest);
        } else {
            bytes.push(0);
        }
    } else {
        bytes.push(0);
    }
    if let Some(provenance_summary) = &report.provenance_summary {
        bytes.push(1);
        bytes.extend_from_slice(&provenance_summary.provenance_root_digest);
        bytes.push(u8::from(provenance_summary.all_signature_checks_passed));
    } else {
        bytes.push(0);
    }
    if let Some(public_inputs) = &report.public_inputs {
        bytes.push(1);
        bytes.extend_from_slice(&public_inputs.public_inputs_hash);
    } else {
        bytes.push(0);
    }
    if let Some(proof_artifact) = &report.proof_artifact {
        bytes.push(1);
        bytes.extend_from_slice(&proof_artifact.proof_binding_digest);
    } else {
        bytes.push(0);
    }
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_head_transition_summary_v1(
    request: &CanonicalPipelineRequestV1,
    report_digest: [u8; 32],
    burn_record: &CanonicalPipelineBurnRecordV1,
    ledger_summary: &CanonicalPipelineLedgerSummaryV1,
    authority_mode: CanonicalPipelineHeadAuthorityModeV1,
) -> CanonicalPipelineHeadTransitionSummaryV1 {
    let mut commitment_bytes = Vec::new();
    commitment_bytes.extend_from_slice(CANONICAL_PIPELINE_HEAD_TRANSITION_DOMAIN_SEPARATOR_V1);
    commitment_bytes.extend_from_slice(&request.head.settlement_head_version.to_le_bytes());
    commitment_bytes.extend_from_slice(&request.head.previous_head_hash);
    commitment_bytes.extend_from_slice(&canonical_pipeline_request_binding_hash_v1(
        request,
        &LocalStateV1::new(request.accounts.clone())
            .expect("validated accounts")
            .ordered_accounts(),
    ));
    commitment_bytes.extend_from_slice(&report_digest);
    commitment_bytes.extend_from_slice(
        &ledger_summary
            .ledger_state_commitment
            .pre_ledger_state_commitment,
    );
    commitment_bytes.extend_from_slice(
        &ledger_summary
            .ledger_state_commitment
            .post_ledger_state_commitment,
    );
    commitment_bytes.extend_from_slice(&burn_record.account_id);
    commitment_bytes.extend_from_slice(&burn_record.pre_balance.to_le_bytes());
    commitment_bytes.extend_from_slice(&burn_record.post_balance.to_le_bytes());
    commitment_bytes.extend_from_slice(&burn_record.burned_amount.to_le_bytes());
    let canonical_head_commitment = sha256_digest_v1(&commitment_bytes);
    let mut current_head_bytes = Vec::new();
    current_head_bytes.extend_from_slice(CANONICAL_PIPELINE_HEAD_HASH_DOMAIN_SEPARATOR_V1);
    current_head_bytes.extend_from_slice(&request.head.settlement_head_version.to_le_bytes());
    current_head_bytes.extend_from_slice(&request.head.head_sequence_number.to_le_bytes());
    current_head_bytes.extend_from_slice(&canonical_head_commitment);
    CanonicalPipelineHeadTransitionSummaryV1 {
        settlement_head_version: request.head.settlement_head_version,
        authority_mode,
        head_sequence_number: request.head.head_sequence_number,
        previous_head_hash: request.head.previous_head_hash,
        current_head_hash: sha256_digest_v1(&current_head_bytes),
        canonical_head_commitment,
        request_canonical_digest: canonical_pipeline_request_binding_hash_v1(
            request,
            &LocalStateV1::new(request.accounts.clone())
                .expect("validated accounts")
                .ordered_accounts(),
        ),
        report_digest,
    }
}

fn canonical_pipeline_head_mismatch_v1(
    request: &CanonicalPipelineRequestV1,
    persisted: Option<&CanonicalPipelineHeadStateFileV1>,
) -> Result<Option<String>, LocalChainErrorV1> {
    match persisted {
        Some(state) => {
            let persisted_hash = decode_hex_32_field(
                &state.current_head_hash_hex,
                "head_state.current_head_hash_hex",
            )?;
            if request.head.previous_head_hash != persisted_hash {
                return Ok(Some(format!(
                    "requested previous_head_hash {} does not match persisted authoritative head {}",
                    encode_hex(&request.head.previous_head_hash),
                    state.current_head_hash_hex
                )));
            }
            if request.head.head_sequence_number != state.head_sequence_number.saturating_add(1) {
                return Ok(Some(format!(
                    "requested head_sequence_number {} must equal persisted head_sequence_number + 1 ({})",
                    request.head.head_sequence_number,
                    state.head_sequence_number.saturating_add(1)
                )));
            }
            Ok(None)
        }
        None => {
            if request.head.previous_head_hash != CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V1 {
                Ok(Some(format!(
                    "first authoritative request must reference the genesis head {}",
                    encode_hex(&CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V1)
                )))
            } else if request.head.head_sequence_number != 1 {
                Ok(Some(
                    "first authoritative request must use head_sequence_number 1".to_string(),
                ))
            } else {
                Ok(None)
            }
        }
    }
}

fn canonical_pipeline_placeholder_head_transition_summary_v1(
    request: &CanonicalPipelineRequestV1,
    authority_mode: CanonicalPipelineHeadAuthorityModeV1,
    request_canonical_digest: [u8; 32],
) -> CanonicalPipelineHeadTransitionSummaryV1 {
    CanonicalPipelineHeadTransitionSummaryV1 {
        settlement_head_version: request.head.settlement_head_version,
        authority_mode,
        head_sequence_number: request.head.head_sequence_number,
        previous_head_hash: request.head.previous_head_hash,
        current_head_hash: [0u8; 32],
        canonical_head_commitment: [0u8; 32],
        request_canonical_digest,
        report_digest: [0u8; 32],
    }
}

fn finalize_canonical_pipeline_report_v1(
    request: &CanonicalPipelineRequestV1,
    options: &CanonicalPipelineRunOptionsV1,
    burn_record: &CanonicalPipelineBurnRecordV1,
    _prepared_attestation: Option<&CanonicalPipelinePreparedAttestationV1>,
    mut report: CanonicalPipelineReportV1,
) -> Result<CanonicalPipelineReportV1, LocalChainErrorV1> {
    let authority_mode = canonical_pipeline_authority_mode_v1(options);
    let persisted_head = match (authority_mode, options.head_state_path.as_deref()) {
        (CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent, Some(path)) => {
            canonical_pipeline_load_head_state_v1(path)?
        }
        _ => None,
    };
    if authority_mode == CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent
        && matches!(
            report.actual_result,
            ScenarioResultV1::Accepted | ScenarioResultV1::SettlementRejected
        )
    {
        if let Some(detail) = canonical_pipeline_head_mismatch_v1(request, persisted_head.as_ref())?
        {
            report.actual_result = ScenarioResultV1::SettlementRejected;
            report.settlement_committed_state_root = None;
            report.stage_outcomes = stage_outcomes_for_actual_result_v1(report.actual_result);
            report.status_explanation = canonical_pipeline_status_explanation_v1(
                request.economic.request_kind,
                report.actual_result,
                CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch,
                detail,
            );
            report.accounting_summary = canonical_pipeline_accounting_summary_v1(
                request,
                &report.burn_summary,
                burn_record,
                report.actual_result,
                None,
            );
            report.attestation_summary =
                canonical_pipeline_attestation_summary_v1(request, report.actual_result)?;
        }
    }
    let report_digest = canonical_pipeline_report_digest_v1(&report);
    report.head_transition_summary = canonical_pipeline_head_transition_summary_v1(
        request,
        report_digest,
        burn_record,
        &report.ledger_summary,
        authority_mode,
    );
    if request.expected_result != report.actual_result {
        return Err(LocalChainErrorV1::UnexpectedResult {
            expected: request.expected_result,
            actual: report.actual_result,
        });
    }
    assert_canonical_pipeline_report_matches_request_v1(request, &report)?;
    validate_canonical_pipeline_report_v1(&report)?;
    if authority_mode == CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent
        && report.status_explanation.failure_reason_code
            != CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
    {
        if let Some(path) = options.head_state_path.as_deref() {
            canonical_pipeline_write_head_state_v1(path, &report.head_transition_summary)?;
        }
    }
    Ok(report)
}

fn canonical_pipeline_transactions_digest_v1(transactions: &[TransferTransactionV1]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PIPELINE_TRANSACTIONS_DIGEST_DOMAIN_SEPARATOR_V1);
    extend_canonical_pipeline_transactions_bytes_v1(&mut bytes, transactions);
    sha256_digest_v1(&bytes)
}

fn canonical_pipeline_genesis_accounts_v1(
    ordered_accounts: &[LocalAccountV1],
) -> CanonicalPipelineGenesisAccountsV1 {
    CanonicalPipelineGenesisAccountsV1 {
        material_version: CANONICAL_PIPELINE_GENESIS_ACCOUNTS_VERSION_V1,
        ordered_accounts: ordered_accounts.to_vec(),
    }
}

fn canonical_pipeline_transactions_commitment_expansion_v1(
    transactions: &[TransferTransactionV1],
) -> CanonicalPipelineTransactionsCommitmentExpansionV1 {
    let transaction_bytes = transactions
        .iter()
        .map(TransferTransactionV1::canonical_bytes)
        .collect::<Vec<_>>();
    CanonicalPipelineTransactionsCommitmentExpansionV1 {
        expansion_version: CANONICAL_PIPELINE_TRANSACTIONS_EXPANSION_VERSION_V1,
        transactions_commitment: derive_transactions_commitment_v1(&transaction_bytes),
        ordered_transactions: transactions.to_vec(),
    }
}

fn canonical_pipeline_outcomes_commitment_expansion_v1(
    executed: &aura_l2_execution_v1::ExecutedBatchV1,
) -> CanonicalPipelineOutcomesCommitmentExpansionV1 {
    CanonicalPipelineOutcomesCommitmentExpansionV1 {
        expansion_version: CANONICAL_PIPELINE_OUTCOMES_EXPANSION_VERSION_V1,
        outcomes_commitment: executed.outcomes_commitment,
        outcomes: executed.outcomes.clone(),
        applied_steps: executed.applied_steps.clone(),
    }
}

fn canonical_pipeline_batch_context_commitment_expansion_v1(
    config: &LocalExecutionConfigV1,
) -> CanonicalPipelineBatchContextCommitmentExpansionV1 {
    let batch_context = config.batch_context();
    CanonicalPipelineBatchContextCommitmentExpansionV1 {
        expansion_version: CANONICAL_PIPELINE_BATCH_CONTEXT_EXPANSION_VERSION_V1,
        batch_context_commitment: batch_context.batch_context_commitment(),
        transition_binding_version: TRANSITION_BINDING_VERSION_V1,
        system_config: *config,
        fee_parameters: CanonicalPipelineFeeParametersExpansionV1 {
            fee_per_transfer: ZERO_FEE_PER_TRANSFER_V1,
        },
        validity_reference: CanonicalPipelineValidityReferenceExpansionV1 {
            kind: CanonicalPipelineValidityReferenceKindV1::None,
            none_marker: 0,
        },
        execution_constants: CanonicalPipelineExecutionConstantsExpansionV1 {
            transfer_tx_version: TRANSFER_TX_VERSION_V1,
            transition_binding_version: TRANSITION_BINDING_VERSION_V1,
            applied_status: EXECUTION_OUTCOME_STATUS_APPLIED_V1,
        },
    }
}

fn canonical_pipeline_fee_summary_commitment_expansion_v1(
    fee_summary: &LocalFeeSummaryV1,
) -> CanonicalPipelineFeeSummaryCommitmentExpansionV1 {
    CanonicalPipelineFeeSummaryCommitmentExpansionV1 {
        expansion_version: CANONICAL_PIPELINE_FEE_SUMMARY_EXPANSION_VERSION_V1,
        fee_summary_commitment: fee_summary.commitment(),
        fee_summary: *fee_summary,
    }
}

fn validate_canonical_pipeline_outcomes_expansion_v1(
    expansion: &CanonicalPipelineOutcomesCommitmentExpansionV1,
) -> Result<(), LocalChainErrorV1> {
    if expansion.outcomes.len() != expansion.applied_steps.len() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report commitment_expansions.outcomes must expose one applied_step per outcome"
                .to_string(),
        ));
    }

    for (outcome, step) in expansion
        .outcomes
        .iter()
        .zip(expansion.applied_steps.iter())
    {
        let expected_sender_nonce_after =
            step.sender_nonce_before
                .checked_add(1)
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical report commitment_expansions.outcomes contains sender nonce overflow"
                            .to_string(),
                    )
                })?;
        if step.sender_nonce_after != expected_sender_nonce_after {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report commitment_expansions.outcomes contains a non-canonical sender nonce transition"
                    .to_string(),
            ));
        }

        let expected_sender_balance_after = step
            .sender_balance_before
            .checked_sub(step.amount)
            .and_then(|balance| balance.checked_sub(step.fee_charged))
            .ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "canonical report commitment_expansions.outcomes contains an impossible sender balance transition"
                        .to_string(),
                )
            })?;
        if step.sender_balance_after != expected_sender_balance_after {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report commitment_expansions.outcomes contains a non-canonical sender balance transition"
                    .to_string(),
            ));
        }

        let expected_recipient_balance_after =
            step.recipient_balance_before
                .checked_add(step.amount)
                .ok_or_else(|| {
                    LocalChainErrorV1::InvalidFixture(
                        "canonical report commitment_expansions.outcomes contains recipient balance overflow"
                            .to_string(),
                    )
                })?;
        if step.recipient_balance_after != expected_recipient_balance_after {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report commitment_expansions.outcomes contains a non-canonical recipient balance transition"
                    .to_string(),
            ));
        }

        let expected_touched_accounts_commitment = derive_touched_accounts_commitment_v1(
            &step.sender_account_id,
            &step.recipient_account_id,
        );
        let expected_operation_result_commitment = derive_transfer_result_commitment_v1(
            step.amount,
            step.sender_balance_before,
            step.sender_balance_after,
            step.recipient_balance_before,
            step.recipient_balance_after,
        );
        if outcome.tx_index != step.tx_index
            || outcome.sender_account_id != step.sender_account_id
            || outcome.consumed_nonce != step.sender_nonce_before
            || outcome.fee_charged != step.fee_charged
            || outcome.status != EXECUTION_OUTCOME_STATUS_APPLIED_V1
            || outcome.touched_accounts_commitment != expected_touched_accounts_commitment
            || outcome.operation_result_commitment != expected_operation_result_commitment
        {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report commitment_expansions.outcomes contradicts its applied_steps"
                    .to_string(),
            ));
        }
    }

    let outcome_bytes = expansion
        .outcomes
        .iter()
        .map(ExecutionOutcomeV1::canonical_bytes)
        .collect::<Vec<_>>();
    if expansion.outcomes_commitment != derive_outcomes_commitment_v1(&outcome_bytes) {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report commitment_expansions.outcomes_commitment does not match outcomes"
                .to_string(),
        ));
    }

    Ok(())
}

fn extend_canonical_pipeline_transactions_bytes_v1(
    bytes: &mut Vec<u8>,
    transactions: &[TransferTransactionV1],
) {
    bytes.extend_from_slice(
        &u64::try_from(transactions.len())
            .expect("transaction length fits in u64")
            .to_le_bytes(),
    );
    for transaction in transactions {
        bytes.extend_from_slice(&transaction.tx_version.to_le_bytes());
        bytes.extend_from_slice(&transaction.sender_account_id);
        bytes.extend_from_slice(&transaction.recipient_account_id);
        bytes.extend_from_slice(&transaction.sender_nonce.to_le_bytes());
        bytes.extend_from_slice(&transaction.amount.to_le_bytes());
    }
}

fn extend_len_prefixed_bytes_v1(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(
        &u64::try_from(value.len())
            .expect("length fits in u64")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value);
}

fn extend_optional_tamper_bytes_v1(bytes: &mut Vec<u8>, tamper: Option<&ByteTamperFixtureV1>) {
    match tamper {
        Some(tamper) => {
            bytes.push(1);
            bytes.extend_from_slice(
                &u64::try_from(tamper.byte_offset)
                    .expect("tamper offset fits in u64")
                    .to_le_bytes(),
            );
            bytes.push(tamper.xor_with);
        }
        None => bytes.push(0),
    }
}

fn extend_canonical_pipeline_head_bytes_v1(
    bytes: &mut Vec<u8>,
    head: &CanonicalPipelineSettlementHeadRequestV1,
) {
    bytes.extend_from_slice(&head.settlement_head_version.to_le_bytes());
    bytes.extend_from_slice(&head.previous_head_hash);
    bytes.extend_from_slice(&head.head_sequence_number.to_le_bytes());
}

fn extend_canonical_pipeline_wallet_binding_bytes_v1(
    bytes: &mut Vec<u8>,
    wallet_binding: &CanonicalPipelineWalletBindingV1,
) {
    bytes.extend_from_slice(&wallet_binding.wallet_binding_version.to_le_bytes());
    bytes.extend_from_slice(&wallet_binding.account_id);
    extend_len_prefixed_bytes_v1(bytes, wallet_binding.wallet_address.as_bytes());
}

fn extend_optional_canonical_pipeline_external_balance_reference_bytes_v1(
    bytes: &mut Vec<u8>,
    reference: Option<&CanonicalPipelineExternalBalanceReferenceV1>,
) {
    match reference {
        Some(reference) => {
            bytes.push(1);
            extend_len_prefixed_bytes_v1(bytes, reference.reference_id.as_bytes());
            match reference.observed_balance {
                Some(balance) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&balance.to_le_bytes());
                }
                None => bytes.push(0),
            }
            match reference.observed_slot {
                Some(slot) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&slot.to_le_bytes());
                }
                None => bytes.push(0),
            }
            bytes.push(u8::from(reference.connected));
        }
        None => bytes.push(0),
    }
}

fn extend_canonical_pipeline_token_anchor_bytes_v1(
    bytes: &mut Vec<u8>,
    token_anchor: &CanonicalPipelineTokenAnchorV1,
) {
    bytes.extend_from_slice(&token_anchor.token_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, token_anchor.network_mode.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(
        bytes,
        token_anchor.settlement_anchor_type.as_str().as_bytes(),
    );
    extend_optional_canonical_pipeline_external_balance_reference_bytes_v1(
        bytes,
        token_anchor.external_balance_reference.as_ref(),
    );
    bytes.push(u8::from(token_anchor.enforce_external_match));
    match token_anchor.expected_external_balance {
        Some(balance) => {
            bytes.push(1);
            bytes.extend_from_slice(&balance.to_le_bytes());
        }
        None => bytes.push(0),
    }
}

fn extend_optional_canonical_pipeline_attestation_bytes_v1(
    bytes: &mut Vec<u8>,
    attestation: Option<&CanonicalPipelineAttestationRequestV1>,
) {
    match attestation {
        Some(attestation) => {
            bytes.push(1);
            bytes.extend_from_slice(&attestation.attestation_schema_version.to_le_bytes());
            extend_len_prefixed_bytes_v1(bytes, attestation.attestation_scope.as_str().as_bytes());
            extend_len_prefixed_bytes_v1(
                bytes,
                attestation
                    .attestation_proof_kind
                    .as_fixture_str()
                    .as_bytes(),
            );
            bytes.extend_from_slice(&attestation.normalization_policy_version.to_le_bytes());
            bytes.push(u8::from(
                attestation.attestation_constraints.require_unique_labels,
            ));
            bytes.extend_from_slice(
                &attestation
                    .attestation_constraints
                    .max_evidence_items
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(
                &attestation
                    .attestation_constraints
                    .max_total_normalized_bytes
                    .to_le_bytes(),
            );
            extend_canonical_pipeline_attestation_claim_bytes_v1(bytes, &attestation.claim);
            bytes.extend_from_slice(
                &u64::try_from(attestation.evidence_items.len())
                    .expect("attestation evidence count fits in u64")
                    .to_le_bytes(),
            );
            for item in &attestation.evidence_items {
                extend_canonical_pipeline_attestation_evidence_item_bytes_v1(bytes, item);
            }
            extend_optional_tamper_bytes_v1(
                bytes,
                attestation.tamper_stark_public_inputs_digest.as_ref(),
            );
            extend_optional_tamper_bytes_v1(bytes, attestation.tamper_stark_proof_bytes.as_ref());
        }
        None => bytes.push(0),
    }
}

fn sha256_digest_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn transition_binding_hash_from_public_input_bytes(
    public_input_bytes: &[u8; PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(
        TRANSITION_BINDING_DOMAIN_SEPARATOR_V1.len() + PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1,
    );
    bytes.extend_from_slice(TRANSITION_BINDING_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(public_input_bytes);
    sha256_digest_v1(&bytes)
}

fn assert_canonical_pipeline_report_matches_request_v1(
    request: &CanonicalPipelineRequestV1,
    report: &CanonicalPipelineReportV1,
) -> Result<(), LocalChainErrorV1> {
    let report_request = canonical_pipeline_request_from_report_v1(report)?;
    if &report_request != request {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report embedded request material drifted from request".to_string(),
        ));
    }
    Ok(())
}

fn canonical_pipeline_request_from_report_v1(
    report: &CanonicalPipelineReportV1,
) -> Result<CanonicalPipelineRequestV1, LocalChainErrorV1> {
    let attestation = if let Some(summary) = report.attestation_summary.as_ref() {
        let provenance_summary = report.provenance_summary.as_ref().ok_or_else(|| {
            LocalChainErrorV1::InvalidFixture(
                "attestation_summary requires provenance_summary".to_string(),
            )
        })?;
        let attestation_proof_summary =
            report.attestation_proof_summary.as_ref().ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "attestation_summary requires attestation_proof_summary".to_string(),
                )
            })?;
        Some(CanonicalPipelineAttestationRequestV1 {
            attestation_schema_version: summary.attestation_schema_version,
            attestation_scope: summary.attestation_scope,
            attestation_proof_kind: summary.attestation_proof_kind,
            normalization_policy_version: summary.normalization_policy_version,
            attestation_constraints: summary.attestation_constraints.clone(),
            claim: summary.claim.clone(),
            evidence_items: summary
                .evidence_summary
                .evidence_items
                .iter()
                .map(|item| {
                    let provenance = provenance_summary
                        .items
                        .iter()
                        .find(|entry| entry.label == item.label)
                        .ok_or_else(|| {
                            LocalChainErrorV1::InvalidFixture(format!(
                                "provenance_summary missing label {}",
                                item.label
                            ))
                        })?;
                    Ok(CanonicalPipelineAttestationEvidenceItemV1 {
                        label: item.label.clone(),
                        evidence_kind: item.evidence_kind,
                        evidence_payload: match item.evidence_kind {
                            CanonicalPipelineAttestationEvidenceKindV1::InlineUtf8 => {
                                CanonicalPipelineAttestationEvidencePayloadV1::InlineUtf8 {
                                    payload_utf8: item.original_payload_utf8.clone(),
                                }
                            }
                            CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8 => {
                                CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 {
                                    payload_utf8: item.original_payload_utf8.clone(),
                                }
                            }
                        },
                        provenance: CanonicalPipelineEvidenceProvenanceV1 {
                            provenance_policy_version: provenance.provenance_policy_version,
                            provenance_type: provenance.provenance_type,
                            source_type: provenance.source_type.clone(),
                            source_identifier: provenance.source_identifier.clone(),
                            signature: match (provenance.signer_public_key, provenance.signature) {
                                (Some(signer_public_key), Some(signature)) => {
                                    Some(CanonicalPipelineEvidenceSignatureV1 {
                                        signer_public_key,
                                        signature,
                                    })
                                }
                                _ => None,
                            },
                            timestamp_unix_seconds: provenance.timestamp_unix_seconds,
                        },
                    })
                })
                .collect::<Result<Vec<_>, LocalChainErrorV1>>()?,
            tamper_stark_public_inputs_digest: None,
            tamper_stark_proof_bytes: None,
        })
        .map(|mut attestation| {
            attestation.attestation_proof_kind = attestation_proof_summary.proof_kind;
            attestation.tamper_stark_public_inputs_digest = report
                .request_audit
                .tamper_attestation_stark_public_inputs_digest
                .as_ref()
                .map(ByteTamperFixtureV1::from);
            attestation.tamper_stark_proof_bytes = report
                .request_audit
                .tamper_attestation_stark_proof_bytes
                .as_ref()
                .map(ByteTamperFixtureV1::from);
            attestation
        })
    } else {
        None
    };
    Ok(CanonicalPipelineRequestV1 {
        pipeline_id: report.pipeline_id.clone(),
        fixture_name: report.fixture_name.clone(),
        proof_system: report.proof_system,
        economic: CanonicalPipelineEconomicPolicyV1 {
            economic_policy_version: report.burn_summary.burn_policy_version,
            request_kind: report.burn_summary.request_kind,
            burn_intent: report.burn_summary.burn_intent,
            declared_fee_units: report.burn_summary.declared_fee_units,
        },
        accounting: CanonicalPipelineAccountingPolicyV1 {
            accounting_policy_version: report.accounting_summary.accounting_policy_version,
            payment_intent: report.accounting_summary.payment_intent,
            settlement_intent: report.accounting_summary.settlement_intent,
        },
        ledger: CanonicalPipelineLedgerPolicyV1 {
            ledger_policy_version: report.ledger_summary.ledger_policy_version,
            payer_account_id: report.ledger_summary.payer_account_id,
            total_supply: report.ledger_summary.total_supply,
            burned_supply: report.ledger_summary.burned_supply_before,
            accounts: report.ledger_accounts.ordered_accounts.clone(),
        },
        head: CanonicalPipelineSettlementHeadRequestV1 {
            settlement_head_version: report.head_transition_summary.settlement_head_version,
            previous_head_hash: report.head_transition_summary.previous_head_hash,
            head_sequence_number: report.head_transition_summary.head_sequence_number,
        },
        wallet_binding: CanonicalPipelineWalletBindingV1 {
            wallet_binding_version: report.wallet_binding_summary.wallet_binding_version,
            account_id: report.wallet_binding_summary.account_id,
            wallet_address: report.wallet_binding_summary.wallet_address.clone(),
        },
        token_anchor: CanonicalPipelineTokenAnchorV1 {
            token_policy_version: report.token_anchor_summary.token_policy_version,
            network_mode: report.token_anchor_summary.network_mode,
            settlement_anchor_type: report.token_anchor_summary.settlement_anchor_type,
            external_balance_reference: report
                .token_anchor_summary
                .external_balance_reference
                .clone(),
            enforce_external_match: report.token_anchor_summary.anchor_verification_status
                == CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
                || report
                    .token_anchor_summary
                    .expected_external_balance
                    .is_some(),
            expected_external_balance: report.token_anchor_summary.expected_external_balance,
        },
        attestation,
        rollup_id: report.request_audit.rollup_id,
        accounts: report.genesis_accounts.ordered_accounts.clone(),
        batch_number: report.request_audit.batch_number,
        parent_batch_commitment: report.request_audit.parent_batch_commitment,
        transactions: report
            .commitment_expansions
            .transactions
            .ordered_transactions
            .clone(),
        tamper_public_inputs: report
            .request_audit
            .tamper_public_inputs
            .as_ref()
            .map(ByteTamperFixtureV1::from),
        tamper_proof_binding_digest: report
            .request_audit
            .tamper_proof_binding_digest
            .as_ref()
            .map(ByteTamperFixtureV1::from),
        expected_result: report.expected_result,
    })
}

pub fn validate_canonical_pipeline_report_v1(
    report: &CanonicalPipelineReportV1,
) -> Result<(), LocalChainErrorV1> {
    if report.pipeline_schema_version != CANONICAL_PIPELINE_SCHEMA_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported pipeline_schema_version: {}",
            report.pipeline_schema_version
        )));
    }
    if report.pipeline_id != CANONICAL_PIPELINE_ID_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported pipeline_id: {}",
            report.pipeline_id
        )));
    }
    if report.fixture_name.trim().is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report fixture_name must not be empty".to_string(),
        ));
    }
    if report.burn_summary.burn_policy_version != CANONICAL_PIPELINE_BURN_POLICY_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported burn_summary.burn_policy_version: {}",
            report.burn_summary.burn_policy_version
        )));
    }
    if report.ledger_summary.ledger_policy_version != CANONICAL_PIPELINE_LEDGER_POLICY_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported ledger_summary.ledger_policy_version: {}",
            report.ledger_summary.ledger_policy_version
        )));
    }
    if report.genesis_accounts.material_version != CANONICAL_PIPELINE_GENESIS_ACCOUNTS_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported genesis_accounts.material_version: {}",
            report.genesis_accounts.material_version
        )));
    }
    if report.ledger_accounts.material_version != CANONICAL_PIPELINE_LEDGER_ACCOUNTS_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported ledger_accounts.material_version: {}",
            report.ledger_accounts.material_version
        )));
    }
    if report
        .ledger_summary
        .ledger_state_commitment
        .commitment_version
        != CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported ledger_summary.ledger_state_commitment.commitment_version: {}",
            report.ledger_summary.ledger_state_commitment.commitment_version
        )));
    }
    if report.commitment_expansions.transactions.expansion_version
        != CANONICAL_PIPELINE_TRANSACTIONS_EXPANSION_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported commitment_expansions.transactions.expansion_version: {}",
            report.commitment_expansions.transactions.expansion_version
        )));
    }
    if report.commitment_expansions.batch_context.expansion_version
        != CANONICAL_PIPELINE_BATCH_CONTEXT_EXPANSION_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported commitment_expansions.batch_context.expansion_version: {}",
            report.commitment_expansions.batch_context.expansion_version
        )));
    }
    if report.commitment_expansions.fee_summary.expansion_version
        != CANONICAL_PIPELINE_FEE_SUMMARY_EXPANSION_VERSION_V1
    {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "canonical report has unsupported commitment_expansions.fee_summary.expansion_version: {}",
            report.commitment_expansions.fee_summary.expansion_version
        )));
    }
    if let Some(outcomes) = &report.commitment_expansions.outcomes {
        if outcomes.expansion_version != CANONICAL_PIPELINE_OUTCOMES_EXPANSION_VERSION_V1 {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "canonical report has unsupported commitment_expansions.outcomes.expansion_version: {}",
                outcomes.expansion_version
            )));
        }
        validate_canonical_pipeline_outcomes_expansion_v1(outcomes)?;
    }
    let expected_stage_outcomes = stage_outcomes_for_actual_result_v1(report.actual_result);
    if report.stage_outcomes != expected_stage_outcomes {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report stage_outcomes contradict actual_result".to_string(),
        ));
    }
    let request = canonical_pipeline_request_from_report_v1(report)?;
    let prepared_attestation = request
        .attestation
        .as_ref()
        .map(canonical_pipeline_prepare_attestation_v1)
        .transpose()?;
    let pre_state = LocalStateV1::new(request.accounts.clone())?;
    let ordered_accounts = pre_state.ordered_accounts();
    validate_canonical_pipeline_request_semantics_v1(&request, &ordered_accounts)?;
    if ordered_accounts != report.genesis_accounts.ordered_accounts {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report genesis_accounts must be duplicate-free and strictly ordered"
                .to_string(),
        ));
    }
    if request.ledger.accounts != report.ledger_accounts.ordered_accounts {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report ledger_accounts must be duplicate-free and strictly ordered"
                .to_string(),
        ));
    }
    let request_binding_hash =
        canonical_pipeline_request_binding_hash_v1(&request, &ordered_accounts);
    let genesis_accounts_digest = canonical_pipeline_genesis_accounts_digest_v1(&ordered_accounts);
    let ledger_accounts_digest =
        canonical_pipeline_ledger_accounts_digest_v1(&request.ledger.accounts);
    let transactions_digest = canonical_pipeline_transactions_digest_v1(
        &report
            .commitment_expansions
            .transactions
            .ordered_transactions,
    );
    let expected_burn_summary = canonical_pipeline_burn_summary_v1(&request, &ordered_accounts)?;
    let (expected_burn_record, expected_ledger_summary) = canonical_pipeline_ledger_transition_v1(
        &request,
        &expected_burn_summary,
        request_binding_hash,
    )?;
    let expected_attestation_summary =
        canonical_pipeline_attestation_summary_v1(&request, report.actual_result)?;
    let expected_wallet_binding_summary = canonical_pipeline_wallet_binding_summary_v1(&request);
    let expected_token_anchor_summary = canonical_pipeline_token_anchor_summary_v1(&request);
    let expected_provenance_summary = prepared_attestation
        .as_ref()
        .map(|prepared| prepared.provenance_summary.clone());
    let expected_genesis_account_count =
        u64::try_from(report.genesis_accounts.ordered_accounts.len()).map_err(|_| {
            LocalChainErrorV1::InvalidFixture(
                "request accounts length exceeds u64 range".to_string(),
            )
        })?;
    let expected_ledger_account_count =
        u64::try_from(report.ledger_accounts.ordered_accounts.len()).map_err(|_| {
            LocalChainErrorV1::InvalidFixture("ledger account length exceeds u64 range".to_string())
        })?;
    let expected_tx_count = u64::try_from(
        report
            .commitment_expansions
            .transactions
            .ordered_transactions
            .len(),
    )
    .map_err(|_| {
        LocalChainErrorV1::InvalidFixture(
            "request transaction length exceeds u64 range".to_string(),
        )
    })?;
    if report.request_audit.request_binding_hash != request_binding_hash
        || report.request_audit.genesis_accounts_digest != genesis_accounts_digest
        || report.request_audit.ledger_accounts_digest != ledger_accounts_digest
        || report.request_audit.transactions_digest != transactions_digest
        || report.request_audit.rollup_id != request.rollup_id
        || report.request_audit.genesis_account_count != expected_genesis_account_count
        || report.request_audit.ledger_account_count != expected_ledger_account_count
        || report.request_audit.ledger_payer_account_id != request.ledger.payer_account_id
        || report.request_audit.ledger_total_supply != request.ledger.total_supply
        || report.request_audit.ledger_burned_supply != request.ledger.burned_supply
        || report.request_audit.batch_number != request.batch_number
        || report.request_audit.tx_count != expected_tx_count
        || report.request_audit.parent_batch_commitment != request.parent_batch_commitment
        || report.request_audit.tamper_public_inputs
            != request
                .tamper_public_inputs
                .as_ref()
                .map(CanonicalPipelineTamperAuditV1::from)
        || report.request_audit.tamper_proof_binding_digest
            != request
                .tamper_proof_binding_digest
                .as_ref()
                .map(CanonicalPipelineTamperAuditV1::from)
        || report
            .request_audit
            .tamper_attestation_stark_public_inputs_digest
            != request
                .attestation
                .as_ref()
                .and_then(|attestation| attestation.tamper_stark_public_inputs_digest.as_ref())
                .map(CanonicalPipelineTamperAuditV1::from)
        || report.request_audit.tamper_attestation_stark_proof_bytes
            != request
                .attestation
                .as_ref()
                .and_then(|attestation| attestation.tamper_stark_proof_bytes.as_ref())
                .map(CanonicalPipelineTamperAuditV1::from)
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report request_audit drifted from request".to_string(),
        ));
    }
    if report.burn_summary != expected_burn_summary
        || !report.burn_summary.request_declares_correct_burn
        || !report.burn_summary.recomputed_burn_matches_report
        || !report.burn_summary.burn_consumed
        || report.burn_summary.consumed_burn_units != report.burn_summary.computed_burn_units
        || report.burn_summary.failure_semantics != canonical_pipeline_burn_failure_semantics_v1()
        || report.burn_summary.burn_policy != canonical_pipeline_burn_policy_v1()
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report burn_summary contradicts the canonical burn policy".to_string(),
        ));
    }
    if report.ledger_summary != expected_ledger_summary
        || !report.ledger_summary.ledger_consistent_with_request
        || !report.ledger_summary.ledger_consistent_with_burn
        || !report.ledger_summary.ledger_consistent_with_supply
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report ledger_summary contradicts the canonical ledger burn transition"
                .to_string(),
        ));
    }
    if report.attestation_summary != expected_attestation_summary {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report attestation_summary contradicts embedded attestation material"
                .to_string(),
        ));
    }
    if report.wallet_binding_summary != expected_wallet_binding_summary {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report wallet_binding_summary contradicts embedded wallet binding"
                .to_string(),
        ));
    }
    if report.token_anchor_summary != expected_token_anchor_summary {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report token_anchor_summary contradicts embedded token anchor".to_string(),
        ));
    }
    if report.provenance_summary != expected_provenance_summary {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report provenance_summary contradicts embedded provenance material"
                .to_string(),
        ));
    }
    if report.status_explanation.request_kind != request.economic.request_kind
        || report.status_explanation.truth_artifact_kind
            != canonical_pipeline_truth_artifact_kind_v1(request.economic.request_kind)
        || report.status_explanation.final_status != report.actual_result
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report status_explanation contradicts request kind or actual_result"
                .to_string(),
        ));
    }
    let expected_transactions_expansion = canonical_pipeline_transactions_commitment_expansion_v1(
        &report
            .commitment_expansions
            .transactions
            .ordered_transactions,
    );
    if report.commitment_expansions.transactions != expected_transactions_expansion {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report commitment_expansions.transactions contradict ordered_transactions"
                .to_string(),
        ));
    }
    let config = LocalExecutionConfigV1::new(report.request_audit.rollup_id);
    let expected_batch_context_expansion =
        canonical_pipeline_batch_context_commitment_expansion_v1(&config);
    if report.commitment_expansions.batch_context != expected_batch_context_expansion {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report commitment_expansions.batch_context contradict the canonical execution config"
                .to_string(),
        ));
    }
    let expected_fee_summary_expansion = canonical_pipeline_fee_summary_commitment_expansion_v1(
        &LocalFeeSummaryV1::new(report.request_audit.tx_count),
    );
    if report.commitment_expansions.fee_summary != expected_fee_summary_expansion {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical report commitment_expansions.fee_summary contradict the canonical fee summary"
                .to_string(),
        ));
    }

    let batch = BatchExecutionRequestV1 {
        batch_number: request.batch_number,
        parent_batch_commitment: request.parent_batch_commitment,
        transactions: request.transactions.clone(),
    };
    let pre_state_root = pre_state.state_root();
    if let Some((failure_reason_code, detail)) =
        canonical_pipeline_pre_execution_rejection_reason_v1(
            &request,
            prepared_attestation.as_ref(),
        )
    {
        if report.actual_result != ScenarioResultV1::ExecutionRejected {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report pre-execution rejection material contradicts actual_result"
                    .to_string(),
            ));
        }
        if report.executed_post_state_root.is_some()
            || report.settlement_committed_state_root.is_some()
            || report.public_inputs.is_some()
            || report.proof_artifact.is_some()
        {
            return Err(LocalChainErrorV1::InvalidFixture(
                "pre-execution-rejected canonical reports must not expose post-execution artifacts"
                    .to_string(),
            ));
        }
        if report.pre_state_root != pre_state_root {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report pre_state_root contradicts embedded genesis_accounts".to_string(),
            ));
        }
        if report.commitment_expansions.outcomes.is_some() {
            return Err(LocalChainErrorV1::InvalidFixture(
                "pre-execution-rejected canonical reports must not expose commitment_expansions.outcomes"
                    .to_string(),
            ));
        }
        let expected_status_explanation = canonical_pipeline_status_explanation_v1(
            request.economic.request_kind,
            ScenarioResultV1::ExecutionRejected,
            failure_reason_code,
            detail,
        );
        if report.status_explanation != expected_status_explanation {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report status_explanation contradicts pre-execution rejection semantics"
                    .to_string(),
            ));
        }
        let expected_accounting_summary = canonical_pipeline_accounting_summary_v1(
            &request,
            &expected_burn_summary,
            &expected_burn_record,
            ScenarioResultV1::ExecutionRejected,
            None,
        );
        if report.accounting_summary != expected_accounting_summary {
            return Err(LocalChainErrorV1::InvalidFixture(
                "canonical report accounting_summary contradicts pre-execution rejection semantics"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    let execution = execute_transfer_batch_v1(&pre_state, &config, &batch);

    match execution {
        Err(error) => {
            if report.actual_result != ScenarioResultV1::ExecutionRejected {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report embedded request material reproduces execution rejection, but actual_result does not"
                        .to_string(),
                ));
            }
            if report.executed_post_state_root.is_some()
                || report.settlement_committed_state_root.is_some()
                || report.public_inputs.is_some()
                || report.proof_artifact.is_some()
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "execution-rejected canonical reports must not expose post-execution artifacts"
                        .to_string(),
                ));
            }
            if report.pre_state_root != pre_state_root {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report pre_state_root contradicts embedded genesis_accounts"
                        .to_string(),
                ));
            }
            if report.commitment_expansions.outcomes.is_some() {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "execution-rejected canonical reports must not expose commitment_expansions.outcomes"
                        .to_string(),
                ));
            }
            let (failure_reason_code, detail) = canonical_pipeline_execution_rejection_reason_v1(
                &request,
                prepared_attestation.as_ref(),
                Some(&error),
            );
            let expected_status_explanation = canonical_pipeline_status_explanation_v1(
                request.economic.request_kind,
                ScenarioResultV1::ExecutionRejected,
                failure_reason_code,
                detail,
            );
            if report.status_explanation != expected_status_explanation {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report status_explanation contradicts execution rejection semantics"
                        .to_string(),
                ));
            }
            let expected_accounting_summary = canonical_pipeline_accounting_summary_v1(
                &request,
                &expected_burn_summary,
                &expected_burn_record,
                ScenarioResultV1::ExecutionRejected,
                None,
            );
            if report.accounting_summary != expected_accounting_summary {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report accounting_summary contradicts execution rejection semantics"
                        .to_string(),
                ));
            }
        }
        Ok(executed) => {
            if report.actual_result == ScenarioResultV1::ExecutionRejected {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report embedded request material executes successfully, but actual_result is ExecutionRejected"
                        .to_string(),
                ));
            }
            if report.pre_state_root != executed.pre_state_root {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report pre_state_root contradicts embedded genesis_accounts"
                        .to_string(),
                ));
            }
            let executed_post_state_root = report.executed_post_state_root.ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "non-execution-rejected canonical reports must expose executed_post_state_root"
                        .to_string(),
                )
            })?;
            if executed_post_state_root != executed.post_state_root {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report executed_post_state_root contradicts embedded request material"
                        .to_string(),
                ));
            }
            if report
                .commitment_expansions
                .transactions
                .transactions_commitment
                != executed.transactions_commitment
                || report
                    .commitment_expansions
                    .batch_context
                    .batch_context_commitment
                    != executed.batch_context_commitment
                || report
                    .commitment_expansions
                    .fee_summary
                    .fee_summary_commitment
                    != executed.fee_summary_commitment
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report commitment expansions contradict embedded request material"
                        .to_string(),
                ));
            }
            if report.commitment_expansions.outcomes.as_ref()
                != Some(&canonical_pipeline_outcomes_commitment_expansion_v1(
                    &executed,
                ))
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report commitment_expansions.outcomes contradict execution-derived outcomes"
                        .to_string(),
                ));
            }
            let public_inputs = report.public_inputs.as_ref().ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "non-execution-rejected canonical reports must expose public_inputs"
                        .to_string(),
                )
            })?;
            let proof_artifact = report.proof_artifact.as_ref().ok_or_else(|| {
                LocalChainErrorV1::InvalidFixture(
                    "non-execution-rejected canonical reports must expose proof_artifact"
                        .to_string(),
                )
            })?;
            if public_inputs.public_inputs_hash
                != sha256_digest_v1(&public_inputs.public_input_bytes)
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report public_inputs_hash is inconsistent with public_input_bytes"
                        .to_string(),
                ));
            }
            if public_inputs.transition_binding_hash
                != transition_binding_hash_from_public_input_bytes(
                    &public_inputs.public_input_bytes,
                )
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report transition_binding_hash is inconsistent with public_input_bytes"
                        .to_string(),
                ));
            }
            let public_inputs_verification_issue = match public_inputs.decode_status {
                CanonicalPipelinePublicInputsDecodeStatusV1::Decoded => {
                    let decoded =
                        public_inputs
                            .decoded_public_inputs
                            .as_ref()
                            .ok_or_else(|| {
                                LocalChainErrorV1::InvalidFixture(
                                    "decoded public_inputs must expose decoded_public_inputs"
                                        .to_string(),
                                )
                            })?;
                    let expected_consistency =
                        canonical_pipeline_request_summary_consistency_audit_v1(
                            public_inputs,
                            &report.request_audit,
                            &report.commitment_expansions,
                            report.pre_state_root,
                            executed_post_state_root,
                        )
                        .ok_or_else(|| {
                            LocalChainErrorV1::InvalidFixture(
                                "decoded public_inputs must expose request_summary_consistency"
                                    .to_string(),
                            )
                        })?;
                    if public_inputs.request_summary_consistency.as_ref()
                        != Some(&expected_consistency)
                    {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "decoded public_inputs request_summary_consistency contradicts the report"
                                .to_string(),
                        ));
                    }
                    if !expected_consistency.transition_binding_version_supported
                        || !expected_consistency.execution_model_version_supported
                        || !expected_consistency.batch_version_supported
                        || !expected_consistency.decoded_bytes_round_trip
                    {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "decoded public_inputs must use only supported canonical versions and round-trip exactly"
                                .to_string(),
                        ));
                    }
                    if decoded.fee_summary_commitment
                        != report
                            .commitment_expansions
                            .fee_summary
                            .fee_summary_commitment
                        || decoded.transactions_commitment
                            != report
                                .commitment_expansions
                                .transactions
                                .transactions_commitment
                        || decoded.outcomes_commitment
                            != report
                                .commitment_expansions
                                .outcomes
                                .as_ref()
                                .expect("validated outcomes expansion")
                                .outcomes_commitment
                        || decoded.batch_context_commitment
                            != report
                                .commitment_expansions
                                .batch_context
                                .batch_context_commitment
                    {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "decoded public_inputs commitments contradict commitment_expansions"
                                .to_string(),
                        ));
                    }
                    let decoded_envelope = decoded.to_envelope();
                    if decoded_envelope.encode_bytes() != public_inputs.public_input_bytes {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "decoded public_inputs do not round-trip into public_input_bytes"
                                .to_string(),
                        ));
                    }
                    if report.actual_result != ScenarioResultV1::VerificationRejected
                        && !expected_consistency.all_fields_match
                    {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "accepted or settlement-rejected reports must have fully consistent decoded public inputs"
                                .to_string(),
                        ));
                    }
                    !expected_consistency.all_fields_match
                }
                CanonicalPipelinePublicInputsDecodeStatusV1::Invalid => {
                    if public_inputs.decoded_public_inputs.is_some() {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "invalid public_inputs must not expose decoded_public_inputs"
                                .to_string(),
                        ));
                    }
                    if public_inputs.request_summary_consistency.is_some() {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "invalid public_inputs must not expose request_summary_consistency"
                                .to_string(),
                        ));
                    }
                    if report.actual_result != ScenarioResultV1::VerificationRejected {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "invalid public_inputs are only allowed on verification rejection"
                                .to_string(),
                        ));
                    }
                    true
                }
            };

            let expected_consistency = canonical_pipeline_proof_artifact_consistency_audit_v1(
                proof_artifact,
                public_inputs.public_inputs_hash,
                report.proof_system,
            )?;
            if proof_artifact.consistency != expected_consistency {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "proof_artifact.consistency contradicts the proof artifact or report"
                        .to_string(),
                ));
            }
            if !expected_consistency.prover_kind_matches_proof_system
                || !expected_consistency.proof_version_supported
                || !expected_consistency.proof_binding_input_kind_matches_proof_system
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "proof_artifact must use the supported canonical prover kind, proof version, and binding input kind"
                        .to_string(),
                ));
            }
            let proof_artifact_verification_issue = !expected_consistency
                .public_inputs_hash_matches_report
                || !expected_consistency.proof_binding_digest_matches_recomputed;
            if report.actual_result != ScenarioResultV1::VerificationRejected
                && !expected_consistency.all_fields_match
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "accepted or settlement-rejected reports must have fully consistent proof artifacts"
                        .to_string(),
                ));
            }
            if report.actual_result == ScenarioResultV1::VerificationRejected
                && !public_inputs_verification_issue
                && !proof_artifact_verification_issue
                && report.status_explanation.failure_reason_code
                    != CanonicalPipelineFailureReasonCodeV1::AttestationProofVerificationRejected
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "verification-rejected reports must expose at least one verification-layer mismatch"
                        .to_string(),
                ));
            }

            match report.actual_result {
                ScenarioResultV1::Accepted => {
                    if report.settlement_committed_state_root != Some(executed_post_state_root) {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "accepted canonical reports must commit the executed post-state root"
                                .to_string(),
                        ));
                    }
                }
                ScenarioResultV1::VerificationRejected | ScenarioResultV1::SettlementRejected => {
                    if report.settlement_committed_state_root.is_some() {
                        return Err(LocalChainErrorV1::InvalidFixture(
                            "rejected canonical reports must not expose settlement_committed_state_root"
                                .to_string(),
                        ));
                    }
                }
                ScenarioResultV1::ExecutionRejected => unreachable!(),
            }
            let wallet_binding_mismatch_detail =
                canonical_pipeline_wallet_binding_mismatch_detail_v1(&request);
            if wallet_binding_mismatch_detail.is_some()
                && report.actual_result == ScenarioResultV1::Accepted
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "wallet binding mismatch must reject before a canonical report can be accepted"
                        .to_string(),
                ));
            }
            let expected_failure_stage = match report.actual_result {
                ScenarioResultV1::Accepted => CanonicalPipelineFailureStageV1::None,
                ScenarioResultV1::VerificationRejected => {
                    CanonicalPipelineFailureStageV1::Verification
                }
                ScenarioResultV1::SettlementRejected => CanonicalPipelineFailureStageV1::Settlement,
                ScenarioResultV1::ExecutionRejected => unreachable!(),
            };
            let allowed_failure_reason_codes = match report.actual_result {
                ScenarioResultV1::Accepted => vec![CanonicalPipelineFailureReasonCodeV1::None],
                ScenarioResultV1::VerificationRejected => vec![
                    CanonicalPipelineFailureReasonCodeV1::VerificationLayerMismatch,
                    CanonicalPipelineFailureReasonCodeV1::AttestationProofVerificationRejected,
                ],
                ScenarioResultV1::SettlementRejected => vec![
                    CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected,
                    CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch,
                    CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch,
                ],
                ScenarioResultV1::ExecutionRejected => unreachable!(),
            };
            if report.status_explanation.failure_stage != expected_failure_stage
                || !allowed_failure_reason_codes
                    .contains(&report.status_explanation.failure_reason_code)
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report status_explanation contradicts actual_result".to_string(),
                ));
            }
            if report.actual_result == ScenarioResultV1::Accepted
                && report.status_explanation
                    != canonical_pipeline_accepted_status_explanation_v1(
                        request.economic.request_kind,
                    )
            {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "accepted canonical reports must pin the accepted status_explanation"
                        .to_string(),
                ));
            }
            if report.status_explanation.failure_reason_code
                == CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
            {
                if report.head_transition_summary.authority_mode
                    != CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent
                {
                    return Err(LocalChainErrorV1::InvalidFixture(
                        "settlement_head_mismatch requires authoritative_persistent head mode"
                            .to_string(),
                    ));
                }
            }
            if report.actual_result == ScenarioResultV1::SettlementRejected {
                match report.status_explanation.failure_reason_code {
                    CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch => {
                        let expected = canonical_pipeline_status_explanation_v1(
                            request.economic.request_kind,
                            ScenarioResultV1::SettlementRejected,
                            CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch,
                            wallet_binding_mismatch_detail.clone().ok_or_else(|| {
                                LocalChainErrorV1::InvalidFixture(
                                    "wallet_binding_mismatch requires a mismatched wallet binding"
                                        .to_string(),
                                )
                            })?,
                        );
                        if report.status_explanation != expected {
                            return Err(LocalChainErrorV1::InvalidFixture(
                                "wallet_binding_mismatch report must pin the wallet binding rejection detail"
                                    .to_string(),
                            ));
                        }
                    }
                    CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected => {
                        if wallet_binding_mismatch_detail.is_some() {
                            return Err(LocalChainErrorV1::InvalidFixture(
                                "wallet binding mismatch must not be downgraded into settlement_acceptance_rejected"
                                    .to_string(),
                            ));
                        }
                        if report.token_anchor_summary.anchor_verification_status
                            == CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
                        {
                            let expected = canonical_pipeline_status_explanation_v1(
                                request.economic.request_kind,
                                ScenarioResultV1::SettlementRejected,
                                CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected,
                                canonical_pipeline_external_anchor_rejection_detail_v1(),
                            );
                            if report.status_explanation != expected {
                                return Err(LocalChainErrorV1::InvalidFixture(
                                    "rejected external token anchors must pin the settlement rejection detail"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                    CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch => {}
                    _ => {}
                }
            }
            let expected_accounting_summary = canonical_pipeline_accounting_summary_v1(
                &request,
                &expected_burn_summary,
                &expected_burn_record,
                report.actual_result,
                report.settlement_committed_state_root,
            );
            if report.accounting_summary != expected_accounting_summary {
                return Err(LocalChainErrorV1::InvalidFixture(
                    "canonical report accounting_summary contradicts burn_summary or settlement result"
                        .to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn canonical_pipeline_request_summary_consistency_audit_v1(
    public_inputs: &CanonicalPipelinePublicInputsAuditV1,
    request_audit: &CanonicalPipelineRequestAuditV1,
    commitment_expansions: &CanonicalPipelineCommitmentExpansionsV1,
    pre_state_root: [u8; 32],
    executed_post_state_root: [u8; 32],
) -> Option<CanonicalPipelineRequestSummaryConsistencyAuditV1> {
    let decoded = public_inputs.decoded_public_inputs.as_ref()?;
    let decoded_bytes_round_trip =
        decoded.to_envelope().encode_bytes() == public_inputs.public_input_bytes;
    let consistency = CanonicalPipelineRequestSummaryConsistencyAuditV1 {
        transition_binding_version_supported: decoded.transition_binding_version
            == TRANSITION_BINDING_VERSION_V1,
        execution_model_version_supported: decoded.execution_model_version
            == EXECUTION_MODEL_VERSION_V1,
        batch_version_supported: decoded.batch_version == BATCH_VERSION_V1,
        rollup_id_matches_request_audit: decoded.rollup_id == request_audit.rollup_id,
        batch_number_matches_request_audit: decoded.batch_number == request_audit.batch_number,
        tx_count_matches_request_audit: decoded.tx_count == request_audit.tx_count,
        parent_batch_commitment_matches_request_audit: decoded.parent_batch_commitment
            == request_audit.parent_batch_commitment,
        fee_summary_commitment_matches_expansion: decoded.fee_summary_commitment
            == commitment_expansions.fee_summary.fee_summary_commitment,
        pre_state_root_matches_report: decoded.pre_state_root == pre_state_root,
        post_state_root_matches_report: decoded.post_state_root == executed_post_state_root,
        transactions_commitment_matches_expansion: decoded.transactions_commitment
            == commitment_expansions.transactions.transactions_commitment,
        outcomes_commitment_matches_expansion: commitment_expansions
            .outcomes
            .as_ref()
            .map(|outcomes| decoded.outcomes_commitment == outcomes.outcomes_commitment)
            .unwrap_or(false),
        batch_context_commitment_matches_expansion: decoded.batch_context_commitment
            == commitment_expansions.batch_context.batch_context_commitment,
        decoded_bytes_round_trip,
        all_fields_match: false,
    };
    Some(CanonicalPipelineRequestSummaryConsistencyAuditV1 {
        all_fields_match: consistency.transition_binding_version_supported
            && consistency.execution_model_version_supported
            && consistency.batch_version_supported
            && consistency.rollup_id_matches_request_audit
            && consistency.batch_number_matches_request_audit
            && consistency.tx_count_matches_request_audit
            && consistency.parent_batch_commitment_matches_request_audit
            && consistency.fee_summary_commitment_matches_expansion
            && consistency.pre_state_root_matches_report
            && consistency.post_state_root_matches_report
            && consistency.transactions_commitment_matches_expansion
            && consistency.outcomes_commitment_matches_expansion
            && consistency.batch_context_commitment_matches_expansion
            && consistency.decoded_bytes_round_trip,
        ..consistency
    })
}

fn canonical_pipeline_proof_artifact_consistency_audit_v1(
    proof_artifact: &CanonicalPipelineProofArtifactAuditV1,
    report_public_inputs_hash: [u8; 32],
    proof_system: ProofSystemSelectionV1,
) -> Result<CanonicalPipelineProofArtifactConsistencyAuditV1, LocalChainErrorV1> {
    let recomputed_proof_binding_digest =
        recomputed_proof_binding_digest_from_audit_v1(proof_artifact);
    let consistency = CanonicalPipelineProofArtifactConsistencyAuditV1 {
        public_inputs_hash_matches_report: proof_artifact.public_inputs_hash
            == report_public_inputs_hash,
        prover_kind_matches_proof_system: proof_artifact.prover_kind
            == expected_prover_kind_for_proof_system_v1(proof_system),
        proof_version_supported: proof_artifact.proof_version
            == expected_proof_version_for_proof_system_v1(proof_system),
        proof_binding_input_kind_matches_proof_system:
            proof_binding_input_kind_matches_proof_system_v1(
                proof_artifact.proof_binding_input_kind,
                proof_system,
            ),
        recomputed_proof_binding_digest,
        proof_binding_digest_matches_recomputed: proof_artifact.proof_binding_digest
            == recomputed_proof_binding_digest,
        all_fields_match: false,
    };
    Ok(CanonicalPipelineProofArtifactConsistencyAuditV1 {
        all_fields_match: consistency.public_inputs_hash_matches_report
            && consistency.prover_kind_matches_proof_system
            && consistency.proof_version_supported
            && consistency.proof_binding_input_kind_matches_proof_system
            && consistency.proof_binding_digest_matches_recomputed,
        ..consistency
    })
}

fn proof_binding_input_kind_matches_proof_system_v1(
    kind: CanonicalPipelineProofBindingInputKindV1,
    proof_system: ProofSystemSelectionV1,
) -> bool {
    matches!(
        (kind, proof_system),
        (
            CanonicalPipelineProofBindingInputKindV1::WitnessDigest,
            ProofSystemSelectionV1::Mock,
        ) | (
            CanonicalPipelineProofBindingInputKindV1::ProofBytesHash,
            ProofSystemSelectionV1::Stark,
        )
    )
}

fn expected_prover_kind_for_proof_system_v1(proof_system: ProofSystemSelectionV1) -> u32 {
    match proof_system {
        ProofSystemSelectionV1::Mock => LOCAL_PROVER_KIND_MOCK_V1,
        ProofSystemSelectionV1::Stark => LOCAL_PROVER_KIND_STARK_V1,
    }
}

fn expected_proof_version_for_proof_system_v1(proof_system: ProofSystemSelectionV1) -> u32 {
    match proof_system {
        ProofSystemSelectionV1::Mock => LOCAL_MOCK_PROOF_VERSION_V1,
        ProofSystemSelectionV1::Stark => LOCAL_STARK_PROOF_VERSION_V1,
    }
}

fn recomputed_proof_binding_digest_from_audit_v1(
    proof_artifact: &CanonicalPipelineProofArtifactAuditV1,
) -> [u8; 32] {
    match proof_artifact.proof_binding_input_kind {
        CanonicalPipelineProofBindingInputKindV1::WitnessDigest => {
            derive_mock_proof_binding_digest_v1(
                proof_artifact.proof_version,
                &proof_artifact.public_inputs_hash,
                &proof_artifact.trace_digest,
                &proof_artifact.trace_layout_digest,
                &proof_artifact.proof_binding_input_digest,
            )
        }
        CanonicalPipelineProofBindingInputKindV1::ProofBytesHash => {
            derive_stark_proof_binding_digest_from_hash_v1(
                proof_artifact.proof_version,
                &proof_artifact.public_inputs_hash,
                &proof_artifact.trace_digest,
                &proof_artifact.trace_layout_digest,
                &proof_artifact.proof_binding_input_digest,
            )
        }
    }
}

fn derive_stark_proof_binding_digest_from_hash_v1(
    proof_version: u32,
    public_inputs_hash: &[u8; 32],
    trace_digest: &[u8; 32],
    trace_layout_digest: &[u8; 32],
    proof_bytes_hash: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AURA_L2_LOCAL_STARK_PROOF_BINDING_V1");
    bytes.extend_from_slice(&proof_version.to_le_bytes());
    bytes.extend_from_slice(public_inputs_hash);
    bytes.extend_from_slice(trace_digest);
    bytes.extend_from_slice(trace_layout_digest);
    bytes.extend_from_slice(proof_bytes_hash);
    sha256_digest_v1(&bytes)
}

struct PreparedProofVectorRuntimeV1 {
    pre_state_root: [u8; 32],
    public_input_bytes: [u8; 284],
    executed: aura_l2_execution_v1::ExecutedBatchV1,
}

fn prepare_proof_vector_runtime(
    fixture: &ProofVectorFixtureV1,
) -> Result<PreparedProofVectorRuntimeV1, LocalChainErrorV1> {
    if fixture.proof_system != ProofSystemSelectionV1::Stark {
        return Err(LocalChainErrorV1::InvalidFixture(
            "proof vectors currently support only STARK-backed fixtures".to_string(),
        ));
    }

    let pre_state = LocalStateV1::new(fixture.genesis.accounts.clone())?;
    let config = LocalExecutionConfigV1::new(fixture.genesis.rollup_id);
    let request = BatchExecutionRequestV1 {
        batch_number: fixture.batch.batch_number,
        parent_batch_commitment: fixture.batch.parent_batch_commitment,
        transactions: fixture.batch.transactions.clone(),
    };
    let pre_state_root = pre_state.state_root();
    let executed = execute_transfer_batch_v1(&pre_state, &config, &request)?;
    let envelope = TransitionEnvelopeV1::from_executed_batch(&executed);
    let public_input_bytes = envelope.encode_bytes();

    assert_transition_matches_expected(&executed, &fixture.expected_transition)?;
    assert_public_inputs_match_expected(
        &envelope,
        public_input_bytes,
        &fixture.expected_public_inputs,
    )?;

    Ok(PreparedProofVectorRuntimeV1 {
        pre_state_root,
        public_input_bytes,
        executed,
    })
}

fn finalize_proof_vector_report(
    fixture: &ProofVectorFixtureV1,
    public_input_bytes: &[u8],
    pre_state_root: [u8; 32],
    proof_artifact: LocalStarkProofArtifactV1,
) -> Result<ProofVectorReportV1, LocalChainErrorV1> {
    let verification_result = verify_proof_artifact_v1(
        public_input_bytes,
        &LocalProofArtifactV1::Stark(proof_artifact.clone()),
    );

    let mut settlement = LocalSettlementStateV1::new(fixture.genesis.rollup_id, pre_state_root);
    match accept_transition_v1(
        &mut settlement,
        public_input_bytes,
        &LocalProofArtifactV1::Stark(proof_artifact.clone()),
    ) {
        Ok(accepted) => {
            let actual = ScenarioResultV1::Accepted;
            if fixture.expected_result != actual {
                return Err(LocalChainErrorV1::UnexpectedResult {
                    expected: fixture.expected_result,
                    actual,
                });
            }
            Ok(ProofVectorReportV1 {
                fixture_name: fixture.fixture_name.clone(),
                proof_system: fixture.proof_system,
                expected_result: fixture.expected_result,
                actual_result: actual,
                pre_state_root,
                post_state_root: Some(accepted.new_state_root),
                transition_binding_hash: accepted.transition_binding_hash,
                public_inputs_hash: proof_artifact.public_inputs_hash,
                trace_digest: proof_artifact.trace_digest,
                trace_layout_digest: proof_artifact.trace_layout_digest,
                proof_binding_digest: proof_artifact.proof_binding_digest,
            })
        }
        Err(_error) => {
            let actual = if verification_result.is_err() {
                ScenarioResultV1::VerificationRejected
            } else {
                ScenarioResultV1::SettlementRejected
            };
            if fixture.expected_result != actual {
                return Err(LocalChainErrorV1::UnexpectedResult {
                    expected: fixture.expected_result,
                    actual,
                });
            }
            Ok(ProofVectorReportV1 {
                fixture_name: fixture.fixture_name.clone(),
                proof_system: fixture.proof_system,
                expected_result: fixture.expected_result,
                actual_result: actual,
                pre_state_root,
                post_state_root: None,
                transition_binding_hash: fixture.expected_public_inputs.transition_binding_hash,
                public_inputs_hash: proof_artifact.public_inputs_hash,
                trace_digest: proof_artifact.trace_digest,
                trace_layout_digest: proof_artifact.trace_layout_digest,
                proof_binding_digest: proof_artifact.proof_binding_digest,
            })
        }
    }
}

fn assert_transition_matches_expected(
    executed: &aura_l2_execution_v1::ExecutedBatchV1,
    expected: &ProofVectorExpectedTransitionV1,
) -> Result<(), LocalChainErrorV1> {
    let actual_accounts = executed.post_state.ordered_accounts();
    if actual_accounts != expected.post_state_accounts {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "post-state accounts do not match expected proof vector".to_string(),
        ));
    }
    let actual_outcomes = executed
        .outcomes
        .iter()
        .map(|outcome| ProofVectorExpectedOutcomeV1 {
            tx_index: outcome.tx_index,
            sender_account_id: outcome.sender_account_id,
            consumed_nonce: outcome.consumed_nonce,
            fee_charged: outcome.fee_charged,
            touched_accounts_commitment: outcome.touched_accounts_commitment,
            operation_result_commitment: outcome.operation_result_commitment,
            status: outcome.status,
        })
        .collect::<Vec<_>>();
    if actual_outcomes != expected.outcomes {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "execution outcomes do not match expected proof vector".to_string(),
        ));
    }
    if executed.pre_state_root != expected.pre_state_root
        || executed.post_state_root != expected.post_state_root
        || executed.transactions_commitment != expected.transactions_commitment
        || executed.outcomes_commitment != expected.outcomes_commitment
        || executed.batch_context_commitment != expected.batch_context_commitment
        || executed.fee_summary_commitment != expected.fee_summary_commitment
    {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "transition commitments do not match expected proof vector".to_string(),
        ));
    }
    Ok(())
}

fn assert_public_inputs_match_expected(
    envelope: &TransitionEnvelopeV1,
    public_input_bytes: [u8; 284],
    expected: &ProofVectorExpectedPublicInputsV1,
) -> Result<(), LocalChainErrorV1> {
    if envelope.transition_binding_version != expected.transition_binding_version
        || envelope.rollup_id != expected.rollup_id
        || envelope.execution_model_version != expected.execution_model_version
        || envelope.batch_version != expected.batch_version
        || envelope.batch_number != expected.batch_number
        || envelope.parent_batch_commitment != expected.parent_batch_commitment
        || envelope.tx_count != expected.tx_count
        || envelope.fee_summary_commitment != expected.fee_summary_commitment
        || envelope.pre_state_root != expected.pre_state_root
        || envelope.post_state_root != expected.post_state_root
        || envelope.transactions_commitment != expected.transactions_commitment
        || envelope.outcomes_commitment != expected.outcomes_commitment
        || envelope.batch_context_commitment != expected.batch_context_commitment
    {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "public-input fields do not match expected proof vector".to_string(),
        ));
    }
    if public_input_bytes != expected.public_input_bytes {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "public-input bytes do not match expected proof vector".to_string(),
        ));
    }
    if envelope.transition_binding_hash_v1() != expected.transition_binding_hash {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "transition binding hash does not match expected proof vector".to_string(),
        ));
    }
    Ok(())
}

fn assert_stark_artifact_matches_expected(
    actual: &LocalStarkProofArtifactV1,
    expected: &ProofVectorCanonicalStarkArtifactV1,
) -> Result<(), LocalChainErrorV1> {
    if actual.prover_kind != expected.prover_kind
        || actual.proof_version != expected.proof_version
        || actual.public_inputs_hash != expected.public_inputs_hash
        || actual.trace_digest != expected.trace_digest
        || actual.trace_layout_digest != expected.trace_layout_digest
        || actual.proof_binding_digest != expected.proof_binding_digest
        || actual.proof_bytes != expected.proof_bytes
    {
        return Err(LocalChainErrorV1::ProofVectorMismatch(
            "generated STARK proof artifact does not match canonical proof vector".to_string(),
        ));
    }
    Ok(())
}

fn apply_proof_vector_tamper(
    mut proof_artifact: LocalStarkProofArtifactV1,
    tamper: Option<&ProofVectorTamperV1>,
) -> Result<LocalStarkProofArtifactV1, LocalChainErrorV1> {
    if let Some(tamper) = tamper {
        match tamper.target {
            ProofVectorTamperTargetV1::ProofBytes => {
                let byte = proof_artifact
                    .proof_bytes
                    .get_mut(tamper.byte_offset)
                    .ok_or_else(|| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "proof_bytes tamper offset {} out of range",
                            tamper.byte_offset
                        ))
                    })?;
                *byte ^= tamper.xor_with;
            }
            ProofVectorTamperTargetV1::ProofBindingDigest => {
                let byte = proof_artifact
                    .proof_binding_digest
                    .get_mut(tamper.byte_offset)
                    .ok_or_else(|| {
                        LocalChainErrorV1::InvalidFixture(format!(
                            "proof_binding_digest tamper offset {} out of range",
                            tamper.byte_offset
                        ))
                    })?;
                *byte ^= tamper.xor_with;
            }
        }
    }
    Ok(proof_artifact)
}

fn parse_proof_vector_genesis(
    genesis: &GenesisFixtureFileV1,
) -> Result<ProofVectorGenesisV1, LocalChainErrorV1> {
    Ok(ProofVectorGenesisV1 {
        rollup_id: decode_hex_32_field(
            &genesis.rollup_id_hex,
            "proof_vector.genesis.rollup_id_hex",
        )?,
        accounts: genesis
            .accounts
            .iter()
            .map(parse_account_fixture)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_proof_vector_batch_from_scenario(
    scenario: &ScenarioFixtureFileV1,
) -> Result<ProofVectorBatchV1, LocalChainErrorV1> {
    Ok(ProofVectorBatchV1 {
        batch_number: scenario.batch_number,
        parent_batch_commitment: decode_hex_32_field(
            &scenario.parent_batch_commitment_hex,
            "proof_vector.batch.parent_batch_commitment_hex",
        )?,
        transactions: scenario
            .transactions
            .iter()
            .map(parse_transfer_fixture)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_account_fixture(account: &AccountFixtureV1) -> Result<LocalAccountV1, LocalChainErrorV1> {
    Ok(LocalAccountV1 {
        account_id: decode_hex_32_field(&account.account_id_hex, "account.account_id_hex")?,
        balance: account.balance,
        nonce: account.nonce,
    })
}

fn parse_transfer_fixture(
    tx: &TransferFixtureV1,
) -> Result<TransferTransactionV1, LocalChainErrorV1> {
    Ok(TransferTransactionV1 {
        tx_version: TRANSFER_TX_VERSION_V1,
        sender_account_id: decode_hex_32_field(
            &tx.sender_account_id_hex,
            "transaction.sender_account_id_hex",
        )?,
        recipient_account_id: decode_hex_32_field(
            &tx.recipient_account_id_hex,
            "transaction.recipient_account_id_hex",
        )?,
        sender_nonce: tx.sender_nonce,
        amount: tx.amount,
    })
}

fn validate_genesis_fixture(genesis: &GenesisFixtureFileV1) -> Result<(), LocalChainErrorV1> {
    if genesis.fixture_schema_version != GENESIS_FIXTURE_SCHEMA_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported genesis fixture_schema_version: expected {}, got {}",
            GENESIS_FIXTURE_SCHEMA_VERSION_V1, genesis.fixture_schema_version
        )));
    }
    if genesis.fixture_name.trim().is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "genesis fixture_name must not be empty".to_string(),
        ));
    }
    if genesis.fixture_name != GENESIS_FIXTURE_NAME_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unexpected genesis fixture name: {}",
            genesis.fixture_name
        )));
    }
    Ok(())
}

fn validate_scenario_fixture(scenario: &ScenarioFixtureFileV1) -> Result<(), LocalChainErrorV1> {
    if scenario.fixture_schema_version != SCENARIO_FIXTURE_SCHEMA_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported scenario fixture_schema_version: expected {}, got {}",
            SCENARIO_FIXTURE_SCHEMA_VERSION_V1, scenario.fixture_schema_version
        )));
    }
    if scenario.fixture_name.trim().is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "fixture_name must not be empty".to_string(),
        ));
    }
    if let Some(tamper) = &scenario.tamper_public_inputs {
        validate_byte_tamper_offset(
            tamper.byte_offset,
            PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1,
            "public-input",
            "284-byte schema",
        )?;
    }
    if let Some(tamper) = &scenario.tamper_proof_binding_digest {
        validate_byte_tamper_offset(
            tamper.byte_offset,
            PROOF_BINDING_DIGEST_LEN_V1,
            "proof_binding_digest",
            "32-byte digest",
        )?;
    }
    Ok(())
}

fn validate_loaded_proof_vector(fixture: &ProofVectorFixtureV1) -> Result<(), LocalChainErrorV1> {
    if fixture.fixture_name.trim().is_empty() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "proof vector fixture_name must not be empty".to_string(),
        ));
    }
    if fixture.proof_system != ProofSystemSelectionV1::Stark {
        return Err(LocalChainErrorV1::InvalidFixture(
            "proof vectors currently support only STARK-backed fixtures".to_string(),
        ));
    }
    if fixture.canonical_stark_proof_artifact.prover_kind != LOCAL_PROVER_KIND_STARK_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical STARK prover kind: expected {}, got {}",
            LOCAL_PROVER_KIND_STARK_V1, fixture.canonical_stark_proof_artifact.prover_kind
        )));
    }
    if fixture.canonical_stark_proof_artifact.proof_version != LOCAL_STARK_PROOF_VERSION_V1 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "unsupported canonical STARK proof version: expected {}, got {}",
            LOCAL_STARK_PROOF_VERSION_V1, fixture.canonical_stark_proof_artifact.proof_version
        )));
    }
    if fixture
        .canonical_stark_proof_artifact
        .proof_bytes
        .is_empty()
    {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical STARK proof bytes must not be empty".to_string(),
        ));
    }
    if let Some(tamper) = &fixture.proof_tamper {
        match tamper.target {
            ProofVectorTamperTargetV1::ProofBytes => {
                if tamper.byte_offset >= fixture.canonical_stark_proof_artifact.proof_bytes.len() {
                    return Err(LocalChainErrorV1::InvalidFixture(format!(
                        "proof-bytes tamper offset {} out of range for {}-byte proof",
                        tamper.byte_offset,
                        fixture.canonical_stark_proof_artifact.proof_bytes.len()
                    )));
                }
            }
            ProofVectorTamperTargetV1::ProofBindingDigest => {
                if tamper.byte_offset >= 32 {
                    return Err(LocalChainErrorV1::InvalidFixture(format!(
                        "proof-binding-digest tamper offset {} out of range for 32-byte digest",
                        tamper.byte_offset
                    )));
                }
            }
        }
    }
    validate_proof_vector_expected_result(fixture.expected_result)?;
    if fixture.proof_tamper.is_none() && fixture.expected_result != ScenarioResultV1::Accepted {
        return Err(LocalChainErrorV1::InvalidFixture(
            "untampered proof vectors must expect acceptance under the verified foundation"
                .to_string(),
        ));
    }

    let expected_binding_digest = derive_stark_proof_binding_digest_v1(
        fixture.canonical_stark_proof_artifact.proof_version,
        &fixture.canonical_stark_proof_artifact.public_inputs_hash,
        &fixture.canonical_stark_proof_artifact.trace_digest,
        &fixture.canonical_stark_proof_artifact.trace_layout_digest,
        &fixture.canonical_stark_proof_artifact.proof_bytes,
    );
    if expected_binding_digest != fixture.canonical_stark_proof_artifact.proof_binding_digest {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical STARK proof artifact has inconsistent proof_binding_digest".to_string(),
        ));
    }

    let prepared = prepare_proof_vector_runtime(fixture).map_err(|error| match error {
        LocalChainErrorV1::Execution(inner) => LocalChainErrorV1::InvalidFixture(format!(
            "proof vector batch does not execute canonically: {inner}"
        )),
        LocalChainErrorV1::ProofVectorMismatch(inner) => {
            LocalChainErrorV1::InvalidFixture(format!("proof vector consistency failure: {inner}"))
        }
        other => other,
    })?;
    let verified = verify_proof_artifact_v1(
        &prepared.public_input_bytes,
        &LocalProofArtifactV1::Stark(fixture.canonical_stark_proof_artifact.to_runtime_artifact()),
    );
    if verified.is_err() {
        return Err(LocalChainErrorV1::InvalidFixture(
            "canonical STARK proof artifact does not verify against the stored public inputs"
                .to_string(),
        ));
    }

    Ok(())
}

fn validate_proof_vector_expected_result(
    expected_result: ScenarioResultV1,
) -> Result<(), LocalChainErrorV1> {
    match expected_result {
        ScenarioResultV1::Accepted | ScenarioResultV1::VerificationRejected => Ok(()),
        ScenarioResultV1::ExecutionRejected => Err(LocalChainErrorV1::InvalidFixture(
            "proof vectors must not target execution rejection; invalid execution never reaches canonical proving"
                .to_string(),
        )),
        ScenarioResultV1::SettlementRejected => Err(LocalChainErrorV1::InvalidFixture(
            "proof vectors must not target settlement rejection; the current proof-vector harness starts from a fresh canonical local-settlement state"
                .to_string(),
        )),
    }
}

impl ProofVectorExpectedTransitionV1 {
    fn from_executed_batch(executed: &aura_l2_execution_v1::ExecutedBatchV1) -> Self {
        Self {
            pre_state_root: executed.pre_state_root,
            post_state_root: executed.post_state_root,
            transactions_commitment: executed.transactions_commitment,
            outcomes_commitment: executed.outcomes_commitment,
            batch_context_commitment: executed.batch_context_commitment,
            fee_summary_commitment: executed.fee_summary_commitment,
            post_state_accounts: executed.post_state.ordered_accounts(),
            outcomes: executed
                .outcomes
                .iter()
                .map(|outcome| ProofVectorExpectedOutcomeV1 {
                    tx_index: outcome.tx_index,
                    sender_account_id: outcome.sender_account_id,
                    consumed_nonce: outcome.consumed_nonce,
                    fee_charged: outcome.fee_charged,
                    touched_accounts_commitment: outcome.touched_accounts_commitment,
                    operation_result_commitment: outcome.operation_result_commitment,
                    status: outcome.status,
                })
                .collect(),
        }
    }
}

impl ProofVectorExpectedPublicInputsV1 {
    fn from_envelope(envelope: &TransitionEnvelopeV1, public_input_bytes: [u8; 284]) -> Self {
        Self {
            transition_binding_version: envelope.transition_binding_version,
            rollup_id: envelope.rollup_id,
            execution_model_version: envelope.execution_model_version,
            batch_version: envelope.batch_version,
            batch_number: envelope.batch_number,
            parent_batch_commitment: envelope.parent_batch_commitment,
            tx_count: envelope.tx_count,
            fee_summary_commitment: envelope.fee_summary_commitment,
            pre_state_root: envelope.pre_state_root,
            post_state_root: envelope.post_state_root,
            transactions_commitment: envelope.transactions_commitment,
            outcomes_commitment: envelope.outcomes_commitment,
            batch_context_commitment: envelope.batch_context_commitment,
            public_input_bytes,
            transition_binding_hash: envelope.transition_binding_hash_v1(),
        }
    }
}

impl CanonicalPipelineDecodedPublicInputsV1 {
    fn from_envelope(envelope: &TransitionEnvelopeV1) -> Self {
        Self {
            transition_binding_version: envelope.transition_binding_version,
            rollup_id: envelope.rollup_id,
            execution_model_version: envelope.execution_model_version,
            batch_version: envelope.batch_version,
            batch_number: envelope.batch_number,
            parent_batch_commitment: envelope.parent_batch_commitment,
            tx_count: envelope.tx_count,
            fee_summary_commitment: envelope.fee_summary_commitment,
            pre_state_root: envelope.pre_state_root,
            post_state_root: envelope.post_state_root,
            transactions_commitment: envelope.transactions_commitment,
            outcomes_commitment: envelope.outcomes_commitment,
            batch_context_commitment: envelope.batch_context_commitment,
        }
    }

    fn to_envelope(&self) -> TransitionEnvelopeV1 {
        TransitionEnvelopeV1 {
            transition_binding_version: self.transition_binding_version,
            rollup_id: self.rollup_id,
            execution_model_version: self.execution_model_version,
            batch_version: self.batch_version,
            batch_number: self.batch_number,
            parent_batch_commitment: self.parent_batch_commitment,
            tx_count: self.tx_count,
            fee_summary_commitment: self.fee_summary_commitment,
            pre_state_root: self.pre_state_root,
            post_state_root: self.post_state_root,
            transactions_commitment: self.transactions_commitment,
            outcomes_commitment: self.outcomes_commitment,
            batch_context_commitment: self.batch_context_commitment,
        }
    }
}

impl CanonicalPipelinePublicInputsAuditV1 {
    fn from_public_input_bytes(public_input_bytes: [u8; PUBLIC_INPUT_SCHEMA_LEN_LOCAL_V1]) -> Self {
        let public_inputs_hash = sha256_digest_v1(&public_input_bytes);
        let transition_binding_hash =
            transition_binding_hash_from_public_input_bytes(&public_input_bytes);
        match TransitionEnvelopeV1::decode_exact(&public_input_bytes) {
            Ok(envelope) => Self {
                decode_status: CanonicalPipelinePublicInputsDecodeStatusV1::Decoded,
                public_input_bytes,
                public_inputs_hash,
                transition_binding_hash,
                request_summary_consistency: None,
                decoded_public_inputs: Some(CanonicalPipelineDecodedPublicInputsV1::from_envelope(
                    &envelope,
                )),
            },
            Err(_) => Self {
                decode_status: CanonicalPipelinePublicInputsDecodeStatusV1::Invalid,
                public_input_bytes,
                public_inputs_hash,
                transition_binding_hash,
                request_summary_consistency: None,
                decoded_public_inputs: None,
            },
        }
    }
}

impl CanonicalPipelineProofArtifactAuditV1 {
    fn from_proof_artifact(proof: &LocalProofArtifactV1) -> Self {
        match proof {
            LocalProofArtifactV1::Mock(mock) => Self {
                prover_kind: mock.prover_kind,
                proof_version: mock.proof_version,
                public_inputs_hash: mock.public_inputs_hash,
                trace_digest: mock.trace_digest,
                trace_layout_digest: mock.trace_layout_digest,
                proof_binding_digest: mock.proof_binding_digest,
                proof_binding_input_kind: CanonicalPipelineProofBindingInputKindV1::WitnessDigest,
                proof_binding_input_digest: mock.witness_digest,
                consistency: CanonicalPipelineProofArtifactConsistencyAuditV1 {
                    public_inputs_hash_matches_report: false,
                    prover_kind_matches_proof_system: false,
                    proof_version_supported: false,
                    proof_binding_input_kind_matches_proof_system: false,
                    recomputed_proof_binding_digest: [0u8; 32],
                    proof_binding_digest_matches_recomputed: false,
                    all_fields_match: false,
                },
            },
            LocalProofArtifactV1::Stark(stark) => Self {
                prover_kind: stark.prover_kind,
                proof_version: stark.proof_version,
                public_inputs_hash: stark.public_inputs_hash,
                trace_digest: stark.trace_digest,
                trace_layout_digest: stark.trace_layout_digest,
                proof_binding_digest: stark.proof_binding_digest,
                proof_binding_input_kind: CanonicalPipelineProofBindingInputKindV1::ProofBytesHash,
                proof_binding_input_digest: sha256_digest_v1(&stark.proof_bytes),
                consistency: CanonicalPipelineProofArtifactConsistencyAuditV1 {
                    public_inputs_hash_matches_report: false,
                    prover_kind_matches_proof_system: false,
                    proof_version_supported: false,
                    proof_binding_input_kind_matches_proof_system: false,
                    recomputed_proof_binding_digest: [0u8; 32],
                    proof_binding_digest_matches_recomputed: false,
                    all_fields_match: false,
                },
            },
        }
    }
}

impl ProofVectorCanonicalStarkArtifactV1 {
    fn from_runtime_artifact(artifact: &LocalStarkProofArtifactV1) -> Self {
        Self {
            prover_kind: artifact.prover_kind,
            proof_version: artifact.proof_version,
            public_inputs_hash: artifact.public_inputs_hash,
            trace_digest: artifact.trace_digest,
            trace_layout_digest: artifact.trace_layout_digest,
            proof_binding_digest: artifact.proof_binding_digest,
            proof_bytes: artifact.proof_bytes.clone(),
        }
    }

    fn to_runtime_artifact(&self) -> LocalStarkProofArtifactV1 {
        LocalStarkProofArtifactV1 {
            prover_kind: self.prover_kind,
            proof_version: self.proof_version,
            public_inputs_hash: self.public_inputs_hash,
            trace_digest: self.trace_digest,
            trace_layout_digest: self.trace_layout_digest,
            proof_bytes: self.proof_bytes.clone(),
            proof_binding_digest: self.proof_binding_digest,
        }
    }
}

impl ProofVectorFixtureV1 {
    fn from_file(file: ProofVectorFixtureFileV1) -> Result<Self, LocalChainErrorV1> {
        if file.fixture_schema_version != PROOF_VECTOR_FIXTURE_SCHEMA_VERSION_V1 {
            return Err(LocalChainErrorV1::InvalidFixture(format!(
                "unsupported proof vector fixture_schema_version: expected {}, got {}",
                PROOF_VECTOR_FIXTURE_SCHEMA_VERSION_V1, file.fixture_schema_version
            )));
        }
        let proof_system = ProofSystemSelectionV1::from_str(&file.proof_system)?;
        if proof_system != ProofSystemSelectionV1::Stark {
            return Err(LocalChainErrorV1::InvalidFixture(
                "proof vectors currently support only STARK-backed fixtures".to_string(),
            ));
        }

        let fixture = Self {
        fixture_name: file.fixture_name,
        proof_system,
        genesis: ProofVectorGenesisV1 {
                rollup_id: decode_hex_32_field(
                    &file.genesis.rollup_id_hex,
                    "proof_vector.genesis.rollup_id_hex",
                )?,
                accounts: file
                    .genesis
                    .accounts
                    .iter()
                    .map(parse_account_fixture)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            batch: ProofVectorBatchV1 {
                batch_number: file.batch.batch_number,
                parent_batch_commitment: decode_hex_32_field(
                    &file.batch.parent_batch_commitment_hex,
                    "proof_vector.batch.parent_batch_commitment_hex",
                )?,
                transactions: file
                    .batch
                    .transactions
                    .iter()
                    .map(parse_transfer_fixture)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            expected_transition: ProofVectorExpectedTransitionV1 {
                pre_state_root: decode_hex_32_field(
                    &file.expected_transition.pre_state_root_hex,
                    "proof_vector.expected_transition.pre_state_root_hex",
                )?,
                post_state_root: decode_hex_32_field(
                    &file.expected_transition.post_state_root_hex,
                    "proof_vector.expected_transition.post_state_root_hex",
                )?,
                transactions_commitment: decode_hex_32_field(
                    &file.expected_transition.transactions_commitment_hex,
                    "proof_vector.expected_transition.transactions_commitment_hex",
                )?,
                outcomes_commitment: decode_hex_32_field(
                    &file.expected_transition.outcomes_commitment_hex,
                    "proof_vector.expected_transition.outcomes_commitment_hex",
                )?,
                batch_context_commitment: decode_hex_32_field(
                    &file.expected_transition.batch_context_commitment_hex,
                    "proof_vector.expected_transition.batch_context_commitment_hex",
                )?,
                fee_summary_commitment: decode_hex_32_field(
                    &file.expected_transition.fee_summary_commitment_hex,
                    "proof_vector.expected_transition.fee_summary_commitment_hex",
                )?,
                post_state_accounts: file
                    .expected_transition
                    .post_state_accounts
                    .iter()
                    .map(parse_account_fixture)
                    .collect::<Result<Vec<_>, _>>()?,
                outcomes: file
                    .expected_transition
                    .outcomes
                    .into_iter()
                    .map(|outcome| {
                        Ok(ProofVectorExpectedOutcomeV1 {
                            tx_index: outcome.tx_index,
                            sender_account_id: decode_hex_32_field(
                                &outcome.sender_account_id_hex,
                                "proof_vector.expected_transition.outcomes[].sender_account_id_hex",
                            )?,
                            consumed_nonce: outcome.consumed_nonce,
                            fee_charged: outcome.fee_charged,
                            touched_accounts_commitment: decode_hex_32_field(
                                &outcome.touched_accounts_commitment_hex,
                                "proof_vector.expected_transition.outcomes[].touched_accounts_commitment_hex",
                            )?,
                            operation_result_commitment: decode_hex_32_field(
                                &outcome.operation_result_commitment_hex,
                                "proof_vector.expected_transition.outcomes[].operation_result_commitment_hex",
                            )?,
                            status: outcome.status,
                        })
                    })
                    .collect::<Result<Vec<_>, LocalChainErrorV1>>()?,
            },
            expected_public_inputs: ProofVectorExpectedPublicInputsV1 {
                transition_binding_version: file.expected_public_inputs.transition_binding_version,
                rollup_id: decode_hex_32_field(
                    &file.expected_public_inputs.rollup_id_hex,
                    "proof_vector.expected_public_inputs.rollup_id_hex",
                )?,
                execution_model_version: file.expected_public_inputs.execution_model_version,
                batch_version: file.expected_public_inputs.batch_version,
                batch_number: file.expected_public_inputs.batch_number,
                parent_batch_commitment: decode_hex_32_field(
                    &file.expected_public_inputs.parent_batch_commitment_hex,
                    "proof_vector.expected_public_inputs.parent_batch_commitment_hex",
                )?,
                tx_count: file.expected_public_inputs.tx_count,
                fee_summary_commitment: decode_hex_32_field(
                    &file.expected_public_inputs.fee_summary_commitment_hex,
                    "proof_vector.expected_public_inputs.fee_summary_commitment_hex",
                )?,
                pre_state_root: decode_hex_32_field(
                    &file.expected_public_inputs.pre_state_root_hex,
                    "proof_vector.expected_public_inputs.pre_state_root_hex",
                )?,
                post_state_root: decode_hex_32_field(
                    &file.expected_public_inputs.post_state_root_hex,
                    "proof_vector.expected_public_inputs.post_state_root_hex",
                )?,
                transactions_commitment: decode_hex_32_field(
                    &file.expected_public_inputs.transactions_commitment_hex,
                    "proof_vector.expected_public_inputs.transactions_commitment_hex",
                )?,
                outcomes_commitment: decode_hex_32_field(
                    &file.expected_public_inputs.outcomes_commitment_hex,
                    "proof_vector.expected_public_inputs.outcomes_commitment_hex",
                )?,
                batch_context_commitment: decode_hex_32_field(
                    &file.expected_public_inputs.batch_context_commitment_hex,
                    "proof_vector.expected_public_inputs.batch_context_commitment_hex",
                )?,
                public_input_bytes: decode_hex_exact_field(
                    &file.expected_public_inputs.public_input_bytes_hex,
                    "proof_vector.expected_public_inputs.public_input_bytes_hex",
                )?,
                transition_binding_hash: decode_hex_32_field(
                    &file.expected_public_inputs.transition_binding_hash_hex,
                    "proof_vector.expected_public_inputs.transition_binding_hash_hex",
                )?,
            },
            canonical_stark_proof_artifact: ProofVectorCanonicalStarkArtifactV1 {
                prover_kind: file.canonical_stark_proof_artifact.prover_kind,
                proof_version: file.canonical_stark_proof_artifact.proof_version,
                public_inputs_hash: decode_hex_32_field(
                    &file.canonical_stark_proof_artifact.public_inputs_hash_hex,
                    "proof_vector.canonical_stark_proof_artifact.public_inputs_hash_hex",
                )?,
                trace_digest: decode_hex_32_field(
                    &file.canonical_stark_proof_artifact.trace_digest_hex,
                    "proof_vector.canonical_stark_proof_artifact.trace_digest_hex",
                )?,
                trace_layout_digest: decode_hex_32_field(
                    &file.canonical_stark_proof_artifact.trace_layout_digest_hex,
                    "proof_vector.canonical_stark_proof_artifact.trace_layout_digest_hex",
                )?,
                proof_binding_digest: decode_hex_32_field(
                    &file.canonical_stark_proof_artifact.proof_binding_digest_hex,
                    "proof_vector.canonical_stark_proof_artifact.proof_binding_digest_hex",
                )?,
                proof_bytes: decode_hex_field(
                    &file.canonical_stark_proof_artifact.proof_bytes_hex,
                    "proof_vector.canonical_stark_proof_artifact.proof_bytes_hex",
                )?,
            },
            proof_tamper: file
                .proof_tamper
                .map(|tamper| {
                    Ok::<ProofVectorTamperV1, LocalChainErrorV1>(ProofVectorTamperV1 {
                        target: ProofVectorTamperTargetV1::from_str(&tamper.target)?,
                        byte_offset: tamper.byte_offset,
                        xor_with: tamper.xor_with,
                    })
                })
                .transpose()?,
            expected_result: ScenarioResultV1::from_str(&file.expected_result)?,
        };

        validate_loaded_proof_vector(&fixture)?;
        Ok(fixture)
    }

    fn to_file(&self) -> ProofVectorFixtureFileV1 {
        ProofVectorFixtureFileV1 {
            fixture_schema_version: PROOF_VECTOR_FIXTURE_SCHEMA_VERSION_V1,
            fixture_name: self.fixture_name.clone(),
            proof_system: self.proof_system.as_fixture_str().to_string(),
            genesis: ProofVectorGenesisFileV1 {
                rollup_id_hex: encode_hex(&self.genesis.rollup_id),
                accounts: self
                    .genesis
                    .accounts
                    .iter()
                    .map(account_to_fixture)
                    .collect(),
            },
            batch: ProofVectorBatchFileV1 {
                batch_number: self.batch.batch_number,
                parent_batch_commitment_hex: encode_hex(&self.batch.parent_batch_commitment),
                transactions: self
                    .batch
                    .transactions
                    .iter()
                    .map(transfer_to_fixture)
                    .collect(),
            },
            expected_transition: ProofVectorExpectedTransitionFileV1 {
                pre_state_root_hex: encode_hex(&self.expected_transition.pre_state_root),
                post_state_root_hex: encode_hex(&self.expected_transition.post_state_root),
                transactions_commitment_hex: encode_hex(
                    &self.expected_transition.transactions_commitment,
                ),
                outcomes_commitment_hex: encode_hex(&self.expected_transition.outcomes_commitment),
                batch_context_commitment_hex: encode_hex(
                    &self.expected_transition.batch_context_commitment,
                ),
                fee_summary_commitment_hex: encode_hex(
                    &self.expected_transition.fee_summary_commitment,
                ),
                post_state_accounts: self
                    .expected_transition
                    .post_state_accounts
                    .iter()
                    .map(account_to_fixture)
                    .collect(),
                outcomes: self
                    .expected_transition
                    .outcomes
                    .iter()
                    .map(|outcome| ProofVectorExpectedOutcomeFileV1 {
                        tx_index: outcome.tx_index,
                        sender_account_id_hex: encode_hex(&outcome.sender_account_id),
                        consumed_nonce: outcome.consumed_nonce,
                        fee_charged: outcome.fee_charged,
                        touched_accounts_commitment_hex: encode_hex(
                            &outcome.touched_accounts_commitment,
                        ),
                        operation_result_commitment_hex: encode_hex(
                            &outcome.operation_result_commitment,
                        ),
                        status: outcome.status,
                    })
                    .collect(),
            },
            expected_public_inputs: ProofVectorExpectedPublicInputsFileV1 {
                transition_binding_version: self.expected_public_inputs.transition_binding_version,
                rollup_id_hex: encode_hex(&self.expected_public_inputs.rollup_id),
                execution_model_version: self.expected_public_inputs.execution_model_version,
                batch_version: self.expected_public_inputs.batch_version,
                batch_number: self.expected_public_inputs.batch_number,
                parent_batch_commitment_hex: encode_hex(
                    &self.expected_public_inputs.parent_batch_commitment,
                ),
                tx_count: self.expected_public_inputs.tx_count,
                fee_summary_commitment_hex: encode_hex(
                    &self.expected_public_inputs.fee_summary_commitment,
                ),
                pre_state_root_hex: encode_hex(&self.expected_public_inputs.pre_state_root),
                post_state_root_hex: encode_hex(&self.expected_public_inputs.post_state_root),
                transactions_commitment_hex: encode_hex(
                    &self.expected_public_inputs.transactions_commitment,
                ),
                outcomes_commitment_hex: encode_hex(
                    &self.expected_public_inputs.outcomes_commitment,
                ),
                batch_context_commitment_hex: encode_hex(
                    &self.expected_public_inputs.batch_context_commitment,
                ),
                public_input_bytes_hex: encode_hex(&self.expected_public_inputs.public_input_bytes),
                transition_binding_hash_hex: encode_hex(
                    &self.expected_public_inputs.transition_binding_hash,
                ),
            },
            canonical_stark_proof_artifact: ProofVectorCanonicalStarkArtifactFileV1 {
                prover_kind: self.canonical_stark_proof_artifact.prover_kind,
                proof_version: self.canonical_stark_proof_artifact.proof_version,
                public_inputs_hash_hex: encode_hex(
                    &self.canonical_stark_proof_artifact.public_inputs_hash,
                ),
                trace_digest_hex: encode_hex(&self.canonical_stark_proof_artifact.trace_digest),
                trace_layout_digest_hex: encode_hex(
                    &self.canonical_stark_proof_artifact.trace_layout_digest,
                ),
                proof_binding_digest_hex: encode_hex(
                    &self.canonical_stark_proof_artifact.proof_binding_digest,
                ),
                proof_bytes_hex: encode_hex(&self.canonical_stark_proof_artifact.proof_bytes),
            },
            proof_tamper: self
                .proof_tamper
                .as_ref()
                .map(|tamper| ProofVectorTamperFileV1 {
                    target: tamper.target.as_fixture_str().to_string(),
                    byte_offset: tamper.byte_offset,
                    xor_with: tamper.xor_with,
                }),
            expected_result: match self.expected_result {
                ScenarioResultV1::Accepted => "ACCEPTED",
                ScenarioResultV1::ExecutionRejected => "EXECUTION_REJECTED",
                ScenarioResultV1::VerificationRejected => "VERIFICATION_REJECTED",
                ScenarioResultV1::SettlementRejected => "SETTLEMENT_REJECTED",
            }
            .to_string(),
        }
    }
}

fn account_to_fixture(account: &LocalAccountV1) -> AccountFixtureV1 {
    AccountFixtureV1 {
        account_id_hex: encode_hex(&account.account_id),
        balance: account.balance,
        nonce: account.nonce,
    }
}

fn transfer_to_fixture(tx: &TransferTransactionV1) -> TransferFixtureV1 {
    TransferFixtureV1 {
        sender_account_id_hex: encode_hex(&tx.sender_account_id),
        recipient_account_id_hex: encode_hex(&tx.recipient_account_id),
        sender_nonce: tx.sender_nonce,
        amount: tx.amount,
    }
}

fn load_genesis_fixture<P: AsRef<Path>>(
    path: P,
) -> Result<GenesisFixtureFileV1, LocalChainErrorV1> {
    let bytes = fs::read(path)?;
    let fixture = serde_json::from_slice(&bytes)?;
    validate_genesis_fixture(&fixture)?;
    Ok(fixture)
}

fn load_scenario_fixture<P: AsRef<Path>>(
    path: P,
) -> Result<ScenarioFixtureFileV1, LocalChainErrorV1> {
    let bytes = fs::read(path)?;
    let fixture = serde_json::from_slice(&bytes)?;
    validate_scenario_fixture(&fixture)?;
    Ok(fixture)
}

fn load_canonical_pipeline_request<P: AsRef<Path>>(
    path: P,
) -> Result<CanonicalPipelineRequestV1, LocalChainErrorV1> {
    let bytes = fs::read(path)?;
    let file: CanonicalPipelineRequestFileV1 = serde_json::from_slice(&bytes)?;
    CanonicalPipelineRequestV1::from_file(file)
}

fn decode_hex_32_field(value: &str, field: &'static str) -> Result<[u8; 32], LocalChainErrorV1> {
    decode_hex_exact_field(value, field)
}

fn decode_hex_exact_field<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], LocalChainErrorV1> {
    let bytes = decode_hex_field(value, field)?;
    if bytes.len() != N {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "{field} must decode to {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_field(value: &str, field: &'static str) -> Result<Vec<u8>, LocalChainErrorV1> {
    if value.len() % 2 != 0 {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "{field} must be an even-length hex string, got {} chars",
            value.len()
        )));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        out.push(
            (decode_hex_nibble_field(bytes[i], field)? << 4)
                | decode_hex_nibble_field(bytes[i + 1], field)?,
        );
    }
    Ok(out)
}

fn decode_hex_vec_v1(value: &str, field: &'static str) -> Result<Vec<u8>, LocalChainErrorV1> {
    decode_hex_field(value, field)
}

fn decode_hex_nibble_field(value: u8, field: &'static str) -> Result<u8, LocalChainErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(LocalChainErrorV1::InvalidFixture(format!(
            "{field} contains invalid hex nibble: {}",
            value as char
        ))),
    }
}

fn validate_byte_tamper_offset(
    byte_offset: usize,
    expected_len: usize,
    label: &'static str,
    shape: &'static str,
) -> Result<(), LocalChainErrorV1> {
    if byte_offset >= expected_len {
        return Err(LocalChainErrorV1::InvalidFixture(format!(
            "{label} tamper offset {byte_offset} out of range for {shape}"
        )));
    }
    Ok(())
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn encode_base58_like_wallet_v1(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    for byte in bytes {
        if *byte == 0 {
            digits.push(0);
        } else {
            break;
        }
    }
    digits
        .iter()
        .rev()
        .map(|digit| ALPHABET[*digit as usize] as char)
        .collect()
}

fn wallet_address_is_base58_v1(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&byte)
        })
}

#[cfg(test)]
mod tests {
    mod cryptanalytic_reduced_bit_research_v1;

    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ed25519_dalek::{Keypair, PublicKey as DalekPublicKey, SecretKey, Signer};
    use serde_json::Value;

    use super::{
        assert_stark_artifact_matches_expected, build_proof_vector_from_paths_with_proof_system,
        canonical_pipeline_request_summary_consistency_audit_v1, encode_hex,
        load_canonical_pipeline_request, load_proof_vector_from_path, prepare_proof_vector_runtime,
        run_canonical_pipeline_from_path, run_proof_vector_from_path, run_scenario_from_paths,
        run_scenario_from_paths_with_proof_system, validate_canonical_pipeline_report_v1,
        verify_proof_vector_from_path, write_proof_vector_to_path, LocalChainErrorV1,
        ProofSystemSelectionV1, ScenarioResultV1, CANONICAL_PIPELINE_ID_V1,
        CANONICAL_PIPELINE_SCHEMA_VERSION_V1,
    };
    use aura_l2_prover_v1::prove_executed_batch_with_stark_prover_v1;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn accepted_canonical_pipeline_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/accepted_transfer_request.json")
    }

    fn accepted_attestation_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/accepted_attestation_request.json")
    }

    fn tampered_attestation_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/tampered_attestation_request.json")
    }

    fn ledger_replay_step1_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/ledger_replay_step1_request.json")
    }

    fn ledger_replay_step2_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/ledger_replay_step2_request.json")
    }

    fn mixed_replay_attestation_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/mixed_replay_attestation_request.json")
    }

    fn accepted_stark_attestation_request_path() -> PathBuf {
        repo_root()
            .join("fixtures/l2_canonical_pipeline_v1/accepted_stark_attestation_request.json")
    }

    fn tampered_stark_attestation_request_path() -> PathBuf {
        repo_root()
            .join("fixtures/l2_canonical_pipeline_v1/tampered_stark_attestation_request.json")
    }

    fn external_anchor_mismatch_request_path() -> PathBuf {
        repo_root().join("fixtures/l2_canonical_pipeline_v1/external_anchor_mismatch_request.json")
    }

    fn external_anchor_disconnected_request_path() -> PathBuf {
        repo_root()
            .join("fixtures/l2_canonical_pipeline_v1/external_anchor_disconnected_request.json")
    }

    fn continuous_chain_request_path(name: &str) -> PathBuf {
        repo_root()
            .join("fixtures/l2_canonical_pipeline_v1/continuous_chain_v1")
            .join(name)
    }

    fn accepted_canonical_pipeline_request() -> super::CanonicalPipelineRequestV1 {
        load_canonical_pipeline_request(accepted_canonical_pipeline_request_path()).unwrap()
    }

    fn accepted_attestation_request() -> super::CanonicalPipelineRequestV1 {
        load_canonical_pipeline_request(accepted_attestation_request_path()).unwrap()
    }

    fn accepted_canonical_pipeline_report() -> super::CanonicalPipelineReportV1 {
        run_canonical_pipeline_from_path(accepted_canonical_pipeline_request_path()).unwrap()
    }

    fn write_temp_json(name: &str, value: &Value) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aura_local_chain_v0_{name}_{}_{}.json",
            std::process::id(),
            nanos
        ));
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    fn temp_head_state_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aura_local_chain_v0_{name}_{}_{}.json",
            std::process::id(),
            nanos
        ))
    }

    fn authoritative_options(head_state_path: &PathBuf) -> super::CanonicalPipelineRunOptionsV1 {
        super::CanonicalPipelineRunOptionsV1 {
            stateless: false,
            head_state_path: Some(head_state_path.to_string_lossy().into_owned()),
        }
    }

    fn stateless_options(head_state_path: &PathBuf) -> super::CanonicalPipelineRunOptionsV1 {
        super::CanonicalPipelineRunOptionsV1 {
            stateless: true,
            head_state_path: Some(head_state_path.to_string_lossy().into_owned()),
        }
    }

    fn load_head_state(head_state_path: &PathBuf) -> super::CanonicalPipelineHeadStateFileV1 {
        super::canonical_pipeline_load_head_state_v1(&head_state_path.to_string_lossy())
            .unwrap()
            .expect("head state")
    }

    fn set_request_head(
        request: &mut super::CanonicalPipelineRequestV1,
        previous_head_hash: [u8; 32],
        head_sequence_number: u64,
    ) {
        request.head.previous_head_hash = previous_head_hash;
        request.head.head_sequence_number = head_sequence_number;
    }

    fn retune_declared_fee_units(request: &mut super::CanonicalPipelineRequestV1) {
        let state = super::LocalStateV1::new(request.accounts.clone()).unwrap();
        request.economic.declared_fee_units =
            super::compute_canonical_pipeline_burn_units_v1(request, &state.ordered_accounts())
                .unwrap();
    }

    fn fixed_provenance_keypair() -> Keypair {
        let secret = SecretKey::from_bytes(&[7u8; 32]).unwrap();
        let public = DalekPublicKey::from(&secret);
        Keypair { secret, public }
    }

    fn set_signed_provenance(
        request: &mut super::CanonicalPipelineRequestV1,
        valid_signature: bool,
    ) {
        let attestation = request.attestation.as_mut().expect("attestation request");
        let prepared = super::canonical_pipeline_prepare_attestation_v1(attestation).unwrap();
        let evidence_digest = prepared.evidence_summary.evidence_items[0].evidence_digest;
        let evidence_item = attestation
            .evidence_items
            .get_mut(0)
            .expect("evidence item");
        evidence_item.provenance.provenance_type =
            super::CanonicalPipelineEvidenceProvenanceTypeV1::SignedBlob;
        evidence_item.provenance.source_type = "signed_fixture".to_string();
        evidence_item.provenance.source_identifier = format!("{}:signed", evidence_item.label);
        evidence_item.provenance.timestamp_unix_seconds = Some(1_711_111_111);
        evidence_item.provenance.signature = None;

        let keypair = fixed_provenance_keypair();
        let message = super::canonical_pipeline_provenance_signature_message_v1(
            &evidence_item.label,
            evidence_digest,
            &evidence_item.provenance,
        );
        let mut signature = keypair.sign(&message).to_bytes();
        if !valid_signature {
            signature[0] ^= 0xff;
        }
        evidence_item.provenance.signature = Some(super::CanonicalPipelineEvidenceSignatureV1 {
            signer_public_key: keypair.public.to_bytes(),
            signature,
        });
    }

    #[test]
    fn canonical_fixtures_run_with_stable_results() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let valid = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/valid_transfer_batch.json"),
        )
        .unwrap();
        assert_eq!(valid.actual_result, ScenarioResultV1::Accepted);

        let accepted = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/accepted_transition_example.json"),
        )
        .unwrap();
        assert_eq!(accepted.actual_result, ScenarioResultV1::Accepted);

        let invalid_nonce = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/invalid_nonce_batch.json"),
        )
        .unwrap();
        assert_eq!(
            invalid_nonce.actual_result,
            ScenarioResultV1::ExecutionRejected
        );

        let insufficient_balance = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/insufficient_balance_batch.json"),
        )
        .unwrap();
        assert_eq!(
            insufficient_balance.actual_result,
            ScenarioResultV1::ExecutionRejected
        );

        let tampered_public_inputs = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/tampered_public_input_vector.json"),
        )
        .unwrap();
        assert_eq!(
            tampered_public_inputs.actual_result,
            ScenarioResultV1::VerificationRejected
        );

        let tampered_proof = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/tampered_proof_artifact.json"),
        )
        .unwrap();
        assert_eq!(
            tampered_proof.actual_result,
            ScenarioResultV1::VerificationRejected
        );

        let rejected = run_scenario_from_paths(
            &genesis,
            root.join("fixtures/l2_local_v1/rejected_transition_example.json"),
        )
        .unwrap();
        assert_eq!(
            rejected.actual_result,
            ScenarioResultV1::VerificationRejected
        );
    }

    #[test]
    fn canonical_fixture_runs_with_real_stark_path() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let accepted = run_scenario_from_paths_with_proof_system(
            &genesis,
            root.join("fixtures/l2_local_v1/accepted_transition_example.json"),
            ProofSystemSelectionV1::Stark,
        )
        .unwrap();
        assert_eq!(accepted.actual_result, ScenarioResultV1::Accepted);
    }

    #[test]
    fn canonical_pipeline_request_fixture_runs_with_stable_results() {
        let root = repo_root();
        let report = run_canonical_pipeline_from_path(
            root.join("fixtures/l2_canonical_pipeline_v1/accepted_transfer_request.json"),
        )
        .unwrap();

        assert_eq!(
            report.pipeline_schema_version,
            CANONICAL_PIPELINE_SCHEMA_VERSION_V1
        );
        assert_eq!(report.pipeline_id, CANONICAL_PIPELINE_ID_V1);
        assert_eq!(report.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(report.request_audit.tx_count, 1);
        assert_eq!(
            report.stage_outcomes,
            crate::stage_outcomes_for_actual_result_v1(ScenarioResultV1::Accepted)
        );
        assert_eq!(report.burn_summary.burn_policy_version, 1);
        assert_eq!(report.burn_summary.declared_fee_units, 49);
        assert_eq!(report.burn_summary.computed_burn_units, 49);
        assert_eq!(report.burn_summary.consumed_burn_units, 49);
        assert!(report.burn_summary.request_declares_correct_burn);
        assert!(report.burn_summary.recomputed_burn_matches_report);
        assert!(report.burn_summary.burn_consumed);
        assert_eq!(
            report.accounting_summary.declared_fee_units,
            report.burn_summary.declared_fee_units
        );
        assert_eq!(
            report.accounting_summary.computed_burn_units,
            report.burn_summary.computed_burn_units
        );
        assert!(report.accounting_summary.accounting_consistent_with_burn);
        assert!(report.accounting_summary.accounting_consistent_with_outcome);
        assert_eq!(
            report.executed_post_state_root,
            report.settlement_committed_state_root
        );
        assert_eq!(
            encode_hex(
                &report
                    .public_inputs
                    .as_ref()
                    .expect("public inputs")
                    .transition_binding_hash
            ),
            "32177663f350097973e712ff2e980836bbc696e97e311c52aeaf9e730380d0b7"
        );
        assert_eq!(
            encode_hex(
                &report
                    .proof_artifact
                    .as_ref()
                    .expect("proof artifact")
                    .proof_binding_digest
            ),
            "dc34a7792af0955f7f544976c56c42940aa1820c633797db9a987660944cb851"
        );
    }

    #[test]
    fn canonical_pipeline_tampered_request_fails_closed() {
        let root = repo_root();
        let report = run_canonical_pipeline_from_path(
            root.join("fixtures/l2_canonical_pipeline_v1/tampered_proof_binding_request.json"),
        )
        .unwrap();

        assert_eq!(report.actual_result, ScenarioResultV1::VerificationRejected);
        assert_eq!(
            report.stage_outcomes,
            crate::stage_outcomes_for_actual_result_v1(ScenarioResultV1::VerificationRejected)
        );
        assert!(report.public_inputs.is_some());
        assert!(report.proof_artifact.is_some());
        assert!(report.settlement_committed_state_root.is_none());
        assert_eq!(report.burn_summary.computed_burn_units, 49);
    }

    #[test]
    fn canonical_pipeline_attestation_request_runs_on_the_same_path() {
        let report = run_canonical_pipeline_from_path(accepted_attestation_request_path()).unwrap();

        assert_eq!(report.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(
            report.burn_summary.request_kind,
            super::CanonicalPipelineRequestKindV1::Attestation
        );
        assert_eq!(report.request_audit.tx_count, 0);
        assert_eq!(report.burn_summary.declared_fee_units, 48);
        assert_eq!(report.burn_summary.computed_burn_units, 48);
        assert_eq!(
            report.executed_post_state_root,
            report.settlement_committed_state_root
        );
        let attestation_summary = report
            .attestation_summary
            .as_ref()
            .expect("attestation summary");
        assert_eq!(
            attestation_summary.attestation_status,
            super::CanonicalPipelineAttestationStatusV1::Accepted
        );
        assert!(attestation_summary.consistency_result.consistent);
        assert_eq!(
            attestation_summary.attestation_failure_reason.reason,
            super::CanonicalPipelineAttestationFailureReasonV1::None
        );
        assert_eq!(attestation_summary.evidence_summary.evidence_item_count, 1);
        assert!(
            attestation_summary
                .normalization_summary
                .normalization_succeeded
        );
        let attestation_proof_summary = report
            .attestation_proof_summary
            .as_ref()
            .expect("attestation proof summary");
        assert_eq!(
            attestation_proof_summary.proof_kind,
            super::CanonicalPipelineAttestationProofKindV1::Mock
        );
        assert!(attestation_proof_summary.verification_passed);
    }

    #[test]
    fn canonical_pipeline_tampered_attestation_request_fails_closed_on_the_same_path() {
        let report = run_canonical_pipeline_from_path(tampered_attestation_request_path()).unwrap();

        assert_eq!(report.actual_result, ScenarioResultV1::ExecutionRejected);
        assert_eq!(
            report.burn_summary.request_kind,
            super::CanonicalPipelineRequestKindV1::Attestation
        );
        assert_eq!(report.burn_summary.declared_fee_units, 48);
        assert_eq!(report.burn_summary.computed_burn_units, 48);
        assert!(report.burn_summary.burn_consumed);
        assert_eq!(report.public_inputs, None);
        assert_eq!(report.proof_artifact, None);
        assert_eq!(report.request_audit.tx_count, 0);
        let attestation_summary = report
            .attestation_summary
            .as_ref()
            .expect("attestation summary");
        assert_eq!(
            attestation_summary.attestation_status,
            super::CanonicalPipelineAttestationStatusV1::Rejected
        );
        assert!(!attestation_summary.consistency_result.consistent);
        assert_eq!(
            attestation_summary.attestation_failure_reason.reason,
            super::CanonicalPipelineAttestationFailureReasonV1::ConsistencyMismatch
        );
        let attestation_proof_summary = report
            .attestation_proof_summary
            .as_ref()
            .expect("attestation proof summary");
        assert_eq!(
            attestation_proof_summary.proof_kind,
            super::CanonicalPipelineAttestationProofKindV1::Mock
        );
        assert!(!attestation_proof_summary.verification_passed);
        assert_eq!(
            report
                .accounting_summary
                .settlement_record
                .settlement_status,
            super::CanonicalPipelineSettlementStatusV1::NotRun
        );
    }

    #[test]
    fn canonical_pipeline_wallet_binding_mismatch_rejects_in_settlement() {
        let mut request = accepted_canonical_pipeline_request();
        request.expected_result = ScenarioResultV1::SettlementRejected;
        request.wallet_binding.account_id = [0x22; 32];

        let report = super::run_canonical_pipeline_request(&request).unwrap();

        assert_eq!(report.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            report.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch
        );
        assert_eq!(
            report.status_explanation.detail,
            "wallet_binding.account_id 2222222222222222222222222222222222222222222222222222222222222222 does not match ledger.payer_account_id 1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert!(
            !report
                .wallet_binding_summary
                .binding_consistent_with_account
        );
        assert_eq!(
            report
                .accounting_summary
                .settlement_record
                .settlement_status,
            super::CanonicalPipelineSettlementStatusV1::Rejected
        );
        assert_eq!(report.burn_summary.consumed_burn_units, 49);
        assert!(report.public_inputs.is_some());
        assert!(report.proof_artifact.is_some());
    }

    #[test]
    fn canonical_pipeline_provenance_without_signature_relevance_keeps_attestation_outcome_stable()
    {
        let baseline =
            super::run_canonical_pipeline_request(&accepted_attestation_request()).unwrap();
        let mut request = accepted_attestation_request();
        let provenance = &mut request
            .attestation
            .as_mut()
            .expect("attestation")
            .evidence_items[0]
            .provenance;
        provenance.source_type = "archive".to_string();
        provenance.source_identifier = "invoice_replay".to_string();
        retune_declared_fee_units(&mut request);

        let variant = super::run_canonical_pipeline_request(&request).unwrap();
        let baseline_attestation = baseline.attestation_summary.as_ref().expect("attestation");
        let variant_attestation = variant.attestation_summary.as_ref().expect("attestation");
        let baseline_provenance = baseline.provenance_summary.as_ref().expect("provenance");
        let variant_provenance = variant.provenance_summary.as_ref().expect("provenance");
        let baseline_item = &baseline_attestation.evidence_summary.evidence_items[0];
        let variant_item = &variant_attestation.evidence_summary.evidence_items[0];

        assert_eq!(baseline.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(variant.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(
            baseline_attestation.attestation_status,
            variant_attestation.attestation_status
        );
        assert_eq!(
            baseline_attestation.consistency_result,
            variant_attestation.consistency_result
        );
        assert_eq!(
            baseline_attestation.evidence_summary.evidence_root_digest,
            variant_attestation.evidence_summary.evidence_root_digest
        );
        assert_eq!(
            baseline_attestation.normalization_summary,
            variant_attestation.normalization_summary
        );
        assert_eq!(baseline_item.evidence_digest, variant_item.evidence_digest);
        assert_eq!(
            baseline_item.normalized_payload_utf8,
            variant_item.normalized_payload_utf8
        );
        assert_ne!(
            baseline_provenance.provenance_root_digest,
            variant_provenance.provenance_root_digest
        );
        assert_ne!(
            baseline_item.provenance_digest,
            variant_item.provenance_digest
        );
    }

    #[test]
    fn canonical_pipeline_provenance_signature_validity_only_changes_signature_surface() {
        let mut valid_request = accepted_attestation_request();
        set_signed_provenance(&mut valid_request, true);
        retune_declared_fee_units(&mut valid_request);
        valid_request.expected_result = ScenarioResultV1::Accepted;
        let valid = super::run_canonical_pipeline_request(&valid_request).unwrap();

        let mut invalid_request = valid_request.clone();
        set_signed_provenance(&mut invalid_request, false);
        retune_declared_fee_units(&mut invalid_request);
        invalid_request.expected_result = ScenarioResultV1::ExecutionRejected;
        let invalid = super::run_canonical_pipeline_request(&invalid_request).unwrap();

        let valid_attestation = valid.attestation_summary.as_ref().expect("attestation");
        let invalid_attestation = invalid.attestation_summary.as_ref().expect("attestation");
        let valid_item = &valid_attestation.evidence_summary.evidence_items[0];
        let invalid_item = &invalid_attestation.evidence_summary.evidence_items[0];

        assert_eq!(
            valid_attestation.evidence_summary.evidence_root_digest,
            invalid_attestation.evidence_summary.evidence_root_digest
        );
        assert_eq!(
            valid_attestation.normalization_summary,
            invalid_attestation.normalization_summary
        );
        assert_eq!(
            valid_attestation.consistency_result,
            invalid_attestation.consistency_result
        );
        assert_eq!(valid_item.evidence_digest, invalid_item.evidence_digest);
        assert_eq!(
            valid_item.normalized_payload_utf8,
            invalid_item.normalized_payload_utf8
        );
        assert_ne!(valid_item.provenance_digest, invalid_item.provenance_digest);
        assert!(
            valid
                .provenance_summary
                .as_ref()
                .expect("provenance")
                .all_signature_checks_passed
        );
        assert!(
            !invalid
                .provenance_summary
                .as_ref()
                .expect("provenance")
                .all_signature_checks_passed
        );
        assert_eq!(
            invalid.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::ProvenanceSignatureInvalid
        );
        assert_eq!(invalid.public_inputs, None);
        assert_eq!(invalid.proof_artifact, None);
    }

    #[test]
    fn canonical_pipeline_reports_remain_identical_across_duplicate_runs() {
        let root = repo_root();
        let path = root.join("fixtures/l2_canonical_pipeline_v1/accepted_transfer_request.json");
        let first = run_canonical_pipeline_from_path(&path).unwrap();
        let second = run_canonical_pipeline_from_path(&path).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn canonical_pipeline_report_reconstructs_exactly_from_embedded_material() {
        let report = accepted_canonical_pipeline_report();
        let reconstructed_request =
            super::canonical_pipeline_request_from_report_v1(&report).unwrap();

        assert_eq!(reconstructed_request, accepted_canonical_pipeline_request());
        assert_eq!(
            super::run_canonical_pipeline_request(&reconstructed_request).unwrap(),
            report
        );
    }

    #[test]
    fn canonical_pipeline_tampered_report_reconstructs_exactly_from_embedded_material() {
        let root = repo_root();
        let path =
            root.join("fixtures/l2_canonical_pipeline_v1/tampered_proof_binding_request.json");
        let report = run_canonical_pipeline_from_path(&path).unwrap();
        let reconstructed_request =
            super::canonical_pipeline_request_from_report_v1(&report).unwrap();

        assert_eq!(
            super::run_canonical_pipeline_request(&reconstructed_request).unwrap(),
            report
        );
    }

    #[test]
    fn canonical_pipeline_report_rejects_mutated_request_digests() {
        let mut report = accepted_canonical_pipeline_report();
        report.request_audit.transactions_digest[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("canonical report request_audit drifted from request"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_inconsistent_genesis_accounts_material() {
        let mut report = accepted_canonical_pipeline_report();
        report.genesis_accounts.ordered_accounts.swap(0, 1);

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("strictly ordered"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_inconsistent_transactions_expansion() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .commitment_expansions
            .transactions
            .transactions_commitment[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("commitment_expansions.transactions contradict ordered_transactions"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_inconsistent_outcomes_expansion() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .commitment_expansions
            .outcomes
            .as_mut()
            .expect("outcomes expansion")
            .outcomes[0]
            .touched_accounts_commitment[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("commitment_expansions.outcomes contradicts its applied_steps"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_inconsistent_batch_context_expansion() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .commitment_expansions
            .batch_context
            .fee_parameters
            .fee_per_transfer = 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("commitment_expansions.batch_context"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_inconsistent_fee_summary_expansion() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .commitment_expansions
            .fee_summary
            .fee_summary
            .tx_count += 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("commitment_expansions.fee_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_burn_summary() {
        let mut report = accepted_canonical_pipeline_report();
        report.burn_summary.computed_burn_units += 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("burn_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_mismatched_burn_recomputation_inputs() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .burn_summary
            .burn_derivation_inputs
            .metered_request_size_bytes += 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("burn_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_contradictory_burn_outcome_states() {
        let mut report = accepted_canonical_pipeline_report();
        report.burn_summary.burn_consumed = false;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("burn_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_mismatched_accounting_summary() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .accounting_summary
            .settlement_record
            .future_token_binding_units += 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("accounting_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_inconsistent_attestation_material() {
        let mut report =
            run_canonical_pipeline_from_path(accepted_attestation_request_path()).unwrap();
        report
            .attestation_summary
            .as_mut()
            .expect("attestation summary")
            .evidence_summary
            .evidence_root_digest[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("attestation_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_normalization_surface() {
        let mut report =
            run_canonical_pipeline_from_path(accepted_attestation_request_path()).unwrap();
        report
            .attestation_summary
            .as_mut()
            .expect("attestation summary")
            .evidence_summary
            .evidence_items[0]
            .normalized_payload_utf8
            .push('!');

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("attestation_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_wallet_binding_summary() {
        let mut report = accepted_canonical_pipeline_report();
        report.wallet_binding_summary.wallet_binding_digest[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("wallet_binding_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_provenance_summary() {
        let mut report =
            run_canonical_pipeline_from_path(accepted_attestation_request_path()).unwrap();
        report
            .provenance_summary
            .as_mut()
            .expect("provenance summary")
            .provenance_root_digest[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("provenance_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_accepted_status_explanation() {
        let mut report = accepted_canonical_pipeline_report();
        report.status_explanation.detail = "tampered accepted detail".to_string();

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("accepted status_explanation"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_missing_request_summary_consistency() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .public_inputs
            .as_mut()
            .expect("public inputs")
            .request_summary_consistency = None;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("request_summary_consistency"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_unsupported_nested_public_input_versions() {
        let mut report = accepted_canonical_pipeline_report();
        let request_audit = report.request_audit.clone();
        let commitment_expansions = report.commitment_expansions.clone();
        let pre_state_root = report.pre_state_root;
        let executed_post_state_root = report.executed_post_state_root.expect("post-state root");
        let public_inputs = report.public_inputs.as_mut().expect("public inputs");
        let decoded = public_inputs
            .decoded_public_inputs
            .as_mut()
            .expect("decoded public inputs");
        decoded.batch_version = 99;
        public_inputs.request_summary_consistency =
            canonical_pipeline_request_summary_consistency_audit_v1(
                public_inputs,
                &request_audit,
                &commitment_expansions,
                pre_state_root,
                executed_post_state_root,
            );

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("supported canonical versions"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_contradictory_proof_binding_consistency() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .proof_artifact
            .as_mut()
            .expect("proof artifact")
            .consistency
            .proof_binding_digest_matches_recomputed = false;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("proof_artifact.consistency"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_verification_rejected_without_verification_mismatch() {
        let mut report = accepted_canonical_pipeline_report();
        let request = accepted_canonical_pipeline_request();
        report.actual_result = ScenarioResultV1::VerificationRejected;
        report.stage_outcomes =
            crate::stage_outcomes_for_actual_result_v1(ScenarioResultV1::VerificationRejected);
        report.settlement_committed_state_root = None;
        report.status_explanation = super::canonical_pipeline_status_explanation_v1(
            report.burn_summary.request_kind,
            ScenarioResultV1::VerificationRejected,
            super::CanonicalPipelineFailureReasonCodeV1::VerificationLayerMismatch,
            "verification-layer mismatch detected inside canonical report material",
        );
        report.accounting_summary = super::canonical_pipeline_accounting_summary_v1(
            &request,
            &report.burn_summary,
            &report.accounting_summary.burn_record,
            ScenarioResultV1::VerificationRejected,
            None,
        );

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("verification-layer mismatch"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_unsupported_economic_policy_versions() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["economic"]["economic_policy_version"] = Value::from(99u64);
        let temp = write_temp_json("invalid_canonical_economic_policy_version", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported canonical pipeline economic_policy_version"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_unsupported_accounting_policy_versions() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["accounting"]["accounting_policy_version"] = Value::from(99u64);
        let temp = write_temp_json("invalid_canonical_accounting_policy_version", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported canonical pipeline accounting_policy_version"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_unsupported_ledger_policy_versions() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["ledger"]["ledger_policy_version"] = Value::from(99u64);
        let temp = write_temp_json("invalid_canonical_ledger_policy_version", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported canonical pipeline ledger_policy_version"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_malformed_economic_sections() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["economic"]["unexpected_field"] = Value::Bool(true);
        let temp = write_temp_json("invalid_canonical_economic_shape", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_malformed_accounting_sections() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["accounting"]["unexpected_field"] = Value::Bool(true);
        let temp = write_temp_json("invalid_canonical_accounting_shape", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_malformed_ledger_sections() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["ledger"]["unexpected_field"] = Value::Bool(true);
        let temp = write_temp_json("invalid_canonical_ledger_shape", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_unsupported_request_kinds() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["economic"]["request_kind"] = Value::from("INVALID_KIND");
        let temp = write_temp_json("invalid_canonical_request_kind", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("request_kind") || message.contains("unknown variant"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_declared_fee_drift() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["economic"]["declared_fee_units"] = Value::from(41u64);
        let temp = write_temp_json("invalid_canonical_declared_fee_units", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("economic.declared_fee_units must equal computed burn units"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_insufficient_ledger_balance_for_burn() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["ledger"]["total_supply"] = Value::from(291u64);
        parsed["ledger"]["accounts"][0]["balance"] = Value::from(41u64);
        let temp = write_temp_json("invalid_canonical_ledger_insufficient_balance", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("canonical pipeline ledger payer balance is insufficient for computed burn"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_execution_requests_with_attestation_material() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_canonical_pipeline_request_path()).unwrap())
                .unwrap();
        parsed["attestation"] = serde_json::json!({
            "attestation_schema_version": 2,
            "attestation_scope": "claim_consistency_with_provided_evidence_only",
            "attestation_proof_kind": "MOCK",
            "normalization_policy_version": 1,
            "attestation_constraints": {
                "require_unique_labels": true,
                "max_evidence_items": 16,
                "max_total_normalized_bytes": 16384
            },
            "claim": {
                "claim_kind": "normalized_text_contains_utf8",
                "claim_payload": {
                    "target_label": "synthetic_evidence",
                    "expected_substring_utf8": "execution requests must not carry attestation material"
                }
            },
            "evidence_items": [{
                "label": "synthetic_evidence",
                "evidence_kind": "inline_utf8",
                "evidence_payload": {
                    "payload_utf8": "execution requests must not carry attestation material"
                },
                "provenance": {
                    "provenance_policy_version": 1,
                    "provenance_type": "inline",
                    "source_type": "fixture",
                    "source_identifier": "synthetic_evidence"
                }
            }]
        });
        let temp = write_temp_json("invalid_execution_attestation_mix", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("request_kind execution must not carry attestation material"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_inconsistent_attestation_transaction_sets() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_attestation_request_path()).unwrap())
                .unwrap();
        parsed["batch"]["transactions"] = Value::Array(vec![serde_json::json!({
            "sender_account_id_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "recipient_account_id_hex": "2222222222222222222222222222222222222222222222222222222222222222",
            "sender_nonce": 0,
            "amount": 1
        })]);
        let temp = write_temp_json("invalid_attestation_transactions", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("request_kind attestation requires zero transactions"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_malformed_attestation_evidence() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_attestation_request_path()).unwrap())
                .unwrap();
        parsed["attestation"]["evidence_items"][0]["evidence_payload"]["payload_utf8"] =
            Value::from("");
        let temp = write_temp_json("invalid_attestation_evidence_payload", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error.to_string().contains(
            "attestation evidence_items[0].evidence_payload.payload_utf8 must not be empty"
        ));
    }

    #[test]
    fn canonical_pipeline_request_rejects_unsupported_provenance_types() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_attestation_request_path()).unwrap())
                .unwrap();
        parsed["attestation"]["evidence_items"][0]["provenance"]["provenance_type"] =
            Value::from("unsupported");
        let temp = write_temp_json("invalid_attestation_provenance_type", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported canonical pipeline evidence_provenance_type"));
    }

    #[test]
    fn canonical_pipeline_request_rejects_malformed_provenance_signatures() {
        let mut parsed: Value =
            serde_json::from_slice(&fs::read(accepted_attestation_request_path()).unwrap())
                .unwrap();
        parsed["attestation"]["evidence_items"][0]["provenance"]["provenance_type"] =
            Value::from("signed_blob");
        parsed["attestation"]["evidence_items"][0]["provenance"]["signature"] = serde_json::json!({
            "signer_public_key_hex": "11".repeat(32),
            "signature_hex": "22".repeat(63)
        });
        let temp = write_temp_json("invalid_attestation_provenance_signature", &parsed);

        let error = load_canonical_pipeline_request(&temp).unwrap_err();
        assert!(error
            .to_string()
            .contains("canonical pipeline provenance signature_hex must decode to 64 bytes"));
    }

    #[test]
    fn canonical_pipeline_stark_attestation_request_runs_on_the_same_path() {
        let request =
            load_canonical_pipeline_request(accepted_stark_attestation_request_path()).unwrap();
        let report =
            run_canonical_pipeline_from_path(accepted_stark_attestation_request_path()).unwrap();

        assert_eq!(
            request
                .attestation
                .as_ref()
                .expect("attestation")
                .attestation_proof_kind,
            super::CanonicalPipelineAttestationProofKindV1::Stark
        );
        assert_eq!(request.proof_system, ProofSystemSelectionV1::Mock);
        assert_eq!(report.actual_result, ScenarioResultV1::Accepted);
        let attestation_proof_summary = report
            .attestation_proof_summary
            .as_ref()
            .expect("attestation proof summary");
        assert_eq!(
            attestation_proof_summary.proof_kind,
            super::CanonicalPipelineAttestationProofKindV1::Stark
        );
        assert!(attestation_proof_summary.verification_passed);
        assert!(attestation_proof_summary
            .stark_public_inputs_digest
            .is_some());
        assert!(attestation_proof_summary.stark_proof_bytes_digest.is_some());
        assert!(attestation_proof_summary
            .stark_proof_binding_digest
            .is_some());
    }

    #[test]
    fn canonical_pipeline_tampered_stark_attestation_request_fails_closed_inside_verification() {
        let report =
            run_canonical_pipeline_from_path(tampered_stark_attestation_request_path()).unwrap();

        assert_eq!(report.actual_result, ScenarioResultV1::VerificationRejected);
        assert_eq!(
            report.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::AttestationProofVerificationRejected
        );
        assert_eq!(report.burn_summary.computed_burn_units, 49);
        let attestation_summary = report
            .attestation_summary
            .as_ref()
            .expect("attestation summary");
        assert_eq!(
            attestation_summary.attestation_status,
            super::CanonicalPipelineAttestationStatusV1::Rejected
        );
        assert_eq!(
            attestation_summary.attestation_failure_reason.reason,
            super::CanonicalPipelineAttestationFailureReasonV1::AttestationProofVerificationFailure
        );
        let attestation_proof_summary = report
            .attestation_proof_summary
            .as_ref()
            .expect("attestation proof summary");
        assert_eq!(
            attestation_proof_summary.proof_kind,
            super::CanonicalPipelineAttestationProofKindV1::Stark
        );
        assert!(!attestation_proof_summary.verification_passed);
    }

    #[test]
    fn canonical_pipeline_report_accepts_consistent_settlement_rejected_accounting_surface() {
        let report =
            run_canonical_pipeline_from_path(external_anchor_mismatch_request_path()).unwrap();

        validate_canonical_pipeline_report_v1(&report).unwrap();
        assert_eq!(report.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            report
                .accounting_summary
                .settlement_record
                .settlement_status,
            super::CanonicalPipelineSettlementStatusV1::Rejected
        );
        assert_eq!(report.accounting_summary.consumed_burn_units, 49);
        assert_eq!(
            report.token_anchor_summary.anchor_verification_status,
            super::CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
        );
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_burn_record_balance_transition() {
        let mut report = accepted_canonical_pipeline_report();
        report.accounting_summary.burn_record.pre_balance += 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("accounting_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_ledger_summary() {
        let mut report = accepted_canonical_pipeline_report();
        report.ledger_summary.burned_supply_after += 1;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("ledger_summary"));
    }

    #[test]
    fn canonical_pipeline_report_rejects_tampered_ledger_state_commitment() {
        let mut report = accepted_canonical_pipeline_report();
        report
            .ledger_summary
            .ledger_state_commitment
            .post_ledger_state_commitment[0] ^= 0xff;

        let error = validate_canonical_pipeline_report_v1(&report).unwrap_err();
        assert!(error.to_string().contains("ledger_summary"));
    }

    #[test]
    fn canonical_pipeline_ledger_replay_sequence_is_deterministic() {
        let step1_first =
            run_canonical_pipeline_from_path(ledger_replay_step1_request_path()).unwrap();
        let step1_second =
            run_canonical_pipeline_from_path(ledger_replay_step1_request_path()).unwrap();
        let step2 = run_canonical_pipeline_from_path(ledger_replay_step2_request_path()).unwrap();

        assert_eq!(step1_first, step1_second);
        assert_eq!(step1_first.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(step2.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            step1_first.accounting_summary.burn_record.post_balance,
            step2.accounting_summary.burn_record.pre_balance
        );
        assert_eq!(
            step1_first.ledger_summary.burned_supply_after,
            step2.ledger_summary.burned_supply_before
        );
        assert_eq!(
            step2.accounting_summary.settlement_record.settlement_status,
            super::CanonicalPipelineSettlementStatusV1::Rejected
        );
        assert_eq!(step2.ledger_summary.burned_supply_after, 94);
        assert_eq!(step2.head_transition_summary.head_sequence_number, 2);
    }

    #[test]
    fn canonical_pipeline_mixed_execution_attestation_replay_is_deterministic() {
        let execution =
            run_canonical_pipeline_from_path(ledger_replay_step1_request_path()).unwrap();
        let attestation_first =
            run_canonical_pipeline_from_path(mixed_replay_attestation_request_path()).unwrap();
        let attestation_second =
            run_canonical_pipeline_from_path(mixed_replay_attestation_request_path()).unwrap();

        assert_eq!(attestation_first, attestation_second);
        assert_eq!(execution.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(
            attestation_first.actual_result,
            ScenarioResultV1::SettlementRejected
        );
        assert_eq!(
            execution.accounting_summary.burn_record.post_balance,
            attestation_first.accounting_summary.burn_record.pre_balance
        );
        assert_eq!(
            execution.ledger_summary.burned_supply_after,
            attestation_first.ledger_summary.burned_supply_before
        );
        let attestation_summary = attestation_first
            .attestation_summary
            .as_ref()
            .expect("attestation summary");
        assert_eq!(
            attestation_summary.attestation_status,
            super::CanonicalPipelineAttestationStatusV1::Rejected
        );
        assert!(attestation_summary.consistency_result.consistent);
        assert_eq!(
            attestation_summary.attestation_failure_reason.reason,
            super::CanonicalPipelineAttestationFailureReasonV1::SettlementLayerFailure
        );
        assert_eq!(
            attestation_first
                .accounting_summary
                .settlement_record
                .settlement_status,
            super::CanonicalPipelineSettlementStatusV1::Rejected
        );
        assert_eq!(
            attestation_first
                .attestation_proof_summary
                .as_ref()
                .expect("attestation proof summary")
                .verification_passed,
            true
        );
        assert_eq!(attestation_first.ledger_summary.burned_supply_after, 95);
    }

    #[test]
    fn canonical_pipeline_external_anchor_disconnects_remain_non_authoritative() {
        let report =
            run_canonical_pipeline_from_path(external_anchor_disconnected_request_path()).unwrap();

        assert_eq!(report.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(
            report.token_anchor_summary.anchor_verification_status,
            super::CanonicalPipelineExternalAnchorVerificationStatusV1::Disconnected
        );
        assert_eq!(
            report
                .accounting_summary
                .settlement_record
                .settlement_status,
            super::CanonicalPipelineSettlementStatusV1::Accepted
        );
        assert_eq!(report.burn_summary.computed_burn_units, 49);
    }

    #[test]
    fn canonical_pipeline_authoritative_head_persistence_matches_continuous_chain_corpus() {
        let head_state_path = temp_head_state_path("continuous_head");
        let head_state_path_string = head_state_path.to_string_lossy().into_owned();
        let options = super::CanonicalPipelineRunOptionsV1 {
            head_state_path: Some(head_state_path_string.clone()),
            stateless: false,
        };

        let step1 = super::run_canonical_pipeline_from_path_with_options(
            continuous_chain_request_path("step01_execution_accept_request.json"),
            &options,
        )
        .unwrap();
        assert_eq!(step1.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(
            step1.head_transition_summary.authority_mode,
            super::CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent
        );
        let persisted_step1 = super::canonical_pipeline_load_head_state_v1(&head_state_path_string)
            .unwrap()
            .expect("persisted head state after step1");
        assert_eq!(persisted_step1.head_sequence_number, 1);
        assert_eq!(
            persisted_step1.current_head_hash_hex,
            encode_hex(&step1.head_transition_summary.current_head_hash)
        );

        let step2 = super::run_canonical_pipeline_from_path_with_options(
            continuous_chain_request_path("step02_head_mismatch_reject_request.json"),
            &options,
        )
        .unwrap();
        assert_eq!(step2.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            step2.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
        );
        let persisted_step2 = super::canonical_pipeline_load_head_state_v1(&head_state_path_string)
            .unwrap()
            .expect("persisted head state after step2");
        assert_eq!(persisted_step2, persisted_step1);

        let step3 = super::run_canonical_pipeline_from_path_with_options(
            continuous_chain_request_path("step03_execution_accept_request.json"),
            &options,
        )
        .unwrap();
        assert_eq!(step3.actual_result, ScenarioResultV1::Accepted);
        let persisted_step3 = super::canonical_pipeline_load_head_state_v1(&head_state_path_string)
            .unwrap()
            .expect("persisted head state after step3");
        assert_ne!(persisted_step3, persisted_step2);
        assert_eq!(persisted_step3.head_sequence_number, 2);
        assert_eq!(
            persisted_step3.current_head_hash_hex,
            encode_hex(&step3.head_transition_summary.current_head_hash)
        );

        let step4 = super::run_canonical_pipeline_from_path_with_options(
            continuous_chain_request_path("step04_anchor_mismatch_reject_request.json"),
            &options,
        )
        .unwrap();
        assert_eq!(step4.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            step4.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected
        );
        let persisted_step4 = super::canonical_pipeline_load_head_state_v1(&head_state_path_string)
            .unwrap()
            .expect("persisted head state after step4");
        assert_ne!(persisted_step4, persisted_step3);
        assert_eq!(persisted_step4.head_sequence_number, 3);
        assert_eq!(
            persisted_step4.current_head_hash_hex,
            encode_hex(&step4.head_transition_summary.current_head_hash)
        );

        let _ = fs::remove_file(head_state_path);
    }

    #[test]
    fn canonical_pipeline_authoritative_head_progression_contract_is_locked() {
        let head_state_path = temp_head_state_path("progression_contract");
        let options = authoritative_options(&head_state_path);

        let step1 = super::run_canonical_pipeline_request_with_options(
            &accepted_canonical_pipeline_request(),
            &options,
        )
        .unwrap();
        let persisted_step1 = load_head_state(&head_state_path);
        assert_eq!(step1.actual_result, ScenarioResultV1::Accepted);
        assert_eq!(persisted_step1.head_sequence_number, 1);

        let mut step2_request =
            load_canonical_pipeline_request(tampered_attestation_request_path()).unwrap();
        set_request_head(
            &mut step2_request,
            step1.head_transition_summary.current_head_hash,
            2,
        );
        let step2 =
            super::run_canonical_pipeline_request_with_options(&step2_request, &options).unwrap();
        let persisted_step2 = load_head_state(&head_state_path);
        assert_eq!(step2.actual_result, ScenarioResultV1::ExecutionRejected);
        assert_eq!(persisted_step2.head_sequence_number, 2);
        assert_eq!(
            persisted_step2.current_head_hash_hex,
            encode_hex(&step2.head_transition_summary.current_head_hash)
        );

        let mut step3_request =
            load_canonical_pipeline_request(tampered_stark_attestation_request_path()).unwrap();
        set_request_head(
            &mut step3_request,
            step2.head_transition_summary.current_head_hash,
            3,
        );
        let step3 =
            super::run_canonical_pipeline_request_with_options(&step3_request, &options).unwrap();
        let persisted_step3 = load_head_state(&head_state_path);
        assert_eq!(step3.actual_result, ScenarioResultV1::VerificationRejected);
        assert_eq!(persisted_step3.head_sequence_number, 3);
        assert_eq!(
            persisted_step3.current_head_hash_hex,
            encode_hex(&step3.head_transition_summary.current_head_hash)
        );

        let mut step4_request =
            load_canonical_pipeline_request(external_anchor_mismatch_request_path()).unwrap();
        set_request_head(
            &mut step4_request,
            step3.head_transition_summary.current_head_hash,
            4,
        );
        let step4 =
            super::run_canonical_pipeline_request_with_options(&step4_request, &options).unwrap();
        let persisted_step4 = load_head_state(&head_state_path);
        assert_eq!(step4.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            step4.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected
        );
        assert_eq!(persisted_step4.head_sequence_number, 4);
        assert_eq!(
            persisted_step4.current_head_hash_hex,
            encode_hex(&step4.head_transition_summary.current_head_hash)
        );

        let mut step5_request = accepted_canonical_pipeline_request();
        step5_request.expected_result = ScenarioResultV1::SettlementRejected;
        set_request_head(&mut step5_request, [0u8; 32], 5);
        let step5 =
            super::run_canonical_pipeline_request_with_options(&step5_request, &options).unwrap();
        let persisted_step5 = load_head_state(&head_state_path);
        assert_eq!(step5.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            step5.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
        );
        assert_eq!(persisted_step5, persisted_step4);

        let _ = fs::remove_file(head_state_path);
    }

    #[test]
    fn canonical_pipeline_head_mismatch_overrides_other_settlement_rejections() {
        let head_state_path = temp_head_state_path("head_override");
        let options = authoritative_options(&head_state_path);
        let step1 = super::run_canonical_pipeline_request_with_options(
            &accepted_canonical_pipeline_request(),
            &options,
        )
        .unwrap();
        let persisted_step1 = load_head_state(&head_state_path);

        let mut wallet_request = accepted_canonical_pipeline_request();
        wallet_request.expected_result = ScenarioResultV1::SettlementRejected;
        wallet_request.wallet_binding.account_id = [0x22; 32];
        set_request_head(&mut wallet_request, [0u8; 32], 2);
        let wallet_report =
            super::run_canonical_pipeline_request_with_options(&wallet_request, &options).unwrap();
        let persisted_wallet = load_head_state(&head_state_path);
        assert_eq!(
            wallet_report.actual_result,
            ScenarioResultV1::SettlementRejected
        );
        assert_eq!(
            wallet_report.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
        );
        assert!(
            !wallet_report
                .wallet_binding_summary
                .binding_consistent_with_account
        );
        assert_eq!(persisted_wallet, persisted_step1);

        let mut anchor_request =
            load_canonical_pipeline_request(external_anchor_mismatch_request_path()).unwrap();
        set_request_head(&mut anchor_request, [0u8; 32], 2);
        let anchor_report =
            super::run_canonical_pipeline_request_with_options(&anchor_request, &options).unwrap();
        let persisted_anchor = load_head_state(&head_state_path);
        assert_eq!(
            anchor_report.actual_result,
            ScenarioResultV1::SettlementRejected
        );
        assert_eq!(
            anchor_report.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
        );
        assert_eq!(
            anchor_report
                .token_anchor_summary
                .anchor_verification_status,
            super::CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
        );
        assert_eq!(persisted_anchor, persisted_step1);

        let _ = fs::remove_file(head_state_path);
        let _ = step1;
    }

    #[test]
    fn canonical_pipeline_wallet_anchor_and_provenance_interactions_use_wallet_precedence() {
        let mut request = accepted_attestation_request();
        request.expected_result = ScenarioResultV1::SettlementRejected;
        request.wallet_binding.account_id = [0x22; 32];
        request.token_anchor =
            load_canonical_pipeline_request(external_anchor_mismatch_request_path())
                .unwrap()
                .token_anchor;
        retune_declared_fee_units(&mut request);

        let report = super::run_canonical_pipeline_request(&request).unwrap();
        let attestation = report.attestation_summary.as_ref().expect("attestation");
        let provenance = report.provenance_summary.as_ref().expect("provenance");

        assert_eq!(report.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            report.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch
        );
        assert!(
            !report
                .wallet_binding_summary
                .binding_consistent_with_account
        );
        assert_eq!(
            report.token_anchor_summary.anchor_verification_status,
            super::CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
        );
        assert!(attestation.consistency_result.consistent);
        assert!(provenance.all_signature_checks_passed);
    }

    #[test]
    fn canonical_pipeline_attestation_provenance_tamper_precedence_is_execution_first() {
        let mut request =
            load_canonical_pipeline_request(accepted_stark_attestation_request_path()).unwrap();
        set_signed_provenance(&mut request, false);
        retune_declared_fee_units(&mut request);
        request.expected_result = ScenarioResultV1::ExecutionRejected;
        request
            .attestation
            .as_mut()
            .expect("attestation")
            .tamper_stark_proof_bytes = Some(super::ByteTamperFixtureV1 {
            byte_offset: 0,
            xor_with: 1,
        });
        retune_declared_fee_units(&mut request);

        let report = super::run_canonical_pipeline_request(&request).unwrap();
        assert_eq!(report.actual_result, ScenarioResultV1::ExecutionRejected);
        assert_eq!(
            report.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::ProvenanceSignatureInvalid
        );
        assert_eq!(report.public_inputs, None);
        assert_eq!(report.proof_artifact, None);
    }

    #[test]
    fn canonical_pipeline_stateless_mode_never_persists_head_state() {
        let head_state_path = temp_head_state_path("stateless_head");
        let report = super::run_canonical_pipeline_request_with_options(
            &accepted_canonical_pipeline_request(),
            &stateless_options(&head_state_path),
        )
        .unwrap();

        assert_eq!(
            report.head_transition_summary.authority_mode,
            super::CanonicalPipelineHeadAuthorityModeV1::StatelessNonAuthoritative
        );
        assert!(!head_state_path.exists());
    }

    #[test]
    fn canonical_pipeline_corrupted_head_state_rejects_fail_closed() {
        let head_state_path = temp_head_state_path("corrupted_head");
        fs::write(
            &head_state_path,
            br#"{"state_file_version":1,"head_sequence_number":1,"current_head_hash_hex":"zz"}"#,
        )
        .unwrap();

        let error = super::run_canonical_pipeline_request_with_options(
            &accepted_canonical_pipeline_request(),
            &authoritative_options(&head_state_path),
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing field") || error.to_string().contains("hex"));

        let _ = fs::remove_file(head_state_path);
    }

    #[test]
    fn canonical_pipeline_skipped_head_sequence_rejects_without_persistence() {
        let head_state_path = temp_head_state_path("skipped_head_sequence");
        let options = authoritative_options(&head_state_path);
        let accepted = super::run_canonical_pipeline_request_with_options(
            &accepted_canonical_pipeline_request(),
            &options,
        )
        .unwrap();
        let persisted_after_accepted = load_head_state(&head_state_path);

        let mut skipped = accepted_canonical_pipeline_request();
        skipped.expected_result = ScenarioResultV1::SettlementRejected;
        set_request_head(
            &mut skipped,
            accepted.head_transition_summary.current_head_hash,
            3,
        );
        let rejected =
            super::run_canonical_pipeline_request_with_options(&skipped, &options).unwrap();
        let persisted_after_rejected = load_head_state(&head_state_path);

        assert_eq!(rejected.actual_result, ScenarioResultV1::SettlementRejected);
        assert_eq!(
            rejected.status_explanation.failure_reason_code,
            super::CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch
        );
        assert_eq!(persisted_after_rejected, persisted_after_accepted);

        let _ = fs::remove_file(head_state_path);
    }

    #[test]
    fn proof_vector_generation_is_reproducible_for_same_inputs() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let scenario = root.join("fixtures/l2_local_v1/accepted_transition_example.json");
        let first = build_proof_vector_from_paths_with_proof_system(
            &genesis,
            &scenario,
            ProofSystemSelectionV1::Stark,
        )
        .unwrap();
        let second = build_proof_vector_from_paths_with_proof_system(
            &genesis,
            &scenario,
            ProofSystemSelectionV1::Stark,
        )
        .unwrap();

        assert_eq!(
            first.expected_public_inputs.public_input_bytes,
            second.expected_public_inputs.public_input_bytes
        );
        assert_eq!(
            first.canonical_stark_proof_artifact,
            second.canonical_stark_proof_artifact
        );
    }

    #[test]
    fn canonical_proof_vectors_run_and_verify() {
        let root = repo_root();
        let accepted = run_proof_vector_from_path(
            root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
        )
        .unwrap();
        assert_eq!(accepted.actual_result, ScenarioResultV1::Accepted);

        let multi = run_proof_vector_from_path(
            root.join("fixtures/l2_proof_vectors_v1/multi_transfer_proof.json"),
        )
        .unwrap();
        assert_eq!(multi.actual_result, ScenarioResultV1::Accepted);

        let edge = verify_proof_vector_from_path(
            root.join("fixtures/l2_proof_vectors_v1/small_trace_edge_case.json"),
        )
        .unwrap();
        assert_eq!(edge.actual_result, ScenarioResultV1::Accepted);

        let tampered = verify_proof_vector_from_path(
            root.join("fixtures/l2_proof_vectors_v1/tampered_proof_case.json"),
        )
        .unwrap();
        assert_eq!(
            tampered.actual_result,
            ScenarioResultV1::VerificationRejected
        );
    }

    #[test]
    fn all_canonical_proof_vectors_rebuild_byte_exactly() {
        let root = repo_root();
        let vectors = [
            "minimal_single_transfer_proof.json",
            "multi_transfer_proof.json",
            "small_trace_edge_case.json",
            "tampered_proof_case.json",
        ];

        for vector in vectors {
            let fixture =
                load_proof_vector_from_path(root.join("fixtures/l2_proof_vectors_v1").join(vector))
                    .unwrap();
            let prepared = prepare_proof_vector_runtime(&fixture).unwrap();
            let regenerated =
                prove_executed_batch_with_stark_prover_v1(&prepared.executed).unwrap();
            assert_stark_artifact_matches_expected(
                &regenerated,
                &fixture.canonical_stark_proof_artifact,
            )
            .unwrap();
        }
    }

    #[test]
    fn malformed_scenario_tamper_offset_rejects_cleanly() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let source = root.join("fixtures/l2_local_v1/tampered_public_input_vector.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["tamper_public_inputs"]["byte_offset"] = Value::from(999u64);
        let temp = write_temp_json("invalid_scenario_tamper", &parsed);
        let error = run_scenario_from_paths(&genesis, &temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_genesis_fixture_name_rejects_cleanly() {
        let root = repo_root();
        let source = root.join("fixtures/l2_local_v1/genesis_state.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["fixture_name"] = Value::from("");
        let temp = write_temp_json("invalid_genesis_name", &parsed);
        let error = run_scenario_from_paths(
            &temp,
            root.join("fixtures/l2_local_v1/accepted_transition_example.json"),
        )
        .unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_genesis_schema_version_rejects_cleanly() {
        let root = repo_root();
        let source = root.join("fixtures/l2_local_v1/genesis_state.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["fixture_schema_version"] = Value::from(99u64);
        let temp = write_temp_json("invalid_genesis_schema_version", &parsed);
        let error = run_scenario_from_paths(
            &temp,
            root.join("fixtures/l2_local_v1/accepted_transition_example.json"),
        )
        .unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_scenario_extra_field_rejects_cleanly() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let source = root.join("fixtures/l2_local_v1/accepted_transition_example.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["unexpected_field"] = Value::from("should not deserialize");
        let temp = write_temp_json("invalid_scenario_extra_field", &parsed);
        let error = run_scenario_from_paths(&genesis, &temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::Json(_)));
    }

    #[test]
    fn malformed_scenario_schema_version_rejects_cleanly() {
        let root = repo_root();
        let genesis = root.join("fixtures/l2_local_v1/genesis_state.json");
        let source = root.join("fixtures/l2_local_v1/accepted_transition_example.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["fixture_schema_version"] = Value::from(99u64);
        let temp = write_temp_json("invalid_scenario_schema_version", &parsed);
        let error = run_scenario_from_paths(&genesis, &temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_proof_vector_rejects_unsupported_proof_system() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["proof_system"] = Value::from("MOCK");
        let temp = write_temp_json("invalid_proof_system", &parsed);
        let error = load_proof_vector_from_path(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_proof_vector_schema_version_rejects_cleanly() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["fixture_schema_version"] = Value::from(99u64);
        let temp = write_temp_json("invalid_proof_vector_schema_version", &parsed);
        let error = load_proof_vector_from_path(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_proof_vector_extra_field_rejects_cleanly() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["unexpected_field"] = Value::from("should not deserialize");
        let temp = write_temp_json("invalid_proof_vector_extra_field", &parsed);
        let error = load_proof_vector_from_path(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::Json(_)));
    }

    #[test]
    fn malformed_proof_vector_rejects_truncated_public_input_bytes() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        let original = parsed["expected_public_inputs"]["public_input_bytes_hex"]
            .as_str()
            .unwrap()
            .to_string();
        parsed["expected_public_inputs"]["public_input_bytes_hex"] =
            Value::from(original[..original.len() - 2].to_string());
        let temp = write_temp_json("invalid_public_inputs", &parsed);
        let error = load_proof_vector_from_path(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn writing_invalid_proof_vector_rejects_before_persisting() {
        let root = repo_root();
        let mut fixture = load_proof_vector_from_path(
            root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
        )
        .unwrap();
        fixture.canonical_stark_proof_artifact.proof_bytes.clear();
        let temp = std::env::temp_dir().join(format!(
            "aura_invalid_proof_vector_write_{}_{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let error = write_proof_vector_to_path(&temp, &fixture).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn proof_vector_reports_are_deterministic_across_duplicate_runs() {
        let root = repo_root();
        let path = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let first = run_proof_vector_from_path(&path).unwrap();
        let second = run_proof_vector_from_path(&path).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn proof_vector_reports_remain_identical_across_twelve_runs() {
        let root = repo_root();
        let path = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let baseline = run_proof_vector_from_path(&path).unwrap();

        for _ in 0..12 {
            let report = run_proof_vector_from_path(&path).unwrap();
            assert_eq!(report, baseline);
        }
    }

    #[test]
    fn every_canonical_vector_rejects_partial_proof_corruption() {
        let root = repo_root();
        for vector in [
            "minimal_single_transfer_proof.json",
            "multi_transfer_proof.json",
            "small_trace_edge_case.json",
        ] {
            let source = root.join("fixtures/l2_proof_vectors_v1").join(vector);
            let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
            parsed["proof_tamper"] = serde_json::json!({
                "target": "PROOF_BYTES",
                "byte_offset": 0,
                "xor_with": 1
            });
            parsed["expected_result"] = Value::from("VERIFICATION_REJECTED");
            let temp = write_temp_json("proof_vector_corruption", &parsed);
            let report = verify_proof_vector_from_path(&temp).unwrap();
            fs::remove_file(temp).ok();

            assert_eq!(report.actual_result, ScenarioResultV1::VerificationRejected);
        }
    }

    #[test]
    fn malformed_proof_vector_rejects_execution_rejected_expectation() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["expected_result"] = Value::from("EXECUTION_REJECTED");
        let temp = write_temp_json("invalid_expected_result_execution", &parsed);
        let error = load_proof_vector_from_path(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }

    #[test]
    fn malformed_proof_vector_rejects_settlement_rejected_expectation() {
        let root = repo_root();
        let source = root.join("fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json");
        let mut parsed: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        parsed["expected_result"] = Value::from("SETTLEMENT_REJECTED");
        let temp = write_temp_json("invalid_expected_result_settlement", &parsed);
        let error = load_proof_vector_from_path(&temp).unwrap_err();
        fs::remove_file(temp).ok();

        assert!(matches!(error, LocalChainErrorV1::InvalidFixture(_)));
    }
}
