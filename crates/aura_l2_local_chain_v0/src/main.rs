use std::{env, path::PathBuf, process::ExitCode};

use aura_l2_execution_v1::{
    AppliedTransferStepV1, ExecutionOutcomeV1, LocalAccountV1, LocalExecutionConfigV1,
    LocalFeeSummaryV1,
};
use aura_l2_local_chain_v0::{
    build_and_write_proof_vector_from_paths_with_proof_system, encode_hex,
    run_canonical_pipeline_from_path_with_options, run_proof_vector_from_path,
    run_scenario_from_paths, run_scenario_from_paths_with_proof_system,
    validate_canonical_pipeline_report_v1, verify_proof_vector_from_path,
    CanonicalPipelineAccountingSummaryV1, CanonicalPipelineAttestationClaimKindV1,
    CanonicalPipelineAttestationClaimPayloadV1, CanonicalPipelineAttestationClaimV1,
    CanonicalPipelineAttestationConsistencyRelationV1,
    CanonicalPipelineAttestationConsistencyResultV1, CanonicalPipelineAttestationConstraintsV1,
    CanonicalPipelineAttestationEvidenceKindV1, CanonicalPipelineAttestationEvidenceSummaryItemV1,
    CanonicalPipelineAttestationEvidenceSummaryV1, CanonicalPipelineAttestationFailureAuditV1,
    CanonicalPipelineAttestationFailureReasonV1,
    CanonicalPipelineAttestationNormalizationSummaryV1,
    CanonicalPipelineAttestationNormalizedFormV1, CanonicalPipelineAttestationProofKindV1,
    CanonicalPipelineAttestationProofSummaryV1, CanonicalPipelineAttestationScopeV1,
    CanonicalPipelineAttestationStatusV1, CanonicalPipelineAttestationSummaryV1,
    CanonicalPipelineBatchContextCommitmentExpansionV1, CanonicalPipelineBurnCategoryV1,
    CanonicalPipelineBurnDerivationInputsV1, CanonicalPipelineBurnFailureSemanticsV1,
    CanonicalPipelineBurnIntentV1, CanonicalPipelineBurnPolicyV1, CanonicalPipelineBurnReasonV1,
    CanonicalPipelineBurnRecordV1, CanonicalPipelineBurnSummaryV1,
    CanonicalPipelineCommitmentExpansionsV1, CanonicalPipelineEvidenceProvenanceTypeV1,
    CanonicalPipelineExecutionConstantsExpansionV1, CanonicalPipelineExecutionStatusV1,
    CanonicalPipelineExternalAnchorVerificationStatusV1,
    CanonicalPipelineExternalBalanceReferenceV1, CanonicalPipelineFailureReasonCodeV1,
    CanonicalPipelineFailureStageV1, CanonicalPipelineFeeDispositionV1,
    CanonicalPipelineFeeParametersExpansionV1, CanonicalPipelineFeeSummaryCommitmentExpansionV1,
    CanonicalPipelineFutureTokenBindingStatusV1, CanonicalPipelineGenesisAccountsV1,
    CanonicalPipelineHeadAuthorityModeV1, CanonicalPipelineHeadTransitionSummaryV1,
    CanonicalPipelineLedgerAccountV1, CanonicalPipelineLedgerAccountsV1,
    CanonicalPipelineLedgerStateCommitmentV1, CanonicalPipelineLedgerSummaryV1,
    CanonicalPipelineNetworkModeV1, CanonicalPipelineOutcomesCommitmentExpansionV1,
    CanonicalPipelinePaymentIntentV1, CanonicalPipelineProofArtifactAuditV1,
    CanonicalPipelineProofArtifactConsistencyAuditV1, CanonicalPipelineProofBindingInputKindV1,
    CanonicalPipelineProvenanceSummaryItemV1, CanonicalPipelineProvenanceSummaryV1,
    CanonicalPipelinePublicInputsAuditV1, CanonicalPipelinePublicInputsDecodeStatusV1,
    CanonicalPipelineReportV1, CanonicalPipelineRequestAuditV1, CanonicalPipelineRequestKindV1,
    CanonicalPipelineRequestSummaryConsistencyAuditV1, CanonicalPipelineRunOptionsV1,
    CanonicalPipelineSettlementAnchorTypeV1, CanonicalPipelineSettlementIntentV1,
    CanonicalPipelineSettlementReasonV1, CanonicalPipelineSettlementRecordV1,
    CanonicalPipelineStageOutcomesV1, CanonicalPipelineStatusExplanationV1,
    CanonicalPipelineTamperAuditV1, CanonicalPipelineTokenAnchorSummaryV1,
    CanonicalPipelineTransactionsCommitmentExpansionV1, CanonicalPipelineTruthArtifactKindV1,
    CanonicalPipelineValidityReferenceExpansionV1, CanonicalPipelineValidityReferenceKindV1,
    CanonicalPipelineWalletBindingSummaryV1, ProofSystemSelectionV1, ProofVectorFixtureV1,
    ProofVectorReportV1, ScenarioReportV1, ScenarioResultV1,
};
use serde::{Deserialize, Serialize};

const USAGE_V1: &str =
    "usage: aura_l2_local_chain_v0 [--output text|json] [--head-state <path>] [--stateless] run-canonical-pipeline <pipeline-request-json>\n\
non-canonical compatibility/repro commands: run-scenario <scenario-json> [genesis-json] | \
run-scenario-stark <scenario-json> [genesis-json] | \
build-proof-vector-stark <scenario-json> <output-json> [genesis-json] | \
run-proof-vector <proof-vector-json> | verify-proof-vector <proof-vector-json>";
const CANONICAL_PIPELINE_USAGE_V1: &str =
    "usage: aura_l2_local_chain_v0 [--output text|json] [--head-state <path>] [--stateless] run-canonical-pipeline <pipeline-request-json>";
const BUILD_PROOF_VECTOR_USAGE_V1: &str =
    "usage: aura_l2_local_chain_v0 [--output text|json] build-proof-vector-stark <scenario-json> <output-json> [genesis-json]";
const RUN_PROOF_VECTOR_USAGE_V1: &str =
    "usage: aura_l2_local_chain_v0 [--output text|json] run-proof-vector <proof-vector-json>";
const VERIFY_PROOF_VECTOR_USAGE_V1: &str =
    "usage: aura_l2_local_chain_v0 [--output text|json] verify-proof-vector <proof-vector-json>";
const BRIDGE_SCHEMA_VERSION_V1: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormatV1 {
    Text,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CliCommandV1 {
    RunCanonicalPipeline {
        request_path: PathBuf,
        head_state_path: Option<PathBuf>,
        stateless: bool,
    },
    RunScenario {
        scenario_path: PathBuf,
        genesis_path: PathBuf,
        proof_system: ProofSystemSelectionV1,
    },
    BuildProofVectorStark {
        scenario_path: PathBuf,
        output_path: PathBuf,
        genesis_path: PathBuf,
    },
    RunProofVector {
        vector_path: PathBuf,
    },
    VerifyProofVector {
        vector_path: PathBuf,
    },
}

impl CliCommandV1 {
    fn name(&self) -> &'static str {
        match self {
            Self::RunCanonicalPipeline { .. } => "run-canonical-pipeline",
            Self::RunScenario {
                proof_system: ProofSystemSelectionV1::Mock,
                ..
            } => "run-scenario",
            Self::RunScenario {
                proof_system: ProofSystemSelectionV1::Stark,
                ..
            } => "run-scenario-stark",
            Self::BuildProofVectorStark { .. } => "build-proof-vector-stark",
            Self::RunProofVector { .. } => "run-proof-vector",
            Self::VerifyProofVector { .. } => "verify-proof-vector",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliV1 {
    output_format: OutputFormatV1,
    command: CliCommandV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BridgeEnvelopeV1<T> {
    bridge_schema_version: u32,
    report_kind: String,
    command: String,
    report: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioBridgeReportV1 {
    fixture_name: String,
    expected_result: String,
    actual_result: String,
    pre_state_root_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_state_root_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transition_binding_hash_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofVectorBridgeReportV1 {
    fixture_name: String,
    proof_system: String,
    expected_result: String,
    actual_result: String,
    pre_state_root_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_state_root_hex: Option<String>,
    transition_binding_hash_hex: String,
    public_inputs_hash_hex: String,
    trace_digest_hex: String,
    trace_layout_digest_hex: String,
    proof_binding_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBridgeReportV1 {
    pipeline_schema_version: u32,
    pipeline_id: String,
    fixture_name: String,
    proof_system: String,
    expected_result: String,
    actual_result: String,
    pre_state_root_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_post_state_root_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_committed_state_root_hex: Option<String>,
    burn_summary: CanonicalPipelineBurnSummaryBridgeV1,
    accounting_summary: CanonicalPipelineAccountingSummaryBridgeV1,
    ledger_summary: CanonicalPipelineLedgerSummaryBridgeV1,
    head_transition_summary: CanonicalPipelineHeadTransitionSummaryBridgeV1,
    wallet_binding_summary: CanonicalPipelineWalletBindingSummaryBridgeV1,
    token_anchor_summary: CanonicalPipelineTokenAnchorSummaryBridgeV1,
    request_audit: CanonicalPipelineRequestBridgeAuditV1,
    genesis_accounts: CanonicalPipelineGenesisAccountsBridgeV1,
    ledger_accounts: CanonicalPipelineLedgerAccountsBridgeV1,
    commitment_expansions: CanonicalPipelineCommitmentExpansionsBridgeV1,
    stage_outcomes: CanonicalPipelineStageOutcomesBridgeV1,
    status_explanation: CanonicalPipelineStatusExplanationBridgeV1,
    attestation_summary: Option<CanonicalPipelineAttestationSummaryBridgeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_proof_summary: Option<CanonicalPipelineAttestationProofSummaryBridgeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance_summary: Option<CanonicalPipelineProvenanceSummaryBridgeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_inputs: Option<CanonicalPipelinePublicInputsBridgeAuditV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_artifact: Option<CanonicalPipelineProofArtifactBridgeAuditV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineHeadTransitionSummaryBridgeV1 {
    settlement_head_version: u32,
    authority_mode: String,
    head_sequence_number: u64,
    previous_head_hash_hex: String,
    current_head_hash_hex: String,
    canonical_head_commitment_hex: String,
    request_canonical_digest_hex: String,
    report_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineWalletBindingSummaryBridgeV1 {
    wallet_binding_version: u32,
    account_id_hex: String,
    wallet_address: String,
    wallet_binding_digest_hex: String,
    binding_consistent_with_account: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineTokenAnchorSummaryBridgeV1 {
    token_policy_version: u32,
    network_mode: String,
    settlement_anchor_type: String,
    anchor_verification_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_balance_reference: Option<CanonicalPipelineExternalBalanceReferenceBridgeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_external_balance: Option<u64>,
    token_anchor_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineExternalBalanceReferenceBridgeV1 {
    reference_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_balance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_slot: Option<u64>,
    connected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineRequestBridgeAuditV1 {
    request_binding_hash_hex: String,
    genesis_accounts_digest_hex: String,
    ledger_accounts_digest_hex: String,
    transactions_digest_hex: String,
    rollup_id_hex: String,
    genesis_account_count: u64,
    ledger_account_count: u64,
    ledger_payer_account_id_hex: String,
    ledger_total_supply: u64,
    ledger_burned_supply: u64,
    batch_number: u64,
    tx_count: u64,
    parent_batch_commitment_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tamper_public_inputs: Option<CanonicalPipelineTamperBridgeAuditV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tamper_proof_binding_digest: Option<CanonicalPipelineTamperBridgeAuditV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tamper_attestation_stark_public_inputs_digest: Option<CanonicalPipelineTamperBridgeAuditV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tamper_attestation_stark_proof_bytes: Option<CanonicalPipelineTamperBridgeAuditV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBurnSummaryBridgeV1 {
    burn_policy_version: u32,
    burn_policy: CanonicalPipelineBurnPolicyBridgeV1,
    burn_reason: String,
    burn_category: String,
    request_kind: String,
    burn_intent: String,
    declared_fee_units: u64,
    computed_burn_units: u64,
    consumed_burn_units: u64,
    burn_derivation_inputs: CanonicalPipelineBurnDerivationInputsBridgeV1,
    request_declares_correct_burn: bool,
    recomputed_burn_matches_report: bool,
    burn_consumed: bool,
    failure_semantics: CanonicalPipelineBurnFailureSemanticsBridgeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBurnPolicyBridgeV1 {
    burn_policy_version: u32,
    base_units: u64,
    execution_request_kind_units: u64,
    attestation_request_kind_units: u64,
    mock_proof_system_units: u64,
    stark_proof_system_units: u64,
    transaction_units_per_item: u64,
    metered_request_size_chunk_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBurnDerivationInputsBridgeV1 {
    tx_count: u64,
    metered_request_size_bytes: u64,
    request_kind: String,
    proof_system: String,
    attestation_evidence_items: u64,
    attestation_claim_bytes: u64,
    attestation_evidence_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBurnFailureSemanticsBridgeV1 {
    execution_rejected_burns_full_amount: bool,
    verification_rejected_burns_full_amount: bool,
    settlement_rejected_burns_full_amount: bool,
    partial_burn_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAccountingSummaryBridgeV1 {
    accounting_policy_version: u32,
    payment_intent: String,
    settlement_intent: String,
    declared_fee_units: u64,
    computed_burn_units: u64,
    consumed_burn_units: u64,
    burn_record: CanonicalPipelineBurnRecordBridgeV1,
    settlement_record: CanonicalPipelineSettlementRecordBridgeV1,
    accounting_consistent_with_burn: bool,
    accounting_consistent_with_outcome: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBurnRecordBridgeV1 {
    burn_reason: String,
    burn_category: String,
    fee_disposition: String,
    account_id_hex: String,
    pre_balance: u64,
    post_balance: u64,
    burned_amount: u64,
    declared_fee_units: u64,
    computed_burn_units: u64,
    consumed_burn_units: u64,
    report_pipeline_id: String,
    report_request_binding_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineLedgerSummaryBridgeV1 {
    ledger_policy_version: u32,
    payer_account_id_hex: String,
    total_supply: u64,
    burned_supply_before: u64,
    burned_supply_after: u64,
    ledger_account_count: u64,
    circulating_supply_before: u64,
    circulating_supply_after: u64,
    ledger_consistent_with_request: bool,
    ledger_consistent_with_burn: bool,
    ledger_consistent_with_supply: bool,
    ledger_state_commitment: CanonicalPipelineLedgerStateCommitmentBridgeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineLedgerStateCommitmentBridgeV1 {
    commitment_version: u32,
    pre_ledger_state_commitment_hex: String,
    post_ledger_state_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineSettlementRecordBridgeV1 {
    settlement_intent: String,
    settlement_status: String,
    settlement_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    committed_state_root_hex: Option<String>,
    future_token_binding_status: String,
    future_token_binding_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineStatusExplanationBridgeV1 {
    truth_artifact_kind: String,
    request_kind: String,
    final_status: String,
    failure_stage: String,
    failure_reason_code: String,
    detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationSummaryBridgeV1 {
    attestation_schema_version: u32,
    attestation_scope: String,
    attestation_proof_kind: String,
    normalization_policy_version: u32,
    attestation_constraints: CanonicalPipelineAttestationConstraintsBridgeV1,
    claim: CanonicalPipelineAttestationClaimBridgeV1,
    claim_digest_hex: String,
    evidence_summary: CanonicalPipelineAttestationEvidenceSummaryBridgeV1,
    normalization_summary: CanonicalPipelineAttestationNormalizationSummaryBridgeV1,
    consistency_result: CanonicalPipelineAttestationConsistencyResultBridgeV1,
    attestation_status: String,
    attestation_failure_reason: CanonicalPipelineAttestationFailureAuditBridgeV1,
    proof_scope_honesty_note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationConstraintsBridgeV1 {
    require_unique_labels: bool,
    max_evidence_items: u64,
    max_total_normalized_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationClaimBridgeV1 {
    claim_kind: String,
    claim_payload: CanonicalPipelineAttestationClaimPayloadBridgeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationClaimPayloadBridgeV1 {
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
struct CanonicalPipelineAttestationEvidenceSummaryBridgeV1 {
    evidence_item_count: u64,
    evidence_items: Vec<CanonicalPipelineAttestationEvidenceSummaryItemBridgeV1>,
    evidence_root_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationEvidenceSummaryItemBridgeV1 {
    label: String,
    evidence_kind: String,
    original_payload_utf8: String,
    original_payload_size_bytes: u64,
    normalized_form: String,
    normalized_payload_utf8: String,
    normalized_payload_size_bytes: u64,
    evidence_digest_hex: String,
    provenance_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationNormalizationSummaryBridgeV1 {
    normalization_policy_version: u32,
    normalized_evidence_count: u64,
    total_normalized_bytes: u64,
    normalization_succeeded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationConsistencyResultBridgeV1 {
    relation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_label: Option<String>,
    consistent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationFailureAuditBridgeV1 {
    reason: String,
    detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAttestationProofSummaryBridgeV1 {
    proof_kind: String,
    attestation_tuple_digest_hex: String,
    verification_passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mock_policy_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stark_policy_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stark_public_inputs_digest_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stark_proof_bytes_digest_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stark_proof_binding_digest_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineProvenanceSummaryBridgeV1 {
    provenance_item_count: u64,
    items: Vec<CanonicalPipelineProvenanceSummaryItemBridgeV1>,
    provenance_root_digest_hex: String,
    all_signature_checks_passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineProvenanceSummaryItemBridgeV1 {
    label: String,
    provenance_policy_version: u32,
    provenance_type: String,
    source_type: String,
    source_identifier: String,
    signature_present: bool,
    signature_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_public_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_unix_seconds: Option<u64>,
    provenance_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineGenesisAccountsBridgeV1 {
    material_version: u32,
    ordered_accounts: Vec<CanonicalPipelineAccountBridgeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineLedgerAccountsBridgeV1 {
    material_version: u32,
    ordered_accounts: Vec<CanonicalPipelineLedgerAccountBridgeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineLedgerAccountBridgeV1 {
    account_id_hex: String,
    balance: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineCommitmentExpansionsBridgeV1 {
    transactions: CanonicalPipelineTransactionsCommitmentExpansionBridgeV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcomes: Option<CanonicalPipelineOutcomesCommitmentExpansionBridgeV1>,
    batch_context: CanonicalPipelineBatchContextCommitmentExpansionBridgeV1,
    fee_summary: CanonicalPipelineFeeSummaryCommitmentExpansionBridgeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineTransactionsCommitmentExpansionBridgeV1 {
    expansion_version: u32,
    transactions_commitment_hex: String,
    ordered_transactions: Vec<CanonicalPipelineTransactionBridgeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineOutcomesCommitmentExpansionBridgeV1 {
    expansion_version: u32,
    outcomes_commitment_hex: String,
    outcomes: Vec<CanonicalPipelineExecutionOutcomeBridgeV1>,
    applied_steps: Vec<CanonicalPipelineAppliedTransferStepBridgeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineBatchContextCommitmentExpansionBridgeV1 {
    expansion_version: u32,
    batch_context_commitment_hex: String,
    transition_binding_version: u32,
    system_config: CanonicalPipelineExecutionConfigBridgeV1,
    fee_parameters: CanonicalPipelineFeeParametersBridgeV1,
    validity_reference: CanonicalPipelineValidityReferenceBridgeV1,
    execution_constants: CanonicalPipelineExecutionConstantsBridgeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineFeeSummaryCommitmentExpansionBridgeV1 {
    expansion_version: u32,
    fee_summary_commitment_hex: String,
    fee_summary: CanonicalPipelineFeeSummaryBridgeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineAccountBridgeV1 {
    account_id_hex: String,
    balance: u64,
    nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineTransactionBridgeV1 {
    tx_version: u32,
    sender_account_id_hex: String,
    recipient_account_id_hex: String,
    sender_nonce: u64,
    amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineExecutionOutcomeBridgeV1 {
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
struct CanonicalPipelineAppliedTransferStepBridgeV1 {
    tx_index: u64,
    sender_account_id_hex: String,
    recipient_account_id_hex: String,
    sender_nonce_before: u64,
    sender_nonce_after: u64,
    sender_balance_before: u64,
    sender_balance_after: u64,
    recipient_balance_before: u64,
    recipient_balance_after: u64,
    amount: u64,
    fee_charged: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineExecutionConfigBridgeV1 {
    rollup_id_hex: String,
    execution_model_version: u32,
    batch_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineFeeParametersBridgeV1 {
    fee_per_transfer: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineValidityReferenceBridgeV1 {
    kind: String,
    none_marker: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineExecutionConstantsBridgeV1 {
    transfer_tx_version: u32,
    transition_binding_version: u32,
    applied_status: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineFeeSummaryBridgeV1 {
    tx_count: u64,
    total_fee_charged: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineTamperBridgeAuditV1 {
    byte_offset: usize,
    xor_with: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineStageOutcomesBridgeV1 {
    execution_status: String,
    verification_status: String,
    settlement_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelinePublicInputsBridgeAuditV1 {
    decode_status: String,
    public_input_bytes_hex: String,
    public_inputs_hash_hex: String,
    transition_binding_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_summary_consistency: Option<CanonicalPipelineRequestSummaryConsistencyBridgeAuditV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_public_inputs: Option<CanonicalPipelineDecodedPublicInputsBridgeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineRequestSummaryConsistencyBridgeAuditV1 {
    transition_binding_version_supported: bool,
    execution_model_version_supported: bool,
    batch_version_supported: bool,
    rollup_id_matches_request_audit: bool,
    batch_number_matches_request_audit: bool,
    tx_count_matches_request_audit: bool,
    parent_batch_commitment_matches_request_audit: bool,
    fee_summary_commitment_matches_expansion: bool,
    pre_state_root_matches_report: bool,
    post_state_root_matches_report: bool,
    transactions_commitment_matches_expansion: bool,
    outcomes_commitment_matches_expansion: bool,
    batch_context_commitment_matches_expansion: bool,
    decoded_bytes_round_trip: bool,
    all_fields_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineDecodedPublicInputsBridgeV1 {
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
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineProofArtifactBridgeAuditV1 {
    prover_kind: u32,
    proof_version: u32,
    public_inputs_hash_hex: String,
    trace_digest_hex: String,
    trace_layout_digest_hex: String,
    proof_binding_digest_hex: String,
    proof_binding_input_kind: String,
    proof_binding_input_digest_hex: String,
    consistency: CanonicalPipelineProofArtifactConsistencyBridgeAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPipelineProofArtifactConsistencyBridgeAuditV1 {
    public_inputs_hash_matches_report: bool,
    prover_kind_matches_proof_system: bool,
    proof_version_supported: bool,
    proof_binding_input_kind_matches_proof_system: bool,
    recomputed_proof_binding_digest_hex: String,
    proof_binding_digest_matches_recomputed: bool,
    all_fields_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildProofVectorBridgeReportV1 {
    fixture_name: String,
    proof_system: String,
    expected_result: String,
    transition_binding_hash_hex: String,
    proof_binding_digest_hex: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_v1(env::args().skip(1))?;
    let command_name = cli.command.name();
    match cli.command {
        CliCommandV1::RunCanonicalPipeline {
            request_path,
            head_state_path,
            stateless,
        } => {
            let report = run_canonical_pipeline_from_path_with_options(
                request_path,
                &CanonicalPipelineRunOptionsV1 {
                    head_state_path: head_state_path
                        .as_ref()
                        .map(|path| path.to_string_lossy().into_owned()),
                    stateless,
                },
            )?;
            print!(
                "{}",
                render_canonical_pipeline_report_v1(cli.output_format, command_name, &report)?
            );
            Ok(())
        }
        CliCommandV1::RunScenario {
            scenario_path,
            genesis_path,
            proof_system,
        } => {
            let report = if proof_system == ProofSystemSelectionV1::Mock {
                run_scenario_from_paths(genesis_path, scenario_path)?
            } else {
                run_scenario_from_paths_with_proof_system(
                    genesis_path,
                    scenario_path,
                    ProofSystemSelectionV1::Stark,
                )?
            };
            print!(
                "{}",
                render_scenario_report_v1(cli.output_format, command_name, &report)?
            );
            Ok(())
        }
        CliCommandV1::BuildProofVectorStark {
            scenario_path,
            output_path,
            genesis_path,
        } => {
            let fixture = build_and_write_proof_vector_from_paths_with_proof_system(
                genesis_path,
                scenario_path,
                output_path,
                ProofSystemSelectionV1::Stark,
            )?;
            print!(
                "{}",
                render_build_proof_vector_report_v1(cli.output_format, command_name, &fixture)?
            );
            Ok(())
        }
        CliCommandV1::RunProofVector { vector_path } => {
            let report = run_proof_vector_from_path(vector_path)?;
            print!(
                "{}",
                render_proof_vector_report_v1(cli.output_format, command_name, &report)?
            );
            Ok(())
        }
        CliCommandV1::VerifyProofVector { vector_path } => {
            let report = verify_proof_vector_from_path(vector_path)?;
            print!(
                "{}",
                render_proof_vector_report_v1(cli.output_format, command_name, &report)?
            );
            Ok(())
        }
    }
}

fn parse_cli_v1(
    args: impl IntoIterator<Item = String>,
) -> Result<CliV1, Box<dyn std::error::Error>> {
    let mut args = args.into_iter();
    let mut output_format = OutputFormatV1::Text;
    let mut canonical_head_state_path: Option<PathBuf> = None;
    let mut canonical_stateless = true;
    let mut canonical_flags_used = false;

    let command = loop {
        let arg = args.next().ok_or(USAGE_V1)?;
        if arg == "--output" {
            output_format = parse_output_format_v1(next_required_arg(&mut args, USAGE_V1)?)?;
            continue;
        }
        if arg == "--head-state" {
            canonical_head_state_path = Some(PathBuf::from(next_required_arg(
                &mut args,
                CANONICAL_PIPELINE_USAGE_V1,
            )?));
            canonical_stateless = false;
            canonical_flags_used = true;
            continue;
        }
        if arg == "--stateless" {
            canonical_stateless = true;
            canonical_flags_used = true;
            continue;
        }
        break arg;
    };

    let command = match command.as_str() {
        "run-canonical-pipeline" => CliCommandV1::RunCanonicalPipeline {
            request_path: PathBuf::from(next_required_arg(
                &mut args,
                CANONICAL_PIPELINE_USAGE_V1,
            )?),
            head_state_path: canonical_head_state_path,
            stateless: canonical_stateless,
        },
        "run-scenario" => CliCommandV1::RunScenario {
            scenario_path: {
                if canonical_flags_used {
                    return Err(
                        "head persistence flags are only supported with run-canonical-pipeline"
                            .into(),
                    );
                }
                PathBuf::from(next_required_arg(&mut args, USAGE_V1)?)
            },
            genesis_path: next_optional_genesis_arg(&mut args),
            proof_system: ProofSystemSelectionV1::Mock,
        },
        "run-scenario-stark" => CliCommandV1::RunScenario {
            scenario_path: {
                if canonical_flags_used {
                    return Err(
                        "head persistence flags are only supported with run-canonical-pipeline"
                            .into(),
                    );
                }
                PathBuf::from(next_required_arg(&mut args, USAGE_V1)?)
            },
            genesis_path: next_optional_genesis_arg(&mut args),
            proof_system: ProofSystemSelectionV1::Stark,
        },
        "build-proof-vector-stark" => CliCommandV1::BuildProofVectorStark {
            scenario_path: {
                if canonical_flags_used {
                    return Err(
                        "head persistence flags are only supported with run-canonical-pipeline"
                            .into(),
                    );
                }
                PathBuf::from(next_required_arg(&mut args, BUILD_PROOF_VECTOR_USAGE_V1)?)
            },
            output_path: PathBuf::from(next_required_arg(&mut args, BUILD_PROOF_VECTOR_USAGE_V1)?),
            genesis_path: next_optional_genesis_arg(&mut args),
        },
        "run-proof-vector" => CliCommandV1::RunProofVector {
            vector_path: {
                if canonical_flags_used {
                    return Err(
                        "head persistence flags are only supported with run-canonical-pipeline"
                            .into(),
                    );
                }
                PathBuf::from(next_required_arg(&mut args, RUN_PROOF_VECTOR_USAGE_V1)?)
            },
        },
        "verify-proof-vector" => CliCommandV1::VerifyProofVector {
            vector_path: {
                if canonical_flags_used {
                    return Err(
                        "head persistence flags are only supported with run-canonical-pipeline"
                            .into(),
                    );
                }
                PathBuf::from(next_required_arg(&mut args, VERIFY_PROOF_VECTOR_USAGE_V1)?)
            },
        },
        _ => {
            return Err(
                "unsupported command; use run-canonical-pipeline or one of the explicitly non-canonical compatibility/repro commands".into(),
            )
        }
    };

    ensure_no_extra_args(&mut args, command.name_usage())?;

    Ok(CliV1 {
        output_format,
        command,
    })
}

trait CliUsageV1 {
    fn name_usage(&self) -> &'static str;
}

impl CliUsageV1 for CliCommandV1 {
    fn name_usage(&self) -> &'static str {
        match self {
            Self::RunCanonicalPipeline { .. } => CANONICAL_PIPELINE_USAGE_V1,
            Self::RunScenario { .. } => USAGE_V1,
            Self::BuildProofVectorStark { .. } => BUILD_PROOF_VECTOR_USAGE_V1,
            Self::RunProofVector { .. } => RUN_PROOF_VECTOR_USAGE_V1,
            Self::VerifyProofVector { .. } => VERIFY_PROOF_VECTOR_USAGE_V1,
        }
    }
}

fn parse_output_format_v1(value: String) -> Result<OutputFormatV1, Box<dyn std::error::Error>> {
    match value.as_str() {
        "text" => Ok(OutputFormatV1::Text),
        "json" => Ok(OutputFormatV1::Json),
        _ => Err(format!("unsupported output format: {value}; expected 'text' or 'json'").into()),
    }
}

fn next_required_arg(
    args: &mut impl Iterator<Item = String>,
    usage: &'static str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next().ok_or_else(|| usage.into())
}

fn next_optional_genesis_arg(args: &mut impl Iterator<Item = String>) -> PathBuf {
    args.next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures/l2_local_v1/genesis_state.json"))
}

fn ensure_no_extra_args(
    args: &mut impl Iterator<Item = String>,
    usage: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(extra) = args.next() {
        return Err(format!("unexpected extra argument: {extra}; {usage}").into());
    }
    Ok(())
}

fn render_scenario_report_v1(
    output_format: OutputFormatV1,
    command: &'static str,
    report: &ScenarioReportV1,
) -> Result<String, Box<dyn std::error::Error>> {
    match output_format {
        OutputFormatV1::Text => {
            let mut output = String::new();
            output.push_str(&format!("fixture_name: {}\n", report.fixture_name));
            output.push_str(&format!(
                "expected_result: {}\n",
                scenario_result_bridge_str_v1(report.expected_result)
            ));
            output.push_str(&format!(
                "actual_result: {}\n",
                scenario_result_bridge_str_v1(report.actual_result)
            ));
            output.push_str(&format!(
                "pre_state_root: {}\n",
                encode_hex(&report.pre_state_root)
            ));
            if let Some(post_state_root) = report.post_state_root {
                output.push_str(&format!(
                    "post_state_root: {}\n",
                    encode_hex(&post_state_root)
                ));
            }
            if let Some(binding_hash) = report.transition_binding_hash {
                output.push_str(&format!(
                    "transition_binding_hash: {}\n",
                    encode_hex(&binding_hash)
                ));
            }
            Ok(output)
        }
        OutputFormatV1::Json => Ok(serde_json::to_string(&BridgeEnvelopeV1 {
            bridge_schema_version: BRIDGE_SCHEMA_VERSION_V1,
            report_kind: "scenario_report_v1".to_string(),
            command: command.to_string(),
            report: ScenarioBridgeReportV1::from(report),
        })?),
    }
}

fn render_canonical_pipeline_report_v1(
    output_format: OutputFormatV1,
    command: &'static str,
    report: &CanonicalPipelineReportV1,
) -> Result<String, Box<dyn std::error::Error>> {
    match output_format {
        OutputFormatV1::Text => {
            let mut output = String::new();
            output.push_str(&format!(
                "pipeline_schema_version: {}\n",
                report.pipeline_schema_version
            ));
            output.push_str(&format!("pipeline_id: {}\n", report.pipeline_id));
            output.push_str(&format!("fixture_name: {}\n", report.fixture_name));
            output.push_str(&format!(
                "proof_system: {}\n",
                proof_system_bridge_str_v1(report.proof_system)
            ));
            output.push_str(&format!(
                "expected_result: {}\n",
                scenario_result_bridge_str_v1(report.expected_result)
            ));
            output.push_str(&format!(
                "actual_result: {}\n",
                scenario_result_bridge_str_v1(report.actual_result)
            ));
            output.push_str(&format!(
                "pre_state_root: {}\n",
                encode_hex(&report.pre_state_root)
            ));
            if let Some(post_state_root) = report.executed_post_state_root {
                output.push_str(&format!(
                    "executed_post_state_root: {}\n",
                    encode_hex(&post_state_root)
                ));
            }
            if let Some(committed_root) = report.settlement_committed_state_root {
                output.push_str(&format!(
                    "settlement_committed_state_root: {}\n",
                    encode_hex(&committed_root)
                ));
            }
            output.push_str(&format!(
                "burn_policy_version: {}\n",
                report.burn_summary.burn_policy_version
            ));
            output.push_str(&format!(
                "request_kind: {}\n",
                canonical_request_kind_bridge_str_v1(report.burn_summary.request_kind)
            ));
            output.push_str(&format!(
                "declared_fee_units: {}\n",
                report.burn_summary.declared_fee_units
            ));
            output.push_str(&format!(
                "computed_burn_units: {}\n",
                report.burn_summary.computed_burn_units
            ));
            output.push_str(&format!(
                "consumed_burn_units: {}\n",
                report.burn_summary.consumed_burn_units
            ));
            output.push_str(&format!(
                "truth_artifact_kind: {}\n",
                canonical_truth_artifact_kind_bridge_str_v1(
                    report.status_explanation.truth_artifact_kind
                )
            ));
            output.push_str(&format!(
                "failure_stage: {}\n",
                canonical_failure_stage_bridge_str_v1(report.status_explanation.failure_stage)
            ));
            output.push_str(&format!(
                "failure_reason_code: {}\n",
                canonical_failure_reason_code_bridge_str_v1(
                    report.status_explanation.failure_reason_code
                )
            ));
            output.push_str(&format!(
                "settlement_reason: {}\n",
                canonical_settlement_reason_bridge_str_v1(
                    report
                        .accounting_summary
                        .settlement_record
                        .settlement_reason
                )
            ));
            output.push_str(&format!(
                "head_authority_mode: {}\n",
                canonical_head_authority_mode_bridge_str_v1(
                    report.head_transition_summary.authority_mode
                )
            ));
            output.push_str(&format!(
                "head_sequence_number: {}\n",
                report.head_transition_summary.head_sequence_number
            ));
            output.push_str(&format!(
                "previous_head_hash: {}\n",
                encode_hex(&report.head_transition_summary.previous_head_hash)
            ));
            output.push_str(&format!(
                "current_head_hash: {}\n",
                encode_hex(&report.head_transition_summary.current_head_hash)
            ));
            output.push_str(&format!(
                "canonical_head_commitment: {}\n",
                encode_hex(&report.head_transition_summary.canonical_head_commitment)
            ));
            output.push_str(&format!(
                "wallet_address: {}\n",
                report.wallet_binding_summary.wallet_address
            ));
            output.push_str(&format!(
                "wallet_binding_digest: {}\n",
                encode_hex(&report.wallet_binding_summary.wallet_binding_digest)
            ));
            output.push_str(&format!(
                "network_mode: {}\n",
                canonical_network_mode_bridge_str_v1(report.token_anchor_summary.network_mode)
            ));
            output.push_str(&format!(
                "settlement_anchor_type: {}\n",
                canonical_settlement_anchor_type_bridge_str_v1(
                    report.token_anchor_summary.settlement_anchor_type
                )
            ));
            output.push_str(&format!(
                "anchor_verification_status: {}\n",
                canonical_external_anchor_verification_status_bridge_str_v1(
                    report.token_anchor_summary.anchor_verification_status
                )
            ));
            output.push_str(&format!(
                "request_binding_hash: {}\n",
                encode_hex(&report.request_audit.request_binding_hash)
            ));
            output.push_str(&format!(
                "request_rollup_id: {}\n",
                encode_hex(&report.request_audit.rollup_id)
            ));
            output.push_str(&format!(
                "request_batch_number: {}\n",
                report.request_audit.batch_number
            ));
            output.push_str(&format!(
                "request_tx_count: {}\n",
                report.request_audit.tx_count
            ));
            output.push_str(&format!(
                "execution_status: {}\n",
                canonical_execution_status_bridge_str_v1(report.stage_outcomes.execution_status)
            ));
            output.push_str(&format!(
                "verification_status: {}\n",
                canonical_verification_status_bridge_str_v1(
                    report.stage_outcomes.verification_status
                )
            ));
            output.push_str(&format!(
                "settlement_status: {}\n",
                canonical_settlement_status_bridge_str_v1(report.stage_outcomes.settlement_status)
            ));
            if let Some(public_inputs) = &report.public_inputs {
                output.push_str(&format!(
                    "public_inputs_decode_status: {}\n",
                    canonical_public_inputs_decode_status_bridge_str_v1(
                        public_inputs.decode_status
                    )
                ));
                output.push_str(&format!(
                    "transition_binding_hash: {}\n",
                    encode_hex(&public_inputs.transition_binding_hash)
                ));
                output.push_str(&format!(
                    "public_inputs_hash: {}\n",
                    encode_hex(&public_inputs.public_inputs_hash)
                ));
            }
            if let Some(proof_artifact) = &report.proof_artifact {
                output.push_str(&format!("prover_kind: {}\n", proof_artifact.prover_kind));
                output.push_str(&format!(
                    "proof_version: {}\n",
                    proof_artifact.proof_version
                ));
                output.push_str(&format!(
                    "proof_binding_digest: {}\n",
                    encode_hex(&proof_artifact.proof_binding_digest)
                ));
            }
            if let Some(attestation_summary) = &report.attestation_summary {
                output.push_str(&format!(
                    "attestation_proof_kind: {}\n",
                    canonical_attestation_proof_kind_bridge_str_v1(
                        attestation_summary.attestation_proof_kind
                    )
                ));
                output.push_str(&format!(
                    "attestation_evidence_root_digest: {}\n",
                    encode_hex(&attestation_summary.evidence_summary.evidence_root_digest)
                ));
                output.push_str(&format!(
                    "attestation_consistency_established: {}\n",
                    attestation_summary.consistency_result.consistent
                ));
            }
            if let Some(attestation_proof_summary) = &report.attestation_proof_summary {
                output.push_str(&format!(
                    "attestation_tuple_digest: {}\n",
                    encode_hex(&attestation_proof_summary.attestation_tuple_digest)
                ));
                output.push_str(&format!(
                    "attestation_proof_verification_passed: {}\n",
                    attestation_proof_summary.verification_passed
                ));
            }
            if let Some(provenance_summary) = &report.provenance_summary {
                output.push_str(&format!(
                    "provenance_root_digest: {}\n",
                    encode_hex(&provenance_summary.provenance_root_digest)
                ));
                output.push_str(&format!(
                    "provenance_all_signature_checks_passed: {}\n",
                    provenance_summary.all_signature_checks_passed
                ));
            }
            Ok(output)
        }
        OutputFormatV1::Json => {
            let json = serde_json::to_string(&BridgeEnvelopeV1 {
                bridge_schema_version: BRIDGE_SCHEMA_VERSION_V1,
                report_kind: "canonical_pipeline_report_v1".to_string(),
                command: command.to_string(),
                report: CanonicalPipelineBridgeReportV1::from(report),
            })?;
            let reparsed = parse_canonical_pipeline_bridge_json_v1(&json)?;
            validate_canonical_pipeline_report_v1(&reparsed)?;
            Ok(json)
        }
    }
}

fn render_proof_vector_report_v1(
    output_format: OutputFormatV1,
    command: &'static str,
    report: &ProofVectorReportV1,
) -> Result<String, Box<dyn std::error::Error>> {
    match output_format {
        OutputFormatV1::Text => {
            let mut output = String::new();
            output.push_str(&format!("fixture_name: {}\n", report.fixture_name));
            output.push_str(&format!(
                "proof_system: {}\n",
                proof_system_bridge_str_v1(report.proof_system)
            ));
            output.push_str(&format!(
                "expected_result: {}\n",
                scenario_result_bridge_str_v1(report.expected_result)
            ));
            output.push_str(&format!(
                "actual_result: {}\n",
                scenario_result_bridge_str_v1(report.actual_result)
            ));
            output.push_str(&format!(
                "pre_state_root: {}\n",
                encode_hex(&report.pre_state_root)
            ));
            if let Some(post_state_root) = report.post_state_root {
                output.push_str(&format!(
                    "post_state_root: {}\n",
                    encode_hex(&post_state_root)
                ));
            }
            output.push_str(&format!(
                "transition_binding_hash: {}\n",
                encode_hex(&report.transition_binding_hash)
            ));
            output.push_str(&format!(
                "public_inputs_hash: {}\n",
                encode_hex(&report.public_inputs_hash)
            ));
            output.push_str(&format!(
                "trace_digest: {}\n",
                encode_hex(&report.trace_digest)
            ));
            output.push_str(&format!(
                "trace_layout_digest: {}\n",
                encode_hex(&report.trace_layout_digest)
            ));
            output.push_str(&format!(
                "proof_binding_digest: {}\n",
                encode_hex(&report.proof_binding_digest)
            ));
            Ok(output)
        }
        OutputFormatV1::Json => Ok(serde_json::to_string(&BridgeEnvelopeV1 {
            bridge_schema_version: BRIDGE_SCHEMA_VERSION_V1,
            report_kind: "proof_vector_report_v1".to_string(),
            command: command.to_string(),
            report: ProofVectorBridgeReportV1::from(report),
        })?),
    }
}

fn render_build_proof_vector_report_v1(
    output_format: OutputFormatV1,
    command: &'static str,
    fixture: &ProofVectorFixtureV1,
) -> Result<String, Box<dyn std::error::Error>> {
    match output_format {
        OutputFormatV1::Text => {
            let mut output = String::new();
            output.push_str(&format!("fixture_name: {}\n", fixture.fixture_name));
            output.push_str(&format!(
                "proof_system: {}\n",
                proof_system_bridge_str_v1(fixture.proof_system)
            ));
            output.push_str(&format!(
                "expected_result: {}\n",
                scenario_result_fixture_str_v1(fixture.expected_result)
            ));
            output.push_str(&format!(
                "transition_binding_hash: {}\n",
                encode_hex(&fixture.expected_public_inputs.transition_binding_hash)
            ));
            output.push_str(&format!(
                "proof_binding_digest: {}\n",
                encode_hex(&fixture.canonical_stark_proof_artifact.proof_binding_digest)
            ));
            Ok(output)
        }
        OutputFormatV1::Json => Ok(serde_json::to_string(&BridgeEnvelopeV1 {
            bridge_schema_version: BRIDGE_SCHEMA_VERSION_V1,
            report_kind: "proof_vector_build_report_v1".to_string(),
            command: command.to_string(),
            report: BuildProofVectorBridgeReportV1::from(fixture),
        })?),
    }
}

fn scenario_result_bridge_str_v1(result: ScenarioResultV1) -> &'static str {
    match result {
        ScenarioResultV1::Accepted => "Accepted",
        ScenarioResultV1::ExecutionRejected => "ExecutionRejected",
        ScenarioResultV1::VerificationRejected => "VerificationRejected",
        ScenarioResultV1::SettlementRejected => "SettlementRejected",
    }
}

fn scenario_result_fixture_str_v1(result: ScenarioResultV1) -> &'static str {
    match result {
        ScenarioResultV1::Accepted => "ACCEPTED",
        ScenarioResultV1::ExecutionRejected => "EXECUTION_REJECTED",
        ScenarioResultV1::VerificationRejected => "VERIFICATION_REJECTED",
        ScenarioResultV1::SettlementRejected => "SETTLEMENT_REJECTED",
    }
}

fn proof_system_bridge_str_v1(proof_system: ProofSystemSelectionV1) -> &'static str {
    match proof_system {
        ProofSystemSelectionV1::Mock => "mock",
        ProofSystemSelectionV1::Stark => "stark",
    }
}

fn canonical_request_kind_bridge_str_v1(kind: CanonicalPipelineRequestKindV1) -> &'static str {
    match kind {
        CanonicalPipelineRequestKindV1::Execution => "execution",
        CanonicalPipelineRequestKindV1::Attestation => "attestation",
    }
}

fn canonical_burn_intent_bridge_str_v1(intent: CanonicalPipelineBurnIntentV1) -> &'static str {
    match intent {
        CanonicalPipelineBurnIntentV1::CanonicalReport => "canonical_report",
    }
}

fn canonical_payment_intent_bridge_str_v1(
    intent: CanonicalPipelinePaymentIntentV1,
) -> &'static str {
    match intent {
        CanonicalPipelinePaymentIntentV1::BurnToProduceCanonicalTruth => {
            "burn_to_produce_canonical_truth"
        }
    }
}

fn canonical_settlement_intent_bridge_str_v1(
    intent: CanonicalPipelineSettlementIntentV1,
) -> &'static str {
    match intent {
        CanonicalPipelineSettlementIntentV1::RecordCanonicalOutcome => "record_canonical_outcome",
    }
}

fn canonical_burn_reason_bridge_str_v1(reason: CanonicalPipelineBurnReasonV1) -> &'static str {
    match reason {
        CanonicalPipelineBurnReasonV1::ProduceCanonicalTruthArtifact => {
            "produce_canonical_truth_artifact"
        }
    }
}

fn canonical_burn_category_bridge_str_v1(
    category: CanonicalPipelineBurnCategoryV1,
) -> &'static str {
    match category {
        CanonicalPipelineBurnCategoryV1::ExecutionTruthProduction => "execution_truth_production",
        CanonicalPipelineBurnCategoryV1::AttestationTruthProduction => {
            "attestation_truth_production"
        }
    }
}

fn canonical_fee_disposition_bridge_str_v1(
    value: CanonicalPipelineFeeDispositionV1,
) -> &'static str {
    match value {
        CanonicalPipelineFeeDispositionV1::BurnedForCanonicalTruth => "burned_for_canonical_truth",
    }
}

fn canonical_future_token_binding_status_bridge_str_v1(
    value: CanonicalPipelineFutureTokenBindingStatusV1,
) -> &'static str {
    match value {
        CanonicalPipelineFutureTokenBindingStatusV1::PendingExternalAnchor => {
            "pending_external_anchor"
        }
    }
}

fn canonical_head_authority_mode_bridge_str_v1(
    value: CanonicalPipelineHeadAuthorityModeV1,
) -> &'static str {
    match value {
        CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent => "authoritative_persistent",
        CanonicalPipelineHeadAuthorityModeV1::StatelessNonAuthoritative => {
            "stateless_non_authoritative"
        }
    }
}

fn canonical_network_mode_bridge_str_v1(value: CanonicalPipelineNetworkModeV1) -> &'static str {
    match value {
        CanonicalPipelineNetworkModeV1::Local => "local",
        CanonicalPipelineNetworkModeV1::Bridged => "bridged",
    }
}

fn canonical_settlement_anchor_type_bridge_str_v1(
    value: CanonicalPipelineSettlementAnchorTypeV1,
) -> &'static str {
    match value {
        CanonicalPipelineSettlementAnchorTypeV1::Local => "local",
        CanonicalPipelineSettlementAnchorTypeV1::Simulated => "simulated",
        CanonicalPipelineSettlementAnchorTypeV1::External => "external",
    }
}

fn canonical_external_anchor_verification_status_bridge_str_v1(
    value: CanonicalPipelineExternalAnchorVerificationStatusV1,
) -> &'static str {
    match value {
        CanonicalPipelineExternalAnchorVerificationStatusV1::NotRequested => "not_requested",
        CanonicalPipelineExternalAnchorVerificationStatusV1::Accepted => "accepted",
        CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected => "rejected",
        CanonicalPipelineExternalAnchorVerificationStatusV1::Disconnected => "disconnected",
    }
}

fn canonical_evidence_provenance_type_bridge_str_v1(
    value: CanonicalPipelineEvidenceProvenanceTypeV1,
) -> &'static str {
    match value {
        CanonicalPipelineEvidenceProvenanceTypeV1::Inline => "inline",
        CanonicalPipelineEvidenceProvenanceTypeV1::HashReference => "hash_reference",
        CanonicalPipelineEvidenceProvenanceTypeV1::SignedBlob => "signed_blob",
        CanonicalPipelineEvidenceProvenanceTypeV1::AnchoredExternal => "anchored_external",
    }
}

fn canonical_attestation_proof_kind_bridge_str_v1(
    value: CanonicalPipelineAttestationProofKindV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationProofKindV1::Mock => "MOCK",
        CanonicalPipelineAttestationProofKindV1::Stark => "STARK",
    }
}

fn canonical_settlement_reason_bridge_str_v1(
    value: CanonicalPipelineSettlementReasonV1,
) -> &'static str {
    match value {
        CanonicalPipelineSettlementReasonV1::AcceptedAndCommitted => "accepted_and_committed",
        CanonicalPipelineSettlementReasonV1::NotRunExecutionRejected => {
            "not_run_execution_rejected"
        }
        CanonicalPipelineSettlementReasonV1::RejectedVerificationMismatch => {
            "rejected_verification_mismatch"
        }
        CanonicalPipelineSettlementReasonV1::RejectedLocalSettlement => "rejected_local_settlement",
    }
}

fn canonical_truth_artifact_kind_bridge_str_v1(
    value: CanonicalPipelineTruthArtifactKindV1,
) -> &'static str {
    match value {
        CanonicalPipelineTruthArtifactKindV1::ExecutionReport => "execution_report",
        CanonicalPipelineTruthArtifactKindV1::AttestationReport => "attestation_report",
    }
}

fn canonical_failure_stage_bridge_str_v1(value: CanonicalPipelineFailureStageV1) -> &'static str {
    match value {
        CanonicalPipelineFailureStageV1::None => "none",
        CanonicalPipelineFailureStageV1::Request => "request",
        CanonicalPipelineFailureStageV1::Execution => "execution",
        CanonicalPipelineFailureStageV1::Verification => "verification",
        CanonicalPipelineFailureStageV1::Settlement => "settlement",
    }
}

fn canonical_failure_reason_code_bridge_str_v1(
    value: CanonicalPipelineFailureReasonCodeV1,
) -> &'static str {
    match value {
        CanonicalPipelineFailureReasonCodeV1::None => "none",
        CanonicalPipelineFailureReasonCodeV1::TransferExecutionRejected => {
            "transfer_execution_rejected"
        }
        CanonicalPipelineFailureReasonCodeV1::UnsupportedAttestationMode => {
            "unsupported_attestation_mode"
        }
        CanonicalPipelineFailureReasonCodeV1::AttestationMalformedEvidence => {
            "attestation_malformed_evidence"
        }
        CanonicalPipelineFailureReasonCodeV1::AttestationNormalizationFailure => {
            "attestation_normalization_failure"
        }
        CanonicalPipelineFailureReasonCodeV1::AttestationConsistencyMismatch => {
            "attestation_consistency_mismatch"
        }
        CanonicalPipelineFailureReasonCodeV1::VerificationLayerMismatch => {
            "verification_layer_mismatch"
        }
        CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected => {
            "settlement_acceptance_rejected"
        }
        CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch => "settlement_head_mismatch",
        CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch => "wallet_binding_mismatch",
        CanonicalPipelineFailureReasonCodeV1::UnsupportedProvenanceType => {
            "unsupported_provenance_type"
        }
        CanonicalPipelineFailureReasonCodeV1::ProvenanceSignatureInvalid => {
            "provenance_signature_invalid"
        }
        CanonicalPipelineFailureReasonCodeV1::AttestationProofVerificationRejected => {
            "attestation_proof_verification_rejected"
        }
    }
}

fn canonical_attestation_scope_bridge_str_v1(
    value: aura_l2_local_chain_v0::CanonicalPipelineAttestationScopeV1,
) -> &'static str {
    match value {
        aura_l2_local_chain_v0::CanonicalPipelineAttestationScopeV1::ClaimConsistencyWithProvidedEvidenceOnly => {
            "claim_consistency_with_provided_evidence_only"
        }
    }
}

fn canonical_attestation_claim_kind_bridge_str_v1(
    value: CanonicalPipelineAttestationClaimKindV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationClaimKindV1::EvidenceRootDigest => "evidence_root_digest",
        CanonicalPipelineAttestationClaimKindV1::NormalizedEvidenceDigest => {
            "normalized_evidence_digest"
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedTextContainsUtf8 => {
            "normalized_text_contains_utf8"
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedJsonFieldEqualsUtf8 => {
            "normalized_json_field_equals_utf8"
        }
    }
}

fn canonical_attestation_evidence_kind_bridge_str_v1(
    value: CanonicalPipelineAttestationEvidenceKindV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationEvidenceKindV1::InlineUtf8 => "inline_utf8",
        CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8 => "inline_json_utf8",
    }
}

fn canonical_attestation_normalized_form_bridge_str_v1(
    value: CanonicalPipelineAttestationNormalizedFormV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationNormalizedFormV1::Utf8Text => "utf8_text",
        CanonicalPipelineAttestationNormalizedFormV1::CanonicalJsonUtf8 => "canonical_json_utf8",
    }
}

fn canonical_attestation_consistency_relation_bridge_str_v1(
    value: CanonicalPipelineAttestationConsistencyRelationV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationConsistencyRelationV1::EvidenceRootDigestEquals => {
            "evidence_root_digest_equals"
        }
        CanonicalPipelineAttestationConsistencyRelationV1::NormalizedEvidenceDigestEquals => {
            "normalized_evidence_digest_equals"
        }
        CanonicalPipelineAttestationConsistencyRelationV1::NormalizedTextContainsUtf8 => {
            "normalized_text_contains_utf8"
        }
        CanonicalPipelineAttestationConsistencyRelationV1::NormalizedJsonFieldEqualsUtf8 => {
            "normalized_json_field_equals_utf8"
        }
    }
}

fn canonical_attestation_status_bridge_str_v1(
    value: CanonicalPipelineAttestationStatusV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationStatusV1::Accepted => "accepted",
        CanonicalPipelineAttestationStatusV1::Rejected => "rejected",
    }
}

fn canonical_attestation_failure_reason_bridge_str_v1(
    value: CanonicalPipelineAttestationFailureReasonV1,
) -> &'static str {
    match value {
        CanonicalPipelineAttestationFailureReasonV1::None => "none",
        CanonicalPipelineAttestationFailureReasonV1::UnsupportedAttestationMode => {
            "unsupported_attestation_mode"
        }
        CanonicalPipelineAttestationFailureReasonV1::MalformedEvidence => "malformed_evidence",
        CanonicalPipelineAttestationFailureReasonV1::NormalizationFailure => {
            "normalization_failure"
        }
        CanonicalPipelineAttestationFailureReasonV1::ConsistencyMismatch => "consistency_mismatch",
        CanonicalPipelineAttestationFailureReasonV1::UnsupportedProvenanceType => {
            "unsupported_provenance_type"
        }
        CanonicalPipelineAttestationFailureReasonV1::ProvenanceSignatureInvalid => {
            "provenance_signature_invalid"
        }
        CanonicalPipelineAttestationFailureReasonV1::VerificationLayerFailure => {
            "verification_layer_failure"
        }
        CanonicalPipelineAttestationFailureReasonV1::AttestationProofVerificationFailure => {
            "attestation_proof_verification_failure"
        }
        CanonicalPipelineAttestationFailureReasonV1::SettlementLayerFailure => {
            "settlement_layer_failure"
        }
    }
}

fn canonical_execution_status_bridge_str_v1(
    status: CanonicalPipelineExecutionStatusV1,
) -> &'static str {
    match status {
        CanonicalPipelineExecutionStatusV1::Applied => "applied",
        CanonicalPipelineExecutionStatusV1::Rejected => "rejected",
    }
}

fn canonical_verification_status_bridge_str_v1(
    status: aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1,
) -> &'static str {
    match status {
        aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1::Passed => "passed",
        aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1::Rejected => "rejected",
        aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1::NotRun => "not_run",
    }
}

fn canonical_settlement_status_bridge_str_v1(
    status: aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1,
) -> &'static str {
    match status {
        aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::Accepted => "accepted",
        aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::Rejected => "rejected",
        aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::NotRun => "not_run",
    }
}

fn canonical_public_inputs_decode_status_bridge_str_v1(
    status: CanonicalPipelinePublicInputsDecodeStatusV1,
) -> &'static str {
    match status {
        CanonicalPipelinePublicInputsDecodeStatusV1::Decoded => "decoded",
        CanonicalPipelinePublicInputsDecodeStatusV1::Invalid => "invalid",
    }
}

fn canonical_proof_binding_input_kind_bridge_str_v1(
    kind: CanonicalPipelineProofBindingInputKindV1,
) -> &'static str {
    match kind {
        CanonicalPipelineProofBindingInputKindV1::WitnessDigest => "witness_digest",
        CanonicalPipelineProofBindingInputKindV1::ProofBytesHash => "proof_bytes_hash",
    }
}

fn canonical_validity_reference_kind_bridge_str_v1(
    kind: CanonicalPipelineValidityReferenceKindV1,
) -> &'static str {
    match kind {
        CanonicalPipelineValidityReferenceKindV1::None => "none",
    }
}

fn parse_canonical_pipeline_bridge_json_v1(
    json_text: &str,
) -> Result<CanonicalPipelineReportV1, Box<dyn std::error::Error>> {
    let envelope: BridgeEnvelopeV1<CanonicalPipelineBridgeReportV1> =
        serde_json::from_str(json_text)?;
    if envelope.bridge_schema_version != BRIDGE_SCHEMA_VERSION_V1 {
        return Err(format!(
            "unsupported bridge_schema_version: {}",
            envelope.bridge_schema_version
        )
        .into());
    }
    if envelope.report_kind != "canonical_pipeline_report_v1" {
        return Err(format!("unexpected report_kind: {}", envelope.report_kind).into());
    }
    if envelope.command != "run-canonical-pipeline" {
        return Err(format!(
            "unexpected command for canonical pipeline bridge: {}",
            envelope.command
        )
        .into());
    }
    parse_canonical_pipeline_bridge_report_v1(envelope.report)
}

fn parse_canonical_pipeline_bridge_report_v1(
    report: CanonicalPipelineBridgeReportV1,
) -> Result<CanonicalPipelineReportV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineReportV1 {
        pipeline_schema_version: report.pipeline_schema_version,
        pipeline_id: report.pipeline_id,
        fixture_name: report.fixture_name,
        proof_system: parse_proof_system_bridge_v1(&report.proof_system)?,
        expected_result: parse_scenario_result_bridge_v1(&report.expected_result)?,
        actual_result: parse_scenario_result_bridge_v1(&report.actual_result)?,
        pre_state_root: decode_hex_32_bridge_v1(&report.pre_state_root_hex, "pre_state_root_hex")?,
        executed_post_state_root: parse_optional_hex_32_bridge_v1(
            report.executed_post_state_root_hex.as_deref(),
            "executed_post_state_root_hex",
        )?,
        settlement_committed_state_root: parse_optional_hex_32_bridge_v1(
            report.settlement_committed_state_root_hex.as_deref(),
            "settlement_committed_state_root_hex",
        )?,
        burn_summary: parse_canonical_pipeline_burn_summary_bridge_v1(report.burn_summary)?,
        accounting_summary: parse_canonical_pipeline_accounting_summary_bridge_v1(
            report.accounting_summary,
        )?,
        ledger_summary: parse_canonical_pipeline_ledger_summary_bridge_v1(report.ledger_summary)?,
        head_transition_summary: parse_canonical_pipeline_head_transition_summary_bridge_v1(
            report.head_transition_summary,
        )?,
        wallet_binding_summary: parse_canonical_pipeline_wallet_binding_summary_bridge_v1(
            report.wallet_binding_summary,
        )?,
        token_anchor_summary: parse_canonical_pipeline_token_anchor_summary_bridge_v1(
            report.token_anchor_summary,
        )?,
        request_audit: parse_canonical_pipeline_request_bridge_audit_v1(report.request_audit)?,
        genesis_accounts: parse_canonical_pipeline_genesis_accounts_bridge_v1(
            report.genesis_accounts,
        )?,
        ledger_accounts: parse_canonical_pipeline_ledger_accounts_bridge_v1(
            report.ledger_accounts,
        )?,
        commitment_expansions: parse_canonical_pipeline_commitment_expansions_bridge_v1(
            report.commitment_expansions,
        )?,
        stage_outcomes: parse_canonical_pipeline_stage_outcomes_bridge_v1(report.stage_outcomes)?,
        status_explanation: parse_canonical_pipeline_status_explanation_bridge_v1(
            report.status_explanation,
        )?,
        attestation_summary: report
            .attestation_summary
            .map(parse_canonical_pipeline_attestation_summary_bridge_v1)
            .transpose()?,
        attestation_proof_summary: report
            .attestation_proof_summary
            .map(parse_canonical_pipeline_attestation_proof_summary_bridge_v1)
            .transpose()?,
        provenance_summary: report
            .provenance_summary
            .map(parse_canonical_pipeline_provenance_summary_bridge_v1)
            .transpose()?,
        public_inputs: parse_canonical_pipeline_public_inputs_bridge_audit_v1(
            report.public_inputs,
        )?,
        proof_artifact: parse_canonical_pipeline_proof_artifact_bridge_audit_v1(
            report.proof_artifact,
        )?,
    })
}

fn parse_canonical_pipeline_head_transition_summary_bridge_v1(
    value: CanonicalPipelineHeadTransitionSummaryBridgeV1,
) -> Result<CanonicalPipelineHeadTransitionSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineHeadTransitionSummaryV1 {
        settlement_head_version: value.settlement_head_version,
        authority_mode: parse_canonical_head_authority_mode_bridge_v1(&value.authority_mode)?,
        head_sequence_number: value.head_sequence_number,
        previous_head_hash: decode_hex_32_bridge_v1(
            &value.previous_head_hash_hex,
            "previous_head_hash_hex",
        )?,
        current_head_hash: decode_hex_32_bridge_v1(
            &value.current_head_hash_hex,
            "current_head_hash_hex",
        )?,
        canonical_head_commitment: decode_hex_32_bridge_v1(
            &value.canonical_head_commitment_hex,
            "canonical_head_commitment_hex",
        )?,
        request_canonical_digest: decode_hex_32_bridge_v1(
            &value.request_canonical_digest_hex,
            "request_canonical_digest_hex",
        )?,
        report_digest: decode_hex_32_bridge_v1(&value.report_digest_hex, "report_digest_hex")?,
    })
}

fn parse_canonical_pipeline_wallet_binding_summary_bridge_v1(
    value: CanonicalPipelineWalletBindingSummaryBridgeV1,
) -> Result<CanonicalPipelineWalletBindingSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineWalletBindingSummaryV1 {
        wallet_binding_version: value.wallet_binding_version,
        account_id: decode_hex_32_bridge_v1(&value.account_id_hex, "account_id_hex")?,
        wallet_address: value.wallet_address,
        wallet_binding_digest: decode_hex_32_bridge_v1(
            &value.wallet_binding_digest_hex,
            "wallet_binding_digest_hex",
        )?,
        binding_consistent_with_account: value.binding_consistent_with_account,
    })
}

fn parse_canonical_pipeline_token_anchor_summary_bridge_v1(
    value: CanonicalPipelineTokenAnchorSummaryBridgeV1,
) -> Result<CanonicalPipelineTokenAnchorSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineTokenAnchorSummaryV1 {
        token_policy_version: value.token_policy_version,
        network_mode: parse_canonical_network_mode_bridge_v1(&value.network_mode)?,
        settlement_anchor_type: parse_canonical_settlement_anchor_type_bridge_v1(
            &value.settlement_anchor_type,
        )?,
        anchor_verification_status: parse_canonical_external_anchor_verification_status_bridge_v1(
            &value.anchor_verification_status,
        )?,
        external_balance_reference: value
            .external_balance_reference
            .map(parse_canonical_pipeline_external_balance_reference_bridge_v1)
            .transpose()?,
        expected_external_balance: value.expected_external_balance,
        token_anchor_digest: decode_hex_32_bridge_v1(
            &value.token_anchor_digest_hex,
            "token_anchor_digest_hex",
        )?,
    })
}

fn parse_canonical_pipeline_external_balance_reference_bridge_v1(
    value: CanonicalPipelineExternalBalanceReferenceBridgeV1,
) -> Result<CanonicalPipelineExternalBalanceReferenceV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineExternalBalanceReferenceV1 {
        reference_id: value.reference_id,
        observed_balance: value.observed_balance,
        observed_slot: value.observed_slot,
        connected: value.connected,
    })
}

fn parse_canonical_pipeline_burn_summary_bridge_v1(
    value: CanonicalPipelineBurnSummaryBridgeV1,
) -> Result<CanonicalPipelineBurnSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineBurnSummaryV1 {
        burn_policy_version: value.burn_policy_version,
        burn_policy: parse_canonical_pipeline_burn_policy_bridge_v1(value.burn_policy)?,
        burn_reason: parse_canonical_burn_reason_bridge_v1(&value.burn_reason)?,
        burn_category: parse_canonical_burn_category_bridge_v1(&value.burn_category)?,
        request_kind: parse_canonical_request_kind_bridge_v1(&value.request_kind)?,
        burn_intent: parse_canonical_burn_intent_bridge_v1(&value.burn_intent)?,
        declared_fee_units: value.declared_fee_units,
        computed_burn_units: value.computed_burn_units,
        consumed_burn_units: value.consumed_burn_units,
        burn_derivation_inputs: parse_canonical_pipeline_burn_derivation_inputs_bridge_v1(
            value.burn_derivation_inputs,
        )?,
        request_declares_correct_burn: value.request_declares_correct_burn,
        recomputed_burn_matches_report: value.recomputed_burn_matches_report,
        burn_consumed: value.burn_consumed,
        failure_semantics: parse_canonical_pipeline_burn_failure_semantics_bridge_v1(
            value.failure_semantics,
        )?,
    })
}

fn parse_canonical_pipeline_burn_policy_bridge_v1(
    value: CanonicalPipelineBurnPolicyBridgeV1,
) -> Result<CanonicalPipelineBurnPolicyV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineBurnPolicyV1 {
        burn_policy_version: value.burn_policy_version,
        base_units: value.base_units,
        execution_request_kind_units: value.execution_request_kind_units,
        attestation_request_kind_units: value.attestation_request_kind_units,
        mock_proof_system_units: value.mock_proof_system_units,
        stark_proof_system_units: value.stark_proof_system_units,
        transaction_units_per_item: value.transaction_units_per_item,
        metered_request_size_chunk_bytes: value.metered_request_size_chunk_bytes,
    })
}

fn parse_canonical_pipeline_burn_derivation_inputs_bridge_v1(
    value: CanonicalPipelineBurnDerivationInputsBridgeV1,
) -> Result<CanonicalPipelineBurnDerivationInputsV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineBurnDerivationInputsV1 {
        tx_count: value.tx_count,
        metered_request_size_bytes: value.metered_request_size_bytes,
        request_kind: parse_canonical_request_kind_bridge_v1(&value.request_kind)?,
        proof_system: parse_proof_system_bridge_v1(&value.proof_system)?,
        attestation_evidence_items: value.attestation_evidence_items,
        attestation_claim_bytes: value.attestation_claim_bytes,
        attestation_evidence_bytes: value.attestation_evidence_bytes,
    })
}

fn parse_canonical_pipeline_burn_failure_semantics_bridge_v1(
    value: CanonicalPipelineBurnFailureSemanticsBridgeV1,
) -> Result<CanonicalPipelineBurnFailureSemanticsV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineBurnFailureSemanticsV1 {
        execution_rejected_burns_full_amount: value.execution_rejected_burns_full_amount,
        verification_rejected_burns_full_amount: value.verification_rejected_burns_full_amount,
        settlement_rejected_burns_full_amount: value.settlement_rejected_burns_full_amount,
        partial_burn_allowed: value.partial_burn_allowed,
    })
}

fn parse_canonical_pipeline_accounting_summary_bridge_v1(
    value: CanonicalPipelineAccountingSummaryBridgeV1,
) -> Result<CanonicalPipelineAccountingSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAccountingSummaryV1 {
        accounting_policy_version: value.accounting_policy_version,
        payment_intent: parse_canonical_payment_intent_bridge_v1(&value.payment_intent)?,
        settlement_intent: parse_canonical_settlement_intent_bridge_v1(&value.settlement_intent)?,
        declared_fee_units: value.declared_fee_units,
        computed_burn_units: value.computed_burn_units,
        consumed_burn_units: value.consumed_burn_units,
        burn_record: parse_canonical_pipeline_burn_record_bridge_v1(value.burn_record)?,
        settlement_record: parse_canonical_pipeline_settlement_record_bridge_v1(
            value.settlement_record,
        )?,
        accounting_consistent_with_burn: value.accounting_consistent_with_burn,
        accounting_consistent_with_outcome: value.accounting_consistent_with_outcome,
    })
}

fn parse_canonical_pipeline_burn_record_bridge_v1(
    value: CanonicalPipelineBurnRecordBridgeV1,
) -> Result<CanonicalPipelineBurnRecordV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineBurnRecordV1 {
        burn_reason: parse_canonical_burn_reason_bridge_v1(&value.burn_reason)?,
        burn_category: parse_canonical_burn_category_bridge_v1(&value.burn_category)?,
        fee_disposition: parse_canonical_fee_disposition_bridge_v1(&value.fee_disposition)?,
        account_id: decode_hex_32_bridge_v1(&value.account_id_hex, "account_id_hex")?,
        pre_balance: value.pre_balance,
        post_balance: value.post_balance,
        burned_amount: value.burned_amount,
        declared_fee_units: value.declared_fee_units,
        computed_burn_units: value.computed_burn_units,
        consumed_burn_units: value.consumed_burn_units,
        report_pipeline_id: value.report_pipeline_id,
        report_request_binding_hash: decode_hex_32_bridge_v1(
            &value.report_request_binding_hash_hex,
            "report_request_binding_hash_hex",
        )?,
    })
}

fn parse_canonical_pipeline_ledger_summary_bridge_v1(
    value: CanonicalPipelineLedgerSummaryBridgeV1,
) -> Result<CanonicalPipelineLedgerSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineLedgerSummaryV1 {
        ledger_policy_version: value.ledger_policy_version,
        payer_account_id: decode_hex_32_bridge_v1(
            &value.payer_account_id_hex,
            "payer_account_id_hex",
        )?,
        total_supply: value.total_supply,
        burned_supply_before: value.burned_supply_before,
        burned_supply_after: value.burned_supply_after,
        ledger_account_count: value.ledger_account_count,
        circulating_supply_before: value.circulating_supply_before,
        circulating_supply_after: value.circulating_supply_after,
        ledger_consistent_with_request: value.ledger_consistent_with_request,
        ledger_consistent_with_burn: value.ledger_consistent_with_burn,
        ledger_consistent_with_supply: value.ledger_consistent_with_supply,
        ledger_state_commitment: parse_canonical_pipeline_ledger_state_commitment_bridge_v1(
            value.ledger_state_commitment,
        )?,
    })
}

fn parse_canonical_pipeline_ledger_state_commitment_bridge_v1(
    value: CanonicalPipelineLedgerStateCommitmentBridgeV1,
) -> Result<CanonicalPipelineLedgerStateCommitmentV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineLedgerStateCommitmentV1 {
        commitment_version: value.commitment_version,
        pre_ledger_state_commitment: decode_hex_32_bridge_v1(
            &value.pre_ledger_state_commitment_hex,
            "pre_ledger_state_commitment_hex",
        )?,
        post_ledger_state_commitment: decode_hex_32_bridge_v1(
            &value.post_ledger_state_commitment_hex,
            "post_ledger_state_commitment_hex",
        )?,
    })
}

fn parse_canonical_pipeline_settlement_record_bridge_v1(
    value: CanonicalPipelineSettlementRecordBridgeV1,
) -> Result<CanonicalPipelineSettlementRecordV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineSettlementRecordV1 {
        settlement_intent: parse_canonical_settlement_intent_bridge_v1(&value.settlement_intent)?,
        settlement_status: parse_canonical_settlement_status_bridge_v1(&value.settlement_status)?,
        settlement_reason: parse_canonical_settlement_reason_bridge_v1(&value.settlement_reason)?,
        committed_state_root: parse_optional_hex_32_bridge_v1(
            value.committed_state_root_hex.as_deref(),
            "committed_state_root_hex",
        )?,
        future_token_binding_status: parse_canonical_future_token_binding_status_bridge_v1(
            &value.future_token_binding_status,
        )?,
        future_token_binding_units: value.future_token_binding_units,
    })
}

fn parse_canonical_pipeline_status_explanation_bridge_v1(
    value: CanonicalPipelineStatusExplanationBridgeV1,
) -> Result<CanonicalPipelineStatusExplanationV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineStatusExplanationV1 {
        truth_artifact_kind: parse_canonical_truth_artifact_kind_bridge_v1(
            &value.truth_artifact_kind,
        )?,
        request_kind: parse_canonical_request_kind_bridge_v1(&value.request_kind)?,
        final_status: parse_scenario_result_bridge_v1(&value.final_status)?,
        failure_stage: parse_canonical_failure_stage_bridge_v1(&value.failure_stage)?,
        failure_reason_code: parse_canonical_failure_reason_code_bridge_v1(
            &value.failure_reason_code,
        )?,
        detail: value.detail,
    })
}

fn parse_canonical_pipeline_attestation_summary_bridge_v1(
    value: CanonicalPipelineAttestationSummaryBridgeV1,
) -> Result<CanonicalPipelineAttestationSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationSummaryV1 {
        attestation_schema_version: value.attestation_schema_version,
        attestation_scope: parse_canonical_attestation_scope_bridge_v1(&value.attestation_scope)?,
        attestation_proof_kind: parse_canonical_attestation_proof_kind_bridge_v1(
            &value.attestation_proof_kind,
        )?,
        normalization_policy_version: value.normalization_policy_version,
        attestation_constraints: parse_canonical_pipeline_attestation_constraints_bridge_v1(
            value.attestation_constraints,
        )?,
        claim: parse_canonical_pipeline_attestation_claim_bridge_v1(value.claim)?,
        claim_digest: decode_hex_32_bridge_v1(&value.claim_digest_hex, "claim_digest_hex")?,
        evidence_summary: parse_canonical_pipeline_attestation_evidence_summary_bridge_v1(
            value.evidence_summary,
        )?,
        normalization_summary:
            parse_canonical_pipeline_attestation_normalization_summary_bridge_v1(
                value.normalization_summary,
            )?,
        consistency_result: parse_canonical_pipeline_attestation_consistency_result_bridge_v1(
            value.consistency_result,
        )?,
        attestation_status: parse_canonical_attestation_status_bridge_v1(
            &value.attestation_status,
        )?,
        attestation_failure_reason: parse_canonical_pipeline_attestation_failure_audit_bridge_v1(
            value.attestation_failure_reason,
        )?,
        proof_scope_honesty_note: value.proof_scope_honesty_note,
    })
}

fn parse_canonical_pipeline_attestation_constraints_bridge_v1(
    value: CanonicalPipelineAttestationConstraintsBridgeV1,
) -> Result<CanonicalPipelineAttestationConstraintsV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationConstraintsV1 {
        require_unique_labels: value.require_unique_labels,
        max_evidence_items: value.max_evidence_items,
        max_total_normalized_bytes: value.max_total_normalized_bytes,
    })
}

fn parse_canonical_pipeline_attestation_claim_bridge_v1(
    value: CanonicalPipelineAttestationClaimBridgeV1,
) -> Result<CanonicalPipelineAttestationClaimV1, Box<dyn std::error::Error>> {
    let claim_kind = parse_canonical_attestation_claim_kind_bridge_v1(&value.claim_kind)?;
    let claim_payload = match claim_kind {
        CanonicalPipelineAttestationClaimKindV1::EvidenceRootDigest => {
            let expected = value
                .claim_payload
                .expected_evidence_root_digest_hex
                .ok_or(
                    "attestation.claim.claim_payload.expected_evidence_root_digest_hex is required",
                )?;
            if value.claim_payload.target_label.is_some()
                || value.claim_payload.expected_evidence_digest_hex.is_some()
                || value.claim_payload.expected_substring_utf8.is_some()
                || value.claim_payload.field_path.is_some()
                || value.claim_payload.expected_value_utf8.is_some()
            {
                return Err(
                    "attestation.claim.claim_payload has unsupported fields for claim_kind evidence_root_digest"
                        .into(),
                );
            }
            CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest {
                expected_evidence_root_digest: decode_hex_32_bridge_v1(
                    &expected,
                    "expected_evidence_root_digest_hex",
                )?,
            }
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedEvidenceDigest => {
            let target_label = value
                .claim_payload
                .target_label
                .ok_or("attestation.claim.claim_payload.target_label is required")?;
            let expected = value.claim_payload.expected_evidence_digest_hex.ok_or(
                "attestation.claim.claim_payload.expected_evidence_digest_hex is required",
            )?;
            if value
                .claim_payload
                .expected_evidence_root_digest_hex
                .is_some()
                || value.claim_payload.expected_substring_utf8.is_some()
                || value.claim_payload.field_path.is_some()
                || value.claim_payload.expected_value_utf8.is_some()
            {
                return Err(
                    "attestation.claim.claim_payload has unsupported fields for claim_kind normalized_evidence_digest"
                        .into(),
                );
            }
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
                target_label,
                expected_evidence_digest: decode_hex_32_bridge_v1(
                    &expected,
                    "expected_evidence_digest_hex",
                )?,
            }
        }
        CanonicalPipelineAttestationClaimKindV1::NormalizedTextContainsUtf8 => {
            let target_label = value
                .claim_payload
                .target_label
                .ok_or("attestation.claim.claim_payload.target_label is required")?;
            let expected_substring_utf8 = value
                .claim_payload
                .expected_substring_utf8
                .ok_or("attestation.claim.claim_payload.expected_substring_utf8 is required")?;
            if value
                .claim_payload
                .expected_evidence_root_digest_hex
                .is_some()
                || value.claim_payload.expected_evidence_digest_hex.is_some()
                || value.claim_payload.field_path.is_some()
                || value.claim_payload.expected_value_utf8.is_some()
            {
                return Err(
                    "attestation.claim.claim_payload has unsupported fields for claim_kind normalized_text_contains_utf8"
                        .into(),
                );
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
                .ok_or("attestation.claim.claim_payload.target_label is required")?;
            let field_path = value
                .claim_payload
                .field_path
                .ok_or("attestation.claim.claim_payload.field_path is required")?;
            let expected_value_utf8 = value
                .claim_payload
                .expected_value_utf8
                .ok_or("attestation.claim.claim_payload.expected_value_utf8 is required")?;
            if value
                .claim_payload
                .expected_evidence_root_digest_hex
                .is_some()
                || value.claim_payload.expected_evidence_digest_hex.is_some()
                || value.claim_payload.expected_substring_utf8.is_some()
            {
                return Err(
                    "attestation.claim.claim_payload has unsupported fields for claim_kind normalized_json_field_equals_utf8"
                        .into(),
                );
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

fn parse_canonical_pipeline_attestation_evidence_summary_bridge_v1(
    value: CanonicalPipelineAttestationEvidenceSummaryBridgeV1,
) -> Result<CanonicalPipelineAttestationEvidenceSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationEvidenceSummaryV1 {
        evidence_item_count: value.evidence_item_count,
        evidence_items: value
            .evidence_items
            .into_iter()
            .map(parse_canonical_pipeline_attestation_evidence_summary_item_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
        evidence_root_digest: decode_hex_32_bridge_v1(
            &value.evidence_root_digest_hex,
            "evidence_root_digest_hex",
        )?,
    })
}

fn parse_canonical_pipeline_attestation_evidence_summary_item_bridge_v1(
    value: CanonicalPipelineAttestationEvidenceSummaryItemBridgeV1,
) -> Result<CanonicalPipelineAttestationEvidenceSummaryItemV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationEvidenceSummaryItemV1 {
        label: value.label,
        evidence_kind: parse_canonical_attestation_evidence_kind_bridge_v1(&value.evidence_kind)?,
        original_payload_utf8: value.original_payload_utf8,
        original_payload_size_bytes: value.original_payload_size_bytes,
        normalized_form: parse_canonical_attestation_normalized_form_bridge_v1(
            &value.normalized_form,
        )?,
        normalized_payload_utf8: value.normalized_payload_utf8,
        normalized_payload_size_bytes: value.normalized_payload_size_bytes,
        evidence_digest: decode_hex_32_bridge_v1(
            &value.evidence_digest_hex,
            "evidence_digest_hex",
        )?,
        provenance_digest: decode_hex_32_bridge_v1(
            &value.provenance_digest_hex,
            "provenance_digest_hex",
        )?,
    })
}

fn parse_canonical_pipeline_attestation_normalization_summary_bridge_v1(
    value: CanonicalPipelineAttestationNormalizationSummaryBridgeV1,
) -> Result<CanonicalPipelineAttestationNormalizationSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationNormalizationSummaryV1 {
        normalization_policy_version: value.normalization_policy_version,
        normalized_evidence_count: value.normalized_evidence_count,
        total_normalized_bytes: value.total_normalized_bytes,
        normalization_succeeded: value.normalization_succeeded,
    })
}

fn parse_canonical_pipeline_attestation_consistency_result_bridge_v1(
    value: CanonicalPipelineAttestationConsistencyResultBridgeV1,
) -> Result<CanonicalPipelineAttestationConsistencyResultV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationConsistencyResultV1 {
        relation: parse_canonical_attestation_consistency_relation_bridge_v1(&value.relation)?,
        target_label: value.target_label,
        consistent: value.consistent,
    })
}

fn parse_canonical_pipeline_attestation_failure_audit_bridge_v1(
    value: CanonicalPipelineAttestationFailureAuditBridgeV1,
) -> Result<CanonicalPipelineAttestationFailureAuditV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationFailureAuditV1 {
        reason: parse_canonical_attestation_failure_reason_bridge_v1(&value.reason)?,
        detail: value.detail,
    })
}

fn parse_canonical_pipeline_attestation_proof_summary_bridge_v1(
    value: CanonicalPipelineAttestationProofSummaryBridgeV1,
) -> Result<CanonicalPipelineAttestationProofSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineAttestationProofSummaryV1 {
        proof_kind: parse_canonical_attestation_proof_kind_bridge_v1(&value.proof_kind)?,
        attestation_tuple_digest: decode_hex_32_bridge_v1(
            &value.attestation_tuple_digest_hex,
            "attestation_tuple_digest_hex",
        )?,
        verification_passed: value.verification_passed,
        mock_policy_version: value.mock_policy_version,
        stark_policy_version: value.stark_policy_version,
        stark_public_inputs_digest: parse_optional_hex_32_bridge_v1(
            value.stark_public_inputs_digest_hex.as_deref(),
            "stark_public_inputs_digest_hex",
        )?,
        stark_proof_bytes_digest: parse_optional_hex_32_bridge_v1(
            value.stark_proof_bytes_digest_hex.as_deref(),
            "stark_proof_bytes_digest_hex",
        )?,
        stark_proof_binding_digest: parse_optional_hex_32_bridge_v1(
            value.stark_proof_binding_digest_hex.as_deref(),
            "stark_proof_binding_digest_hex",
        )?,
    })
}

fn parse_canonical_pipeline_provenance_summary_bridge_v1(
    value: CanonicalPipelineProvenanceSummaryBridgeV1,
) -> Result<CanonicalPipelineProvenanceSummaryV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineProvenanceSummaryV1 {
        provenance_item_count: value.provenance_item_count,
        items: value
            .items
            .into_iter()
            .map(parse_canonical_pipeline_provenance_summary_item_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
        provenance_root_digest: decode_hex_32_bridge_v1(
            &value.provenance_root_digest_hex,
            "provenance_root_digest_hex",
        )?,
        all_signature_checks_passed: value.all_signature_checks_passed,
    })
}

fn parse_canonical_pipeline_provenance_summary_item_bridge_v1(
    value: CanonicalPipelineProvenanceSummaryItemBridgeV1,
) -> Result<CanonicalPipelineProvenanceSummaryItemV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineProvenanceSummaryItemV1 {
        label: value.label,
        provenance_policy_version: value.provenance_policy_version,
        provenance_type: parse_canonical_evidence_provenance_type_bridge_v1(
            &value.provenance_type,
        )?,
        source_type: value.source_type,
        source_identifier: value.source_identifier,
        signature_present: value.signature_present,
        signature_valid: value.signature_valid,
        signer_public_key: parse_optional_hex_fixed_bytes_bridge_v1::<32>(
            value.signer_public_key_hex.as_deref(),
            "signer_public_key_hex",
        )?,
        signature: parse_optional_hex_fixed_bytes_bridge_v1::<64>(
            value.signature_hex.as_deref(),
            "signature_hex",
        )?,
        timestamp_unix_seconds: value.timestamp_unix_seconds,
        provenance_digest: decode_hex_32_bridge_v1(
            &value.provenance_digest_hex,
            "provenance_digest_hex",
        )?,
    })
}

fn parse_canonical_pipeline_request_bridge_audit_v1(
    value: CanonicalPipelineRequestBridgeAuditV1,
) -> Result<CanonicalPipelineRequestAuditV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineRequestAuditV1 {
        request_binding_hash: decode_hex_32_bridge_v1(
            &value.request_binding_hash_hex,
            "request_binding_hash_hex",
        )?,
        genesis_accounts_digest: decode_hex_32_bridge_v1(
            &value.genesis_accounts_digest_hex,
            "genesis_accounts_digest_hex",
        )?,
        ledger_accounts_digest: decode_hex_32_bridge_v1(
            &value.ledger_accounts_digest_hex,
            "ledger_accounts_digest_hex",
        )?,
        transactions_digest: decode_hex_32_bridge_v1(
            &value.transactions_digest_hex,
            "transactions_digest_hex",
        )?,
        rollup_id: decode_hex_32_bridge_v1(&value.rollup_id_hex, "rollup_id_hex")?,
        genesis_account_count: value.genesis_account_count,
        ledger_account_count: value.ledger_account_count,
        ledger_payer_account_id: decode_hex_32_bridge_v1(
            &value.ledger_payer_account_id_hex,
            "ledger_payer_account_id_hex",
        )?,
        ledger_total_supply: value.ledger_total_supply,
        ledger_burned_supply: value.ledger_burned_supply,
        batch_number: value.batch_number,
        tx_count: value.tx_count,
        parent_batch_commitment: decode_hex_32_bridge_v1(
            &value.parent_batch_commitment_hex,
            "parent_batch_commitment_hex",
        )?,
        tamper_public_inputs: value
            .tamper_public_inputs
            .map(parse_canonical_pipeline_tamper_bridge_audit_v1)
            .transpose()?,
        tamper_proof_binding_digest: value
            .tamper_proof_binding_digest
            .map(parse_canonical_pipeline_tamper_bridge_audit_v1)
            .transpose()?,
        tamper_attestation_stark_public_inputs_digest: value
            .tamper_attestation_stark_public_inputs_digest
            .map(parse_canonical_pipeline_tamper_bridge_audit_v1)
            .transpose()?,
        tamper_attestation_stark_proof_bytes: value
            .tamper_attestation_stark_proof_bytes
            .map(parse_canonical_pipeline_tamper_bridge_audit_v1)
            .transpose()?,
    })
}

fn parse_canonical_pipeline_genesis_accounts_bridge_v1(
    value: CanonicalPipelineGenesisAccountsBridgeV1,
) -> Result<CanonicalPipelineGenesisAccountsV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineGenesisAccountsV1 {
        material_version: value.material_version,
        ordered_accounts: value
            .ordered_accounts
            .into_iter()
            .map(parse_canonical_pipeline_account_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_canonical_pipeline_ledger_accounts_bridge_v1(
    value: CanonicalPipelineLedgerAccountsBridgeV1,
) -> Result<CanonicalPipelineLedgerAccountsV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineLedgerAccountsV1 {
        material_version: value.material_version,
        ordered_accounts: value
            .ordered_accounts
            .into_iter()
            .map(parse_canonical_pipeline_ledger_account_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_canonical_pipeline_ledger_account_bridge_v1(
    value: CanonicalPipelineLedgerAccountBridgeV1,
) -> Result<CanonicalPipelineLedgerAccountV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineLedgerAccountV1 {
        account_id: decode_hex_32_bridge_v1(&value.account_id_hex, "account_id_hex")?,
        balance: value.balance,
    })
}

fn parse_canonical_pipeline_commitment_expansions_bridge_v1(
    value: CanonicalPipelineCommitmentExpansionsBridgeV1,
) -> Result<CanonicalPipelineCommitmentExpansionsV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineCommitmentExpansionsV1 {
        transactions: parse_canonical_pipeline_transactions_commitment_expansion_bridge_v1(
            value.transactions,
        )?,
        outcomes: value
            .outcomes
            .map(parse_canonical_pipeline_outcomes_commitment_expansion_bridge_v1)
            .transpose()?,
        batch_context: parse_canonical_pipeline_batch_context_commitment_expansion_bridge_v1(
            value.batch_context,
        )?,
        fee_summary: parse_canonical_pipeline_fee_summary_commitment_expansion_bridge_v1(
            value.fee_summary,
        )?,
    })
}

fn parse_canonical_pipeline_stage_outcomes_bridge_v1(
    value: CanonicalPipelineStageOutcomesBridgeV1,
) -> Result<CanonicalPipelineStageOutcomesV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineStageOutcomesV1 {
        execution_status: match value.execution_status.as_str() {
            "applied" => CanonicalPipelineExecutionStatusV1::Applied,
            "rejected" => CanonicalPipelineExecutionStatusV1::Rejected,
            _ => {
                return Err(
                    format!("unsupported execution_status: {}", value.execution_status).into(),
                )
            }
        },
        verification_status: match value.verification_status.as_str() {
            "passed" => aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1::Passed,
            "rejected" => aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1::Rejected,
            "not_run" => aura_l2_local_chain_v0::CanonicalPipelineVerificationStatusV1::NotRun,
            _ => {
                return Err(format!(
                    "unsupported verification_status: {}",
                    value.verification_status
                )
                .into())
            }
        },
        settlement_status: match value.settlement_status.as_str() {
            "accepted" => aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::Accepted,
            "rejected" => aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::Rejected,
            "not_run" => aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::NotRun,
            _ => {
                return Err(
                    format!("unsupported settlement_status: {}", value.settlement_status).into(),
                )
            }
        },
    })
}

fn parse_canonical_pipeline_public_inputs_bridge_audit_v1(
    value: Option<CanonicalPipelinePublicInputsBridgeAuditV1>,
) -> Result<Option<CanonicalPipelinePublicInputsAuditV1>, Box<dyn std::error::Error>> {
    value
        .map(|value| {
            Ok(CanonicalPipelinePublicInputsAuditV1 {
                decode_status: match value.decode_status.as_str() {
                    "decoded" => CanonicalPipelinePublicInputsDecodeStatusV1::Decoded,
                    "invalid" => CanonicalPipelinePublicInputsDecodeStatusV1::Invalid,
                    _ => {
                        return Err(format!(
                            "unsupported public_inputs.decode_status: {}",
                            value.decode_status
                        )
                        .into())
                    }
                },
                public_input_bytes: decode_hex_fixed_bytes_bridge_v1::<284>(
                    &value.public_input_bytes_hex,
                    "public_input_bytes_hex",
                )?,
                public_inputs_hash: decode_hex_32_bridge_v1(
                    &value.public_inputs_hash_hex,
                    "public_inputs_hash_hex",
                )?,
                transition_binding_hash: decode_hex_32_bridge_v1(
                    &value.transition_binding_hash_hex,
                    "transition_binding_hash_hex",
                )?,
                request_summary_consistency: value
                    .request_summary_consistency
                    .map(parse_canonical_pipeline_request_summary_consistency_bridge_audit_v1)
                    .transpose()?,
                decoded_public_inputs: value
                    .decoded_public_inputs
                    .map(parse_canonical_pipeline_decoded_public_inputs_bridge_v1)
                    .transpose()?,
            })
        })
        .transpose()
}

fn parse_canonical_pipeline_request_summary_consistency_bridge_audit_v1(
    value: CanonicalPipelineRequestSummaryConsistencyBridgeAuditV1,
) -> Result<CanonicalPipelineRequestSummaryConsistencyAuditV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineRequestSummaryConsistencyAuditV1 {
        transition_binding_version_supported: value.transition_binding_version_supported,
        execution_model_version_supported: value.execution_model_version_supported,
        batch_version_supported: value.batch_version_supported,
        rollup_id_matches_request_audit: value.rollup_id_matches_request_audit,
        batch_number_matches_request_audit: value.batch_number_matches_request_audit,
        tx_count_matches_request_audit: value.tx_count_matches_request_audit,
        parent_batch_commitment_matches_request_audit: value
            .parent_batch_commitment_matches_request_audit,
        fee_summary_commitment_matches_expansion: value.fee_summary_commitment_matches_expansion,
        pre_state_root_matches_report: value.pre_state_root_matches_report,
        post_state_root_matches_report: value.post_state_root_matches_report,
        transactions_commitment_matches_expansion: value.transactions_commitment_matches_expansion,
        outcomes_commitment_matches_expansion: value.outcomes_commitment_matches_expansion,
        batch_context_commitment_matches_expansion: value
            .batch_context_commitment_matches_expansion,
        decoded_bytes_round_trip: value.decoded_bytes_round_trip,
        all_fields_match: value.all_fields_match,
    })
}

fn parse_canonical_pipeline_decoded_public_inputs_bridge_v1(
    value: CanonicalPipelineDecodedPublicInputsBridgeV1,
) -> Result<
    aura_l2_local_chain_v0::CanonicalPipelineDecodedPublicInputsV1,
    Box<dyn std::error::Error>,
> {
    Ok(
        aura_l2_local_chain_v0::CanonicalPipelineDecodedPublicInputsV1 {
            transition_binding_version: value.transition_binding_version,
            rollup_id: decode_hex_32_bridge_v1(&value.rollup_id_hex, "rollup_id_hex")?,
            execution_model_version: value.execution_model_version,
            batch_version: value.batch_version,
            batch_number: value.batch_number,
            parent_batch_commitment: decode_hex_32_bridge_v1(
                &value.parent_batch_commitment_hex,
                "parent_batch_commitment_hex",
            )?,
            tx_count: value.tx_count,
            fee_summary_commitment: decode_hex_32_bridge_v1(
                &value.fee_summary_commitment_hex,
                "fee_summary_commitment_hex",
            )?,
            pre_state_root: decode_hex_32_bridge_v1(
                &value.pre_state_root_hex,
                "pre_state_root_hex",
            )?,
            post_state_root: decode_hex_32_bridge_v1(
                &value.post_state_root_hex,
                "post_state_root_hex",
            )?,
            transactions_commitment: decode_hex_32_bridge_v1(
                &value.transactions_commitment_hex,
                "transactions_commitment_hex",
            )?,
            outcomes_commitment: decode_hex_32_bridge_v1(
                &value.outcomes_commitment_hex,
                "outcomes_commitment_hex",
            )?,
            batch_context_commitment: decode_hex_32_bridge_v1(
                &value.batch_context_commitment_hex,
                "batch_context_commitment_hex",
            )?,
        },
    )
}

fn parse_canonical_pipeline_proof_artifact_bridge_audit_v1(
    value: Option<CanonicalPipelineProofArtifactBridgeAuditV1>,
) -> Result<Option<CanonicalPipelineProofArtifactAuditV1>, Box<dyn std::error::Error>> {
    value
        .map(|value| {
            Ok(CanonicalPipelineProofArtifactAuditV1 {
                prover_kind: value.prover_kind,
                proof_version: value.proof_version,
                public_inputs_hash: decode_hex_32_bridge_v1(
                    &value.public_inputs_hash_hex,
                    "public_inputs_hash_hex",
                )?,
                trace_digest: decode_hex_32_bridge_v1(&value.trace_digest_hex, "trace_digest_hex")?,
                trace_layout_digest: decode_hex_32_bridge_v1(
                    &value.trace_layout_digest_hex,
                    "trace_layout_digest_hex",
                )?,
                proof_binding_digest: decode_hex_32_bridge_v1(
                    &value.proof_binding_digest_hex,
                    "proof_binding_digest_hex",
                )?,
                proof_binding_input_kind: match value.proof_binding_input_kind.as_str() {
                    "witness_digest" => CanonicalPipelineProofBindingInputKindV1::WitnessDigest,
                    "proof_bytes_hash" => CanonicalPipelineProofBindingInputKindV1::ProofBytesHash,
                    _ => {
                        return Err(format!(
                            "unsupported proof_binding_input_kind: {}",
                            value.proof_binding_input_kind
                        )
                        .into())
                    }
                },
                proof_binding_input_digest: decode_hex_32_bridge_v1(
                    &value.proof_binding_input_digest_hex,
                    "proof_binding_input_digest_hex",
                )?,
                consistency: CanonicalPipelineProofArtifactConsistencyAuditV1 {
                    public_inputs_hash_matches_report: value
                        .consistency
                        .public_inputs_hash_matches_report,
                    prover_kind_matches_proof_system: value
                        .consistency
                        .prover_kind_matches_proof_system,
                    proof_version_supported: value.consistency.proof_version_supported,
                    proof_binding_input_kind_matches_proof_system: value
                        .consistency
                        .proof_binding_input_kind_matches_proof_system,
                    recomputed_proof_binding_digest: decode_hex_32_bridge_v1(
                        &value.consistency.recomputed_proof_binding_digest_hex,
                        "recomputed_proof_binding_digest_hex",
                    )?,
                    proof_binding_digest_matches_recomputed: value
                        .consistency
                        .proof_binding_digest_matches_recomputed,
                    all_fields_match: value.consistency.all_fields_match,
                },
            })
        })
        .transpose()
}

fn parse_canonical_pipeline_tamper_bridge_audit_v1(
    value: CanonicalPipelineTamperBridgeAuditV1,
) -> Result<CanonicalPipelineTamperAuditV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineTamperAuditV1 {
        byte_offset: value.byte_offset,
        xor_with: value.xor_with,
    })
}

fn parse_canonical_pipeline_transactions_commitment_expansion_bridge_v1(
    value: CanonicalPipelineTransactionsCommitmentExpansionBridgeV1,
) -> Result<CanonicalPipelineTransactionsCommitmentExpansionV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineTransactionsCommitmentExpansionV1 {
        expansion_version: value.expansion_version,
        transactions_commitment: decode_hex_32_bridge_v1(
            &value.transactions_commitment_hex,
            "transactions_commitment_hex",
        )?,
        ordered_transactions: value
            .ordered_transactions
            .into_iter()
            .map(parse_canonical_pipeline_transaction_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_canonical_pipeline_outcomes_commitment_expansion_bridge_v1(
    value: CanonicalPipelineOutcomesCommitmentExpansionBridgeV1,
) -> Result<CanonicalPipelineOutcomesCommitmentExpansionV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineOutcomesCommitmentExpansionV1 {
        expansion_version: value.expansion_version,
        outcomes_commitment: decode_hex_32_bridge_v1(
            &value.outcomes_commitment_hex,
            "outcomes_commitment_hex",
        )?,
        outcomes: value
            .outcomes
            .into_iter()
            .map(parse_canonical_pipeline_execution_outcome_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
        applied_steps: value
            .applied_steps
            .into_iter()
            .map(parse_canonical_pipeline_applied_transfer_step_bridge_v1)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_canonical_pipeline_batch_context_commitment_expansion_bridge_v1(
    value: CanonicalPipelineBatchContextCommitmentExpansionBridgeV1,
) -> Result<CanonicalPipelineBatchContextCommitmentExpansionV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineBatchContextCommitmentExpansionV1 {
        expansion_version: value.expansion_version,
        batch_context_commitment: decode_hex_32_bridge_v1(
            &value.batch_context_commitment_hex,
            "batch_context_commitment_hex",
        )?,
        transition_binding_version: value.transition_binding_version,
        system_config: parse_canonical_pipeline_execution_config_bridge_v1(value.system_config)?,
        fee_parameters: CanonicalPipelineFeeParametersExpansionV1 {
            fee_per_transfer: value.fee_parameters.fee_per_transfer,
        },
        validity_reference: CanonicalPipelineValidityReferenceExpansionV1 {
            kind: match value.validity_reference.kind.as_str() {
                "none" => CanonicalPipelineValidityReferenceKindV1::None,
                _ => {
                    return Err(format!(
                        "unsupported validity_reference.kind: {}",
                        value.validity_reference.kind
                    )
                    .into())
                }
            },
            none_marker: value.validity_reference.none_marker,
        },
        execution_constants: CanonicalPipelineExecutionConstantsExpansionV1 {
            transfer_tx_version: value.execution_constants.transfer_tx_version,
            transition_binding_version: value.execution_constants.transition_binding_version,
            applied_status: value.execution_constants.applied_status,
        },
    })
}

fn parse_canonical_pipeline_fee_summary_commitment_expansion_bridge_v1(
    value: CanonicalPipelineFeeSummaryCommitmentExpansionBridgeV1,
) -> Result<CanonicalPipelineFeeSummaryCommitmentExpansionV1, Box<dyn std::error::Error>> {
    Ok(CanonicalPipelineFeeSummaryCommitmentExpansionV1 {
        expansion_version: value.expansion_version,
        fee_summary_commitment: decode_hex_32_bridge_v1(
            &value.fee_summary_commitment_hex,
            "fee_summary_commitment_hex",
        )?,
        fee_summary: LocalFeeSummaryV1 {
            tx_count: value.fee_summary.tx_count,
            total_fee_charged: value.fee_summary.total_fee_charged,
        },
    })
}

fn parse_canonical_pipeline_account_bridge_v1(
    value: CanonicalPipelineAccountBridgeV1,
) -> Result<LocalAccountV1, Box<dyn std::error::Error>> {
    Ok(LocalAccountV1 {
        account_id: decode_hex_32_bridge_v1(&value.account_id_hex, "account_id_hex")?,
        balance: value.balance,
        nonce: value.nonce,
    })
}

fn parse_canonical_pipeline_transaction_bridge_v1(
    value: CanonicalPipelineTransactionBridgeV1,
) -> Result<aura_l2_execution_v1::TransferTransactionV1, Box<dyn std::error::Error>> {
    Ok(aura_l2_execution_v1::TransferTransactionV1 {
        tx_version: value.tx_version,
        sender_account_id: decode_hex_32_bridge_v1(
            &value.sender_account_id_hex,
            "sender_account_id_hex",
        )?,
        recipient_account_id: decode_hex_32_bridge_v1(
            &value.recipient_account_id_hex,
            "recipient_account_id_hex",
        )?,
        sender_nonce: value.sender_nonce,
        amount: value.amount,
    })
}

fn parse_canonical_pipeline_execution_outcome_bridge_v1(
    value: CanonicalPipelineExecutionOutcomeBridgeV1,
) -> Result<ExecutionOutcomeV1, Box<dyn std::error::Error>> {
    Ok(ExecutionOutcomeV1 {
        tx_index: value.tx_index,
        sender_account_id: decode_hex_32_bridge_v1(
            &value.sender_account_id_hex,
            "sender_account_id_hex",
        )?,
        consumed_nonce: value.consumed_nonce,
        fee_charged: value.fee_charged,
        touched_accounts_commitment: decode_hex_32_bridge_v1(
            &value.touched_accounts_commitment_hex,
            "touched_accounts_commitment_hex",
        )?,
        operation_result_commitment: decode_hex_32_bridge_v1(
            &value.operation_result_commitment_hex,
            "operation_result_commitment_hex",
        )?,
        status: value.status,
    })
}

fn parse_canonical_pipeline_applied_transfer_step_bridge_v1(
    value: CanonicalPipelineAppliedTransferStepBridgeV1,
) -> Result<AppliedTransferStepV1, Box<dyn std::error::Error>> {
    Ok(AppliedTransferStepV1 {
        tx_index: value.tx_index,
        sender_account_id: decode_hex_32_bridge_v1(
            &value.sender_account_id_hex,
            "sender_account_id_hex",
        )?,
        recipient_account_id: decode_hex_32_bridge_v1(
            &value.recipient_account_id_hex,
            "recipient_account_id_hex",
        )?,
        sender_nonce_before: value.sender_nonce_before,
        sender_nonce_after: value.sender_nonce_after,
        sender_balance_before: value.sender_balance_before,
        sender_balance_after: value.sender_balance_after,
        recipient_balance_before: value.recipient_balance_before,
        recipient_balance_after: value.recipient_balance_after,
        amount: value.amount,
        fee_charged: value.fee_charged,
    })
}

fn parse_canonical_pipeline_execution_config_bridge_v1(
    value: CanonicalPipelineExecutionConfigBridgeV1,
) -> Result<LocalExecutionConfigV1, Box<dyn std::error::Error>> {
    Ok(LocalExecutionConfigV1 {
        rollup_id: decode_hex_32_bridge_v1(&value.rollup_id_hex, "rollup_id_hex")?,
        execution_model_version: value.execution_model_version,
        batch_version: value.batch_version,
    })
}

fn parse_scenario_result_bridge_v1(
    value: &str,
) -> Result<ScenarioResultV1, Box<dyn std::error::Error>> {
    match value {
        "Accepted" => Ok(ScenarioResultV1::Accepted),
        "ExecutionRejected" => Ok(ScenarioResultV1::ExecutionRejected),
        "VerificationRejected" => Ok(ScenarioResultV1::VerificationRejected),
        "SettlementRejected" => Ok(ScenarioResultV1::SettlementRejected),
        _ => Err(format!("unsupported scenario result: {value}").into()),
    }
}

fn parse_proof_system_bridge_v1(
    value: &str,
) -> Result<ProofSystemSelectionV1, Box<dyn std::error::Error>> {
    match value {
        "mock" => Ok(ProofSystemSelectionV1::Mock),
        "stark" => Ok(ProofSystemSelectionV1::Stark),
        _ => Err(format!("unsupported proof system: {value}").into()),
    }
}

fn parse_canonical_request_kind_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineRequestKindV1, Box<dyn std::error::Error>> {
    match value {
        "execution" => Ok(CanonicalPipelineRequestKindV1::Execution),
        "attestation" => Ok(CanonicalPipelineRequestKindV1::Attestation),
        _ => Err(format!("unsupported request_kind: {value}").into()),
    }
}

fn parse_canonical_burn_intent_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineBurnIntentV1, Box<dyn std::error::Error>> {
    match value {
        "canonical_report" => Ok(CanonicalPipelineBurnIntentV1::CanonicalReport),
        _ => Err(format!("unsupported burn_intent: {value}").into()),
    }
}

fn parse_canonical_payment_intent_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelinePaymentIntentV1, Box<dyn std::error::Error>> {
    match value {
        "burn_to_produce_canonical_truth" => {
            Ok(CanonicalPipelinePaymentIntentV1::BurnToProduceCanonicalTruth)
        }
        _ => Err(format!("unsupported payment_intent: {value}").into()),
    }
}

fn parse_canonical_settlement_intent_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineSettlementIntentV1, Box<dyn std::error::Error>> {
    match value {
        "record_canonical_outcome" => {
            Ok(CanonicalPipelineSettlementIntentV1::RecordCanonicalOutcome)
        }
        _ => Err(format!("unsupported settlement_intent: {value}").into()),
    }
}

fn parse_canonical_burn_reason_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineBurnReasonV1, Box<dyn std::error::Error>> {
    match value {
        "produce_canonical_truth_artifact" => {
            Ok(CanonicalPipelineBurnReasonV1::ProduceCanonicalTruthArtifact)
        }
        _ => Err(format!("unsupported burn_reason: {value}").into()),
    }
}

fn parse_canonical_burn_category_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineBurnCategoryV1, Box<dyn std::error::Error>> {
    match value {
        "execution_truth_production" => {
            Ok(CanonicalPipelineBurnCategoryV1::ExecutionTruthProduction)
        }
        "attestation_truth_production" => {
            Ok(CanonicalPipelineBurnCategoryV1::AttestationTruthProduction)
        }
        _ => Err(format!("unsupported burn_category: {value}").into()),
    }
}

fn parse_canonical_fee_disposition_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineFeeDispositionV1, Box<dyn std::error::Error>> {
    match value {
        "burned_for_canonical_truth" => {
            Ok(CanonicalPipelineFeeDispositionV1::BurnedForCanonicalTruth)
        }
        _ => Err(format!("unsupported fee_disposition: {value}").into()),
    }
}

fn parse_canonical_future_token_binding_status_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineFutureTokenBindingStatusV1, Box<dyn std::error::Error>> {
    match value {
        "pending_external_anchor" => {
            Ok(CanonicalPipelineFutureTokenBindingStatusV1::PendingExternalAnchor)
        }
        _ => Err(format!("unsupported future_token_binding_status: {value}").into()),
    }
}

fn parse_canonical_head_authority_mode_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineHeadAuthorityModeV1, Box<dyn std::error::Error>> {
    match value {
        "authoritative_persistent" => {
            Ok(CanonicalPipelineHeadAuthorityModeV1::AuthoritativePersistent)
        }
        "stateless_non_authoritative" => {
            Ok(CanonicalPipelineHeadAuthorityModeV1::StatelessNonAuthoritative)
        }
        _ => Err(format!("unsupported authority_mode: {value}").into()),
    }
}

fn parse_canonical_network_mode_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineNetworkModeV1, Box<dyn std::error::Error>> {
    match value {
        "local" => Ok(CanonicalPipelineNetworkModeV1::Local),
        "bridged" => Ok(CanonicalPipelineNetworkModeV1::Bridged),
        _ => Err(format!("unsupported network_mode: {value}").into()),
    }
}

fn parse_canonical_settlement_anchor_type_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineSettlementAnchorTypeV1, Box<dyn std::error::Error>> {
    match value {
        "local" => Ok(CanonicalPipelineSettlementAnchorTypeV1::Local),
        "simulated" => Ok(CanonicalPipelineSettlementAnchorTypeV1::Simulated),
        "external" => Ok(CanonicalPipelineSettlementAnchorTypeV1::External),
        _ => Err(format!("unsupported settlement_anchor_type: {value}").into()),
    }
}

fn parse_canonical_external_anchor_verification_status_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineExternalAnchorVerificationStatusV1, Box<dyn std::error::Error>> {
    match value {
        "not_requested" => Ok(CanonicalPipelineExternalAnchorVerificationStatusV1::NotRequested),
        "accepted" => Ok(CanonicalPipelineExternalAnchorVerificationStatusV1::Accepted),
        "rejected" => Ok(CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected),
        "disconnected" => Ok(CanonicalPipelineExternalAnchorVerificationStatusV1::Disconnected),
        _ => Err(format!("unsupported anchor_verification_status: {value}").into()),
    }
}

fn parse_canonical_evidence_provenance_type_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineEvidenceProvenanceTypeV1, Box<dyn std::error::Error>> {
    match value {
        "inline" => Ok(CanonicalPipelineEvidenceProvenanceTypeV1::Inline),
        "hash_reference" => Ok(CanonicalPipelineEvidenceProvenanceTypeV1::HashReference),
        "signed_blob" => Ok(CanonicalPipelineEvidenceProvenanceTypeV1::SignedBlob),
        "anchored_external" => Ok(CanonicalPipelineEvidenceProvenanceTypeV1::AnchoredExternal),
        _ => Err(format!("unsupported provenance_type: {value}").into()),
    }
}

fn parse_canonical_settlement_reason_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineSettlementReasonV1, Box<dyn std::error::Error>> {
    match value {
        "accepted_and_committed" => Ok(CanonicalPipelineSettlementReasonV1::AcceptedAndCommitted),
        "not_run_execution_rejected" => {
            Ok(CanonicalPipelineSettlementReasonV1::NotRunExecutionRejected)
        }
        "rejected_verification_mismatch" => {
            Ok(CanonicalPipelineSettlementReasonV1::RejectedVerificationMismatch)
        }
        "rejected_local_settlement" => {
            Ok(CanonicalPipelineSettlementReasonV1::RejectedLocalSettlement)
        }
        _ => Err(format!("unsupported settlement_reason: {value}").into()),
    }
}

fn parse_canonical_truth_artifact_kind_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineTruthArtifactKindV1, Box<dyn std::error::Error>> {
    match value {
        "execution_report" => Ok(CanonicalPipelineTruthArtifactKindV1::ExecutionReport),
        "attestation_report" => Ok(CanonicalPipelineTruthArtifactKindV1::AttestationReport),
        _ => Err(format!("unsupported truth_artifact_kind: {value}").into()),
    }
}

fn parse_canonical_failure_stage_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineFailureStageV1, Box<dyn std::error::Error>> {
    match value {
        "none" => Ok(CanonicalPipelineFailureStageV1::None),
        "request" => Ok(CanonicalPipelineFailureStageV1::Request),
        "execution" => Ok(CanonicalPipelineFailureStageV1::Execution),
        "verification" => Ok(CanonicalPipelineFailureStageV1::Verification),
        "settlement" => Ok(CanonicalPipelineFailureStageV1::Settlement),
        _ => Err(format!("unsupported failure_stage: {value}").into()),
    }
}

fn parse_canonical_failure_reason_code_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineFailureReasonCodeV1, Box<dyn std::error::Error>> {
    match value {
        "none" => Ok(CanonicalPipelineFailureReasonCodeV1::None),
        "transfer_execution_rejected" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::TransferExecutionRejected)
        }
        "unsupported_attestation_mode" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::UnsupportedAttestationMode)
        }
        "attestation_malformed_evidence" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::AttestationMalformedEvidence)
        }
        "attestation_normalization_failure" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::AttestationNormalizationFailure)
        }
        "attestation_consistency_mismatch" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::AttestationConsistencyMismatch)
        }
        "verification_layer_mismatch" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::VerificationLayerMismatch)
        }
        "settlement_acceptance_rejected" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::SettlementAcceptanceRejected)
        }
        "settlement_head_mismatch" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::SettlementHeadMismatch)
        }
        "wallet_binding_mismatch" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::WalletBindingMismatch)
        }
        "unsupported_provenance_type" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::UnsupportedProvenanceType)
        }
        "provenance_signature_invalid" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::ProvenanceSignatureInvalid)
        }
        "attestation_proof_verification_rejected" => {
            Ok(CanonicalPipelineFailureReasonCodeV1::AttestationProofVerificationRejected)
        }
        _ => Err(format!("unsupported failure_reason_code: {value}").into()),
    }
}

fn parse_canonical_attestation_scope_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationScopeV1, Box<dyn std::error::Error>> {
    match value {
        "claim_consistency_with_provided_evidence_only" => {
            Ok(CanonicalPipelineAttestationScopeV1::ClaimConsistencyWithProvidedEvidenceOnly)
        }
        _ => Err(format!("unsupported attestation_scope: {value}").into()),
    }
}

fn parse_canonical_attestation_proof_kind_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationProofKindV1, Box<dyn std::error::Error>> {
    match value {
        "MOCK" => Ok(CanonicalPipelineAttestationProofKindV1::Mock),
        "STARK" => Ok(CanonicalPipelineAttestationProofKindV1::Stark),
        _ => Err(format!("unsupported attestation_proof_kind: {value}").into()),
    }
}

fn parse_canonical_attestation_claim_kind_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationClaimKindV1, Box<dyn std::error::Error>> {
    match value {
        "evidence_root_digest" => Ok(CanonicalPipelineAttestationClaimKindV1::EvidenceRootDigest),
        "normalized_evidence_digest" => {
            Ok(CanonicalPipelineAttestationClaimKindV1::NormalizedEvidenceDigest)
        }
        "normalized_text_contains_utf8" => {
            Ok(CanonicalPipelineAttestationClaimKindV1::NormalizedTextContainsUtf8)
        }
        "normalized_json_field_equals_utf8" => {
            Ok(CanonicalPipelineAttestationClaimKindV1::NormalizedJsonFieldEqualsUtf8)
        }
        _ => Err(format!("unsupported attestation.claim_kind: {value}").into()),
    }
}

fn parse_canonical_attestation_evidence_kind_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationEvidenceKindV1, Box<dyn std::error::Error>> {
    match value {
        "inline_utf8" => Ok(CanonicalPipelineAttestationEvidenceKindV1::InlineUtf8),
        "inline_json_utf8" => Ok(CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8),
        _ => Err(format!("unsupported attestation.evidence_kind: {value}").into()),
    }
}

fn parse_canonical_attestation_normalized_form_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationNormalizedFormV1, Box<dyn std::error::Error>> {
    match value {
        "utf8_text" => Ok(CanonicalPipelineAttestationNormalizedFormV1::Utf8Text),
        "canonical_json_utf8" => {
            Ok(CanonicalPipelineAttestationNormalizedFormV1::CanonicalJsonUtf8)
        }
        _ => Err(format!("unsupported attestation.normalized_form: {value}").into()),
    }
}

fn parse_canonical_attestation_consistency_relation_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationConsistencyRelationV1, Box<dyn std::error::Error>> {
    match value {
        "evidence_root_digest_equals" => {
            Ok(CanonicalPipelineAttestationConsistencyRelationV1::EvidenceRootDigestEquals)
        }
        "normalized_evidence_digest_equals" => {
            Ok(CanonicalPipelineAttestationConsistencyRelationV1::NormalizedEvidenceDigestEquals)
        }
        "normalized_text_contains_utf8" => {
            Ok(CanonicalPipelineAttestationConsistencyRelationV1::NormalizedTextContainsUtf8)
        }
        "normalized_json_field_equals_utf8" => {
            Ok(CanonicalPipelineAttestationConsistencyRelationV1::NormalizedJsonFieldEqualsUtf8)
        }
        _ => Err(format!("unsupported attestation.consistency_result.relation: {value}").into()),
    }
}

fn parse_canonical_attestation_status_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationStatusV1, Box<dyn std::error::Error>> {
    match value {
        "accepted" => Ok(CanonicalPipelineAttestationStatusV1::Accepted),
        "rejected" => Ok(CanonicalPipelineAttestationStatusV1::Rejected),
        _ => Err(format!("unsupported attestation.attestation_status: {value}").into()),
    }
}

fn parse_canonical_attestation_failure_reason_bridge_v1(
    value: &str,
) -> Result<CanonicalPipelineAttestationFailureReasonV1, Box<dyn std::error::Error>> {
    match value {
        "none" => Ok(CanonicalPipelineAttestationFailureReasonV1::None),
        "unsupported_attestation_mode" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::UnsupportedAttestationMode)
        }
        "malformed_evidence" => Ok(CanonicalPipelineAttestationFailureReasonV1::MalformedEvidence),
        "normalization_failure" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::NormalizationFailure)
        }
        "consistency_mismatch" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::ConsistencyMismatch)
        }
        "unsupported_provenance_type" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::UnsupportedProvenanceType)
        }
        "provenance_signature_invalid" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::ProvenanceSignatureInvalid)
        }
        "verification_layer_failure" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::VerificationLayerFailure)
        }
        "attestation_proof_verification_failure" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::AttestationProofVerificationFailure)
        }
        "settlement_layer_failure" => {
            Ok(CanonicalPipelineAttestationFailureReasonV1::SettlementLayerFailure)
        }
        _ => Err(format!("unsupported attestation.attestation_failure_reason: {value}").into()),
    }
}

fn parse_canonical_settlement_status_bridge_v1(
    value: &str,
) -> Result<aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1, Box<dyn std::error::Error>>
{
    match value {
        "accepted" => Ok(aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::Accepted),
        "rejected" => Ok(aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::Rejected),
        "not_run" => Ok(aura_l2_local_chain_v0::CanonicalPipelineSettlementStatusV1::NotRun),
        _ => Err(format!("unsupported settlement_status: {value}").into()),
    }
}

fn parse_optional_hex_32_bridge_v1(
    value: Option<&str>,
    label: &str,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    value
        .map(|value| decode_hex_32_bridge_v1(value, label))
        .transpose()
}

fn parse_optional_hex_fixed_bytes_bridge_v1<const N: usize>(
    value: Option<&str>,
    label: &str,
) -> Result<Option<[u8; N]>, Box<dyn std::error::Error>> {
    value
        .map(|value| decode_hex_fixed_bytes_bridge_v1::<N>(value, label))
        .transpose()
}

fn decode_hex_32_bridge_v1(
    value: &str,
    label: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    decode_hex_fixed_bytes_bridge_v1::<32>(value, label)
}

fn decode_hex_fixed_bytes_bridge_v1<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], Box<dyn std::error::Error>> {
    if value.len() != N * 2 {
        return Err(format!("{label} must be {} hex chars, got {}", N * 2, value.len()).into());
    }
    let mut bytes = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let chunk = std::str::from_utf8(chunk)?;
        bytes[index] =
            u8::from_str_radix(chunk, 16).map_err(|_| format!("{label} contains invalid hex"))?;
    }
    Ok(bytes)
}

impl From<&ScenarioReportV1> for ScenarioBridgeReportV1 {
    fn from(value: &ScenarioReportV1) -> Self {
        Self {
            fixture_name: value.fixture_name.clone(),
            expected_result: scenario_result_bridge_str_v1(value.expected_result).to_string(),
            actual_result: scenario_result_bridge_str_v1(value.actual_result).to_string(),
            pre_state_root_hex: encode_hex(&value.pre_state_root),
            post_state_root_hex: value.post_state_root.map(|root| encode_hex(&root)),
            transition_binding_hash_hex: value
                .transition_binding_hash
                .map(|hash| encode_hex(&hash)),
        }
    }
}

impl From<&CanonicalPipelineReportV1> for CanonicalPipelineBridgeReportV1 {
    fn from(value: &CanonicalPipelineReportV1) -> Self {
        Self {
            pipeline_schema_version: value.pipeline_schema_version,
            pipeline_id: value.pipeline_id.clone(),
            fixture_name: value.fixture_name.clone(),
            proof_system: proof_system_bridge_str_v1(value.proof_system).to_string(),
            expected_result: scenario_result_bridge_str_v1(value.expected_result).to_string(),
            actual_result: scenario_result_bridge_str_v1(value.actual_result).to_string(),
            pre_state_root_hex: encode_hex(&value.pre_state_root),
            executed_post_state_root_hex: value
                .executed_post_state_root
                .map(|root| encode_hex(&root)),
            settlement_committed_state_root_hex: value
                .settlement_committed_state_root
                .map(|root| encode_hex(&root)),
            burn_summary: CanonicalPipelineBurnSummaryBridgeV1::from(&value.burn_summary),
            accounting_summary: CanonicalPipelineAccountingSummaryBridgeV1::from(
                &value.accounting_summary,
            ),
            ledger_summary: CanonicalPipelineLedgerSummaryBridgeV1::from(&value.ledger_summary),
            head_transition_summary: CanonicalPipelineHeadTransitionSummaryBridgeV1::from(
                &value.head_transition_summary,
            ),
            wallet_binding_summary: CanonicalPipelineWalletBindingSummaryBridgeV1::from(
                &value.wallet_binding_summary,
            ),
            token_anchor_summary: CanonicalPipelineTokenAnchorSummaryBridgeV1::from(
                &value.token_anchor_summary,
            ),
            request_audit: CanonicalPipelineRequestBridgeAuditV1::from(&value.request_audit),
            genesis_accounts: CanonicalPipelineGenesisAccountsBridgeV1::from(
                &value.genesis_accounts,
            ),
            ledger_accounts: CanonicalPipelineLedgerAccountsBridgeV1::from(&value.ledger_accounts),
            commitment_expansions: CanonicalPipelineCommitmentExpansionsBridgeV1::from(
                &value.commitment_expansions,
            ),
            stage_outcomes: CanonicalPipelineStageOutcomesBridgeV1::from(&value.stage_outcomes),
            status_explanation: CanonicalPipelineStatusExplanationBridgeV1::from(
                &value.status_explanation,
            ),
            attestation_summary: value
                .attestation_summary
                .as_ref()
                .map(CanonicalPipelineAttestationSummaryBridgeV1::from),
            attestation_proof_summary: value
                .attestation_proof_summary
                .as_ref()
                .map(CanonicalPipelineAttestationProofSummaryBridgeV1::from),
            provenance_summary: value
                .provenance_summary
                .as_ref()
                .map(CanonicalPipelineProvenanceSummaryBridgeV1::from),
            public_inputs: value
                .public_inputs
                .as_ref()
                .map(CanonicalPipelinePublicInputsBridgeAuditV1::from),
            proof_artifact: value
                .proof_artifact
                .as_ref()
                .map(CanonicalPipelineProofArtifactBridgeAuditV1::from),
        }
    }
}

impl From<&CanonicalPipelineHeadTransitionSummaryV1>
    for CanonicalPipelineHeadTransitionSummaryBridgeV1
{
    fn from(value: &CanonicalPipelineHeadTransitionSummaryV1) -> Self {
        Self {
            settlement_head_version: value.settlement_head_version,
            authority_mode: canonical_head_authority_mode_bridge_str_v1(value.authority_mode)
                .to_string(),
            head_sequence_number: value.head_sequence_number,
            previous_head_hash_hex: encode_hex(&value.previous_head_hash),
            current_head_hash_hex: encode_hex(&value.current_head_hash),
            canonical_head_commitment_hex: encode_hex(&value.canonical_head_commitment),
            request_canonical_digest_hex: encode_hex(&value.request_canonical_digest),
            report_digest_hex: encode_hex(&value.report_digest),
        }
    }
}

impl From<&CanonicalPipelineWalletBindingSummaryV1>
    for CanonicalPipelineWalletBindingSummaryBridgeV1
{
    fn from(value: &CanonicalPipelineWalletBindingSummaryV1) -> Self {
        Self {
            wallet_binding_version: value.wallet_binding_version,
            account_id_hex: encode_hex(&value.account_id),
            wallet_address: value.wallet_address.clone(),
            wallet_binding_digest_hex: encode_hex(&value.wallet_binding_digest),
            binding_consistent_with_account: value.binding_consistent_with_account,
        }
    }
}

impl From<&CanonicalPipelineTokenAnchorSummaryV1> for CanonicalPipelineTokenAnchorSummaryBridgeV1 {
    fn from(value: &CanonicalPipelineTokenAnchorSummaryV1) -> Self {
        Self {
            token_policy_version: value.token_policy_version,
            network_mode: canonical_network_mode_bridge_str_v1(value.network_mode).to_string(),
            settlement_anchor_type: canonical_settlement_anchor_type_bridge_str_v1(
                value.settlement_anchor_type,
            )
            .to_string(),
            anchor_verification_status:
                canonical_external_anchor_verification_status_bridge_str_v1(
                    value.anchor_verification_status,
                )
                .to_string(),
            external_balance_reference: value
                .external_balance_reference
                .as_ref()
                .map(CanonicalPipelineExternalBalanceReferenceBridgeV1::from),
            expected_external_balance: value.expected_external_balance,
            token_anchor_digest_hex: encode_hex(&value.token_anchor_digest),
        }
    }
}

impl From<&CanonicalPipelineExternalBalanceReferenceV1>
    for CanonicalPipelineExternalBalanceReferenceBridgeV1
{
    fn from(value: &CanonicalPipelineExternalBalanceReferenceV1) -> Self {
        Self {
            reference_id: value.reference_id.clone(),
            observed_balance: value.observed_balance,
            observed_slot: value.observed_slot,
            connected: value.connected,
        }
    }
}

impl From<&CanonicalPipelineBurnSummaryV1> for CanonicalPipelineBurnSummaryBridgeV1 {
    fn from(value: &CanonicalPipelineBurnSummaryV1) -> Self {
        Self {
            burn_policy_version: value.burn_policy_version,
            burn_policy: CanonicalPipelineBurnPolicyBridgeV1::from(&value.burn_policy),
            burn_reason: canonical_burn_reason_bridge_str_v1(value.burn_reason).to_string(),
            burn_category: canonical_burn_category_bridge_str_v1(value.burn_category).to_string(),
            request_kind: canonical_request_kind_bridge_str_v1(value.request_kind).to_string(),
            burn_intent: canonical_burn_intent_bridge_str_v1(value.burn_intent).to_string(),
            declared_fee_units: value.declared_fee_units,
            computed_burn_units: value.computed_burn_units,
            consumed_burn_units: value.consumed_burn_units,
            burn_derivation_inputs: CanonicalPipelineBurnDerivationInputsBridgeV1::from(
                &value.burn_derivation_inputs,
            ),
            request_declares_correct_burn: value.request_declares_correct_burn,
            recomputed_burn_matches_report: value.recomputed_burn_matches_report,
            burn_consumed: value.burn_consumed,
            failure_semantics: CanonicalPipelineBurnFailureSemanticsBridgeV1::from(
                &value.failure_semantics,
            ),
        }
    }
}

impl From<&CanonicalPipelineBurnPolicyV1> for CanonicalPipelineBurnPolicyBridgeV1 {
    fn from(value: &CanonicalPipelineBurnPolicyV1) -> Self {
        Self {
            burn_policy_version: value.burn_policy_version,
            base_units: value.base_units,
            execution_request_kind_units: value.execution_request_kind_units,
            attestation_request_kind_units: value.attestation_request_kind_units,
            mock_proof_system_units: value.mock_proof_system_units,
            stark_proof_system_units: value.stark_proof_system_units,
            transaction_units_per_item: value.transaction_units_per_item,
            metered_request_size_chunk_bytes: value.metered_request_size_chunk_bytes,
        }
    }
}

impl From<&CanonicalPipelineBurnDerivationInputsV1>
    for CanonicalPipelineBurnDerivationInputsBridgeV1
{
    fn from(value: &CanonicalPipelineBurnDerivationInputsV1) -> Self {
        Self {
            tx_count: value.tx_count,
            metered_request_size_bytes: value.metered_request_size_bytes,
            request_kind: canonical_request_kind_bridge_str_v1(value.request_kind).to_string(),
            proof_system: proof_system_bridge_str_v1(value.proof_system).to_string(),
            attestation_evidence_items: value.attestation_evidence_items,
            attestation_claim_bytes: value.attestation_claim_bytes,
            attestation_evidence_bytes: value.attestation_evidence_bytes,
        }
    }
}

impl From<&CanonicalPipelineBurnFailureSemanticsV1>
    for CanonicalPipelineBurnFailureSemanticsBridgeV1
{
    fn from(value: &CanonicalPipelineBurnFailureSemanticsV1) -> Self {
        Self {
            execution_rejected_burns_full_amount: value.execution_rejected_burns_full_amount,
            verification_rejected_burns_full_amount: value.verification_rejected_burns_full_amount,
            settlement_rejected_burns_full_amount: value.settlement_rejected_burns_full_amount,
            partial_burn_allowed: value.partial_burn_allowed,
        }
    }
}

impl From<&CanonicalPipelineAccountingSummaryV1> for CanonicalPipelineAccountingSummaryBridgeV1 {
    fn from(value: &CanonicalPipelineAccountingSummaryV1) -> Self {
        Self {
            accounting_policy_version: value.accounting_policy_version,
            payment_intent: canonical_payment_intent_bridge_str_v1(value.payment_intent)
                .to_string(),
            settlement_intent: canonical_settlement_intent_bridge_str_v1(value.settlement_intent)
                .to_string(),
            declared_fee_units: value.declared_fee_units,
            computed_burn_units: value.computed_burn_units,
            consumed_burn_units: value.consumed_burn_units,
            burn_record: CanonicalPipelineBurnRecordBridgeV1::from(&value.burn_record),
            settlement_record: CanonicalPipelineSettlementRecordBridgeV1::from(
                &value.settlement_record,
            ),
            accounting_consistent_with_burn: value.accounting_consistent_with_burn,
            accounting_consistent_with_outcome: value.accounting_consistent_with_outcome,
        }
    }
}

impl From<&CanonicalPipelineBurnRecordV1> for CanonicalPipelineBurnRecordBridgeV1 {
    fn from(value: &CanonicalPipelineBurnRecordV1) -> Self {
        Self {
            burn_reason: canonical_burn_reason_bridge_str_v1(value.burn_reason).to_string(),
            burn_category: canonical_burn_category_bridge_str_v1(value.burn_category).to_string(),
            fee_disposition: canonical_fee_disposition_bridge_str_v1(value.fee_disposition)
                .to_string(),
            account_id_hex: encode_hex(&value.account_id),
            pre_balance: value.pre_balance,
            post_balance: value.post_balance,
            burned_amount: value.burned_amount,
            declared_fee_units: value.declared_fee_units,
            computed_burn_units: value.computed_burn_units,
            consumed_burn_units: value.consumed_burn_units,
            report_pipeline_id: value.report_pipeline_id.clone(),
            report_request_binding_hash_hex: encode_hex(&value.report_request_binding_hash),
        }
    }
}

impl From<&CanonicalPipelineLedgerSummaryV1> for CanonicalPipelineLedgerSummaryBridgeV1 {
    fn from(value: &CanonicalPipelineLedgerSummaryV1) -> Self {
        Self {
            ledger_policy_version: value.ledger_policy_version,
            payer_account_id_hex: encode_hex(&value.payer_account_id),
            total_supply: value.total_supply,
            burned_supply_before: value.burned_supply_before,
            burned_supply_after: value.burned_supply_after,
            ledger_account_count: value.ledger_account_count,
            circulating_supply_before: value.circulating_supply_before,
            circulating_supply_after: value.circulating_supply_after,
            ledger_consistent_with_request: value.ledger_consistent_with_request,
            ledger_consistent_with_burn: value.ledger_consistent_with_burn,
            ledger_consistent_with_supply: value.ledger_consistent_with_supply,
            ledger_state_commitment: CanonicalPipelineLedgerStateCommitmentBridgeV1::from(
                &value.ledger_state_commitment,
            ),
        }
    }
}

impl From<&CanonicalPipelineLedgerStateCommitmentV1>
    for CanonicalPipelineLedgerStateCommitmentBridgeV1
{
    fn from(value: &CanonicalPipelineLedgerStateCommitmentV1) -> Self {
        Self {
            commitment_version: value.commitment_version,
            pre_ledger_state_commitment_hex: encode_hex(&value.pre_ledger_state_commitment),
            post_ledger_state_commitment_hex: encode_hex(&value.post_ledger_state_commitment),
        }
    }
}

impl From<&CanonicalPipelineSettlementRecordV1> for CanonicalPipelineSettlementRecordBridgeV1 {
    fn from(value: &CanonicalPipelineSettlementRecordV1) -> Self {
        Self {
            settlement_intent: canonical_settlement_intent_bridge_str_v1(value.settlement_intent)
                .to_string(),
            settlement_status: canonical_settlement_status_bridge_str_v1(value.settlement_status)
                .to_string(),
            settlement_reason: canonical_settlement_reason_bridge_str_v1(value.settlement_reason)
                .to_string(),
            committed_state_root_hex: value.committed_state_root.map(|root| encode_hex(&root)),
            future_token_binding_status: canonical_future_token_binding_status_bridge_str_v1(
                value.future_token_binding_status,
            )
            .to_string(),
            future_token_binding_units: value.future_token_binding_units,
        }
    }
}

impl From<&CanonicalPipelineStatusExplanationV1> for CanonicalPipelineStatusExplanationBridgeV1 {
    fn from(value: &CanonicalPipelineStatusExplanationV1) -> Self {
        Self {
            truth_artifact_kind: canonical_truth_artifact_kind_bridge_str_v1(
                value.truth_artifact_kind,
            )
            .to_string(),
            request_kind: canonical_request_kind_bridge_str_v1(value.request_kind).to_string(),
            final_status: scenario_result_bridge_str_v1(value.final_status).to_string(),
            failure_stage: canonical_failure_stage_bridge_str_v1(value.failure_stage).to_string(),
            failure_reason_code: canonical_failure_reason_code_bridge_str_v1(
                value.failure_reason_code,
            )
            .to_string(),
            detail: value.detail.clone(),
        }
    }
}

impl From<&CanonicalPipelineAttestationSummaryV1> for CanonicalPipelineAttestationSummaryBridgeV1 {
    fn from(value: &CanonicalPipelineAttestationSummaryV1) -> Self {
        Self {
            attestation_schema_version: value.attestation_schema_version,
            attestation_scope: canonical_attestation_scope_bridge_str_v1(value.attestation_scope)
                .to_string(),
            attestation_proof_kind: canonical_attestation_proof_kind_bridge_str_v1(
                value.attestation_proof_kind,
            )
            .to_string(),
            normalization_policy_version: value.normalization_policy_version,
            attestation_constraints: CanonicalPipelineAttestationConstraintsBridgeV1::from(
                &value.attestation_constraints,
            ),
            claim: CanonicalPipelineAttestationClaimBridgeV1::from(&value.claim),
            claim_digest_hex: encode_hex(&value.claim_digest),
            evidence_summary: CanonicalPipelineAttestationEvidenceSummaryBridgeV1::from(
                &value.evidence_summary,
            ),
            normalization_summary: CanonicalPipelineAttestationNormalizationSummaryBridgeV1::from(
                &value.normalization_summary,
            ),
            consistency_result: CanonicalPipelineAttestationConsistencyResultBridgeV1::from(
                &value.consistency_result,
            ),
            attestation_status: canonical_attestation_status_bridge_str_v1(
                value.attestation_status,
            )
            .to_string(),
            attestation_failure_reason: CanonicalPipelineAttestationFailureAuditBridgeV1::from(
                &value.attestation_failure_reason,
            ),
            proof_scope_honesty_note: value.proof_scope_honesty_note.clone(),
        }
    }
}

impl From<&CanonicalPipelineAttestationConstraintsV1>
    for CanonicalPipelineAttestationConstraintsBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationConstraintsV1) -> Self {
        Self {
            require_unique_labels: value.require_unique_labels,
            max_evidence_items: value.max_evidence_items,
            max_total_normalized_bytes: value.max_total_normalized_bytes,
        }
    }
}

impl From<&CanonicalPipelineAttestationClaimV1> for CanonicalPipelineAttestationClaimBridgeV1 {
    fn from(value: &CanonicalPipelineAttestationClaimV1) -> Self {
        Self {
            claim_kind: canonical_attestation_claim_kind_bridge_str_v1(value.claim_kind)
                .to_string(),
            claim_payload: CanonicalPipelineAttestationClaimPayloadBridgeV1::from(
                &value.claim_payload,
            ),
        }
    }
}

impl From<&CanonicalPipelineAttestationClaimPayloadV1>
    for CanonicalPipelineAttestationClaimPayloadBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationClaimPayloadV1) -> Self {
        match value {
            CanonicalPipelineAttestationClaimPayloadV1::EvidenceRootDigest {
                expected_evidence_root_digest,
            } => Self {
                expected_evidence_root_digest_hex: Some(encode_hex(expected_evidence_root_digest)),
                target_label: None,
                expected_evidence_digest_hex: None,
                expected_substring_utf8: None,
                field_path: None,
                expected_value_utf8: None,
            },
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedEvidenceDigest {
                target_label,
                expected_evidence_digest,
            } => Self {
                expected_evidence_root_digest_hex: None,
                target_label: Some(target_label.clone()),
                expected_evidence_digest_hex: Some(encode_hex(expected_evidence_digest)),
                expected_substring_utf8: None,
                field_path: None,
                expected_value_utf8: None,
            },
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedTextContainsUtf8 {
                target_label,
                expected_substring_utf8,
            } => Self {
                expected_evidence_root_digest_hex: None,
                target_label: Some(target_label.clone()),
                expected_evidence_digest_hex: None,
                expected_substring_utf8: Some(expected_substring_utf8.clone()),
                field_path: None,
                expected_value_utf8: None,
            },
            CanonicalPipelineAttestationClaimPayloadV1::NormalizedJsonFieldEqualsUtf8 {
                target_label,
                field_path,
                expected_value_utf8,
            } => Self {
                expected_evidence_root_digest_hex: None,
                target_label: Some(target_label.clone()),
                expected_evidence_digest_hex: None,
                expected_substring_utf8: None,
                field_path: Some(field_path.clone()),
                expected_value_utf8: Some(expected_value_utf8.clone()),
            },
        }
    }
}

impl From<&CanonicalPipelineAttestationEvidenceSummaryV1>
    for CanonicalPipelineAttestationEvidenceSummaryBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationEvidenceSummaryV1) -> Self {
        Self {
            evidence_item_count: value.evidence_item_count,
            evidence_items: value
                .evidence_items
                .iter()
                .map(CanonicalPipelineAttestationEvidenceSummaryItemBridgeV1::from)
                .collect(),
            evidence_root_digest_hex: encode_hex(&value.evidence_root_digest),
        }
    }
}

impl From<&CanonicalPipelineAttestationEvidenceSummaryItemV1>
    for CanonicalPipelineAttestationEvidenceSummaryItemBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationEvidenceSummaryItemV1) -> Self {
        Self {
            label: value.label.clone(),
            evidence_kind: canonical_attestation_evidence_kind_bridge_str_v1(value.evidence_kind)
                .to_string(),
            original_payload_utf8: value.original_payload_utf8.clone(),
            original_payload_size_bytes: value.original_payload_size_bytes,
            normalized_form: canonical_attestation_normalized_form_bridge_str_v1(
                value.normalized_form,
            )
            .to_string(),
            normalized_payload_utf8: value.normalized_payload_utf8.clone(),
            normalized_payload_size_bytes: value.normalized_payload_size_bytes,
            evidence_digest_hex: encode_hex(&value.evidence_digest),
            provenance_digest_hex: encode_hex(&value.provenance_digest),
        }
    }
}

impl From<&CanonicalPipelineAttestationNormalizationSummaryV1>
    for CanonicalPipelineAttestationNormalizationSummaryBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationNormalizationSummaryV1) -> Self {
        Self {
            normalization_policy_version: value.normalization_policy_version,
            normalized_evidence_count: value.normalized_evidence_count,
            total_normalized_bytes: value.total_normalized_bytes,
            normalization_succeeded: value.normalization_succeeded,
        }
    }
}

impl From<&CanonicalPipelineAttestationConsistencyResultV1>
    for CanonicalPipelineAttestationConsistencyResultBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationConsistencyResultV1) -> Self {
        Self {
            relation: canonical_attestation_consistency_relation_bridge_str_v1(value.relation)
                .to_string(),
            target_label: value.target_label.clone(),
            consistent: value.consistent,
        }
    }
}

impl From<&CanonicalPipelineAttestationFailureAuditV1>
    for CanonicalPipelineAttestationFailureAuditBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationFailureAuditV1) -> Self {
        Self {
            reason: canonical_attestation_failure_reason_bridge_str_v1(value.reason).to_string(),
            detail: value.detail.clone(),
        }
    }
}

impl From<&CanonicalPipelineAttestationProofSummaryV1>
    for CanonicalPipelineAttestationProofSummaryBridgeV1
{
    fn from(value: &CanonicalPipelineAttestationProofSummaryV1) -> Self {
        Self {
            proof_kind: canonical_attestation_proof_kind_bridge_str_v1(value.proof_kind)
                .to_string(),
            attestation_tuple_digest_hex: encode_hex(&value.attestation_tuple_digest),
            verification_passed: value.verification_passed,
            mock_policy_version: value.mock_policy_version,
            stark_policy_version: value.stark_policy_version,
            stark_public_inputs_digest_hex: value
                .stark_public_inputs_digest
                .map(|digest| encode_hex(&digest)),
            stark_proof_bytes_digest_hex: value
                .stark_proof_bytes_digest
                .map(|digest| encode_hex(&digest)),
            stark_proof_binding_digest_hex: value
                .stark_proof_binding_digest
                .map(|digest| encode_hex(&digest)),
        }
    }
}

impl From<&CanonicalPipelineProvenanceSummaryV1> for CanonicalPipelineProvenanceSummaryBridgeV1 {
    fn from(value: &CanonicalPipelineProvenanceSummaryV1) -> Self {
        Self {
            provenance_item_count: value.provenance_item_count,
            items: value
                .items
                .iter()
                .map(CanonicalPipelineProvenanceSummaryItemBridgeV1::from)
                .collect(),
            provenance_root_digest_hex: encode_hex(&value.provenance_root_digest),
            all_signature_checks_passed: value.all_signature_checks_passed,
        }
    }
}

impl From<&CanonicalPipelineProvenanceSummaryItemV1>
    for CanonicalPipelineProvenanceSummaryItemBridgeV1
{
    fn from(value: &CanonicalPipelineProvenanceSummaryItemV1) -> Self {
        Self {
            label: value.label.clone(),
            provenance_policy_version: value.provenance_policy_version,
            provenance_type: canonical_evidence_provenance_type_bridge_str_v1(
                value.provenance_type,
            )
            .to_string(),
            source_type: value.source_type.clone(),
            source_identifier: value.source_identifier.clone(),
            signature_present: value.signature_present,
            signature_valid: value.signature_valid,
            signer_public_key_hex: value.signer_public_key.map(|bytes| encode_hex(&bytes)),
            signature_hex: value.signature.map(|bytes| encode_hex(&bytes)),
            timestamp_unix_seconds: value.timestamp_unix_seconds,
            provenance_digest_hex: encode_hex(&value.provenance_digest),
        }
    }
}

impl From<&CanonicalPipelineGenesisAccountsV1> for CanonicalPipelineGenesisAccountsBridgeV1 {
    fn from(value: &CanonicalPipelineGenesisAccountsV1) -> Self {
        Self {
            material_version: value.material_version,
            ordered_accounts: value
                .ordered_accounts
                .iter()
                .map(CanonicalPipelineAccountBridgeV1::from)
                .collect(),
        }
    }
}

impl From<&CanonicalPipelineLedgerAccountsV1> for CanonicalPipelineLedgerAccountsBridgeV1 {
    fn from(value: &CanonicalPipelineLedgerAccountsV1) -> Self {
        Self {
            material_version: value.material_version,
            ordered_accounts: value
                .ordered_accounts
                .iter()
                .map(CanonicalPipelineLedgerAccountBridgeV1::from)
                .collect(),
        }
    }
}

impl From<&CanonicalPipelineLedgerAccountV1> for CanonicalPipelineLedgerAccountBridgeV1 {
    fn from(value: &CanonicalPipelineLedgerAccountV1) -> Self {
        Self {
            account_id_hex: encode_hex(&value.account_id),
            balance: value.balance,
        }
    }
}

impl From<&CanonicalPipelineCommitmentExpansionsV1>
    for CanonicalPipelineCommitmentExpansionsBridgeV1
{
    fn from(value: &CanonicalPipelineCommitmentExpansionsV1) -> Self {
        Self {
            transactions: CanonicalPipelineTransactionsCommitmentExpansionBridgeV1::from(
                &value.transactions,
            ),
            outcomes: value
                .outcomes
                .as_ref()
                .map(CanonicalPipelineOutcomesCommitmentExpansionBridgeV1::from),
            batch_context: CanonicalPipelineBatchContextCommitmentExpansionBridgeV1::from(
                &value.batch_context,
            ),
            fee_summary: CanonicalPipelineFeeSummaryCommitmentExpansionBridgeV1::from(
                &value.fee_summary,
            ),
        }
    }
}

impl From<&CanonicalPipelineTransactionsCommitmentExpansionV1>
    for CanonicalPipelineTransactionsCommitmentExpansionBridgeV1
{
    fn from(value: &CanonicalPipelineTransactionsCommitmentExpansionV1) -> Self {
        Self {
            expansion_version: value.expansion_version,
            transactions_commitment_hex: encode_hex(&value.transactions_commitment),
            ordered_transactions: value
                .ordered_transactions
                .iter()
                .map(CanonicalPipelineTransactionBridgeV1::from)
                .collect(),
        }
    }
}

impl From<&CanonicalPipelineOutcomesCommitmentExpansionV1>
    for CanonicalPipelineOutcomesCommitmentExpansionBridgeV1
{
    fn from(value: &CanonicalPipelineOutcomesCommitmentExpansionV1) -> Self {
        Self {
            expansion_version: value.expansion_version,
            outcomes_commitment_hex: encode_hex(&value.outcomes_commitment),
            outcomes: value
                .outcomes
                .iter()
                .map(CanonicalPipelineExecutionOutcomeBridgeV1::from)
                .collect(),
            applied_steps: value
                .applied_steps
                .iter()
                .map(CanonicalPipelineAppliedTransferStepBridgeV1::from)
                .collect(),
        }
    }
}

impl From<&CanonicalPipelineBatchContextCommitmentExpansionV1>
    for CanonicalPipelineBatchContextCommitmentExpansionBridgeV1
{
    fn from(value: &CanonicalPipelineBatchContextCommitmentExpansionV1) -> Self {
        Self {
            expansion_version: value.expansion_version,
            batch_context_commitment_hex: encode_hex(&value.batch_context_commitment),
            transition_binding_version: value.transition_binding_version,
            system_config: CanonicalPipelineExecutionConfigBridgeV1::from(&value.system_config),
            fee_parameters: CanonicalPipelineFeeParametersBridgeV1::from(&value.fee_parameters),
            validity_reference: CanonicalPipelineValidityReferenceBridgeV1::from(
                &value.validity_reference,
            ),
            execution_constants: CanonicalPipelineExecutionConstantsBridgeV1::from(
                &value.execution_constants,
            ),
        }
    }
}

impl From<&CanonicalPipelineFeeSummaryCommitmentExpansionV1>
    for CanonicalPipelineFeeSummaryCommitmentExpansionBridgeV1
{
    fn from(value: &CanonicalPipelineFeeSummaryCommitmentExpansionV1) -> Self {
        Self {
            expansion_version: value.expansion_version,
            fee_summary_commitment_hex: encode_hex(&value.fee_summary_commitment),
            fee_summary: CanonicalPipelineFeeSummaryBridgeV1::from(&value.fee_summary),
        }
    }
}

impl From<&LocalAccountV1> for CanonicalPipelineAccountBridgeV1 {
    fn from(value: &LocalAccountV1) -> Self {
        Self {
            account_id_hex: encode_hex(&value.account_id),
            balance: value.balance,
            nonce: value.nonce,
        }
    }
}

impl From<&aura_l2_execution_v1::TransferTransactionV1> for CanonicalPipelineTransactionBridgeV1 {
    fn from(value: &aura_l2_execution_v1::TransferTransactionV1) -> Self {
        Self {
            tx_version: value.tx_version,
            sender_account_id_hex: encode_hex(&value.sender_account_id),
            recipient_account_id_hex: encode_hex(&value.recipient_account_id),
            sender_nonce: value.sender_nonce,
            amount: value.amount,
        }
    }
}

impl From<&ExecutionOutcomeV1> for CanonicalPipelineExecutionOutcomeBridgeV1 {
    fn from(value: &ExecutionOutcomeV1) -> Self {
        Self {
            tx_index: value.tx_index,
            sender_account_id_hex: encode_hex(&value.sender_account_id),
            consumed_nonce: value.consumed_nonce,
            fee_charged: value.fee_charged,
            touched_accounts_commitment_hex: encode_hex(&value.touched_accounts_commitment),
            operation_result_commitment_hex: encode_hex(&value.operation_result_commitment),
            status: value.status,
        }
    }
}

impl From<&AppliedTransferStepV1> for CanonicalPipelineAppliedTransferStepBridgeV1 {
    fn from(value: &AppliedTransferStepV1) -> Self {
        Self {
            tx_index: value.tx_index,
            sender_account_id_hex: encode_hex(&value.sender_account_id),
            recipient_account_id_hex: encode_hex(&value.recipient_account_id),
            sender_nonce_before: value.sender_nonce_before,
            sender_nonce_after: value.sender_nonce_after,
            sender_balance_before: value.sender_balance_before,
            sender_balance_after: value.sender_balance_after,
            recipient_balance_before: value.recipient_balance_before,
            recipient_balance_after: value.recipient_balance_after,
            amount: value.amount,
            fee_charged: value.fee_charged,
        }
    }
}

impl From<&LocalExecutionConfigV1> for CanonicalPipelineExecutionConfigBridgeV1 {
    fn from(value: &LocalExecutionConfigV1) -> Self {
        Self {
            rollup_id_hex: encode_hex(&value.rollup_id),
            execution_model_version: value.execution_model_version,
            batch_version: value.batch_version,
        }
    }
}

impl From<&CanonicalPipelineFeeParametersExpansionV1> for CanonicalPipelineFeeParametersBridgeV1 {
    fn from(value: &CanonicalPipelineFeeParametersExpansionV1) -> Self {
        Self {
            fee_per_transfer: value.fee_per_transfer,
        }
    }
}

impl From<&CanonicalPipelineValidityReferenceExpansionV1>
    for CanonicalPipelineValidityReferenceBridgeV1
{
    fn from(value: &CanonicalPipelineValidityReferenceExpansionV1) -> Self {
        Self {
            kind: canonical_validity_reference_kind_bridge_str_v1(value.kind).to_string(),
            none_marker: value.none_marker,
        }
    }
}

impl From<&CanonicalPipelineExecutionConstantsExpansionV1>
    for CanonicalPipelineExecutionConstantsBridgeV1
{
    fn from(value: &CanonicalPipelineExecutionConstantsExpansionV1) -> Self {
        Self {
            transfer_tx_version: value.transfer_tx_version,
            transition_binding_version: value.transition_binding_version,
            applied_status: value.applied_status,
        }
    }
}

impl From<&LocalFeeSummaryV1> for CanonicalPipelineFeeSummaryBridgeV1 {
    fn from(value: &LocalFeeSummaryV1) -> Self {
        Self {
            tx_count: value.tx_count,
            total_fee_charged: value.total_fee_charged,
        }
    }
}

impl From<&CanonicalPipelineRequestAuditV1> for CanonicalPipelineRequestBridgeAuditV1 {
    fn from(value: &CanonicalPipelineRequestAuditV1) -> Self {
        Self {
            request_binding_hash_hex: encode_hex(&value.request_binding_hash),
            genesis_accounts_digest_hex: encode_hex(&value.genesis_accounts_digest),
            ledger_accounts_digest_hex: encode_hex(&value.ledger_accounts_digest),
            transactions_digest_hex: encode_hex(&value.transactions_digest),
            rollup_id_hex: encode_hex(&value.rollup_id),
            genesis_account_count: value.genesis_account_count,
            ledger_account_count: value.ledger_account_count,
            ledger_payer_account_id_hex: encode_hex(&value.ledger_payer_account_id),
            ledger_total_supply: value.ledger_total_supply,
            ledger_burned_supply: value.ledger_burned_supply,
            batch_number: value.batch_number,
            tx_count: value.tx_count,
            parent_batch_commitment_hex: encode_hex(&value.parent_batch_commitment),
            tamper_public_inputs: value
                .tamper_public_inputs
                .as_ref()
                .map(CanonicalPipelineTamperBridgeAuditV1::from),
            tamper_proof_binding_digest: value
                .tamper_proof_binding_digest
                .as_ref()
                .map(CanonicalPipelineTamperBridgeAuditV1::from),
            tamper_attestation_stark_public_inputs_digest: value
                .tamper_attestation_stark_public_inputs_digest
                .as_ref()
                .map(CanonicalPipelineTamperBridgeAuditV1::from),
            tamper_attestation_stark_proof_bytes: value
                .tamper_attestation_stark_proof_bytes
                .as_ref()
                .map(CanonicalPipelineTamperBridgeAuditV1::from),
        }
    }
}

impl From<&CanonicalPipelineTamperAuditV1> for CanonicalPipelineTamperBridgeAuditV1 {
    fn from(value: &CanonicalPipelineTamperAuditV1) -> Self {
        Self {
            byte_offset: value.byte_offset,
            xor_with: value.xor_with,
        }
    }
}

impl From<&CanonicalPipelineStageOutcomesV1> for CanonicalPipelineStageOutcomesBridgeV1 {
    fn from(value: &CanonicalPipelineStageOutcomesV1) -> Self {
        Self {
            execution_status: canonical_execution_status_bridge_str_v1(value.execution_status)
                .to_string(),
            verification_status: canonical_verification_status_bridge_str_v1(
                value.verification_status,
            )
            .to_string(),
            settlement_status: canonical_settlement_status_bridge_str_v1(value.settlement_status)
                .to_string(),
        }
    }
}

impl From<&CanonicalPipelinePublicInputsAuditV1> for CanonicalPipelinePublicInputsBridgeAuditV1 {
    fn from(value: &CanonicalPipelinePublicInputsAuditV1) -> Self {
        Self {
            decode_status: canonical_public_inputs_decode_status_bridge_str_v1(value.decode_status)
                .to_string(),
            public_input_bytes_hex: encode_hex(&value.public_input_bytes),
            public_inputs_hash_hex: encode_hex(&value.public_inputs_hash),
            transition_binding_hash_hex: encode_hex(&value.transition_binding_hash),
            request_summary_consistency: value
                .request_summary_consistency
                .as_ref()
                .map(CanonicalPipelineRequestSummaryConsistencyBridgeAuditV1::from),
            decoded_public_inputs: value
                .decoded_public_inputs
                .as_ref()
                .map(CanonicalPipelineDecodedPublicInputsBridgeV1::from),
        }
    }
}

impl From<&CanonicalPipelineRequestSummaryConsistencyAuditV1>
    for CanonicalPipelineRequestSummaryConsistencyBridgeAuditV1
{
    fn from(value: &CanonicalPipelineRequestSummaryConsistencyAuditV1) -> Self {
        Self {
            transition_binding_version_supported: value.transition_binding_version_supported,
            execution_model_version_supported: value.execution_model_version_supported,
            batch_version_supported: value.batch_version_supported,
            rollup_id_matches_request_audit: value.rollup_id_matches_request_audit,
            batch_number_matches_request_audit: value.batch_number_matches_request_audit,
            tx_count_matches_request_audit: value.tx_count_matches_request_audit,
            parent_batch_commitment_matches_request_audit: value
                .parent_batch_commitment_matches_request_audit,
            fee_summary_commitment_matches_expansion: value
                .fee_summary_commitment_matches_expansion,
            pre_state_root_matches_report: value.pre_state_root_matches_report,
            post_state_root_matches_report: value.post_state_root_matches_report,
            transactions_commitment_matches_expansion: value
                .transactions_commitment_matches_expansion,
            outcomes_commitment_matches_expansion: value.outcomes_commitment_matches_expansion,
            batch_context_commitment_matches_expansion: value
                .batch_context_commitment_matches_expansion,
            decoded_bytes_round_trip: value.decoded_bytes_round_trip,
            all_fields_match: value.all_fields_match,
        }
    }
}

impl From<&aura_l2_local_chain_v0::CanonicalPipelineDecodedPublicInputsV1>
    for CanonicalPipelineDecodedPublicInputsBridgeV1
{
    fn from(value: &aura_l2_local_chain_v0::CanonicalPipelineDecodedPublicInputsV1) -> Self {
        Self {
            transition_binding_version: value.transition_binding_version,
            rollup_id_hex: encode_hex(&value.rollup_id),
            execution_model_version: value.execution_model_version,
            batch_version: value.batch_version,
            batch_number: value.batch_number,
            parent_batch_commitment_hex: encode_hex(&value.parent_batch_commitment),
            tx_count: value.tx_count,
            fee_summary_commitment_hex: encode_hex(&value.fee_summary_commitment),
            pre_state_root_hex: encode_hex(&value.pre_state_root),
            post_state_root_hex: encode_hex(&value.post_state_root),
            transactions_commitment_hex: encode_hex(&value.transactions_commitment),
            outcomes_commitment_hex: encode_hex(&value.outcomes_commitment),
            batch_context_commitment_hex: encode_hex(&value.batch_context_commitment),
        }
    }
}

impl From<&CanonicalPipelineProofArtifactAuditV1> for CanonicalPipelineProofArtifactBridgeAuditV1 {
    fn from(value: &CanonicalPipelineProofArtifactAuditV1) -> Self {
        Self {
            prover_kind: value.prover_kind,
            proof_version: value.proof_version,
            public_inputs_hash_hex: encode_hex(&value.public_inputs_hash),
            trace_digest_hex: encode_hex(&value.trace_digest),
            trace_layout_digest_hex: encode_hex(&value.trace_layout_digest),
            proof_binding_digest_hex: encode_hex(&value.proof_binding_digest),
            proof_binding_input_kind: canonical_proof_binding_input_kind_bridge_str_v1(
                value.proof_binding_input_kind,
            )
            .to_string(),
            proof_binding_input_digest_hex: encode_hex(&value.proof_binding_input_digest),
            consistency: CanonicalPipelineProofArtifactConsistencyBridgeAuditV1::from(
                &value.consistency,
            ),
        }
    }
}

impl From<&CanonicalPipelineProofArtifactConsistencyAuditV1>
    for CanonicalPipelineProofArtifactConsistencyBridgeAuditV1
{
    fn from(value: &CanonicalPipelineProofArtifactConsistencyAuditV1) -> Self {
        Self {
            public_inputs_hash_matches_report: value.public_inputs_hash_matches_report,
            prover_kind_matches_proof_system: value.prover_kind_matches_proof_system,
            proof_version_supported: value.proof_version_supported,
            proof_binding_input_kind_matches_proof_system: value
                .proof_binding_input_kind_matches_proof_system,
            recomputed_proof_binding_digest_hex: encode_hex(&value.recomputed_proof_binding_digest),
            proof_binding_digest_matches_recomputed: value.proof_binding_digest_matches_recomputed,
            all_fields_match: value.all_fields_match,
        }
    }
}

impl From<&ProofVectorReportV1> for ProofVectorBridgeReportV1 {
    fn from(value: &ProofVectorReportV1) -> Self {
        Self {
            fixture_name: value.fixture_name.clone(),
            proof_system: proof_system_bridge_str_v1(value.proof_system).to_string(),
            expected_result: scenario_result_bridge_str_v1(value.expected_result).to_string(),
            actual_result: scenario_result_bridge_str_v1(value.actual_result).to_string(),
            pre_state_root_hex: encode_hex(&value.pre_state_root),
            post_state_root_hex: value.post_state_root.map(|root| encode_hex(&root)),
            transition_binding_hash_hex: encode_hex(&value.transition_binding_hash),
            public_inputs_hash_hex: encode_hex(&value.public_inputs_hash),
            trace_digest_hex: encode_hex(&value.trace_digest),
            trace_layout_digest_hex: encode_hex(&value.trace_layout_digest),
            proof_binding_digest_hex: encode_hex(&value.proof_binding_digest),
        }
    }
}

impl From<&ProofVectorFixtureV1> for BuildProofVectorBridgeReportV1 {
    fn from(value: &ProofVectorFixtureV1) -> Self {
        Self {
            fixture_name: value.fixture_name.clone(),
            proof_system: proof_system_bridge_str_v1(value.proof_system).to_string(),
            expected_result: scenario_result_fixture_str_v1(value.expected_result).to_string(),
            transition_binding_hash_hex: encode_hex(
                &value.expected_public_inputs.transition_binding_hash,
            ),
            proof_binding_digest_hex: encode_hex(
                &value.canonical_stark_proof_artifact.proof_binding_digest,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_canonical_pipeline_bridge_json_v1, parse_cli_v1, render_canonical_pipeline_report_v1,
        render_proof_vector_report_v1, render_scenario_report_v1, CliCommandV1, OutputFormatV1,
    };
    use aura_l2_local_chain_v0::{
        encode_hex, run_canonical_pipeline_from_path, ProofSystemSelectionV1, ProofVectorReportV1,
        ScenarioReportV1, ScenarioResultV1, CANONICAL_PIPELINE_ID_V1,
    };
    use serde_json::Value;
    use std::path::PathBuf;

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

    fn accepted_canonical_pipeline_report() -> aura_l2_local_chain_v0::CanonicalPipelineReportV1 {
        run_canonical_pipeline_from_path(accepted_canonical_pipeline_request_path()).unwrap()
    }

    #[test]
    fn cli_parser_accepts_json_output_prefix() {
        let cli = parse_cli_v1([
            "--output".to_string(),
            "json".to_string(),
            "run-canonical-pipeline".to_string(),
            "fixtures/l2_canonical_pipeline_v1/accepted_transfer_request.json".to_string(),
        ])
        .unwrap();

        assert_eq!(cli.output_format, OutputFormatV1::Json);
        assert_eq!(
            cli.command,
            CliCommandV1::RunCanonicalPipeline {
                request_path: PathBuf::from(
                    "fixtures/l2_canonical_pipeline_v1/accepted_transfer_request.json",
                ),
                head_state_path: None,
                stateless: true,
            }
        );
    }

    #[test]
    fn cli_parser_rejects_unknown_output_format() {
        let error = parse_cli_v1([
            "--output".to_string(),
            "yaml".to_string(),
            "run-scenario".to_string(),
            "fixtures/l2_local_v1/accepted_transition_example.json".to_string(),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("unsupported output format"));
    }

    #[test]
    fn scenario_json_output_is_versioned_and_hex_encoded() {
        let rendered = render_scenario_report_v1(
            OutputFormatV1::Json,
            "run-scenario",
            &ScenarioReportV1 {
                fixture_name: "accepted_transition_example".to_string(),
                expected_result: ScenarioResultV1::Accepted,
                actual_result: ScenarioResultV1::Accepted,
                pre_state_root: [0x11; 32],
                post_state_root: Some([0x22; 32]),
                transition_binding_hash: Some([0x33; 32]),
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["bridge_schema_version"], 1);
        assert_eq!(parsed["report_kind"], "scenario_report_v1");
        assert_eq!(parsed["command"], "run-scenario");
        assert_eq!(parsed["report"]["expected_result"], "Accepted");
        assert_eq!(parsed["report"]["pre_state_root_hex"], "11".repeat(32));
        assert_eq!(parsed["report"]["post_state_root_hex"], "22".repeat(32));
        assert_eq!(
            parsed["report"]["transition_binding_hash_hex"],
            "33".repeat(32)
        );
    }

    #[test]
    fn proof_vector_json_output_is_versioned_and_hex_encoded() {
        let rendered = render_proof_vector_report_v1(
            OutputFormatV1::Json,
            "verify-proof-vector",
            &ProofVectorReportV1 {
                fixture_name: "minimal_single_transfer_proof".to_string(),
                proof_system: ProofSystemSelectionV1::Stark,
                expected_result: ScenarioResultV1::Accepted,
                actual_result: ScenarioResultV1::Accepted,
                pre_state_root: [0x44; 32],
                post_state_root: Some([0x55; 32]),
                transition_binding_hash: [0x66; 32],
                public_inputs_hash: [0x77; 32],
                trace_digest: [0x88; 32],
                trace_layout_digest: [0x99; 32],
                proof_binding_digest: [0xaa; 32],
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["bridge_schema_version"], 1);
        assert_eq!(parsed["report_kind"], "proof_vector_report_v1");
        assert_eq!(parsed["command"], "verify-proof-vector");
        assert_eq!(parsed["report"]["proof_system"], "stark");
        assert_eq!(parsed["report"]["pre_state_root_hex"], "44".repeat(32));
        assert_eq!(parsed["report"]["trace_layout_digest_hex"], "99".repeat(32));
        assert_eq!(
            parsed["report"]["proof_binding_digest_hex"],
            "aa".repeat(32)
        );
    }

    #[test]
    fn canonical_pipeline_json_output_is_versioned_and_self_describing() {
        let report = accepted_canonical_pipeline_report();
        let rendered = render_canonical_pipeline_report_v1(
            OutputFormatV1::Json,
            "run-canonical-pipeline",
            &report,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["bridge_schema_version"], 1);
        assert_eq!(parsed["report_kind"], "canonical_pipeline_report_v1");
        assert_eq!(parsed["command"], "run-canonical-pipeline");
        assert_eq!(
            parsed["report"]["pipeline_schema_version"],
            report.pipeline_schema_version
        );
        assert_eq!(parsed["report"]["pipeline_id"], CANONICAL_PIPELINE_ID_V1);
        assert_eq!(parsed["report"]["proof_system"], "stark");
        assert_eq!(parsed["report"]["burn_summary"]["burn_policy_version"], 1);
        assert_eq!(
            parsed["report"]["burn_summary"]["request_kind"],
            "execution"
        );
        assert_eq!(parsed["report"]["burn_summary"]["computed_burn_units"], 49);
        assert_eq!(parsed["report"]["burn_summary"]["consumed_burn_units"], 49);
        assert_eq!(
            parsed["report"]["accounting_summary"]["declared_fee_units"],
            49
        );
        assert_eq!(
            parsed["report"]["ledger_summary"]["ledger_policy_version"],
            1
        );
        assert_eq!(parsed["report"]["ledger_summary"]["total_supply"], 1250);
        assert_eq!(
            parsed["report"]["ledger_summary"]["burned_supply_after"],
            49
        );
        assert_eq!(
            parsed["report"]["head_transition_summary"]["settlement_head_version"],
            1
        );
        assert_eq!(
            parsed["report"]["wallet_binding_summary"]["wallet_binding_version"],
            1
        );
        assert_eq!(
            parsed["report"]["token_anchor_summary"]["anchor_verification_status"],
            "accepted"
        );
        assert_eq!(parsed["report"]["ledger_accounts"]["material_version"], 1);
        assert_eq!(
            parsed["report"]["status_explanation"]["truth_artifact_kind"],
            "execution_report"
        );
        assert_eq!(
            parsed["report"]["status_explanation"]["failure_reason_code"],
            "none"
        );
        assert_eq!(
            parsed["report"]["pre_state_root_hex"],
            encode_hex(&report.pre_state_root)
        );
        assert_eq!(
            parsed["report"]["request_audit"]["request_binding_hash_hex"],
            encode_hex(&report.request_audit.request_binding_hash)
        );
        assert_eq!(
            parsed["report"]["request_audit"]["genesis_accounts_digest_hex"],
            encode_hex(&report.request_audit.genesis_accounts_digest)
        );
        assert_eq!(
            parsed["report"]["genesis_accounts"]["ordered_accounts"]
                .as_array()
                .unwrap()
                .len(),
            report.genesis_accounts.ordered_accounts.len()
        );
        assert_eq!(
            parsed["report"]["public_inputs"]["public_input_bytes_hex"],
            encode_hex(
                &report
                    .public_inputs
                    .as_ref()
                    .unwrap()
                    .public_input_bytes
                    .as_slice()
            )
        );
        assert_eq!(
            parsed["report"]["public_inputs"]["request_summary_consistency"]["all_fields_match"],
            true
        );
        assert_eq!(
            parsed["report"]["commitment_expansions"]["transactions"]
                ["transactions_commitment_hex"],
            encode_hex(
                &report
                    .commitment_expansions
                    .transactions
                    .transactions_commitment
            )
        );
        assert_eq!(
            parsed["report"]["commitment_expansions"]["fee_summary"]["fee_summary_commitment_hex"],
            encode_hex(
                &report
                    .commitment_expansions
                    .fee_summary
                    .fee_summary_commitment
            )
        );
        assert_eq!(
            parsed["report"]["proof_artifact"]["proof_binding_digest_hex"],
            encode_hex(&report.proof_artifact.as_ref().unwrap().proof_binding_digest)
        );
        assert_eq!(
            parsed["report"]["proof_artifact"]["consistency"]
                ["recomputed_proof_binding_digest_hex"],
            encode_hex(
                &report
                    .proof_artifact
                    .as_ref()
                    .unwrap()
                    .consistency
                    .recomputed_proof_binding_digest
            )
        );
    }

    #[test]
    fn canonical_pipeline_json_output_round_trips_through_the_strict_bridge_schema() {
        let report = accepted_canonical_pipeline_report();
        let rendered = render_canonical_pipeline_report_v1(
            OutputFormatV1::Json,
            "run-canonical-pipeline",
            &report,
        )
        .unwrap();
        let reparsed = parse_canonical_pipeline_bridge_json_v1(&rendered).unwrap();
        assert_eq!(reparsed, report);
    }

    #[test]
    fn strict_bridge_schema_rejects_unexpected_nested_canonical_pipeline_fields() {
        let report = accepted_canonical_pipeline_report();
        let rendered = render_canonical_pipeline_report_v1(
            OutputFormatV1::Json,
            "run-canonical-pipeline",
            &report,
        )
        .unwrap();
        let mut value: Value = serde_json::from_str(&rendered).unwrap();
        value["report"]["commitment_expansions"]["transactions"]["unexpected_field"] =
            Value::Bool(true);

        let error =
            parse_canonical_pipeline_bridge_json_v1(&serde_json::to_string(&value).unwrap())
                .unwrap_err();
        assert!(error.to_string().contains("unexpected_field"));
    }
}
