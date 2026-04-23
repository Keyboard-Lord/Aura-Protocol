import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const textEncoder = new TextEncoder();

export const HASH_LEN_V0 = 32;
export const PUBLIC_INPUT_SCHEMA_LEN_V0 = 284;
export const TRANSFER_TX_VERSION_V0 = 1;
export const EXECUTION_MODEL_VERSION_V0 = 1;
export const BATCH_VERSION_V0 = 1;
export const TRANSITION_BINDING_VERSION_V0 = 1;
export const EXECUTION_OUTCOME_STATUS_APPLIED_V0 = 1;
export const ZERO_FEE_PER_TRANSFER_V0 = 0n;
export const ZERO32_V0 = new Uint8Array(HASH_LEN_V0);
const LOCAL_PROVER_KIND_MOCK_V0 = 1;
const LOCAL_PROVER_KIND_STARK_V0 = 2;
const LOCAL_MOCK_PROOF_VERSION_V0 = 1;
const LOCAL_STARK_PROOF_VERSION_V0 = 1;
const GENESIS_FIXTURE_NAME_V0 = "genesis_state";
const LOCAL_CHAIN_GENESIS_FIXTURE_SCHEMA_V0 = 1;
const LOCAL_CHAIN_SCENARIO_FIXTURE_SCHEMA_V0 = 1;
const LOCAL_CHAIN_PROOF_VECTOR_FIXTURE_SCHEMA_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0 = "aura_local_pipeline_v1";
export const LOCAL_CHAIN_CANONICAL_ECONOMIC_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_BURN_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_ACCOUNTING_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_ATTESTATION_SCHEMA_VERSION_V0 = 2;
export const LOCAL_CHAIN_CANONICAL_ATTESTATION_NORMALIZATION_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_LEDGER_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_SETTLEMENT_HEAD_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_WALLET_BINDING_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_TOKEN_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_PROVENANCE_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_ATTESTATION_PROOF_MOCK_POLICY_VERSION_V0 = 1;
export const LOCAL_CHAIN_CANONICAL_STARK_POLICY_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_LEDGER_ACCOUNTS_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_TRANSACTIONS_EXPANSION_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_OUTCOMES_EXPANSION_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_BATCH_CONTEXT_EXPANSION_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_PIPELINE_FEE_SUMMARY_EXPANSION_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_HEAD_STATE_FILE_VERSION_V0 = 1;
const LOCAL_CHAIN_CANONICAL_BURN_BASE_UNITS_V0 = 10n;
const LOCAL_CHAIN_CANONICAL_BURN_EXECUTION_KIND_UNITS_V0 = 5n;
const LOCAL_CHAIN_CANONICAL_BURN_ATTESTATION_KIND_UNITS_V0 = 2n;
const LOCAL_CHAIN_CANONICAL_BURN_STARK_UNITS_V0 = 3n;
const LOCAL_CHAIN_CANONICAL_BURN_MOCK_UNITS_V0 = 1n;
const LOCAL_CHAIN_CANONICAL_BURN_TRANSACTION_UNITS_V0 = 4n;
const LOCAL_CHAIN_CANONICAL_BURN_SIZE_CHUNK_BYTES_V0 = 32n;
const ED25519_SPKI_PREFIX_V0 = bytesFromHexRawV0("302a300506032b6570032100");

const AURA_L2_LOCAL_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_ACCOUNT_LEAF_V1",
);
const AURA_L2_LOCAL_STATE_ROOT_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_STATE_ROOT_V1",
);
const AURA_L2_LOCAL_STATE_EMPTY_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_STATE_EMPTY_V1",
);
const AURA_L2_LOCAL_TRANSFER_TX_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_TRANSFER_TX_V1",
);
const AURA_L2_LOCAL_TOUCHED_ACCOUNTS_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_TOUCHED_ACCOUNTS_V1",
);
const AURA_L2_LOCAL_TRANSFER_RESULT_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_TRANSFER_RESULT_V1",
);
const AURA_L2_LOCAL_SYSTEM_CONFIG_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_SYSTEM_CONFIG_V1",
);
const AURA_L2_LOCAL_FEE_PARAMETERS_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_FEE_PARAMETERS_V1",
);
const AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_V1",
);
const AURA_L2_LOCAL_EXECUTION_CONSTANTS_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_EXECUTION_CONSTANTS_V1",
);
const AURA_L2_LOCAL_FEE_SUMMARY_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_FEE_SUMMARY_V1",
);
const D_TX_ENTRY_V1 = textEncoder.encode("AURA_L2_TX_ENTRY_V1");
const D_TX_LIST_V1 = textEncoder.encode("AURA_L2_TX_LIST_V1");
const D_OUTCOME_V1 = textEncoder.encode("AURA_L2_EXECUTION_OUTCOME_V1");
const D_OUTCOME_LIST_V1 = textEncoder.encode("AURA_L2_OUTCOME_LIST_V1");
const D_CONTEXT_V1 = textEncoder.encode("AURA_L2_BATCH_CONTEXT_V1");
const D_BINDING_V1 = textEncoder.encode("AURA_L2_TRANSITION_BINDING_V1");
const D_CANONICAL_PIPELINE_REQUEST_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_REQUEST_V1",
);
const D_CANONICAL_PIPELINE_BURN_METERING_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_BURN_METERING_V1",
);
const D_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_V1",
);
const D_CANONICAL_PIPELINE_LEDGER_ACCOUNTS_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_LEDGER_ACCOUNTS_V1",
);
const D_CANONICAL_PIPELINE_LEDGER_STATE_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_LEDGER_STATE_V1",
);
const D_CANONICAL_PIPELINE_TRANSACTIONS_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_TRANSACTIONS_V1",
);
const D_CANONICAL_PIPELINE_ATTESTATION_CLAIM_V2 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_ATTESTATION_CLAIM_V2",
);
const D_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_DIGEST_V2 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_V2",
);
const D_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_ROOT_V2 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_ROOT_V2",
);
const D_CANONICAL_PIPELINE_PROVENANCE_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_PROVENANCE_V1",
);
const D_CANONICAL_PIPELINE_PROVENANCE_ITEM_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_PROVENANCE_ITEM_V1",
);
const D_CANONICAL_PIPELINE_ATTESTATION_TUPLE_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_ATTESTATION_TUPLE_V1",
);
const D_CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_MESSAGE_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_V1",
);
const D_CANONICAL_PIPELINE_HEAD_TRANSITION_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_HEAD_TRANSITION_V1",
);
const D_CANONICAL_PIPELINE_HEAD_HASH_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_HEAD_HASH_V1",
);
const D_CANONICAL_PIPELINE_REPORT_DIGEST_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_REPORT_DIGEST_V1",
);
const D_CANONICAL_PIPELINE_WALLET_BINDING_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_WALLET_BINDING_V1",
);
const D_CANONICAL_PIPELINE_TOKEN_ANCHOR_V1 = textEncoder.encode(
  "AURA_L2_CANONICAL_PIPELINE_TOKEN_ANCHOR_V1",
);
const AURA_L2_LOCAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR_V1 = textEncoder.encode(
  "AURA_L2_LOCAL_STARK_PROOF_BINDING_V1",
);
export const CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V0 = bytesFromHexRawV0(
  "8a2ce870aa1ef47b5e78116dc9591363d1224932893d445719a1be2df732710f",
);

export const ProofSystemV0 = {
  Mock: "mock",
  Stark: "stark",
} as const;

export type ProofSystemV0 = (typeof ProofSystemV0)[keyof typeof ProofSystemV0];

export interface AccountV0 {
  accountId: Uint8Array;
  balance: bigint;
  nonce: bigint;
}

export interface TransferTxV0 {
  txVersion: number;
  senderAccountId: Uint8Array;
  recipientAccountId: Uint8Array;
  senderNonce: bigint;
  amount: bigint;
}

export interface BatchV0 {
  batchNumber: bigint;
  parentBatchCommitment: Uint8Array;
  transactions: TransferTxV0[];
}

export interface ExecutionConfigV0 {
  rollupId: Uint8Array;
  executionModelVersion: number;
  batchVersion: number;
}

export interface BatchContextV0 {
  systemConfigCommitment: Uint8Array;
  feeParametersCommitment: Uint8Array;
  validityReferenceCommitment: Uint8Array;
  executionConstantsCommitment: Uint8Array;
}

export interface FeeSummaryV0 {
  txCount: bigint;
  totalFeeCharged: bigint;
}

export interface ExecutionOutcomeV0 {
  txIndex: bigint;
  senderAccountId: Uint8Array;
  consumedNonce: bigint;
  feeCharged: bigint;
  touchedAccountsCommitment: Uint8Array;
  operationResultCommitment: Uint8Array;
  status: number;
}

export interface AppliedTransferStepV0 {
  txIndex: bigint;
  senderAccountId: Uint8Array;
  recipientAccountId: Uint8Array;
  senderNonceBefore: bigint;
  senderNonceAfter: bigint;
  senderBalanceBefore: bigint;
  senderBalanceAfter: bigint;
  recipientBalanceBefore: bigint;
  recipientBalanceAfter: bigint;
  amount: bigint;
  feeCharged: bigint;
}

export interface TransitionV0 {
  config: ExecutionConfigV0;
  batchNumber: bigint;
  parentBatchCommitment: Uint8Array;
  txCount: bigint;
  preState: StateV0;
  postState: StateV0;
  preStateRoot: Uint8Array;
  postStateRoot: Uint8Array;
  transactions: TransferTxV0[];
  transactionBytes: Uint8Array[];
  transactionsCommitment: Uint8Array;
  outcomes: ExecutionOutcomeV0[];
  outcomeBytes: Uint8Array[];
  outcomesCommitment: Uint8Array;
  batchContext: BatchContextV0;
  contextBytes: Uint8Array;
  batchContextCommitment: Uint8Array;
  feeSummary: FeeSummaryV0;
  feeSummaryBytes: Uint8Array;
  feeSummaryCommitment: Uint8Array;
  appliedSteps: AppliedTransferStepV0[];
}

export interface TransitionClaimV0 {
  preStateRoot: Uint8Array;
  postStateRoot: Uint8Array;
  transactionsCommitment: Uint8Array;
  outcomesCommitment: Uint8Array;
  batchContextCommitment: Uint8Array;
}

export interface PublicInputsV0 {
  transitionBindingVersion: number;
  rollupId: Uint8Array;
  executionModelVersion: number;
  batchVersion: number;
  batchNumber: bigint;
  parentBatchCommitment: Uint8Array;
  txCount: bigint;
  feeSummaryCommitment: Uint8Array;
  preStateRoot: Uint8Array;
  postStateRoot: Uint8Array;
  transactionsCommitment: Uint8Array;
  outcomesCommitment: Uint8Array;
  batchContextCommitment: Uint8Array;
}

export interface TransitionArtifactsV0 {
  transition: TransitionV0;
  publicInputs: PublicInputsV0;
  publicInputBytes: Uint8Array;
  transitionClaim: TransitionClaimV0;
  transitionBindingHash: Uint8Array;
}

export interface MockProofArtifactV0 {
  proofSystem: typeof ProofSystemV0.Mock;
  backend: "rust-local-chain";
  artifactBytesExposed: false;
}

export interface StarkProofArtifactV0 {
  proofSystem: typeof ProofSystemV0.Stark;
  backend: "rust-local-chain";
  artifactBytesExposed: false;
}

export type ProofArtifactV0 = MockProofArtifactV0 | StarkProofArtifactV0;

export const ScenarioResultV0 = {
  Accepted: "Accepted",
  ExecutionRejected: "ExecutionRejected",
  VerificationRejected: "VerificationRejected",
  SettlementRejected: "SettlementRejected",
} as const;

export type ScenarioResultV0 =
  (typeof ScenarioResultV0)[keyof typeof ScenarioResultV0];

export interface ScenarioReportV0 {
  fixtureName: string;
  expectedResult: ScenarioResultV0;
  actualResult: ScenarioResultV0;
  preStateRoot: Uint8Array;
  postStateRoot: Uint8Array | null;
  transitionBindingHash: Uint8Array | null;
}

export const ProofVectorTamperTargetV0 = {
  ProofBytes: "PROOF_BYTES",
  ProofBindingDigest: "PROOF_BINDING_DIGEST",
} as const;

export type ProofVectorTamperTargetV0 =
  (typeof ProofVectorTamperTargetV0)[keyof typeof ProofVectorTamperTargetV0];

export interface ProofVectorGenesisV0 {
  rollupId: Uint8Array;
  accounts: AccountV0[];
}

export interface ProofVectorBatchV0 {
  batchNumber: bigint;
  parentBatchCommitment: Uint8Array;
  transactions: TransferTxV0[];
}

export interface ProofVectorExpectedOutcomeV0 {
  txIndex: bigint;
  senderAccountId: Uint8Array;
  consumedNonce: bigint;
  feeCharged: bigint;
  touchedAccountsCommitment: Uint8Array;
  operationResultCommitment: Uint8Array;
  status: number;
}

export interface ProofVectorExpectedTransitionV0 {
  preStateRoot: Uint8Array;
  postStateRoot: Uint8Array;
  transactionsCommitment: Uint8Array;
  outcomesCommitment: Uint8Array;
  batchContextCommitment: Uint8Array;
  feeSummaryCommitment: Uint8Array;
  postStateAccounts: AccountV0[];
  outcomes: ProofVectorExpectedOutcomeV0[];
}

export interface ProofVectorExpectedPublicInputsV0 extends PublicInputsV0 {
  publicInputBytes: Uint8Array;
  transitionBindingHash: Uint8Array;
}

export interface ProofVectorCanonicalStarkArtifactV0 {
  proverKind: number;
  proofVersion: number;
  publicInputsHash: Uint8Array;
  traceDigest: Uint8Array;
  traceLayoutDigest: Uint8Array;
  proofBindingDigest: Uint8Array;
  proofBytes: Uint8Array;
}

export interface ProofVectorTamperV0 {
  target: ProofVectorTamperTargetV0;
  byteOffset: number;
  xorWith: number;
}

export interface ProofVectorFixtureV0 {
  fixtureName: string;
  proofSystem: ProofSystemV0;
  genesis: ProofVectorGenesisV0;
  batch: ProofVectorBatchV0;
  expectedTransition: ProofVectorExpectedTransitionV0;
  expectedPublicInputs: ProofVectorExpectedPublicInputsV0;
  canonicalStarkProofArtifact: ProofVectorCanonicalStarkArtifactV0;
  proofTamper: ProofVectorTamperV0 | null;
  expectedResult: ScenarioResultV0;
}

export interface ProofVectorReportV0 {
  fixtureName: string;
  proofSystem: ProofSystemV0;
  expectedResult: ScenarioResultV0;
  actualResult: ScenarioResultV0;
  preStateRoot: Uint8Array;
  postStateRoot: Uint8Array | null;
  transitionBindingHash: Uint8Array;
  publicInputsHash: Uint8Array;
  traceDigest: Uint8Array;
  traceLayoutDigest: Uint8Array;
  proofBindingDigest: Uint8Array;
}

export interface CanonicalPipelineRequestV0 {
  pipelineSchemaVersion: number;
  pipelineId: string;
  fixtureName: string;
  proofSystem: ProofSystemV0;
  economic: CanonicalPipelineEconomicPolicyV0;
  accounting: CanonicalPipelineAccountingPolicyV0;
  ledger: CanonicalPipelineLedgerPolicyV0;
  head: CanonicalPipelineSettlementHeadRequestV0;
  walletBinding: CanonicalPipelineWalletBindingV0;
  tokenAnchor: CanonicalPipelineTokenAnchorV0;
  attestation: CanonicalPipelineAttestationRequestV0 | null;
  state: StateV0;
  rollupId: Uint8Array;
  batch: BatchV0;
  expectedResult: ScenarioResultV0;
  tamperPublicInputs: { byteOffset: number; xorWith: number } | null;
  tamperProofBindingDigest: { byteOffset: number; xorWith: number } | null;
}

export const CanonicalPipelineRequestKindV0 = {
  Execution: "execution",
  Attestation: "attestation",
} as const;

export type CanonicalPipelineRequestKindV0 =
  (typeof CanonicalPipelineRequestKindV0)[keyof typeof CanonicalPipelineRequestKindV0];

export const CanonicalPipelineBurnIntentV0 = {
  CanonicalReport: "canonical_report",
} as const;

export type CanonicalPipelineBurnIntentV0 =
  (typeof CanonicalPipelineBurnIntentV0)[keyof typeof CanonicalPipelineBurnIntentV0];

export interface CanonicalPipelineEconomicPolicyV0 {
  economicPolicyVersion: number;
  requestKind: CanonicalPipelineRequestKindV0;
  burnIntent: CanonicalPipelineBurnIntentV0;
  declaredFeeUnits: bigint;
}

export const CanonicalPipelinePaymentIntentV0 = {
  BurnToProduceCanonicalTruth: "burn_to_produce_canonical_truth",
} as const;

export type CanonicalPipelinePaymentIntentV0 =
  (typeof CanonicalPipelinePaymentIntentV0)[keyof typeof CanonicalPipelinePaymentIntentV0];

export const CanonicalPipelineSettlementIntentV0 = {
  RecordCanonicalOutcome: "record_canonical_outcome",
} as const;

export type CanonicalPipelineSettlementIntentV0 =
  (typeof CanonicalPipelineSettlementIntentV0)[keyof typeof CanonicalPipelineSettlementIntentV0];

export interface CanonicalPipelineAccountingPolicyV0 {
  accountingPolicyVersion: number;
  paymentIntent: CanonicalPipelinePaymentIntentV0;
  settlementIntent: CanonicalPipelineSettlementIntentV0;
}

export interface CanonicalPipelineLedgerAccountV0 {
  accountId: Uint8Array;
  balance: bigint;
}

export interface CanonicalPipelineLedgerPolicyV0 {
  ledgerPolicyVersion: number;
  payerAccountId: Uint8Array;
  totalSupply: bigint;
  burnedSupply: bigint;
  accounts: CanonicalPipelineLedgerAccountV0[];
}

export interface CanonicalPipelineSettlementHeadRequestV0 {
  settlementHeadVersion: number;
  previousHeadHash: Uint8Array;
  headSequenceNumber: bigint;
}

export interface CanonicalPipelineWalletBindingV0 {
  walletBindingVersion: number;
  accountId: Uint8Array;
  walletAddress: string;
}

export interface CanonicalPipelineExternalBalanceReferenceV0 {
  referenceId: string;
  observedBalance: bigint | null;
  observedSlot: bigint | null;
  connected: boolean;
}

export const CanonicalPipelineNetworkModeV0 = {
  Local: "local",
  Bridged: "bridged",
} as const;

export type CanonicalPipelineNetworkModeV0 =
  (typeof CanonicalPipelineNetworkModeV0)[keyof typeof CanonicalPipelineNetworkModeV0];

export const CanonicalPipelineSettlementAnchorTypeV0 = {
  Local: "local",
  Simulated: "simulated",
  External: "external",
} as const;

export type CanonicalPipelineSettlementAnchorTypeV0 =
  (typeof CanonicalPipelineSettlementAnchorTypeV0)[keyof typeof CanonicalPipelineSettlementAnchorTypeV0];

export interface CanonicalPipelineTokenAnchorV0 {
  tokenPolicyVersion: number;
  networkMode: CanonicalPipelineNetworkModeV0;
  settlementAnchorType: CanonicalPipelineSettlementAnchorTypeV0;
  externalBalanceReference: CanonicalPipelineExternalBalanceReferenceV0 | null;
  enforceExternalMatch: boolean;
  expectedExternalBalance: bigint | null;
}

export const CanonicalPipelineAttestationScopeV0 = {
  ClaimConsistencyWithProvidedEvidenceOnly:
    "claim_consistency_with_provided_evidence_only",
} as const;

export type CanonicalPipelineAttestationScopeV0 =
  (typeof CanonicalPipelineAttestationScopeV0)[keyof typeof CanonicalPipelineAttestationScopeV0];

export const CanonicalPipelineAttestationClaimKindV0 = {
  EvidenceRootDigest: "evidence_root_digest",
  NormalizedEvidenceDigest: "normalized_evidence_digest",
  NormalizedTextContainsUtf8: "normalized_text_contains_utf8",
  NormalizedJsonFieldEqualsUtf8: "normalized_json_field_equals_utf8",
} as const;

export type CanonicalPipelineAttestationClaimKindV0 =
  (typeof CanonicalPipelineAttestationClaimKindV0)[keyof typeof CanonicalPipelineAttestationClaimKindV0];

export const CanonicalPipelineAttestationEvidenceKindV0 = {
  InlineUtf8: "inline_utf8",
  InlineJsonUtf8: "inline_json_utf8",
} as const;

export type CanonicalPipelineAttestationEvidenceKindV0 =
  (typeof CanonicalPipelineAttestationEvidenceKindV0)[keyof typeof CanonicalPipelineAttestationEvidenceKindV0];

export const CanonicalPipelineAttestationNormalizedFormV0 = {
  Utf8Text: "utf8_text",
  CanonicalJsonUtf8: "canonical_json_utf8",
} as const;

export type CanonicalPipelineAttestationNormalizedFormV0 =
  (typeof CanonicalPipelineAttestationNormalizedFormV0)[keyof typeof CanonicalPipelineAttestationNormalizedFormV0];

export const CanonicalPipelineAttestationConsistencyRelationV0 = {
  EvidenceRootDigestEquals: "evidence_root_digest_equals",
  NormalizedEvidenceDigestEquals: "normalized_evidence_digest_equals",
  NormalizedTextContainsUtf8: "normalized_text_contains_utf8",
  NormalizedJsonFieldEqualsUtf8: "normalized_json_field_equals_utf8",
} as const;

export type CanonicalPipelineAttestationConsistencyRelationV0 =
  (typeof CanonicalPipelineAttestationConsistencyRelationV0)[keyof typeof CanonicalPipelineAttestationConsistencyRelationV0];

export const CanonicalPipelineAttestationStatusV0 = {
  Accepted: "accepted",
  Rejected: "rejected",
} as const;

export type CanonicalPipelineAttestationStatusV0 =
  (typeof CanonicalPipelineAttestationStatusV0)[keyof typeof CanonicalPipelineAttestationStatusV0];

export const CanonicalPipelineAttestationFailureReasonV0 = {
  None: "none",
  UnsupportedAttestationMode: "unsupported_attestation_mode",
  MalformedEvidence: "malformed_evidence",
  NormalizationFailure: "normalization_failure",
  ConsistencyMismatch: "consistency_mismatch",
  UnsupportedProvenanceType: "unsupported_provenance_type",
  ProvenanceSignatureInvalid: "provenance_signature_invalid",
  VerificationLayerFailure: "verification_layer_failure",
  AttestationProofVerificationFailure: "attestation_proof_verification_failure",
  SettlementLayerFailure: "settlement_layer_failure",
} as const;

export type CanonicalPipelineAttestationFailureReasonV0 =
  (typeof CanonicalPipelineAttestationFailureReasonV0)[keyof typeof CanonicalPipelineAttestationFailureReasonV0];

export type CanonicalPipelineAttestationClaimPayloadV0 =
  | {
      expectedEvidenceRootDigest: Uint8Array;
    }
  | {
      targetLabel: string;
      expectedEvidenceDigest: Uint8Array;
    }
  | {
      targetLabel: string;
      expectedSubstringUtf8: string;
    }
  | {
      targetLabel: string;
      fieldPath: string[];
      expectedValueUtf8: string;
    };

export interface CanonicalPipelineAttestationClaimV0 {
  claimKind: CanonicalPipelineAttestationClaimKindV0;
  claimPayload: CanonicalPipelineAttestationClaimPayloadV0;
}

export type CanonicalPipelineAttestationEvidencePayloadV0 =
  | {
      payloadUtf8: string;
    }
  | {
      payloadUtf8: string;
    };

export interface CanonicalPipelineAttestationConstraintsV0 {
  requireUniqueLabels: boolean;
  maxEvidenceItems: bigint;
  maxTotalNormalizedBytes: bigint;
}

export interface CanonicalPipelineAttestationEvidenceItemV0 {
  label: string;
  evidenceKind: CanonicalPipelineAttestationEvidenceKindV0;
  evidencePayload: CanonicalPipelineAttestationEvidencePayloadV0;
  provenance: CanonicalPipelineEvidenceProvenanceV0;
}

export const CanonicalPipelineAttestationProofKindV0 = {
  Mock: "MOCK",
  Stark: "STARK",
} as const;

export type CanonicalPipelineAttestationProofKindV0 =
  (typeof CanonicalPipelineAttestationProofKindV0)[keyof typeof CanonicalPipelineAttestationProofKindV0];

export const CanonicalPipelineEvidenceProvenanceTypeV0 = {
  Inline: "inline",
  HashReference: "hash_reference",
  SignedBlob: "signed_blob",
  AnchoredExternal: "anchored_external",
} as const;

export type CanonicalPipelineEvidenceProvenanceTypeV0 =
  (typeof CanonicalPipelineEvidenceProvenanceTypeV0)[keyof typeof CanonicalPipelineEvidenceProvenanceTypeV0];

export interface CanonicalPipelineEvidenceSignatureV0 {
  signerPublicKey: Uint8Array;
  signature: Uint8Array;
}

export interface CanonicalPipelineEvidenceProvenanceV0 {
  provenancePolicyVersion: number;
  provenanceType: CanonicalPipelineEvidenceProvenanceTypeV0;
  sourceType: string;
  sourceIdentifier: string;
  signature: CanonicalPipelineEvidenceSignatureV0 | null;
  timestampUnixSeconds: bigint | null;
}

export interface CanonicalPipelineAttestationRequestV0 {
  attestationSchemaVersion: number;
  attestationScope: CanonicalPipelineAttestationScopeV0;
  attestationProofKind: CanonicalPipelineAttestationProofKindV0;
  normalizationPolicyVersion: number;
  attestationConstraints: CanonicalPipelineAttestationConstraintsV0;
  claim: CanonicalPipelineAttestationClaimV0;
  evidenceItems: CanonicalPipelineAttestationEvidenceItemV0[];
  tamperStarkPublicInputsDigest: { byteOffset: number; xorWith: number } | null;
  tamperStarkProofBytes: { byteOffset: number; xorWith: number } | null;
}

export const CanonicalPipelineExecutionStatusV0 = {
  Applied: "applied",
  Rejected: "rejected",
} as const;

export type CanonicalPipelineExecutionStatusV0 =
  (typeof CanonicalPipelineExecutionStatusV0)[keyof typeof CanonicalPipelineExecutionStatusV0];

export const CanonicalPipelineVerificationStatusV0 = {
  Passed: "passed",
  Rejected: "rejected",
  NotRun: "not_run",
} as const;

export type CanonicalPipelineVerificationStatusV0 =
  (typeof CanonicalPipelineVerificationStatusV0)[keyof typeof CanonicalPipelineVerificationStatusV0];

export const CanonicalPipelineSettlementStatusV0 = {
  Accepted: "accepted",
  Rejected: "rejected",
  NotRun: "not_run",
} as const;

export type CanonicalPipelineSettlementStatusV0 =
  (typeof CanonicalPipelineSettlementStatusV0)[keyof typeof CanonicalPipelineSettlementStatusV0];

export const CanonicalPipelinePublicInputsDecodeStatusV0 = {
  Decoded: "decoded",
  Invalid: "invalid",
} as const;

export type CanonicalPipelinePublicInputsDecodeStatusV0 =
  (typeof CanonicalPipelinePublicInputsDecodeStatusV0)[keyof typeof CanonicalPipelinePublicInputsDecodeStatusV0];

export const CanonicalPipelineProofBindingInputKindV0 = {
  WitnessDigest: "witness_digest",
  ProofBytesHash: "proof_bytes_hash",
} as const;

export type CanonicalPipelineProofBindingInputKindV0 =
  (typeof CanonicalPipelineProofBindingInputKindV0)[keyof typeof CanonicalPipelineProofBindingInputKindV0];

export const CanonicalPipelineValidityReferenceKindV0 = {
  None: "none",
} as const;

export type CanonicalPipelineValidityReferenceKindV0 =
  (typeof CanonicalPipelineValidityReferenceKindV0)[keyof typeof CanonicalPipelineValidityReferenceKindV0];

export interface CanonicalPipelineTamperAuditV0 {
  byteOffset: number;
  xorWith: number;
}

export interface CanonicalPipelineBurnDerivationInputsV0 {
  txCount: bigint;
  meteredRequestSizeBytes: bigint;
  requestKind: CanonicalPipelineRequestKindV0;
  proofSystem: ProofSystemV0;
  attestationEvidenceItems: bigint;
  attestationClaimBytes: bigint;
  attestationEvidenceBytes: bigint;
}

export interface CanonicalPipelineBurnPolicyV0 {
  burnPolicyVersion: number;
  baseUnits: bigint;
  executionRequestKindUnits: bigint;
  attestationRequestKindUnits: bigint;
  mockProofSystemUnits: bigint;
  starkProofSystemUnits: bigint;
  transactionUnitsPerItem: bigint;
  meteredRequestSizeChunkBytes: bigint;
}

export const CanonicalPipelineBurnReasonV0 = {
  ProduceCanonicalTruthArtifact: "produce_canonical_truth_artifact",
} as const;

export type CanonicalPipelineBurnReasonV0 =
  (typeof CanonicalPipelineBurnReasonV0)[keyof typeof CanonicalPipelineBurnReasonV0];

export const CanonicalPipelineBurnCategoryV0 = {
  ExecutionTruthProduction: "execution_truth_production",
  AttestationTruthProduction: "attestation_truth_production",
} as const;

export type CanonicalPipelineBurnCategoryV0 =
  (typeof CanonicalPipelineBurnCategoryV0)[keyof typeof CanonicalPipelineBurnCategoryV0];

export interface CanonicalPipelineBurnFailureSemanticsV0 {
  executionRejectedBurnsFullAmount: boolean;
  verificationRejectedBurnsFullAmount: boolean;
  settlementRejectedBurnsFullAmount: boolean;
  partialBurnAllowed: boolean;
}

export interface CanonicalPipelineBurnSummaryV0 {
  burnPolicyVersion: number;
  burnPolicy: CanonicalPipelineBurnPolicyV0;
  burnReason: CanonicalPipelineBurnReasonV0;
  burnCategory: CanonicalPipelineBurnCategoryV0;
  requestKind: CanonicalPipelineRequestKindV0;
  burnIntent: CanonicalPipelineBurnIntentV0;
  declaredFeeUnits: bigint;
  computedBurnUnits: bigint;
  consumedBurnUnits: bigint;
  burnDerivationInputs: CanonicalPipelineBurnDerivationInputsV0;
  requestDeclaresCorrectBurn: boolean;
  recomputedBurnMatchesReport: boolean;
  burnConsumed: boolean;
  failureSemantics: CanonicalPipelineBurnFailureSemanticsV0;
}

export const CanonicalPipelineFeeDispositionV0 = {
  BurnedForCanonicalTruth: "burned_for_canonical_truth",
} as const;

export type CanonicalPipelineFeeDispositionV0 =
  (typeof CanonicalPipelineFeeDispositionV0)[keyof typeof CanonicalPipelineFeeDispositionV0];

export const CanonicalPipelineFutureTokenBindingStatusV0 = {
  PendingExternalAnchor: "pending_external_anchor",
} as const;

export type CanonicalPipelineFutureTokenBindingStatusV0 =
  (typeof CanonicalPipelineFutureTokenBindingStatusV0)[keyof typeof CanonicalPipelineFutureTokenBindingStatusV0];

export const CanonicalPipelineSettlementReasonV0 = {
  AcceptedAndCommitted: "accepted_and_committed",
  NotRunExecutionRejected: "not_run_execution_rejected",
  RejectedVerificationMismatch: "rejected_verification_mismatch",
  RejectedLocalSettlement: "rejected_local_settlement",
} as const;

export type CanonicalPipelineSettlementReasonV0 =
  (typeof CanonicalPipelineSettlementReasonV0)[keyof typeof CanonicalPipelineSettlementReasonV0];

export interface CanonicalPipelineBurnRecordV0 {
  burnReason: CanonicalPipelineBurnReasonV0;
  burnCategory: CanonicalPipelineBurnCategoryV0;
  feeDisposition: CanonicalPipelineFeeDispositionV0;
  accountId: Uint8Array;
  preBalance: bigint;
  postBalance: bigint;
  burnedAmount: bigint;
  declaredFeeUnits: bigint;
  computedBurnUnits: bigint;
  consumedBurnUnits: bigint;
  reportPipelineId: string;
  reportRequestBindingHash: Uint8Array;
}

export interface CanonicalPipelineSettlementRecordV0 {
  settlementIntent: CanonicalPipelineSettlementIntentV0;
  settlementStatus: CanonicalPipelineSettlementStatusV0;
  settlementReason: CanonicalPipelineSettlementReasonV0;
  committedStateRoot: Uint8Array | null;
  futureTokenBindingStatus: CanonicalPipelineFutureTokenBindingStatusV0;
  futureTokenBindingUnits: bigint;
}

export interface CanonicalPipelineAccountingSummaryV0 {
  accountingPolicyVersion: number;
  paymentIntent: CanonicalPipelinePaymentIntentV0;
  settlementIntent: CanonicalPipelineSettlementIntentV0;
  declaredFeeUnits: bigint;
  computedBurnUnits: bigint;
  consumedBurnUnits: bigint;
  burnRecord: CanonicalPipelineBurnRecordV0;
  settlementRecord: CanonicalPipelineSettlementRecordV0;
  accountingConsistentWithBurn: boolean;
  accountingConsistentWithOutcome: boolean;
}

export interface CanonicalPipelineRequestAuditV0 {
  requestBindingHash: Uint8Array;
  genesisAccountsDigest: Uint8Array;
  ledgerAccountsDigest: Uint8Array;
  transactionsDigest: Uint8Array;
  rollupId: Uint8Array;
  genesisAccountCount: bigint;
  ledgerAccountCount: bigint;
  ledgerPayerAccountId: Uint8Array;
  ledgerTotalSupply: bigint;
  ledgerBurnedSupply: bigint;
  batchNumber: bigint;
  txCount: bigint;
  parentBatchCommitment: Uint8Array;
  tamperPublicInputs: CanonicalPipelineTamperAuditV0 | null;
  tamperProofBindingDigest: CanonicalPipelineTamperAuditV0 | null;
  tamperAttestationStarkPublicInputsDigest: CanonicalPipelineTamperAuditV0 | null;
  tamperAttestationStarkProofBytes: CanonicalPipelineTamperAuditV0 | null;
}

export interface CanonicalPipelineGenesisAccountsV0 {
  materialVersion: number;
  orderedAccounts: AccountV0[];
}

export interface CanonicalPipelineLedgerAccountsV0 {
  materialVersion: number;
  orderedAccounts: CanonicalPipelineLedgerAccountV0[];
}

export interface CanonicalPipelineLedgerStateCommitmentV0 {
  commitmentVersion: number;
  preLedgerStateCommitment: Uint8Array;
  postLedgerStateCommitment: Uint8Array;
}

export interface CanonicalPipelineLedgerSummaryV0 {
  ledgerPolicyVersion: number;
  payerAccountId: Uint8Array;
  totalSupply: bigint;
  burnedSupplyBefore: bigint;
  burnedSupplyAfter: bigint;
  ledgerAccountCount: bigint;
  circulatingSupplyBefore: bigint;
  circulatingSupplyAfter: bigint;
  ledgerConsistentWithRequest: boolean;
  ledgerConsistentWithBurn: boolean;
  ledgerConsistentWithSupply: boolean;
  ledgerStateCommitment: CanonicalPipelineLedgerStateCommitmentV0;
}

export interface CanonicalPipelineTransactionsCommitmentExpansionV0 {
  expansionVersion: number;
  transactionsCommitment: Uint8Array;
  orderedTransactions: TransferTxV0[];
}

export interface CanonicalPipelineOutcomesCommitmentExpansionV0 {
  expansionVersion: number;
  outcomesCommitment: Uint8Array;
  outcomes: ExecutionOutcomeV0[];
  appliedSteps: AppliedTransferStepV0[];
}

export interface CanonicalPipelineFeeParametersExpansionV0 {
  feePerTransfer: bigint;
}

export interface CanonicalPipelineValidityReferenceExpansionV0 {
  kind: CanonicalPipelineValidityReferenceKindV0;
  noneMarker: number;
}

export interface CanonicalPipelineExecutionConstantsExpansionV0 {
  transferTxVersion: number;
  transitionBindingVersion: number;
  appliedStatus: number;
}

export interface CanonicalPipelineBatchContextCommitmentExpansionV0 {
  expansionVersion: number;
  batchContextCommitment: Uint8Array;
  transitionBindingVersion: number;
  systemConfig: ExecutionConfigV0;
  feeParameters: CanonicalPipelineFeeParametersExpansionV0;
  validityReference: CanonicalPipelineValidityReferenceExpansionV0;
  executionConstants: CanonicalPipelineExecutionConstantsExpansionV0;
}

export interface CanonicalPipelineFeeSummaryCommitmentExpansionV0 {
  expansionVersion: number;
  feeSummaryCommitment: Uint8Array;
  feeSummary: FeeSummaryV0;
}

export interface CanonicalPipelineCommitmentExpansionsV0 {
  transactions: CanonicalPipelineTransactionsCommitmentExpansionV0;
  outcomes: CanonicalPipelineOutcomesCommitmentExpansionV0 | null;
  batchContext: CanonicalPipelineBatchContextCommitmentExpansionV0;
  feeSummary: CanonicalPipelineFeeSummaryCommitmentExpansionV0;
}

export interface CanonicalPipelineStageOutcomesV0 {
  executionStatus: CanonicalPipelineExecutionStatusV0;
  verificationStatus: CanonicalPipelineVerificationStatusV0;
  settlementStatus: CanonicalPipelineSettlementStatusV0;
}

export const CanonicalPipelineTruthArtifactKindV0 = {
  ExecutionReport: "execution_report",
  AttestationReport: "attestation_report",
} as const;

export type CanonicalPipelineTruthArtifactKindV0 =
  (typeof CanonicalPipelineTruthArtifactKindV0)[keyof typeof CanonicalPipelineTruthArtifactKindV0];

export const CanonicalPipelineFailureStageV0 = {
  None: "none",
  Request: "request",
  Execution: "execution",
  Verification: "verification",
  Settlement: "settlement",
} as const;

export type CanonicalPipelineFailureStageV0 =
  (typeof CanonicalPipelineFailureStageV0)[keyof typeof CanonicalPipelineFailureStageV0];

export const CanonicalPipelineFailureReasonCodeV0 = {
  None: "none",
  TransferExecutionRejected: "transfer_execution_rejected",
  UnsupportedAttestationMode: "unsupported_attestation_mode",
  AttestationMalformedEvidence: "attestation_malformed_evidence",
  AttestationNormalizationFailure: "attestation_normalization_failure",
  AttestationConsistencyMismatch: "attestation_consistency_mismatch",
  VerificationLayerMismatch: "verification_layer_mismatch",
  SettlementAcceptanceRejected: "settlement_acceptance_rejected",
  SettlementHeadMismatch: "settlement_head_mismatch",
  WalletBindingMismatch: "wallet_binding_mismatch",
  UnsupportedProvenanceType: "unsupported_provenance_type",
  ProvenanceSignatureInvalid: "provenance_signature_invalid",
  AttestationProofVerificationRejected: "attestation_proof_verification_rejected",
} as const;

export type CanonicalPipelineFailureReasonCodeV0 =
  (typeof CanonicalPipelineFailureReasonCodeV0)[keyof typeof CanonicalPipelineFailureReasonCodeV0];

export interface CanonicalPipelineStatusExplanationV0 {
  truthArtifactKind: CanonicalPipelineTruthArtifactKindV0;
  requestKind: CanonicalPipelineRequestKindV0;
  finalStatus: ScenarioResultV0;
  failureStage: CanonicalPipelineFailureStageV0;
  failureReasonCode: CanonicalPipelineFailureReasonCodeV0;
  detail: string;
}

export interface CanonicalPipelineAttestationEvidenceSummaryItemV0 {
  label: string;
  evidenceKind: CanonicalPipelineAttestationEvidenceKindV0;
  originalPayloadUtf8: string;
  originalPayloadSizeBytes: bigint;
  normalizedForm: CanonicalPipelineAttestationNormalizedFormV0;
  normalizedPayloadUtf8: string;
  normalizedPayloadSizeBytes: bigint;
  evidenceDigest: Uint8Array;
  provenanceDigest: Uint8Array;
}

export interface CanonicalPipelineAttestationEvidenceSummaryV0 {
  evidenceItemCount: bigint;
  evidenceItems: CanonicalPipelineAttestationEvidenceSummaryItemV0[];
  evidenceRootDigest: Uint8Array;
}

export interface CanonicalPipelineAttestationNormalizationSummaryV0 {
  normalizationPolicyVersion: number;
  normalizedEvidenceCount: bigint;
  totalNormalizedBytes: bigint;
  normalizationSucceeded: boolean;
}

export interface CanonicalPipelineAttestationConsistencyResultV0 {
  relation: CanonicalPipelineAttestationConsistencyRelationV0;
  targetLabel: string | null;
  consistent: boolean;
}

export interface CanonicalPipelineAttestationFailureAuditV0 {
  reason: CanonicalPipelineAttestationFailureReasonV0;
  detail: string;
}

export interface CanonicalPipelineAttestationSummaryV0 {
  attestationSchemaVersion: number;
  attestationScope: CanonicalPipelineAttestationScopeV0;
  attestationProofKind: CanonicalPipelineAttestationProofKindV0;
  normalizationPolicyVersion: number;
  attestationConstraints: CanonicalPipelineAttestationConstraintsV0;
  claim: CanonicalPipelineAttestationClaimV0;
  claimDigest: Uint8Array;
  evidenceSummary: CanonicalPipelineAttestationEvidenceSummaryV0;
  normalizationSummary: CanonicalPipelineAttestationNormalizationSummaryV0;
  consistencyResult: CanonicalPipelineAttestationConsistencyResultV0;
  attestationStatus: CanonicalPipelineAttestationStatusV0;
  attestationFailureReason: CanonicalPipelineAttestationFailureAuditV0;
  proofScopeHonestyNote: string;
}

export const CanonicalPipelineHeadAuthorityModeV0 = {
  AuthoritativePersistent: "authoritative_persistent",
  StatelessNonAuthoritative: "stateless_non_authoritative",
} as const;

export type CanonicalPipelineHeadAuthorityModeV0 =
  (typeof CanonicalPipelineHeadAuthorityModeV0)[keyof typeof CanonicalPipelineHeadAuthorityModeV0];

export const CanonicalPipelineExternalAnchorVerificationStatusV0 = {
  NotRequested: "not_requested",
  Accepted: "accepted",
  Rejected: "rejected",
  Disconnected: "disconnected",
} as const;

export type CanonicalPipelineExternalAnchorVerificationStatusV0 =
  (typeof CanonicalPipelineExternalAnchorVerificationStatusV0)[keyof typeof CanonicalPipelineExternalAnchorVerificationStatusV0];

export interface CanonicalPipelineHeadTransitionSummaryV0 {
  settlementHeadVersion: number;
  authorityMode: CanonicalPipelineHeadAuthorityModeV0;
  headSequenceNumber: bigint;
  previousHeadHash: Uint8Array;
  currentHeadHash: Uint8Array;
  canonicalHeadCommitment: Uint8Array;
  requestCanonicalDigest: Uint8Array;
  reportDigest: Uint8Array;
}

export interface CanonicalPipelineWalletBindingSummaryV0 {
  walletBindingVersion: number;
  accountId: Uint8Array;
  walletAddress: string;
  walletBindingDigest: Uint8Array;
  bindingConsistentWithAccount: boolean;
}

export interface CanonicalPipelineTokenAnchorSummaryV0 {
  tokenPolicyVersion: number;
  networkMode: CanonicalPipelineNetworkModeV0;
  settlementAnchorType: CanonicalPipelineSettlementAnchorTypeV0;
  anchorVerificationStatus: CanonicalPipelineExternalAnchorVerificationStatusV0;
  externalBalanceReference: CanonicalPipelineExternalBalanceReferenceV0 | null;
  expectedExternalBalance: bigint | null;
  tokenAnchorDigest: Uint8Array;
}

export interface CanonicalPipelineProvenanceSummaryItemV0 {
  label: string;
  provenancePolicyVersion: number;
  provenanceType: CanonicalPipelineEvidenceProvenanceTypeV0;
  sourceType: string;
  sourceIdentifier: string;
  signaturePresent: boolean;
  signatureValid: boolean;
  signerPublicKey: Uint8Array | null;
  signature: Uint8Array | null;
  timestampUnixSeconds: bigint | null;
  provenanceDigest: Uint8Array;
}

export interface CanonicalPipelineProvenanceSummaryV0 {
  provenanceItemCount: bigint;
  items: CanonicalPipelineProvenanceSummaryItemV0[];
  provenanceRootDigest: Uint8Array;
  allSignatureChecksPassed: boolean;
}

export interface CanonicalPipelineAttestationProofSummaryV0 {
  proofKind: CanonicalPipelineAttestationProofKindV0;
  attestationTupleDigest: Uint8Array;
  verificationPassed: boolean;
  mockPolicyVersion: number | null;
  starkPolicyVersion: number | null;
  starkPublicInputsDigest: Uint8Array | null;
  starkProofBytesDigest: Uint8Array | null;
  starkProofBindingDigest: Uint8Array | null;
}

export interface CanonicalPipelineDecodedPublicInputsV0 extends PublicInputsV0 {}

export interface CanonicalPipelineRequestSummaryConsistencyAuditV0 {
  transitionBindingVersionSupported: boolean;
  executionModelVersionSupported: boolean;
  batchVersionSupported: boolean;
  rollupIdMatchesRequestAudit: boolean;
  batchNumberMatchesRequestAudit: boolean;
  txCountMatchesRequestAudit: boolean;
  parentBatchCommitmentMatchesRequestAudit: boolean;
  feeSummaryCommitmentMatchesExpansion: boolean;
  preStateRootMatchesReport: boolean;
  transactionsCommitmentMatchesExpansion: boolean;
  outcomesCommitmentMatchesExpansion: boolean;
  batchContextCommitmentMatchesExpansion: boolean;
  postStateRootMatchesReport: boolean;
  decodedBytesRoundTrip: boolean;
  allFieldsMatch: boolean;
}

export interface CanonicalPipelinePublicInputsAuditV0 {
  decodeStatus: CanonicalPipelinePublicInputsDecodeStatusV0;
  publicInputBytes: Uint8Array;
  publicInputsHash: Uint8Array;
  transitionBindingHash: Uint8Array;
  requestSummaryConsistency: CanonicalPipelineRequestSummaryConsistencyAuditV0 | null;
  decodedPublicInputs: CanonicalPipelineDecodedPublicInputsV0 | null;
}

export interface CanonicalPipelineProofArtifactConsistencyAuditV0 {
  publicInputsHashMatchesReport: boolean;
  proverKindMatchesProofSystem: boolean;
  proofVersionSupported: boolean;
  proofBindingInputKindMatchesProofSystem: boolean;
  recomputedProofBindingDigest: Uint8Array;
  proofBindingDigestMatchesRecomputed: boolean;
  allFieldsMatch: boolean;
}

export interface CanonicalPipelineProofArtifactAuditV0 {
  proverKind: number;
  proofVersion: number;
  publicInputsHash: Uint8Array;
  traceDigest: Uint8Array;
  traceLayoutDigest: Uint8Array;
  proofBindingDigest: Uint8Array;
  proofBindingInputKind: CanonicalPipelineProofBindingInputKindV0;
  proofBindingInputDigest: Uint8Array;
  consistency: CanonicalPipelineProofArtifactConsistencyAuditV0;
}

export interface CanonicalPipelineReportV0 {
  pipelineSchemaVersion: number;
  pipelineId: string;
  fixtureName: string;
  proofSystem: ProofSystemV0;
  expectedResult: ScenarioResultV0;
  actualResult: ScenarioResultV0;
  preStateRoot: Uint8Array;
  executedPostStateRoot: Uint8Array | null;
  settlementCommittedStateRoot: Uint8Array | null;
  burnSummary: CanonicalPipelineBurnSummaryV0;
  accountingSummary: CanonicalPipelineAccountingSummaryV0;
  ledgerSummary: CanonicalPipelineLedgerSummaryV0;
  headTransitionSummary: CanonicalPipelineHeadTransitionSummaryV0;
  walletBindingSummary: CanonicalPipelineWalletBindingSummaryV0;
  tokenAnchorSummary: CanonicalPipelineTokenAnchorSummaryV0;
  requestAudit: CanonicalPipelineRequestAuditV0;
  genesisAccounts: CanonicalPipelineGenesisAccountsV0;
  ledgerAccounts: CanonicalPipelineLedgerAccountsV0;
  commitmentExpansions: CanonicalPipelineCommitmentExpansionsV0;
  stageOutcomes: CanonicalPipelineStageOutcomesV0;
  statusExplanation: CanonicalPipelineStatusExplanationV0;
  attestationSummary: CanonicalPipelineAttestationSummaryV0 | null;
  attestationProofSummary: CanonicalPipelineAttestationProofSummaryV0 | null;
  provenanceSummary: CanonicalPipelineProvenanceSummaryV0 | null;
  publicInputs: CanonicalPipelinePublicInputsAuditV0 | null;
  proofArtifact: CanonicalPipelineProofArtifactAuditV0 | null;
}

const RUST_LOCAL_CHAIN_BRIDGE_SCHEMA_V0 = 1;
const RUST_CANONICAL_PIPELINE_COMMANDS_V0 = ["run-canonical-pipeline"] as const;
const RUST_SCENARIO_COMMANDS_V0 = ["run-scenario", "run-scenario-stark"] as const;
const RUST_PROOF_VECTOR_COMMANDS_V0 = ["run-proof-vector", "verify-proof-vector"] as const;

interface RustScenarioBridgeEnvelopeV0 {
  bridge_schema_version: number;
  report_kind: "scenario_report_v1";
  command: string;
  report: {
    fixture_name: string;
    expected_result: string;
    actual_result: string;
    pre_state_root_hex: string;
    post_state_root_hex?: string;
    transition_binding_hash_hex?: string;
  };
}

interface RustProofVectorBridgeEnvelopeV0 {
  bridge_schema_version: number;
  report_kind: "proof_vector_report_v1";
  command: string;
  report: {
    fixture_name: string;
    proof_system: string;
    expected_result: string;
    actual_result: string;
    pre_state_root_hex: string;
    post_state_root_hex?: string;
    transition_binding_hash_hex: string;
    public_inputs_hash_hex: string;
    trace_digest_hex: string;
    trace_layout_digest_hex: string;
    proof_binding_digest_hex: string;
  };
}

interface RustCanonicalPipelineBridgeEnvelopeV0 {
  bridge_schema_version: number;
  report_kind: "canonical_pipeline_report_v1";
  command: string;
  report: {
    pipeline_schema_version: number;
    pipeline_id: string;
    fixture_name: string;
    proof_system: string;
    expected_result: string;
    actual_result: string;
    pre_state_root_hex: string;
    executed_post_state_root_hex?: string;
    settlement_committed_state_root_hex?: string;
    burn_summary: {
      burn_policy_version: number;
      burn_policy: {
        burn_policy_version: number;
        base_units: number;
        execution_request_kind_units: number;
        attestation_request_kind_units: number;
        mock_proof_system_units: number;
        stark_proof_system_units: number;
        transaction_units_per_item: number;
        metered_request_size_chunk_bytes: number;
      };
      burn_reason: string;
      burn_category: string;
      request_kind: string;
      burn_intent: string;
      declared_fee_units: number;
      computed_burn_units: number;
      consumed_burn_units: number;
      burn_derivation_inputs: {
        tx_count: number;
        metered_request_size_bytes: number;
        request_kind: string;
        proof_system: string;
        attestation_evidence_items: number;
        attestation_claim_bytes: number;
        attestation_evidence_bytes: number;
      };
      request_declares_correct_burn: boolean;
      recomputed_burn_matches_report: boolean;
      burn_consumed: boolean;
      failure_semantics: {
        execution_rejected_burns_full_amount: boolean;
        verification_rejected_burns_full_amount: boolean;
        settlement_rejected_burns_full_amount: boolean;
        partial_burn_allowed: boolean;
      };
    };
    accounting_summary: {
      accounting_policy_version: number;
      payment_intent: string;
      settlement_intent: string;
      declared_fee_units: number;
      computed_burn_units: number;
      consumed_burn_units: number;
      burn_record: {
        burn_reason: string;
        burn_category: string;
        fee_disposition: string;
        account_id_hex: string;
        pre_balance: number;
        post_balance: number;
        burned_amount: number;
        declared_fee_units: number;
        computed_burn_units: number;
        consumed_burn_units: number;
        report_pipeline_id: string;
        report_request_binding_hash_hex: string;
      };
      settlement_record: {
        settlement_intent: string;
        settlement_status: string;
        settlement_reason: string;
        committed_state_root_hex?: string;
        future_token_binding_status: string;
        future_token_binding_units: number;
      };
      accounting_consistent_with_burn: boolean;
      accounting_consistent_with_outcome: boolean;
    };
    ledger_summary: {
      ledger_policy_version: number;
      payer_account_id_hex: string;
      total_supply: number;
      burned_supply_before: number;
      burned_supply_after: number;
      ledger_account_count: number;
      circulating_supply_before: number;
      circulating_supply_after: number;
      ledger_consistent_with_request: boolean;
      ledger_consistent_with_burn: boolean;
      ledger_consistent_with_supply: boolean;
      ledger_state_commitment: {
        commitment_version: number;
        pre_ledger_state_commitment_hex: string;
        post_ledger_state_commitment_hex: string;
      };
    };
    request_audit: {
      request_binding_hash_hex: string;
      genesis_accounts_digest_hex: string;
      ledger_accounts_digest_hex: string;
      transactions_digest_hex: string;
      rollup_id_hex: string;
      genesis_account_count: number;
      ledger_account_count: number;
      ledger_payer_account_id_hex: string;
      ledger_total_supply: number;
      ledger_burned_supply: number;
      batch_number: number;
      tx_count: number;
      parent_batch_commitment_hex: string;
      tamper_public_inputs?: {
        byte_offset: number;
        xor_with: number;
      };
      tamper_proof_binding_digest?: {
        byte_offset: number;
        xor_with: number;
      };
      tamper_attestation_stark_public_inputs_digest?: {
        byte_offset: number;
        xor_with: number;
      };
      tamper_attestation_stark_proof_bytes?: {
        byte_offset: number;
        xor_with: number;
      };
    };
    genesis_accounts: {
      material_version: number;
      ordered_accounts: Array<{
        account_id_hex: string;
        balance: number;
        nonce: number;
      }>;
    };
    ledger_accounts: {
      material_version: number;
      ordered_accounts: Array<{
        account_id_hex: string;
        balance: number;
      }>;
    };
    commitment_expansions: {
      transactions: {
        expansion_version: number;
        transactions_commitment_hex: string;
        ordered_transactions: Array<{
          tx_version: number;
          sender_account_id_hex: string;
          recipient_account_id_hex: string;
          sender_nonce: number;
          amount: number;
        }>;
      };
      outcomes?: {
        expansion_version: number;
        outcomes_commitment_hex: string;
        outcomes: Array<{
          tx_index: number;
          sender_account_id_hex: string;
          consumed_nonce: number;
          fee_charged: number;
          touched_accounts_commitment_hex: string;
          operation_result_commitment_hex: string;
          status: number;
        }>;
        applied_steps: Array<{
          tx_index: number;
          sender_account_id_hex: string;
          recipient_account_id_hex: string;
          sender_nonce_before: number;
          sender_nonce_after: number;
          sender_balance_before: number;
          sender_balance_after: number;
          recipient_balance_before: number;
          recipient_balance_after: number;
          amount: number;
          fee_charged: number;
        }>;
      };
      batch_context: {
        expansion_version: number;
        batch_context_commitment_hex: string;
        transition_binding_version: number;
        system_config: {
          rollup_id_hex: string;
          execution_model_version: number;
          batch_version: number;
        };
        fee_parameters: {
          fee_per_transfer: number;
        };
        validity_reference: {
          kind: string;
          none_marker: number;
        };
        execution_constants: {
          transfer_tx_version: number;
          transition_binding_version: number;
          applied_status: number;
        };
      };
      fee_summary: {
        expansion_version: number;
        fee_summary_commitment_hex: string;
        fee_summary: {
          tx_count: number;
          total_fee_charged: number;
        };
      };
    };
    stage_outcomes: {
      execution_status: string;
      verification_status: string;
      settlement_status: string;
    };
    status_explanation: {
      truth_artifact_kind: string;
      request_kind: string;
      final_status: string;
      failure_stage: string;
      failure_reason_code: string;
      detail: string;
    };
    attestation_summary?: {
      attestation_schema_version: number;
      attestation_scope: string;
      normalization_policy_version: number;
      attestation_constraints: {
        require_unique_labels: boolean;
        max_evidence_items: number;
        max_total_normalized_bytes: number;
      };
      claim: {
        claim_kind: string;
        claim_payload: {
          expected_evidence_root_digest_hex?: string;
          target_label?: string;
          expected_evidence_digest_hex?: string;
          expected_substring_utf8?: string;
          field_path?: string[];
          expected_value_utf8?: string;
        };
      };
      claim_digest_hex: string;
      evidence_summary: {
        evidence_item_count: number;
        evidence_items: Array<{
          label: string;
          evidence_kind: string;
          original_payload_utf8: string;
          original_payload_size_bytes: number;
          normalized_form: string;
          normalized_payload_utf8: string;
          normalized_payload_size_bytes: number;
          evidence_digest_hex: string;
        }>;
        evidence_root_digest_hex: string;
      };
      normalization_summary: {
        normalization_policy_version: number;
        normalized_evidence_count: number;
        total_normalized_bytes: number;
        normalization_succeeded: boolean;
      };
      consistency_result: {
        relation: string;
        target_label?: string;
        consistent: boolean;
      };
      attestation_status: string;
      attestation_failure_reason: {
        reason: string;
        detail: string;
      };
      proof_scope_honesty_note: string;
    };
    public_inputs?: {
      decode_status: string;
      public_input_bytes_hex: string;
      public_inputs_hash_hex: string;
      transition_binding_hash_hex: string;
      request_summary_consistency?: {
        transition_binding_version_supported: boolean;
        execution_model_version_supported: boolean;
        batch_version_supported: boolean;
        rollup_id_matches_request_audit: boolean;
        batch_number_matches_request_audit: boolean;
        tx_count_matches_request_audit: boolean;
        parent_batch_commitment_matches_request_audit: boolean;
        fee_summary_commitment_matches_expansion: boolean;
        pre_state_root_matches_report: boolean;
        transactions_commitment_matches_expansion: boolean;
        outcomes_commitment_matches_expansion: boolean;
        batch_context_commitment_matches_expansion: boolean;
        post_state_root_matches_report: boolean;
        decoded_bytes_round_trip: boolean;
        all_fields_match: boolean;
      };
      decoded_public_inputs?: {
        transition_binding_version: number;
        rollup_id_hex: string;
        execution_model_version: number;
        batch_version: number;
        batch_number: number;
        parent_batch_commitment_hex: string;
        tx_count: number;
        fee_summary_commitment_hex: string;
        pre_state_root_hex: string;
        post_state_root_hex: string;
        transactions_commitment_hex: string;
        outcomes_commitment_hex: string;
        batch_context_commitment_hex: string;
      };
    };
    proof_artifact?: {
      prover_kind: number;
      proof_version: number;
      public_inputs_hash_hex: string;
      trace_digest_hex: string;
      trace_layout_digest_hex: string;
      proof_binding_digest_hex: string;
      proof_binding_input_kind: string;
      proof_binding_input_digest_hex: string;
      consistency: {
        public_inputs_hash_matches_report: boolean;
        prover_kind_matches_proof_system: boolean;
        proof_version_supported: boolean;
        proof_binding_input_kind_matches_proof_system: boolean;
        recomputed_proof_binding_digest_hex: string;
        proof_binding_digest_matches_recomputed: boolean;
        all_fields_match: boolean;
      };
    };
  };
}

export interface RustBridgeFlowOptionsV0 {
  state: StateV0;
  rollupId: Uint8Array;
  batch: BatchV0;
  proofSystem: ProofSystemV0;
  requestKind?: CanonicalPipelineRequestKindV0;
  ledger?: CanonicalPipelineLedgerPolicyV0;
  attestation?: CanonicalPipelineAttestationRequestV0 | null;
  expectedResult?: ScenarioResultV0;
  tamperPublicInputs?: { byteOffset: number; xorWith: number };
  tamperProofBindingDigest?: { byteOffset: number; xorWith: number };
  head?: CanonicalPipelineSettlementHeadRequestV0;
  walletBinding?: CanonicalPipelineWalletBindingV0;
  tokenAnchor?: CanonicalPipelineTokenAnchorV0;
  headStatePath?: string;
  stateless?: boolean;
  fixtureName?: string;
}

export class ExecutionErrorV0 extends Error {
  readonly code:
    | "DuplicateAccountId"
    | "UnsupportedTxVersion"
    | "ZeroAmount"
    | "SelfTransfer"
    | "MissingSender"
    | "MissingRecipient"
    | "NonceMismatch"
    | "InsufficientBalance"
    | "RecipientBalanceOverflow";

  constructor(code: ExecutionErrorV0["code"], message: string) {
    super(message);
    this.name = "ExecutionErrorV0";
    this.code = code;
  }
}

export class AuraTypescriptSdkErrorV0 extends Error {
  readonly code:
    | "InvalidLength"
    | "InvalidHex"
    | "InvalidFixture"
    | "RustBridgeFailure";

  constructor(code: AuraTypescriptSdkErrorV0["code"], message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuraTypescriptSdkErrorV0";
    this.code = code;
  }
}

export class StateV0 {
  readonly #accounts: Map<string, AccountV0>;

  constructor(accounts: Iterable<AccountV0>) {
    const map = new Map<string, AccountV0>();
    for (const account of accounts) {
      const normalized = normalizeAccountV0(account);
      const key = hexFromBytesV0(normalized.accountId);
      if (map.has(key)) {
        throw new ExecutionErrorV0("DuplicateAccountId", `duplicate account id: ${key}`);
      }
      map.set(key, normalized);
    }
    this.#accounts = map;
  }

  account(accountId: Uint8Array): AccountV0 | undefined {
    return this.#accounts.get(hexFromBytesV0(copyBytes32V0("accountId", accountId)));
  }

  orderedAccounts(): AccountV0[] {
    return [...this.#accounts.values()]
      .map(cloneAccountV0)
      .sort((a, b) => compareBytesV0(a.accountId, b.accountId));
  }

  stateRoot(): Uint8Array {
    const accounts = this.orderedAccounts();
    if (accounts.length === 0) {
      return sha256BytesV0(AURA_L2_LOCAL_STATE_EMPTY_DOMAIN_SEPARATOR_V1);
    }

    const preimage = concatBytesV0(
      AURA_L2_LOCAL_STATE_ROOT_DOMAIN_SEPARATOR_V1,
      u64ToLeBytesV0(BigInt(accounts.length)),
      ...accounts.map((account) => accountLeafHashV0(account)),
    );
    return sha256BytesV0(preimage);
  }
}

export class GenesisBuilderV0 {
  #accounts: AccountV0[] = [];

  account(accountId: Uint8Array, balance: bigint | number, nonce: bigint | number): this {
    this.#accounts.push({
      accountId: copyBytes32V0("accountId", accountId),
      balance: toU64BigIntV0(balance, "account.balance"),
      nonce: toU64BigIntV0(nonce, "account.nonce"),
    });
    return this;
  }

  buildState(): StateV0 {
    return new StateV0(this.#accounts);
  }
}

export class BatchBuilderV0 {
  #batchNumber: bigint;
  #parentBatchCommitment: Uint8Array = copyBytesV0(ZERO32_V0);
  #transactions: TransferTxV0[] = [];

  constructor(batchNumber: bigint | number) {
    this.#batchNumber = toU64BigIntV0(batchNumber, "batch.batchNumber");
  }

  withParentBatchCommitment(parentBatchCommitment: Uint8Array): this {
    this.#parentBatchCommitment = copyBytes32V0(
      "parentBatchCommitment",
      parentBatchCommitment,
    );
    return this;
  }

  transfer(
    senderAccountId: Uint8Array,
    recipientAccountId: Uint8Array,
    senderNonce: bigint | number,
    amount: bigint | number,
  ): this {
    this.#transactions.push(
      transferTxV0(senderAccountId, recipientAccountId, senderNonce, amount),
    );
    return this;
  }

  build(): BatchV0 {
    return {
      batchNumber: this.#batchNumber,
      parentBatchCommitment: copyBytesV0(this.#parentBatchCommitment),
      transactions: this.#transactions.map(cloneTransferTxV0),
    };
  }
}

export function accountV0(
  accountId: Uint8Array,
  balance: bigint | number,
  nonce: bigint | number,
): AccountV0 {
  return {
    accountId: copyBytes32V0("accountId", accountId),
    balance: toU64BigIntV0(balance, "account.balance"),
    nonce: toU64BigIntV0(nonce, "account.nonce"),
  };
}

export function transferTxV0(
  senderAccountId: Uint8Array,
  recipientAccountId: Uint8Array,
  senderNonce: bigint | number,
  amount: bigint | number,
): TransferTxV0 {
  return {
    txVersion: TRANSFER_TX_VERSION_V0,
    senderAccountId: copyBytes32V0("senderAccountId", senderAccountId),
    recipientAccountId: copyBytes32V0("recipientAccountId", recipientAccountId),
    senderNonce: toU64BigIntV0(senderNonce, "transaction.senderNonce"),
    amount: toU64BigIntV0(amount, "transaction.amount"),
  };
}

export function executionConfigV0(rollupId: Uint8Array): ExecutionConfigV0 {
  return {
    rollupId: copyBytes32V0("rollupId", rollupId),
    executionModelVersion: EXECUTION_MODEL_VERSION_V0,
    batchVersion: BATCH_VERSION_V0,
  };
}

export function loadGenesisFixtureV0(filePath: string): {
  fixtureName: string;
  rollupId: Uint8Array;
  state: StateV0;
} {
  const parsed = parseJsonFileRecordV0(filePath, "genesis fixture");
  assertOnlyAllowedKeysV0(
    parsed,
    ["fixture_schema_version", "fixture_name", "rollup_id_hex", "accounts"],
    "genesis fixture",
  );
  const fixtureSchemaVersion = safeJsonU32V0(
    numberFieldV0(parsed, "fixture_schema_version", "genesis fixture"),
    "genesis.fixture_schema_version",
  );
  if (fixtureSchemaVersion !== LOCAL_CHAIN_GENESIS_FIXTURE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported genesis fixture_schema_version: ${fixtureSchemaVersion}`,
    );
  }
  const fixtureName = stringFieldV0(parsed, "fixture_name", "genesis fixture");
  if (fixtureName !== GENESIS_FIXTURE_NAME_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unexpected genesis fixture name: ${fixtureName}`,
    );
  }
  const accounts = arrayFieldV0(parsed, "accounts", "genesis fixture");
  const state = new StateV0(
    accounts.map((account) => {
      const record = recordValueV0(account, "genesis fixture account");
      assertOnlyAllowedKeysV0(
        record,
        ["account_id_hex", "balance", "nonce"],
        "genesis fixture account",
      );
      return accountV0(
        bytesFromHexV0(stringFieldV0(record, "account_id_hex", "genesis fixture account")),
        safeJsonU64V0(
          numberFieldV0(record, "balance", "genesis fixture account"),
          "genesis.accounts[].balance",
        ),
        safeJsonU64V0(
          numberFieldV0(record, "nonce", "genesis fixture account"),
          "genesis.accounts[].nonce",
        ),
      );
    }),
  );
  return {
    fixtureName,
    rollupId: bytesFromHexV0(stringFieldV0(parsed, "rollup_id_hex", "genesis fixture")),
    state,
  };
}

export function loadCanonicalPipelineRequestV0(filePath: string): CanonicalPipelineRequestV0 {
  const parsed = parseJsonFileRecordV0(filePath, "canonical pipeline request");
  assertOnlyAllowedKeysV0(
    parsed,
    [
      "pipeline_schema_version",
      "pipeline_id",
      "fixture_name",
      "proof_system",
      "economic",
      "accounting",
      "ledger",
      "head",
      "wallet_binding",
      "token_anchor",
      "attestation",
      "genesis",
      "batch",
      "tamper_public_inputs",
      "tamper_proof_binding_digest",
      "expected_result",
    ],
    "canonical pipeline request",
  );
  const pipelineSchemaVersion = safeJsonU32V0(
    numberFieldV0(parsed, "pipeline_schema_version", "canonical pipeline request"),
    "canonical_pipeline.pipeline_schema_version",
  );
  if (pipelineSchemaVersion !== LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline schema version: ${pipelineSchemaVersion}`,
    );
  }
  const pipelineId = stringFieldV0(parsed, "pipeline_id", "canonical pipeline request");
  if (pipelineId !== LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline id: ${pipelineId}`,
    );
  }
  const fixtureName = stringFieldV0(parsed, "fixture_name", "canonical pipeline request");
  if (fixtureName.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.fixture_name must not be empty",
    );
  }
  const economic = parseCanonicalPipelineEconomicPolicyV0(
    recordFieldV0(parsed, "economic", "canonical pipeline request"),
    "canonical pipeline request.economic",
  );
  const accounting = parseCanonicalPipelineAccountingPolicyV0(
    recordFieldV0(parsed, "accounting", "canonical pipeline request"),
    "canonical pipeline request.accounting",
  );
  const ledger = parseCanonicalPipelineLedgerPolicyV0(
    recordFieldV0(parsed, "ledger", "canonical pipeline request"),
    "canonical pipeline request.ledger",
  );
  const head = parseCanonicalPipelineSettlementHeadRequestV0(
    recordFieldV0(parsed, "head", "canonical pipeline request"),
    "canonical pipeline request.head",
  );
  const walletBinding = parseCanonicalPipelineWalletBindingV0(
    recordFieldV0(parsed, "wallet_binding", "canonical pipeline request"),
    "canonical pipeline request.wallet_binding",
  );
  const tokenAnchor = parseCanonicalPipelineTokenAnchorV0(
    recordFieldV0(parsed, "token_anchor", "canonical pipeline request"),
    "canonical pipeline request.token_anchor",
  );
  const attestation = parseCanonicalPipelineAttestationRequestV0(
    optionalRecordFieldV0(parsed, "attestation", "canonical pipeline request"),
    "canonical pipeline request.attestation",
  );

  const genesis = recordFieldV0(parsed, "genesis", "canonical pipeline request");
  assertOnlyAllowedKeysV0(
    genesis,
    ["rollup_id_hex", "accounts"],
    "canonical pipeline request.genesis",
  );
  const state = new StateV0(
    arrayFieldV0(genesis, "accounts", "canonical pipeline request.genesis").map((account) => {
      const record = recordValueV0(account, "canonical pipeline request.genesis account");
      assertOnlyAllowedKeysV0(
        record,
        ["account_id_hex", "balance", "nonce"],
        "canonical pipeline request.genesis account",
      );
      return accountV0(
        bytesFromHexV0(
          stringFieldV0(record, "account_id_hex", "canonical pipeline request.genesis account"),
        ),
        safeJsonU64V0(
          numberFieldV0(record, "balance", "canonical pipeline request.genesis account"),
          "canonical_pipeline.genesis.accounts[].balance",
        ),
        safeJsonU64V0(
          numberFieldV0(record, "nonce", "canonical pipeline request.genesis account"),
          "canonical_pipeline.genesis.accounts[].nonce",
        ),
      );
    }),
  );

  const batchRecord = recordFieldV0(parsed, "batch", "canonical pipeline request");
  assertOnlyAllowedKeysV0(
    batchRecord,
    ["batch_number", "parent_batch_commitment_hex", "transactions"],
    "canonical pipeline request.batch",
  );
  const batch: BatchV0 = {
    batchNumber: safeJsonU64V0(
      numberFieldV0(batchRecord, "batch_number", "canonical pipeline request.batch"),
      "canonical_pipeline.batch.batch_number",
    ),
    parentBatchCommitment: bytesFromHexV0(
      stringFieldV0(
        batchRecord,
        "parent_batch_commitment_hex",
        "canonical pipeline request.batch",
      ),
    ),
    transactions: arrayFieldV0(
      batchRecord,
      "transactions",
      "canonical pipeline request.batch",
    ).map((tx) => {
      const record = recordValueV0(tx, "canonical pipeline request.batch transaction");
      assertOnlyAllowedKeysV0(
        record,
        ["sender_account_id_hex", "recipient_account_id_hex", "sender_nonce", "amount"],
        "canonical pipeline request.batch transaction",
      );
      return transferTxV0(
        bytesFromHexV0(
          stringFieldV0(
            record,
            "sender_account_id_hex",
            "canonical pipeline request.batch transaction",
          ),
        ),
        bytesFromHexV0(
          stringFieldV0(
            record,
            "recipient_account_id_hex",
            "canonical pipeline request.batch transaction",
          ),
        ),
        safeJsonU64V0(
          numberFieldV0(record, "sender_nonce", "canonical pipeline request.batch transaction"),
          "canonical_pipeline.batch.transactions[].sender_nonce",
        ),
        safeJsonU64V0(
          numberFieldV0(record, "amount", "canonical pipeline request.batch transaction"),
          "canonical_pipeline.batch.transactions[].amount",
        ),
      );
    }),
  };

  const tamperPublicInputs = parseOptionalTamperFieldV0(
    parsed,
    "tamper_public_inputs",
    "canonical pipeline request",
    PUBLIC_INPUT_SCHEMA_LEN_V0,
    "public input bytes",
  );
  const tamperProofBindingDigest = parseOptionalTamperFieldV0(
    parsed,
    "tamper_proof_binding_digest",
    "canonical pipeline request",
    HASH_LEN_V0,
    "proof binding digest",
  );

  const request: CanonicalPipelineRequestV0 = {
    pipelineSchemaVersion,
    pipelineId,
    fixtureName,
    proofSystem: parseProofSystemV0(
      stringFieldV0(parsed, "proof_system", "canonical pipeline request"),
    ),
    economic,
    accounting,
    ledger,
    head,
    walletBinding,
    tokenAnchor,
    attestation,
    state,
    rollupId: bytesFromHexV0(
      stringFieldV0(genesis, "rollup_id_hex", "canonical pipeline request.genesis"),
    ),
    batch,
    expectedResult: parseRustExpectedResultV0(
      stringFieldV0(parsed, "expected_result", "canonical pipeline request"),
    ),
    tamperPublicInputs,
    tamperProofBindingDigest,
  };
  validateCanonicalPipelineRequestV0(request);
  return request;
}

function parseCanonicalPipelineAccountingPolicyV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAccountingPolicyV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["accounting_policy_version", "payment_intent", "settlement_intent"],
    label,
  );
  return {
    accountingPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "accounting_policy_version", label),
      `${label}.accounting_policy_version`,
    ),
    paymentIntent: parseCanonicalPipelinePaymentIntentV0(
      stringFieldV0(record, "payment_intent", label),
      `${label}.payment_intent`,
    ),
    settlementIntent: parseCanonicalPipelineSettlementIntentV0(
      stringFieldV0(record, "settlement_intent", label),
      `${label}.settlement_intent`,
    ),
  };
}

function parseCanonicalPipelineLedgerPolicyV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineLedgerPolicyV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "ledger_policy_version",
      "payer_account_id_hex",
      "total_supply",
      "burned_supply",
      "accounts",
    ],
    label,
  );
  return {
    ledgerPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "ledger_policy_version", label),
      `${label}.ledger_policy_version`,
    ),
    payerAccountId: bytesFromHexV0(stringFieldV0(record, "payer_account_id_hex", label)),
    totalSupply: safeJsonU64V0(
      numberFieldV0(record, "total_supply", label),
      `${label}.total_supply`,
    ),
    burnedSupply: safeJsonU64V0(
      numberFieldV0(record, "burned_supply", label),
      `${label}.burned_supply`,
    ),
    accounts: arrayFieldV0(record, "accounts", label).map((account) => {
      const item = recordValueV0(account, `${label}.accounts[]`);
      assertOnlyAllowedKeysV0(item, ["account_id_hex", "balance"], `${label}.accounts[]`);
      return {
        accountId: bytesFromHexV0(stringFieldV0(item, "account_id_hex", `${label}.accounts[]`)),
        balance: safeJsonU64V0(
          numberFieldV0(item, "balance", `${label}.accounts[]`),
          `${label}.accounts[].balance`,
        ),
      };
    }),
  };
}

function parseCanonicalPipelineSettlementHeadRequestV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineSettlementHeadRequestV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["settlement_head_version", "previous_head_hash_hex", "head_sequence_number"],
    label,
  );
  return {
    settlementHeadVersion: safeJsonU32V0(
      numberFieldV0(record, "settlement_head_version", label),
      `${label}.settlement_head_version`,
    ),
    previousHeadHash: bytesFromHexV0(
      stringFieldV0(record, "previous_head_hash_hex", label),
    ),
    headSequenceNumber: safeJsonU64V0(
      numberFieldV0(record, "head_sequence_number", label),
      `${label}.head_sequence_number`,
    ),
  };
}

function parseCanonicalPipelineWalletBindingV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineWalletBindingV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["wallet_binding_version", "account_id_hex", "wallet_address"],
    label,
  );
  return {
    walletBindingVersion: safeJsonU32V0(
      numberFieldV0(record, "wallet_binding_version", label),
      `${label}.wallet_binding_version`,
    ),
    accountId: bytesFromHexV0(stringFieldV0(record, "account_id_hex", label)),
    walletAddress: stringFieldV0(record, "wallet_address", label),
  };
}

function parseCanonicalPipelineExternalBalanceReferenceV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineExternalBalanceReferenceV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["reference_id", "observed_balance", "observed_slot", "connected"],
    label,
  );
  return {
    referenceId: stringFieldV0(record, "reference_id", label),
    observedBalance: optionalU64FieldV0(record, "observed_balance", label),
    observedSlot: optionalU64FieldV0(record, "observed_slot", label),
    connected: booleanFieldV0(record, "connected", label),
  };
}

function parseCanonicalPipelineTokenAnchorV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineTokenAnchorV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "token_policy_version",
      "network_mode",
      "settlement_anchor_type",
      "external_balance_reference",
      "enforce_external_match",
      "expected_external_balance",
    ],
    label,
  );
  return {
    tokenPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "token_policy_version", label),
      `${label}.token_policy_version`,
    ),
    networkMode: parseCanonicalPipelineNetworkModeV0(
      stringFieldV0(record, "network_mode", label),
      `${label}.network_mode`,
    ),
    settlementAnchorType: parseCanonicalPipelineSettlementAnchorTypeV0(
      stringFieldV0(record, "settlement_anchor_type", label),
      `${label}.settlement_anchor_type`,
    ),
    externalBalanceReference: optionalRecordFieldV0(
      record,
      "external_balance_reference",
      label,
    )
      ? parseCanonicalPipelineExternalBalanceReferenceV0(
          recordFieldV0(record, "external_balance_reference", label),
          `${label}.external_balance_reference`,
        )
      : null,
    enforceExternalMatch: booleanFieldV0(record, "enforce_external_match", label),
    expectedExternalBalance: optionalU64FieldV0(record, "expected_external_balance", label),
  };
}

function parseCanonicalPipelineEconomicPolicyV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineEconomicPolicyV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["economic_policy_version", "request_kind", "burn_intent", "declared_fee_units"],
    label,
  );
  return {
    economicPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "economic_policy_version", label),
      `${label}.economic_policy_version`,
    ),
    requestKind: parseCanonicalPipelineRequestKindV0(
      stringFieldV0(record, "request_kind", label),
      `${label}.request_kind`,
    ),
    burnIntent: parseCanonicalPipelineBurnIntentV0(
      stringFieldV0(record, "burn_intent", label),
      `${label}.burn_intent`,
    ),
    declaredFeeUnits: safeJsonU64V0(
      numberFieldV0(record, "declared_fee_units", label),
      `${label}.declared_fee_units`,
    ),
  };
}

function parseCanonicalPipelineAttestationRequestV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineAttestationRequestV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "attestation_schema_version",
      "attestation_scope",
      "attestation_proof_kind",
      "normalization_policy_version",
      "attestation_constraints",
      "claim",
      "evidence_items",
      "tamper_stark_public_inputs_digest",
      "tamper_stark_proof_bytes",
    ],
    label,
  );
  return {
    attestationSchemaVersion: safeJsonU32V0(
      numberFieldV0(record, "attestation_schema_version", label),
      `${label}.attestation_schema_version`,
    ),
    attestationScope: parseCanonicalPipelineAttestationScopeV0(
      stringFieldV0(record, "attestation_scope", label),
      `${label}.attestation_scope`,
    ),
    attestationProofKind: parseCanonicalPipelineAttestationProofKindV0(
      stringFieldV0(record, "attestation_proof_kind", label),
      `${label}.attestation_proof_kind`,
    ),
    normalizationPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "normalization_policy_version", label),
      `${label}.normalization_policy_version`,
    ),
    attestationConstraints: parseCanonicalPipelineAttestationConstraintsV0(
      recordFieldV0(record, "attestation_constraints", label),
      `${label}.attestation_constraints`,
    ),
    claim: parseCanonicalPipelineAttestationClaimV0(
      recordFieldV0(record, "claim", label),
      `${label}.claim`,
    ),
    evidenceItems: arrayFieldV0(record, "evidence_items", label).map((item, index) => {
      const itemRecord = recordValueV0(item, `${label}.evidence_items[${index}]`);
      assertOnlyAllowedKeysV0(
        itemRecord,
        ["label", "evidence_kind", "evidence_payload", "provenance"],
        `${label}.evidence_items[${index}]`,
      );
      const evidenceKind = parseCanonicalPipelineAttestationEvidenceKindV0(
        stringFieldV0(itemRecord, "evidence_kind", `${label}.evidence_items[${index}]`),
        `${label}.evidence_items[${index}].evidence_kind`,
      );
      return {
        label: stringFieldV0(itemRecord, "label", `${label}.evidence_items[${index}]`),
        evidenceKind,
        evidencePayload: parseCanonicalPipelineAttestationEvidencePayloadV0(
          evidenceKind,
          recordFieldV0(itemRecord, "evidence_payload", `${label}.evidence_items[${index}]`),
          `${label}.evidence_items[${index}].evidence_payload`,
        ),
        provenance: parseCanonicalPipelineEvidenceProvenanceV0(
          recordFieldV0(itemRecord, "provenance", `${label}.evidence_items[${index}]`),
          `${label}.evidence_items[${index}].provenance`,
        ),
      };
    }),
    tamperStarkPublicInputsDigest: parseOptionalTamperFieldV0(
      record,
      "tamper_stark_public_inputs_digest",
      label,
      HASH_LEN_V0,
      "attestation STARK public inputs digest",
    ),
    tamperStarkProofBytes: parseOptionalTamperFieldV0(
      record,
      "tamper_stark_proof_bytes",
      label,
      Number.MAX_SAFE_INTEGER,
      "attestation STARK proof bytes",
    ),
  };
}

function parseCanonicalPipelineEvidenceSignatureV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineEvidenceSignatureV0 {
  assertOnlyAllowedKeysV0(record, ["signer_public_key_hex", "signature_hex"], label);
  return {
    signerPublicKey: bytesFromHexV0(
      stringFieldV0(record, "signer_public_key_hex", label),
    ),
    signature: bytesFromHexRawV0(stringFieldV0(record, "signature_hex", label)),
  };
}

function parseCanonicalPipelineEvidenceProvenanceV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineEvidenceProvenanceV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "provenance_policy_version",
      "provenance_type",
      "source_type",
      "source_identifier",
      "signature",
      "timestamp_unix_seconds",
    ],
    label,
  );
  return {
    provenancePolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "provenance_policy_version", label),
      `${label}.provenance_policy_version`,
    ),
    provenanceType: parseCanonicalPipelineEvidenceProvenanceTypeV0(
      stringFieldV0(record, "provenance_type", label),
      `${label}.provenance_type`,
    ),
    sourceType: stringFieldV0(record, "source_type", label),
    sourceIdentifier: stringFieldV0(record, "source_identifier", label),
    signature: optionalRecordFieldV0(record, "signature", label)
      ? parseCanonicalPipelineEvidenceSignatureV0(
          recordFieldV0(record, "signature", label),
          `${label}.signature`,
        )
      : null,
    timestampUnixSeconds: optionalU64FieldV0(record, "timestamp_unix_seconds", label),
  };
}

function parseCanonicalPipelineAttestationConstraintsV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationConstraintsV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["require_unique_labels", "max_evidence_items", "max_total_normalized_bytes"],
    label,
  );
  return {
    requireUniqueLabels: booleanFieldV0(record, "require_unique_labels", label),
    maxEvidenceItems: safeJsonU64V0(
      numberFieldV0(record, "max_evidence_items", label),
      `${label}.max_evidence_items`,
    ),
    maxTotalNormalizedBytes: safeJsonU64V0(
      numberFieldV0(record, "max_total_normalized_bytes", label),
      `${label}.max_total_normalized_bytes`,
    ),
  };
}

function parseCanonicalPipelineAttestationClaimV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationClaimV0 {
  assertOnlyAllowedKeysV0(record, ["claim_kind", "claim_payload"], label);
  const claimKind = parseCanonicalPipelineAttestationClaimKindV0(
    stringFieldV0(record, "claim_kind", label),
    `${label}.claim_kind`,
  );
  return {
    claimKind,
    claimPayload: parseCanonicalPipelineAttestationClaimPayloadV0(
      claimKind,
      recordFieldV0(record, "claim_payload", label),
      `${label}.claim_payload`,
    ),
  };
}

function parseCanonicalPipelineAttestationClaimPayloadV0(
  claimKind: CanonicalPipelineAttestationClaimKindV0,
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationClaimPayloadV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "expected_evidence_root_digest_hex",
      "target_label",
      "expected_evidence_digest_hex",
      "expected_substring_utf8",
      "field_path",
      "expected_value_utf8",
    ],
    label,
  );
  const has = (field: string): boolean => record[field] !== undefined && record[field] !== null;
  switch (claimKind) {
    case CanonicalPipelineAttestationClaimKindV0.EvidenceRootDigest:
      if (
        has("target_label") ||
        has("expected_evidence_digest_hex") ||
        has("expected_substring_utf8") ||
        has("field_path") ||
        has("expected_value_utf8")
      ) {
        throw new AuraTypescriptSdkErrorV0(
          "InvalidFixture",
          "attestation.claim.claim_payload has unsupported fields for claim_kind evidence_root_digest",
        );
      }
      return {
        expectedEvidenceRootDigest: bytesFromHexV0(
          stringFieldV0(record, "expected_evidence_root_digest_hex", label),
        ),
      };
    case CanonicalPipelineAttestationClaimKindV0.NormalizedEvidenceDigest:
      if (
        has("expected_evidence_root_digest_hex") ||
        has("expected_substring_utf8") ||
        has("field_path") ||
        has("expected_value_utf8")
      ) {
        throw new AuraTypescriptSdkErrorV0(
          "InvalidFixture",
          "attestation.claim.claim_payload has unsupported fields for claim_kind normalized_evidence_digest",
        );
      }
      return {
        targetLabel: stringFieldV0(record, "target_label", label),
        expectedEvidenceDigest: bytesFromHexV0(
          stringFieldV0(record, "expected_evidence_digest_hex", label),
        ),
      };
    case CanonicalPipelineAttestationClaimKindV0.NormalizedTextContainsUtf8:
      if (
        has("expected_evidence_root_digest_hex") ||
        has("expected_evidence_digest_hex") ||
        has("field_path") ||
        has("expected_value_utf8")
      ) {
        throw new AuraTypescriptSdkErrorV0(
          "InvalidFixture",
          "attestation.claim.claim_payload has unsupported fields for claim_kind normalized_text_contains_utf8",
        );
      }
      return {
        targetLabel: stringFieldV0(record, "target_label", label),
        expectedSubstringUtf8: stringFieldV0(record, "expected_substring_utf8", label),
      };
    case CanonicalPipelineAttestationClaimKindV0.NormalizedJsonFieldEqualsUtf8:
      if (
        has("expected_evidence_root_digest_hex") ||
        has("expected_evidence_digest_hex") ||
        has("expected_substring_utf8")
      ) {
        throw new AuraTypescriptSdkErrorV0(
          "InvalidFixture",
          "attestation.claim.claim_payload has unsupported fields for claim_kind normalized_json_field_equals_utf8",
        );
      }
      return {
        targetLabel: stringFieldV0(record, "target_label", label),
        fieldPath: arrayFieldV0(record, "field_path", label).map((segment, index) =>
          stringValueV0(segment, `${label}.field_path[${index}]`),
        ),
        expectedValueUtf8: stringFieldV0(record, "expected_value_utf8", label),
      };
    default:
      return assertUnreachableV0(claimKind);
  }
}

function parseCanonicalPipelineAttestationEvidencePayloadV0(
  _evidenceKind: CanonicalPipelineAttestationEvidenceKindV0,
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationEvidencePayloadV0 {
  assertOnlyAllowedKeysV0(record, ["payload_utf8"], label);
  return {
    payloadUtf8: stringFieldV0(record, "payload_utf8", label),
  };
}

export function loadProofVectorV0(filePath: string): ProofVectorFixtureV0 {
  const parsed = parseJsonFileRecordV0(filePath, "proof vector");
  assertOnlyAllowedKeysV0(
    parsed,
    [
      "fixture_schema_version",
      "fixture_name",
      "proof_system",
      "genesis",
      "batch",
      "expected_transition",
      "expected_public_inputs",
      "canonical_stark_proof_artifact",
      "proof_tamper",
      "expected_result",
    ],
    "proof vector",
  );
  const fixtureSchemaVersion = safeJsonU32V0(
    numberFieldV0(parsed, "fixture_schema_version", "proof vector"),
    "proof_vector.fixture_schema_version",
  );
  if (fixtureSchemaVersion !== LOCAL_CHAIN_PROOF_VECTOR_FIXTURE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported proof vector fixture_schema_version: ${fixtureSchemaVersion}`,
    );
  }
  const genesis = recordFieldV0(parsed, "genesis", "proof vector");
  assertOnlyAllowedKeysV0(genesis, ["rollup_id_hex", "accounts"], "proof vector genesis");
  const batch = recordFieldV0(parsed, "batch", "proof vector");
  assertOnlyAllowedKeysV0(
    batch,
    ["batch_number", "parent_batch_commitment_hex", "transactions"],
    "proof vector batch",
  );
  const expectedTransition = recordFieldV0(parsed, "expected_transition", "proof vector");
  assertOnlyAllowedKeysV0(
    expectedTransition,
    [
      "pre_state_root_hex",
      "post_state_root_hex",
      "transactions_commitment_hex",
      "outcomes_commitment_hex",
      "batch_context_commitment_hex",
      "fee_summary_commitment_hex",
      "post_state_accounts",
      "outcomes",
    ],
    "proof vector expected_transition",
  );
  const expectedPublicInputs = recordFieldV0(parsed, "expected_public_inputs", "proof vector");
  assertOnlyAllowedKeysV0(
    expectedPublicInputs,
    [
      "transition_binding_version",
      "rollup_id_hex",
      "execution_model_version",
      "batch_version",
      "batch_number",
      "parent_batch_commitment_hex",
      "tx_count",
      "fee_summary_commitment_hex",
      "pre_state_root_hex",
      "post_state_root_hex",
      "transactions_commitment_hex",
      "outcomes_commitment_hex",
      "batch_context_commitment_hex",
      "public_input_bytes_hex",
      "transition_binding_hash_hex",
    ],
    "proof vector expected_public_inputs",
  );
  const canonicalStarkProofArtifact = recordFieldV0(
    parsed,
    "canonical_stark_proof_artifact",
    "proof vector",
  );
  assertOnlyAllowedKeysV0(
    canonicalStarkProofArtifact,
    [
      "prover_kind",
      "proof_version",
      "public_inputs_hash_hex",
      "trace_digest_hex",
      "trace_layout_digest_hex",
      "proof_binding_digest_hex",
      "proof_bytes_hex",
    ],
    "proof vector canonical_stark_proof_artifact",
  );
  const proofTamper = optionalRecordFieldV0(parsed, "proof_tamper", "proof vector");
  if (proofTamper) {
    assertOnlyAllowedKeysV0(
      proofTamper,
      ["target", "byte_offset", "xor_with"],
      "proof vector proof_tamper",
    );
  }

  const fixture: ProofVectorFixtureV0 = {
    fixtureName: stringFieldV0(parsed, "fixture_name", "proof vector"),
    proofSystem: parseProofSystemV0(stringFieldV0(parsed, "proof_system", "proof vector")),
    genesis: {
      rollupId: bytesFromHexV0(stringFieldV0(genesis, "rollup_id_hex", "proof vector genesis")),
      accounts: arrayFieldV0(genesis, "accounts", "proof vector genesis").map((account) => {
        const record = recordValueV0(account, "proof vector genesis account");
        assertOnlyAllowedKeysV0(
          record,
          ["account_id_hex", "balance", "nonce"],
          "proof vector genesis account",
        );
        return accountV0(
          bytesFromHexV0(stringFieldV0(record, "account_id_hex", "proof vector genesis account")),
          safeJsonU64V0(
            numberFieldV0(record, "balance", "proof vector genesis account"),
            "proof_vector.genesis.accounts[].balance",
          ),
          safeJsonU64V0(
            numberFieldV0(record, "nonce", "proof vector genesis account"),
            "proof_vector.genesis.accounts[].nonce",
          ),
        );
      }),
    },
    batch: {
      batchNumber: safeJsonU64V0(
        numberFieldV0(batch, "batch_number", "proof vector batch"),
        "proof_vector.batch.batch_number",
      ),
      parentBatchCommitment: bytesFromHexV0(
        stringFieldV0(batch, "parent_batch_commitment_hex", "proof vector batch"),
      ),
      transactions: arrayFieldV0(batch, "transactions", "proof vector batch").map((tx) => {
        const record = recordValueV0(tx, "proof vector batch transaction");
        assertOnlyAllowedKeysV0(
          record,
          ["sender_account_id_hex", "recipient_account_id_hex", "sender_nonce", "amount"],
          "proof vector batch transaction",
        );
        return transferTxV0(
          bytesFromHexV0(
            stringFieldV0(record, "sender_account_id_hex", "proof vector batch transaction"),
          ),
          bytesFromHexV0(
            stringFieldV0(record, "recipient_account_id_hex", "proof vector batch transaction"),
          ),
          safeJsonU64V0(
            numberFieldV0(record, "sender_nonce", "proof vector batch transaction"),
            "proof_vector.batch.transactions[].sender_nonce",
          ),
          safeJsonU64V0(
            numberFieldV0(record, "amount", "proof vector batch transaction"),
            "proof_vector.batch.transactions[].amount",
          ),
        );
      }),
    },
    expectedTransition: {
      preStateRoot: bytesFromHexV0(
        stringFieldV0(expectedTransition, "pre_state_root_hex", "proof vector expected_transition"),
      ),
      postStateRoot: bytesFromHexV0(
        stringFieldV0(expectedTransition, "post_state_root_hex", "proof vector expected_transition"),
      ),
      transactionsCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedTransition,
          "transactions_commitment_hex",
          "proof vector expected_transition",
        ),
      ),
      outcomesCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedTransition,
          "outcomes_commitment_hex",
          "proof vector expected_transition",
        ),
      ),
      batchContextCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedTransition,
          "batch_context_commitment_hex",
          "proof vector expected_transition",
        ),
      ),
      feeSummaryCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedTransition,
          "fee_summary_commitment_hex",
          "proof vector expected_transition",
        ),
      ),
      postStateAccounts: arrayFieldV0(
        expectedTransition,
        "post_state_accounts",
        "proof vector expected_transition",
      ).map((account) => {
        const record = recordValueV0(account, "proof vector expected_transition post_state_account");
        assertOnlyAllowedKeysV0(
          record,
          ["account_id_hex", "balance", "nonce"],
          "proof vector expected_transition post_state_account",
        );
        return accountV0(
          bytesFromHexV0(
            stringFieldV0(
              record,
              "account_id_hex",
              "proof vector expected_transition post_state_account",
            ),
          ),
          safeJsonU64V0(
            numberFieldV0(
              record,
              "balance",
              "proof vector expected_transition post_state_account",
            ),
            "proof_vector.expected_transition.post_state_accounts[].balance",
          ),
          safeJsonU64V0(
            numberFieldV0(
              record,
              "nonce",
              "proof vector expected_transition post_state_account",
            ),
            "proof_vector.expected_transition.post_state_accounts[].nonce",
          ),
        );
      }),
      outcomes: arrayFieldV0(expectedTransition, "outcomes", "proof vector expected_transition").map((outcome) => {
        const record = recordValueV0(outcome, "proof vector expected_transition outcome");
        assertOnlyAllowedKeysV0(
          record,
          [
            "tx_index",
            "sender_account_id_hex",
            "consumed_nonce",
            "fee_charged",
            "touched_accounts_commitment_hex",
            "operation_result_commitment_hex",
            "status",
          ],
          "proof vector expected_transition outcome",
        );
        return {
        txIndex: safeJsonU64V0(
          numberFieldV0(record, "tx_index", "proof vector expected_transition outcome"),
          "proof_vector.expected_transition.outcomes[].tx_index",
        ),
        senderAccountId: bytesFromHexV0(
          stringFieldV0(record, "sender_account_id_hex", "proof vector expected_transition outcome"),
        ),
        consumedNonce: safeJsonU64V0(
          numberFieldV0(record, "consumed_nonce", "proof vector expected_transition outcome"),
          "proof_vector.expected_transition.outcomes[].consumed_nonce",
        ),
        feeCharged: safeJsonU64V0(
          numberFieldV0(record, "fee_charged", "proof vector expected_transition outcome"),
          "proof_vector.expected_transition.outcomes[].fee_charged",
        ),
        touchedAccountsCommitment: bytesFromHexV0(
          stringFieldV0(
            record,
            "touched_accounts_commitment_hex",
            "proof vector expected_transition outcome",
          ),
        ),
        operationResultCommitment: bytesFromHexV0(
          stringFieldV0(
            record,
            "operation_result_commitment_hex",
            "proof vector expected_transition outcome",
          ),
        ),
        status: safeJsonU8V0(
          numberFieldV0(record, "status", "proof vector expected_transition outcome"),
          "proof_vector.expected_transition.outcomes[].status",
        ),
      };
      }),
    },
    expectedPublicInputs: {
      transitionBindingVersion: safeJsonU32V0(
        numberFieldV0(
          expectedPublicInputs,
          "transition_binding_version",
          "proof vector expected_public_inputs",
        ),
        "proof_vector.expected_public_inputs.transition_binding_version",
      ),
      rollupId: bytesFromHexV0(
        stringFieldV0(expectedPublicInputs, "rollup_id_hex", "proof vector expected_public_inputs"),
      ),
      executionModelVersion: safeJsonU32V0(
        numberFieldV0(
          expectedPublicInputs,
          "execution_model_version",
          "proof vector expected_public_inputs",
        ),
        "proof_vector.expected_public_inputs.execution_model_version",
      ),
      batchVersion: safeJsonU32V0(
        numberFieldV0(expectedPublicInputs, "batch_version", "proof vector expected_public_inputs"),
        "proof_vector.expected_public_inputs.batch_version",
      ),
      batchNumber: safeJsonU64V0(
        numberFieldV0(expectedPublicInputs, "batch_number", "proof vector expected_public_inputs"),
        "proof_vector.expected_public_inputs.batch_number",
      ),
      parentBatchCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedPublicInputs,
          "parent_batch_commitment_hex",
          "proof vector expected_public_inputs",
        ),
      ),
      txCount: safeJsonU64V0(
        numberFieldV0(expectedPublicInputs, "tx_count", "proof vector expected_public_inputs"),
        "proof_vector.expected_public_inputs.tx_count",
      ),
      feeSummaryCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedPublicInputs,
          "fee_summary_commitment_hex",
          "proof vector expected_public_inputs",
        ),
      ),
      preStateRoot: bytesFromHexV0(
        stringFieldV0(expectedPublicInputs, "pre_state_root_hex", "proof vector expected_public_inputs"),
      ),
      postStateRoot: bytesFromHexV0(
        stringFieldV0(expectedPublicInputs, "post_state_root_hex", "proof vector expected_public_inputs"),
      ),
      transactionsCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedPublicInputs,
          "transactions_commitment_hex",
          "proof vector expected_public_inputs",
        ),
      ),
      outcomesCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedPublicInputs,
          "outcomes_commitment_hex",
          "proof vector expected_public_inputs",
        ),
      ),
      batchContextCommitment: bytesFromHexV0(
        stringFieldV0(
          expectedPublicInputs,
          "batch_context_commitment_hex",
          "proof vector expected_public_inputs",
        ),
      ),
      publicInputBytes: bytesFromHexRawV0(
        stringFieldV0(
          expectedPublicInputs,
          "public_input_bytes_hex",
          "proof vector expected_public_inputs",
        ),
      ),
      transitionBindingHash: bytesFromHexV0(
        stringFieldV0(
          expectedPublicInputs,
          "transition_binding_hash_hex",
          "proof vector expected_public_inputs",
        ),
      ),
    },
    canonicalStarkProofArtifact: {
      proverKind: safeJsonU32V0(
        numberFieldV0(
          canonicalStarkProofArtifact,
          "prover_kind",
          "proof vector canonical_stark_proof_artifact",
        ),
        "proof_vector.canonical_stark_proof_artifact.prover_kind",
      ),
      proofVersion: safeJsonU32V0(
        numberFieldV0(
          canonicalStarkProofArtifact,
          "proof_version",
          "proof vector canonical_stark_proof_artifact",
        ),
        "proof_vector.canonical_stark_proof_artifact.proof_version",
      ),
      publicInputsHash: bytesFromHexV0(
        stringFieldV0(
          canonicalStarkProofArtifact,
          "public_inputs_hash_hex",
          "proof vector canonical_stark_proof_artifact",
        ),
      ),
      traceDigest: bytesFromHexV0(
        stringFieldV0(
          canonicalStarkProofArtifact,
          "trace_digest_hex",
          "proof vector canonical_stark_proof_artifact",
        ),
      ),
      traceLayoutDigest: bytesFromHexV0(
        stringFieldV0(
          canonicalStarkProofArtifact,
          "trace_layout_digest_hex",
          "proof vector canonical_stark_proof_artifact",
        ),
      ),
      proofBindingDigest: bytesFromHexV0(
        stringFieldV0(
          canonicalStarkProofArtifact,
          "proof_binding_digest_hex",
          "proof vector canonical_stark_proof_artifact",
        ),
      ),
      proofBytes: bytesFromHexRawV0(
        stringFieldV0(
          canonicalStarkProofArtifact,
          "proof_bytes_hex",
          "proof vector canonical_stark_proof_artifact",
        ),
      ),
    },
    proofTamper: proofTamper
      ? {
          target: parseProofVectorTamperTargetV0(
            stringFieldV0(proofTamper, "target", "proof vector proof_tamper"),
          ),
          byteOffset: safeJsonIndexV0(
            numberFieldV0(proofTamper, "byte_offset", "proof vector proof_tamper"),
            "proof_vector.proof_tamper.byte_offset",
          ),
          xorWith: safeJsonU8V0(
            numberFieldV0(proofTamper, "xor_with", "proof vector proof_tamper"),
            "proof_vector.proof_tamper.xor_with",
          ),
        }
      : null,
    expectedResult: parseRustExpectedResultV0(
      stringFieldV0(parsed, "expected_result", "proof vector"),
    ),
  };

  validateLoadedProofVectorV0(fixture);
  return fixture;
}

export function executeBatchV0(
  preState: StateV0,
  rollupId: Uint8Array,
  batch: BatchV0,
): TransitionV0 {
  const config = executionConfigV0(rollupId);
  const txCount = BigInt(batch.transactions.length);
  const preStateRoot = preState.stateRoot();
  const transactionBytes = batch.transactions.map(transferCanonicalBytesV0);
  const transactionsCommitment = deriveTransactionsCommitmentV0(transactionBytes);
  const batchContext = batchContextV0(config);
  const contextBytes = batchContextBytesV0(batchContext);
  const batchContextCommitment = sha256BytesV0(contextBytes);
  const feeSummary = feeSummaryV0(txCount);
  const feeSummaryBytes = feeSummaryCanonicalBytesV0(feeSummary);
  const feeSummaryCommitment = sha256BytesV0(feeSummaryBytes);

  const effectiveAccounts = new Map(
    preState.orderedAccounts().map((account) => [hexFromBytesV0(account.accountId), cloneAccountV0(account)]),
  );
  const outcomes: ExecutionOutcomeV0[] = [];
  const appliedSteps: AppliedTransferStepV0[] = [];

  batch.transactions.forEach((tx, index) => {
    const txIndex = BigInt(index);
    if (tx.txVersion !== TRANSFER_TX_VERSION_V0) {
      throw new ExecutionErrorV0(
        "UnsupportedTxVersion",
        `unsupported tx version: expected ${TRANSFER_TX_VERSION_V0}, got ${tx.txVersion}`,
      );
    }
    if (tx.amount === 0n) {
      throw new ExecutionErrorV0("ZeroAmount", `zero amount at tx index ${txIndex}`);
    }
    if (bytesEqualV0(tx.senderAccountId, tx.recipientAccountId)) {
      throw new ExecutionErrorV0(
        "SelfTransfer",
        `self transfer at tx index ${txIndex} for account ${hexFromBytesV0(tx.senderAccountId)}`,
      );
    }

    const senderKey = hexFromBytesV0(tx.senderAccountId);
    const recipientKey = hexFromBytesV0(tx.recipientAccountId);
    const senderBefore = effectiveAccounts.get(senderKey);
    if (!senderBefore) {
      throw new ExecutionErrorV0(
        "MissingSender",
        `missing sender at tx index ${txIndex}: ${senderKey}`,
      );
    }
    const recipientBefore = effectiveAccounts.get(recipientKey);
    if (!recipientBefore) {
      throw new ExecutionErrorV0(
        "MissingRecipient",
        `missing recipient at tx index ${txIndex}: ${recipientKey}`,
      );
    }

    if (senderBefore.nonce !== tx.senderNonce) {
      throw new ExecutionErrorV0(
        "NonceMismatch",
        `nonce mismatch at tx index ${txIndex}: expected ${senderBefore.nonce}, got ${tx.senderNonce}`,
      );
    }
    if (senderBefore.balance < tx.amount) {
      throw new ExecutionErrorV0(
        "InsufficientBalance",
        `insufficient balance at tx index ${txIndex}: available ${senderBefore.balance}, required ${tx.amount}`,
      );
    }

    const recipientAfterBalance = recipientBefore.balance + tx.amount;
    if (recipientAfterBalance > 0xffff_ffff_ffff_ffffn) {
      throw new ExecutionErrorV0(
        "RecipientBalanceOverflow",
        `recipient balance overflow at tx index ${txIndex}`,
      );
    }

    const senderAfter: AccountV0 = {
      accountId: copyBytesV0(senderBefore.accountId),
      balance: senderBefore.balance - tx.amount,
      nonce: senderBefore.nonce + 1n,
    };
    const recipientAfter: AccountV0 = {
      accountId: copyBytesV0(recipientBefore.accountId),
      balance: recipientAfterBalance,
      nonce: recipientBefore.nonce,
    };

    effectiveAccounts.set(senderKey, senderAfter);
    effectiveAccounts.set(recipientKey, recipientAfter);

    const touchedAccountsCommitment = deriveTouchedAccountsCommitmentV0(
      tx.senderAccountId,
      tx.recipientAccountId,
    );
    const operationResultCommitment = deriveTransferResultCommitmentV0(
      tx.amount,
      senderBefore.balance,
      senderAfter.balance,
      recipientBefore.balance,
      recipientAfter.balance,
    );

    outcomes.push({
      txIndex,
      senderAccountId: copyBytesV0(tx.senderAccountId),
      consumedNonce: senderBefore.nonce,
      feeCharged: ZERO_FEE_PER_TRANSFER_V0,
      touchedAccountsCommitment,
      operationResultCommitment,
      status: EXECUTION_OUTCOME_STATUS_APPLIED_V0,
    });

    appliedSteps.push({
      txIndex,
      senderAccountId: copyBytesV0(tx.senderAccountId),
      recipientAccountId: copyBytesV0(tx.recipientAccountId),
      senderNonceBefore: senderBefore.nonce,
      senderNonceAfter: senderAfter.nonce,
      senderBalanceBefore: senderBefore.balance,
      senderBalanceAfter: senderAfter.balance,
      recipientBalanceBefore: recipientBefore.balance,
      recipientBalanceAfter: recipientAfter.balance,
      amount: tx.amount,
      feeCharged: ZERO_FEE_PER_TRANSFER_V0,
    });
  });

  const postState = new StateV0(effectiveAccounts.values());
  const postStateRoot = postState.stateRoot();
  const outcomeBytes = outcomes.map(outcomeCanonicalBytesV0);
  const outcomesCommitment = deriveOutcomesCommitmentV0(outcomeBytes);

  return {
    config,
    batchNumber: batch.batchNumber,
    parentBatchCommitment: copyBytesV0(batch.parentBatchCommitment),
    txCount,
    preState,
    postState,
    preStateRoot,
    postStateRoot,
    transactions: batch.transactions.map(cloneTransferTxV0),
    transactionBytes,
    transactionsCommitment,
    outcomes,
    outcomeBytes,
    outcomesCommitment,
    batchContext,
    contextBytes,
    batchContextCommitment,
    feeSummary,
    feeSummaryBytes,
    feeSummaryCommitment,
    appliedSteps,
  };
}

export function deriveTransitionArtifactsV0(transition: TransitionV0): TransitionArtifactsV0 {
  const publicInputs = publicInputsFromTransitionV0(transition);
  const publicInputBytes = encodePublicInputsV0(publicInputs);
  const transitionClaim = transitionClaimFromPublicInputsV0(publicInputs);
  const transitionBindingHash = transitionBindingHashV0(publicInputBytes);
  return {
    transition,
    publicInputs,
    publicInputBytes,
    transitionClaim,
    transitionBindingHash,
  };
}

export function publicInputsFromTransitionV0(transition: TransitionV0): PublicInputsV0 {
  return {
    transitionBindingVersion: TRANSITION_BINDING_VERSION_V0,
    rollupId: copyBytesV0(transition.config.rollupId),
    executionModelVersion: transition.config.executionModelVersion,
    batchVersion: transition.config.batchVersion,
    batchNumber: transition.batchNumber,
    parentBatchCommitment: copyBytesV0(transition.parentBatchCommitment),
    txCount: transition.txCount,
    feeSummaryCommitment: copyBytesV0(transition.feeSummaryCommitment),
    preStateRoot: copyBytesV0(transition.preStateRoot),
    postStateRoot: copyBytesV0(transition.postStateRoot),
    transactionsCommitment: copyBytesV0(transition.transactionsCommitment),
    outcomesCommitment: copyBytesV0(transition.outcomesCommitment),
    batchContextCommitment: copyBytesV0(transition.batchContextCommitment),
  };
}

export function transitionClaimFromPublicInputsV0(publicInputs: PublicInputsV0): TransitionClaimV0 {
  return {
    preStateRoot: copyBytesV0(publicInputs.preStateRoot),
    postStateRoot: copyBytesV0(publicInputs.postStateRoot),
    transactionsCommitment: copyBytesV0(publicInputs.transactionsCommitment),
    outcomesCommitment: copyBytesV0(publicInputs.outcomesCommitment),
    batchContextCommitment: copyBytesV0(publicInputs.batchContextCommitment),
  };
}

export function encodePublicInputsV0(publicInputs: PublicInputsV0): Uint8Array {
  return concatBytesV0(
    u32ToLeBytesV0(publicInputs.transitionBindingVersion),
    copyBytes32V0("rollupId", publicInputs.rollupId),
    u32ToLeBytesV0(publicInputs.executionModelVersion),
    u32ToLeBytesV0(publicInputs.batchVersion),
    u64ToLeBytesV0(publicInputs.batchNumber),
    copyBytes32V0("parentBatchCommitment", publicInputs.parentBatchCommitment),
    u64ToLeBytesV0(publicInputs.txCount),
    copyBytes32V0("feeSummaryCommitment", publicInputs.feeSummaryCommitment),
    copyBytes32V0("preStateRoot", publicInputs.preStateRoot),
    copyBytes32V0("postStateRoot", publicInputs.postStateRoot),
    copyBytes32V0("transactionsCommitment", publicInputs.transactionsCommitment),
    copyBytes32V0("outcomesCommitment", publicInputs.outcomesCommitment),
    copyBytes32V0("batchContextCommitment", publicInputs.batchContextCommitment),
  );
}

export function transitionBindingHashV0(publicInputBytes: Uint8Array): Uint8Array {
  if (publicInputBytes.length !== PUBLIC_INPUT_SCHEMA_LEN_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidLength",
      `invalid public input length: expected ${PUBLIC_INPUT_SCHEMA_LEN_V0}, got ${publicInputBytes.length}`,
    );
  }
  return sha256BytesV0(concatBytesV0(D_BINDING_V1, publicInputBytes));
}

export function runRustScenarioV0(
  genesisPath: string,
  scenarioPath: string,
  proofSystem: ProofSystemV0 = ProofSystemV0.Mock,
): ScenarioReportV0 {
  const request = canonicalPipelineRequestFromLegacyFixturesV0(
    genesisPath,
    scenarioPath,
    proofSystem,
  );
  return scenarioReportFromCanonicalPipelineReportV0(
    runCanonicalPipelineRequestObjectV0(request),
  );
}

export interface CanonicalPipelineRunOptionsV0 {
  headStatePath?: string;
  stateless?: boolean;
}

export function runCanonicalPipelineV0(
  filePath: string,
  options: CanonicalPipelineRunOptionsV0 = {},
): CanonicalPipelineReportV0 {
  const request = loadCanonicalPipelineRequestV0(filePath);
  const args: string[] = [];
  if (options.headStatePath !== undefined) {
    args.push("--head-state", options.headStatePath);
  }
  if (options.stateless === true) {
    args.push("--stateless");
  }
  args.push("run-canonical-pipeline", filePath);
  const report = parseRustCanonicalPipelineReportJsonV0(
    runRustLocalChainJsonTextV0(args),
  );
  assertCanonicalPipelineReportMatchesRequestV0(report, request);
  return report;
}

export function runProofVectorV0(filePath: string): ProofVectorReportV0 {
  loadProofVectorV0(filePath);
  return parseRustProofVectorReportJsonV0(
    runRustLocalChainJsonTextV0(["run-proof-vector", filePath]),
  );
}

export function verifyProofVectorV0(filePath: string): ProofVectorReportV0 {
  loadProofVectorV0(filePath);
  return parseRustProofVectorReportJsonV0(
    runRustLocalChainJsonTextV0(["verify-proof-vector", filePath]),
  );
}

export function parseRustScenarioReportJsonV0(jsonText: string): ScenarioReportV0 {
  return parseRustScenarioReportV0(parseRustBridgeJsonTextV0(jsonText));
}

export function parseRustCanonicalPipelineReportJsonV0(
  jsonText: string,
): CanonicalPipelineReportV0 {
  return parseRustCanonicalPipelineReportV0(parseRustBridgeJsonTextV0(jsonText));
}

export function parseRustProofVectorReportJsonV0(jsonText: string): ProofVectorReportV0 {
  return parseRustProofVectorReportV0(parseRustBridgeJsonTextV0(jsonText));
}

function validateLoadedProofVectorV0(fixture: ProofVectorFixtureV0): void {
  if (fixture.fixtureName.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector fixtureName must not be empty",
    );
  }
  if (fixture.proofSystem !== ProofSystemV0.Stark) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vectors currently support only the STARK proof system",
    );
  }
  if (fixture.expectedPublicInputs.publicInputBytes.length !== PUBLIC_INPUT_SCHEMA_LEN_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `invalid proof vector public-input length: expected ${PUBLIC_INPUT_SCHEMA_LEN_V0}, got ${fixture.expectedPublicInputs.publicInputBytes.length}`,
    );
  }
  if (fixture.canonicalStarkProofArtifact.proverKind !== LOCAL_PROVER_KIND_STARK_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical STARK prover kind: ${fixture.canonicalStarkProofArtifact.proverKind}`,
    );
  }
  if (fixture.canonicalStarkProofArtifact.proofVersion !== LOCAL_STARK_PROOF_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical STARK proof version: ${fixture.canonicalStarkProofArtifact.proofVersion}`,
    );
  }
  if (fixture.canonicalStarkProofArtifact.proofBytes.length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical STARK proof bytes must not be empty",
    );
  }

  if (fixture.proofTamper) {
    if (
      fixture.proofTamper.target === ProofVectorTamperTargetV0.ProofBindingDigest &&
      fixture.proofTamper.byteOffset >= HASH_LEN_V0
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `proof-binding-digest tamper offset ${fixture.proofTamper.byteOffset} out of range`,
      );
    }
    if (
      fixture.proofTamper.target === ProofVectorTamperTargetV0.ProofBytes &&
      fixture.proofTamper.byteOffset >= fixture.canonicalStarkProofArtifact.proofBytes.length
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `proof-bytes tamper offset ${fixture.proofTamper.byteOffset} out of range`,
      );
    }
  }
  if (fixture.proofTamper === null && fixture.expectedResult !== ScenarioResultV0.Accepted) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "untampered proof vectors must expect acceptance under the verified foundation",
    );
  }
  if (
    fixture.expectedResult !== ScenarioResultV0.Accepted &&
    fixture.expectedResult !== ScenarioResultV0.VerificationRejected
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vectors currently allow only Accepted or VerificationRejected expected results",
    );
  }

  const recomputedPublicInputBytes = encodePublicInputsV0({
    transitionBindingVersion: fixture.expectedPublicInputs.transitionBindingVersion,
    rollupId: fixture.expectedPublicInputs.rollupId,
    executionModelVersion: fixture.expectedPublicInputs.executionModelVersion,
    batchVersion: fixture.expectedPublicInputs.batchVersion,
    batchNumber: fixture.expectedPublicInputs.batchNumber,
    parentBatchCommitment: fixture.expectedPublicInputs.parentBatchCommitment,
    txCount: fixture.expectedPublicInputs.txCount,
    feeSummaryCommitment: fixture.expectedPublicInputs.feeSummaryCommitment,
    preStateRoot: fixture.expectedPublicInputs.preStateRoot,
    postStateRoot: fixture.expectedPublicInputs.postStateRoot,
    transactionsCommitment: fixture.expectedPublicInputs.transactionsCommitment,
    outcomesCommitment: fixture.expectedPublicInputs.outcomesCommitment,
    batchContextCommitment: fixture.expectedPublicInputs.batchContextCommitment,
  });

  if (!bytesEqualV0(recomputedPublicInputBytes, fixture.expectedPublicInputs.publicInputBytes)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector public-input bytes do not match the encoded field values",
    );
  }

  const recomputedTransitionBindingHash = transitionBindingHashV0(
    fixture.expectedPublicInputs.publicInputBytes,
  );
  if (
    !bytesEqualV0(
      recomputedTransitionBindingHash,
      fixture.expectedPublicInputs.transitionBindingHash,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector transition-binding hash does not match the stored public-input bytes",
    );
  }

  const executed = executeBatchV0(
    new StateV0(fixture.genesis.accounts),
    fixture.genesis.rollupId,
    fixture.batch,
  );
  const derived = deriveTransitionArtifactsV0(executed);
  if (!bytesEqualV0(derived.transition.preStateRoot, fixture.expectedTransition.preStateRoot)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector pre-state root does not match execution-derived value",
    );
  }
  if (!bytesEqualV0(derived.transition.postStateRoot, fixture.expectedTransition.postStateRoot)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector post-state root does not match execution-derived value",
    );
  }
  if (
    !bytesEqualV0(
      derived.transition.transactionsCommitment,
      fixture.expectedTransition.transactionsCommitment,
    ) ||
    !bytesEqualV0(
      derived.transition.outcomesCommitment,
      fixture.expectedTransition.outcomesCommitment,
    ) ||
    !bytesEqualV0(
      derived.transition.batchContextCommitment,
      fixture.expectedTransition.batchContextCommitment,
    ) ||
    !bytesEqualV0(
      derived.transition.feeSummaryCommitment,
      fixture.expectedTransition.feeSummaryCommitment,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector transition commitments do not match execution-derived values",
    );
  }
  if (
    !accountListsEqualV0(
      derived.transition.postState.orderedAccounts(),
      fixture.expectedTransition.postStateAccounts,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector post-state accounts do not match execution-derived values",
    );
  }
  if (!outcomeListsEqualV0(derived.transition.outcomes, fixture.expectedTransition.outcomes)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector outcomes do not match execution-derived values",
    );
  }
  if (
    !bytesEqualV0(derived.publicInputBytes, fixture.expectedPublicInputs.publicInputBytes) ||
    !bytesEqualV0(
      derived.transitionBindingHash,
      fixture.expectedPublicInputs.transitionBindingHash,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "proof vector expected public inputs do not match execution-derived values",
    );
  }

  const publicInputsHash = sha256BytesV0(fixture.expectedPublicInputs.publicInputBytes);
  if (
    !bytesEqualV0(publicInputsHash, fixture.canonicalStarkProofArtifact.publicInputsHash)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical STARK proof public_inputs_hash does not match the stored public inputs",
    );
  }
  const proofBindingDigest = deriveStarkProofBindingDigestV0(
    fixture.canonicalStarkProofArtifact.proofVersion,
    fixture.canonicalStarkProofArtifact.publicInputsHash,
    fixture.canonicalStarkProofArtifact.traceDigest,
    fixture.canonicalStarkProofArtifact.traceLayoutDigest,
    fixture.canonicalStarkProofArtifact.proofBytes,
  );
  if (
    !bytesEqualV0(proofBindingDigest, fixture.canonicalStarkProofArtifact.proofBindingDigest)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical STARK proof binding digest is inconsistent with the stored proof artifact",
    );
  }
}

export function runRustFlowV0(options: RustBridgeFlowOptionsV0): {
  proofArtifact: ProofArtifactV0;
  report: ScenarioReportV0;
} {
  validateRustBridgeFlowOptionsV0(options);
  const normalizedProofSystem = normalizeProofSystemV0(options.proofSystem);
  const report = runCanonicalPipelineRequestObjectV0(
    canonicalPipelineRequestFromBridgeOptionsV0(options),
    {
      headStatePath: options.headStatePath,
      stateless: options.stateless,
    },
  );

  return {
    proofArtifact:
      normalizedProofSystem === ProofSystemV0.Stark
        ? {
            proofSystem: ProofSystemV0.Stark,
            backend: "rust-local-chain",
            artifactBytesExposed: false,
          }
        : {
            proofSystem: ProofSystemV0.Mock,
            backend: "rust-local-chain",
            artifactBytesExposed: false,
          },
    report: scenarioReportFromCanonicalPipelineReportV0(report),
  };
}

export function hexFromBytesV0(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function bytesFromHexV0(hex: string): Uint8Array {
  const bytes = bytesFromHexRawV0(hex);
  if (bytes.length !== HASH_LEN_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidHex",
      `expected ${HASH_LEN_V0 * 2} hex chars, got ${hex.length}`,
    );
  }
  return bytes;
}

function bytesFromHexRawV0(hex: string): Uint8Array {
  if (hex.length === 0) {
    return new Uint8Array(0);
  }
  if (hex.length !== HASH_LEN_V0 * 2) {
    if (hex.length % 2 !== 0) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidHex",
        `expected even-length hex chars, got ${hex.length}`,
      );
    }
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new AuraTypescriptSdkErrorV0("InvalidHex", "invalid hex string");
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function runRustLocalChainJsonTextV0(args: string[]): string {
  const repoRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../../..",
  );
  const result = spawnSync(
    "cargo",
    ["run", "-p", "aura_l2_local_chain_v0", "--offline", "--", "--output", "json", ...args],
    {
      cwd: repoRoot,
      encoding: "utf8",
    },
  );
  if (result.status !== 0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `rust local chain bridge failed for '${args.join(" ")}': ${(
        result.stderr ||
        result.stdout ||
        "unknown rust bridge failure"
      ).trim()}`,
    );
  }
  return result.stdout;
}

function parseRustBridgeJsonTextV0(jsonText: string): unknown {
  try {
    return JSON.parse(jsonText) as unknown;
  } catch (error) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "rust local chain bridge returned invalid JSON",
      { cause: error instanceof Error ? error : undefined },
    );
  }
}

function parseRustScenarioReportV0(value: unknown): ScenarioReportV0 {
  const envelope = parseRustScenarioBridgeEnvelopeV0(value);
  const report = recordFieldV0(envelope as Record<string, unknown>, "report", "rust_bridge");
  assertOnlyAllowedKeysV0(
    report,
    [
      "fixture_name",
      "expected_result",
      "actual_result",
      "pre_state_root_hex",
      "post_state_root_hex",
      "transition_binding_hash_hex",
    ],
    "rust_bridge.report",
  );

  return {
    fixtureName: stringFieldV0(report, "fixture_name", "rust_bridge.report"),
    expectedResult: parseScenarioResultV0(
      stringFieldV0(report, "expected_result", "rust_bridge.report"),
    ),
    actualResult: parseScenarioResultV0(
      stringFieldV0(report, "actual_result", "rust_bridge.report"),
    ),
    preStateRoot: bytesFromHexV0(
      stringFieldV0(report, "pre_state_root_hex", "rust_bridge.report"),
    ),
    postStateRoot: optionalHexFieldV0(report, "post_state_root_hex", "rust_bridge.report"),
    transitionBindingHash: optionalHexFieldV0(
      report,
      "transition_binding_hash_hex",
      "rust_bridge.report",
    ),
  };
}

function parseRustCanonicalPipelineReportV0(value: unknown): CanonicalPipelineReportV0 {
  const envelope = parseRustCanonicalPipelineBridgeEnvelopeV0(value);
  const report = recordFieldV0(envelope as Record<string, unknown>, "report", "rust_bridge");
  assertOnlyAllowedKeysV0(
    report,
    [
      "pipeline_schema_version",
      "pipeline_id",
      "fixture_name",
      "proof_system",
      "expected_result",
      "actual_result",
      "pre_state_root_hex",
      "executed_post_state_root_hex",
      "settlement_committed_state_root_hex",
      "burn_summary",
      "accounting_summary",
      "ledger_summary",
      "head_transition_summary",
      "wallet_binding_summary",
      "token_anchor_summary",
      "request_audit",
      "genesis_accounts",
      "ledger_accounts",
      "commitment_expansions",
      "stage_outcomes",
      "status_explanation",
      "attestation_summary",
      "attestation_proof_summary",
      "provenance_summary",
      "public_inputs",
      "proof_artifact",
    ],
    "rust_bridge.report",
  );

  const pipelineSchemaVersion = safeJsonU32V0(
    numberFieldV0(report, "pipeline_schema_version", "rust_bridge.report"),
    "rust_bridge.report.pipeline_schema_version",
  );
  if (pipelineSchemaVersion !== LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline schema version: ${pipelineSchemaVersion}`,
    );
  }
  const pipelineId = stringFieldV0(report, "pipeline_id", "rust_bridge.report");
  if (pipelineId !== LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline id: ${pipelineId}`,
    );
  }

  const proofSystem = parseProofSystemV0(
    stringFieldV0(report, "proof_system", "rust_bridge.report"),
  );
  const actualResult = parseScenarioResultV0(
    stringFieldV0(report, "actual_result", "rust_bridge.report"),
  );
  const canonicalReport: CanonicalPipelineReportV0 = {
    pipelineSchemaVersion,
    pipelineId,
    fixtureName: stringFieldV0(report, "fixture_name", "rust_bridge.report"),
    proofSystem,
    expectedResult: parseScenarioResultV0(
      stringFieldV0(report, "expected_result", "rust_bridge.report"),
    ),
    actualResult,
    preStateRoot: bytesFromHexV0(
      stringFieldV0(report, "pre_state_root_hex", "rust_bridge.report"),
    ),
    executedPostStateRoot: optionalHexFieldV0(
      report,
      "executed_post_state_root_hex",
      "rust_bridge.report",
    ),
    settlementCommittedStateRoot: optionalHexFieldV0(
      report,
      "settlement_committed_state_root_hex",
      "rust_bridge.report",
    ),
    burnSummary: parseCanonicalPipelineBurnSummaryV0(
      recordFieldV0(report, "burn_summary", "rust_bridge.report"),
      "rust_bridge.report.burn_summary",
    ),
    accountingSummary: parseCanonicalPipelineAccountingSummaryV0(
      recordFieldV0(report, "accounting_summary", "rust_bridge.report"),
      "rust_bridge.report.accounting_summary",
    ),
    ledgerSummary: parseCanonicalPipelineLedgerSummaryV0(
      recordFieldV0(report, "ledger_summary", "rust_bridge.report"),
      "rust_bridge.report.ledger_summary",
    ),
    headTransitionSummary: parseCanonicalPipelineHeadTransitionSummaryV0(
      recordFieldV0(report, "head_transition_summary", "rust_bridge.report"),
      "rust_bridge.report.head_transition_summary",
    ),
    walletBindingSummary: parseCanonicalPipelineWalletBindingSummaryV0(
      recordFieldV0(report, "wallet_binding_summary", "rust_bridge.report"),
      "rust_bridge.report.wallet_binding_summary",
    ),
    tokenAnchorSummary: parseCanonicalPipelineTokenAnchorSummaryV0(
      recordFieldV0(report, "token_anchor_summary", "rust_bridge.report"),
      "rust_bridge.report.token_anchor_summary",
    ),
    requestAudit: parseCanonicalPipelineRequestAuditV0(
      recordFieldV0(report, "request_audit", "rust_bridge.report"),
      "rust_bridge.report.request_audit",
    ),
    genesisAccounts: parseCanonicalPipelineGenesisAccountsV0(
      recordFieldV0(report, "genesis_accounts", "rust_bridge.report"),
      "rust_bridge.report.genesis_accounts",
    ),
    ledgerAccounts: parseCanonicalPipelineLedgerAccountsV0(
      recordFieldV0(report, "ledger_accounts", "rust_bridge.report"),
      "rust_bridge.report.ledger_accounts",
    ),
    commitmentExpansions: parseCanonicalPipelineCommitmentExpansionsV0(
      recordFieldV0(report, "commitment_expansions", "rust_bridge.report"),
      "rust_bridge.report.commitment_expansions",
    ),
    stageOutcomes: parseCanonicalPipelineStageOutcomesV0(
      recordFieldV0(report, "stage_outcomes", "rust_bridge.report"),
      "rust_bridge.report.stage_outcomes",
    ),
    statusExplanation: parseCanonicalPipelineStatusExplanationV0(
      recordFieldV0(report, "status_explanation", "rust_bridge.report"),
      "rust_bridge.report.status_explanation",
    ),
    attestationSummary: parseCanonicalPipelineAttestationSummaryV0(
      optionalRecordFieldV0(report, "attestation_summary", "rust_bridge.report"),
      "rust_bridge.report.attestation_summary",
    ),
    attestationProofSummary: parseCanonicalPipelineAttestationProofSummaryV0(
      optionalRecordFieldV0(report, "attestation_proof_summary", "rust_bridge.report"),
      "rust_bridge.report.attestation_proof_summary",
    ),
    provenanceSummary: parseCanonicalPipelineProvenanceSummaryV0(
      optionalRecordFieldV0(report, "provenance_summary", "rust_bridge.report"),
      "rust_bridge.report.provenance_summary",
    ),
    publicInputs: parseCanonicalPipelinePublicInputsAuditV0(
      optionalRecordFieldV0(report, "public_inputs", "rust_bridge.report"),
      "rust_bridge.report.public_inputs",
    ),
    proofArtifact: parseCanonicalPipelineProofArtifactAuditV0(
      optionalRecordFieldV0(report, "proof_artifact", "rust_bridge.report"),
      "rust_bridge.report.proof_artifact",
    ),
  };
  assertCanonicalPipelineReportShapeV0(canonicalReport);
  return canonicalReport;
}

function parseCanonicalPipelineRequestAuditV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineRequestAuditV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "request_binding_hash_hex",
      "genesis_accounts_digest_hex",
      "ledger_accounts_digest_hex",
      "transactions_digest_hex",
      "rollup_id_hex",
      "genesis_account_count",
      "ledger_account_count",
      "ledger_payer_account_id_hex",
      "ledger_total_supply",
      "ledger_burned_supply",
      "batch_number",
      "tx_count",
      "parent_batch_commitment_hex",
      "tamper_public_inputs",
      "tamper_proof_binding_digest",
      "tamper_attestation_stark_public_inputs_digest",
      "tamper_attestation_stark_proof_bytes",
    ],
    label,
  );
  return {
    requestBindingHash: bytesFromHexV0(stringFieldV0(record, "request_binding_hash_hex", label)),
    genesisAccountsDigest: bytesFromHexV0(
      stringFieldV0(record, "genesis_accounts_digest_hex", label),
    ),
    ledgerAccountsDigest: bytesFromHexV0(
      stringFieldV0(record, "ledger_accounts_digest_hex", label),
    ),
    transactionsDigest: bytesFromHexV0(
      stringFieldV0(record, "transactions_digest_hex", label),
    ),
    rollupId: bytesFromHexV0(stringFieldV0(record, "rollup_id_hex", label)),
    genesisAccountCount: safeJsonU64V0(
      numberFieldV0(record, "genesis_account_count", label),
      `${label}.genesis_account_count`,
    ),
    ledgerAccountCount: safeJsonU64V0(
      numberFieldV0(record, "ledger_account_count", label),
      `${label}.ledger_account_count`,
    ),
    ledgerPayerAccountId: bytesFromHexV0(
      stringFieldV0(record, "ledger_payer_account_id_hex", label),
    ),
    ledgerTotalSupply: safeJsonU64V0(
      numberFieldV0(record, "ledger_total_supply", label),
      `${label}.ledger_total_supply`,
    ),
    ledgerBurnedSupply: safeJsonU64V0(
      numberFieldV0(record, "ledger_burned_supply", label),
      `${label}.ledger_burned_supply`,
    ),
    batchNumber: safeJsonU64V0(
      numberFieldV0(record, "batch_number", label),
      `${label}.batch_number`,
    ),
    txCount: safeJsonU64V0(
      numberFieldV0(record, "tx_count", label),
      `${label}.tx_count`,
    ),
    parentBatchCommitment: bytesFromHexV0(
      stringFieldV0(record, "parent_batch_commitment_hex", label),
    ),
    tamperPublicInputs: parseOptionalTamperFieldV0(
      record,
      "tamper_public_inputs",
      label,
      PUBLIC_INPUT_SCHEMA_LEN_V0,
      "canonical pipeline public inputs",
    ),
    tamperProofBindingDigest: parseOptionalTamperFieldV0(
      record,
      "tamper_proof_binding_digest",
      label,
      HASH_LEN_V0,
      "canonical pipeline proof binding digest",
    ),
    tamperAttestationStarkPublicInputsDigest: parseOptionalTamperFieldV0(
      record,
      "tamper_attestation_stark_public_inputs_digest",
      label,
      HASH_LEN_V0,
      "canonical pipeline attestation stark public inputs digest",
    ),
    tamperAttestationStarkProofBytes: parseOptionalTamperFieldV0(
      record,
      "tamper_attestation_stark_proof_bytes",
      label,
      HASH_LEN_V0,
      "canonical pipeline attestation stark proof bytes",
    ),
  };
}

function parseCanonicalPipelineBurnSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineBurnSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "burn_policy_version",
      "burn_policy",
      "burn_reason",
      "burn_category",
      "request_kind",
      "burn_intent",
      "declared_fee_units",
      "computed_burn_units",
      "consumed_burn_units",
      "burn_derivation_inputs",
      "request_declares_correct_burn",
      "recomputed_burn_matches_report",
      "burn_consumed",
      "failure_semantics",
    ],
    label,
  );
  return {
    burnPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "burn_policy_version", label),
      `${label}.burn_policy_version`,
    ),
    burnPolicy: parseCanonicalPipelineBurnPolicyV0(
      recordFieldV0(record, "burn_policy", label),
      `${label}.burn_policy`,
    ),
    burnReason: parseCanonicalPipelineBurnReasonV0(
      stringFieldV0(record, "burn_reason", label),
      `${label}.burn_reason`,
    ),
    burnCategory: parseCanonicalPipelineBurnCategoryV0(
      stringFieldV0(record, "burn_category", label),
      `${label}.burn_category`,
    ),
    requestKind: parseCanonicalPipelineRequestKindV0(
      stringFieldV0(record, "request_kind", label),
      `${label}.request_kind`,
    ),
    burnIntent: parseCanonicalPipelineBurnIntentV0(
      stringFieldV0(record, "burn_intent", label),
      `${label}.burn_intent`,
    ),
    declaredFeeUnits: safeJsonU64V0(
      numberFieldV0(record, "declared_fee_units", label),
      `${label}.declared_fee_units`,
    ),
    computedBurnUnits: safeJsonU64V0(
      numberFieldV0(record, "computed_burn_units", label),
      `${label}.computed_burn_units`,
    ),
    consumedBurnUnits: safeJsonU64V0(
      numberFieldV0(record, "consumed_burn_units", label),
      `${label}.consumed_burn_units`,
    ),
    burnDerivationInputs: parseCanonicalPipelineBurnDerivationInputsV0(
      recordFieldV0(record, "burn_derivation_inputs", label),
      `${label}.burn_derivation_inputs`,
    ),
    requestDeclaresCorrectBurn: booleanFieldV0(
      record,
      "request_declares_correct_burn",
      label,
    ),
    recomputedBurnMatchesReport: booleanFieldV0(
      record,
      "recomputed_burn_matches_report",
      label,
    ),
    burnConsumed: booleanFieldV0(record, "burn_consumed", label),
    failureSemantics: parseCanonicalPipelineBurnFailureSemanticsV0(
      recordFieldV0(record, "failure_semantics", label),
      `${label}.failure_semantics`,
    ),
  };
}

function parseCanonicalPipelineBurnPolicyV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineBurnPolicyV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "burn_policy_version",
      "base_units",
      "execution_request_kind_units",
      "attestation_request_kind_units",
      "mock_proof_system_units",
      "stark_proof_system_units",
      "transaction_units_per_item",
      "metered_request_size_chunk_bytes",
    ],
    label,
  );
  return {
    burnPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "burn_policy_version", label),
      `${label}.burn_policy_version`,
    ),
    baseUnits: safeJsonU64V0(numberFieldV0(record, "base_units", label), `${label}.base_units`),
    executionRequestKindUnits: safeJsonU64V0(
      numberFieldV0(record, "execution_request_kind_units", label),
      `${label}.execution_request_kind_units`,
    ),
    attestationRequestKindUnits: safeJsonU64V0(
      numberFieldV0(record, "attestation_request_kind_units", label),
      `${label}.attestation_request_kind_units`,
    ),
    mockProofSystemUnits: safeJsonU64V0(
      numberFieldV0(record, "mock_proof_system_units", label),
      `${label}.mock_proof_system_units`,
    ),
    starkProofSystemUnits: safeJsonU64V0(
      numberFieldV0(record, "stark_proof_system_units", label),
      `${label}.stark_proof_system_units`,
    ),
    transactionUnitsPerItem: safeJsonU64V0(
      numberFieldV0(record, "transaction_units_per_item", label),
      `${label}.transaction_units_per_item`,
    ),
    meteredRequestSizeChunkBytes: safeJsonU64V0(
      numberFieldV0(record, "metered_request_size_chunk_bytes", label),
      `${label}.metered_request_size_chunk_bytes`,
    ),
  };
}

function parseCanonicalPipelineBurnDerivationInputsV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineBurnDerivationInputsV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "tx_count",
      "metered_request_size_bytes",
      "request_kind",
      "proof_system",
      "attestation_evidence_items",
      "attestation_claim_bytes",
      "attestation_evidence_bytes",
    ],
    label,
  );
  return {
    txCount: safeJsonU64V0(numberFieldV0(record, "tx_count", label), `${label}.tx_count`),
    meteredRequestSizeBytes: safeJsonU64V0(
      numberFieldV0(record, "metered_request_size_bytes", label),
      `${label}.metered_request_size_bytes`,
    ),
    requestKind: parseCanonicalPipelineRequestKindV0(
      stringFieldV0(record, "request_kind", label),
      `${label}.request_kind`,
    ),
    proofSystem: parseProofSystemV0(stringFieldV0(record, "proof_system", label)),
    attestationEvidenceItems: safeJsonU64V0(
      numberFieldV0(record, "attestation_evidence_items", label),
      `${label}.attestation_evidence_items`,
    ),
    attestationClaimBytes: safeJsonU64V0(
      numberFieldV0(record, "attestation_claim_bytes", label),
      `${label}.attestation_claim_bytes`,
    ),
    attestationEvidenceBytes: safeJsonU64V0(
      numberFieldV0(record, "attestation_evidence_bytes", label),
      `${label}.attestation_evidence_bytes`,
    ),
  };
}

function parseCanonicalPipelineBurnFailureSemanticsV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineBurnFailureSemanticsV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "execution_rejected_burns_full_amount",
      "verification_rejected_burns_full_amount",
      "settlement_rejected_burns_full_amount",
      "partial_burn_allowed",
    ],
    label,
  );
  return {
    executionRejectedBurnsFullAmount: booleanFieldV0(
      record,
      "execution_rejected_burns_full_amount",
      label,
    ),
    verificationRejectedBurnsFullAmount: booleanFieldV0(
      record,
      "verification_rejected_burns_full_amount",
      label,
    ),
    settlementRejectedBurnsFullAmount: booleanFieldV0(
      record,
      "settlement_rejected_burns_full_amount",
      label,
    ),
    partialBurnAllowed: booleanFieldV0(record, "partial_burn_allowed", label),
  };
}

function parseCanonicalPipelineAccountingSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAccountingSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "accounting_policy_version",
      "payment_intent",
      "settlement_intent",
      "declared_fee_units",
      "computed_burn_units",
      "consumed_burn_units",
      "burn_record",
      "settlement_record",
      "accounting_consistent_with_burn",
      "accounting_consistent_with_outcome",
    ],
    label,
  );
  return {
    accountingPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "accounting_policy_version", label),
      `${label}.accounting_policy_version`,
    ),
    paymentIntent: parseCanonicalPipelinePaymentIntentV0(
      stringFieldV0(record, "payment_intent", label),
      `${label}.payment_intent`,
    ),
    settlementIntent: parseCanonicalPipelineSettlementIntentV0(
      stringFieldV0(record, "settlement_intent", label),
      `${label}.settlement_intent`,
    ),
    declaredFeeUnits: safeJsonU64V0(
      numberFieldV0(record, "declared_fee_units", label),
      `${label}.declared_fee_units`,
    ),
    computedBurnUnits: safeJsonU64V0(
      numberFieldV0(record, "computed_burn_units", label),
      `${label}.computed_burn_units`,
    ),
    consumedBurnUnits: safeJsonU64V0(
      numberFieldV0(record, "consumed_burn_units", label),
      `${label}.consumed_burn_units`,
    ),
    burnRecord: parseCanonicalPipelineBurnRecordV0(
      recordFieldV0(record, "burn_record", label),
      `${label}.burn_record`,
    ),
    settlementRecord: parseCanonicalPipelineSettlementRecordV0(
      recordFieldV0(record, "settlement_record", label),
      `${label}.settlement_record`,
    ),
    accountingConsistentWithBurn: booleanFieldV0(
      record,
      "accounting_consistent_with_burn",
      label,
    ),
    accountingConsistentWithOutcome: booleanFieldV0(
      record,
      "accounting_consistent_with_outcome",
      label,
    ),
  };
}

function parseCanonicalPipelineBurnRecordV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineBurnRecordV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "burn_reason",
      "burn_category",
      "fee_disposition",
      "account_id_hex",
      "pre_balance",
      "post_balance",
      "burned_amount",
      "declared_fee_units",
      "computed_burn_units",
      "consumed_burn_units",
      "report_pipeline_id",
      "report_request_binding_hash_hex",
    ],
    label,
  );
  return {
    burnReason: parseCanonicalPipelineBurnReasonV0(
      stringFieldV0(record, "burn_reason", label),
      `${label}.burn_reason`,
    ),
    burnCategory: parseCanonicalPipelineBurnCategoryV0(
      stringFieldV0(record, "burn_category", label),
      `${label}.burn_category`,
    ),
    feeDisposition: parseCanonicalPipelineFeeDispositionV0(
      stringFieldV0(record, "fee_disposition", label),
      `${label}.fee_disposition`,
    ),
    accountId: bytesFromHexV0(stringFieldV0(record, "account_id_hex", label)),
    preBalance: safeJsonU64V0(
      numberFieldV0(record, "pre_balance", label),
      `${label}.pre_balance`,
    ),
    postBalance: safeJsonU64V0(
      numberFieldV0(record, "post_balance", label),
      `${label}.post_balance`,
    ),
    burnedAmount: safeJsonU64V0(
      numberFieldV0(record, "burned_amount", label),
      `${label}.burned_amount`,
    ),
    declaredFeeUnits: safeJsonU64V0(
      numberFieldV0(record, "declared_fee_units", label),
      `${label}.declared_fee_units`,
    ),
    computedBurnUnits: safeJsonU64V0(
      numberFieldV0(record, "computed_burn_units", label),
      `${label}.computed_burn_units`,
    ),
    consumedBurnUnits: safeJsonU64V0(
      numberFieldV0(record, "consumed_burn_units", label),
      `${label}.consumed_burn_units`,
    ),
    reportPipelineId: stringFieldV0(record, "report_pipeline_id", label),
    reportRequestBindingHash: bytesFromHexV0(
      stringFieldV0(record, "report_request_binding_hash_hex", label),
    ),
  };
}

function parseCanonicalPipelineLedgerSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineLedgerSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "ledger_policy_version",
      "payer_account_id_hex",
      "total_supply",
      "burned_supply_before",
      "burned_supply_after",
      "ledger_account_count",
      "circulating_supply_before",
      "circulating_supply_after",
      "ledger_consistent_with_request",
      "ledger_consistent_with_burn",
      "ledger_consistent_with_supply",
      "ledger_state_commitment",
    ],
    label,
  );
  return {
    ledgerPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "ledger_policy_version", label),
      `${label}.ledger_policy_version`,
    ),
    payerAccountId: bytesFromHexV0(stringFieldV0(record, "payer_account_id_hex", label)),
    totalSupply: safeJsonU64V0(numberFieldV0(record, "total_supply", label), `${label}.total_supply`),
    burnedSupplyBefore: safeJsonU64V0(
      numberFieldV0(record, "burned_supply_before", label),
      `${label}.burned_supply_before`,
    ),
    burnedSupplyAfter: safeJsonU64V0(
      numberFieldV0(record, "burned_supply_after", label),
      `${label}.burned_supply_after`,
    ),
    ledgerAccountCount: safeJsonU64V0(
      numberFieldV0(record, "ledger_account_count", label),
      `${label}.ledger_account_count`,
    ),
    circulatingSupplyBefore: safeJsonU64V0(
      numberFieldV0(record, "circulating_supply_before", label),
      `${label}.circulating_supply_before`,
    ),
    circulatingSupplyAfter: safeJsonU64V0(
      numberFieldV0(record, "circulating_supply_after", label),
      `${label}.circulating_supply_after`,
    ),
    ledgerConsistentWithRequest: booleanFieldV0(
      record,
      "ledger_consistent_with_request",
      label,
    ),
    ledgerConsistentWithBurn: booleanFieldV0(record, "ledger_consistent_with_burn", label),
    ledgerConsistentWithSupply: booleanFieldV0(
      record,
      "ledger_consistent_with_supply",
      label,
    ),
    ledgerStateCommitment: parseCanonicalPipelineLedgerStateCommitmentV0(
      recordFieldV0(record, "ledger_state_commitment", label),
      `${label}.ledger_state_commitment`,
    ),
  };
}

function parseCanonicalPipelineLedgerStateCommitmentV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineLedgerStateCommitmentV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "commitment_version",
      "pre_ledger_state_commitment_hex",
      "post_ledger_state_commitment_hex",
    ],
    label,
  );
  return {
    commitmentVersion: safeJsonU32V0(
      numberFieldV0(record, "commitment_version", label),
      `${label}.commitment_version`,
    ),
    preLedgerStateCommitment: bytesFromHexV0(
      stringFieldV0(record, "pre_ledger_state_commitment_hex", label),
    ),
    postLedgerStateCommitment: bytesFromHexV0(
      stringFieldV0(record, "post_ledger_state_commitment_hex", label),
    ),
  };
}

function parseCanonicalPipelineHeadTransitionSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineHeadTransitionSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "settlement_head_version",
      "authority_mode",
      "head_sequence_number",
      "previous_head_hash_hex",
      "current_head_hash_hex",
      "canonical_head_commitment_hex",
      "request_canonical_digest_hex",
      "report_digest_hex",
    ],
    label,
  );
  return {
    settlementHeadVersion: safeJsonU32V0(
      numberFieldV0(record, "settlement_head_version", label),
      `${label}.settlement_head_version`,
    ),
    authorityMode: parseCanonicalPipelineHeadAuthorityModeV0(
      stringFieldV0(record, "authority_mode", label),
      `${label}.authority_mode`,
    ),
    headSequenceNumber: safeJsonU64V0(
      numberFieldV0(record, "head_sequence_number", label),
      `${label}.head_sequence_number`,
    ),
    previousHeadHash: bytesFromHexV0(
      stringFieldV0(record, "previous_head_hash_hex", label),
    ),
    currentHeadHash: bytesFromHexV0(
      stringFieldV0(record, "current_head_hash_hex", label),
    ),
    canonicalHeadCommitment: bytesFromHexV0(
      stringFieldV0(record, "canonical_head_commitment_hex", label),
    ),
    requestCanonicalDigest: bytesFromHexV0(
      stringFieldV0(record, "request_canonical_digest_hex", label),
    ),
    reportDigest: bytesFromHexV0(stringFieldV0(record, "report_digest_hex", label)),
  };
}

function parseCanonicalPipelineWalletBindingSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineWalletBindingSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "wallet_binding_version",
      "account_id_hex",
      "wallet_address",
      "wallet_binding_digest_hex",
      "binding_consistent_with_account",
    ],
    label,
  );
  return {
    walletBindingVersion: safeJsonU32V0(
      numberFieldV0(record, "wallet_binding_version", label),
      `${label}.wallet_binding_version`,
    ),
    accountId: bytesFromHexV0(stringFieldV0(record, "account_id_hex", label)),
    walletAddress: stringFieldV0(record, "wallet_address", label),
    walletBindingDigest: bytesFromHexV0(
      stringFieldV0(record, "wallet_binding_digest_hex", label),
    ),
    bindingConsistentWithAccount: booleanFieldV0(
      record,
      "binding_consistent_with_account",
      label,
    ),
  };
}

function parseCanonicalPipelineTokenAnchorSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineTokenAnchorSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "token_policy_version",
      "network_mode",
      "settlement_anchor_type",
      "anchor_verification_status",
      "external_balance_reference",
      "expected_external_balance",
      "token_anchor_digest_hex",
    ],
    label,
  );
  return {
    tokenPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "token_policy_version", label),
      `${label}.token_policy_version`,
    ),
    networkMode: parseCanonicalPipelineNetworkModeV0(
      stringFieldV0(record, "network_mode", label),
      `${label}.network_mode`,
    ),
    settlementAnchorType: parseCanonicalPipelineSettlementAnchorTypeV0(
      stringFieldV0(record, "settlement_anchor_type", label),
      `${label}.settlement_anchor_type`,
    ),
    anchorVerificationStatus: parseCanonicalPipelineExternalAnchorVerificationStatusV0(
      stringFieldV0(record, "anchor_verification_status", label),
      `${label}.anchor_verification_status`,
    ),
    externalBalanceReference: optionalRecordFieldV0(
      record,
      "external_balance_reference",
      label,
    )
      ? parseCanonicalPipelineExternalBalanceReferenceV0(
          recordFieldV0(record, "external_balance_reference", label),
          `${label}.external_balance_reference`,
        )
      : null,
    expectedExternalBalance: optionalU64FieldV0(record, "expected_external_balance", label),
    tokenAnchorDigest: bytesFromHexV0(
      stringFieldV0(record, "token_anchor_digest_hex", label),
    ),
  };
}

function parseCanonicalPipelineSettlementRecordV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineSettlementRecordV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "settlement_intent",
      "settlement_status",
      "settlement_reason",
      "committed_state_root_hex",
      "future_token_binding_status",
      "future_token_binding_units",
    ],
    label,
  );
  return {
    settlementIntent: parseCanonicalPipelineSettlementIntentV0(
      stringFieldV0(record, "settlement_intent", label),
      `${label}.settlement_intent`,
    ),
    settlementStatus: parseCanonicalPipelineSettlementStatusV0(
      stringFieldV0(record, "settlement_status", label),
      `${label}.settlement_status`,
    ),
    settlementReason: parseCanonicalPipelineSettlementReasonV0(
      stringFieldV0(record, "settlement_reason", label),
      `${label}.settlement_reason`,
    ),
    committedStateRoot: optionalHexFieldV0(record, "committed_state_root_hex", label),
    futureTokenBindingStatus: parseCanonicalPipelineFutureTokenBindingStatusV0(
      stringFieldV0(record, "future_token_binding_status", label),
      `${label}.future_token_binding_status`,
    ),
    futureTokenBindingUnits: safeJsonU64V0(
      numberFieldV0(record, "future_token_binding_units", label),
      `${label}.future_token_binding_units`,
    ),
  };
}

function parseCanonicalPipelineStatusExplanationV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineStatusExplanationV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "truth_artifact_kind",
      "request_kind",
      "final_status",
      "failure_stage",
      "failure_reason_code",
      "detail",
    ],
    label,
  );
  return {
    truthArtifactKind: parseCanonicalPipelineTruthArtifactKindV0(
      stringFieldV0(record, "truth_artifact_kind", label),
      `${label}.truth_artifact_kind`,
    ),
    requestKind: parseCanonicalPipelineRequestKindV0(
      stringFieldV0(record, "request_kind", label),
      `${label}.request_kind`,
    ),
    finalStatus: parseScenarioResultV0(
      stringFieldV0(record, "final_status", label),
    ),
    failureStage: parseCanonicalPipelineFailureStageV0(
      stringFieldV0(record, "failure_stage", label),
      `${label}.failure_stage`,
    ),
    failureReasonCode: parseCanonicalPipelineFailureReasonCodeV0(
      stringFieldV0(record, "failure_reason_code", label),
      `${label}.failure_reason_code`,
    ),
    detail: stringFieldV0(record, "detail", label),
  };
}

function parseCanonicalPipelineAttestationSummaryV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineAttestationSummaryV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "attestation_schema_version",
      "attestation_scope",
      "attestation_proof_kind",
      "normalization_policy_version",
      "attestation_constraints",
      "claim",
      "claim_digest_hex",
      "evidence_summary",
      "normalization_summary",
      "consistency_result",
      "attestation_status",
      "attestation_failure_reason",
      "proof_scope_honesty_note",
    ],
    label,
  );
  return {
    attestationSchemaVersion: safeJsonU32V0(
      numberFieldV0(record, "attestation_schema_version", label),
      `${label}.attestation_schema_version`,
    ),
    attestationScope: parseCanonicalPipelineAttestationScopeV0(
      stringFieldV0(record, "attestation_scope", label),
      `${label}.attestation_scope`,
    ),
    attestationProofKind: parseCanonicalPipelineAttestationProofKindV0(
      stringFieldV0(record, "attestation_proof_kind", label),
      `${label}.attestation_proof_kind`,
    ),
    normalizationPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "normalization_policy_version", label),
      `${label}.normalization_policy_version`,
    ),
    attestationConstraints: parseCanonicalPipelineAttestationConstraintsV0(
      recordFieldV0(record, "attestation_constraints", label),
      `${label}.attestation_constraints`,
    ),
    claim: parseCanonicalPipelineAttestationClaimV0(
      recordFieldV0(record, "claim", label),
      `${label}.claim`,
    ),
    claimDigest: bytesFromHexV0(stringFieldV0(record, "claim_digest_hex", label)),
    evidenceSummary: parseCanonicalPipelineAttestationEvidenceSummaryV0(
      recordFieldV0(record, "evidence_summary", label),
      `${label}.evidence_summary`,
    ),
    normalizationSummary: parseCanonicalPipelineAttestationNormalizationSummaryV0(
      recordFieldV0(record, "normalization_summary", label),
      `${label}.normalization_summary`,
    ),
    consistencyResult: parseCanonicalPipelineAttestationConsistencyResultV0(
      recordFieldV0(record, "consistency_result", label),
      `${label}.consistency_result`,
    ),
    attestationStatus: parseCanonicalPipelineAttestationStatusV0(
      stringFieldV0(record, "attestation_status", label),
      `${label}.attestation_status`,
    ),
    attestationFailureReason: parseCanonicalPipelineAttestationFailureAuditV0(
      recordFieldV0(record, "attestation_failure_reason", label),
      `${label}.attestation_failure_reason`,
    ),
    proofScopeHonestyNote: stringFieldV0(record, "proof_scope_honesty_note", label),
  };
}

function parseCanonicalPipelineAttestationEvidenceSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationEvidenceSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["evidence_item_count", "evidence_items", "evidence_root_digest_hex"],
    label,
  );
  return {
    evidenceItemCount: safeJsonU64V0(
      numberFieldV0(record, "evidence_item_count", label),
      `${label}.evidence_item_count`,
    ),
    evidenceItems: arrayFieldV0(record, "evidence_items", label).map((item, index) => {
      const itemRecord = recordValueV0(item, `${label}.evidence_items[${index}]`);
      assertOnlyAllowedKeysV0(
        itemRecord,
        [
          "label",
          "evidence_kind",
          "original_payload_utf8",
          "original_payload_size_bytes",
          "normalized_form",
          "normalized_payload_utf8",
          "normalized_payload_size_bytes",
          "evidence_digest_hex",
          "provenance_digest_hex",
        ],
        `${label}.evidence_items[${index}]`,
      );
      return {
        label: stringFieldV0(itemRecord, "label", `${label}.evidence_items[${index}]`),
        evidenceKind: parseCanonicalPipelineAttestationEvidenceKindV0(
          stringFieldV0(itemRecord, "evidence_kind", `${label}.evidence_items[${index}]`),
          `${label}.evidence_items[${index}].evidence_kind`,
        ),
        originalPayloadUtf8: stringFieldV0(
          itemRecord,
          "original_payload_utf8",
          `${label}.evidence_items[${index}]`,
        ),
        originalPayloadSizeBytes: safeJsonU64V0(
          numberFieldV0(
            itemRecord,
            "original_payload_size_bytes",
            `${label}.evidence_items[${index}]`,
          ),
          `${label}.evidence_items[${index}].original_payload_size_bytes`,
        ),
        normalizedForm: parseCanonicalPipelineAttestationNormalizedFormV0(
          stringFieldV0(itemRecord, "normalized_form", `${label}.evidence_items[${index}]`),
          `${label}.evidence_items[${index}].normalized_form`,
        ),
        normalizedPayloadUtf8: stringFieldV0(
          itemRecord,
          "normalized_payload_utf8",
          `${label}.evidence_items[${index}]`,
        ),
        normalizedPayloadSizeBytes: safeJsonU64V0(
          numberFieldV0(
            itemRecord,
            "normalized_payload_size_bytes",
            `${label}.evidence_items[${index}]`,
          ),
          `${label}.evidence_items[${index}].normalized_payload_size_bytes`,
        ),
        evidenceDigest: bytesFromHexV0(
          stringFieldV0(itemRecord, "evidence_digest_hex", `${label}.evidence_items[${index}]`),
        ),
        provenanceDigest: bytesFromHexV0(
          stringFieldV0(itemRecord, "provenance_digest_hex", `${label}.evidence_items[${index}]`),
        ),
      };
    }),
    evidenceRootDigest: bytesFromHexV0(
      stringFieldV0(record, "evidence_root_digest_hex", label),
    ),
  };
}

function parseCanonicalPipelineAttestationNormalizationSummaryV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationNormalizationSummaryV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "normalization_policy_version",
      "normalized_evidence_count",
      "total_normalized_bytes",
      "normalization_succeeded",
    ],
    label,
  );
  return {
    normalizationPolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "normalization_policy_version", label),
      `${label}.normalization_policy_version`,
    ),
    normalizedEvidenceCount: safeJsonU64V0(
      numberFieldV0(record, "normalized_evidence_count", label),
      `${label}.normalized_evidence_count`,
    ),
    totalNormalizedBytes: safeJsonU64V0(
      numberFieldV0(record, "total_normalized_bytes", label),
      `${label}.total_normalized_bytes`,
    ),
    normalizationSucceeded: booleanFieldV0(record, "normalization_succeeded", label),
  };
}

function parseCanonicalPipelineAttestationConsistencyResultV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationConsistencyResultV0 {
  assertOnlyAllowedKeysV0(record, ["relation", "target_label", "consistent"], label);
  return {
    relation: parseCanonicalPipelineAttestationConsistencyRelationV0(
      stringFieldV0(record, "relation", label),
      `${label}.relation`,
    ),
    targetLabel: optionalStringFieldV0(record, "target_label", label),
    consistent: booleanFieldV0(record, "consistent", label),
  };
}

function parseCanonicalPipelineAttestationFailureAuditV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineAttestationFailureAuditV0 {
  assertOnlyAllowedKeysV0(record, ["reason", "detail"], label);
  return {
    reason: parseCanonicalPipelineAttestationFailureReasonV0(
      stringFieldV0(record, "reason", label),
      `${label}.reason`,
    ),
    detail: stringFieldV0(record, "detail", label),
  };
}

function parseCanonicalPipelineAttestationProofSummaryV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineAttestationProofSummaryV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "proof_kind",
      "attestation_tuple_digest_hex",
      "verification_passed",
      "mock_policy_version",
      "stark_policy_version",
      "stark_public_inputs_digest_hex",
      "stark_proof_bytes_digest_hex",
      "stark_proof_binding_digest_hex",
    ],
    label,
  );
  return {
    proofKind: parseCanonicalPipelineAttestationProofKindV0(
      stringFieldV0(record, "proof_kind", label),
      `${label}.proof_kind`,
    ),
    attestationTupleDigest: bytesFromHexV0(
      stringFieldV0(record, "attestation_tuple_digest_hex", label),
    ),
    verificationPassed: booleanFieldV0(record, "verification_passed", label),
    mockPolicyVersion: optionalU32FieldV0(record, "mock_policy_version", label),
    starkPolicyVersion: optionalU32FieldV0(record, "stark_policy_version", label),
    starkPublicInputsDigest: optionalHexFieldV0(
      record,
      "stark_public_inputs_digest_hex",
      label,
    ),
    starkProofBytesDigest: optionalHexFieldV0(
      record,
      "stark_proof_bytes_digest_hex",
      label,
    ),
    starkProofBindingDigest: optionalHexFieldV0(
      record,
      "stark_proof_binding_digest_hex",
      label,
    ),
  };
}

function parseCanonicalPipelineProvenanceSummaryV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineProvenanceSummaryV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "provenance_item_count",
      "items",
      "provenance_root_digest_hex",
      "all_signature_checks_passed",
    ],
    label,
  );
  return {
    provenanceItemCount: safeJsonU64V0(
      numberFieldV0(record, "provenance_item_count", label),
      `${label}.provenance_item_count`,
    ),
    items: arrayFieldV0(record, "items", label).map((item, index) =>
      parseCanonicalPipelineProvenanceSummaryItemV0(
        recordValueV0(item, `${label}.items[${index}]`),
        `${label}.items[${index}]`,
      ),
    ),
    provenanceRootDigest: bytesFromHexV0(
      stringFieldV0(record, "provenance_root_digest_hex", label),
    ),
    allSignatureChecksPassed: booleanFieldV0(
      record,
      "all_signature_checks_passed",
      label,
    ),
  };
}

function parseCanonicalPipelineProvenanceSummaryItemV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineProvenanceSummaryItemV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "label",
      "provenance_policy_version",
      "provenance_type",
      "source_type",
      "source_identifier",
      "signature_present",
      "signature_valid",
      "signer_public_key_hex",
      "signature_hex",
      "timestamp_unix_seconds",
      "provenance_digest_hex",
    ],
    label,
  );
  return {
    label: stringFieldV0(record, "label", label),
    provenancePolicyVersion: safeJsonU32V0(
      numberFieldV0(record, "provenance_policy_version", label),
      `${label}.provenance_policy_version`,
    ),
    provenanceType: parseCanonicalPipelineEvidenceProvenanceTypeV0(
      stringFieldV0(record, "provenance_type", label),
      `${label}.provenance_type`,
    ),
    sourceType: stringFieldV0(record, "source_type", label),
    sourceIdentifier: stringFieldV0(record, "source_identifier", label),
    signaturePresent: booleanFieldV0(record, "signature_present", label),
    signatureValid: booleanFieldV0(record, "signature_valid", label),
    signerPublicKey: optionalHexFieldV0(record, "signer_public_key_hex", label),
    signature: optionalHexRawFieldV0(record, "signature_hex", label),
    timestampUnixSeconds: optionalU64FieldV0(record, "timestamp_unix_seconds", label),
    provenanceDigest: bytesFromHexV0(
      stringFieldV0(record, "provenance_digest_hex", label),
    ),
  };
}

function parseCanonicalPipelineGenesisAccountsV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineGenesisAccountsV0 {
  assertOnlyAllowedKeysV0(record, ["material_version", "ordered_accounts"], label);
  return {
    materialVersion: safeJsonU32V0(
      numberFieldV0(record, "material_version", label),
      `${label}.material_version`,
    ),
    orderedAccounts: arrayFieldV0(record, "ordered_accounts", label).map((value, index) =>
      parseCanonicalPipelineAccountV0(
        recordValueV0(value, `${label}.ordered_accounts[${index}]`),
        `${label}.ordered_accounts[${index}]`,
      ),
    ),
  };
}

function parseCanonicalPipelineLedgerAccountsV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineLedgerAccountsV0 {
  assertOnlyAllowedKeysV0(record, ["material_version", "ordered_accounts"], label);
  return {
    materialVersion: safeJsonU32V0(
      numberFieldV0(record, "material_version", label),
      `${label}.material_version`,
    ),
    orderedAccounts: arrayFieldV0(record, "ordered_accounts", label).map((entry) => {
      const item = recordValueV0(entry, `${label}.ordered_accounts[]`);
      assertOnlyAllowedKeysV0(item, ["account_id_hex", "balance"], `${label}.ordered_accounts[]`);
      return {
        accountId: bytesFromHexV0(
          stringFieldV0(item, "account_id_hex", `${label}.ordered_accounts[]`),
        ),
        balance: safeJsonU64V0(
          numberFieldV0(item, "balance", `${label}.ordered_accounts[]`),
          `${label}.ordered_accounts[].balance`,
        ),
      };
    }),
  };
}

function parseCanonicalPipelineCommitmentExpansionsV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineCommitmentExpansionsV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["transactions", "outcomes", "batch_context", "fee_summary"],
    label,
  );
  return {
    transactions: parseCanonicalPipelineTransactionsCommitmentExpansionV0(
      recordFieldV0(record, "transactions", label),
      `${label}.transactions`,
    ),
    outcomes: parseCanonicalPipelineOutcomesCommitmentExpansionV0(
      optionalRecordFieldV0(record, "outcomes", label),
      `${label}.outcomes`,
    ),
    batchContext: parseCanonicalPipelineBatchContextCommitmentExpansionV0(
      recordFieldV0(record, "batch_context", label),
      `${label}.batch_context`,
    ),
    feeSummary: parseCanonicalPipelineFeeSummaryCommitmentExpansionV0(
      recordFieldV0(record, "fee_summary", label),
      `${label}.fee_summary`,
    ),
  };
}

function parseCanonicalPipelineAccountV0(
  record: Record<string, unknown>,
  label: string,
): AccountV0 {
  assertOnlyAllowedKeysV0(record, ["account_id_hex", "balance", "nonce"], label);
  return {
    accountId: bytesFromHexV0(stringFieldV0(record, "account_id_hex", label)),
    balance: safeJsonU64V0(numberFieldV0(record, "balance", label), `${label}.balance`),
    nonce: safeJsonU64V0(numberFieldV0(record, "nonce", label), `${label}.nonce`),
  };
}

function parseCanonicalPipelineTransactionV0(
  record: Record<string, unknown>,
  label: string,
): TransferTxV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "tx_version",
      "sender_account_id_hex",
      "recipient_account_id_hex",
      "sender_nonce",
      "amount",
    ],
    label,
  );
  return {
    txVersion: safeJsonU32V0(numberFieldV0(record, "tx_version", label), `${label}.tx_version`),
    senderAccountId: bytesFromHexV0(stringFieldV0(record, "sender_account_id_hex", label)),
    recipientAccountId: bytesFromHexV0(
      stringFieldV0(record, "recipient_account_id_hex", label),
    ),
    senderNonce: safeJsonU64V0(
      numberFieldV0(record, "sender_nonce", label),
      `${label}.sender_nonce`,
    ),
    amount: safeJsonU64V0(numberFieldV0(record, "amount", label), `${label}.amount`),
  };
}

function parseCanonicalPipelineTransactionsCommitmentExpansionV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineTransactionsCommitmentExpansionV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["expansion_version", "transactions_commitment_hex", "ordered_transactions"],
    label,
  );
  return {
    expansionVersion: safeJsonU32V0(
      numberFieldV0(record, "expansion_version", label),
      `${label}.expansion_version`,
    ),
    transactionsCommitment: bytesFromHexV0(
      stringFieldV0(record, "transactions_commitment_hex", label),
    ),
    orderedTransactions: arrayFieldV0(record, "ordered_transactions", label).map((value, index) =>
      parseCanonicalPipelineTransactionV0(
        recordValueV0(value, `${label}.ordered_transactions[${index}]`),
        `${label}.ordered_transactions[${index}]`,
      ),
    ),
  };
}

function parseCanonicalPipelineExecutionOutcomeV0(
  record: Record<string, unknown>,
  label: string,
): ExecutionOutcomeV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "tx_index",
      "sender_account_id_hex",
      "consumed_nonce",
      "fee_charged",
      "touched_accounts_commitment_hex",
      "operation_result_commitment_hex",
      "status",
    ],
    label,
  );
  return {
    txIndex: safeJsonU64V0(numberFieldV0(record, "tx_index", label), `${label}.tx_index`),
    senderAccountId: bytesFromHexV0(stringFieldV0(record, "sender_account_id_hex", label)),
    consumedNonce: safeJsonU64V0(
      numberFieldV0(record, "consumed_nonce", label),
      `${label}.consumed_nonce`,
    ),
    feeCharged: safeJsonU64V0(
      numberFieldV0(record, "fee_charged", label),
      `${label}.fee_charged`,
    ),
    touchedAccountsCommitment: bytesFromHexV0(
      stringFieldV0(record, "touched_accounts_commitment_hex", label),
    ),
    operationResultCommitment: bytesFromHexV0(
      stringFieldV0(record, "operation_result_commitment_hex", label),
    ),
    status: safeJsonU8V0(numberFieldV0(record, "status", label), `${label}.status`),
  };
}

function parseCanonicalPipelineAppliedTransferStepV0(
  record: Record<string, unknown>,
  label: string,
): AppliedTransferStepV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "tx_index",
      "sender_account_id_hex",
      "recipient_account_id_hex",
      "sender_nonce_before",
      "sender_nonce_after",
      "sender_balance_before",
      "sender_balance_after",
      "recipient_balance_before",
      "recipient_balance_after",
      "amount",
      "fee_charged",
    ],
    label,
  );
  return {
    txIndex: safeJsonU64V0(numberFieldV0(record, "tx_index", label), `${label}.tx_index`),
    senderAccountId: bytesFromHexV0(stringFieldV0(record, "sender_account_id_hex", label)),
    recipientAccountId: bytesFromHexV0(
      stringFieldV0(record, "recipient_account_id_hex", label),
    ),
    senderNonceBefore: safeJsonU64V0(
      numberFieldV0(record, "sender_nonce_before", label),
      `${label}.sender_nonce_before`,
    ),
    senderNonceAfter: safeJsonU64V0(
      numberFieldV0(record, "sender_nonce_after", label),
      `${label}.sender_nonce_after`,
    ),
    senderBalanceBefore: safeJsonU64V0(
      numberFieldV0(record, "sender_balance_before", label),
      `${label}.sender_balance_before`,
    ),
    senderBalanceAfter: safeJsonU64V0(
      numberFieldV0(record, "sender_balance_after", label),
      `${label}.sender_balance_after`,
    ),
    recipientBalanceBefore: safeJsonU64V0(
      numberFieldV0(record, "recipient_balance_before", label),
      `${label}.recipient_balance_before`,
    ),
    recipientBalanceAfter: safeJsonU64V0(
      numberFieldV0(record, "recipient_balance_after", label),
      `${label}.recipient_balance_after`,
    ),
    amount: safeJsonU64V0(numberFieldV0(record, "amount", label), `${label}.amount`),
    feeCharged: safeJsonU64V0(
      numberFieldV0(record, "fee_charged", label),
      `${label}.fee_charged`,
    ),
  };
}

function parseCanonicalPipelineOutcomesCommitmentExpansionV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineOutcomesCommitmentExpansionV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    ["expansion_version", "outcomes_commitment_hex", "outcomes", "applied_steps"],
    label,
  );
  return {
    expansionVersion: safeJsonU32V0(
      numberFieldV0(record, "expansion_version", label),
      `${label}.expansion_version`,
    ),
    outcomesCommitment: bytesFromHexV0(
      stringFieldV0(record, "outcomes_commitment_hex", label),
    ),
    outcomes: arrayFieldV0(record, "outcomes", label).map((value, index) =>
      parseCanonicalPipelineExecutionOutcomeV0(
        recordValueV0(value, `${label}.outcomes[${index}]`),
        `${label}.outcomes[${index}]`,
      ),
    ),
    appliedSteps: arrayFieldV0(record, "applied_steps", label).map((value, index) =>
      parseCanonicalPipelineAppliedTransferStepV0(
        recordValueV0(value, `${label}.applied_steps[${index}]`),
        `${label}.applied_steps[${index}]`,
      ),
    ),
  };
}

function parseCanonicalPipelineExecutionConfigV0(
  record: Record<string, unknown>,
  label: string,
): ExecutionConfigV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["rollup_id_hex", "execution_model_version", "batch_version"],
    label,
  );
  return {
    rollupId: bytesFromHexV0(stringFieldV0(record, "rollup_id_hex", label)),
    executionModelVersion: safeJsonU32V0(
      numberFieldV0(record, "execution_model_version", label),
      `${label}.execution_model_version`,
    ),
    batchVersion: safeJsonU32V0(
      numberFieldV0(record, "batch_version", label),
      `${label}.batch_version`,
    ),
  };
}

function parseCanonicalPipelineFeeParametersExpansionV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineFeeParametersExpansionV0 {
  assertOnlyAllowedKeysV0(record, ["fee_per_transfer"], label);
  return {
    feePerTransfer: safeJsonU64V0(
      numberFieldV0(record, "fee_per_transfer", label),
      `${label}.fee_per_transfer`,
    ),
  };
}

function parseCanonicalPipelineValidityReferenceExpansionV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineValidityReferenceExpansionV0 {
  assertOnlyAllowedKeysV0(record, ["kind", "none_marker"], label);
  return {
    kind: parseCanonicalPipelineValidityReferenceKindV0(
      stringFieldV0(record, "kind", label),
    ),
    noneMarker: safeJsonU8V0(
      numberFieldV0(record, "none_marker", label),
      `${label}.none_marker`,
    ),
  };
}

function parseCanonicalPipelineExecutionConstantsExpansionV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineExecutionConstantsExpansionV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["transfer_tx_version", "transition_binding_version", "applied_status"],
    label,
  );
  return {
    transferTxVersion: safeJsonU32V0(
      numberFieldV0(record, "transfer_tx_version", label),
      `${label}.transfer_tx_version`,
    ),
    transitionBindingVersion: safeJsonU32V0(
      numberFieldV0(record, "transition_binding_version", label),
      `${label}.transition_binding_version`,
    ),
    appliedStatus: safeJsonU8V0(
      numberFieldV0(record, "applied_status", label),
      `${label}.applied_status`,
    ),
  };
}

function parseCanonicalPipelineBatchContextCommitmentExpansionV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineBatchContextCommitmentExpansionV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "expansion_version",
      "batch_context_commitment_hex",
      "transition_binding_version",
      "system_config",
      "fee_parameters",
      "validity_reference",
      "execution_constants",
    ],
    label,
  );
  return {
    expansionVersion: safeJsonU32V0(
      numberFieldV0(record, "expansion_version", label),
      `${label}.expansion_version`,
    ),
    batchContextCommitment: bytesFromHexV0(
      stringFieldV0(record, "batch_context_commitment_hex", label),
    ),
    transitionBindingVersion: safeJsonU32V0(
      numberFieldV0(record, "transition_binding_version", label),
      `${label}.transition_binding_version`,
    ),
    systemConfig: parseCanonicalPipelineExecutionConfigV0(
      recordFieldV0(record, "system_config", label),
      `${label}.system_config`,
    ),
    feeParameters: parseCanonicalPipelineFeeParametersExpansionV0(
      recordFieldV0(record, "fee_parameters", label),
      `${label}.fee_parameters`,
    ),
    validityReference: parseCanonicalPipelineValidityReferenceExpansionV0(
      recordFieldV0(record, "validity_reference", label),
      `${label}.validity_reference`,
    ),
    executionConstants: parseCanonicalPipelineExecutionConstantsExpansionV0(
      recordFieldV0(record, "execution_constants", label),
      `${label}.execution_constants`,
    ),
  };
}

function parseCanonicalPipelineFeeSummaryV0(
  record: Record<string, unknown>,
  label: string,
): FeeSummaryV0 {
  assertOnlyAllowedKeysV0(record, ["tx_count", "total_fee_charged"], label);
  return {
    txCount: safeJsonU64V0(numberFieldV0(record, "tx_count", label), `${label}.tx_count`),
    totalFeeCharged: safeJsonU64V0(
      numberFieldV0(record, "total_fee_charged", label),
      `${label}.total_fee_charged`,
    ),
  };
}

function parseCanonicalPipelineFeeSummaryCommitmentExpansionV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineFeeSummaryCommitmentExpansionV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["expansion_version", "fee_summary_commitment_hex", "fee_summary"],
    label,
  );
  return {
    expansionVersion: safeJsonU32V0(
      numberFieldV0(record, "expansion_version", label),
      `${label}.expansion_version`,
    ),
    feeSummaryCommitment: bytesFromHexV0(
      stringFieldV0(record, "fee_summary_commitment_hex", label),
    ),
    feeSummary: parseCanonicalPipelineFeeSummaryV0(
      recordFieldV0(record, "fee_summary", label),
      `${label}.fee_summary`,
    ),
  };
}

function parseCanonicalPipelineStageOutcomesV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineStageOutcomesV0 {
  assertOnlyAllowedKeysV0(
    record,
    ["execution_status", "verification_status", "settlement_status"],
    label,
  );
  return {
    executionStatus: parseCanonicalPipelineExecutionStatusV0(
      stringFieldV0(record, "execution_status", label),
    ),
    verificationStatus: parseCanonicalPipelineVerificationStatusV0(
      stringFieldV0(record, "verification_status", label),
    ),
    settlementStatus: parseCanonicalPipelineSettlementStatusV0(
      stringFieldV0(record, "settlement_status", label),
    ),
  };
}

function parseCanonicalPipelinePublicInputsAuditV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelinePublicInputsAuditV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "decode_status",
      "public_input_bytes_hex",
      "public_inputs_hash_hex",
      "transition_binding_hash_hex",
      "request_summary_consistency",
      "decoded_public_inputs",
    ],
    label,
  );
  return {
    decodeStatus: parseCanonicalPipelinePublicInputsDecodeStatusV0(
      stringFieldV0(record, "decode_status", label),
    ),
    publicInputBytes: (() => {
      const bytes = bytesFromHexRawV0(stringFieldV0(record, "public_input_bytes_hex", label));
      if (bytes.length !== PUBLIC_INPUT_SCHEMA_LEN_V0) {
        throw new AuraTypescriptSdkErrorV0(
          "RustBridgeFailure",
          `${label}.public_input_bytes_hex must decode to ${PUBLIC_INPUT_SCHEMA_LEN_V0} bytes, got ${bytes.length}`,
        );
      }
      return bytes;
    })(),
    publicInputsHash: bytesFromHexV0(stringFieldV0(record, "public_inputs_hash_hex", label)),
    transitionBindingHash: bytesFromHexV0(
      stringFieldV0(record, "transition_binding_hash_hex", label),
    ),
    requestSummaryConsistency: parseCanonicalPipelineRequestSummaryConsistencyAuditV0(
      optionalRecordFieldV0(record, "request_summary_consistency", label),
      `${label}.request_summary_consistency`,
    ),
    decodedPublicInputs: parseCanonicalPipelineDecodedPublicInputsV0(
      optionalRecordFieldV0(record, "decoded_public_inputs", label),
      `${label}.decoded_public_inputs`,
    ),
  };
}

function parseCanonicalPipelineRequestSummaryConsistencyAuditV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineRequestSummaryConsistencyAuditV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "transition_binding_version_supported",
      "execution_model_version_supported",
      "batch_version_supported",
      "rollup_id_matches_request_audit",
      "batch_number_matches_request_audit",
      "tx_count_matches_request_audit",
      "parent_batch_commitment_matches_request_audit",
      "fee_summary_commitment_matches_expansion",
      "pre_state_root_matches_report",
      "transactions_commitment_matches_expansion",
      "outcomes_commitment_matches_expansion",
      "batch_context_commitment_matches_expansion",
      "post_state_root_matches_report",
      "decoded_bytes_round_trip",
      "all_fields_match",
    ],
    label,
  );
  return {
    transitionBindingVersionSupported: booleanFieldV0(
      record,
      "transition_binding_version_supported",
      label,
    ),
    executionModelVersionSupported: booleanFieldV0(
      record,
      "execution_model_version_supported",
      label,
    ),
    batchVersionSupported: booleanFieldV0(record, "batch_version_supported", label),
    rollupIdMatchesRequestAudit: booleanFieldV0(
      record,
      "rollup_id_matches_request_audit",
      label,
    ),
    batchNumberMatchesRequestAudit: booleanFieldV0(
      record,
      "batch_number_matches_request_audit",
      label,
    ),
    txCountMatchesRequestAudit: booleanFieldV0(record, "tx_count_matches_request_audit", label),
    parentBatchCommitmentMatchesRequestAudit: booleanFieldV0(
      record,
      "parent_batch_commitment_matches_request_audit",
      label,
    ),
    feeSummaryCommitmentMatchesExpansion: booleanFieldV0(
      record,
      "fee_summary_commitment_matches_expansion",
      label,
    ),
    preStateRootMatchesReport: booleanFieldV0(record, "pre_state_root_matches_report", label),
    transactionsCommitmentMatchesExpansion: booleanFieldV0(
      record,
      "transactions_commitment_matches_expansion",
      label,
    ),
    outcomesCommitmentMatchesExpansion: booleanFieldV0(
      record,
      "outcomes_commitment_matches_expansion",
      label,
    ),
    batchContextCommitmentMatchesExpansion: booleanFieldV0(
      record,
      "batch_context_commitment_matches_expansion",
      label,
    ),
    postStateRootMatchesReport: booleanFieldV0(record, "post_state_root_matches_report", label),
    decodedBytesRoundTrip: booleanFieldV0(record, "decoded_bytes_round_trip", label),
    allFieldsMatch: booleanFieldV0(record, "all_fields_match", label),
  };
}

function parseCanonicalPipelineDecodedPublicInputsV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineDecodedPublicInputsV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "transition_binding_version",
      "rollup_id_hex",
      "execution_model_version",
      "batch_version",
      "batch_number",
      "parent_batch_commitment_hex",
      "tx_count",
      "fee_summary_commitment_hex",
      "pre_state_root_hex",
      "post_state_root_hex",
      "transactions_commitment_hex",
      "outcomes_commitment_hex",
      "batch_context_commitment_hex",
    ],
    label,
  );
  return {
    transitionBindingVersion: safeJsonU32V0(
      numberFieldV0(record, "transition_binding_version", label),
      `${label}.transition_binding_version`,
    ),
    rollupId: bytesFromHexV0(stringFieldV0(record, "rollup_id_hex", label)),
    executionModelVersion: safeJsonU32V0(
      numberFieldV0(record, "execution_model_version", label),
      `${label}.execution_model_version`,
    ),
    batchVersion: safeJsonU32V0(
      numberFieldV0(record, "batch_version", label),
      `${label}.batch_version`,
    ),
    batchNumber: safeJsonU64V0(
      numberFieldV0(record, "batch_number", label),
      `${label}.batch_number`,
    ),
    parentBatchCommitment: bytesFromHexV0(
      stringFieldV0(record, "parent_batch_commitment_hex", label),
    ),
    txCount: safeJsonU64V0(
      numberFieldV0(record, "tx_count", label),
      `${label}.tx_count`,
    ),
    feeSummaryCommitment: bytesFromHexV0(
      stringFieldV0(record, "fee_summary_commitment_hex", label),
    ),
    preStateRoot: bytesFromHexV0(stringFieldV0(record, "pre_state_root_hex", label)),
    postStateRoot: bytesFromHexV0(stringFieldV0(record, "post_state_root_hex", label)),
    transactionsCommitment: bytesFromHexV0(
      stringFieldV0(record, "transactions_commitment_hex", label),
    ),
    outcomesCommitment: bytesFromHexV0(
      stringFieldV0(record, "outcomes_commitment_hex", label),
    ),
    batchContextCommitment: bytesFromHexV0(
      stringFieldV0(record, "batch_context_commitment_hex", label),
    ),
  };
}

function parseCanonicalPipelineProofArtifactAuditV0(
  record: Record<string, unknown> | null,
  label: string,
): CanonicalPipelineProofArtifactAuditV0 | null {
  if (record === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(
    record,
    [
      "prover_kind",
      "proof_version",
      "public_inputs_hash_hex",
      "trace_digest_hex",
      "trace_layout_digest_hex",
      "proof_binding_digest_hex",
      "proof_binding_input_kind",
      "proof_binding_input_digest_hex",
      "consistency",
    ],
    label,
  );
  return {
    proverKind: safeJsonU32V0(numberFieldV0(record, "prover_kind", label), `${label}.prover_kind`),
    proofVersion: safeJsonU32V0(
      numberFieldV0(record, "proof_version", label),
      `${label}.proof_version`,
    ),
    publicInputsHash: bytesFromHexV0(stringFieldV0(record, "public_inputs_hash_hex", label)),
    traceDigest: bytesFromHexV0(stringFieldV0(record, "trace_digest_hex", label)),
    traceLayoutDigest: bytesFromHexV0(
      stringFieldV0(record, "trace_layout_digest_hex", label),
    ),
    proofBindingDigest: bytesFromHexV0(
      stringFieldV0(record, "proof_binding_digest_hex", label),
    ),
    proofBindingInputKind: parseCanonicalPipelineProofBindingInputKindV0(
      stringFieldV0(record, "proof_binding_input_kind", label),
    ),
    proofBindingInputDigest: bytesFromHexV0(
      stringFieldV0(record, "proof_binding_input_digest_hex", label),
    ),
    consistency: parseCanonicalPipelineProofArtifactConsistencyAuditV0(
      recordFieldV0(record, "consistency", label),
      `${label}.consistency`,
    ),
  };
}

function parseCanonicalPipelineProofArtifactConsistencyAuditV0(
  record: Record<string, unknown>,
  label: string,
): CanonicalPipelineProofArtifactConsistencyAuditV0 {
  assertOnlyAllowedKeysV0(
    record,
    [
      "public_inputs_hash_matches_report",
      "prover_kind_matches_proof_system",
      "proof_version_supported",
      "proof_binding_input_kind_matches_proof_system",
      "recomputed_proof_binding_digest_hex",
      "proof_binding_digest_matches_recomputed",
      "all_fields_match",
    ],
    label,
  );
  return {
    publicInputsHashMatchesReport: booleanFieldV0(
      record,
      "public_inputs_hash_matches_report",
      label,
    ),
    proverKindMatchesProofSystem: booleanFieldV0(
      record,
      "prover_kind_matches_proof_system",
      label,
    ),
    proofVersionSupported: booleanFieldV0(record, "proof_version_supported", label),
    proofBindingInputKindMatchesProofSystem: booleanFieldV0(
      record,
      "proof_binding_input_kind_matches_proof_system",
      label,
    ),
    recomputedProofBindingDigest: bytesFromHexV0(
      stringFieldV0(record, "recomputed_proof_binding_digest_hex", label),
    ),
    proofBindingDigestMatchesRecomputed: booleanFieldV0(
      record,
      "proof_binding_digest_matches_recomputed",
      label,
    ),
    allFieldsMatch: booleanFieldV0(record, "all_fields_match", label),
  };
}

function parseRustProofVectorReportV0(value: unknown): ProofVectorReportV0 {
  const envelope = parseRustProofVectorBridgeEnvelopeV0(value);
  const report = recordFieldV0(envelope as Record<string, unknown>, "report", "rust_bridge");
  assertOnlyAllowedKeysV0(
    report,
    [
      "fixture_name",
      "proof_system",
      "expected_result",
      "actual_result",
      "pre_state_root_hex",
      "post_state_root_hex",
      "transition_binding_hash_hex",
      "public_inputs_hash_hex",
      "trace_digest_hex",
      "trace_layout_digest_hex",
      "proof_binding_digest_hex",
    ],
    "rust_bridge.report",
  );

  return {
    fixtureName: stringFieldV0(report, "fixture_name", "rust_bridge.report"),
    proofSystem: parseProofSystemV0(
      stringFieldV0(report, "proof_system", "rust_bridge.report"),
    ),
    expectedResult: parseScenarioResultV0(
      stringFieldV0(report, "expected_result", "rust_bridge.report"),
    ),
    actualResult: parseScenarioResultV0(
      stringFieldV0(report, "actual_result", "rust_bridge.report"),
    ),
    preStateRoot: bytesFromHexV0(
      stringFieldV0(report, "pre_state_root_hex", "rust_bridge.report"),
    ),
    postStateRoot: optionalHexFieldV0(report, "post_state_root_hex", "rust_bridge.report"),
    transitionBindingHash: bytesFromHexV0(
      stringFieldV0(report, "transition_binding_hash_hex", "rust_bridge.report"),
    ),
    publicInputsHash: bytesFromHexV0(
      stringFieldV0(report, "public_inputs_hash_hex", "rust_bridge.report"),
    ),
    traceDigest: bytesFromHexV0(
      stringFieldV0(report, "trace_digest_hex", "rust_bridge.report"),
    ),
    traceLayoutDigest: bytesFromHexV0(
      stringFieldV0(report, "trace_layout_digest_hex", "rust_bridge.report"),
    ),
    proofBindingDigest: bytesFromHexV0(
      stringFieldV0(report, "proof_binding_digest_hex", "rust_bridge.report"),
    ),
  };
}

function parseRustScenarioBridgeEnvelopeV0(
  value: unknown,
): RustScenarioBridgeEnvelopeV0 {
  const envelope = parseRustBridgeEnvelopeV0(value, "scenario_report_v1");
  return envelope as RustScenarioBridgeEnvelopeV0;
}

function parseRustCanonicalPipelineBridgeEnvelopeV0(
  value: unknown,
): RustCanonicalPipelineBridgeEnvelopeV0 {
  const envelope = parseRustBridgeEnvelopeV0(value, "canonical_pipeline_report_v1");
  return envelope as RustCanonicalPipelineBridgeEnvelopeV0;
}

function parseRustProofVectorBridgeEnvelopeV0(
  value: unknown,
): RustProofVectorBridgeEnvelopeV0 {
  const envelope = parseRustBridgeEnvelopeV0(value, "proof_vector_report_v1");
  return envelope as RustProofVectorBridgeEnvelopeV0;
}

function parseRustBridgeEnvelopeV0(
  value: unknown,
  expectedReportKind: string,
): Record<string, unknown> {
  const envelope = recordValueV0(value, "rust_bridge");
  assertOnlyAllowedKeysV0(
    envelope,
    ["bridge_schema_version", "report_kind", "command", "report"],
    "rust_bridge",
  );
  const schemaVersion = numberFieldV0(
    envelope,
    "bridge_schema_version",
    "rust_bridge",
  );
  if (schemaVersion !== RUST_LOCAL_CHAIN_BRIDGE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported rust bridge schema version: ${schemaVersion}`,
    );
  }
  const reportKind = stringFieldV0(envelope, "report_kind", "rust_bridge");
  if (reportKind !== expectedReportKind) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unexpected rust bridge report kind: ${reportKind}`,
    );
  }
  const command = stringFieldV0(envelope, "command", "rust_bridge");
  if (command.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "rust bridge command must not be empty",
    );
  }
  assertRustBridgeCommandMatchesReportKindV0(command, expectedReportKind);
  envelope.report = recordFieldV0(envelope, "report", "rust_bridge");
  return envelope;
}

function assertRustBridgeCommandMatchesReportKindV0(
  command: string,
  reportKind: string,
): void {
  const allowedCommands =
    reportKind === "canonical_pipeline_report_v1"
      ? RUST_CANONICAL_PIPELINE_COMMANDS_V0
      : reportKind === "scenario_report_v1"
      ? RUST_SCENARIO_COMMANDS_V0
      : reportKind === "proof_vector_report_v1"
        ? RUST_PROOF_VECTOR_COMMANDS_V0
        : null;
  if (!allowedCommands) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported rust bridge report kind: ${reportKind}`,
    );
  }
  if (!(allowedCommands as readonly string[]).includes(command)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unexpected rust bridge command for ${reportKind}: ${command}`,
    );
  }
}

function optionalHexFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): Uint8Array | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `${label}.${field} must be a string when present`,
    );
  }
  return bytesFromHexV0(value);
}

function optionalHexRawFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): Uint8Array | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `${label}.${field} must be a string when present`,
    );
  }
  return bytesFromHexRawV0(value);
}

function optionalHexBytesFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
  expectedLength: number,
): Uint8Array | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `${label}.${field} must be a string when present`,
    );
  }
  const bytes = bytesFromHexRawV0(value);
  if (bytes.length !== expectedLength) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `${label}.${field} must decode to ${expectedLength} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

function optionalNumberFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): number | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  return safeJsonU32V0(numberFieldV0(record, field, label), `${label}.${field}`);
}

function parseScenarioResultV0(value: string): ScenarioResultV0 {
  switch (value) {
    case "Accepted":
      return ScenarioResultV0.Accepted;
    case "ExecutionRejected":
      return ScenarioResultV0.ExecutionRejected;
    case "VerificationRejected":
      return ScenarioResultV0.VerificationRejected;
    case "SettlementRejected":
      return ScenarioResultV0.SettlementRejected;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported scenario result: ${value}`,
      );
  }
}

function parseRustExpectedResultV0(value: string): ScenarioResultV0 {
  switch (value) {
    case "ACCEPTED":
    case "Accepted":
      return ScenarioResultV0.Accepted;
    case "EXECUTION_REJECTED":
    case "ExecutionRejected":
      return ScenarioResultV0.ExecutionRejected;
    case "VERIFICATION_REJECTED":
    case "VerificationRejected":
      return ScenarioResultV0.VerificationRejected;
    case "SETTLEMENT_REJECTED":
    case "SettlementRejected":
      return ScenarioResultV0.SettlementRejected;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `unsupported expected result: ${value}`,
      );
  }
}

function parseCanonicalPipelineExecutionStatusV0(
  value: string,
): CanonicalPipelineExecutionStatusV0 {
  switch (value) {
    case CanonicalPipelineExecutionStatusV0.Applied:
    case CanonicalPipelineExecutionStatusV0.Rejected:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline execution status: ${value}`,
      );
  }
}

function parseCanonicalPipelineVerificationStatusV0(
  value: string,
): CanonicalPipelineVerificationStatusV0 {
  switch (value) {
    case CanonicalPipelineVerificationStatusV0.Passed:
    case CanonicalPipelineVerificationStatusV0.Rejected:
    case CanonicalPipelineVerificationStatusV0.NotRun:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline verification status: ${value}`,
      );
  }
}

function parseCanonicalPipelineSettlementStatusV0(
  value: string,
): CanonicalPipelineSettlementStatusV0 {
  switch (value) {
    case CanonicalPipelineSettlementStatusV0.Accepted:
    case CanonicalPipelineSettlementStatusV0.Rejected:
    case CanonicalPipelineSettlementStatusV0.NotRun:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline settlement status: ${value}`,
      );
  }
}

function parseCanonicalPipelinePublicInputsDecodeStatusV0(
  value: string,
): CanonicalPipelinePublicInputsDecodeStatusV0 {
  switch (value) {
    case CanonicalPipelinePublicInputsDecodeStatusV0.Decoded:
    case CanonicalPipelinePublicInputsDecodeStatusV0.Invalid:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline public input decode status: ${value}`,
      );
  }
}

function parseCanonicalPipelineProofBindingInputKindV0(
  value: string,
): CanonicalPipelineProofBindingInputKindV0 {
  switch (value) {
    case CanonicalPipelineProofBindingInputKindV0.WitnessDigest:
    case CanonicalPipelineProofBindingInputKindV0.ProofBytesHash:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline proof binding input kind: ${value}`,
      );
  }
}

function parseCanonicalPipelineValidityReferenceKindV0(
  value: string,
): CanonicalPipelineValidityReferenceKindV0 {
  switch (value) {
    case CanonicalPipelineValidityReferenceKindV0.None:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline validity reference kind: ${value}`,
      );
  }
}

function parseProofSystemV0(value: string): ProofSystemV0 {
  switch (value) {
    case "MOCK":
    case "mock":
      return ProofSystemV0.Mock;
    case "STARK":
    case "stark":
      return ProofSystemV0.Stark;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `unsupported proof system: ${value}`,
      );
  }
}

function parseCanonicalPipelineRequestKindV0(
  value: string,
  label: string,
): CanonicalPipelineRequestKindV0 {
  switch (value) {
    case CanonicalPipelineRequestKindV0.Execution:
    case CanonicalPipelineRequestKindV0.Attestation:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported request_kind: ${value}`,
      );
  }
}

function parseCanonicalPipelineBurnIntentV0(
  value: string,
  label: string,
): CanonicalPipelineBurnIntentV0 {
  switch (value) {
    case CanonicalPipelineBurnIntentV0.CanonicalReport:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported burn_intent: ${value}`,
      );
  }
}

function parseCanonicalPipelinePaymentIntentV0(
  value: string,
  label: string,
): CanonicalPipelinePaymentIntentV0 {
  switch (value) {
    case CanonicalPipelinePaymentIntentV0.BurnToProduceCanonicalTruth:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline payment intent: ${value}`,
      );
  }
}

function parseCanonicalPipelineSettlementIntentV0(
  value: string,
  label: string,
): CanonicalPipelineSettlementIntentV0 {
  switch (value) {
    case CanonicalPipelineSettlementIntentV0.RecordCanonicalOutcome:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline settlement intent: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationScopeV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationScopeV0 {
  switch (value) {
    case CanonicalPipelineAttestationScopeV0.ClaimConsistencyWithProvidedEvidenceOnly:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation scope: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationClaimKindV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationClaimKindV0 {
  switch (value) {
    case CanonicalPipelineAttestationClaimKindV0.EvidenceRootDigest:
    case CanonicalPipelineAttestationClaimKindV0.NormalizedEvidenceDigest:
    case CanonicalPipelineAttestationClaimKindV0.NormalizedTextContainsUtf8:
    case CanonicalPipelineAttestationClaimKindV0.NormalizedJsonFieldEqualsUtf8:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation claim kind: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationEvidenceKindV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationEvidenceKindV0 {
  switch (value) {
    case CanonicalPipelineAttestationEvidenceKindV0.InlineUtf8:
    case CanonicalPipelineAttestationEvidenceKindV0.InlineJsonUtf8:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation evidence kind: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationNormalizedFormV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationNormalizedFormV0 {
  switch (value) {
    case CanonicalPipelineAttestationNormalizedFormV0.Utf8Text:
    case CanonicalPipelineAttestationNormalizedFormV0.CanonicalJsonUtf8:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation normalized form: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationConsistencyRelationV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationConsistencyRelationV0 {
  switch (value) {
    case CanonicalPipelineAttestationConsistencyRelationV0.EvidenceRootDigestEquals:
    case CanonicalPipelineAttestationConsistencyRelationV0.NormalizedEvidenceDigestEquals:
    case CanonicalPipelineAttestationConsistencyRelationV0.NormalizedTextContainsUtf8:
    case CanonicalPipelineAttestationConsistencyRelationV0.NormalizedJsonFieldEqualsUtf8:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation consistency relation: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationStatusV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationStatusV0 {
  switch (value) {
    case CanonicalPipelineAttestationStatusV0.Accepted:
    case CanonicalPipelineAttestationStatusV0.Rejected:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation status: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationProofKindV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationProofKindV0 {
  switch (value) {
    case CanonicalPipelineAttestationProofKindV0.Mock:
    case CanonicalPipelineAttestationProofKindV0.Stark:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation proof kind: ${value}`,
      );
  }
}

function parseCanonicalPipelineAttestationFailureReasonV0(
  value: string,
  label: string,
): CanonicalPipelineAttestationFailureReasonV0 {
  switch (value) {
    case CanonicalPipelineAttestationFailureReasonV0.None:
    case CanonicalPipelineAttestationFailureReasonV0.UnsupportedAttestationMode:
    case CanonicalPipelineAttestationFailureReasonV0.MalformedEvidence:
    case CanonicalPipelineAttestationFailureReasonV0.NormalizationFailure:
    case CanonicalPipelineAttestationFailureReasonV0.ConsistencyMismatch:
    case CanonicalPipelineAttestationFailureReasonV0.UnsupportedProvenanceType:
    case CanonicalPipelineAttestationFailureReasonV0.ProvenanceSignatureInvalid:
    case CanonicalPipelineAttestationFailureReasonV0.VerificationLayerFailure:
    case CanonicalPipelineAttestationFailureReasonV0.AttestationProofVerificationFailure:
    case CanonicalPipelineAttestationFailureReasonV0.SettlementLayerFailure:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline attestation failure reason: ${value}`,
      );
  }
}

function parseCanonicalPipelineBurnReasonV0(
  value: string,
  label: string,
): CanonicalPipelineBurnReasonV0 {
  switch (value) {
    case CanonicalPipelineBurnReasonV0.ProduceCanonicalTruthArtifact:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline burn reason: ${value}`,
      );
  }
}

function parseCanonicalPipelineBurnCategoryV0(
  value: string,
  label: string,
): CanonicalPipelineBurnCategoryV0 {
  switch (value) {
    case CanonicalPipelineBurnCategoryV0.ExecutionTruthProduction:
    case CanonicalPipelineBurnCategoryV0.AttestationTruthProduction:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline burn category: ${value}`,
      );
  }
}

function parseCanonicalPipelineFeeDispositionV0(
  value: string,
  label: string,
): CanonicalPipelineFeeDispositionV0 {
  switch (value) {
    case CanonicalPipelineFeeDispositionV0.BurnedForCanonicalTruth:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline fee disposition: ${value}`,
      );
  }
}

function parseCanonicalPipelineFutureTokenBindingStatusV0(
  value: string,
  label: string,
): CanonicalPipelineFutureTokenBindingStatusV0 {
  switch (value) {
    case CanonicalPipelineFutureTokenBindingStatusV0.PendingExternalAnchor:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline future token binding status: ${value}`,
      );
  }
}

function parseCanonicalPipelineSettlementReasonV0(
  value: string,
  label: string,
): CanonicalPipelineSettlementReasonV0 {
  switch (value) {
    case CanonicalPipelineSettlementReasonV0.AcceptedAndCommitted:
    case CanonicalPipelineSettlementReasonV0.NotRunExecutionRejected:
    case CanonicalPipelineSettlementReasonV0.RejectedVerificationMismatch:
    case CanonicalPipelineSettlementReasonV0.RejectedLocalSettlement:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline settlement reason: ${value}`,
      );
  }
}

function parseCanonicalPipelineTruthArtifactKindV0(
  value: string,
  label: string,
): CanonicalPipelineTruthArtifactKindV0 {
  switch (value) {
    case CanonicalPipelineTruthArtifactKindV0.ExecutionReport:
    case CanonicalPipelineTruthArtifactKindV0.AttestationReport:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline truth artifact kind: ${value}`,
      );
  }
}

function parseCanonicalPipelineFailureStageV0(
  value: string,
  label: string,
): CanonicalPipelineFailureStageV0 {
  switch (value) {
    case CanonicalPipelineFailureStageV0.None:
    case CanonicalPipelineFailureStageV0.Request:
    case CanonicalPipelineFailureStageV0.Execution:
    case CanonicalPipelineFailureStageV0.Verification:
    case CanonicalPipelineFailureStageV0.Settlement:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline failure stage: ${value}`,
      );
  }
}

function parseCanonicalPipelineFailureReasonCodeV0(
  value: string,
  label: string,
): CanonicalPipelineFailureReasonCodeV0 {
  switch (value) {
    case CanonicalPipelineFailureReasonCodeV0.None:
    case CanonicalPipelineFailureReasonCodeV0.TransferExecutionRejected:
    case CanonicalPipelineFailureReasonCodeV0.UnsupportedAttestationMode:
    case CanonicalPipelineFailureReasonCodeV0.AttestationMalformedEvidence:
    case CanonicalPipelineFailureReasonCodeV0.AttestationNormalizationFailure:
    case CanonicalPipelineFailureReasonCodeV0.AttestationConsistencyMismatch:
    case CanonicalPipelineFailureReasonCodeV0.VerificationLayerMismatch:
    case CanonicalPipelineFailureReasonCodeV0.SettlementAcceptanceRejected:
    case CanonicalPipelineFailureReasonCodeV0.SettlementHeadMismatch:
    case CanonicalPipelineFailureReasonCodeV0.WalletBindingMismatch:
    case CanonicalPipelineFailureReasonCodeV0.UnsupportedProvenanceType:
    case CanonicalPipelineFailureReasonCodeV0.ProvenanceSignatureInvalid:
    case CanonicalPipelineFailureReasonCodeV0.AttestationProofVerificationRejected:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline failure reason code: ${value}`,
      );
  }
}

function parseCanonicalPipelineHeadAuthorityModeV0(
  value: string,
  label: string,
): CanonicalPipelineHeadAuthorityModeV0 {
  switch (value) {
    case CanonicalPipelineHeadAuthorityModeV0.AuthoritativePersistent:
    case CanonicalPipelineHeadAuthorityModeV0.StatelessNonAuthoritative:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline head authority mode: ${value}`,
      );
  }
}

function parseCanonicalPipelineNetworkModeV0(
  value: string,
  label: string,
): CanonicalPipelineNetworkModeV0 {
  switch (value) {
    case CanonicalPipelineNetworkModeV0.Local:
    case CanonicalPipelineNetworkModeV0.Bridged:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline network mode: ${value}`,
      );
  }
}

function parseCanonicalPipelineSettlementAnchorTypeV0(
  value: string,
  label: string,
): CanonicalPipelineSettlementAnchorTypeV0 {
  switch (value) {
    case CanonicalPipelineSettlementAnchorTypeV0.Local:
    case CanonicalPipelineSettlementAnchorTypeV0.Simulated:
    case CanonicalPipelineSettlementAnchorTypeV0.External:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline settlement anchor type: ${value}`,
      );
  }
}

function parseCanonicalPipelineExternalAnchorVerificationStatusV0(
  value: string,
  label: string,
): CanonicalPipelineExternalAnchorVerificationStatusV0 {
  switch (value) {
    case CanonicalPipelineExternalAnchorVerificationStatusV0.NotRequested:
    case CanonicalPipelineExternalAnchorVerificationStatusV0.Accepted:
    case CanonicalPipelineExternalAnchorVerificationStatusV0.Rejected:
    case CanonicalPipelineExternalAnchorVerificationStatusV0.Disconnected:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `${label} has unsupported canonical pipeline anchor verification status: ${value}`,
      );
  }
}

function parseCanonicalPipelineEvidenceProvenanceTypeV0(
  value: string,
  label: string,
): CanonicalPipelineEvidenceProvenanceTypeV0 {
  switch (value) {
    case CanonicalPipelineEvidenceProvenanceTypeV0.Inline:
    case CanonicalPipelineEvidenceProvenanceTypeV0.HashReference:
    case CanonicalPipelineEvidenceProvenanceTypeV0.SignedBlob:
    case CanonicalPipelineEvidenceProvenanceTypeV0.AnchoredExternal:
      return value;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `${label} has unsupported canonical pipeline provenance type: ${value}`,
      );
  }
}

function parseProofVectorTamperTargetV0(value: string): ProofVectorTamperTargetV0 {
  switch (value) {
    case ProofVectorTamperTargetV0.ProofBytes:
      return ProofVectorTamperTargetV0.ProofBytes;
    case ProofVectorTamperTargetV0.ProofBindingDigest:
      return ProofVectorTamperTargetV0.ProofBindingDigest;
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `unsupported proof-vector tamper target: ${value}`,
      );
  }
}

function rustProofSystemV0(value: ProofSystemV0): string {
  switch (normalizeProofSystemV0(value)) {
    case ProofSystemV0.Mock:
      return "MOCK";
    case ProofSystemV0.Stark:
      return "STARK";
  }
}

function rustExpectedResultV0(value: ScenarioResultV0): string {
  switch (value) {
    case ScenarioResultV0.Accepted:
      return "ACCEPTED";
    case ScenarioResultV0.ExecutionRejected:
      return "EXECUTION_REJECTED";
    case ScenarioResultV0.VerificationRejected:
      return "VERIFICATION_REJECTED";
    case ScenarioResultV0.SettlementRejected:
      return "SETTLEMENT_REJECTED";
    default:
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `unsupported scenario result: ${String(value)}`,
      );
  }
}

function cloneAccountV0(account: AccountV0): AccountV0 {
  return {
    accountId: copyBytesV0(account.accountId),
    balance: account.balance,
    nonce: account.nonce,
  };
}

function normalizeAccountV0(account: AccountV0): AccountV0 {
  return {
    accountId: copyBytes32V0("accountId", account.accountId),
    balance: toU64BigIntV0(account.balance, "account.balance"),
    nonce: toU64BigIntV0(account.nonce, "account.nonce"),
  };
}

function cloneTransferTxV0(tx: TransferTxV0): TransferTxV0 {
  return {
    txVersion: tx.txVersion,
    senderAccountId: copyBytesV0(tx.senderAccountId),
    recipientAccountId: copyBytesV0(tx.recipientAccountId),
    senderNonce: tx.senderNonce,
    amount: tx.amount,
  };
}

function accountListsEqualV0(left: AccountV0[], right: AccountV0[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (
      !bytesEqualV0(left[i].accountId, right[i].accountId) ||
      left[i].balance !== right[i].balance ||
      left[i].nonce !== right[i].nonce
    ) {
      return false;
    }
  }
  return true;
}

function transferTxListsEqualV0(left: TransferTxV0[], right: TransferTxV0[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (
      left[i].txVersion !== right[i].txVersion ||
      !bytesEqualV0(left[i].senderAccountId, right[i].senderAccountId) ||
      !bytesEqualV0(left[i].recipientAccountId, right[i].recipientAccountId) ||
      left[i].senderNonce !== right[i].senderNonce ||
      left[i].amount !== right[i].amount
    ) {
      return false;
    }
  }
  return true;
}

function canonicalExecutionOutcomeListsEqualV0(
  left: ExecutionOutcomeV0[],
  right: ExecutionOutcomeV0[],
): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (
      left[i].txIndex !== right[i].txIndex ||
      !bytesEqualV0(left[i].senderAccountId, right[i].senderAccountId) ||
      left[i].consumedNonce !== right[i].consumedNonce ||
      left[i].feeCharged !== right[i].feeCharged ||
      !bytesEqualV0(left[i].touchedAccountsCommitment, right[i].touchedAccountsCommitment) ||
      !bytesEqualV0(left[i].operationResultCommitment, right[i].operationResultCommitment) ||
      left[i].status !== right[i].status
    ) {
      return false;
    }
  }
  return true;
}

function appliedTransferStepListsEqualV0(
  left: AppliedTransferStepV0[],
  right: AppliedTransferStepV0[],
): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (
      left[i].txIndex !== right[i].txIndex ||
      !bytesEqualV0(left[i].senderAccountId, right[i].senderAccountId) ||
      !bytesEqualV0(left[i].recipientAccountId, right[i].recipientAccountId) ||
      left[i].senderNonceBefore !== right[i].senderNonceBefore ||
      left[i].senderNonceAfter !== right[i].senderNonceAfter ||
      left[i].senderBalanceBefore !== right[i].senderBalanceBefore ||
      left[i].senderBalanceAfter !== right[i].senderBalanceAfter ||
      left[i].recipientBalanceBefore !== right[i].recipientBalanceBefore ||
      left[i].recipientBalanceAfter !== right[i].recipientBalanceAfter ||
      left[i].amount !== right[i].amount ||
      left[i].feeCharged !== right[i].feeCharged
    ) {
      return false;
    }
  }
  return true;
}

function outcomeListsEqualV0(
  left: ExecutionOutcomeV0[],
  right: ProofVectorExpectedOutcomeV0[],
): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (
      left[i].txIndex !== right[i].txIndex ||
      !bytesEqualV0(left[i].senderAccountId, right[i].senderAccountId) ||
      left[i].consumedNonce !== right[i].consumedNonce ||
      left[i].feeCharged !== right[i].feeCharged ||
      !bytesEqualV0(left[i].touchedAccountsCommitment, right[i].touchedAccountsCommitment) ||
      !bytesEqualV0(left[i].operationResultCommitment, right[i].operationResultCommitment) ||
      left[i].status !== right[i].status
    ) {
      return false;
    }
  }
  return true;
}

function accountLeafHashV0(account: AccountV0): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1,
      accountCanonicalBytesV0(account),
    ),
  );
}

function accountCanonicalBytesV0(account: AccountV0): Uint8Array {
  return concatBytesV0(
    copyBytes32V0("accountId", account.accountId),
    u64ToLeBytesV0(account.balance),
    u64ToLeBytesV0(account.nonce),
  );
}

function transferCanonicalBytesV0(tx: TransferTxV0): Uint8Array {
  return concatBytesV0(
    AURA_L2_LOCAL_TRANSFER_TX_DOMAIN_SEPARATOR_V1,
    u32ToLeBytesV0(tx.txVersion),
    copyBytes32V0("senderAccountId", tx.senderAccountId),
    copyBytes32V0("recipientAccountId", tx.recipientAccountId),
    u64ToLeBytesV0(tx.senderNonce),
    u64ToLeBytesV0(tx.amount),
  );
}

function batchContextV0(config: ExecutionConfigV0): BatchContextV0 {
  const systemConfigCommitment = sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_SYSTEM_CONFIG_DOMAIN_SEPARATOR_V1,
      copyBytes32V0("rollupId", config.rollupId),
      u32ToLeBytesV0(config.executionModelVersion),
      u32ToLeBytesV0(config.batchVersion),
    ),
  );
  const feeParametersCommitment = sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_FEE_PARAMETERS_DOMAIN_SEPARATOR_V1,
      u64ToLeBytesV0(ZERO_FEE_PER_TRANSFER_V0),
    ),
  );
  const validityReferenceCommitment = sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_VALIDITY_REFERENCE_NONE_DOMAIN_SEPARATOR_V1,
      Uint8Array.of(0),
    ),
  );
  const executionConstantsCommitment = sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_EXECUTION_CONSTANTS_DOMAIN_SEPARATOR_V1,
      u32ToLeBytesV0(TRANSFER_TX_VERSION_V0),
      u32ToLeBytesV0(TRANSITION_BINDING_VERSION_V0),
      Uint8Array.of(EXECUTION_OUTCOME_STATUS_APPLIED_V0),
    ),
  );
  return {
    systemConfigCommitment,
    feeParametersCommitment,
    validityReferenceCommitment,
    executionConstantsCommitment,
  };
}

function batchContextBytesV0(batchContext: BatchContextV0): Uint8Array {
  return concatBytesV0(
    D_CONTEXT_V1,
    u32ToLeBytesV0(TRANSITION_BINDING_VERSION_V0),
    batchContext.systemConfigCommitment,
    batchContext.feeParametersCommitment,
    batchContext.validityReferenceCommitment,
    batchContext.executionConstantsCommitment,
  );
}

function feeSummaryV0(txCount: bigint): FeeSummaryV0 {
  return {
    txCount,
    totalFeeCharged: 0n,
  };
}

function feeSummaryCanonicalBytesV0(feeSummary: FeeSummaryV0): Uint8Array {
  return concatBytesV0(
    AURA_L2_LOCAL_FEE_SUMMARY_DOMAIN_SEPARATOR_V1,
    u32ToLeBytesV0(1),
    u64ToLeBytesV0(feeSummary.txCount),
    u64ToLeBytesV0(feeSummary.totalFeeCharged),
    ZERO32_V0,
  );
}

function deriveTouchedAccountsCommitmentV0(
  senderAccountId: Uint8Array,
  recipientAccountId: Uint8Array,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_TOUCHED_ACCOUNTS_DOMAIN_SEPARATOR_V1,
      copyBytes32V0("senderAccountId", senderAccountId),
      copyBytes32V0("recipientAccountId", recipientAccountId),
    ),
  );
}

function deriveTransferResultCommitmentV0(
  amount: bigint,
  senderBalanceBefore: bigint,
  senderBalanceAfter: bigint,
  recipientBalanceBefore: bigint,
  recipientBalanceAfter: bigint,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_TRANSFER_RESULT_DOMAIN_SEPARATOR_V1,
      u64ToLeBytesV0(amount),
      u64ToLeBytesV0(senderBalanceBefore),
      u64ToLeBytesV0(senderBalanceAfter),
      u64ToLeBytesV0(recipientBalanceBefore),
      u64ToLeBytesV0(recipientBalanceAfter),
    ),
  );
}

function outcomeCanonicalBytesV0(outcome: ExecutionOutcomeV0): Uint8Array {
  return concatBytesV0(
    D_OUTCOME_V1,
    u64ToLeBytesV0(outcome.txIndex),
    copyBytes32V0("senderAccountId", outcome.senderAccountId),
    u64ToLeBytesV0(outcome.consumedNonce),
    u64ToLeBytesV0(outcome.feeCharged),
    copyBytes32V0(
      "touchedAccountsCommitment",
      outcome.touchedAccountsCommitment,
    ),
    copyBytes32V0(
      "operationResultCommitment",
      outcome.operationResultCommitment,
    ),
    Uint8Array.of(outcome.status),
  );
}

function deriveStarkProofBindingDigestV0(
  proofVersion: number,
  publicInputsHash: Uint8Array,
  traceDigest: Uint8Array,
  traceLayoutDigest: Uint8Array,
  proofBytes: Uint8Array,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR_V1,
      u32ToLeBytesV0(proofVersion),
      copyBytes32V0("publicInputsHash", publicInputsHash),
      copyBytes32V0("traceDigest", traceDigest),
      copyBytes32V0("traceLayoutDigest", traceLayoutDigest),
      sha256BytesV0(proofBytes),
    ),
  );
}

function deriveMockProofBindingDigestFromWitnessDigestV0(
  proofVersion: number,
  publicInputsHash: Uint8Array,
  traceDigest: Uint8Array,
  traceLayoutDigest: Uint8Array,
  witnessDigest: Uint8Array,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      textEncoder.encode("AURA_L2_LOCAL_MOCK_PROOF_BINDING_V1"),
      u32ToLeBytesV0(proofVersion),
      copyBytes32V0("publicInputsHash", publicInputsHash),
      copyBytes32V0("traceDigest", traceDigest),
      copyBytes32V0("traceLayoutDigest", traceLayoutDigest),
      copyBytes32V0("witnessDigest", witnessDigest),
    ),
  );
}

function deriveStarkProofBindingDigestFromHashV0(
  proofVersion: number,
  publicInputsHash: Uint8Array,
  traceDigest: Uint8Array,
  traceLayoutDigest: Uint8Array,
  proofBytesHash: Uint8Array,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      AURA_L2_LOCAL_STARK_PROOF_BINDING_DOMAIN_SEPARATOR_V1,
      u32ToLeBytesV0(proofVersion),
      copyBytes32V0("publicInputsHash", publicInputsHash),
      copyBytes32V0("traceDigest", traceDigest),
      copyBytes32V0("traceLayoutDigest", traceLayoutDigest),
      copyBytes32V0("proofBytesHash", proofBytesHash),
    ),
  );
}

function decodePublicInputsV0(bytes: Uint8Array): PublicInputsV0 {
  if (bytes.length !== PUBLIC_INPUT_SCHEMA_LEN_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `invalid public input length: expected ${PUBLIC_INPUT_SCHEMA_LEN_V0}, got ${bytes.length}`,
    );
  }
  const transitionBindingVersion = readU32LeV0(bytes, 0, "transitionBindingVersion");
  if (transitionBindingVersion !== TRANSITION_BINDING_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported transition binding version in public input bytes: ${transitionBindingVersion}`,
    );
  }
  return {
    transitionBindingVersion,
    rollupId: bytes.slice(4, 36),
    executionModelVersion: readU32LeV0(bytes, 36, "executionModelVersion"),
    batchVersion: readU32LeV0(bytes, 40, "batchVersion"),
    batchNumber: readU64LeV0(bytes, 44, "batchNumber"),
    parentBatchCommitment: bytes.slice(52, 84),
    txCount: readU64LeV0(bytes, 84, "txCount"),
    feeSummaryCommitment: bytes.slice(92, 124),
    preStateRoot: bytes.slice(124, 156),
    postStateRoot: bytes.slice(156, 188),
    transactionsCommitment: bytes.slice(188, 220),
    outcomesCommitment: bytes.slice(220, 252),
    batchContextCommitment: bytes.slice(252, 284),
  };
}

function publicInputsEqualV0(left: PublicInputsV0, right: PublicInputsV0): boolean {
  return (
    left.transitionBindingVersion === right.transitionBindingVersion &&
    bytesEqualV0(left.rollupId, right.rollupId) &&
    left.executionModelVersion === right.executionModelVersion &&
    left.batchVersion === right.batchVersion &&
    left.batchNumber === right.batchNumber &&
    bytesEqualV0(left.parentBatchCommitment, right.parentBatchCommitment) &&
    left.txCount === right.txCount &&
    bytesEqualV0(left.feeSummaryCommitment, right.feeSummaryCommitment) &&
    bytesEqualV0(left.preStateRoot, right.preStateRoot) &&
    bytesEqualV0(left.postStateRoot, right.postStateRoot) &&
    bytesEqualV0(left.transactionsCommitment, right.transactionsCommitment) &&
    bytesEqualV0(left.outcomesCommitment, right.outcomesCommitment) &&
    bytesEqualV0(left.batchContextCommitment, right.batchContextCommitment)
  );
}

function stageOutcomesForActualResultV0(
  actualResult: ScenarioResultV0,
): CanonicalPipelineStageOutcomesV0 {
  switch (actualResult) {
    case ScenarioResultV0.Accepted:
      return {
        executionStatus: CanonicalPipelineExecutionStatusV0.Applied,
        verificationStatus: CanonicalPipelineVerificationStatusV0.Passed,
        settlementStatus: CanonicalPipelineSettlementStatusV0.Accepted,
      };
    case ScenarioResultV0.ExecutionRejected:
      return {
        executionStatus: CanonicalPipelineExecutionStatusV0.Rejected,
        verificationStatus: CanonicalPipelineVerificationStatusV0.NotRun,
        settlementStatus: CanonicalPipelineSettlementStatusV0.NotRun,
      };
    case ScenarioResultV0.VerificationRejected:
      return {
        executionStatus: CanonicalPipelineExecutionStatusV0.Applied,
        verificationStatus: CanonicalPipelineVerificationStatusV0.Rejected,
        settlementStatus: CanonicalPipelineSettlementStatusV0.Rejected,
      };
    case ScenarioResultV0.SettlementRejected:
      return {
        executionStatus: CanonicalPipelineExecutionStatusV0.Applied,
        verificationStatus: CanonicalPipelineVerificationStatusV0.Passed,
        settlementStatus: CanonicalPipelineSettlementStatusV0.Rejected,
      };
  }
}

function canonicalPipelineRequestBindingHashV0(
  request: CanonicalPipelineRequestV0,
): Uint8Array {
  const orderedAccounts = request.state.orderedAccounts();
  const chunks: Uint8Array[] = [
    D_CANONICAL_PIPELINE_REQUEST_V1,
    ...canonicalPipelineRequestBindingPayloadChunksV0(request, orderedAccounts),
  ];
  return sha256BytesV0(concatBytesV0(...chunks));
}

function canonicalPipelineRequestBindingPayloadChunksV0(
  request: CanonicalPipelineRequestV0,
  orderedAccounts: AccountV0[],
): Uint8Array[] {
  return [
    ...canonicalPipelineBurnMeteringPayloadChunksV0(request, orderedAccounts),
    lengthPrefixedBytesV0(textEncoder.encode(request.fixtureName)),
    optionalTamperBytesV0(request.tamperPublicInputs ?? null),
    optionalTamperBytesV0(request.tamperProofBindingDigest ?? null),
    lengthPrefixedBytesV0(textEncoder.encode(rustExpectedResultV0(request.expectedResult))),
    u64ToLeBytesV0(request.economic.declaredFeeUnits),
  ];
}

function canonicalPipelineBurnMeteredBytesV0(
  request: CanonicalPipelineRequestV0,
): Uint8Array {
  return concatBytesV0(
    D_CANONICAL_PIPELINE_BURN_METERING_V1,
    ...canonicalPipelineBurnMeteringPayloadChunksV0(request, request.state.orderedAccounts()),
  );
}

function canonicalPipelineBurnMeteringPayloadChunksV0(
  request: CanonicalPipelineRequestV0,
  orderedAccounts: AccountV0[],
): Uint8Array[] {
  return [
    u32ToLeBytesV0(request.pipelineSchemaVersion),
    lengthPrefixedBytesV0(textEncoder.encode(request.pipelineId)),
    lengthPrefixedBytesV0(textEncoder.encode(rustProofSystemV0(request.proofSystem))),
    u32ToLeBytesV0(request.economic.economicPolicyVersion),
    lengthPrefixedBytesV0(textEncoder.encode(request.economic.requestKind)),
    lengthPrefixedBytesV0(textEncoder.encode(request.economic.burnIntent)),
    u32ToLeBytesV0(request.accounting.accountingPolicyVersion),
    lengthPrefixedBytesV0(textEncoder.encode(request.accounting.paymentIntent)),
    lengthPrefixedBytesV0(textEncoder.encode(request.accounting.settlementIntent)),
    u32ToLeBytesV0(request.ledger.ledgerPolicyVersion),
    copyBytes32V0("ledger.payerAccountId", request.ledger.payerAccountId),
    u64ToLeBytesV0(request.ledger.totalSupply),
    u64ToLeBytesV0(request.ledger.burnedSupply),
    canonicalPipelineLedgerOrderedAccountBytesV0(request.ledger.accounts),
    u32ToLeBytesV0(request.head.settlementHeadVersion),
    copyBytes32V0("head.previousHeadHash", request.head.previousHeadHash),
    u64ToLeBytesV0(request.head.headSequenceNumber),
    u32ToLeBytesV0(request.walletBinding.walletBindingVersion),
    copyBytes32V0("walletBinding.accountId", request.walletBinding.accountId),
    lengthPrefixedBytesV0(textEncoder.encode(request.walletBinding.walletAddress)),
    u32ToLeBytesV0(request.tokenAnchor.tokenPolicyVersion),
    lengthPrefixedBytesV0(textEncoder.encode(request.tokenAnchor.networkMode)),
    lengthPrefixedBytesV0(textEncoder.encode(request.tokenAnchor.settlementAnchorType)),
    request.tokenAnchor.externalBalanceReference === null
      ? Uint8Array.of(0)
      : concatBytesV0(
          Uint8Array.of(1),
          lengthPrefixedBytesV0(
            textEncoder.encode(request.tokenAnchor.externalBalanceReference.referenceId),
          ),
          request.tokenAnchor.externalBalanceReference.observedBalance === null
            ? Uint8Array.of(0)
            : concatBytesV0(
                Uint8Array.of(1),
                u64ToLeBytesV0(request.tokenAnchor.externalBalanceReference.observedBalance),
              ),
          request.tokenAnchor.externalBalanceReference.observedSlot === null
            ? Uint8Array.of(0)
            : concatBytesV0(
                Uint8Array.of(1),
                u64ToLeBytesV0(request.tokenAnchor.externalBalanceReference.observedSlot),
              ),
          Uint8Array.of(request.tokenAnchor.externalBalanceReference.connected ? 1 : 0),
        ),
    Uint8Array.of(request.tokenAnchor.enforceExternalMatch ? 1 : 0),
    request.tokenAnchor.expectedExternalBalance === null
      ? Uint8Array.of(0)
      : concatBytesV0(Uint8Array.of(1), u64ToLeBytesV0(request.tokenAnchor.expectedExternalBalance)),
    optionalCanonicalPipelineAttestationBytesV0(request.attestation),
    copyBytes32V0("rollupId", request.rollupId),
    canonicalPipelineOrderedAccountBytesV0(orderedAccounts),
    u64ToLeBytesV0(request.batch.batchNumber),
    copyBytes32V0("parentBatchCommitment", request.batch.parentBatchCommitment),
    canonicalPipelineTransactionBytesV0(request.batch.transactions),
  ];
}

interface CanonicalPipelinePreparedAttestationV0 {
  claimDigest: Uint8Array;
  evidenceSummary: CanonicalPipelineAttestationEvidenceSummaryV0;
  normalizationSummary: CanonicalPipelineAttestationNormalizationSummaryV0;
  consistencyResult: CanonicalPipelineAttestationConsistencyResultV0;
  provenanceSummary: CanonicalPipelineProvenanceSummaryV0;
  attestationTupleDigest: Uint8Array;
}

function canonicalPipelineSupportedAttestationConstraintsV0(): CanonicalPipelineAttestationConstraintsV0 {
  return {
    requireUniqueLabels: true,
    maxEvidenceItems: 16n,
    maxTotalNormalizedBytes: 16384n,
  };
}

function canonicalPipelineAttestationPayloadUtf8V0(
  item: CanonicalPipelineAttestationEvidenceItemV0,
): string {
  return item.evidencePayload.payloadUtf8;
}

function canonicalPipelineNormalizeUtf8TextV0(payload: string): string {
  const normalizedLineEndings = payload.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalizedLineEndings.split("\n").map((line) => line.replace(/[ \t]+$/g, ""));
  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines.join("\n");
}

function canonicalPipelineCanonicalizeJsonValueV0(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalPipelineCanonicalizeJsonValueV0).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    return `{${entries
      .map(
        ([key, nestedValue]) =>
          `${JSON.stringify(key)}:${canonicalPipelineCanonicalizeJsonValueV0(nestedValue)}`,
      )
      .join(",")}}`;
  }
  throw new AuraTypescriptSdkErrorV0(
    "InvalidFixture",
    `canonical pipeline attestation encountered unsupported JSON value type: ${typeof value}`,
  );
}

function canonicalPipelineAttestationClaimPayloadBytesV0(
  claimPayload: CanonicalPipelineAttestationClaimPayloadV0,
): Uint8Array {
  if ("expectedEvidenceRootDigest" in claimPayload) {
    return copyBytes32V0(
      "attestation.claim.claimPayload.expectedEvidenceRootDigest",
      claimPayload.expectedEvidenceRootDigest,
    );
  }
  if ("expectedEvidenceDigest" in claimPayload) {
    return concatBytesV0(
      lengthPrefixedBytesV0(textEncoder.encode(claimPayload.targetLabel)),
      copyBytes32V0(
        "attestation.claim.claimPayload.expectedEvidenceDigest",
        claimPayload.expectedEvidenceDigest,
      ),
    );
  }
  if ("expectedSubstringUtf8" in claimPayload) {
    return concatBytesV0(
      lengthPrefixedBytesV0(textEncoder.encode(claimPayload.targetLabel)),
      lengthPrefixedBytesV0(textEncoder.encode(claimPayload.expectedSubstringUtf8)),
    );
  }
  return concatBytesV0(
    lengthPrefixedBytesV0(textEncoder.encode(claimPayload.targetLabel)),
    u64ToLeBytesV0(BigInt(claimPayload.fieldPath.length)),
    ...claimPayload.fieldPath.map((segment) => lengthPrefixedBytesV0(textEncoder.encode(segment))),
    lengthPrefixedBytesV0(textEncoder.encode(claimPayload.expectedValueUtf8)),
  );
}

function canonicalPipelineAttestationClaimBytesV0(
  claim: CanonicalPipelineAttestationClaimV0,
): Uint8Array {
  return concatBytesV0(
    lengthPrefixedBytesV0(textEncoder.encode(claim.claimKind)),
    canonicalPipelineAttestationClaimPayloadBytesV0(claim.claimPayload),
  );
}

function canonicalPipelineAttestationEvidencePayloadBytesV0(
  evidencePayload: CanonicalPipelineAttestationEvidencePayloadV0,
): Uint8Array {
  return lengthPrefixedBytesV0(textEncoder.encode(evidencePayload.payloadUtf8));
}

function optionalCanonicalPipelineEvidenceSignatureBytesV0(
  signature: CanonicalPipelineEvidenceSignatureV0 | null,
): Uint8Array {
  if (signature === null) {
    return Uint8Array.of(0);
  }
  return concatBytesV0(
    Uint8Array.of(1),
    copyBytes32V0("provenance.signature.signerPublicKey", signature.signerPublicKey),
    copyBytesFixedV0("provenance.signature.signature", signature.signature, 64),
  );
}

function canonicalPipelineProvenanceBytesV0(
  provenance: CanonicalPipelineEvidenceProvenanceV0,
): Uint8Array {
  return concatBytesV0(
    u32ToLeBytesV0(provenance.provenancePolicyVersion),
    lengthPrefixedBytesV0(textEncoder.encode(provenance.provenanceType)),
    lengthPrefixedBytesV0(textEncoder.encode(provenance.sourceType)),
    lengthPrefixedBytesV0(textEncoder.encode(provenance.sourceIdentifier)),
    optionalCanonicalPipelineEvidenceSignatureBytesV0(provenance.signature),
    provenance.timestampUnixSeconds === null
      ? Uint8Array.of(0)
      : concatBytesV0(Uint8Array.of(1), u64ToLeBytesV0(provenance.timestampUnixSeconds)),
  );
}

function canonicalPipelineAttestationEvidenceItemBytesV0(
  item: CanonicalPipelineAttestationEvidenceItemV0,
): Uint8Array {
  return concatBytesV0(
    lengthPrefixedBytesV0(textEncoder.encode(item.label)),
    lengthPrefixedBytesV0(textEncoder.encode(item.evidenceKind)),
    canonicalPipelineAttestationEvidencePayloadBytesV0(item.evidencePayload),
    canonicalPipelineProvenanceBytesV0(item.provenance),
  );
}

function optionalCanonicalPipelineAttestationBytesV0(
  attestation: CanonicalPipelineAttestationRequestV0 | null,
): Uint8Array {
  if (attestation === null) {
    return Uint8Array.of(0);
  }
  return concatBytesV0(
    Uint8Array.of(1),
    u32ToLeBytesV0(attestation.attestationSchemaVersion),
    lengthPrefixedBytesV0(textEncoder.encode(attestation.attestationScope)),
    lengthPrefixedBytesV0(textEncoder.encode(attestation.attestationProofKind)),
    u32ToLeBytesV0(attestation.normalizationPolicyVersion),
    Uint8Array.of(attestation.attestationConstraints.requireUniqueLabels ? 1 : 0),
    u64ToLeBytesV0(attestation.attestationConstraints.maxEvidenceItems),
    u64ToLeBytesV0(attestation.attestationConstraints.maxTotalNormalizedBytes),
    canonicalPipelineAttestationClaimBytesV0(attestation.claim),
    u64ToLeBytesV0(BigInt(attestation.evidenceItems.length)),
    ...attestation.evidenceItems.map(canonicalPipelineAttestationEvidenceItemBytesV0),
    optionalTamperBytesV0(attestation.tamperStarkPublicInputsDigest),
    optionalTamperBytesV0(attestation.tamperStarkProofBytes),
  );
}

function canonicalPipelineBurnDerivationInputsFromRequestV0(
  request: CanonicalPipelineRequestV0,
): CanonicalPipelineBurnDerivationInputsV0 {
  const attestationEvidenceItems = BigInt(request.attestation?.evidenceItems.length ?? 0);
  const attestationClaimBytes =
    request.attestation === null
      ? 0n
      : BigInt(canonicalPipelineAttestationClaimBytesV0(request.attestation.claim).length);
  const attestationEvidenceBytes =
    request.attestation === null
      ? 0n
      : BigInt(
          concatBytesV0(
            u64ToLeBytesV0(BigInt(request.attestation.evidenceItems.length)),
            ...request.attestation.evidenceItems.map(
              canonicalPipelineAttestationEvidenceItemBytesV0,
            ),
          ).length,
        );
  return {
    txCount: BigInt(request.batch.transactions.length),
    meteredRequestSizeBytes: BigInt(canonicalPipelineBurnMeteredBytesV0(request).length),
    requestKind: request.economic.requestKind,
    proofSystem: request.proofSystem,
    attestationEvidenceItems,
    attestationClaimBytes,
    attestationEvidenceBytes,
  };
}

function computeCanonicalPipelineBurnUnitsFromInputsV0(
  inputs: CanonicalPipelineBurnDerivationInputsV0,
): bigint {
  const requestKindUnits =
    inputs.requestKind === CanonicalPipelineRequestKindV0.Execution
      ? LOCAL_CHAIN_CANONICAL_BURN_EXECUTION_KIND_UNITS_V0
      : LOCAL_CHAIN_CANONICAL_BURN_ATTESTATION_KIND_UNITS_V0;
  const proofSystemUnits =
    inputs.proofSystem === ProofSystemV0.Stark
      ? LOCAL_CHAIN_CANONICAL_BURN_STARK_UNITS_V0
      : LOCAL_CHAIN_CANONICAL_BURN_MOCK_UNITS_V0;
  const sizeUnits =
    (inputs.meteredRequestSizeBytes + LOCAL_CHAIN_CANONICAL_BURN_SIZE_CHUNK_BYTES_V0 - 1n) /
    LOCAL_CHAIN_CANONICAL_BURN_SIZE_CHUNK_BYTES_V0;
  return (
    LOCAL_CHAIN_CANONICAL_BURN_BASE_UNITS_V0 +
    requestKindUnits +
    proofSystemUnits +
    inputs.txCount * LOCAL_CHAIN_CANONICAL_BURN_TRANSACTION_UNITS_V0 +
    sizeUnits
  );
}

export function computeCanonicalPipelineBurnUnitsV0(
  request: CanonicalPipelineRequestV0,
): bigint {
  return computeCanonicalPipelineBurnUnitsFromInputsV0(
    canonicalPipelineBurnDerivationInputsFromRequestV0(request),
  );
}

function canonicalPipelineBurnFailureSemanticsV0(): CanonicalPipelineBurnFailureSemanticsV0 {
  return {
    executionRejectedBurnsFullAmount: true,
    verificationRejectedBurnsFullAmount: true,
    settlementRejectedBurnsFullAmount: true,
    partialBurnAllowed: false,
  };
}

function canonicalPipelineBurnPolicyV0(): CanonicalPipelineBurnPolicyV0 {
  return {
    burnPolicyVersion: LOCAL_CHAIN_CANONICAL_BURN_POLICY_VERSION_V0,
    baseUnits: LOCAL_CHAIN_CANONICAL_BURN_BASE_UNITS_V0,
    executionRequestKindUnits: LOCAL_CHAIN_CANONICAL_BURN_EXECUTION_KIND_UNITS_V0,
    attestationRequestKindUnits: LOCAL_CHAIN_CANONICAL_BURN_ATTESTATION_KIND_UNITS_V0,
    mockProofSystemUnits: LOCAL_CHAIN_CANONICAL_BURN_MOCK_UNITS_V0,
    starkProofSystemUnits: LOCAL_CHAIN_CANONICAL_BURN_STARK_UNITS_V0,
    transactionUnitsPerItem: LOCAL_CHAIN_CANONICAL_BURN_TRANSACTION_UNITS_V0,
    meteredRequestSizeChunkBytes: LOCAL_CHAIN_CANONICAL_BURN_SIZE_CHUNK_BYTES_V0,
  };
}

function canonicalPipelineBurnCategoryV0(
  requestKind: CanonicalPipelineRequestKindV0,
): CanonicalPipelineBurnCategoryV0 {
  return requestKind === CanonicalPipelineRequestKindV0.Execution
    ? CanonicalPipelineBurnCategoryV0.ExecutionTruthProduction
    : CanonicalPipelineBurnCategoryV0.AttestationTruthProduction;
}

function canonicalPipelineBurnSummaryFromRequestV0(
  request: CanonicalPipelineRequestV0,
): CanonicalPipelineBurnSummaryV0 {
  const burnDerivationInputs = canonicalPipelineBurnDerivationInputsFromRequestV0(request);
  const computedBurnUnits = computeCanonicalPipelineBurnUnitsFromInputsV0(burnDerivationInputs);
  return {
    burnPolicyVersion: LOCAL_CHAIN_CANONICAL_BURN_POLICY_VERSION_V0,
    burnPolicy: canonicalPipelineBurnPolicyV0(),
    burnReason: CanonicalPipelineBurnReasonV0.ProduceCanonicalTruthArtifact,
    burnCategory: canonicalPipelineBurnCategoryV0(request.economic.requestKind),
    requestKind: request.economic.requestKind,
    burnIntent: request.economic.burnIntent,
    declaredFeeUnits: request.economic.declaredFeeUnits,
    computedBurnUnits,
    consumedBurnUnits: computedBurnUnits,
    burnDerivationInputs,
    requestDeclaresCorrectBurn: request.economic.declaredFeeUnits === computedBurnUnits,
    recomputedBurnMatchesReport: true,
    burnConsumed: true,
    failureSemantics: canonicalPipelineBurnFailureSemanticsV0(),
  };
}

function canonicalPipelineRequestFromReportV0(
  report: CanonicalPipelineReportV0,
): CanonicalPipelineRequestV0 {
  const attestation =
    report.attestationSummary === null
      ? null
      : {
          attestationSchemaVersion: report.attestationSummary.attestationSchemaVersion,
          attestationScope: report.attestationSummary.attestationScope,
          attestationProofKind:
            report.attestationProofSummary?.proofKind ??
            report.attestationSummary.attestationProofKind,
          normalizationPolicyVersion: report.attestationSummary.normalizationPolicyVersion,
          attestationConstraints: { ...report.attestationSummary.attestationConstraints },
          claim: cloneCanonicalPipelineAttestationClaimV0(report.attestationSummary.claim),
          evidenceItems: report.attestationSummary.evidenceSummary.evidenceItems.map((item) => {
            const provenance = report.provenanceSummary?.items.find(
              (entry) => entry.label === item.label,
            );
            if (provenance === undefined) {
              throw new AuraTypescriptSdkErrorV0(
                "RustBridgeFailure",
                `provenanceSummary missing label ${item.label}`,
              );
            }
            return {
              label: item.label,
              evidenceKind: item.evidenceKind,
              evidencePayload: {
                payloadUtf8: item.originalPayloadUtf8,
              },
              provenance: {
                provenancePolicyVersion: provenance.provenancePolicyVersion,
                provenanceType: provenance.provenanceType,
                sourceType: provenance.sourceType,
                sourceIdentifier: provenance.sourceIdentifier,
                signature:
                  provenance.signerPublicKey !== null && provenance.signature !== null
                    ? {
                        signerPublicKey: copyBytesV0(provenance.signerPublicKey),
                        signature: copyBytesFixedV0(
                          "provenance.signature",
                          provenance.signature,
                          64,
                        ),
                      }
                    : null,
                timestampUnixSeconds: provenance.timestampUnixSeconds,
              },
            };
          }),
          tamperStarkPublicInputsDigest:
            report.requestAudit.tamperAttestationStarkPublicInputsDigest === null
              ? null
              : { ...report.requestAudit.tamperAttestationStarkPublicInputsDigest },
          tamperStarkProofBytes:
            report.requestAudit.tamperAttestationStarkProofBytes === null
              ? null
              : { ...report.requestAudit.tamperAttestationStarkProofBytes },
        };
  return {
    pipelineSchemaVersion: report.pipelineSchemaVersion,
    pipelineId: report.pipelineId,
    fixtureName: report.fixtureName,
    proofSystem: report.proofSystem,
    economic: {
      economicPolicyVersion: report.burnSummary.burnPolicyVersion,
      requestKind: report.burnSummary.requestKind,
      burnIntent: report.burnSummary.burnIntent,
      declaredFeeUnits: report.burnSummary.declaredFeeUnits,
    },
    accounting: {
      accountingPolicyVersion: report.accountingSummary.accountingPolicyVersion,
      paymentIntent: report.accountingSummary.paymentIntent,
      settlementIntent: report.accountingSummary.settlementIntent,
    },
    ledger: {
      ledgerPolicyVersion: report.ledgerSummary.ledgerPolicyVersion,
      payerAccountId: copyBytesV0(report.ledgerSummary.payerAccountId),
      totalSupply: report.ledgerSummary.totalSupply,
      burnedSupply: report.ledgerSummary.burnedSupplyBefore,
      accounts: report.ledgerAccounts.orderedAccounts.map((account) => ({
        accountId: copyBytesV0(account.accountId),
        balance: account.balance,
      })),
    },
    head: {
      settlementHeadVersion: report.headTransitionSummary.settlementHeadVersion,
      previousHeadHash: copyBytesV0(report.headTransitionSummary.previousHeadHash),
      headSequenceNumber: report.headTransitionSummary.headSequenceNumber,
    },
    walletBinding: {
      walletBindingVersion: report.walletBindingSummary.walletBindingVersion,
      accountId: copyBytesV0(report.walletBindingSummary.accountId),
      walletAddress: report.walletBindingSummary.walletAddress,
    },
    tokenAnchor: {
      tokenPolicyVersion: report.tokenAnchorSummary.tokenPolicyVersion,
      networkMode: report.tokenAnchorSummary.networkMode,
      settlementAnchorType: report.tokenAnchorSummary.settlementAnchorType,
      externalBalanceReference:
        report.tokenAnchorSummary.externalBalanceReference === null
          ? null
          : {
              referenceId: report.tokenAnchorSummary.externalBalanceReference.referenceId,
              observedBalance:
                report.tokenAnchorSummary.externalBalanceReference.observedBalance,
              observedSlot: report.tokenAnchorSummary.externalBalanceReference.observedSlot,
              connected: report.tokenAnchorSummary.externalBalanceReference.connected,
            },
      enforceExternalMatch:
        report.tokenAnchorSummary.anchorVerificationStatus ===
          CanonicalPipelineExternalAnchorVerificationStatusV0.Rejected ||
        report.tokenAnchorSummary.expectedExternalBalance !== null,
      expectedExternalBalance: report.tokenAnchorSummary.expectedExternalBalance,
    },
    attestation,
    state: new StateV0(report.genesisAccounts.orderedAccounts),
    rollupId: copyBytesV0(report.requestAudit.rollupId),
    batch: {
      batchNumber: report.requestAudit.batchNumber,
      parentBatchCommitment: copyBytesV0(report.requestAudit.parentBatchCommitment),
      transactions: report.commitmentExpansions.transactions.orderedTransactions.map(cloneTransferTxV0),
    },
    expectedResult: report.expectedResult,
    tamperPublicInputs: report.requestAudit.tamperPublicInputs
      ? { ...report.requestAudit.tamperPublicInputs }
      : null,
    tamperProofBindingDigest: report.requestAudit.tamperProofBindingDigest
      ? { ...report.requestAudit.tamperProofBindingDigest }
      : null,
  };
}

function canonicalPipelineTruthArtifactKindFromRequestKindV0(
  requestKind: CanonicalPipelineRequestKindV0,
): CanonicalPipelineTruthArtifactKindV0 {
  return requestKind === CanonicalPipelineRequestKindV0.Execution
    ? CanonicalPipelineTruthArtifactKindV0.ExecutionReport
    : CanonicalPipelineTruthArtifactKindV0.AttestationReport;
}

function canonicalPipelineAttestationClaimDigestV0(
  claim: CanonicalPipelineAttestationClaimV0,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_ATTESTATION_CLAIM_V2,
      lengthPrefixedBytesV0(textEncoder.encode(claim.claimKind)),
      canonicalPipelineAttestationClaimPayloadBytesV0(claim.claimPayload),
    ),
  );
}

function canonicalPipelineAttestationEvidenceDigestV0(
  evidenceKind: CanonicalPipelineAttestationEvidenceKindV0,
  normalizedForm: CanonicalPipelineAttestationNormalizedFormV0,
  normalizedPayloadUtf8: string,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_DIGEST_V2,
      lengthPrefixedBytesV0(textEncoder.encode(evidenceKind)),
      lengthPrefixedBytesV0(textEncoder.encode(normalizedForm)),
      lengthPrefixedBytesV0(textEncoder.encode(normalizedPayloadUtf8)),
    ),
  );
}

function canonicalPipelineAttestationEvidenceRootDigestV0(
  items: readonly CanonicalPipelineAttestationEvidenceSummaryItemV0[],
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_ATTESTATION_EVIDENCE_ROOT_V2,
      u64ToLeBytesV0(BigInt(items.length)),
      ...items.flatMap((item) => [
        lengthPrefixedBytesV0(textEncoder.encode(item.label)),
        lengthPrefixedBytesV0(textEncoder.encode(item.evidenceKind)),
        copyBytes32V0("attestation.evidenceDigest", item.evidenceDigest),
      ]),
    ),
  );
}

function canonicalPipelineProvenanceSignatureMessageBytesV0(
  label: string,
  evidenceDigest: Uint8Array,
  provenance: CanonicalPipelineEvidenceProvenanceV0,
): Uint8Array {
  return concatBytesV0(
    D_CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_MESSAGE_V1,
    lengthPrefixedBytesV0(textEncoder.encode(label)),
    copyBytes32V0("provenance.evidenceDigest", evidenceDigest),
    u32ToLeBytesV0(provenance.provenancePolicyVersion),
    lengthPrefixedBytesV0(textEncoder.encode(provenance.provenanceType)),
    lengthPrefixedBytesV0(textEncoder.encode(provenance.sourceType)),
    lengthPrefixedBytesV0(textEncoder.encode(provenance.sourceIdentifier)),
    provenance.timestampUnixSeconds === null
      ? Uint8Array.of(0)
      : concatBytesV0(Uint8Array.of(1), u64ToLeBytesV0(provenance.timestampUnixSeconds)),
  );
}

function canonicalPipelineProvenanceDigestV0(
  label: string,
  evidenceDigest: Uint8Array,
  provenance: CanonicalPipelineEvidenceProvenanceV0,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_PROVENANCE_V1,
      canonicalPipelineProvenanceSignatureMessageBytesV0(label, evidenceDigest, provenance),
      provenance.signature === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            copyBytes32V0(
              "provenance.signature.signerPublicKey",
              provenance.signature.signerPublicKey,
            ),
            copyBytesFixedV0(
              "provenance.signature.signature",
              provenance.signature.signature,
              64,
            ),
          ),
    ),
  );
}

function canonicalPipelineVerifyProvenanceSignatureV0(
  label: string,
  evidenceDigest: Uint8Array,
  provenance: CanonicalPipelineEvidenceProvenanceV0,
): boolean {
  if (provenance.signature === null) {
    return true;
  }
  const signerPublicKey = copyBytes32V0(
    "provenance.signature.signerPublicKey",
    provenance.signature.signerPublicKey,
  );
  const signature = copyBytesFixedV0(
    "provenance.signature.signature",
    provenance.signature.signature,
    64,
  );
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX_V0), Buffer.from(signerPublicKey)]),
      format: "der",
      type: "spki",
    });
    return verify(
      null,
      Buffer.from(
        canonicalPipelineProvenanceSignatureMessageBytesV0(label, evidenceDigest, provenance),
      ),
      publicKey,
      Buffer.from(signature),
    );
  } catch (error) {
    const message =
      error instanceof Error && error.message.includes("key")
        ? "canonical pipeline provenance signerPublicKey is not a valid ed25519 key"
        : "canonical pipeline provenance signature is not a valid ed25519 signature";
    throw new AuraTypescriptSdkErrorV0("InvalidFixture", message, {
      cause: error instanceof Error ? error : undefined,
    });
  }
}

function canonicalPipelineBuildProvenanceSummaryV0(
  items: readonly CanonicalPipelineAttestationEvidenceItemV0[],
  evidenceItems: readonly CanonicalPipelineAttestationEvidenceSummaryItemV0[],
): CanonicalPipelineProvenanceSummaryV0 {
  const summaryItems: CanonicalPipelineProvenanceSummaryItemV0[] = [];
  let allSignatureChecksPassed = true;
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index]!;
    const evidenceSummary = evidenceItems[index]!;
    const signatureValid = canonicalPipelineVerifyProvenanceSignatureV0(
      item.label,
      evidenceSummary.evidenceDigest,
      item.provenance,
    );
    allSignatureChecksPassed &&= signatureValid;
    summaryItems.push({
      label: item.label,
      provenancePolicyVersion: item.provenance.provenancePolicyVersion,
      provenanceType: item.provenance.provenanceType,
      sourceType: item.provenance.sourceType,
      sourceIdentifier: item.provenance.sourceIdentifier,
      signaturePresent: item.provenance.signature !== null,
      signatureValid,
      signerPublicKey:
        item.provenance.signature === null
          ? null
          : copyBytesV0(item.provenance.signature.signerPublicKey),
      signature:
        item.provenance.signature === null
          ? null
          : copyBytesFixedV0("provenance.signature.signature", item.provenance.signature.signature, 64),
      timestampUnixSeconds: item.provenance.timestampUnixSeconds,
      provenanceDigest: canonicalPipelineProvenanceDigestV0(
        item.label,
        evidenceSummary.evidenceDigest,
        item.provenance,
      ),
    });
  }
  const rootPreimage = concatBytesV0(
    D_CANONICAL_PIPELINE_PROVENANCE_ITEM_V1,
    u64ToLeBytesV0(BigInt(summaryItems.length)),
    ...summaryItems.flatMap((item) => [
      lengthPrefixedBytesV0(textEncoder.encode(item.label)),
      u32ToLeBytesV0(item.provenancePolicyVersion),
      lengthPrefixedBytesV0(textEncoder.encode(item.provenanceType)),
      lengthPrefixedBytesV0(textEncoder.encode(item.sourceType)),
      lengthPrefixedBytesV0(textEncoder.encode(item.sourceIdentifier)),
      Uint8Array.of(item.signaturePresent ? 1 : 0),
      Uint8Array.of(item.signatureValid ? 1 : 0),
      item.signerPublicKey !== null && item.signature !== null
        ? concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0("provenance.signerPublicKey", item.signerPublicKey),
            copyBytesFixedV0("provenance.signature", item.signature, 64),
          )
        : Uint8Array.of(0),
      item.timestampUnixSeconds === null
        ? Uint8Array.of(0)
        : concatBytesV0(Uint8Array.of(1), u64ToLeBytesV0(item.timestampUnixSeconds)),
      copyBytes32V0("provenance.provenanceDigest", item.provenanceDigest),
    ]),
  );
  return {
    provenanceItemCount: BigInt(summaryItems.length),
    provenanceRootDigest: sha256BytesV0(rootPreimage),
    items: summaryItems,
    allSignatureChecksPassed,
  };
}

function canonicalPipelineAttestationTupleDigestV0(
  claimDigest: Uint8Array,
  evidenceRootDigest: Uint8Array,
  provenanceRootDigest: Uint8Array,
  consistencyResult: CanonicalPipelineAttestationConsistencyResultV0,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_ATTESTATION_TUPLE_V1,
      copyBytes32V0("attestation.claimDigest", claimDigest),
      copyBytes32V0("attestation.evidenceRootDigest", evidenceRootDigest),
      copyBytes32V0("attestation.provenanceRootDigest", provenanceRootDigest),
      lengthPrefixedBytesV0(textEncoder.encode(consistencyResult.relation)),
      consistencyResult.targetLabel === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            lengthPrefixedBytesV0(textEncoder.encode(consistencyResult.targetLabel)),
          ),
      Uint8Array.of(consistencyResult.consistent ? 1 : 0),
    ),
  );
}

function canonicalPipelineAttestationConstraintsEqualV0(
  left: CanonicalPipelineAttestationConstraintsV0,
  right: CanonicalPipelineAttestationConstraintsV0,
): boolean {
  return (
    left.requireUniqueLabels === right.requireUniqueLabels &&
    left.maxEvidenceItems === right.maxEvidenceItems &&
    left.maxTotalNormalizedBytes === right.maxTotalNormalizedBytes
  );
}

function canonicalPipelineAttestationTargetLabelV0(
  claim: CanonicalPipelineAttestationClaimV0,
): string | null {
  if ("expectedEvidenceRootDigest" in claim.claimPayload) {
    return null;
  }
  return claim.claimPayload.targetLabel;
}

function canonicalPipelineFindAttestationEvidenceSummaryItemV0(
  evidenceSummary: CanonicalPipelineAttestationEvidenceSummaryV0,
  targetLabel: string,
): CanonicalPipelineAttestationEvidenceSummaryItemV0 {
  const found = evidenceSummary.evidenceItems.find((item) => item.label === targetLabel);
  if (!found) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `canonical pipeline attestation claim references unknown targetLabel: ${targetLabel}`,
    );
  }
  return found;
}

function canonicalPipelineExtractJsonFieldV0(
  normalizedPayloadUtf8: string,
  fieldPath: readonly string[],
): string | null {
  let cursor: unknown = JSON.parse(normalizedPayloadUtf8);
  for (const segment of fieldPath) {
    if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) {
      return null;
    }
    const next = (cursor as Record<string, unknown>)[segment];
    if (next === undefined) {
      return null;
    }
    cursor = next;
  }
  return typeof cursor === "string"
    ? cursor
    : canonicalPipelineCanonicalizeJsonValueV0(cursor);
}

function canonicalPipelinePrepareAttestationV0(
  attestation: CanonicalPipelineAttestationRequestV0,
): CanonicalPipelinePreparedAttestationV0 {
  const supportedConstraints = canonicalPipelineSupportedAttestationConstraintsV0();
  if (
    attestation.attestationSchemaVersion !== LOCAL_CHAIN_CANONICAL_ATTESTATION_SCHEMA_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline attestation_schema_version: expected ${LOCAL_CHAIN_CANONICAL_ATTESTATION_SCHEMA_VERSION_V0}, got ${attestation.attestationSchemaVersion}`,
    );
  }
  if (
    attestation.normalizationPolicyVersion !==
    LOCAL_CHAIN_CANONICAL_ATTESTATION_NORMALIZATION_POLICY_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline normalization_policy_version: expected ${LOCAL_CHAIN_CANONICAL_ATTESTATION_NORMALIZATION_POLICY_VERSION_V0}, got ${attestation.normalizationPolicyVersion}`,
    );
  }
  if (
    !canonicalPipelineAttestationConstraintsEqualV0(
      attestation.attestationConstraints,
      supportedConstraints,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline attestation_constraints must match the supported attestation contract",
    );
  }
  if (attestation.evidenceItems.length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline attestation evidence_items must not be empty",
    );
  }
  if (BigInt(attestation.evidenceItems.length) > attestation.attestationConstraints.maxEvidenceItems) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `canonical pipeline attestation evidence_items exceeds max_evidence_items ${attestation.attestationConstraints.maxEvidenceItems}`,
    );
  }
  const seenLabels = new Set<string>();
  const evidenceItems: CanonicalPipelineAttestationEvidenceSummaryItemV0[] = [];
  let totalNormalizedBytes = 0n;
  for (const [index, item] of attestation.evidenceItems.entries()) {
    if (item.label.trim().length === 0) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline attestation evidence_items[${index}].label must not be empty`,
      );
    }
    if (
      attestation.attestationConstraints.requireUniqueLabels &&
      seenLabels.has(item.label)
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline attestation evidence_items contains duplicate label: ${item.label}`,
      );
    }
    seenLabels.add(item.label);
    if (
      item.provenance.provenancePolicyVersion !==
      LOCAL_CHAIN_CANONICAL_PROVENANCE_POLICY_VERSION_V0
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `unsupported canonical pipeline provenance_policy_version: expected ${LOCAL_CHAIN_CANONICAL_PROVENANCE_POLICY_VERSION_V0}, got ${item.provenance.provenancePolicyVersion}`,
      );
    }
    parseCanonicalPipelineEvidenceProvenanceTypeV0(
      item.provenance.provenanceType,
      `canonical pipeline attestation evidence_items[${index}].provenance`,
    );
    if (
      item.provenance.sourceType.trim().length === 0 ||
      item.provenance.sourceIdentifier.trim().length === 0
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline attestation evidence_items[${index}].provenance sourceType and sourceIdentifier must not be empty`,
      );
    }
    if (
      item.provenance.provenanceType === CanonicalPipelineEvidenceProvenanceTypeV0.SignedBlob &&
      item.provenance.signature === null
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline attestation evidence_items[${index}].provenance signed_blob requires signature material`,
      );
    }
    if (item.provenance.signature !== null) {
      copyBytes32V0(
        `canonical pipeline attestation evidence_items[${index}].provenance.signature.signerPublicKey`,
        item.provenance.signature.signerPublicKey,
      );
      copyBytesFixedV0(
        `canonical pipeline attestation evidence_items[${index}].provenance.signature.signature`,
        item.provenance.signature.signature,
        64,
      );
    }
    const originalPayloadUtf8 = canonicalPipelineAttestationPayloadUtf8V0(item);
    if (originalPayloadUtf8.length === 0) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline attestation evidence_items[${index}].evidence_payload.payload_utf8 must not be empty`,
      );
    }
    let normalizedForm: CanonicalPipelineAttestationNormalizedFormV0;
    let normalizedPayloadUtf8: string;
    switch (item.evidenceKind) {
      case CanonicalPipelineAttestationEvidenceKindV0.InlineUtf8:
        normalizedForm = CanonicalPipelineAttestationNormalizedFormV0.Utf8Text;
        normalizedPayloadUtf8 = canonicalPipelineNormalizeUtf8TextV0(originalPayloadUtf8);
        break;
      case CanonicalPipelineAttestationEvidenceKindV0.InlineJsonUtf8: {
        normalizedForm = CanonicalPipelineAttestationNormalizedFormV0.CanonicalJsonUtf8;
        let parsed: unknown;
        try {
          parsed = JSON.parse(originalPayloadUtf8);
        } catch (error) {
          throw new AuraTypescriptSdkErrorV0(
            "InvalidFixture",
            `canonical pipeline attestation evidence_items[${index}] malformed inline_json_utf8 payload: ${error}`,
          );
        }
        normalizedPayloadUtf8 = canonicalPipelineCanonicalizeJsonValueV0(parsed);
        break;
      }
      default:
        assertUnreachableV0(item.evidenceKind);
    }
    const originalPayloadSizeBytes = BigInt(textEncoder.encode(originalPayloadUtf8).length);
    const normalizedPayloadSizeBytes = BigInt(textEncoder.encode(normalizedPayloadUtf8).length);
    totalNormalizedBytes += normalizedPayloadSizeBytes;
    evidenceItems.push({
      label: item.label,
      evidenceKind: item.evidenceKind,
      originalPayloadUtf8,
      originalPayloadSizeBytes,
      normalizedForm,
      normalizedPayloadUtf8,
      normalizedPayloadSizeBytes,
      evidenceDigest: canonicalPipelineAttestationEvidenceDigestV0(
        item.evidenceKind,
        normalizedForm,
        normalizedPayloadUtf8,
      ),
      provenanceDigest: ZERO32_V0,
    });
    evidenceItems[evidenceItems.length - 1]!.provenanceDigest = canonicalPipelineProvenanceDigestV0(
      item.label,
      evidenceItems[evidenceItems.length - 1]!.evidenceDigest,
      item.provenance,
    );
  }
  if (totalNormalizedBytes > attestation.attestationConstraints.maxTotalNormalizedBytes) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `canonical pipeline attestation normalized evidence bytes exceeds max_total_normalized_bytes ${attestation.attestationConstraints.maxTotalNormalizedBytes}`,
    );
  }
  const evidenceSummary: CanonicalPipelineAttestationEvidenceSummaryV0 = {
    evidenceItemCount: BigInt(evidenceItems.length),
    evidenceItems,
    evidenceRootDigest: canonicalPipelineAttestationEvidenceRootDigestV0(evidenceItems),
  };
  const provenanceSummary = canonicalPipelineBuildProvenanceSummaryV0(
    attestation.evidenceItems,
    evidenceItems,
  );
  const targetLabel = canonicalPipelineAttestationTargetLabelV0(attestation.claim);
  if (targetLabel !== null) {
    const targetItem = canonicalPipelineFindAttestationEvidenceSummaryItemV0(
      evidenceSummary,
      targetLabel,
    );
    if (
      attestation.claim.claimKind ===
        CanonicalPipelineAttestationClaimKindV0.NormalizedJsonFieldEqualsUtf8 &&
      targetItem.normalizedForm !==
        CanonicalPipelineAttestationNormalizedFormV0.CanonicalJsonUtf8
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline attestation claim_kind normalized_json_field_equals_utf8 requires inline_json_utf8 evidence for target_label ${targetLabel}`,
      );
    }
  }
  if (
    "expectedSubstringUtf8" in attestation.claim.claimPayload &&
    attestation.claim.claimPayload.expectedSubstringUtf8.length === 0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline attestation claim_payload.expected_substring_utf8 must not be empty",
    );
  }
  if ("fieldPath" in attestation.claim.claimPayload) {
    if (
      attestation.claim.claimPayload.fieldPath.length === 0 ||
      attestation.claim.claimPayload.fieldPath.some((segment) => segment.trim().length === 0)
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        "canonical pipeline attestation claim_payload.field_path must contain only non-empty segments",
      );
    }
    if (attestation.claim.claimPayload.expectedValueUtf8.length === 0) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        "canonical pipeline attestation claim_payload.expected_value_utf8 must not be empty",
      );
    }
  }
  let consistencyResult: CanonicalPipelineAttestationConsistencyResultV0;
  if ("expectedEvidenceRootDigest" in attestation.claim.claimPayload) {
    consistencyResult = {
      relation: CanonicalPipelineAttestationConsistencyRelationV0.EvidenceRootDigestEquals,
      targetLabel: null,
      consistent: bytesEqualV0(
        copyBytes32V0(
          "attestation.claim.claimPayload.expectedEvidenceRootDigest",
          attestation.claim.claimPayload.expectedEvidenceRootDigest,
        ),
        evidenceSummary.evidenceRootDigest,
      ),
    };
  } else if ("expectedEvidenceDigest" in attestation.claim.claimPayload) {
    const targetItem = canonicalPipelineFindAttestationEvidenceSummaryItemV0(
      evidenceSummary,
      attestation.claim.claimPayload.targetLabel,
    );
    consistencyResult = {
      relation: CanonicalPipelineAttestationConsistencyRelationV0.NormalizedEvidenceDigestEquals,
      targetLabel: attestation.claim.claimPayload.targetLabel,
      consistent: bytesEqualV0(
        copyBytes32V0(
          "attestation.claim.claimPayload.expectedEvidenceDigest",
          attestation.claim.claimPayload.expectedEvidenceDigest,
        ),
        targetItem.evidenceDigest,
      ),
    };
  } else if ("expectedSubstringUtf8" in attestation.claim.claimPayload) {
    const targetItem = canonicalPipelineFindAttestationEvidenceSummaryItemV0(
      evidenceSummary,
      attestation.claim.claimPayload.targetLabel,
    );
    consistencyResult = {
      relation: CanonicalPipelineAttestationConsistencyRelationV0.NormalizedTextContainsUtf8,
      targetLabel: attestation.claim.claimPayload.targetLabel,
      consistent: targetItem.normalizedPayloadUtf8.includes(
        attestation.claim.claimPayload.expectedSubstringUtf8,
      ),
    };
  } else {
    const targetItem = canonicalPipelineFindAttestationEvidenceSummaryItemV0(
      evidenceSummary,
      attestation.claim.claimPayload.targetLabel,
    );
    consistencyResult = {
      relation: CanonicalPipelineAttestationConsistencyRelationV0.NormalizedJsonFieldEqualsUtf8,
      targetLabel: attestation.claim.claimPayload.targetLabel,
      consistent:
        canonicalPipelineExtractJsonFieldV0(
          targetItem.normalizedPayloadUtf8,
          attestation.claim.claimPayload.fieldPath,
        ) === attestation.claim.claimPayload.expectedValueUtf8,
    };
  }
  return {
    claimDigest: canonicalPipelineAttestationClaimDigestV0(attestation.claim),
    evidenceSummary,
    normalizationSummary: {
      normalizationPolicyVersion: attestation.normalizationPolicyVersion,
      normalizedEvidenceCount: BigInt(attestation.evidenceItems.length),
      totalNormalizedBytes,
      normalizationSucceeded: true,
    },
    consistencyResult,
    provenanceSummary,
    attestationTupleDigest: canonicalPipelineAttestationTupleDigestV0(
      canonicalPipelineAttestationClaimDigestV0(attestation.claim),
      evidenceSummary.evidenceRootDigest,
      provenanceSummary.provenanceRootDigest,
      consistencyResult,
    ),
  };
}

function canonicalPipelineAttestationFailureDetailV0(
  request: CanonicalPipelineRequestV0,
  prepared: CanonicalPipelinePreparedAttestationV0,
  actualResult: ScenarioResultV0,
): CanonicalPipelineAttestationFailureAuditV0 {
  switch (actualResult) {
    case ScenarioResultV0.Accepted:
      return {
        reason: CanonicalPipelineAttestationFailureReasonV0.None,
        detail:
          "attestation consistency was established under the supported normalization and evidence rules",
      };
    case ScenarioResultV0.ExecutionRejected:
      if (!prepared.provenanceSummary.allSignatureChecksPassed) {
        return {
          reason: CanonicalPipelineAttestationFailureReasonV0.ProvenanceSignatureInvalid,
          detail:
            "attestation provenance carried signature material that failed deterministic verification",
        };
      }
      if (!prepared.consistencyResult.consistent) {
        return {
          reason: CanonicalPipelineAttestationFailureReasonV0.ConsistencyMismatch,
          detail:
            "attestation claim was not consistent with the normalized evidence derived from the supplied canonical evidence set",
        };
      }
      return {
        reason: CanonicalPipelineAttestationFailureReasonV0.MalformedEvidence,
        detail: "attestation request was rejected before proof production",
      };
    case ScenarioResultV0.VerificationRejected:
      return {
        reason:
          request.attestation?.attestationProofKind ===
          CanonicalPipelineAttestationProofKindV0.Stark
            ? CanonicalPipelineAttestationFailureReasonV0.AttestationProofVerificationFailure
            : CanonicalPipelineAttestationFailureReasonV0.VerificationLayerFailure,
        detail:
          "verification-layer mismatch rejected an otherwise normalized and evaluated attestation",
      };
    case ScenarioResultV0.SettlementRejected:
      return {
        reason: CanonicalPipelineAttestationFailureReasonV0.SettlementLayerFailure,
        detail: "local settlement rejected an otherwise verified attestation transition",
      };
    default:
      return assertUnreachableV0(actualResult);
  }
}

function canonicalPipelineAttestationSummaryFromRequestV0(
  request: CanonicalPipelineRequestV0,
  actualResult: ScenarioResultV0,
): CanonicalPipelineAttestationSummaryV0 | null {
  if (request.attestation === null) {
    return null;
  }
  const prepared = canonicalPipelinePrepareAttestationV0(request.attestation);
  return {
    attestationSchemaVersion: request.attestation.attestationSchemaVersion,
    attestationScope: request.attestation.attestationScope,
    attestationProofKind: request.attestation.attestationProofKind,
    normalizationPolicyVersion: request.attestation.normalizationPolicyVersion,
    attestationConstraints: { ...request.attestation.attestationConstraints },
    claim: cloneCanonicalPipelineAttestationClaimV0(request.attestation.claim),
    claimDigest: prepared.claimDigest,
    evidenceSummary: cloneCanonicalPipelineAttestationEvidenceSummaryV0(prepared.evidenceSummary),
    normalizationSummary: { ...prepared.normalizationSummary },
    consistencyResult: {
      relation: prepared.consistencyResult.relation,
      targetLabel: prepared.consistencyResult.targetLabel,
      consistent: prepared.consistencyResult.consistent,
    },
    attestationStatus:
      actualResult === ScenarioResultV0.Accepted
        ? CanonicalPipelineAttestationStatusV0.Accepted
        : CanonicalPipelineAttestationStatusV0.Rejected,
    attestationFailureReason: canonicalPipelineAttestationFailureDetailV0(
      request,
      prepared,
      actualResult,
    ),
    proofScopeHonestyNote:
      "Aura only attests to claim consistency with the provided evidence set and typed provenance descriptor after deterministic normalization; it does not prove external real-world truth.",
  };
}

function canonicalPipelinePreExecutionRejectionReasonV0(
  _request: CanonicalPipelineRequestV0,
  preparedAttestation: CanonicalPipelinePreparedAttestationV0 | null,
): { failureReasonCode: CanonicalPipelineFailureReasonCodeV0; detail: string } | null {
  if (preparedAttestation !== null) {
    if (!preparedAttestation.provenanceSummary.allSignatureChecksPassed) {
      return {
        failureReasonCode: CanonicalPipelineFailureReasonCodeV0.ProvenanceSignatureInvalid,
        detail:
          "attestation provenance carried signature material that failed deterministic verification",
      };
    }
    if (!preparedAttestation.consistencyResult.consistent) {
      return {
        failureReasonCode: CanonicalPipelineFailureReasonCodeV0.AttestationConsistencyMismatch,
        detail:
          "attestation claim was not consistent with the normalized evidence derived from the supplied canonical evidence set",
      };
    }
  }
  return null;
}

function canonicalPipelineAttestationProofSummaryFromRequestV0(
  request: CanonicalPipelineRequestV0,
  prepared: CanonicalPipelinePreparedAttestationV0 | null,
  report: CanonicalPipelineReportV0,
): CanonicalPipelineAttestationProofSummaryV0 | null {
  if (request.attestation === null) {
    return null;
  }
  if (prepared === null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "attestation proof summary requires prepared attestation material",
    );
  }
  const proofKind = request.attestation.attestationProofKind;
  const verificationPassed = !(
    report.actualResult === ScenarioResultV0.ExecutionRejected ||
    (report.actualResult === ScenarioResultV0.VerificationRejected &&
      report.statusExplanation.failureReasonCode ===
        CanonicalPipelineFailureReasonCodeV0.AttestationProofVerificationRejected)
  );
  return {
    proofKind,
    attestationTupleDigest: copyBytesV0(prepared.attestationTupleDigest),
    verificationPassed,
    mockPolicyVersion:
      proofKind === CanonicalPipelineAttestationProofKindV0.Mock
        ? LOCAL_CHAIN_CANONICAL_ATTESTATION_PROOF_MOCK_POLICY_VERSION_V0
        : null,
    starkPolicyVersion:
      proofKind === CanonicalPipelineAttestationProofKindV0.Stark
        ? LOCAL_CHAIN_CANONICAL_STARK_POLICY_VERSION_V0
        : null,
    starkPublicInputsDigest:
      proofKind === CanonicalPipelineAttestationProofKindV0.Stark
        ? report.attestationProofSummary?.starkPublicInputsDigest === null ||
          report.attestationProofSummary === null
          ? null
          : copyBytesV0(report.attestationProofSummary.starkPublicInputsDigest)
        : null,
    starkProofBytesDigest:
      proofKind === CanonicalPipelineAttestationProofKindV0.Stark
        ? report.attestationProofSummary?.starkProofBytesDigest === null ||
          report.attestationProofSummary === null
          ? null
          : copyBytesV0(report.attestationProofSummary.starkProofBytesDigest)
        : null,
    starkProofBindingDigest:
      proofKind === CanonicalPipelineAttestationProofKindV0.Stark
        ? report.attestationProofSummary?.starkProofBindingDigest === null ||
          report.attestationProofSummary === null
          ? null
          : copyBytesV0(report.attestationProofSummary.starkProofBindingDigest)
        : null,
  };
}

function canonicalPipelineExecutionRejectionReasonV0(
  request: CanonicalPipelineRequestV0,
  preparedAttestation: CanonicalPipelinePreparedAttestationV0 | null,
  executionError: ExecutionErrorV0 | null,
): { failureReasonCode: CanonicalPipelineFailureReasonCodeV0; detail: string } {
  const preExecutionReason = canonicalPipelinePreExecutionRejectionReasonV0(
    request,
    preparedAttestation,
  );
  if (preExecutionReason !== null) {
    return preExecutionReason;
  }
  return {
    failureReasonCode: CanonicalPipelineFailureReasonCodeV0.TransferExecutionRejected,
    detail: executionError?.message ?? "canonical execution rejected before proof production",
  };
}

function canonicalPipelineStatusExplanationFromResultV0(
  requestKind: CanonicalPipelineRequestKindV0,
  finalStatus: ScenarioResultV0,
  failureReasonCode: CanonicalPipelineFailureReasonCodeV0,
  detail: string,
): CanonicalPipelineStatusExplanationV0 {
  const failureStage =
    finalStatus === ScenarioResultV0.Accepted
      ? CanonicalPipelineFailureStageV0.None
      : finalStatus === ScenarioResultV0.ExecutionRejected
        ? CanonicalPipelineFailureStageV0.Execution
        : finalStatus === ScenarioResultV0.VerificationRejected
          ? CanonicalPipelineFailureStageV0.Verification
          : CanonicalPipelineFailureStageV0.Settlement;
  return {
    truthArtifactKind: canonicalPipelineTruthArtifactKindFromRequestKindV0(requestKind),
    requestKind,
    finalStatus,
    failureStage,
    failureReasonCode,
    detail,
  };
}

function canonicalPipelineAcceptedStatusExplanationV0(
  requestKind: CanonicalPipelineRequestKindV0,
): CanonicalPipelineStatusExplanationV0 {
  return canonicalPipelineStatusExplanationFromResultV0(
    requestKind,
    ScenarioResultV0.Accepted,
    CanonicalPipelineFailureReasonCodeV0.None,
    "canonical report accepted and locally committed",
  );
}

function cloneCanonicalPipelineAttestationClaimV0(
  claim: CanonicalPipelineAttestationClaimV0,
): CanonicalPipelineAttestationClaimV0 {
  if ("expectedEvidenceRootDigest" in claim.claimPayload) {
    return {
      claimKind: claim.claimKind,
      claimPayload: {
        expectedEvidenceRootDigest: copyBytesV0(
          claim.claimPayload.expectedEvidenceRootDigest,
        ),
      },
    };
  }
  if ("expectedEvidenceDigest" in claim.claimPayload) {
    return {
      claimKind: claim.claimKind,
      claimPayload: {
        targetLabel: claim.claimPayload.targetLabel,
        expectedEvidenceDigest: copyBytesV0(claim.claimPayload.expectedEvidenceDigest),
      },
    };
  }
  if ("expectedSubstringUtf8" in claim.claimPayload) {
    return {
      claimKind: claim.claimKind,
      claimPayload: {
        targetLabel: claim.claimPayload.targetLabel,
        expectedSubstringUtf8: claim.claimPayload.expectedSubstringUtf8,
      },
    };
  }
  return {
    claimKind: claim.claimKind,
    claimPayload: {
      targetLabel: claim.claimPayload.targetLabel,
      fieldPath: [...claim.claimPayload.fieldPath],
      expectedValueUtf8: claim.claimPayload.expectedValueUtf8,
    },
  };
}

function cloneCanonicalPipelineAttestationEvidenceSummaryV0(
  evidenceSummary: CanonicalPipelineAttestationEvidenceSummaryV0,
): CanonicalPipelineAttestationEvidenceSummaryV0 {
  return {
    evidenceItemCount: evidenceSummary.evidenceItemCount,
    evidenceItems: evidenceSummary.evidenceItems.map((item) => ({
      label: item.label,
      evidenceKind: item.evidenceKind,
      originalPayloadUtf8: item.originalPayloadUtf8,
      originalPayloadSizeBytes: item.originalPayloadSizeBytes,
      normalizedForm: item.normalizedForm,
      normalizedPayloadUtf8: item.normalizedPayloadUtf8,
      normalizedPayloadSizeBytes: item.normalizedPayloadSizeBytes,
      evidenceDigest: copyBytesV0(item.evidenceDigest),
      provenanceDigest: copyBytesV0(item.provenanceDigest),
    })),
    evidenceRootDigest: copyBytesV0(evidenceSummary.evidenceRootDigest),
  };
}

function canonicalPipelineSettlementReasonFromResultV0(
  actualResult: ScenarioResultV0,
): CanonicalPipelineSettlementReasonV0 {
  switch (actualResult) {
    case ScenarioResultV0.Accepted:
      return CanonicalPipelineSettlementReasonV0.AcceptedAndCommitted;
    case ScenarioResultV0.ExecutionRejected:
      return CanonicalPipelineSettlementReasonV0.NotRunExecutionRejected;
    case ScenarioResultV0.VerificationRejected:
      return CanonicalPipelineSettlementReasonV0.RejectedVerificationMismatch;
    case ScenarioResultV0.SettlementRejected:
      return CanonicalPipelineSettlementReasonV0.RejectedLocalSettlement;
  }
}

function canonicalPipelineLedgerTotalBalanceV0(
  accounts: readonly CanonicalPipelineLedgerAccountV0[],
): bigint {
  return accounts.reduce((acc, account) => acc + account.balance, 0n);
}

function canonicalPipelineLedgerCirculatingSupplyV0(
  totalSupply: bigint,
  burnedSupply: bigint,
): bigint {
  if (burnedSupply > totalSupply) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline ledger burnedSupply exceeds totalSupply",
    );
  }
  return totalSupply - burnedSupply;
}

function canonicalPipelineDefaultLedgerPolicyV0(
  orderedAccounts: AccountV0[],
): CanonicalPipelineLedgerPolicyV0 {
  if (orderedAccounts.length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline legacy/default ledger synthesis requires at least one genesis account",
    );
  }
  const ledgerAccounts = orderedAccounts.map((account) => ({
    accountId: copyBytesV0(account.accountId),
    balance: account.balance,
  }));
  return {
    ledgerPolicyVersion: LOCAL_CHAIN_CANONICAL_LEDGER_POLICY_VERSION_V0,
    payerAccountId: copyBytesV0(orderedAccounts[0].accountId),
    totalSupply: canonicalPipelineLedgerTotalBalanceV0(ledgerAccounts),
    burnedSupply: 0n,
    accounts: ledgerAccounts,
  };
}

function encodeBase58LikeWalletV0(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      const value = digits[index] * 256 + carry;
      digits[index] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  for (const byte of bytes) {
    if (byte === 0) {
      digits.push(0);
    } else {
      break;
    }
  }
  return digits
    .reverse()
    .map((digit) => alphabet[digit]!)
    .join("");
}

function walletAddressIsBase58V0(value: string): boolean {
  return (
    value.length > 0 &&
    /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(value)
  );
}

function canonicalPipelineDefaultWalletBindingV0(
  ledger: CanonicalPipelineLedgerPolicyV0,
): CanonicalPipelineWalletBindingV0 {
  return {
    walletBindingVersion: LOCAL_CHAIN_CANONICAL_WALLET_BINDING_VERSION_V0,
    accountId: copyBytesV0(ledger.payerAccountId),
    walletAddress: encodeBase58LikeWalletV0(ledger.payerAccountId),
  };
}

function canonicalPipelineDefaultTokenAnchorV0(): CanonicalPipelineTokenAnchorV0 {
  return {
    tokenPolicyVersion: LOCAL_CHAIN_CANONICAL_TOKEN_POLICY_VERSION_V0,
    networkMode: CanonicalPipelineNetworkModeV0.Local,
    settlementAnchorType: CanonicalPipelineSettlementAnchorTypeV0.Local,
    externalBalanceReference: null,
    enforceExternalMatch: false,
    expectedExternalBalance: null,
  };
}

function canonicalPipelineWalletBindingDigestV0(
  walletBinding: CanonicalPipelineWalletBindingV0,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_WALLET_BINDING_V1,
      u32ToLeBytesV0(walletBinding.walletBindingVersion),
      copyBytes32V0("walletBinding.accountId", walletBinding.accountId),
      lengthPrefixedBytesV0(textEncoder.encode(walletBinding.walletAddress)),
    ),
  );
}

function canonicalPipelineWalletBindingSummaryFromRequestV0(
  request: CanonicalPipelineRequestV0,
): CanonicalPipelineWalletBindingSummaryV0 {
  return {
    walletBindingVersion: request.walletBinding.walletBindingVersion,
    accountId: copyBytesV0(request.walletBinding.accountId),
    walletAddress: request.walletBinding.walletAddress,
    walletBindingDigest: canonicalPipelineWalletBindingDigestV0(request.walletBinding),
    bindingConsistentWithAccount: bytesEqualV0(
      request.walletBinding.accountId,
      request.ledger.payerAccountId,
    ),
  };
}

function canonicalPipelineWalletBindingMismatchDetailV0(
  request: CanonicalPipelineRequestV0,
): string | null {
  return bytesEqualV0(request.walletBinding.accountId, request.ledger.payerAccountId)
    ? null
    : `wallet_binding.account_id ${hexFromBytesV0(request.walletBinding.accountId)} does not match ledger.payer_account_id ${hexFromBytesV0(request.ledger.payerAccountId)}`;
}

function canonicalPipelineTokenAnchorDigestV0(
  tokenAnchor: CanonicalPipelineTokenAnchorV0,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_TOKEN_ANCHOR_V1,
      u32ToLeBytesV0(tokenAnchor.tokenPolicyVersion),
      lengthPrefixedBytesV0(textEncoder.encode(tokenAnchor.networkMode)),
      lengthPrefixedBytesV0(textEncoder.encode(tokenAnchor.settlementAnchorType)),
      tokenAnchor.externalBalanceReference === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            lengthPrefixedBytesV0(
              textEncoder.encode(tokenAnchor.externalBalanceReference.referenceId),
            ),
            tokenAnchor.externalBalanceReference.observedBalance === null
              ? Uint8Array.of(0)
              : concatBytesV0(
                  Uint8Array.of(1),
                  u64ToLeBytesV0(tokenAnchor.externalBalanceReference.observedBalance),
                ),
            tokenAnchor.externalBalanceReference.observedSlot === null
              ? Uint8Array.of(0)
              : concatBytesV0(
                  Uint8Array.of(1),
                  u64ToLeBytesV0(tokenAnchor.externalBalanceReference.observedSlot),
                ),
            Uint8Array.of(tokenAnchor.externalBalanceReference.connected ? 1 : 0),
          ),
      Uint8Array.of(tokenAnchor.enforceExternalMatch ? 1 : 0),
      tokenAnchor.expectedExternalBalance === null
        ? Uint8Array.of(0)
        : concatBytesV0(Uint8Array.of(1), u64ToLeBytesV0(tokenAnchor.expectedExternalBalance)),
    ),
  );
}

function canonicalPipelineTokenAnchorSummaryFromRequestV0(
  request: CanonicalPipelineRequestV0,
): CanonicalPipelineTokenAnchorSummaryV0 {
  const reference = request.tokenAnchor.externalBalanceReference;
  let anchorVerificationStatus: CanonicalPipelineExternalAnchorVerificationStatusV0;
  if (reference === null) {
    anchorVerificationStatus = CanonicalPipelineExternalAnchorVerificationStatusV0.NotRequested;
  } else if (!reference.connected) {
    anchorVerificationStatus = CanonicalPipelineExternalAnchorVerificationStatusV0.Disconnected;
  } else if (
    request.tokenAnchor.enforceExternalMatch &&
    request.tokenAnchor.expectedExternalBalance !== null &&
    reference.observedBalance !== request.tokenAnchor.expectedExternalBalance
  ) {
    anchorVerificationStatus = CanonicalPipelineExternalAnchorVerificationStatusV0.Rejected;
  } else if (request.tokenAnchor.enforceExternalMatch && request.tokenAnchor.expectedExternalBalance === null) {
    anchorVerificationStatus = CanonicalPipelineExternalAnchorVerificationStatusV0.Rejected;
  } else {
    anchorVerificationStatus = CanonicalPipelineExternalAnchorVerificationStatusV0.Accepted;
  }
  return {
    tokenPolicyVersion: request.tokenAnchor.tokenPolicyVersion,
    networkMode: request.tokenAnchor.networkMode,
    settlementAnchorType: request.tokenAnchor.settlementAnchorType,
    anchorVerificationStatus,
    externalBalanceReference:
      reference === null
        ? null
        : {
            referenceId: reference.referenceId,
            observedBalance: reference.observedBalance,
            observedSlot: reference.observedSlot,
            connected: reference.connected,
          },
    expectedExternalBalance: request.tokenAnchor.expectedExternalBalance,
    tokenAnchorDigest: canonicalPipelineTokenAnchorDigestV0(request.tokenAnchor),
  };
}

function canonicalPipelineExternalAnchorRejectionDetailV0(): string {
  return "external token anchor verification rejected the otherwise verified canonical transition";
}

function canonicalPipelineLedgerPayerAccountV0(
  request: CanonicalPipelineRequestV0,
): CanonicalPipelineLedgerAccountV0 {
  const payer = request.ledger.accounts.find((account) =>
    bytesEqualV0(account.accountId, request.ledger.payerAccountId),
  );
  if (!payer) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline ledger payerAccountId must exist in ledger.accounts",
    );
  }
  return payer;
}

function canonicalPipelineLedgerTransitionFromRequestV0(
  request: CanonicalPipelineRequestV0,
  burnSummary: CanonicalPipelineBurnSummaryV0,
  requestBindingHash: Uint8Array,
): {
  burnRecord: CanonicalPipelineBurnRecordV0;
  ledgerSummary: CanonicalPipelineLedgerSummaryV0;
} {
  const payer = canonicalPipelineLedgerPayerAccountV0(request);
  if (payer.balance < burnSummary.consumedBurnUnits) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline ledger payer balance is insufficient for computed burn",
    );
  }
  const preBalance = payer.balance;
  const postBalance = preBalance - burnSummary.consumedBurnUnits;
  const postAccounts = request.ledger.accounts.map((account) =>
    bytesEqualV0(account.accountId, request.ledger.payerAccountId)
      ? { accountId: copyBytesV0(account.accountId), balance: postBalance }
      : { accountId: copyBytesV0(account.accountId), balance: account.balance },
  );
  const burnedSupplyAfter = request.ledger.burnedSupply + burnSummary.consumedBurnUnits;
  const circulatingSupplyBefore = canonicalPipelineLedgerCirculatingSupplyV0(
    request.ledger.totalSupply,
    request.ledger.burnedSupply,
  );
  const circulatingSupplyAfter = canonicalPipelineLedgerCirculatingSupplyV0(
    request.ledger.totalSupply,
    burnedSupplyAfter,
  );
  const burnRecord: CanonicalPipelineBurnRecordV0 = {
    burnReason: burnSummary.burnReason,
    burnCategory: burnSummary.burnCategory,
    feeDisposition: CanonicalPipelineFeeDispositionV0.BurnedForCanonicalTruth,
    accountId: copyBytesV0(request.ledger.payerAccountId),
    preBalance,
    postBalance,
    burnedAmount: burnSummary.consumedBurnUnits,
    declaredFeeUnits: burnSummary.declaredFeeUnits,
    computedBurnUnits: burnSummary.computedBurnUnits,
    consumedBurnUnits: burnSummary.consumedBurnUnits,
    reportPipelineId: request.pipelineId,
    reportRequestBindingHash: copyBytesV0(requestBindingHash),
  };
  return {
    burnRecord,
    ledgerSummary: {
      ledgerPolicyVersion: request.ledger.ledgerPolicyVersion,
      payerAccountId: copyBytesV0(request.ledger.payerAccountId),
      totalSupply: request.ledger.totalSupply,
      burnedSupplyBefore: request.ledger.burnedSupply,
      burnedSupplyAfter,
      ledgerAccountCount: BigInt(request.ledger.accounts.length),
      circulatingSupplyBefore,
      circulatingSupplyAfter,
      ledgerConsistentWithRequest:
        burnRecord.reportPipelineId === request.pipelineId &&
        bytesEqualV0(burnRecord.reportRequestBindingHash, requestBindingHash) &&
        bytesEqualV0(burnRecord.accountId, request.ledger.payerAccountId),
      ledgerConsistentWithBurn:
        burnRecord.burnedAmount === burnSummary.consumedBurnUnits &&
        burnRecord.declaredFeeUnits === burnSummary.declaredFeeUnits &&
        burnRecord.computedBurnUnits === burnSummary.computedBurnUnits &&
        burnRecord.consumedBurnUnits === burnSummary.consumedBurnUnits &&
        burnRecord.preBalance >= burnRecord.consumedBurnUnits &&
        burnRecord.postBalance + burnRecord.consumedBurnUnits === burnRecord.preBalance,
      ledgerConsistentWithSupply:
        canonicalPipelineLedgerTotalBalanceV0(request.ledger.accounts) ===
          circulatingSupplyBefore &&
        canonicalPipelineLedgerTotalBalanceV0(postAccounts) === circulatingSupplyAfter,
      ledgerStateCommitment: {
        commitmentVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_VERSION_V0,
        preLedgerStateCommitment: canonicalPipelineLedgerStateCommitmentV0(
          request.ledger.ledgerPolicyVersion,
          request.ledger.payerAccountId,
          request.ledger.totalSupply,
          request.ledger.burnedSupply,
          request.ledger.accounts,
        ),
        postLedgerStateCommitment: canonicalPipelineLedgerStateCommitmentV0(
          request.ledger.ledgerPolicyVersion,
          request.ledger.payerAccountId,
          request.ledger.totalSupply,
          burnedSupplyAfter,
          postAccounts,
        ),
      },
    },
  };
}

function canonicalPipelineAccountingSummaryFromRequestV0(
  request: CanonicalPipelineRequestV0,
  burnSummary: CanonicalPipelineBurnSummaryV0,
  burnRecord: CanonicalPipelineBurnRecordV0,
  actualResult: ScenarioResultV0,
  settlementCommittedStateRoot: Uint8Array | null,
): CanonicalPipelineAccountingSummaryV0 {
  return {
    accountingPolicyVersion: request.accounting.accountingPolicyVersion,
    paymentIntent: request.accounting.paymentIntent,
    settlementIntent: request.accounting.settlementIntent,
    declaredFeeUnits: burnSummary.declaredFeeUnits,
    computedBurnUnits: burnSummary.computedBurnUnits,
    consumedBurnUnits: burnSummary.consumedBurnUnits,
    burnRecord: cloneCanonicalPipelineBurnRecordV0(burnRecord),
    settlementRecord: {
      settlementIntent: request.accounting.settlementIntent,
      settlementStatus: stageOutcomesForActualResultV0(actualResult).settlementStatus,
      settlementReason: canonicalPipelineSettlementReasonFromResultV0(actualResult),
      committedStateRoot:
        settlementCommittedStateRoot === null ? null : copyBytesV0(settlementCommittedStateRoot),
      futureTokenBindingStatus:
        CanonicalPipelineFutureTokenBindingStatusV0.PendingExternalAnchor,
      futureTokenBindingUnits: burnSummary.consumedBurnUnits,
    },
    accountingConsistentWithBurn:
      burnSummary.requestDeclaresCorrectBurn &&
      burnSummary.recomputedBurnMatchesReport &&
      burnSummary.burnConsumed &&
      burnSummary.consumedBurnUnits === burnSummary.computedBurnUnits &&
      burnRecord.declaredFeeUnits === burnSummary.declaredFeeUnits &&
      burnRecord.computedBurnUnits === burnSummary.computedBurnUnits &&
      burnRecord.consumedBurnUnits === burnSummary.consumedBurnUnits &&
      burnRecord.burnedAmount === burnSummary.consumedBurnUnits &&
      burnRecord.postBalance + burnRecord.consumedBurnUnits === burnRecord.preBalance,
    accountingConsistentWithOutcome:
      actualResult === ScenarioResultV0.Accepted
        ? settlementCommittedStateRoot !== null
        : settlementCommittedStateRoot === null,
  };
}

function canonicalPipelineReportDigestV0(report: CanonicalPipelineReportV0): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_REPORT_DIGEST_V1,
      u32ToLeBytesV0(report.pipelineSchemaVersion),
      lengthPrefixedBytesV0(textEncoder.encode(report.pipelineId)),
      lengthPrefixedBytesV0(textEncoder.encode(report.fixtureName)),
      lengthPrefixedBytesV0(textEncoder.encode(rustProofSystemV0(report.proofSystem))),
      lengthPrefixedBytesV0(textEncoder.encode(rustExpectedResultV0(report.expectedResult))),
      lengthPrefixedBytesV0(textEncoder.encode(rustExpectedResultV0(report.actualResult))),
      copyBytes32V0("report.preStateRoot", report.preStateRoot),
      report.executedPostStateRoot === null
        ? Uint8Array.of(0)
        : concatBytesV0(Uint8Array.of(1), copyBytes32V0("report.executedPostStateRoot", report.executedPostStateRoot)),
      report.settlementCommittedStateRoot === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0(
              "report.settlementCommittedStateRoot",
              report.settlementCommittedStateRoot,
            ),
          ),
      copyBytes32V0("report.requestBindingHash", report.requestAudit.requestBindingHash),
      copyBytes32V0(
        "report.preLedgerStateCommitment",
        report.ledgerSummary.ledgerStateCommitment.preLedgerStateCommitment,
      ),
      copyBytes32V0(
        "report.postLedgerStateCommitment",
        report.ledgerSummary.ledgerStateCommitment.postLedgerStateCommitment,
      ),
      copyBytes32V0("report.burnRecord.accountId", report.accountingSummary.burnRecord.accountId),
      u64ToLeBytesV0(report.accountingSummary.burnRecord.preBalance),
      u64ToLeBytesV0(report.accountingSummary.burnRecord.postBalance),
      u64ToLeBytesV0(report.accountingSummary.burnRecord.burnedAmount),
      copyBytes32V0(
        "report.walletBindingDigest",
        report.walletBindingSummary.walletBindingDigest,
      ),
      copyBytes32V0("report.tokenAnchorDigest", report.tokenAnchorSummary.tokenAnchorDigest),
      lengthPrefixedBytesV0(
        textEncoder.encode(report.statusExplanation.failureReasonCode),
      ),
      report.attestationSummary === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0("report.attestation.claimDigest", report.attestationSummary.claimDigest),
            copyBytes32V0(
              "report.attestation.evidenceRootDigest",
              report.attestationSummary.evidenceSummary.evidenceRootDigest,
            ),
            Uint8Array.of(report.attestationSummary.consistencyResult.consistent ? 1 : 0),
          ),
      report.attestationProofSummary === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0(
              "report.attestationProof.attestationTupleDigest",
              report.attestationProofSummary.attestationTupleDigest,
            ),
            Uint8Array.of(report.attestationProofSummary.verificationPassed ? 1 : 0),
            report.attestationProofSummary.starkPublicInputsDigest === null
              ? Uint8Array.of(0)
              : concatBytesV0(
                  Uint8Array.of(1),
                  copyBytes32V0(
                    "report.attestationProof.starkPublicInputsDigest",
                    report.attestationProofSummary.starkPublicInputsDigest,
                  ),
                ),
          ),
      report.provenanceSummary === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0(
              "report.provenance.provenanceRootDigest",
              report.provenanceSummary.provenanceRootDigest,
            ),
            Uint8Array.of(report.provenanceSummary.allSignatureChecksPassed ? 1 : 0),
          ),
      report.publicInputs === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0("report.publicInputsHash", report.publicInputs.publicInputsHash),
          ),
      report.proofArtifact === null
        ? Uint8Array.of(0)
        : concatBytesV0(
            Uint8Array.of(1),
            copyBytes32V0(
              "report.proofArtifact.proofBindingDigest",
              report.proofArtifact.proofBindingDigest,
            ),
          ),
    ),
  );
}

function canonicalPipelineHeadTransitionSummaryFromReportV0(
  request: CanonicalPipelineRequestV0,
  report: CanonicalPipelineReportV0,
  burnRecord: CanonicalPipelineBurnRecordV0,
): CanonicalPipelineHeadTransitionSummaryV0 {
  const requestCanonicalDigest = canonicalPipelineRequestBindingHashV0(request);
  const reportDigest = canonicalPipelineReportDigestV0(report);
  const canonicalHeadCommitment = sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_HEAD_TRANSITION_V1,
      u32ToLeBytesV0(request.head.settlementHeadVersion),
      copyBytes32V0("head.previousHeadHash", request.head.previousHeadHash),
      copyBytes32V0("head.requestCanonicalDigest", requestCanonicalDigest),
      copyBytes32V0("head.reportDigest", reportDigest),
      copyBytes32V0(
        "head.preLedgerStateCommitment",
        report.ledgerSummary.ledgerStateCommitment.preLedgerStateCommitment,
      ),
      copyBytes32V0(
        "head.postLedgerStateCommitment",
        report.ledgerSummary.ledgerStateCommitment.postLedgerStateCommitment,
      ),
      copyBytes32V0("head.burnAccountId", burnRecord.accountId),
      u64ToLeBytesV0(burnRecord.preBalance),
      u64ToLeBytesV0(burnRecord.postBalance),
      u64ToLeBytesV0(burnRecord.burnedAmount),
    ),
  );
  const currentHeadHash = sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_HEAD_HASH_V1,
      u32ToLeBytesV0(request.head.settlementHeadVersion),
      u64ToLeBytesV0(request.head.headSequenceNumber),
      copyBytes32V0("head.canonicalHeadCommitment", canonicalHeadCommitment),
    ),
  );
  return {
    settlementHeadVersion: request.head.settlementHeadVersion,
    authorityMode: report.headTransitionSummary.authorityMode,
    headSequenceNumber: request.head.headSequenceNumber,
    previousHeadHash: copyBytesV0(request.head.previousHeadHash),
    currentHeadHash,
    canonicalHeadCommitment,
    requestCanonicalDigest,
    reportDigest,
  };
}

function assertCanonicalPipelineHeadTransitionSummaryMatchesV0(
  report: CanonicalPipelineReportV0,
  request: CanonicalPipelineRequestV0,
  burnRecord: CanonicalPipelineBurnRecordV0,
): void {
  const expected = canonicalPipelineHeadTransitionSummaryFromReportV0(
    request,
    report,
    burnRecord,
  );
  if (!canonicalPipelineHeadTransitionSummaryEqualV0(report.headTransitionSummary, expected)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline headTransitionSummary contradicts the canonical head transition contract",
    );
  }
}

function canonicalPipelineGenesisAccountsDigestV0(
  request: CanonicalPipelineRequestV0,
): Uint8Array {
  return canonicalPipelineGenesisAccountsDigestFromAccountsV0(request.state.orderedAccounts());
}

function canonicalPipelineGenesisAccountsDigestFromAccountsV0(
  accounts: AccountV0[],
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_V1,
      canonicalPipelineOrderedAccountBytesV0(accounts),
    ),
  );
}

function canonicalPipelineLedgerAccountsDigestV0(
  ledger: CanonicalPipelineLedgerPolicyV0,
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_LEDGER_ACCOUNTS_V1,
      canonicalPipelineLedgerOrderedAccountBytesV0(ledger.accounts),
    ),
  );
}

function canonicalPipelineLedgerStateCommitmentV0(
  ledgerPolicyVersion: number,
  payerAccountId: Uint8Array,
  totalSupply: bigint,
  burnedSupply: bigint,
  orderedAccounts: CanonicalPipelineLedgerAccountV0[],
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_LEDGER_STATE_V1,
      u32ToLeBytesV0(ledgerPolicyVersion),
      copyBytes32V0("ledger.payerAccountId", payerAccountId),
      u64ToLeBytesV0(totalSupply),
      u64ToLeBytesV0(burnedSupply),
      canonicalPipelineLedgerOrderedAccountBytesV0(orderedAccounts),
    ),
  );
}

function canonicalPipelineTransactionsDigestV0(
  request: CanonicalPipelineRequestV0,
): Uint8Array {
  return canonicalPipelineTransactionsDigestFromTransactionsV0(request.batch.transactions);
}

function canonicalPipelineTransactionsDigestFromTransactionsV0(
  transactions: TransferTxV0[],
): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_CANONICAL_PIPELINE_TRANSACTIONS_V1,
      canonicalPipelineTransactionBytesV0(transactions),
    ),
  );
}

function canonicalPipelineGenesisAccountsFromAccountsV0(
  accounts: AccountV0[],
): CanonicalPipelineGenesisAccountsV0 {
  return {
    materialVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_VERSION_V0,
    orderedAccounts: accounts.map(cloneAccountV0),
  };
}

function canonicalPipelineTransactionsCommitmentExpansionFromTransactionsV0(
  transactions: TransferTxV0[],
): CanonicalPipelineTransactionsCommitmentExpansionV0 {
  const transactionBytes = transactions.map(transferCanonicalBytesV0);
  return {
    expansionVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_TRANSACTIONS_EXPANSION_VERSION_V0,
    transactionsCommitment: deriveTransactionsCommitmentV0(transactionBytes),
    orderedTransactions: transactions.map(cloneTransferTxV0),
  };
}

function canonicalPipelineOutcomesCommitmentExpansionFromTransitionV0(
  transition: TransitionV0,
): CanonicalPipelineOutcomesCommitmentExpansionV0 {
  return {
    expansionVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_OUTCOMES_EXPANSION_VERSION_V0,
    outcomesCommitment: copyBytesV0(transition.outcomesCommitment),
    outcomes: transition.outcomes.map((outcome) => ({
      txIndex: outcome.txIndex,
      senderAccountId: copyBytesV0(outcome.senderAccountId),
      consumedNonce: outcome.consumedNonce,
      feeCharged: outcome.feeCharged,
      touchedAccountsCommitment: copyBytesV0(outcome.touchedAccountsCommitment),
      operationResultCommitment: copyBytesV0(outcome.operationResultCommitment),
      status: outcome.status,
    })),
    appliedSteps: transition.appliedSteps.map((step) => ({
      txIndex: step.txIndex,
      senderAccountId: copyBytesV0(step.senderAccountId),
      recipientAccountId: copyBytesV0(step.recipientAccountId),
      senderNonceBefore: step.senderNonceBefore,
      senderNonceAfter: step.senderNonceAfter,
      senderBalanceBefore: step.senderBalanceBefore,
      senderBalanceAfter: step.senderBalanceAfter,
      recipientBalanceBefore: step.recipientBalanceBefore,
      recipientBalanceAfter: step.recipientBalanceAfter,
      amount: step.amount,
      feeCharged: step.feeCharged,
    })),
  };
}

function canonicalPipelineBatchContextCommitmentExpansionFromConfigV0(
  config: ExecutionConfigV0,
): CanonicalPipelineBatchContextCommitmentExpansionV0 {
  return {
    expansionVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_BATCH_CONTEXT_EXPANSION_VERSION_V0,
    batchContextCommitment: sha256BytesV0(batchContextBytesV0(batchContextV0(config))),
    transitionBindingVersion: TRANSITION_BINDING_VERSION_V0,
    systemConfig: {
      rollupId: copyBytesV0(config.rollupId),
      executionModelVersion: config.executionModelVersion,
      batchVersion: config.batchVersion,
    },
    feeParameters: {
      feePerTransfer: ZERO_FEE_PER_TRANSFER_V0,
    },
    validityReference: {
      kind: CanonicalPipelineValidityReferenceKindV0.None,
      noneMarker: 0,
    },
    executionConstants: {
      transferTxVersion: TRANSFER_TX_VERSION_V0,
      transitionBindingVersion: TRANSITION_BINDING_VERSION_V0,
      appliedStatus: EXECUTION_OUTCOME_STATUS_APPLIED_V0,
    },
  };
}

function canonicalPipelineFeeSummaryCommitmentExpansionFromFeeSummaryV0(
  summary: FeeSummaryV0,
): CanonicalPipelineFeeSummaryCommitmentExpansionV0 {
  return {
    expansionVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_FEE_SUMMARY_EXPANSION_VERSION_V0,
    feeSummaryCommitment: sha256BytesV0(feeSummaryCanonicalBytesV0(summary)),
    feeSummary: {
      txCount: summary.txCount,
      totalFeeCharged: summary.totalFeeCharged,
    },
  };
}

function canonicalPipelineOrderedAccountBytesV0(accounts: AccountV0[]): Uint8Array {
  return concatBytesV0(
    u64ToLeBytesV0(BigInt(accounts.length)),
    ...accounts.map((account) =>
      concatBytesV0(
        copyBytes32V0("accountId", account.accountId),
        u64ToLeBytesV0(account.balance),
        u64ToLeBytesV0(account.nonce),
      ),
    ),
  );
}

function canonicalPipelineLedgerOrderedAccountBytesV0(
  accounts: CanonicalPipelineLedgerAccountV0[],
): Uint8Array {
  return concatBytesV0(
    u64ToLeBytesV0(BigInt(accounts.length)),
    ...accounts.map((account) =>
      concatBytesV0(
        copyBytes32V0("ledger.accountId", account.accountId),
        u64ToLeBytesV0(account.balance),
      ),
    ),
  );
}

function canonicalPipelineTransactionBytesV0(transactions: TransferTxV0[]): Uint8Array {
  return concatBytesV0(
    u64ToLeBytesV0(BigInt(transactions.length)),
    ...transactions.map((tx) =>
      concatBytesV0(
        u32ToLeBytesV0(tx.txVersion),
        copyBytes32V0("senderAccountId", tx.senderAccountId),
        copyBytes32V0("recipientAccountId", tx.recipientAccountId),
        u64ToLeBytesV0(tx.senderNonce),
        u64ToLeBytesV0(tx.amount),
      ),
    ),
  );
}

function executionConfigEqualV0(left: ExecutionConfigV0, right: ExecutionConfigV0): boolean {
  return (
    bytesEqualV0(left.rollupId, right.rollupId) &&
    left.executionModelVersion === right.executionModelVersion &&
    left.batchVersion === right.batchVersion
  );
}

function feeSummaryEqualV0(left: FeeSummaryV0, right: FeeSummaryV0): boolean {
  return left.txCount === right.txCount && left.totalFeeCharged === right.totalFeeCharged;
}

function canonicalPipelineBurnDerivationInputsEqualV0(
  left: CanonicalPipelineBurnDerivationInputsV0,
  right: CanonicalPipelineBurnDerivationInputsV0,
): boolean {
  return (
    left.txCount === right.txCount &&
    left.meteredRequestSizeBytes === right.meteredRequestSizeBytes &&
    left.requestKind === right.requestKind &&
    left.proofSystem === right.proofSystem &&
    left.attestationEvidenceItems === right.attestationEvidenceItems &&
    left.attestationClaimBytes === right.attestationClaimBytes &&
    left.attestationEvidenceBytes === right.attestationEvidenceBytes
  );
}

function canonicalPipelineBurnPolicyEqualV0(
  left: CanonicalPipelineBurnPolicyV0,
  right: CanonicalPipelineBurnPolicyV0,
): boolean {
  return (
    left.burnPolicyVersion === right.burnPolicyVersion &&
    left.baseUnits === right.baseUnits &&
    left.executionRequestKindUnits === right.executionRequestKindUnits &&
    left.attestationRequestKindUnits === right.attestationRequestKindUnits &&
    left.mockProofSystemUnits === right.mockProofSystemUnits &&
    left.starkProofSystemUnits === right.starkProofSystemUnits &&
    left.transactionUnitsPerItem === right.transactionUnitsPerItem &&
    left.meteredRequestSizeChunkBytes === right.meteredRequestSizeChunkBytes
  );
}

function canonicalPipelineBurnFailureSemanticsEqualV0(
  left: CanonicalPipelineBurnFailureSemanticsV0,
  right: CanonicalPipelineBurnFailureSemanticsV0,
): boolean {
  return (
    left.executionRejectedBurnsFullAmount === right.executionRejectedBurnsFullAmount &&
    left.verificationRejectedBurnsFullAmount === right.verificationRejectedBurnsFullAmount &&
    left.settlementRejectedBurnsFullAmount === right.settlementRejectedBurnsFullAmount &&
    left.partialBurnAllowed === right.partialBurnAllowed
  );
}

function canonicalPipelineBurnSummaryEqualV0(
  left: CanonicalPipelineBurnSummaryV0,
  right: CanonicalPipelineBurnSummaryV0,
): boolean {
  return (
    left.burnPolicyVersion === right.burnPolicyVersion &&
    canonicalPipelineBurnPolicyEqualV0(left.burnPolicy, right.burnPolicy) &&
    left.burnReason === right.burnReason &&
    left.burnCategory === right.burnCategory &&
    left.requestKind === right.requestKind &&
    left.burnIntent === right.burnIntent &&
    left.declaredFeeUnits === right.declaredFeeUnits &&
    left.computedBurnUnits === right.computedBurnUnits &&
    left.consumedBurnUnits === right.consumedBurnUnits &&
    canonicalPipelineBurnDerivationInputsEqualV0(
      left.burnDerivationInputs,
      right.burnDerivationInputs,
    ) &&
    left.requestDeclaresCorrectBurn === right.requestDeclaresCorrectBurn &&
    left.recomputedBurnMatchesReport === right.recomputedBurnMatchesReport &&
    left.burnConsumed === right.burnConsumed &&
    canonicalPipelineBurnFailureSemanticsEqualV0(
      left.failureSemantics,
      right.failureSemantics,
    )
  );
}

function canonicalPipelineBurnRecordEqualV0(
  left: CanonicalPipelineBurnRecordV0,
  right: CanonicalPipelineBurnRecordV0,
): boolean {
  return (
    left.burnReason === right.burnReason &&
    left.burnCategory === right.burnCategory &&
    left.feeDisposition === right.feeDisposition &&
    bytesEqualV0(left.accountId, right.accountId) &&
    left.preBalance === right.preBalance &&
    left.postBalance === right.postBalance &&
    left.burnedAmount === right.burnedAmount &&
    left.declaredFeeUnits === right.declaredFeeUnits &&
    left.computedBurnUnits === right.computedBurnUnits &&
    left.consumedBurnUnits === right.consumedBurnUnits &&
    left.reportPipelineId === right.reportPipelineId &&
    bytesEqualV0(left.reportRequestBindingHash, right.reportRequestBindingHash)
  );
}

function cloneCanonicalPipelineBurnRecordV0(
  value: CanonicalPipelineBurnRecordV0,
): CanonicalPipelineBurnRecordV0 {
  return {
    burnReason: value.burnReason,
    burnCategory: value.burnCategory,
    feeDisposition: value.feeDisposition,
    accountId: copyBytesV0(value.accountId),
    preBalance: value.preBalance,
    postBalance: value.postBalance,
    burnedAmount: value.burnedAmount,
    declaredFeeUnits: value.declaredFeeUnits,
    computedBurnUnits: value.computedBurnUnits,
    consumedBurnUnits: value.consumedBurnUnits,
    reportPipelineId: value.reportPipelineId,
    reportRequestBindingHash: copyBytesV0(value.reportRequestBindingHash),
  };
}

function canonicalPipelineSettlementRecordEqualV0(
  left: CanonicalPipelineSettlementRecordV0,
  right: CanonicalPipelineSettlementRecordV0,
): boolean {
  return (
    left.settlementIntent === right.settlementIntent &&
    left.settlementStatus === right.settlementStatus &&
    left.settlementReason === right.settlementReason &&
    nullableBytesEqualV0(left.committedStateRoot, right.committedStateRoot) &&
    left.futureTokenBindingStatus === right.futureTokenBindingStatus &&
    left.futureTokenBindingUnits === right.futureTokenBindingUnits
  );
}

function canonicalPipelineAccountingSummaryEqualV0(
  left: CanonicalPipelineAccountingSummaryV0,
  right: CanonicalPipelineAccountingSummaryV0,
): boolean {
  return (
    left.accountingPolicyVersion === right.accountingPolicyVersion &&
    left.paymentIntent === right.paymentIntent &&
    left.settlementIntent === right.settlementIntent &&
    left.declaredFeeUnits === right.declaredFeeUnits &&
    left.computedBurnUnits === right.computedBurnUnits &&
    left.consumedBurnUnits === right.consumedBurnUnits &&
    canonicalPipelineBurnRecordEqualV0(left.burnRecord, right.burnRecord) &&
    canonicalPipelineSettlementRecordEqualV0(
      left.settlementRecord,
      right.settlementRecord,
    ) &&
    left.accountingConsistentWithBurn === right.accountingConsistentWithBurn &&
    left.accountingConsistentWithOutcome === right.accountingConsistentWithOutcome
  );
}

function canonicalPipelineLedgerAccountListsEqualV0(
  left: readonly CanonicalPipelineLedgerAccountV0[],
  right: readonly CanonicalPipelineLedgerAccountV0[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (account, index) =>
        bytesEqualV0(account.accountId, right[index].accountId) &&
        account.balance === right[index].balance,
    )
  );
}

function canonicalPipelineLedgerStateCommitmentEqualV0(
  left: CanonicalPipelineLedgerStateCommitmentV0,
  right: CanonicalPipelineLedgerStateCommitmentV0,
): boolean {
  return (
    left.commitmentVersion === right.commitmentVersion &&
    bytesEqualV0(left.preLedgerStateCommitment, right.preLedgerStateCommitment) &&
    bytesEqualV0(left.postLedgerStateCommitment, right.postLedgerStateCommitment)
  );
}

function canonicalPipelineLedgerSummaryEqualV0(
  left: CanonicalPipelineLedgerSummaryV0,
  right: CanonicalPipelineLedgerSummaryV0,
): boolean {
  return (
    left.ledgerPolicyVersion === right.ledgerPolicyVersion &&
    bytesEqualV0(left.payerAccountId, right.payerAccountId) &&
    left.totalSupply === right.totalSupply &&
    left.burnedSupplyBefore === right.burnedSupplyBefore &&
    left.burnedSupplyAfter === right.burnedSupplyAfter &&
    left.ledgerAccountCount === right.ledgerAccountCount &&
    left.circulatingSupplyBefore === right.circulatingSupplyBefore &&
    left.circulatingSupplyAfter === right.circulatingSupplyAfter &&
    left.ledgerConsistentWithRequest === right.ledgerConsistentWithRequest &&
    left.ledgerConsistentWithBurn === right.ledgerConsistentWithBurn &&
    left.ledgerConsistentWithSupply === right.ledgerConsistentWithSupply &&
    canonicalPipelineLedgerStateCommitmentEqualV0(
      left.ledgerStateCommitment,
      right.ledgerStateCommitment,
    )
  );
}

function canonicalPipelineStatusExplanationEqualV0(
  left: CanonicalPipelineStatusExplanationV0,
  right: CanonicalPipelineStatusExplanationV0,
): boolean {
  return (
    left.truthArtifactKind === right.truthArtifactKind &&
    left.requestKind === right.requestKind &&
    left.finalStatus === right.finalStatus &&
    left.failureStage === right.failureStage &&
    left.failureReasonCode === right.failureReasonCode &&
    left.detail === right.detail
  );
}

function canonicalPipelineAttestationClaimEqualV0(
  left: CanonicalPipelineAttestationClaimV0,
  right: CanonicalPipelineAttestationClaimV0,
): boolean {
  if (left.claimKind !== right.claimKind) {
    return false;
  }
  if (
    "expectedEvidenceRootDigest" in left.claimPayload &&
    "expectedEvidenceRootDigest" in right.claimPayload
  ) {
    return bytesEqualV0(
      left.claimPayload.expectedEvidenceRootDigest,
      right.claimPayload.expectedEvidenceRootDigest,
    );
  }
  if (
    "expectedEvidenceDigest" in left.claimPayload &&
    "expectedEvidenceDigest" in right.claimPayload
  ) {
    return (
      left.claimPayload.targetLabel === right.claimPayload.targetLabel &&
      bytesEqualV0(
        left.claimPayload.expectedEvidenceDigest,
        right.claimPayload.expectedEvidenceDigest,
      )
    );
  }
  if (
    "expectedSubstringUtf8" in left.claimPayload &&
    "expectedSubstringUtf8" in right.claimPayload
  ) {
    return (
      left.claimPayload.targetLabel === right.claimPayload.targetLabel &&
      left.claimPayload.expectedSubstringUtf8 === right.claimPayload.expectedSubstringUtf8
    );
  }
  if ("fieldPath" in left.claimPayload && "fieldPath" in right.claimPayload) {
    return (
      left.claimPayload.targetLabel === right.claimPayload.targetLabel &&
      left.claimPayload.expectedValueUtf8 === right.claimPayload.expectedValueUtf8 &&
      left.claimPayload.fieldPath.length === right.claimPayload.fieldPath.length &&
      left.claimPayload.fieldPath.every(
        (segment, index) => segment === right.claimPayload.fieldPath[index],
      )
    );
  }
  return false;
}

function canonicalPipelineAttestationEvidenceSummaryItemEqualV0(
  left: CanonicalPipelineAttestationEvidenceSummaryItemV0,
  right: CanonicalPipelineAttestationEvidenceSummaryItemV0,
): boolean {
  return (
    left.evidenceKind === right.evidenceKind &&
    left.label === right.label &&
    left.originalPayloadUtf8 === right.originalPayloadUtf8 &&
    left.originalPayloadSizeBytes === right.originalPayloadSizeBytes &&
    left.normalizedForm === right.normalizedForm &&
    left.normalizedPayloadUtf8 === right.normalizedPayloadUtf8 &&
    left.normalizedPayloadSizeBytes === right.normalizedPayloadSizeBytes &&
    bytesEqualV0(left.evidenceDigest, right.evidenceDigest) &&
    bytesEqualV0(left.provenanceDigest, right.provenanceDigest)
  );
}

function canonicalPipelineAttestationSummaryEqualV0(
  left: CanonicalPipelineAttestationSummaryV0 | null,
  right: CanonicalPipelineAttestationSummaryV0 | null,
): boolean {
  if (left === null || right === null) {
    return left === right;
  }
  return (
    left.attestationSchemaVersion === right.attestationSchemaVersion &&
    left.attestationScope === right.attestationScope &&
    left.attestationProofKind === right.attestationProofKind &&
    left.normalizationPolicyVersion === right.normalizationPolicyVersion &&
    canonicalPipelineAttestationConstraintsEqualV0(
      left.attestationConstraints,
      right.attestationConstraints,
    ) &&
    canonicalPipelineAttestationClaimEqualV0(left.claim, right.claim) &&
    bytesEqualV0(left.claimDigest, right.claimDigest) &&
    left.evidenceSummary.evidenceItemCount === right.evidenceSummary.evidenceItemCount &&
    left.evidenceSummary.evidenceItems.length === right.evidenceSummary.evidenceItems.length &&
    left.evidenceSummary.evidenceItems.every((item, index) =>
      canonicalPipelineAttestationEvidenceSummaryItemEqualV0(
        item,
        right.evidenceSummary.evidenceItems[index]!,
      ),
    ) &&
    bytesEqualV0(
      left.evidenceSummary.evidenceRootDigest,
      right.evidenceSummary.evidenceRootDigest,
    ) &&
    left.normalizationSummary.normalizationPolicyVersion ===
      right.normalizationSummary.normalizationPolicyVersion &&
    left.normalizationSummary.normalizedEvidenceCount ===
      right.normalizationSummary.normalizedEvidenceCount &&
    left.normalizationSummary.totalNormalizedBytes ===
      right.normalizationSummary.totalNormalizedBytes &&
    left.normalizationSummary.normalizationSucceeded ===
      right.normalizationSummary.normalizationSucceeded &&
    left.consistencyResult.relation === right.consistencyResult.relation &&
    left.consistencyResult.targetLabel === right.consistencyResult.targetLabel &&
    left.consistencyResult.consistent === right.consistencyResult.consistent &&
    left.attestationStatus === right.attestationStatus &&
    left.attestationFailureReason.reason === right.attestationFailureReason.reason &&
    left.attestationFailureReason.detail === right.attestationFailureReason.detail &&
    left.proofScopeHonestyNote === right.proofScopeHonestyNote
  );
}

function canonicalPipelineExternalBalanceReferenceEqualV0(
  left: CanonicalPipelineExternalBalanceReferenceV0 | null,
  right: CanonicalPipelineExternalBalanceReferenceV0 | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.referenceId === right.referenceId &&
      left.observedBalance === right.observedBalance &&
      left.observedSlot === right.observedSlot &&
      left.connected === right.connected)
  );
}

function canonicalPipelineHeadTransitionSummaryEqualV0(
  left: CanonicalPipelineHeadTransitionSummaryV0,
  right: CanonicalPipelineHeadTransitionSummaryV0,
): boolean {
  return (
    left.settlementHeadVersion === right.settlementHeadVersion &&
    left.authorityMode === right.authorityMode &&
    left.headSequenceNumber === right.headSequenceNumber &&
    bytesEqualV0(left.previousHeadHash, right.previousHeadHash) &&
    bytesEqualV0(left.currentHeadHash, right.currentHeadHash) &&
    bytesEqualV0(left.canonicalHeadCommitment, right.canonicalHeadCommitment) &&
    bytesEqualV0(left.requestCanonicalDigest, right.requestCanonicalDigest) &&
    bytesEqualV0(left.reportDigest, right.reportDigest)
  );
}

function canonicalPipelineWalletBindingSummaryEqualV0(
  left: CanonicalPipelineWalletBindingSummaryV0,
  right: CanonicalPipelineWalletBindingSummaryV0,
): boolean {
  return (
    left.walletBindingVersion === right.walletBindingVersion &&
    bytesEqualV0(left.accountId, right.accountId) &&
    left.walletAddress === right.walletAddress &&
    bytesEqualV0(left.walletBindingDigest, right.walletBindingDigest) &&
    left.bindingConsistentWithAccount === right.bindingConsistentWithAccount
  );
}

function canonicalPipelineTokenAnchorSummaryEqualV0(
  left: CanonicalPipelineTokenAnchorSummaryV0,
  right: CanonicalPipelineTokenAnchorSummaryV0,
): boolean {
  return (
    left.tokenPolicyVersion === right.tokenPolicyVersion &&
    left.networkMode === right.networkMode &&
    left.settlementAnchorType === right.settlementAnchorType &&
    left.anchorVerificationStatus === right.anchorVerificationStatus &&
    canonicalPipelineExternalBalanceReferenceEqualV0(
      left.externalBalanceReference,
      right.externalBalanceReference,
    ) &&
    left.expectedExternalBalance === right.expectedExternalBalance &&
    bytesEqualV0(left.tokenAnchorDigest, right.tokenAnchorDigest)
  );
}

function canonicalPipelineProvenanceSummaryItemEqualV0(
  left: CanonicalPipelineProvenanceSummaryItemV0,
  right: CanonicalPipelineProvenanceSummaryItemV0,
): boolean {
  return (
    left.label === right.label &&
    left.provenancePolicyVersion === right.provenancePolicyVersion &&
    left.provenanceType === right.provenanceType &&
    left.sourceType === right.sourceType &&
    left.sourceIdentifier === right.sourceIdentifier &&
    left.signaturePresent === right.signaturePresent &&
    left.signatureValid === right.signatureValid &&
    nullableBytesEqualV0(left.signerPublicKey, right.signerPublicKey) &&
    nullableBytesEqualV0(left.signature, right.signature) &&
    left.timestampUnixSeconds === right.timestampUnixSeconds &&
    bytesEqualV0(left.provenanceDigest, right.provenanceDigest)
  );
}

function canonicalPipelineProvenanceSummaryEqualV0(
  left: CanonicalPipelineProvenanceSummaryV0 | null,
  right: CanonicalPipelineProvenanceSummaryV0 | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.provenanceItemCount === right.provenanceItemCount &&
      bytesEqualV0(left.provenanceRootDigest, right.provenanceRootDigest) &&
      left.allSignatureChecksPassed === right.allSignatureChecksPassed &&
      left.items.length === right.items.length &&
      left.items.every((item, index) =>
        canonicalPipelineProvenanceSummaryItemEqualV0(item, right.items[index]!),
      ))
  );
}

function canonicalPipelineAttestationProofSummaryEqualV0(
  left: CanonicalPipelineAttestationProofSummaryV0 | null,
  right: CanonicalPipelineAttestationProofSummaryV0 | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.proofKind === right.proofKind &&
      bytesEqualV0(left.attestationTupleDigest, right.attestationTupleDigest) &&
      left.verificationPassed === right.verificationPassed &&
      left.mockPolicyVersion === right.mockPolicyVersion &&
      left.starkPolicyVersion === right.starkPolicyVersion &&
      nullableBytesEqualV0(left.starkPublicInputsDigest, right.starkPublicInputsDigest) &&
      nullableBytesEqualV0(left.starkProofBytesDigest, right.starkProofBytesDigest) &&
      nullableBytesEqualV0(left.starkProofBindingDigest, right.starkProofBindingDigest))
  );
}

function canonicalPipelineTransactionsCommitmentExpansionEqualV0(
  left: CanonicalPipelineTransactionsCommitmentExpansionV0,
  right: CanonicalPipelineTransactionsCommitmentExpansionV0,
): boolean {
  return (
    left.expansionVersion === right.expansionVersion &&
    bytesEqualV0(left.transactionsCommitment, right.transactionsCommitment) &&
    transferTxListsEqualV0(left.orderedTransactions, right.orderedTransactions)
  );
}

function canonicalPipelineOutcomesCommitmentExpansionEqualV0(
  left: CanonicalPipelineOutcomesCommitmentExpansionV0,
  right: CanonicalPipelineOutcomesCommitmentExpansionV0,
): boolean {
  return (
    left.expansionVersion === right.expansionVersion &&
    bytesEqualV0(left.outcomesCommitment, right.outcomesCommitment) &&
    canonicalExecutionOutcomeListsEqualV0(left.outcomes, right.outcomes) &&
    appliedTransferStepListsEqualV0(left.appliedSteps, right.appliedSteps)
  );
}

function canonicalPipelineBatchContextCommitmentExpansionEqualV0(
  left: CanonicalPipelineBatchContextCommitmentExpansionV0,
  right: CanonicalPipelineBatchContextCommitmentExpansionV0,
): boolean {
  return (
    left.expansionVersion === right.expansionVersion &&
    bytesEqualV0(left.batchContextCommitment, right.batchContextCommitment) &&
    left.transitionBindingVersion === right.transitionBindingVersion &&
    executionConfigEqualV0(left.systemConfig, right.systemConfig) &&
    left.feeParameters.feePerTransfer === right.feeParameters.feePerTransfer &&
    left.validityReference.kind === right.validityReference.kind &&
    left.validityReference.noneMarker === right.validityReference.noneMarker &&
    left.executionConstants.transferTxVersion === right.executionConstants.transferTxVersion &&
    left.executionConstants.transitionBindingVersion ===
      right.executionConstants.transitionBindingVersion &&
    left.executionConstants.appliedStatus === right.executionConstants.appliedStatus
  );
}

function canonicalPipelineFeeSummaryCommitmentExpansionEqualV0(
  left: CanonicalPipelineFeeSummaryCommitmentExpansionV0,
  right: CanonicalPipelineFeeSummaryCommitmentExpansionV0,
): boolean {
  return (
    left.expansionVersion === right.expansionVersion &&
    bytesEqualV0(left.feeSummaryCommitment, right.feeSummaryCommitment) &&
    feeSummaryEqualV0(left.feeSummary, right.feeSummary)
  );
}

function assertCanonicalPipelineOutcomesExpansionShapeV0(
  expansion: CanonicalPipelineOutcomesCommitmentExpansionV0,
): void {
  if (expansion.outcomes.length !== expansion.appliedSteps.length) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline commitmentExpansions.outcomes must expose one appliedStep per outcome",
    );
  }
  for (let index = 0; index < expansion.outcomes.length; index += 1) {
    const outcome = expansion.outcomes[index];
    const step = expansion.appliedSteps[index];
    if (step.senderNonceAfter !== step.senderNonceBefore + 1n) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline commitmentExpansions.outcomes contains a non-canonical sender nonce transition",
      );
    }
    if (step.senderBalanceAfter !== step.senderBalanceBefore - step.amount - step.feeCharged) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline commitmentExpansions.outcomes contains a non-canonical sender balance transition",
      );
    }
    if (step.recipientBalanceAfter !== step.recipientBalanceBefore + step.amount) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline commitmentExpansions.outcomes contains a non-canonical recipient balance transition",
      );
    }
    if (
      outcome.txIndex !== step.txIndex ||
      !bytesEqualV0(outcome.senderAccountId, step.senderAccountId) ||
      outcome.consumedNonce !== step.senderNonceBefore ||
      outcome.feeCharged !== step.feeCharged ||
      outcome.status !== EXECUTION_OUTCOME_STATUS_APPLIED_V0 ||
      !bytesEqualV0(
        outcome.touchedAccountsCommitment,
        deriveTouchedAccountsCommitmentV0(step.senderAccountId, step.recipientAccountId),
      ) ||
      !bytesEqualV0(
        outcome.operationResultCommitment,
        deriveTransferResultCommitmentV0(
          step.amount,
          step.senderBalanceBefore,
          step.senderBalanceAfter,
          step.recipientBalanceBefore,
          step.recipientBalanceAfter,
        ),
      )
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline commitmentExpansions.outcomes contradicts its appliedSteps",
      );
    }
  }
  const recomputedOutcomesCommitment = deriveOutcomesCommitmentV0(
    expansion.outcomes.map(outcomeCanonicalBytesV0),
  );
  if (!bytesEqualV0(expansion.outcomesCommitment, recomputedOutcomesCommitment)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline commitmentExpansions.outcomesCommitment does not match outcomes",
    );
  }
}

function canonicalPipelineTamperEqualV0(
  left: CanonicalPipelineTamperAuditV0 | { byteOffset: number; xorWith: number } | null,
  right: CanonicalPipelineTamperAuditV0 | { byteOffset: number; xorWith: number } | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.byteOffset === right.byteOffset &&
      left.xorWith === right.xorWith)
  );
}

function optionalTamperBytesV0(
  tamper: { byteOffset: number; xorWith: number } | null,
): Uint8Array {
  if (tamper === null) {
    return Uint8Array.of(0);
  }
  return concatBytesV0(
    Uint8Array.of(1),
    u64ToLeBytesV0(BigInt(tamper.byteOffset)),
    Uint8Array.of(tamper.xorWith),
  );
}

function lengthPrefixedBytesV0(bytes: Uint8Array): Uint8Array {
  return concatBytesV0(u64ToLeBytesV0(BigInt(bytes.length)), bytes);
}

function deriveTransactionsCommitmentV0(transactionBytes: Uint8Array[]): Uint8Array {
  const entryHashes = transactionBytes.map((txBytes, index) =>
    sha256BytesV0(
      concatBytesV0(
        D_TX_ENTRY_V1,
        u64ToLeBytesV0(BigInt(index)),
        u64ToLeBytesV0(BigInt(txBytes.length)),
        txBytes,
      ),
    ),
  );
  return sha256BytesV0(
    concatBytesV0(
      D_TX_LIST_V1,
      u64ToLeBytesV0(BigInt(transactionBytes.length)),
      ...entryHashes,
    ),
  );
}

function deriveOutcomesCommitmentV0(outcomeBytes: Uint8Array[]): Uint8Array {
  return sha256BytesV0(
    concatBytesV0(
      D_OUTCOME_LIST_V1,
      u64ToLeBytesV0(BigInt(outcomeBytes.length)),
      ...outcomeBytes.map((bytes) => sha256BytesV0(bytes)),
    ),
  );
}

function sha256BytesV0(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function copyBytesV0(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function copyBytesFixedV0(label: string, bytes: Uint8Array, expectedLength: number): Uint8Array {
  if (bytes.length !== expectedLength) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidLength",
      `${label} must be ${expectedLength} bytes, got ${bytes.length}`,
    );
  }
  return copyBytesV0(bytes);
}

function copyBytes32V0(label: string, bytes: Uint8Array): Uint8Array {
  if (bytes.length !== HASH_LEN_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidLength",
      `${label} must be ${HASH_LEN_V0} bytes, got ${bytes.length}`,
    );
  }
  return copyBytesV0(bytes);
}

function bytesEqualV0(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
}

function nullableBytesEqualV0(
  left: Uint8Array | null,
  right: Uint8Array | null,
): boolean {
  if (left === null || right === null) {
    return left === right;
  }
  return bytesEqualV0(left, right);
}

function compareBytesV0(left: Uint8Array, right: Uint8Array): number {
  const len = Math.min(left.length, right.length);
  for (let i = 0; i < len; i += 1) {
    if (left[i] !== right[i]) {
      return left[i] - right[i];
    }
  }
  return left.length - right.length;
}

function concatBytesV0(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32ToLeBytesV0(value: number): Uint8Array {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value, true);
  return out;
}

function u64ToLeBytesV0(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new AuraTypescriptSdkErrorV0("InvalidLength", `u64 out of range: ${value}`);
  }
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, value, true);
  return out;
}

function readU32LeV0(bytes: Uint8Array, offset: number, field: string): number {
  if (offset < 0 || offset + 4 > bytes.length) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `cannot read u32 ${field} at offset ${offset}`,
    );
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
}

function readU64LeV0(bytes: Uint8Array, offset: number, field: string): bigint {
  if (offset < 0 || offset + 8 > bytes.length) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `cannot read u64 ${field} at offset ${offset}`,
    );
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0, true);
}

function toU64BigIntV0(value: bigint | number, field: string): bigint {
  const normalized =
    typeof value === "bigint" ? value : normalizedNumberToBigIntV0(value, field);
  if (normalized < 0n || normalized > 0xffff_ffff_ffff_ffffn) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} must be a u64 value`,
    );
  }
  return normalized;
}

function normalizedNumberToBigIntV0(value: number, field: string): bigint {
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} must be an integer number or bigint`,
    );
  }
  return BigInt(value);
}

function safeJsonU64V0(value: number, field: string): bigint {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} must be a non-negative safe integer`,
    );
  }
  return BigInt(value);
}

function safeJsonU32V0(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} must be a u32-safe integer`,
    );
  }
  return value;
}

function safeJsonU8V0(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} must be a u8-safe integer`,
    );
  }
  return value;
}

function safeJsonIndexV0(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} must be a non-negative safe integer`,
    );
  }
  return value;
}

function numberFromU64ForRustBridgeV0(value: bigint, field: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${field} exceeds safe integer range for the current Rust bridge`,
    );
  }
  return Number(value);
}

function runCanonicalPipelineRequestObjectV0(
  request: CanonicalPipelineRequestV0,
  options: CanonicalPipelineRunOptionsV0 = {},
): CanonicalPipelineReportV0 {
  validateCanonicalPipelineRequestV0(request);
  const dir = mkdtempSync(path.join(tmpdir(), "aura-sdk-v0-ts-canonical-pipeline-"));
  try {
    const requestPath = path.join(dir, "canonical_pipeline_request.json");
    writeCanonicalPipelineRequestFileV0(requestPath, request);
    return runCanonicalPipelineV0(requestPath, options);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function scenarioReportFromCanonicalPipelineReportV0(
  report: CanonicalPipelineReportV0,
): ScenarioReportV0 {
  return {
    fixtureName: report.fixtureName,
    expectedResult: report.expectedResult,
    actualResult: report.actualResult,
    preStateRoot: report.preStateRoot,
    postStateRoot: report.executedPostStateRoot,
    transitionBindingHash: report.publicInputs?.transitionBindingHash ?? null,
  };
}

function canonicalPipelineRequestFromBridgeOptionsV0(
  options: RustBridgeFlowOptionsV0,
): CanonicalPipelineRequestV0 {
  const requestKind =
    options.requestKind ??
    (options.batch.transactions.length === 0
      ? CanonicalPipelineRequestKindV0.Attestation
      : CanonicalPipelineRequestKindV0.Execution);
  const orderedAccounts = options.state.orderedAccounts();
  const ledger = options.ledger
    ? {
        ledgerPolicyVersion: options.ledger.ledgerPolicyVersion,
        payerAccountId: copyBytesV0(options.ledger.payerAccountId),
        totalSupply: options.ledger.totalSupply,
        burnedSupply: options.ledger.burnedSupply,
        accounts: options.ledger.accounts.map((account) => ({
          accountId: copyBytesV0(account.accountId),
          balance: account.balance,
        })),
      }
    : canonicalPipelineDefaultLedgerPolicyV0(orderedAccounts);
  const request: CanonicalPipelineRequestV0 = {
    pipelineSchemaVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0,
    pipelineId: LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0,
    fixtureName: options.fixtureName ?? "sdk_v0_temp_pipeline_request",
    proofSystem: normalizeProofSystemV0(options.proofSystem),
    economic: {
      economicPolicyVersion: LOCAL_CHAIN_CANONICAL_ECONOMIC_POLICY_VERSION_V0,
      requestKind,
      burnIntent: CanonicalPipelineBurnIntentV0.CanonicalReport,
      declaredFeeUnits: 0n,
    },
    accounting: {
      accountingPolicyVersion: LOCAL_CHAIN_CANONICAL_ACCOUNTING_POLICY_VERSION_V0,
      paymentIntent: CanonicalPipelinePaymentIntentV0.BurnToProduceCanonicalTruth,
      settlementIntent: CanonicalPipelineSettlementIntentV0.RecordCanonicalOutcome,
    },
    ledger,
    head: options.head ?? {
      settlementHeadVersion: LOCAL_CHAIN_CANONICAL_SETTLEMENT_HEAD_VERSION_V0,
      previousHeadHash: copyBytesV0(CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V0),
      headSequenceNumber: 1n,
    },
    walletBinding:
      options.walletBinding ?? canonicalPipelineDefaultWalletBindingV0(ledger),
    tokenAnchor: options.tokenAnchor ?? canonicalPipelineDefaultTokenAnchorV0(),
    attestation: options.attestation ?? null,
    state: options.state,
    rollupId: copyBytes32V0("rollupId", options.rollupId),
    batch: {
      batchNumber: toU64BigIntV0(options.batch.batchNumber, "batch.batchNumber"),
      parentBatchCommitment: copyBytes32V0(
        "batch.parentBatchCommitment",
        options.batch.parentBatchCommitment,
      ),
      transactions: options.batch.transactions.map(cloneTransferTxV0),
    },
    expectedResult: options.expectedResult ?? ScenarioResultV0.Accepted,
    tamperPublicInputs: options.tamperPublicInputs
      ? {
          byteOffset: options.tamperPublicInputs.byteOffset,
          xorWith: options.tamperPublicInputs.xorWith,
        }
      : null,
    tamperProofBindingDigest: options.tamperProofBindingDigest
      ? {
          byteOffset: options.tamperProofBindingDigest.byteOffset,
          xorWith: options.tamperProofBindingDigest.xorWith,
        }
      : null,
  };
  request.economic.declaredFeeUnits = computeCanonicalPipelineBurnUnitsV0(request);
  return request;
}

function canonicalPipelineRequestFromLegacyFixturesV0(
  genesisPath: string,
  scenarioPath: string,
  proofSystem: ProofSystemV0,
): CanonicalPipelineRequestV0 {
  const genesis = loadGenesisFixtureV0(genesisPath);
  const scenario = loadScenarioFixtureRecordV0(scenarioPath);
  const requestKind =
    scenario.batch.transactions.length === 0
      ? CanonicalPipelineRequestKindV0.Attestation
      : CanonicalPipelineRequestKindV0.Execution;
  const request: CanonicalPipelineRequestV0 = {
    pipelineSchemaVersion: LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0,
    pipelineId: LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0,
    fixtureName: scenario.fixtureName,
    proofSystem: normalizeProofSystemV0(proofSystem),
    economic: {
      economicPolicyVersion: LOCAL_CHAIN_CANONICAL_ECONOMIC_POLICY_VERSION_V0,
      requestKind,
      burnIntent: CanonicalPipelineBurnIntentV0.CanonicalReport,
      declaredFeeUnits: 0n,
    },
    accounting: {
      accountingPolicyVersion: LOCAL_CHAIN_CANONICAL_ACCOUNTING_POLICY_VERSION_V0,
      paymentIntent: CanonicalPipelinePaymentIntentV0.BurnToProduceCanonicalTruth,
      settlementIntent: CanonicalPipelineSettlementIntentV0.RecordCanonicalOutcome,
    },
    ledger: canonicalPipelineDefaultLedgerPolicyV0(genesis.state.orderedAccounts()),
    head: {
      settlementHeadVersion: LOCAL_CHAIN_CANONICAL_SETTLEMENT_HEAD_VERSION_V0,
      previousHeadHash: copyBytesV0(CANONICAL_PIPELINE_GENESIS_HEAD_HASH_V0),
      headSequenceNumber: 1n,
    },
    walletBinding: canonicalPipelineDefaultWalletBindingV0(
      canonicalPipelineDefaultLedgerPolicyV0(genesis.state.orderedAccounts()),
    ),
    tokenAnchor: canonicalPipelineDefaultTokenAnchorV0(),
    attestation: null,
    state: genesis.state,
    rollupId: genesis.rollupId,
    batch: scenario.batch,
    expectedResult: scenario.expectedResult,
    tamperPublicInputs: scenario.tamperPublicInputs,
    tamperProofBindingDigest: scenario.tamperProofBindingDigest,
  };
  request.economic.declaredFeeUnits = computeCanonicalPipelineBurnUnitsV0(request);
  validateCanonicalPipelineRequestV0(request);
  return request;
}

function loadScenarioFixtureRecordV0(filePath: string): {
  fixtureName: string;
  batch: BatchV0;
  expectedResult: ScenarioResultV0;
  tamperPublicInputs: { byteOffset: number; xorWith: number } | null;
  tamperProofBindingDigest: { byteOffset: number; xorWith: number } | null;
} {
  const parsed = parseJsonFileRecordV0(filePath, "scenario fixture");
  assertOnlyAllowedKeysV0(
    parsed,
    [
      "fixture_schema_version",
      "fixture_name",
      "batch_number",
      "parent_batch_commitment_hex",
      "transactions",
      "tamper_public_inputs",
      "tamper_proof_binding_digest",
      "expected_result",
    ],
    "scenario fixture",
  );
  const fixtureSchemaVersion = safeJsonU32V0(
    numberFieldV0(parsed, "fixture_schema_version", "scenario fixture"),
    "scenario.fixture_schema_version",
  );
  if (fixtureSchemaVersion !== LOCAL_CHAIN_SCENARIO_FIXTURE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported scenario fixture_schema_version: ${fixtureSchemaVersion}`,
    );
  }
  const fixtureName = stringFieldV0(parsed, "fixture_name", "scenario fixture");
  if (fixtureName.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "scenario fixture.fixture_name must not be empty",
    );
  }
  return {
    fixtureName,
    batch: {
      batchNumber: safeJsonU64V0(
        numberFieldV0(parsed, "batch_number", "scenario fixture"),
        "scenario.batch_number",
      ),
      parentBatchCommitment: bytesFromHexV0(
        stringFieldV0(parsed, "parent_batch_commitment_hex", "scenario fixture"),
      ),
      transactions: arrayFieldV0(parsed, "transactions", "scenario fixture").map((tx) => {
        const record = recordValueV0(tx, "scenario fixture transaction");
        assertOnlyAllowedKeysV0(
          record,
          ["sender_account_id_hex", "recipient_account_id_hex", "sender_nonce", "amount"],
          "scenario fixture transaction",
        );
        return transferTxV0(
          bytesFromHexV0(
            stringFieldV0(record, "sender_account_id_hex", "scenario fixture transaction"),
          ),
          bytesFromHexV0(
            stringFieldV0(record, "recipient_account_id_hex", "scenario fixture transaction"),
          ),
          safeJsonU64V0(
            numberFieldV0(record, "sender_nonce", "scenario fixture transaction"),
            "scenario.transactions[].sender_nonce",
          ),
          safeJsonU64V0(
            numberFieldV0(record, "amount", "scenario fixture transaction"),
            "scenario.transactions[].amount",
          ),
        );
      }),
    },
    expectedResult: parseRustExpectedResultV0(
      stringFieldV0(parsed, "expected_result", "scenario fixture"),
    ),
    tamperPublicInputs: parseOptionalTamperFieldV0(
      parsed,
      "tamper_public_inputs",
      "scenario fixture",
      PUBLIC_INPUT_SCHEMA_LEN_V0,
      "public input bytes",
    ),
    tamperProofBindingDigest: parseOptionalTamperFieldV0(
      parsed,
      "tamper_proof_binding_digest",
      "scenario fixture",
      HASH_LEN_V0,
      "proof binding digest",
    ),
  };
}

function canonicalPipelineAttestationClaimPayloadRecordForRustBridgeV0(
  claimPayload: CanonicalPipelineAttestationClaimPayloadV0,
): Record<string, unknown> {
  if ("expectedEvidenceRootDigest" in claimPayload) {
    return {
      expected_evidence_root_digest_hex: hexFromBytesV0(
        claimPayload.expectedEvidenceRootDigest,
      ),
    };
  }
  if ("expectedEvidenceDigest" in claimPayload) {
    return {
      target_label: claimPayload.targetLabel,
      expected_evidence_digest_hex: hexFromBytesV0(claimPayload.expectedEvidenceDigest),
    };
  }
  if ("expectedSubstringUtf8" in claimPayload) {
    return {
      target_label: claimPayload.targetLabel,
      expected_substring_utf8: claimPayload.expectedSubstringUtf8,
    };
  }
  return {
    target_label: claimPayload.targetLabel,
    field_path: [...claimPayload.fieldPath],
    expected_value_utf8: claimPayload.expectedValueUtf8,
  };
}

function writeCanonicalPipelineRequestFileV0(
  filePath: string,
  request: CanonicalPipelineRequestV0,
): void {
  validateCanonicalPipelineRequestV0(request);
  writeFileSync(
    filePath,
    JSON.stringify(
      {
        pipeline_schema_version: LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0,
        pipeline_id: LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0,
        fixture_name: request.fixtureName,
        proof_system: rustProofSystemV0(request.proofSystem),
        economic: {
          economic_policy_version: request.economic.economicPolicyVersion,
          request_kind: request.economic.requestKind,
          burn_intent: request.economic.burnIntent,
          declared_fee_units: numberFromU64ForRustBridgeV0(
            request.economic.declaredFeeUnits,
            "economic.declaredFeeUnits",
          ),
        },
        accounting: {
          accounting_policy_version: request.accounting.accountingPolicyVersion,
          payment_intent: request.accounting.paymentIntent,
          settlement_intent: request.accounting.settlementIntent,
        },
        ledger: {
          ledger_policy_version: request.ledger.ledgerPolicyVersion,
          payer_account_id_hex: hexFromBytesV0(request.ledger.payerAccountId),
          total_supply: numberFromU64ForRustBridgeV0(
            request.ledger.totalSupply,
            "ledger.totalSupply",
          ),
          burned_supply: numberFromU64ForRustBridgeV0(
            request.ledger.burnedSupply,
            "ledger.burnedSupply",
          ),
          accounts: request.ledger.accounts.map((account) => ({
            account_id_hex: hexFromBytesV0(account.accountId),
            balance: numberFromU64ForRustBridgeV0(account.balance, "ledger.account.balance"),
          })),
        },
        head: {
          settlement_head_version: request.head.settlementHeadVersion,
          previous_head_hash_hex: hexFromBytesV0(request.head.previousHeadHash),
          head_sequence_number: numberFromU64ForRustBridgeV0(
            request.head.headSequenceNumber,
            "head.headSequenceNumber",
          ),
        },
        wallet_binding: {
          wallet_binding_version: request.walletBinding.walletBindingVersion,
          account_id_hex: hexFromBytesV0(request.walletBinding.accountId),
          wallet_address: request.walletBinding.walletAddress,
        },
        token_anchor: {
          token_policy_version: request.tokenAnchor.tokenPolicyVersion,
          network_mode: request.tokenAnchor.networkMode,
          settlement_anchor_type: request.tokenAnchor.settlementAnchorType,
          external_balance_reference: request.tokenAnchor.externalBalanceReference
            ? {
                reference_id: request.tokenAnchor.externalBalanceReference.referenceId,
                observed_balance:
                  request.tokenAnchor.externalBalanceReference.observedBalance === null
                    ? undefined
                    : numberFromU64ForRustBridgeV0(
                        request.tokenAnchor.externalBalanceReference.observedBalance,
                        "tokenAnchor.externalBalanceReference.observedBalance",
                      ),
                observed_slot:
                  request.tokenAnchor.externalBalanceReference.observedSlot === null
                    ? undefined
                    : numberFromU64ForRustBridgeV0(
                        request.tokenAnchor.externalBalanceReference.observedSlot,
                        "tokenAnchor.externalBalanceReference.observedSlot",
                      ),
                connected: request.tokenAnchor.externalBalanceReference.connected,
              }
            : undefined,
          enforce_external_match: request.tokenAnchor.enforceExternalMatch,
          expected_external_balance:
            request.tokenAnchor.expectedExternalBalance === null
              ? undefined
              : numberFromU64ForRustBridgeV0(
                  request.tokenAnchor.expectedExternalBalance,
                  "tokenAnchor.expectedExternalBalance",
                ),
        },
        attestation: request.attestation
          ? {
              attestation_schema_version: request.attestation.attestationSchemaVersion,
              attestation_scope: request.attestation.attestationScope,
              attestation_proof_kind: request.attestation.attestationProofKind,
              normalization_policy_version: request.attestation.normalizationPolicyVersion,
              attestation_constraints: {
                require_unique_labels: request.attestation.attestationConstraints.requireUniqueLabels,
                max_evidence_items: numberFromU64ForRustBridgeV0(
                  request.attestation.attestationConstraints.maxEvidenceItems,
                  "attestation.attestationConstraints.maxEvidenceItems",
                ),
                max_total_normalized_bytes: numberFromU64ForRustBridgeV0(
                  request.attestation.attestationConstraints.maxTotalNormalizedBytes,
                  "attestation.attestationConstraints.maxTotalNormalizedBytes",
                ),
              },
              claim: {
                claim_kind: request.attestation.claim.claimKind,
                claim_payload: canonicalPipelineAttestationClaimPayloadRecordForRustBridgeV0(
                  request.attestation.claim.claimPayload,
                ),
              },
              evidence_items: request.attestation.evidenceItems.map((item) => ({
                label: item.label,
                evidence_kind: item.evidenceKind,
                evidence_payload: {
                  payload_utf8: item.evidencePayload.payloadUtf8,
                },
                provenance: {
                  provenance_policy_version: item.provenance.provenancePolicyVersion,
                  provenance_type: item.provenance.provenanceType,
                  source_type: item.provenance.sourceType,
                  source_identifier: item.provenance.sourceIdentifier,
                  signature: item.provenance.signature
                    ? {
                        signer_public_key_hex: hexFromBytesV0(
                          item.provenance.signature.signerPublicKey,
                        ),
                        signature_hex: hexFromBytesV0(item.provenance.signature.signature),
                      }
                    : undefined,
                  timestamp_unix_seconds:
                    item.provenance.timestampUnixSeconds === null
                      ? undefined
                      : numberFromU64ForRustBridgeV0(
                          item.provenance.timestampUnixSeconds,
                          "attestation.provenance.timestampUnixSeconds",
                        ),
                },
              })),
              tamper_stark_public_inputs_digest:
                request.attestation.tamperStarkPublicInputsDigest
                  ? {
                      byte_offset: request.attestation.tamperStarkPublicInputsDigest.byteOffset,
                      xor_with: request.attestation.tamperStarkPublicInputsDigest.xorWith,
                    }
                  : undefined,
              tamper_stark_proof_bytes: request.attestation.tamperStarkProofBytes
                ? {
                    byte_offset: request.attestation.tamperStarkProofBytes.byteOffset,
                    xor_with: request.attestation.tamperStarkProofBytes.xorWith,
                  }
                : undefined,
            }
          : undefined,
        genesis: {
          rollup_id_hex: hexFromBytesV0(request.rollupId),
          accounts: request.state.orderedAccounts().map((account) => ({
            account_id_hex: hexFromBytesV0(account.accountId),
            balance: numberFromU64ForRustBridgeV0(account.balance, "account.balance"),
            nonce: numberFromU64ForRustBridgeV0(account.nonce, "account.nonce"),
          })),
        },
        batch: {
          batch_number: numberFromU64ForRustBridgeV0(
            request.batch.batchNumber,
            "batch.batchNumber",
          ),
          parent_batch_commitment_hex: hexFromBytesV0(request.batch.parentBatchCommitment),
          transactions: request.batch.transactions.map((tx) => ({
            sender_account_id_hex: hexFromBytesV0(tx.senderAccountId),
            recipient_account_id_hex: hexFromBytesV0(tx.recipientAccountId),
            sender_nonce: numberFromU64ForRustBridgeV0(
              tx.senderNonce,
              "transaction.senderNonce",
            ),
            amount: numberFromU64ForRustBridgeV0(tx.amount, "transaction.amount"),
          })),
        },
        tamper_public_inputs: request.tamperPublicInputs
          ? {
              byte_offset: request.tamperPublicInputs.byteOffset,
              xor_with: request.tamperPublicInputs.xorWith,
            }
          : undefined,
        tamper_proof_binding_digest: request.tamperProofBindingDigest
          ? {
              byte_offset: request.tamperProofBindingDigest.byteOffset,
              xor_with: request.tamperProofBindingDigest.xorWith,
            }
          : undefined,
        expected_result: rustExpectedResultV0(request.expectedResult),
      },
      null,
      2,
    ),
    "utf8",
  );
}

function validateRustBridgeFlowOptionsV0(options: RustBridgeFlowOptionsV0): void {
  normalizeProofSystemV0(options.proofSystem);
  if (options.requestKind !== undefined) {
    parseCanonicalPipelineRequestKindV0(options.requestKind, "rust bridge options");
  }
  void rustExpectedResultV0(options.expectedResult ?? ScenarioResultV0.Accepted);
  if (!(options.state instanceof StateV0)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "state must be a StateV0 instance",
    );
  }
  if (typeof options.batch !== "object" || options.batch === null) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "batch must be a batch-like object",
    );
  }
  copyBytes32V0("rollupId", options.rollupId);
  toU64BigIntV0(options.batch.batchNumber, "batch.batchNumber");
  copyBytes32V0("batch.parentBatchCommitment", options.batch.parentBatchCommitment);
  if (options.fixtureName !== undefined && options.fixtureName.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "fixtureName must not be empty when provided",
    );
  }
  if (
    options.headStatePath !== undefined &&
    options.headStatePath.trim().length === 0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "headStatePath must not be empty when provided",
    );
  }
  if (options.stateless !== undefined && typeof options.stateless !== "boolean") {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "stateless must be a boolean when provided",
    );
  }
  if (!Array.isArray(options.batch.transactions)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "batch.transactions must be an array",
    );
  }
  for (const [index, tx] of options.batch.transactions.entries()) {
    if (tx.txVersion !== TRANSFER_TX_VERSION_V0) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `batch.transactions[${index}].txVersion must be ${TRANSFER_TX_VERSION_V0}`,
      );
    }
    copyBytes32V0(`batch.transactions[${index}].senderAccountId`, tx.senderAccountId);
    copyBytes32V0(`batch.transactions[${index}].recipientAccountId`, tx.recipientAccountId);
    toU64BigIntV0(tx.senderNonce, `batch.transactions[${index}].senderNonce`);
    toU64BigIntV0(tx.amount, `batch.transactions[${index}].amount`);
  }
  if (
    options.tamperPublicInputs &&
    (!Number.isSafeInteger(options.tamperPublicInputs.byteOffset) ||
      options.tamperPublicInputs.byteOffset < 0 ||
      !Number.isSafeInteger(options.tamperPublicInputs.xorWith) ||
      options.tamperPublicInputs.xorWith < 0 ||
      options.tamperPublicInputs.xorWith > 0xff)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "tamperPublicInputs must use non-negative safe-integer offsets and u8 xor values",
    );
  }
  if (
    options.tamperProofBindingDigest &&
    (!Number.isSafeInteger(options.tamperProofBindingDigest.byteOffset) ||
      options.tamperProofBindingDigest.byteOffset < 0 ||
      !Number.isSafeInteger(options.tamperProofBindingDigest.xorWith) ||
      options.tamperProofBindingDigest.xorWith < 0 ||
      options.tamperProofBindingDigest.xorWith > 0xff)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "tamperProofBindingDigest must use non-negative safe-integer offsets and u8 xor values",
    );
  }
}

function validateCanonicalPipelineRequestV0(request: CanonicalPipelineRequestV0): void {
  if (request.pipelineSchemaVersion !== LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline schema version: ${request.pipelineSchemaVersion}`,
    );
  }
  if (request.pipelineId !== LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline id: ${request.pipelineId}`,
    );
  }
  if (request.fixtureName.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.fixtureName must not be empty",
    );
  }
  normalizeProofSystemV0(request.proofSystem);
  if (
    request.economic.economicPolicyVersion !== LOCAL_CHAIN_CANONICAL_ECONOMIC_POLICY_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline economic_policy_version: expected ${LOCAL_CHAIN_CANONICAL_ECONOMIC_POLICY_VERSION_V0}, got ${request.economic.economicPolicyVersion}`,
    );
  }
  if (
    request.accounting.accountingPolicyVersion !==
    LOCAL_CHAIN_CANONICAL_ACCOUNTING_POLICY_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline accounting_policy_version: expected ${LOCAL_CHAIN_CANONICAL_ACCOUNTING_POLICY_VERSION_V0}, got ${request.accounting.accountingPolicyVersion}`,
    );
  }
  if (request.ledger.ledgerPolicyVersion !== LOCAL_CHAIN_CANONICAL_LEDGER_POLICY_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline ledger_policy_version: expected ${LOCAL_CHAIN_CANONICAL_LEDGER_POLICY_VERSION_V0}, got ${request.ledger.ledgerPolicyVersion}`,
    );
  }
  if (request.head.settlementHeadVersion !== LOCAL_CHAIN_CANONICAL_SETTLEMENT_HEAD_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline settlement_head_version: expected ${LOCAL_CHAIN_CANONICAL_SETTLEMENT_HEAD_VERSION_V0}, got ${request.head.settlementHeadVersion}`,
    );
  }
  if (request.head.headSequenceNumber === 0n) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline head.headSequenceNumber must start at 1",
    );
  }
  copyBytes32V0("canonical pipeline head.previousHeadHash", request.head.previousHeadHash);
  if (
    request.walletBinding.walletBindingVersion !==
    LOCAL_CHAIN_CANONICAL_WALLET_BINDING_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline wallet_binding_version: expected ${LOCAL_CHAIN_CANONICAL_WALLET_BINDING_VERSION_V0}, got ${request.walletBinding.walletBindingVersion}`,
    );
  }
  if (!walletAddressIsBase58V0(request.walletBinding.walletAddress)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline walletBinding.walletAddress must be a non-empty base58 string",
    );
  }
  if (request.tokenAnchor.tokenPolicyVersion !== LOCAL_CHAIN_CANONICAL_TOKEN_POLICY_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `unsupported canonical pipeline token_policy_version: expected ${LOCAL_CHAIN_CANONICAL_TOKEN_POLICY_VERSION_V0}, got ${request.tokenAnchor.tokenPolicyVersion}`,
    );
  }
  parseCanonicalPipelineNetworkModeV0(
    request.tokenAnchor.networkMode,
    "canonical pipeline request.tokenAnchor",
  );
  parseCanonicalPipelineSettlementAnchorTypeV0(
    request.tokenAnchor.settlementAnchorType,
    "canonical pipeline request.tokenAnchor",
  );
  if (
    request.tokenAnchor.networkMode === CanonicalPipelineNetworkModeV0.Local &&
    request.tokenAnchor.settlementAnchorType !== CanonicalPipelineSettlementAnchorTypeV0.Local
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline local networkMode requires settlementAnchorType local",
    );
  }
  if (
    request.tokenAnchor.networkMode === CanonicalPipelineNetworkModeV0.Bridged &&
    request.tokenAnchor.settlementAnchorType === CanonicalPipelineSettlementAnchorTypeV0.Local
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline bridged networkMode must not use settlementAnchorType local",
    );
  }
  if (
    request.tokenAnchor.enforceExternalMatch &&
    request.tokenAnchor.expectedExternalBalance === null
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline tokenAnchor.expectedExternalBalance is required when enforceExternalMatch is true",
    );
  }
  if (
    request.tokenAnchor.externalBalanceReference !== null &&
    request.tokenAnchor.externalBalanceReference.referenceId.trim().length === 0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline tokenAnchor.externalBalanceReference.referenceId must not be empty",
    );
  }
  parseCanonicalPipelineRequestKindV0(
    request.economic.requestKind,
    "canonical pipeline request.economic",
  );
  parseCanonicalPipelineBurnIntentV0(
    request.economic.burnIntent,
    "canonical pipeline request.economic",
  );
  parseCanonicalPipelinePaymentIntentV0(
    request.accounting.paymentIntent,
    "canonical pipeline request.accounting",
  );
  parseCanonicalPipelineSettlementIntentV0(
    request.accounting.settlementIntent,
    "canonical pipeline request.accounting",
  );
  copyBytes32V0("canonical pipeline ledger.payerAccountId", request.ledger.payerAccountId);
  toU64BigIntV0(request.ledger.totalSupply, "canonical pipeline ledger.totalSupply");
  toU64BigIntV0(request.ledger.burnedSupply, "canonical pipeline ledger.burnedSupply");
  if (
    request.accounting.paymentIntent !==
    CanonicalPipelinePaymentIntentV0.BurnToProduceCanonicalTruth
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline payment_intent must be burn_to_produce_canonical_truth",
    );
  }
  if (request.economic.burnIntent !== CanonicalPipelineBurnIntentV0.CanonicalReport) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline burn_intent must be canonical_report",
    );
  }
  if (
    request.accounting.settlementIntent !==
    CanonicalPipelineSettlementIntentV0.RecordCanonicalOutcome
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline settlement_intent must be record_canonical_outcome",
    );
  }
  if (!(request.state instanceof StateV0)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.state must be a StateV0 instance",
    );
  }
  if (request.ledger.accounts.length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline ledger.accounts must not be empty",
    );
  }
  let payerFound = false;
  for (let index = 0; index < request.ledger.accounts.length; index += 1) {
    const account = request.ledger.accounts[index];
    copyBytes32V0(`canonical pipeline ledger.accounts[${index}].accountId`, account.accountId);
    toU64BigIntV0(account.balance, `canonical pipeline ledger.accounts[${index}].balance`);
    if (index > 0) {
      const previous = request.ledger.accounts[index - 1];
      if (compareBytesV0(account.accountId, previous.accountId) <= 0) {
        throw new AuraTypescriptSdkErrorV0(
          "InvalidFixture",
          `canonical pipeline ledger.accounts must be strictly ordered and duplicate-free at index ${index}`,
        );
      }
    }
    if (bytesEqualV0(account.accountId, request.ledger.payerAccountId)) {
      payerFound = true;
    }
  }
  if (!payerFound) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline ledger payerAccountId must exist in ledger.accounts",
    );
  }
  const ledgerTotalBalance = canonicalPipelineLedgerTotalBalanceV0(request.ledger.accounts);
  if (ledgerTotalBalance + request.ledger.burnedSupply !== request.ledger.totalSupply) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `canonical pipeline ledger totalSupply must equal sum(accounts.balance) + burnedSupply: expected ${ledgerTotalBalance + request.ledger.burnedSupply}, got ${request.ledger.totalSupply}`,
    );
  }
  canonicalPipelineLedgerCirculatingSupplyV0(
    request.ledger.totalSupply,
    request.ledger.burnedSupply,
  );
  copyBytes32V0("canonical pipeline request.rollupId", request.rollupId);
  toU64BigIntV0(request.batch.batchNumber, "canonical pipeline request.batch.batchNumber");
  copyBytes32V0(
    "canonical pipeline request.batch.parentBatchCommitment",
    request.batch.parentBatchCommitment,
  );
  for (const [index, tx] of request.batch.transactions.entries()) {
    if (tx.txVersion !== TRANSFER_TX_VERSION_V0) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        `canonical pipeline request.batch.transactions[${index}].txVersion must be ${TRANSFER_TX_VERSION_V0}`,
      );
    }
    copyBytes32V0(
      `canonical pipeline request.batch.transactions[${index}].senderAccountId`,
      tx.senderAccountId,
    );
    copyBytes32V0(
      `canonical pipeline request.batch.transactions[${index}].recipientAccountId`,
      tx.recipientAccountId,
    );
    toU64BigIntV0(
      tx.senderNonce,
      `canonical pipeline request.batch.transactions[${index}].senderNonce`,
    );
    toU64BigIntV0(
      tx.amount,
      `canonical pipeline request.batch.transactions[${index}].amount`,
    );
  }
  if (
    request.economic.requestKind === CanonicalPipelineRequestKindV0.Execution &&
    request.batch.transactions.length === 0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.economic.requestKind execution requires at least one transaction",
    );
  }
  if (
    request.economic.requestKind === CanonicalPipelineRequestKindV0.Execution &&
    request.attestation !== null
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request_kind execution must not carry attestation material",
    );
  }
  if (
    request.economic.requestKind === CanonicalPipelineRequestKindV0.Attestation &&
    request.attestation === null
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request_kind attestation requires attestation material",
    );
  }
  if (
    request.economic.requestKind === CanonicalPipelineRequestKindV0.Attestation &&
    request.batch.transactions.length !== 0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.economic.requestKind attestation requires zero transactions",
    );
  }
  if (request.attestation !== null) {
    parseCanonicalPipelineAttestationProofKindV0(
      request.attestation.attestationProofKind,
      "canonical pipeline request.attestation",
    );
    if (
      request.attestation.attestationScope !==
      CanonicalPipelineAttestationScopeV0.ClaimConsistencyWithProvidedEvidenceOnly
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        "canonical pipeline attestation_scope must be claim_consistency_with_provided_evidence_only",
      );
    }
    if (
      request.attestation.tamperStarkPublicInputsDigest &&
      (request.attestation.tamperStarkPublicInputsDigest.byteOffset < 0 ||
        !Number.isSafeInteger(request.attestation.tamperStarkPublicInputsDigest.byteOffset) ||
        request.attestation.tamperStarkPublicInputsDigest.byteOffset >= HASH_LEN_V0 ||
        request.attestation.tamperStarkPublicInputsDigest.xorWith < 0 ||
        request.attestation.tamperStarkPublicInputsDigest.xorWith > 0xff ||
        !Number.isSafeInteger(request.attestation.tamperStarkPublicInputsDigest.xorWith))
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        "canonical pipeline request.attestation.tamperStarkPublicInputsDigest must target a valid digest byte",
      );
    }
    if (
      request.attestation.tamperStarkProofBytes &&
      (request.attestation.tamperStarkProofBytes.byteOffset < 0 ||
        !Number.isSafeInteger(request.attestation.tamperStarkProofBytes.byteOffset) ||
        request.attestation.tamperStarkProofBytes.xorWith < 0 ||
        request.attestation.tamperStarkProofBytes.xorWith > 0xff ||
        !Number.isSafeInteger(request.attestation.tamperStarkProofBytes.xorWith))
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "InvalidFixture",
        "canonical pipeline request.attestation.tamperStarkProofBytes must use a non-negative safe-integer offset and u8 xor value",
      );
    }
    canonicalPipelinePrepareAttestationV0(request.attestation);
  }
  void rustExpectedResultV0(request.expectedResult);
  if (
    request.tamperPublicInputs &&
    (request.tamperPublicInputs.byteOffset < 0 ||
      !Number.isSafeInteger(request.tamperPublicInputs.byteOffset) ||
      request.tamperPublicInputs.byteOffset >= PUBLIC_INPUT_SCHEMA_LEN_V0 ||
      request.tamperPublicInputs.xorWith < 0 ||
      request.tamperPublicInputs.xorWith > 0xff ||
      !Number.isSafeInteger(request.tamperPublicInputs.xorWith))
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.tamperPublicInputs must target a valid public-input byte",
    );
  }
  if (
    request.tamperProofBindingDigest &&
    (request.tamperProofBindingDigest.byteOffset < 0 ||
      !Number.isSafeInteger(request.tamperProofBindingDigest.byteOffset) ||
      request.tamperProofBindingDigest.byteOffset >= HASH_LEN_V0 ||
      request.tamperProofBindingDigest.xorWith < 0 ||
      request.tamperProofBindingDigest.xorWith > 0xff ||
      !Number.isSafeInteger(request.tamperProofBindingDigest.xorWith))
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      "canonical pipeline request.tamperProofBindingDigest must target a valid digest byte",
    );
  }
  const computedBurnUnits = computeCanonicalPipelineBurnUnitsV0(request);
  if (request.economic.declaredFeeUnits !== computedBurnUnits) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `canonical pipeline request.economic.declaredFeeUnits must equal computed burn units: expected ${computedBurnUnits}, got ${request.economic.declaredFeeUnits}`,
    );
  }
  if (canonicalPipelineLedgerPayerAccountV0(request).balance < computedBurnUnits) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `canonical pipeline ledger payer balance is insufficient for computed burn: balance ${canonicalPipelineLedgerPayerAccountV0(request).balance}, required ${computedBurnUnits}`,
    );
  }
}

function assertCanonicalPipelineReportMatchesRequestV0(
  report: CanonicalPipelineReportV0,
  request: CanonicalPipelineRequestV0,
): void {
  const expectedRequestBindingHash = canonicalPipelineRequestBindingHashV0(request);
  const expectedGenesisAccountsDigest = canonicalPipelineGenesisAccountsDigestV0(request);
  const expectedLedgerAccountsDigest = canonicalPipelineLedgerAccountsDigestV0(request.ledger);
  const expectedTransactionsDigest = canonicalPipelineTransactionsDigestV0(request);
  if (!bytesEqualV0(report.requestAudit.requestBindingHash, expectedRequestBindingHash)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.requestAudit.requestBindingHash does not match the request",
    );
  }
  if (!bytesEqualV0(report.requestAudit.genesisAccountsDigest, expectedGenesisAccountsDigest)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.requestAudit.genesisAccountsDigest does not match the request",
    );
  }
  if (!bytesEqualV0(report.requestAudit.ledgerAccountsDigest, expectedLedgerAccountsDigest)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.requestAudit.ledgerAccountsDigest does not match the request",
    );
  }
  if (!bytesEqualV0(report.requestAudit.transactionsDigest, expectedTransactionsDigest)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.requestAudit.transactionsDigest does not match the request",
    );
  }
  if (!bytesEqualV0(report.requestAudit.rollupId, request.rollupId)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.requestAudit.rollupId does not match the request",
    );
  }
  if (report.requestAudit.genesisAccountCount !== BigInt(request.state.orderedAccounts().length)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.requestAudit.genesisAccountCount does not match the request",
    );
  }
  if (
    report.requestAudit.ledgerAccountCount !== BigInt(request.ledger.accounts.length) ||
    !bytesEqualV0(
      report.requestAudit.ledgerPayerAccountId,
      request.ledger.payerAccountId,
    ) ||
    report.requestAudit.ledgerTotalSupply !== request.ledger.totalSupply ||
    report.requestAudit.ledgerBurnedSupply !== request.ledger.burnedSupply ||
    report.requestAudit.batchNumber !== request.batch.batchNumber ||
    report.requestAudit.txCount !== BigInt(request.batch.transactions.length) ||
    !bytesEqualV0(
      report.requestAudit.parentBatchCommitment,
      request.batch.parentBatchCommitment,
    ) ||
    !canonicalPipelineTamperEqualV0(
      report.requestAudit.tamperPublicInputs,
      request.tamperPublicInputs ?? null,
    ) ||
    !canonicalPipelineTamperEqualV0(
      report.requestAudit.tamperProofBindingDigest,
      request.tamperProofBindingDigest ?? null,
    ) ||
    !canonicalPipelineTamperEqualV0(
      report.requestAudit.tamperAttestationStarkPublicInputsDigest,
      request.attestation?.tamperStarkPublicInputsDigest ?? null,
    ) ||
    !canonicalPipelineTamperEqualV0(
      report.requestAudit.tamperAttestationStarkProofBytes,
      request.attestation?.tamperStarkProofBytes ?? null,
    ) ||
    report.expectedResult !== request.expectedResult ||
    report.proofSystem !== request.proofSystem
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report request audit drifted from the request",
    );
  }
  if (
    !bytesEqualV0(
      report.headTransitionSummary.previousHeadHash,
      request.head.previousHeadHash,
    ) ||
    report.headTransitionSummary.headSequenceNumber !== request.head.headSequenceNumber ||
    report.headTransitionSummary.settlementHeadVersion !== request.head.settlementHeadVersion ||
    report.walletBindingSummary.walletBindingVersion !== request.walletBinding.walletBindingVersion ||
    !bytesEqualV0(report.walletBindingSummary.accountId, request.walletBinding.accountId) ||
    report.walletBindingSummary.walletAddress !== request.walletBinding.walletAddress ||
    report.tokenAnchorSummary.tokenPolicyVersion !== request.tokenAnchor.tokenPolicyVersion ||
    report.tokenAnchorSummary.networkMode !== request.tokenAnchor.networkMode ||
    report.tokenAnchorSummary.settlementAnchorType !==
      request.tokenAnchor.settlementAnchorType ||
    !canonicalPipelineExternalBalanceReferenceEqualV0(
      report.tokenAnchorSummary.externalBalanceReference,
      request.tokenAnchor.externalBalanceReference,
    ) ||
    report.tokenAnchorSummary.expectedExternalBalance !==
      request.tokenAnchor.expectedExternalBalance
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline head, wallet binding, or token anchor drifted from the request",
    );
  }
}

function assertCanonicalPipelineReportShapeV0(report: CanonicalPipelineReportV0): void {
  if (report.pipelineSchemaVersion !== LOCAL_CHAIN_CANONICAL_PIPELINE_SCHEMA_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline schema version: ${report.pipelineSchemaVersion}`,
    );
  }
  if (report.pipelineId !== LOCAL_CHAIN_CANONICAL_PIPELINE_ID_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline id: ${report.pipelineId}`,
    );
  }
  if (report.burnSummary.burnPolicyVersion !== LOCAL_CHAIN_CANONICAL_BURN_POLICY_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline burn policy version: ${report.burnSummary.burnPolicyVersion}`,
    );
  }
  if (
    report.accountingSummary.accountingPolicyVersion !==
    LOCAL_CHAIN_CANONICAL_ACCOUNTING_POLICY_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline accounting policy version: ${report.accountingSummary.accountingPolicyVersion}`,
    );
  }
  if (report.ledgerSummary.ledgerPolicyVersion !== LOCAL_CHAIN_CANONICAL_LEDGER_POLICY_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline ledger policy version: ${report.ledgerSummary.ledgerPolicyVersion}`,
    );
  }
  if (
    report.headTransitionSummary.settlementHeadVersion !==
    LOCAL_CHAIN_CANONICAL_SETTLEMENT_HEAD_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline settlement head version: ${report.headTransitionSummary.settlementHeadVersion}`,
    );
  }
  if (
    report.walletBindingSummary.walletBindingVersion !==
    LOCAL_CHAIN_CANONICAL_WALLET_BINDING_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline wallet binding version: ${report.walletBindingSummary.walletBindingVersion}`,
    );
  }
  if (report.tokenAnchorSummary.tokenPolicyVersion !== LOCAL_CHAIN_CANONICAL_TOKEN_POLICY_VERSION_V0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline token policy version: ${report.tokenAnchorSummary.tokenPolicyVersion}`,
    );
  }
  if (report.fixtureName.trim().length === 0) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.fixtureName must not be empty",
    );
  }
  if (
    report.genesisAccounts.materialVersion !==
    LOCAL_CHAIN_CANONICAL_PIPELINE_GENESIS_ACCOUNTS_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline genesisAccounts material version: ${report.genesisAccounts.materialVersion}`,
    );
  }
  if (
    report.ledgerAccounts.materialVersion !==
    LOCAL_CHAIN_CANONICAL_PIPELINE_LEDGER_ACCOUNTS_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline ledgerAccounts material version: ${report.ledgerAccounts.materialVersion}`,
    );
  }
  if (
    report.ledgerSummary.ledgerStateCommitment.commitmentVersion !==
    LOCAL_CHAIN_CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline ledgerStateCommitment version: ${report.ledgerSummary.ledgerStateCommitment.commitmentVersion}`,
    );
  }
  if (
    report.commitmentExpansions.transactions.expansionVersion !==
    LOCAL_CHAIN_CANONICAL_PIPELINE_TRANSACTIONS_EXPANSION_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline transactions expansion version: ${report.commitmentExpansions.transactions.expansionVersion}`,
    );
  }
  if (
    report.commitmentExpansions.batchContext.expansionVersion !==
    LOCAL_CHAIN_CANONICAL_PIPELINE_BATCH_CONTEXT_EXPANSION_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline batchContext expansion version: ${report.commitmentExpansions.batchContext.expansionVersion}`,
    );
  }
  if (
    report.commitmentExpansions.feeSummary.expansionVersion !==
    LOCAL_CHAIN_CANONICAL_PIPELINE_FEE_SUMMARY_EXPANSION_VERSION_V0
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      `unsupported canonical pipeline feeSummary expansion version: ${report.commitmentExpansions.feeSummary.expansionVersion}`,
    );
  }
  if (report.commitmentExpansions.outcomes !== null) {
    if (
      report.commitmentExpansions.outcomes.expansionVersion !==
      LOCAL_CHAIN_CANONICAL_PIPELINE_OUTCOMES_EXPANSION_VERSION_V0
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        `unsupported canonical pipeline outcomes expansion version: ${report.commitmentExpansions.outcomes.expansionVersion}`,
      );
    }
    assertCanonicalPipelineOutcomesExpansionShapeV0(report.commitmentExpansions.outcomes);
  }

  const reconstructedRequest = canonicalPipelineRequestFromReportV0(report);
  const preparedAttestation =
    reconstructedRequest.attestation === null
      ? null
      : canonicalPipelinePrepareAttestationV0(reconstructedRequest.attestation);
  const expectedAttestationSummary = canonicalPipelineAttestationSummaryFromRequestV0(
    reconstructedRequest,
    report.actualResult,
  );
  const expectedProvenanceSummary =
    preparedAttestation === null ? null : preparedAttestation.provenanceSummary;
  const expectedAttestationProofSummary = canonicalPipelineAttestationProofSummaryFromRequestV0(
    reconstructedRequest,
    preparedAttestation,
    report,
  );
  const expectedWalletBindingSummary =
    canonicalPipelineWalletBindingSummaryFromRequestV0(reconstructedRequest);
  const expectedTokenAnchorSummary =
    canonicalPipelineTokenAnchorSummaryFromRequestV0(reconstructedRequest);
  const orderedAccounts = reconstructedRequest.state.orderedAccounts();
  if (!accountListsEqualV0(report.genesisAccounts.orderedAccounts, orderedAccounts)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline genesisAccounts must be duplicate-free and strictly ordered",
    );
  }
  if (
    !canonicalPipelineLedgerAccountListsEqualV0(
      report.ledgerAccounts.orderedAccounts,
      reconstructedRequest.ledger.accounts,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline ledgerAccounts must be duplicate-free and strictly ordered",
    );
  }
  assertCanonicalPipelineReportMatchesRequestV0(report, reconstructedRequest);
  const expectedBurnSummary = canonicalPipelineBurnSummaryFromRequestV0(reconstructedRequest);
  const expectedRequestBindingHash = canonicalPipelineRequestBindingHashV0(reconstructedRequest);
  const { burnRecord: expectedBurnRecord, ledgerSummary: expectedLedgerSummary } =
    canonicalPipelineLedgerTransitionFromRequestV0(
      reconstructedRequest,
      expectedBurnSummary,
      expectedRequestBindingHash,
    );
  if (!canonicalPipelineBurnSummaryEqualV0(report.burnSummary, expectedBurnSummary)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline burnSummary contradicts the canonical burn policy",
    );
  }
  if (
    report.burnSummary.consumedBurnUnits !== report.burnSummary.computedBurnUnits ||
    !canonicalPipelineBurnPolicyEqualV0(
      report.burnSummary.burnPolicy,
      canonicalPipelineBurnPolicyV0(),
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline burnSummary must pin the canonical burn policy and consumed burn amount",
    );
  }
  if (
    !report.burnSummary.requestDeclaresCorrectBurn ||
    !report.burnSummary.recomputedBurnMatchesReport ||
    !report.burnSummary.burnConsumed ||
    !canonicalPipelineBurnFailureSemanticsEqualV0(
      report.burnSummary.failureSemantics,
      canonicalPipelineBurnFailureSemanticsV0(),
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline burnSummary must pin full-burn fail-closed semantics",
    );
  }
  if (!canonicalPipelineLedgerSummaryEqualV0(report.ledgerSummary, expectedLedgerSummary)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline ledgerSummary contradicts the canonical ledger burn transition",
    );
  }
  if (
    !report.ledgerSummary.ledgerConsistentWithRequest ||
    !report.ledgerSummary.ledgerConsistentWithBurn ||
    !report.ledgerSummary.ledgerConsistentWithSupply
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline ledgerSummary must pin the canonical ledger burn invariants",
    );
  }
  if (
    report.statusExplanation.requestKind !== reconstructedRequest.economic.requestKind ||
    report.statusExplanation.truthArtifactKind !==
      canonicalPipelineTruthArtifactKindFromRequestKindV0(
        reconstructedRequest.economic.requestKind,
      ) ||
    report.statusExplanation.finalStatus !== report.actualResult
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline statusExplanation contradicts request kind or actualResult",
    );
  }
  if (!canonicalPipelineAttestationSummaryEqualV0(report.attestationSummary, expectedAttestationSummary)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline attestationSummary contradicts the embedded attestation material",
    );
  }
  if (
    !canonicalPipelineWalletBindingSummaryEqualV0(
      report.walletBindingSummary,
      expectedWalletBindingSummary,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline walletBindingSummary contradicts the embedded wallet binding",
    );
  }
  if (
    !canonicalPipelineTokenAnchorSummaryEqualV0(
      report.tokenAnchorSummary,
      expectedTokenAnchorSummary,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline tokenAnchorSummary contradicts the embedded token anchor",
    );
  }
  if (
    report.tokenAnchorSummary.anchorVerificationStatus ===
      CanonicalPipelineExternalAnchorVerificationStatusV0.Rejected &&
    report.actualResult === ScenarioResultV0.Accepted
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline accepted reports must not carry a rejected external token anchor verification",
    );
  }
  if (
    !canonicalPipelineProvenanceSummaryEqualV0(
      report.provenanceSummary,
      expectedProvenanceSummary,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline provenanceSummary contradicts the embedded provenance material",
    );
  }
  if (
    !canonicalPipelineAttestationProofSummaryEqualV0(
      report.attestationProofSummary,
      expectedAttestationProofSummary,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline attestationProofSummary contradicts the embedded attestation proof contract",
    );
  }
  if (report.attestationProofSummary !== null) {
    if (
      report.attestationProofSummary.proofKind === CanonicalPipelineAttestationProofKindV0.Mock &&
      (report.attestationProofSummary.mockPolicyVersion !==
        LOCAL_CHAIN_CANONICAL_ATTESTATION_PROOF_MOCK_POLICY_VERSION_V0 ||
        report.attestationProofSummary.starkPolicyVersion !== null ||
        report.attestationProofSummary.starkPublicInputsDigest !== null ||
        report.attestationProofSummary.starkProofBytesDigest !== null ||
        report.attestationProofSummary.starkProofBindingDigest !== null)
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "mock attestation proof summaries must pin only the canonical mock proof policy",
      );
    }
    if (
      report.attestationProofSummary.proofKind === CanonicalPipelineAttestationProofKindV0.Stark &&
      (report.attestationProofSummary.mockPolicyVersion !== null ||
        report.attestationProofSummary.starkPolicyVersion !==
          LOCAL_CHAIN_CANONICAL_STARK_POLICY_VERSION_V0 ||
        (report.actualResult === ScenarioResultV0.ExecutionRejected
          ? report.attestationProofSummary.starkPublicInputsDigest !== null ||
            report.attestationProofSummary.starkProofBytesDigest !== null ||
            report.attestationProofSummary.starkProofBindingDigest !== null
          : report.attestationProofSummary.starkPublicInputsDigest === null ||
            report.attestationProofSummary.starkProofBytesDigest === null ||
            report.attestationProofSummary.starkProofBindingDigest === null))
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "STARK attestation proof summaries must pin the canonical STARK policy and digest fields",
      );
    }
  }

  const expectedTransactionsExpansion =
    canonicalPipelineTransactionsCommitmentExpansionFromTransactionsV0(
      report.commitmentExpansions.transactions.orderedTransactions,
    );
  if (
    !canonicalPipelineTransactionsCommitmentExpansionEqualV0(
      report.commitmentExpansions.transactions,
      expectedTransactionsExpansion,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline commitmentExpansions.transactions contradict orderedTransactions",
    );
  }
  const expectedBatchContextExpansion =
    canonicalPipelineBatchContextCommitmentExpansionFromConfigV0(
      executionConfigV0(report.requestAudit.rollupId),
    );
  if (
    !canonicalPipelineBatchContextCommitmentExpansionEqualV0(
      report.commitmentExpansions.batchContext,
      expectedBatchContextExpansion,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline commitmentExpansions.batchContext contradict the canonical execution config",
    );
  }
  const expectedFeeSummaryExpansion = canonicalPipelineFeeSummaryCommitmentExpansionFromFeeSummaryV0(
    feeSummaryV0(report.requestAudit.txCount),
  );
  if (
    !canonicalPipelineFeeSummaryCommitmentExpansionEqualV0(
      report.commitmentExpansions.feeSummary,
      expectedFeeSummaryExpansion,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline commitmentExpansions.feeSummary contradict the canonical fee summary",
    );
  }

  const expectedStageOutcomes = stageOutcomesForActualResultV0(report.actualResult);
  if (
    report.stageOutcomes.executionStatus !== expectedStageOutcomes.executionStatus ||
    report.stageOutcomes.verificationStatus !== expectedStageOutcomes.verificationStatus ||
    report.stageOutcomes.settlementStatus !== expectedStageOutcomes.settlementStatus
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline report.stageOutcomes contradict actualResult",
    );
  }

  const preExecutionRejection = canonicalPipelinePreExecutionRejectionReasonV0(
    reconstructedRequest,
    preparedAttestation,
  );
  if (preExecutionRejection !== null) {
    if (report.actualResult !== ScenarioResultV0.ExecutionRejected) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline embedded request material reproduces execution rejection, but actualResult does not",
      );
    }
    if (
      report.executedPostStateRoot !== null ||
      report.settlementCommittedStateRoot !== null ||
      report.publicInputs !== null ||
      report.proofArtifact !== null
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "pre-execution-rejected canonical pipeline reports must not expose post-execution artifacts",
      );
    }
    if (!bytesEqualV0(report.preStateRoot, reconstructedRequest.state.stateRoot())) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline preStateRoot contradicts embedded genesisAccounts",
      );
    }
    if (report.commitmentExpansions.outcomes !== null) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "pre-execution-rejected canonical pipeline reports must not expose commitmentExpansions.outcomes",
      );
    }
    const expectedStatusExplanation = canonicalPipelineStatusExplanationFromResultV0(
      reconstructedRequest.economic.requestKind,
      ScenarioResultV0.ExecutionRejected,
      preExecutionRejection.failureReasonCode,
      preExecutionRejection.detail,
    );
    if (
      !canonicalPipelineStatusExplanationEqualV0(
        report.statusExplanation,
        expectedStatusExplanation,
      )
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline statusExplanation contradicts pre-execution rejection semantics",
      );
    }
    const expectedAccountingSummary = canonicalPipelineAccountingSummaryFromRequestV0(
      reconstructedRequest,
      expectedBurnSummary,
      expectedBurnRecord,
      ScenarioResultV0.ExecutionRejected,
      null,
    );
    if (
      !canonicalPipelineAccountingSummaryEqualV0(
        report.accountingSummary,
        expectedAccountingSummary,
      )
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline accountingSummary contradicts pre-execution rejection semantics",
      );
    }
    assertCanonicalPipelineHeadTransitionSummaryMatchesV0(
      report,
      reconstructedRequest,
      expectedBurnRecord,
    );
    return;
  }

  let executed: TransitionV0;
  try {
    executed = executeBatchV0(
      reconstructedRequest.state,
      reconstructedRequest.rollupId,
      reconstructedRequest.batch,
    );
  } catch (error) {
    if (!(error instanceof ExecutionErrorV0)) {
      throw error;
    }
    if (report.actualResult !== ScenarioResultV0.ExecutionRejected) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline embedded request material reproduces execution rejection, but actualResult does not",
      );
    }
    if (
      report.executedPostStateRoot !== null ||
      report.settlementCommittedStateRoot !== null ||
      report.publicInputs !== null ||
      report.proofArtifact !== null
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "execution-rejected canonical pipeline reports must not expose post-execution artifacts",
      );
    }
    if (!bytesEqualV0(report.preStateRoot, reconstructedRequest.state.stateRoot())) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline preStateRoot contradicts embedded genesisAccounts",
      );
    }
    if (report.commitmentExpansions.outcomes !== null) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "execution-rejected canonical pipeline reports must not expose commitmentExpansions.outcomes",
      );
    }
    const expectedExecutionRejection = canonicalPipelineExecutionRejectionReasonV0(
      reconstructedRequest,
      preparedAttestation,
      error,
    );
    const expectedStatusExplanation = canonicalPipelineStatusExplanationFromResultV0(
      reconstructedRequest.economic.requestKind,
      ScenarioResultV0.ExecutionRejected,
      expectedExecutionRejection.failureReasonCode,
      expectedExecutionRejection.detail,
    );
    if (
      !canonicalPipelineStatusExplanationEqualV0(
        report.statusExplanation,
        expectedStatusExplanation,
      )
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline statusExplanation contradicts execution rejection semantics",
      );
    }
    const expectedAccountingSummary = canonicalPipelineAccountingSummaryFromRequestV0(
      reconstructedRequest,
      expectedBurnSummary,
      expectedBurnRecord,
      ScenarioResultV0.ExecutionRejected,
      null,
    );
    if (
      !canonicalPipelineAccountingSummaryEqualV0(
        report.accountingSummary,
        expectedAccountingSummary,
      )
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "canonical pipeline accountingSummary contradicts execution rejection semantics",
      );
    }
    assertCanonicalPipelineHeadTransitionSummaryMatchesV0(
      report,
      reconstructedRequest,
      expectedBurnRecord,
    );
    return;
  }

  if (report.actualResult === ScenarioResultV0.ExecutionRejected) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline embedded request material executes successfully, but actualResult is ExecutionRejected",
    );
  }
  if (!bytesEqualV0(report.preStateRoot, executed.preStateRoot)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline preStateRoot contradicts embedded genesisAccounts",
    );
  }
  if (report.executedPostStateRoot === null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "non-execution-rejected canonical pipeline reports must expose executedPostStateRoot",
    );
  }
  if (!bytesEqualV0(report.executedPostStateRoot, executed.postStateRoot)) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline executedPostStateRoot contradicts embedded request material",
    );
  }
  const expectedOutcomesExpansion = canonicalPipelineOutcomesCommitmentExpansionFromTransitionV0(
    executed,
  );
  if (
    report.commitmentExpansions.outcomes === null ||
    !canonicalPipelineOutcomesCommitmentExpansionEqualV0(
      report.commitmentExpansions.outcomes,
      expectedOutcomesExpansion,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline commitmentExpansions.outcomes contradict execution-derived outcomes",
    );
  }
  if (report.publicInputs === null || report.proofArtifact === null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "non-execution-rejected canonical pipeline reports must expose publicInputs and proofArtifact",
    );
  }

  if (!bytesEqualV0(report.publicInputs.publicInputsHash, sha256BytesV0(report.publicInputs.publicInputBytes))) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline publicInputsHash is inconsistent with publicInputBytes",
    );
  }
  if (
    !bytesEqualV0(
      report.publicInputs.transitionBindingHash,
      transitionBindingHashV0(report.publicInputs.publicInputBytes),
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline transitionBindingHash is inconsistent with publicInputBytes",
    );
  }

  let publicInputsVerificationIssue: boolean;
  if (report.publicInputs.decodeStatus === CanonicalPipelinePublicInputsDecodeStatusV0.Decoded) {
    if (report.publicInputs.decodedPublicInputs === null) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "decoded canonical pipeline publicInputs must expose decodedPublicInputs",
      );
    }
    const expectedConsistency = canonicalPipelineRequestSummaryConsistencyFromReportV0(report);
    if (
      report.publicInputs.requestSummaryConsistency === null ||
      !canonicalPipelineRequestSummaryConsistencyEqualV0(
        report.publicInputs.requestSummaryConsistency,
        expectedConsistency,
      )
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "decoded canonical pipeline requestSummaryConsistency contradicts the report",
      );
    }
    if (
      !expectedConsistency.transitionBindingVersionSupported ||
      !expectedConsistency.executionModelVersionSupported ||
      !expectedConsistency.batchVersionSupported ||
      !expectedConsistency.decodedBytesRoundTrip
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "decoded canonical pipeline publicInputs must use supported canonical versions and round-trip exactly",
      );
    }
    if (
      report.actualResult !== ScenarioResultV0.VerificationRejected &&
      !expectedConsistency.allFieldsMatch
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "accepted or settlement-rejected canonical pipeline reports must have fully consistent decoded publicInputs",
      );
    }
    publicInputsVerificationIssue = !expectedConsistency.allFieldsMatch;
  } else {
    if (report.publicInputs.decodedPublicInputs !== null) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "invalid canonical pipeline publicInputs must not expose decodedPublicInputs",
      );
    }
    if (report.publicInputs.requestSummaryConsistency !== null) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "invalid canonical pipeline publicInputs must not expose requestSummaryConsistency",
      );
    }
    if (report.actualResult !== ScenarioResultV0.VerificationRejected) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "invalid canonical pipeline publicInputs are only allowed on verification rejection",
      );
    }
    publicInputsVerificationIssue = true;
  }

  const expectedProofConsistency = canonicalPipelineProofArtifactConsistencyFromReportV0(report);
  if (
    !canonicalPipelineProofArtifactConsistencyEqualV0(
      report.proofArtifact.consistency,
      expectedProofConsistency,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline proofArtifact.consistency contradicts the proof artifact or report",
    );
  }
  if (
    !expectedProofConsistency.proverKindMatchesProofSystem ||
    !expectedProofConsistency.proofVersionSupported ||
    !expectedProofConsistency.proofBindingInputKindMatchesProofSystem
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline proofArtifact must use the supported canonical prover kind, proof version, and binding input kind",
    );
  }
  const proofArtifactVerificationIssue =
    !expectedProofConsistency.publicInputsHashMatchesReport ||
    !expectedProofConsistency.proofBindingDigestMatchesRecomputed;
  if (
    report.actualResult !== ScenarioResultV0.VerificationRejected &&
    !expectedProofConsistency.allFieldsMatch
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "accepted or settlement-rejected canonical pipeline reports must have fully consistent proof artifacts",
    );
  }
  if (
    report.actualResult === ScenarioResultV0.VerificationRejected &&
    !publicInputsVerificationIssue &&
    !proofArtifactVerificationIssue &&
    report.statusExplanation.failureReasonCode !==
      CanonicalPipelineFailureReasonCodeV0.AttestationProofVerificationRejected
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "verification-rejected canonical pipeline reports must expose at least one verification-layer mismatch",
    );
  }

  if (report.actualResult === ScenarioResultV0.Accepted) {
    if (
      report.settlementCommittedStateRoot === null ||
      !bytesEqualV0(report.settlementCommittedStateRoot, report.executedPostStateRoot)
    ) {
      throw new AuraTypescriptSdkErrorV0(
        "RustBridgeFailure",
        "accepted canonical pipeline reports must commit the executed post-state root",
      );
    }
  } else if (report.settlementCommittedStateRoot !== null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "rejected canonical pipeline reports must not expose settlementCommittedStateRoot",
    );
  }
  const walletBindingMismatchDetail =
    canonicalPipelineWalletBindingMismatchDetailV0(reconstructedRequest);
  if (
    walletBindingMismatchDetail !== null &&
    report.actualResult === ScenarioResultV0.Accepted
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "wallet binding mismatch must reject before a canonical report can be accepted",
    );
  }
  const expectedFailureStage =
    report.actualResult === ScenarioResultV0.Accepted
      ? CanonicalPipelineFailureStageV0.None
      : report.actualResult === ScenarioResultV0.VerificationRejected
        ? CanonicalPipelineFailureStageV0.Verification
        : CanonicalPipelineFailureStageV0.Settlement;
  const allowedFailureReasonCodes =
    report.actualResult === ScenarioResultV0.Accepted
      ? [CanonicalPipelineFailureReasonCodeV0.None]
      : report.actualResult === ScenarioResultV0.VerificationRejected
        ? [
            CanonicalPipelineFailureReasonCodeV0.VerificationLayerMismatch,
            CanonicalPipelineFailureReasonCodeV0.AttestationProofVerificationRejected,
          ]
        : [
            CanonicalPipelineFailureReasonCodeV0.SettlementAcceptanceRejected,
            CanonicalPipelineFailureReasonCodeV0.SettlementHeadMismatch,
            CanonicalPipelineFailureReasonCodeV0.WalletBindingMismatch,
          ];
  if (
    report.statusExplanation.failureStage !== expectedFailureStage ||
    !allowedFailureReasonCodes.includes(report.statusExplanation.failureReasonCode)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline statusExplanation contradicts actualResult",
    );
  }
  if (
    report.actualResult === ScenarioResultV0.Accepted &&
    !canonicalPipelineStatusExplanationEqualV0(
      report.statusExplanation,
      canonicalPipelineAcceptedStatusExplanationV0(reconstructedRequest.economic.requestKind),
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "accepted canonical pipeline reports must pin the accepted statusExplanation",
    );
  }
  if (
    report.statusExplanation.failureReasonCode ===
      CanonicalPipelineFailureReasonCodeV0.AttestationProofVerificationRejected &&
    (report.attestationSummary?.attestationProofKind !== CanonicalPipelineAttestationProofKindV0.Stark ||
      report.attestationProofSummary?.verificationPassed !== false)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "attestation proof verification rejection requires STARK attestation proof failure material",
    );
  }
  if (
    report.statusExplanation.failureReasonCode ===
      CanonicalPipelineFailureReasonCodeV0.SettlementHeadMismatch &&
    (publicInputsVerificationIssue || proofArtifactVerificationIssue)
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "settlement head mismatch must not mask a verification-layer mismatch",
    );
  }
  if (
    report.statusExplanation.failureReasonCode ===
      CanonicalPipelineFailureReasonCodeV0.SettlementHeadMismatch &&
    report.headTransitionSummary.authorityMode !==
      CanonicalPipelineHeadAuthorityModeV0.AuthoritativePersistent
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "settlement_head_mismatch requires authoritative_persistent head mode",
    );
  }
  if (report.actualResult === ScenarioResultV0.SettlementRejected) {
    if (
      report.statusExplanation.failureReasonCode ===
      CanonicalPipelineFailureReasonCodeV0.WalletBindingMismatch
    ) {
      if (walletBindingMismatchDetail === null) {
        throw new AuraTypescriptSdkErrorV0(
          "RustBridgeFailure",
          "wallet_binding_mismatch requires a mismatched wallet binding",
        );
      }
      const expectedWalletBindingStatus = canonicalPipelineStatusExplanationFromResultV0(
        reconstructedRequest.economic.requestKind,
        ScenarioResultV0.SettlementRejected,
        CanonicalPipelineFailureReasonCodeV0.WalletBindingMismatch,
        walletBindingMismatchDetail,
      );
      if (
        !canonicalPipelineStatusExplanationEqualV0(
          report.statusExplanation,
          expectedWalletBindingStatus,
        )
      ) {
        throw new AuraTypescriptSdkErrorV0(
          "RustBridgeFailure",
          "wallet_binding_mismatch report must pin the wallet binding rejection detail",
        );
      }
    }
    if (
      report.statusExplanation.failureReasonCode ===
      CanonicalPipelineFailureReasonCodeV0.SettlementAcceptanceRejected
    ) {
      if (walletBindingMismatchDetail !== null) {
        throw new AuraTypescriptSdkErrorV0(
          "RustBridgeFailure",
          "wallet binding mismatch must not be downgraded into settlement_acceptance_rejected",
        );
      }
      if (
        report.tokenAnchorSummary.anchorVerificationStatus ===
        CanonicalPipelineExternalAnchorVerificationStatusV0.Rejected
      ) {
        const expectedAnchorStatus = canonicalPipelineStatusExplanationFromResultV0(
          reconstructedRequest.economic.requestKind,
          ScenarioResultV0.SettlementRejected,
          CanonicalPipelineFailureReasonCodeV0.SettlementAcceptanceRejected,
          canonicalPipelineExternalAnchorRejectionDetailV0(),
        );
        if (
          !canonicalPipelineStatusExplanationEqualV0(
            report.statusExplanation,
            expectedAnchorStatus,
          )
        ) {
          throw new AuraTypescriptSdkErrorV0(
            "RustBridgeFailure",
            "rejected external token anchors must pin the settlement rejection detail",
          );
        }
      }
    }
  }
  const expectedAccountingSummary = canonicalPipelineAccountingSummaryFromRequestV0(
    reconstructedRequest,
    expectedBurnSummary,
    expectedBurnRecord,
    report.actualResult,
    report.settlementCommittedStateRoot,
  );
  if (
    !canonicalPipelineAccountingSummaryEqualV0(
      report.accountingSummary,
      expectedAccountingSummary,
    )
  ) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline accountingSummary contradicts burnSummary or settlement result",
    );
  }
  assertCanonicalPipelineHeadTransitionSummaryMatchesV0(
    report,
    reconstructedRequest,
    expectedBurnRecord,
  );
}

function canonicalPipelineRequestSummaryConsistencyFromReportV0(
  report: CanonicalPipelineReportV0,
): CanonicalPipelineRequestSummaryConsistencyAuditV0 {
  if (report.publicInputs === null || report.publicInputs.decodedPublicInputs === null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "decoded canonical pipeline publicInputs are required to compute requestSummaryConsistency",
    );
  }
  if (report.executedPostStateRoot === null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "executedPostStateRoot is required to compute requestSummaryConsistency",
    );
  }
  const decodedFromBytes = decodePublicInputsV0(report.publicInputs.publicInputBytes);
  const consistency: CanonicalPipelineRequestSummaryConsistencyAuditV0 = {
    transitionBindingVersionSupported:
      report.publicInputs.decodedPublicInputs.transitionBindingVersion ===
      TRANSITION_BINDING_VERSION_V0,
    executionModelVersionSupported:
      report.publicInputs.decodedPublicInputs.executionModelVersion ===
      EXECUTION_MODEL_VERSION_V0,
    batchVersionSupported:
      report.publicInputs.decodedPublicInputs.batchVersion === BATCH_VERSION_V0,
    rollupIdMatchesRequestAudit: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.rollupId,
      report.requestAudit.rollupId,
    ),
    batchNumberMatchesRequestAudit:
      report.publicInputs.decodedPublicInputs.batchNumber === report.requestAudit.batchNumber,
    txCountMatchesRequestAudit:
      report.publicInputs.decodedPublicInputs.txCount === report.requestAudit.txCount,
    parentBatchCommitmentMatchesRequestAudit: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.parentBatchCommitment,
      report.requestAudit.parentBatchCommitment,
    ),
    feeSummaryCommitmentMatchesExpansion: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.feeSummaryCommitment,
      report.commitmentExpansions.feeSummary.feeSummaryCommitment,
    ),
    preStateRootMatchesReport: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.preStateRoot,
      report.preStateRoot,
    ),
    transactionsCommitmentMatchesExpansion: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.transactionsCommitment,
      report.commitmentExpansions.transactions.transactionsCommitment,
    ),
    outcomesCommitmentMatchesExpansion:
      report.commitmentExpansions.outcomes !== null &&
      bytesEqualV0(
        report.publicInputs.decodedPublicInputs.outcomesCommitment,
        report.commitmentExpansions.outcomes.outcomesCommitment,
      ),
    batchContextCommitmentMatchesExpansion: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.batchContextCommitment,
      report.commitmentExpansions.batchContext.batchContextCommitment,
    ),
    postStateRootMatchesReport: bytesEqualV0(
      report.publicInputs.decodedPublicInputs.postStateRoot,
      report.executedPostStateRoot,
    ),
    decodedBytesRoundTrip: publicInputsEqualV0(
      decodedFromBytes,
      report.publicInputs.decodedPublicInputs,
    ),
    allFieldsMatch: false,
  };
  return {
    ...consistency,
    allFieldsMatch:
      consistency.transitionBindingVersionSupported &&
      consistency.executionModelVersionSupported &&
      consistency.batchVersionSupported &&
      consistency.rollupIdMatchesRequestAudit &&
      consistency.batchNumberMatchesRequestAudit &&
      consistency.txCountMatchesRequestAudit &&
      consistency.parentBatchCommitmentMatchesRequestAudit &&
      consistency.feeSummaryCommitmentMatchesExpansion &&
      consistency.preStateRootMatchesReport &&
      consistency.transactionsCommitmentMatchesExpansion &&
      consistency.outcomesCommitmentMatchesExpansion &&
      consistency.batchContextCommitmentMatchesExpansion &&
      consistency.postStateRootMatchesReport &&
      consistency.decodedBytesRoundTrip,
  };
}

function canonicalPipelineRequestSummaryConsistencyEqualV0(
  left: CanonicalPipelineRequestSummaryConsistencyAuditV0,
  right: CanonicalPipelineRequestSummaryConsistencyAuditV0,
): boolean {
  return (
    left.transitionBindingVersionSupported === right.transitionBindingVersionSupported &&
    left.executionModelVersionSupported === right.executionModelVersionSupported &&
    left.batchVersionSupported === right.batchVersionSupported &&
    left.rollupIdMatchesRequestAudit === right.rollupIdMatchesRequestAudit &&
    left.batchNumberMatchesRequestAudit === right.batchNumberMatchesRequestAudit &&
    left.txCountMatchesRequestAudit === right.txCountMatchesRequestAudit &&
    left.parentBatchCommitmentMatchesRequestAudit ===
      right.parentBatchCommitmentMatchesRequestAudit &&
    left.feeSummaryCommitmentMatchesExpansion === right.feeSummaryCommitmentMatchesExpansion &&
    left.preStateRootMatchesReport === right.preStateRootMatchesReport &&
    left.transactionsCommitmentMatchesExpansion ===
      right.transactionsCommitmentMatchesExpansion &&
    left.outcomesCommitmentMatchesExpansion === right.outcomesCommitmentMatchesExpansion &&
    left.batchContextCommitmentMatchesExpansion ===
      right.batchContextCommitmentMatchesExpansion &&
    left.postStateRootMatchesReport === right.postStateRootMatchesReport &&
    left.decodedBytesRoundTrip === right.decodedBytesRoundTrip &&
    left.allFieldsMatch === right.allFieldsMatch
  );
}

function canonicalPipelineProofArtifactConsistencyFromReportV0(
  report: CanonicalPipelineReportV0,
): CanonicalPipelineProofArtifactConsistencyAuditV0 {
  if (report.publicInputs === null || report.proofArtifact === null) {
    throw new AuraTypescriptSdkErrorV0(
      "RustBridgeFailure",
      "canonical pipeline publicInputs and proofArtifact are required to compute proof consistency",
    );
  }
  const recomputedProofBindingDigest =
    report.proofArtifact.proofBindingInputKind ===
    CanonicalPipelineProofBindingInputKindV0.WitnessDigest
      ? deriveMockProofBindingDigestFromWitnessDigestV0(
          report.proofArtifact.proofVersion,
          report.proofArtifact.publicInputsHash,
          report.proofArtifact.traceDigest,
          report.proofArtifact.traceLayoutDigest,
          report.proofArtifact.proofBindingInputDigest,
        )
      : deriveStarkProofBindingDigestFromHashV0(
          report.proofArtifact.proofVersion,
          report.proofArtifact.publicInputsHash,
          report.proofArtifact.traceDigest,
          report.proofArtifact.traceLayoutDigest,
          report.proofArtifact.proofBindingInputDigest,
        );
  const consistency: CanonicalPipelineProofArtifactConsistencyAuditV0 = {
    publicInputsHashMatchesReport: bytesEqualV0(
      report.proofArtifact.publicInputsHash,
      report.publicInputs.publicInputsHash,
    ),
    proverKindMatchesProofSystem:
      report.proofArtifact.proverKind === expectedProverKindForProofSystemV0(report.proofSystem),
    proofVersionSupported:
      report.proofArtifact.proofVersion ===
      expectedProofVersionForProofSystemV0(report.proofSystem),
    proofBindingInputKindMatchesProofSystem: proofBindingInputKindMatchesProofSystemV0(
      report.proofArtifact.proofBindingInputKind,
      report.proofSystem,
    ),
    recomputedProofBindingDigest,
    proofBindingDigestMatchesRecomputed: bytesEqualV0(
      report.proofArtifact.proofBindingDigest,
      recomputedProofBindingDigest,
    ),
    allFieldsMatch: false,
  };
  return {
    ...consistency,
    allFieldsMatch:
      consistency.publicInputsHashMatchesReport &&
      consistency.proverKindMatchesProofSystem &&
      consistency.proofVersionSupported &&
      consistency.proofBindingInputKindMatchesProofSystem &&
      consistency.proofBindingDigestMatchesRecomputed,
  };
}

function canonicalPipelineProofArtifactConsistencyEqualV0(
  left: CanonicalPipelineProofArtifactConsistencyAuditV0,
  right: CanonicalPipelineProofArtifactConsistencyAuditV0,
): boolean {
  return (
    left.publicInputsHashMatchesReport === right.publicInputsHashMatchesReport &&
    left.proverKindMatchesProofSystem === right.proverKindMatchesProofSystem &&
    left.proofVersionSupported === right.proofVersionSupported &&
    left.proofBindingInputKindMatchesProofSystem ===
      right.proofBindingInputKindMatchesProofSystem &&
    bytesEqualV0(left.recomputedProofBindingDigest, right.recomputedProofBindingDigest) &&
    left.proofBindingDigestMatchesRecomputed === right.proofBindingDigestMatchesRecomputed &&
    left.allFieldsMatch === right.allFieldsMatch
  );
}

function proofBindingInputKindMatchesProofSystemV0(
  kind: CanonicalPipelineProofBindingInputKindV0,
  proofSystem: ProofSystemV0,
): boolean {
  return (
    (kind === CanonicalPipelineProofBindingInputKindV0.WitnessDigest &&
      proofSystem === ProofSystemV0.Mock) ||
    (kind === CanonicalPipelineProofBindingInputKindV0.ProofBytesHash &&
      proofSystem === ProofSystemV0.Stark)
  );
}

function expectedProverKindForProofSystemV0(proofSystem: ProofSystemV0): number {
  return proofSystem === ProofSystemV0.Mock ? LOCAL_PROVER_KIND_MOCK_V0 : LOCAL_PROVER_KIND_STARK_V0;
}

function expectedProofVersionForProofSystemV0(proofSystem: ProofSystemV0): number {
  return proofSystem === ProofSystemV0.Mock ? LOCAL_MOCK_PROOF_VERSION_V0 : LOCAL_STARK_PROOF_VERSION_V0;
}

function normalizeProofSystemV0(value: ProofSystemV0): ProofSystemV0 {
  return parseProofSystemV0(String(value));
}

function parseJsonFileRecordV0(filePath: string, label: string): Record<string, unknown> {
  const fileContents = readTextFileV0(filePath, label);
  try {
    return recordValueV0(JSON.parse(fileContents), label);
  } catch (error) {
    if (error instanceof AuraTypescriptSdkErrorV0) {
      throw error;
    }
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label} is not valid JSON`,
      { cause: error instanceof Error ? error : undefined },
    );
  }
}

function readTextFileV0(filePath: string, label: string): string {
  try {
    return readFileSync(filePath, "utf8");
  } catch (error) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label} could not be read`,
      { cause: error instanceof Error ? error : undefined },
    );
  }
}

function recordValueV0(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label} must be a JSON object`,
    );
  }
  return value as Record<string, unknown>;
}

function assertOnlyAllowedKeysV0(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  label: string,
): void {
  const allowed = new Set(allowedKeys);
  const extras = Object.keys(record)
    .filter((key) => !allowed.has(key))
    .sort();
  if (extras.length > 0) {
    throw new AuraTypescriptSdkErrorV0(
      label === "rust_bridge" || label.startsWith("rust_bridge.")
        ? "RustBridgeFailure"
        : "InvalidFixture",
      `${label} contains unexpected field(s): ${extras.join(", ")}`,
    );
  }
}

function recordFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): Record<string, unknown> {
  return recordValueV0(record[field], `${label}.${field}`);
}

function optionalRecordFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): Record<string, unknown> | null {
  const value = record[field];
  return value === undefined || value === null ? null : recordValueV0(value, `${label}.${field}`);
}

function parseOptionalTamperFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
  maxLength: number,
  targetLabel: string,
): { byteOffset: number; xorWith: number } | null {
  const tamper = optionalRecordFieldV0(record, field, label);
  if (tamper === null) {
    return null;
  }
  assertOnlyAllowedKeysV0(tamper, ["byte_offset", "xor_with"], `${label}.${field}`);
  const byteOffset = safeJsonIndexV0(
    numberFieldV0(tamper, "byte_offset", `${label}.${field}`),
    `${label}.${field}.byte_offset`,
  );
  if (byteOffset >= maxLength) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field}.byte_offset out of range for ${targetLabel}`,
    );
  }
  return {
    byteOffset,
    xorWith: safeJsonU8V0(
      numberFieldV0(tamper, "xor_with", `${label}.${field}`),
      `${label}.${field}.xor_with`,
    ),
  };
}

function arrayFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): unknown[] {
  const value = record[field];
  if (!Array.isArray(value)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be an array`,
    );
  }
  return value;
}

function stringFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): string {
  const value = record[field];
  if (typeof value !== "string") {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be a string`,
    );
  }
  return value;
}

function optionalStringFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): string | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be a string when present`,
    );
  }
  return value;
}

function optionalU64FieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): bigint | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be a finite number when present`,
    );
  }
  return safeJsonU64V0(value, `${label}.${field}`);
}

function optionalU32FieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): number | null {
  const value = record[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be a finite number when present`,
    );
  }
  return safeJsonU32V0(value, `${label}.${field}`);
}

function stringValueV0(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label} must be a string`,
    );
  }
  return value;
}

function assertUnreachableV0(value: never): never {
  throw new AuraTypescriptSdkErrorV0(
    "InvalidFixture",
    `unreachable value encountered: ${String(value)}`,
  );
}

function numberFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = record[field];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be a finite number`,
    );
  }
  return value;
}

function booleanFieldV0(
  record: Record<string, unknown>,
  field: string,
  label: string,
): boolean {
  const value = record[field];
  if (typeof value !== "boolean") {
    throw new AuraTypescriptSdkErrorV0(
      "InvalidFixture",
      `${label}.${field} must be a boolean`,
    );
  }
  return value;
}
