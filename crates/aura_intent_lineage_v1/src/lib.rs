// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Aura canonical lower-layer cat-map runtime crate.
//!
//! Implemented here:
//! - Layer 1 cat-map execution and canonical trace commitments under the legacy `DCM` name
//! - active AIR-style pair-state trace validation over the forward cat-map relation
//! - Layer 2 native authorization-lineage construction bound to pair-state commitments
//! - Layer 4 native envelope validation and a thin deterministic state-transition slice
//! - Layer 3 proof-claim assembly, recurrence checking, and transcript construction
//! - deterministic AIR proof-packaging plus a real Winterfell-backed lower-layer STARK path
//! - retained mock/scaffold proving surfaces for staged and regression-only coverage
//! - deterministic 521-bit seed reduction into pair-state initializers
//!
//! CRATE BOUNDARY GUARANTEE
//!
//! This crate is the pure lower-layer runtime/proof spine.
//! Research / supporting overlays that feed this spine through `(x0, y0)` now live behind the
//! standalone `aura_intent_lineage_research_v1` crate boundary.
//!
//! Intentionally not implemented here:
//! - a native backend field equal to `2^521 - 1`
//! - trace-commitment hashing inside the AIR
//! - final production Merkle or settlement schemes
//!
//! This crate is the authoritative lower-layer implementation for Aura's 2D cat-map runtime and
//! its immediate AIR/binding/claim surfaces. Its real STARK path proves the lower-layer AIR
//! through an explicit non-native representation bridge inside Winterfell and keeps the canonical
//! `DcmClaim521V1` object authoritative across transcript, session, verifier, and acceptance
//! boundaries.

use core::fmt;
use sha2::{Digest, Sha256};

mod commitment_521_v1;
mod aura_hash_v1;
mod dcm_air_adapter_v1;
mod dcm_air_v1;
mod dcm_v1;
mod field_521_v1;
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
mod storm_state_v1;
mod storm_trace_commitment_v1;
mod symmetric_envelope_v1;

pub use commitment_521_v1::*;
// Canonicalization functions from legacy module - still valid for V2
pub use aura_hash_v1::{
    canonical_message_bytes_v1, canonical_text_payload_bytes_v1,
    canonical_text_payload_bytes_from_text_v1, decode_and_normalize_message_utf8_v1,
    normalize_text_message_v1, AuraHashV1Error, AURA_HASH_V1_BOM_CODEPOINT,
    AURA_HASH_V1_LENGTH_PREFIX_BYTES,
};
pub use dcm_air_adapter_v1::*;
pub use dcm_air_v1::*;
pub use dcm_v1::*;
pub use field_521_v1::*;
pub use layer1_layer2_bridge_v1::*;
pub use layer2_object_v1::*;
pub use layer3_authorization_lineage_consumer_v1::*;
pub use layer3_authorization_lineage_proof_v1::*;
pub use layer3_claim_v1::*;
pub use layer3_layer4_verified_authorization_ingress_v1::*;
pub use lower_layer_execution_commitment_v2::*;
pub use mock_prover_v1::*;
pub use mock_verifier_v1::*;
pub use proof_session_v1::*;
pub use proof_transcript_v1::*;
pub use recurrence_constraints_v1::*;
pub use session_encryption_context_v1::*;
pub use session_key_v1::*;
pub use stark_prover_v1::*;
pub use stark_trace_commitment_v1::*;
pub use stark_transcript_v1::*;
pub use stark_verifier_v1::*;
pub use state_engine_v1::*;
pub use storm_air_v1::*;
pub use storm_claim_v1::*;
pub use storm_context_v1::*;
pub use storm_encryption_binding_v1::*;
pub use storm_execution_v1::*;
pub use storm_hash521_v1::*;
pub use storm_state_v1::*;
pub use storm_trace_commitment_v1::*;
pub use symmetric_envelope_v1::*;

/// Legacy interfaces for historical compatibility only.
/// 
/// These modules implement deprecated protocol versions and are NOT part of the
/// active canonical protocol. Active implementations MUST use the storm_* surfaces.
/// 
/// # Deprecated
/// - `aura_hash_v1`: Use `storm_hash521_v1` (AURA_HASH_V2) instead
/// - `dcm_*` (Arnold cat map): Use `storm_*` (quadratic recurrence) instead
pub mod legacy {
    /// Legacy SHA-256-based hash (AURA_HASH_V1) - DEPRECATED
    /// 
    /// This module implements the deprecated V1 identity function using SHA-256.
    /// The active protocol uses AURA_HASH_V2 (H_521 with SHA3-512) via `storm_hash521_v1`.
    #[deprecated(
        since = "2.0.0",
        note = "Use storm_hash521_v1 (AURA_HASH_V2) instead. This legacy module will be removed in a future release."
    )]
    pub mod aura_hash_v1 {
        pub use crate::aura_hash_v1::*;
    }
    
    /// Legacy Arnold cat map execution (DCM) - DEPRECATED
    /// 
    /// These modules implement the linear Arnold cat map recurrence.
    /// The active protocol uses STORM_V1_1 (quadratic recurrence) via `storm_execution_v1`.
    #[deprecated(
        since = "2.0.0",
        note = "Use storm_execution_v1 (STORM_V1_1 quadratic recurrence) instead. This legacy module will be removed in a future release."
    )]
    pub mod catmap_v1 {
        pub use crate::dcm_air_v1::*;
        pub use crate::dcm_v1::*;
        pub use crate::recurrence_constraints_v1::*;
        pub use crate::stark_trace_commitment_v1::*;
    }
}

pub const HASH_LEN_V1: usize = 32;
pub const AURA_LAYER4_INTENT_HASH_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_LAYER4_INTENT_HASH_V1";
pub const AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_AUTHORIZATION_LINEAGE_V1";

pub const INTENT_VERSION_V1: u8 = 1;
pub const INTENT_FLAG_HAS_CLIENT_CONTEXT_COMMITMENT: u16 = 0x0001;
pub const VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS: u16 = 0x0001;
pub const VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS: u16 = 0x0002;
pub const VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER: u16 = 0x0004;
pub const VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER: u16 = 0x0008;
pub const ACCOUNT_UPDATE_FLAG_HAS_NEXT_AUTHORIZATION_POLICY: u8 = 0x01;
pub const ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT: u8 = 0x02;

pub const AUTHORIZATION_LINEAGE_VERSION_V1: u8 = 1;
pub const LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT: u16 = 0x0001;
pub const LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY: u16 = 0x0002;
pub const LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH: u16 = 0x0004;
pub const LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH: u16 = 0x0008;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuraLayer4TxKindV1 {
    AccountCreate = 0x01,
    ValueTransfer = 0x02,
    AccountUpdate = 0x03,
    SystemOperationReservedReject = 0x04,
}

impl AuraLayer4TxKindV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuraLayer4FeePolicyKindV1 {
    MaxFeePerTxNative = 0x01,
}

impl AuraLayer4FeePolicyKindV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControllerBindingTypeV1 {
    RawEd25519PublicKey32 = 0x01,
    ExternalSubjectId32 = 0x02,
}

impl ControllerBindingTypeV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorizationPolicyFamilyV1 {
    AuraL2AuthorizationEnvelopeV1 = 0x01,
}

impl AuthorizationPolicyFamilyV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorizationPolicyKindV1 {
    AuraV1ExactIntentLegacyPair = 0x01,
}

impl AuthorizationPolicyKindV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountCreateOperationV1 {
    pub new_account_id: [u8; HASH_LEN_V1],
    pub new_controller_binding_type: ControllerBindingTypeV1,
    pub new_controller_binding_id: [u8; HASH_LEN_V1],
    pub initial_authorization_policy_family: AuthorizationPolicyFamilyV1,
    pub initial_authorization_policy_version: u8,
    pub initial_authorization_policy_kind: AuthorizationPolicyKindV1,
    pub initial_authorization_policy_flags: u8,
    pub initial_data_commitment: [u8; HASH_LEN_V1],
    pub initial_funding_amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueTransferOperationV1 {
    pub recipient_account_id: [u8; HASH_LEN_V1],
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountUpdateOperationV1 {
    pub target_account_id: [u8; HASH_LEN_V1],
    pub account_update_flags: u8,
    pub next_authorization_policy_family: u8,
    pub next_authorization_policy_version: u8,
    pub next_authorization_policy_kind: u8,
    pub next_authorization_policy_flags: u8,
    pub next_data_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuraLayer4OperationBodyV1 {
    AccountCreate(AccountCreateOperationV1),
    ValueTransfer(ValueTransferOperationV1),
    AccountUpdate(AccountUpdateOperationV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuraLayer4IntentBodyV1 {
    pub intent_version: u8,
    pub intent_flags: u16,
    pub rollup_id: [u8; HASH_LEN_V1],
    pub tx_kind: AuraLayer4TxKindV1,
    pub sender_account_id: [u8; HASH_LEN_V1],
    pub sender_nonce: u64,
    pub validity_flags: u16,
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    pub not_before_batch_number: u64,
    pub not_after_batch_number: u64,
    pub fee_policy_kind: AuraLayer4FeePolicyKindV1,
    pub max_fee_native: u64,
    pub client_context_commitment: [u8; HASH_LEN_V1],
    pub operation_body: AuraLayer4OperationBodyV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuraLayer4IntentHashV1Error {
    InvalidIntentVersion { expected: u8, actual: u8 },
    IntentFlagsReservedBitsNonZero { actual: u16 },
    ValidityFlagsReservedBitsNonZero { actual: u16 },
    ClientContextCommitmentMustBeZeroWhenAbsent,
    NotBeforeUnixSecondsMustBeZeroWhenAbsent,
    NotAfterUnixSecondsMustBeZeroWhenAbsent,
    NotBeforeBatchNumberMustBeZeroWhenAbsent,
    NotAfterBatchNumberMustBeZeroWhenAbsent,
    InvalidUnixValidityWindow { not_before: u64, not_after: u64 },
    InvalidBatchValidityWindow { not_before: u64, not_after: u64 },
    SystemOperationReservedReject,
    OperationBodyDoesNotMatchTxKind,
    InitialAuthorizationPolicyVersionMustEqualOne { actual: u8 },
    InitialAuthorizationPolicyFlagsMustBeZero { actual: u8 },
    ValueTransferAmountMustBePositive,
    ValueTransferRecipientMustDifferFromSender,
    AccountUpdateFlagsReservedBitsNonZero { actual: u8 },
    AccountUpdateTargetMustEqualSender,
    NextAuthorizationPolicyVersionMustEqualOne { actual: u8 },
    NextAuthorizationPolicyFamilyUnsupported { actual: u8 },
    NextAuthorizationPolicyKindUnsupported { actual: u8 },
    NextAuthorizationPolicyFlagsMustBeZero { actual: u8 },
    NextAuthorizationPolicyFieldsMustBeZeroWhenAbsent,
    NextDataCommitmentMustBeZeroWhenAbsent,
    AccountUpdateRequiresAtLeastOneMutation,
}

impl AuraLayer4IntentHashV1Error {
    pub const fn reject_reason(self) -> &'static str {
        match self {
            Self::InvalidIntentVersion { .. } => "intent_version_invalid",
            Self::IntentFlagsReservedBitsNonZero { .. } => "intent_flags_reserved_bits_non_zero",
            Self::ValidityFlagsReservedBitsNonZero { .. } => {
                "validity_flags_reserved_bits_non_zero"
            }
            Self::ClientContextCommitmentMustBeZeroWhenAbsent => {
                "client_context_commitment_must_be_zero_when_absent"
            }
            Self::NotBeforeUnixSecondsMustBeZeroWhenAbsent => {
                "not_before_unix_seconds_must_be_zero_when_absent"
            }
            Self::NotAfterUnixSecondsMustBeZeroWhenAbsent => {
                "not_after_unix_seconds_must_be_zero_when_absent"
            }
            Self::NotBeforeBatchNumberMustBeZeroWhenAbsent => {
                "not_before_batch_number_must_be_zero_when_absent"
            }
            Self::NotAfterBatchNumberMustBeZeroWhenAbsent => {
                "not_after_batch_number_must_be_zero_when_absent"
            }
            Self::InvalidUnixValidityWindow { .. } => "invalid_unix_validity_window",
            Self::InvalidBatchValidityWindow { .. } => "invalid_batch_validity_window",
            Self::SystemOperationReservedReject => "system_operation_reserved_reject",
            Self::OperationBodyDoesNotMatchTxKind => "operation_body_does_not_match_tx_kind",
            Self::InitialAuthorizationPolicyVersionMustEqualOne { .. } => {
                "initial_authorization_policy_version_must_equal_one"
            }
            Self::InitialAuthorizationPolicyFlagsMustBeZero { .. } => {
                "initial_authorization_policy_flags_must_be_zero"
            }
            Self::ValueTransferAmountMustBePositive => "value_transfer_amount_must_be_positive",
            Self::ValueTransferRecipientMustDifferFromSender => {
                "value_transfer_recipient_must_differ_from_sender"
            }
            Self::AccountUpdateFlagsReservedBitsNonZero { .. } => {
                "account_update_flags_reserved_bits_non_zero"
            }
            Self::AccountUpdateTargetMustEqualSender => "account_update_target_must_equal_sender",
            Self::NextAuthorizationPolicyVersionMustEqualOne { .. } => {
                "next_authorization_policy_version_must_equal_one"
            }
            Self::NextAuthorizationPolicyFamilyUnsupported { .. } => {
                "next_authorization_policy_family_unsupported"
            }
            Self::NextAuthorizationPolicyKindUnsupported { .. } => {
                "next_authorization_policy_kind_unsupported"
            }
            Self::NextAuthorizationPolicyFlagsMustBeZero { .. } => {
                "next_authorization_policy_flags_must_be_zero"
            }
            Self::NextAuthorizationPolicyFieldsMustBeZeroWhenAbsent => {
                "next_authorization_policy_fields_must_be_zero_when_absent"
            }
            Self::NextDataCommitmentMustBeZeroWhenAbsent => {
                "next_data_commitment_must_be_zero_when_absent"
            }
            Self::AccountUpdateRequiresAtLeastOneMutation => {
                "account_update_requires_at_least_one_mutation"
            }
        }
    }
}

impl fmt::Display for AuraLayer4IntentHashV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIntentVersion { expected, actual } => {
                write!(f, "invalid intent version: expected {expected}, got {actual}")
            }
            Self::IntentFlagsReservedBitsNonZero { actual } => {
                write!(f, "intent flags reserved bits non-zero: 0x{actual:04x}")
            }
            Self::ValidityFlagsReservedBitsNonZero { actual } => {
                write!(f, "validity flags reserved bits non-zero: 0x{actual:04x}")
            }
            Self::ClientContextCommitmentMustBeZeroWhenAbsent => {
                write!(f, "client context commitment must be zero when absent")
            }
            Self::NotBeforeUnixSecondsMustBeZeroWhenAbsent => {
                write!(f, "not_before_unix_seconds must be zero when absent")
            }
            Self::NotAfterUnixSecondsMustBeZeroWhenAbsent => {
                write!(f, "not_after_unix_seconds must be zero when absent")
            }
            Self::NotBeforeBatchNumberMustBeZeroWhenAbsent => {
                write!(f, "not_before_batch_number must be zero when absent")
            }
            Self::NotAfterBatchNumberMustBeZeroWhenAbsent => {
                write!(f, "not_after_batch_number must be zero when absent")
            }
            Self::InvalidUnixValidityWindow {
                not_before,
                not_after,
            } => write!(
                f,
                "invalid unix validity window: not_after ({not_after}) must be greater than not_before ({not_before})"
            ),
            Self::InvalidBatchValidityWindow {
                not_before,
                not_after,
            } => write!(
                f,
                "invalid batch validity window: not_after ({not_after}) must be greater than not_before ({not_before})"
            ),
            Self::SystemOperationReservedReject => {
                write!(f, "system_operation is reserved and rejected in version 1")
            }
            Self::OperationBodyDoesNotMatchTxKind => {
                write!(f, "operation body does not match tx_kind")
            }
            Self::InitialAuthorizationPolicyVersionMustEqualOne { actual } => write!(
                f,
                "initial authorization policy version must equal 1, got {actual}"
            ),
            Self::InitialAuthorizationPolicyFlagsMustBeZero { actual } => write!(
                f,
                "initial authorization policy flags must be zero, got 0x{actual:02x}"
            ),
            Self::ValueTransferAmountMustBePositive => {
                write!(f, "value transfer amount must be positive")
            }
            Self::ValueTransferRecipientMustDifferFromSender => {
                write!(f, "value transfer recipient must differ from sender")
            }
            Self::AccountUpdateFlagsReservedBitsNonZero { actual } => write!(
                f,
                "account update flags reserved bits non-zero: 0x{actual:02x}"
            ),
            Self::AccountUpdateTargetMustEqualSender => {
                write!(f, "account update target must equal sender")
            }
            Self::NextAuthorizationPolicyVersionMustEqualOne { actual } => write!(
                f,
                "next authorization policy version must equal 1, got {actual}"
            ),
            Self::NextAuthorizationPolicyFamilyUnsupported { actual } => write!(
                f,
                "next authorization policy family unsupported: 0x{actual:02x}"
            ),
            Self::NextAuthorizationPolicyKindUnsupported { actual } => write!(
                f,
                "next authorization policy kind unsupported: 0x{actual:02x}"
            ),
            Self::NextAuthorizationPolicyFlagsMustBeZero { actual } => write!(
                f,
                "next authorization policy flags must be zero, got 0x{actual:02x}"
            ),
            Self::NextAuthorizationPolicyFieldsMustBeZeroWhenAbsent => {
                write!(f, "next authorization policy fields must be zero when absent")
            }
            Self::NextDataCommitmentMustBeZeroWhenAbsent => {
                write!(f, "next data commitment must be zero when absent")
            }
            Self::AccountUpdateRequiresAtLeastOneMutation => {
                write!(f, "account update requires at least one mutation")
            }
        }
    }
}

impl std::error::Error for AuraLayer4IntentHashV1Error {}

impl AuraLayer4IntentBodyV1 {
    pub fn validate(&self) -> Result<(), AuraLayer4IntentHashV1Error> {
        if self.intent_version != INTENT_VERSION_V1 {
            return Err(AuraLayer4IntentHashV1Error::InvalidIntentVersion {
                expected: INTENT_VERSION_V1,
                actual: self.intent_version,
            });
        }

        if self.intent_flags & !INTENT_FLAG_HAS_CLIENT_CONTEXT_COMMITMENT != 0 {
            return Err(
                AuraLayer4IntentHashV1Error::IntentFlagsReservedBitsNonZero {
                    actual: self.intent_flags,
                },
            );
        }

        if self.validity_flags
            & !(VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS
                | VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS
                | VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER
                | VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER)
            != 0
        {
            return Err(
                AuraLayer4IntentHashV1Error::ValidityFlagsReservedBitsNonZero {
                    actual: self.validity_flags,
                },
            );
        }

        if !has_flag_u16(self.intent_flags, INTENT_FLAG_HAS_CLIENT_CONTEXT_COMMITMENT)
            && !is_zero32(&self.client_context_commitment)
        {
            return Err(AuraLayer4IntentHashV1Error::ClientContextCommitmentMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS,
        ) && self.not_before_unix_seconds != 0
        {
            return Err(AuraLayer4IntentHashV1Error::NotBeforeUnixSecondsMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS,
        ) && self.not_after_unix_seconds != 0
        {
            return Err(AuraLayer4IntentHashV1Error::NotAfterUnixSecondsMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER,
        ) && self.not_before_batch_number != 0
        {
            return Err(AuraLayer4IntentHashV1Error::NotBeforeBatchNumberMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER,
        ) && self.not_after_batch_number != 0
        {
            return Err(AuraLayer4IntentHashV1Error::NotAfterBatchNumberMustBeZeroWhenAbsent);
        }

        if has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS,
        ) && has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS,
        ) && self.not_after_unix_seconds <= self.not_before_unix_seconds
        {
            return Err(AuraLayer4IntentHashV1Error::InvalidUnixValidityWindow {
                not_before: self.not_before_unix_seconds,
                not_after: self.not_after_unix_seconds,
            });
        }

        if has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER,
        ) && has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER,
        ) && self.not_after_batch_number <= self.not_before_batch_number
        {
            return Err(AuraLayer4IntentHashV1Error::InvalidBatchValidityWindow {
                not_before: self.not_before_batch_number,
                not_after: self.not_after_batch_number,
            });
        }

        match (self.tx_kind, self.operation_body) {
            (AuraLayer4TxKindV1::AccountCreate, AuraLayer4OperationBodyV1::AccountCreate(op)) => {
                if op.initial_authorization_policy_version != 1 {
                    return Err(
                        AuraLayer4IntentHashV1Error::InitialAuthorizationPolicyVersionMustEqualOne {
                            actual: op.initial_authorization_policy_version,
                        },
                    );
                }

                if op.initial_authorization_policy_flags != 0 {
                    return Err(
                        AuraLayer4IntentHashV1Error::InitialAuthorizationPolicyFlagsMustBeZero {
                            actual: op.initial_authorization_policy_flags,
                        },
                    );
                }
            }
            (AuraLayer4TxKindV1::ValueTransfer, AuraLayer4OperationBodyV1::ValueTransfer(op)) => {
                if op.amount == 0 {
                    return Err(AuraLayer4IntentHashV1Error::ValueTransferAmountMustBePositive);
                }

                if op.recipient_account_id == self.sender_account_id {
                    return Err(
                        AuraLayer4IntentHashV1Error::ValueTransferRecipientMustDifferFromSender,
                    );
                }
            }
            (AuraLayer4TxKindV1::AccountUpdate, AuraLayer4OperationBodyV1::AccountUpdate(op)) => {
                if op.target_account_id != self.sender_account_id {
                    return Err(AuraLayer4IntentHashV1Error::AccountUpdateTargetMustEqualSender);
                }

                if op.account_update_flags
                    & !(ACCOUNT_UPDATE_FLAG_HAS_NEXT_AUTHORIZATION_POLICY
                        | ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT)
                    != 0
                {
                    return Err(
                        AuraLayer4IntentHashV1Error::AccountUpdateFlagsReservedBitsNonZero {
                            actual: op.account_update_flags,
                        },
                    );
                }

                let has_next_policy = has_flag_u8(
                    op.account_update_flags,
                    ACCOUNT_UPDATE_FLAG_HAS_NEXT_AUTHORIZATION_POLICY,
                );
                let has_next_data = has_flag_u8(
                    op.account_update_flags,
                    ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT,
                );

                if !has_next_policy
                    && (op.next_authorization_policy_family != 0
                        || op.next_authorization_policy_version != 0
                        || op.next_authorization_policy_kind != 0
                        || op.next_authorization_policy_flags != 0)
                {
                    return Err(
                        AuraLayer4IntentHashV1Error::NextAuthorizationPolicyFieldsMustBeZeroWhenAbsent,
                    );
                }

                if has_next_policy && op.next_authorization_policy_version != 1 {
                    return Err(
                        AuraLayer4IntentHashV1Error::NextAuthorizationPolicyVersionMustEqualOne {
                            actual: op.next_authorization_policy_version,
                        },
                    );
                }

                if has_next_policy && op.next_authorization_policy_flags != 0 {
                    return Err(
                        AuraLayer4IntentHashV1Error::NextAuthorizationPolicyFlagsMustBeZero {
                            actual: op.next_authorization_policy_flags,
                        },
                    );
                }

                if has_next_policy
                    && op.next_authorization_policy_family
                        != AuthorizationPolicyFamilyV1::AuraL2AuthorizationEnvelopeV1.as_u8()
                {
                    return Err(
                        AuraLayer4IntentHashV1Error::NextAuthorizationPolicyFamilyUnsupported {
                            actual: op.next_authorization_policy_family,
                        },
                    );
                }

                if has_next_policy
                    && op.next_authorization_policy_kind
                        != AuthorizationPolicyKindV1::AuraV1ExactIntentLegacyPair.as_u8()
                {
                    return Err(
                        AuraLayer4IntentHashV1Error::NextAuthorizationPolicyKindUnsupported {
                            actual: op.next_authorization_policy_kind,
                        },
                    );
                }

                if !has_next_data && !is_zero32(&op.next_data_commitment) {
                    return Err(
                        AuraLayer4IntentHashV1Error::NextDataCommitmentMustBeZeroWhenAbsent,
                    );
                }

                if !has_next_policy && !has_next_data {
                    return Err(
                        AuraLayer4IntentHashV1Error::AccountUpdateRequiresAtLeastOneMutation,
                    );
                }
            }
            (AuraLayer4TxKindV1::SystemOperationReservedReject, _) => {
                return Err(AuraLayer4IntentHashV1Error::SystemOperationReservedReject)
            }
            _ => return Err(AuraLayer4IntentHashV1Error::OperationBodyDoesNotMatchTxKind),
        }

        Ok(())
    }

    pub fn canonical_serialized_body(&self) -> Result<Vec<u8>, AuraLayer4IntentHashV1Error> {
        self.validate()?;

        let mut bytes = Vec::with_capacity(260);
        bytes.push(self.intent_version);
        bytes.extend_from_slice(&self.intent_flags.to_le_bytes());
        bytes.extend_from_slice(&self.rollup_id);
        bytes.push(self.tx_kind.as_u8());
        bytes.extend_from_slice(&self.sender_account_id);
        bytes.extend_from_slice(&self.sender_nonce.to_le_bytes());
        bytes.extend_from_slice(&self.validity_flags.to_le_bytes());
        bytes.extend_from_slice(&self.not_before_unix_seconds.to_le_bytes());
        bytes.extend_from_slice(&self.not_after_unix_seconds.to_le_bytes());
        bytes.extend_from_slice(&self.not_before_batch_number.to_le_bytes());
        bytes.extend_from_slice(&self.not_after_batch_number.to_le_bytes());
        bytes.push(self.fee_policy_kind.as_u8());
        bytes.extend_from_slice(&self.max_fee_native.to_le_bytes());
        bytes.extend_from_slice(&self.client_context_commitment);

        match self.operation_body {
            AuraLayer4OperationBodyV1::AccountCreate(op) => {
                bytes.extend_from_slice(&op.new_account_id);
                bytes.push(op.new_controller_binding_type.as_u8());
                bytes.extend_from_slice(&op.new_controller_binding_id);
                bytes.push(op.initial_authorization_policy_family.as_u8());
                bytes.push(op.initial_authorization_policy_version);
                bytes.push(op.initial_authorization_policy_kind.as_u8());
                bytes.push(op.initial_authorization_policy_flags);
                bytes.extend_from_slice(&op.initial_data_commitment);
                bytes.extend_from_slice(&op.initial_funding_amount.to_le_bytes());
            }
            AuraLayer4OperationBodyV1::ValueTransfer(op) => {
                bytes.extend_from_slice(&op.recipient_account_id);
                bytes.extend_from_slice(&op.amount.to_le_bytes());
            }
            AuraLayer4OperationBodyV1::AccountUpdate(op) => {
                bytes.extend_from_slice(&op.target_account_id);
                bytes.push(op.account_update_flags);
                bytes.push(op.next_authorization_policy_family);
                bytes.push(op.next_authorization_policy_version);
                bytes.push(op.next_authorization_policy_kind);
                bytes.push(op.next_authorization_policy_flags);
                bytes.extend_from_slice(&op.next_data_commitment);
            }
        }

        Ok(bytes)
    }

    pub fn canonical_hash_preimage(&self) -> Result<Vec<u8>, AuraLayer4IntentHashV1Error> {
        let body = self.canonical_serialized_body()?;
        let mut preimage =
            Vec::with_capacity(AURA_LAYER4_INTENT_HASH_DOMAIN_SEPARATOR_V1.len() + body.len());
        preimage.extend_from_slice(AURA_LAYER4_INTENT_HASH_DOMAIN_SEPARATOR_V1);
        preimage.extend_from_slice(&body);
        Ok(preimage)
    }

    pub fn intent_hash(&self) -> Result<[u8; HASH_LEN_V1], AuraLayer4IntentHashV1Error> {
        Ok(sha256_bytes(&self.canonical_hash_preimage()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DcmCommitmentKindV1 {
    DcmRootCommitmentV1 = 0x01,
    LegacyV1CompatibilityOnly = 0xfe,
}

impl DcmCommitmentKindV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::DcmRootCommitmentV1),
            0xfe => Some(Self::LegacyV1CompatibilityOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubjectBindingTypeV1 {
    RawEd25519PublicKey32 = 0x01,
    ExternalSubjectId32 = 0x02,
}

impl SubjectBindingTypeV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::RawEd25519PublicKey32),
            0x02 => Some(Self::ExternalSubjectId32),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IntentTypeV1 {
    OpaqueIntentHash32 = 0x01,
    AuraLayer4IntentHashV1 = 0x02,
    LegacyV1ChallengeContext = 0xfe,
}

impl IntentTypeV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::OpaqueIntentHash32),
            0x02 => Some(Self::AuraLayer4IntentHashV1),
            0xfe => Some(Self::LegacyV1ChallengeContext),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FreshnessModeV1 {
    NonceOnly = 0x01,
    NoncePlusUnixTimeSeconds = 0x02,
    NoncePlusSlotNumber = 0x03,
    LegacyV1ChallengeFreshness = 0xfe,
}

impl FreshnessModeV1 {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::NonceOnly),
            0x02 => Some(Self::NoncePlusUnixTimeSeconds),
            0x03 => Some(Self::NoncePlusSlotNumber),
            0xfe => Some(Self::LegacyV1ChallengeFreshness),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationLineageV1 {
    pub version: u8,
    pub lineage_flags: u16,
    pub dcm_commitment_kind: DcmCommitmentKindV1,
    pub dcm_commitment_root: [u8; HASH_LEN_V1],
    pub dcm_trace_commitment: [u8; HASH_LEN_V1],
    pub subject_binding_type: SubjectBindingTypeV1,
    pub subject_id: [u8; HASH_LEN_V1],
    pub subject_public_key: [u8; HASH_LEN_V1],
    pub intent_type: IntentTypeV1,
    pub intent_hash: [u8; HASH_LEN_V1],
    pub freshness_mode: FreshnessModeV1,
    pub freshness_nonce: [u8; HASH_LEN_V1],
    pub freshness_reference: u64,
    pub proof_material_v1_hash: [u8; HASH_LEN_V1],
    pub fractal_key_v1_hash: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationLineageV1Error {
    InvalidVersion { expected: u8, actual: u8 },
    LineageFlagsReservedBitsNonZero { actual: u16 },
    DcmTraceCommitmentMustBeZeroWhenAbsent,
    SubjectPublicKeyMustBeZeroWhenAbsent,
    ProofMaterialV1HashMustBeZeroWhenAbsent,
    FractalKeyV1HashMustBeZeroWhenAbsent,
    SubjectPublicKeyFlagForbiddenForRawEd25519,
    SubjectPublicKeyMustBeZeroForRawEd25519,
    NativeDcmRootedCannotUseLegacyIntentType,
    NativeDcmRootedCannotUseLegacyFreshnessMode,
    NativeDcmRootedCannotCarryProofMaterialV1Hash,
    NativeDcmRootedCannotCarryFractalKeyV1Hash,
    LegacyCompatibilityRequiresZeroDcmCommitmentRoot,
    LegacyCompatibilityCannotCarryDcmTraceCommitment,
    LegacyCompatibilityRequiresLegacyIntentType,
    LegacyCompatibilityRequiresLegacyFreshnessMode,
    LegacyCompatibilityRequiresProofMaterialV1Hash,
    LegacyCompatibilityRequiresFractalKeyV1Hash,
}

impl AuthorizationLineageV1Error {
    pub const fn reject_reason(self) -> &'static str {
        match self {
            Self::InvalidVersion { .. } => "lineage_version_invalid",
            Self::LineageFlagsReservedBitsNonZero { .. } => "lineage_flags_reserved_bits_non_zero",
            Self::DcmTraceCommitmentMustBeZeroWhenAbsent => {
                "dcm_trace_commitment_must_be_zero_when_absent"
            }
            Self::SubjectPublicKeyMustBeZeroWhenAbsent => {
                "subject_public_key_must_be_zero_when_absent"
            }
            Self::ProofMaterialV1HashMustBeZeroWhenAbsent => {
                "proof_material_v1_hash_must_be_zero_when_absent"
            }
            Self::FractalKeyV1HashMustBeZeroWhenAbsent => {
                "fractal_key_v1_hash_must_be_zero_when_absent"
            }
            Self::SubjectPublicKeyFlagForbiddenForRawEd25519 => {
                "subject_public_key_flag_forbidden_for_raw_ed25519"
            }
            Self::SubjectPublicKeyMustBeZeroForRawEd25519 => {
                "subject_public_key_must_be_zero_for_raw_ed25519"
            }
            Self::NativeDcmRootedCannotUseLegacyIntentType => {
                "native_dcm_rooted_cannot_use_legacy_intent_type"
            }
            Self::NativeDcmRootedCannotUseLegacyFreshnessMode => {
                "native_dcm_rooted_cannot_use_legacy_freshness_mode"
            }
            Self::NativeDcmRootedCannotCarryProofMaterialV1Hash => {
                "native_dcm_rooted_cannot_carry_proof_material_v1_hash"
            }
            Self::NativeDcmRootedCannotCarryFractalKeyV1Hash => {
                "native_dcm_rooted_cannot_carry_fractal_key_v1_hash"
            }
            Self::LegacyCompatibilityRequiresZeroDcmCommitmentRoot => {
                "legacy_compatibility_requires_zero_dcm_commitment_root"
            }
            Self::LegacyCompatibilityCannotCarryDcmTraceCommitment => {
                "legacy_compatibility_cannot_carry_dcm_trace_commitment"
            }
            Self::LegacyCompatibilityRequiresLegacyIntentType => {
                "legacy_compatibility_requires_legacy_intent_type"
            }
            Self::LegacyCompatibilityRequiresLegacyFreshnessMode => {
                "legacy_compatibility_requires_legacy_freshness_mode"
            }
            Self::LegacyCompatibilityRequiresProofMaterialV1Hash => {
                "legacy_compatibility_requires_proof_material_v1_hash"
            }
            Self::LegacyCompatibilityRequiresFractalKeyV1Hash => {
                "legacy_compatibility_requires_fractal_key_v1_hash"
            }
        }
    }
}

impl fmt::Display for AuthorizationLineageV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid lineage version: expected {expected}, got {actual}"
                )
            }
            Self::LineageFlagsReservedBitsNonZero { actual } => {
                write!(f, "lineage flags reserved bits non-zero: 0x{actual:04x}")
            }
            Self::DcmTraceCommitmentMustBeZeroWhenAbsent => {
                write!(f, "dcm_trace_commitment must be zero when absent")
            }
            Self::SubjectPublicKeyMustBeZeroWhenAbsent => {
                write!(f, "subject_public_key must be zero when absent")
            }
            Self::ProofMaterialV1HashMustBeZeroWhenAbsent => {
                write!(f, "proof_material_v1_hash must be zero when absent")
            }
            Self::FractalKeyV1HashMustBeZeroWhenAbsent => {
                write!(f, "fractal_key_v1_hash must be zero when absent")
            }
            Self::SubjectPublicKeyFlagForbiddenForRawEd25519 => {
                write!(
                    f,
                    "subject_public_key flag is forbidden for raw ed25519 binding"
                )
            }
            Self::SubjectPublicKeyMustBeZeroForRawEd25519 => {
                write!(f, "subject_public_key must be zero for raw ed25519 binding")
            }
            Self::NativeDcmRootedCannotUseLegacyIntentType => {
                write!(f, "native dcm-rooted lineage cannot use legacy intent type")
            }
            Self::NativeDcmRootedCannotUseLegacyFreshnessMode => {
                write!(
                    f,
                    "native dcm-rooted lineage cannot use legacy freshness mode"
                )
            }
            Self::NativeDcmRootedCannotCarryProofMaterialV1Hash => {
                write!(
                    f,
                    "native dcm-rooted lineage cannot carry proof_material_v1_hash"
                )
            }
            Self::NativeDcmRootedCannotCarryFractalKeyV1Hash => {
                write!(
                    f,
                    "native dcm-rooted lineage cannot carry fractal_key_v1_hash"
                )
            }
            Self::LegacyCompatibilityRequiresZeroDcmCommitmentRoot => {
                write!(f, "legacy compatibility requires zero dcm_commitment_root")
            }
            Self::LegacyCompatibilityCannotCarryDcmTraceCommitment => {
                write!(f, "legacy compatibility cannot carry dcm_trace_commitment")
            }
            Self::LegacyCompatibilityRequiresLegacyIntentType => {
                write!(f, "legacy compatibility requires legacy intent type")
            }
            Self::LegacyCompatibilityRequiresLegacyFreshnessMode => {
                write!(f, "legacy compatibility requires legacy freshness mode")
            }
            Self::LegacyCompatibilityRequiresProofMaterialV1Hash => {
                write!(f, "legacy compatibility requires proof_material_v1_hash")
            }
            Self::LegacyCompatibilityRequiresFractalKeyV1Hash => {
                write!(f, "legacy compatibility requires fractal_key_v1_hash")
            }
        }
    }
}

impl std::error::Error for AuthorizationLineageV1Error {}

impl AuthorizationLineageV1 {
    pub fn validate(&self) -> Result<(), AuthorizationLineageV1Error> {
        if self.version != AUTHORIZATION_LINEAGE_VERSION_V1 {
            return Err(AuthorizationLineageV1Error::InvalidVersion {
                expected: AUTHORIZATION_LINEAGE_VERSION_V1,
                actual: self.version,
            });
        }

        if self.lineage_flags
            & !(LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT
                | LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY
                | LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH
                | LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH)
            != 0
        {
            return Err(
                AuthorizationLineageV1Error::LineageFlagsReservedBitsNonZero {
                    actual: self.lineage_flags,
                },
            );
        }

        if !has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT)
            && !is_zero32(&self.dcm_trace_commitment)
        {
            return Err(AuthorizationLineageV1Error::DcmTraceCommitmentMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY)
            && !is_zero32(&self.subject_public_key)
        {
            return Err(AuthorizationLineageV1Error::SubjectPublicKeyMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH)
            && !is_zero32(&self.proof_material_v1_hash)
        {
            return Err(AuthorizationLineageV1Error::ProofMaterialV1HashMustBeZeroWhenAbsent);
        }

        if !has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH)
            && !is_zero32(&self.fractal_key_v1_hash)
        {
            return Err(AuthorizationLineageV1Error::FractalKeyV1HashMustBeZeroWhenAbsent);
        }

        if self.subject_binding_type == SubjectBindingTypeV1::RawEd25519PublicKey32
            && has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_SUBJECT_PUBLIC_KEY)
        {
            return Err(AuthorizationLineageV1Error::SubjectPublicKeyFlagForbiddenForRawEd25519);
        }

        if self.subject_binding_type == SubjectBindingTypeV1::RawEd25519PublicKey32
            && !is_zero32(&self.subject_public_key)
        {
            return Err(AuthorizationLineageV1Error::SubjectPublicKeyMustBeZeroForRawEd25519);
        }

        match self.dcm_commitment_kind {
            DcmCommitmentKindV1::DcmRootCommitmentV1 => {
                if self.intent_type == IntentTypeV1::LegacyV1ChallengeContext {
                    return Err(
                        AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyIntentType,
                    );
                }

                if self.freshness_mode == FreshnessModeV1::LegacyV1ChallengeFreshness {
                    return Err(
                        AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyFreshnessMode,
                    );
                }

                if has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH) {
                    return Err(
                        AuthorizationLineageV1Error::NativeDcmRootedCannotCarryProofMaterialV1Hash,
                    );
                }

                if has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH) {
                    return Err(
                        AuthorizationLineageV1Error::NativeDcmRootedCannotCarryFractalKeyV1Hash,
                    );
                }
            }
            DcmCommitmentKindV1::LegacyV1CompatibilityOnly => {
                if !is_zero32(&self.dcm_commitment_root) {
                    return Err(
                        AuthorizationLineageV1Error::LegacyCompatibilityRequiresZeroDcmCommitmentRoot,
                    );
                }

                if has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_DCM_TRACE_COMMITMENT)
                    || !is_zero32(&self.dcm_trace_commitment)
                {
                    return Err(
                        AuthorizationLineageV1Error::LegacyCompatibilityCannotCarryDcmTraceCommitment,
                    );
                }

                if self.intent_type != IntentTypeV1::LegacyV1ChallengeContext {
                    return Err(
                        AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyIntentType,
                    );
                }

                if self.freshness_mode != FreshnessModeV1::LegacyV1ChallengeFreshness {
                    return Err(
                        AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyFreshnessMode,
                    );
                }

                if !has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH) {
                    return Err(
                        AuthorizationLineageV1Error::LegacyCompatibilityRequiresProofMaterialV1Hash,
                    );
                }

                if !has_flag_u16(self.lineage_flags, LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH) {
                    return Err(
                        AuthorizationLineageV1Error::LegacyCompatibilityRequiresFractalKeyV1Hash,
                    );
                }
            }
        }

        Ok(())
    }

    pub fn canonical_preimage(&self) -> Result<Vec<u8>, AuthorizationLineageV1Error> {
        self.validate()?;

        let mut bytes = Vec::with_capacity(300);
        bytes.extend_from_slice(AURA_AUTHORIZATION_LINEAGE_DOMAIN_SEPARATOR_V1);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.lineage_flags.to_le_bytes());
        bytes.push(self.dcm_commitment_kind.as_u8());
        bytes.extend_from_slice(&self.dcm_commitment_root);
        bytes.extend_from_slice(&self.dcm_trace_commitment);
        bytes.push(self.subject_binding_type.as_u8());
        bytes.extend_from_slice(&self.subject_id);
        bytes.extend_from_slice(&self.subject_public_key);
        bytes.push(self.intent_type.as_u8());
        bytes.extend_from_slice(&self.intent_hash);
        bytes.push(self.freshness_mode.as_u8());
        bytes.extend_from_slice(&self.freshness_nonce);
        bytes.extend_from_slice(&self.freshness_reference.to_le_bytes());
        bytes.extend_from_slice(&self.proof_material_v1_hash);
        bytes.extend_from_slice(&self.fractal_key_v1_hash);
        Ok(bytes)
    }

    pub fn lineage_hash(&self) -> Result<[u8; HASH_LEN_V1], AuthorizationLineageV1Error> {
        Ok(sha256_bytes(&self.canonical_preimage()?))
    }

    pub fn serialized_object(&self) -> Result<Vec<u8>, AuthorizationLineageV1Error> {
        let preimage = self.canonical_preimage()?;
        let lineage_hash = sha256_bytes(&preimage);
        let mut bytes = Vec::with_capacity(preimage.len() + HASH_LEN_V1);
        bytes.extend_from_slice(&preimage);
        bytes.extend_from_slice(&lineage_hash);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorizationEnvelopeAuthKindV1 {
    AuthorizationLineageV1ExactIntent = 0x01,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationEnvelopeLineageTransportKindV1 {
    InlineAuthorizationLineageV1,
    ProofMediatedLineageStatementV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationEnvelopeValidityBoundsV1 {
    pub validity_flags: u16,
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    pub not_before_batch_number: u64,
    pub not_after_batch_number: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationEnvelopeFreshnessContextV1 {
    pub previous_nonce: Option<[u8; HASH_LEN_V1]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationEnvelopeV1 {
    pub auth_version: u8,
    pub auth_kind: AuthorizationEnvelopeAuthKindV1,
    pub controlled_account_id: [u8; HASH_LEN_V1],
    pub envelope_validity_bounds: AuthorizationEnvelopeValidityBoundsV1,
    pub lineage_transport_kind: AuthorizationEnvelopeLineageTransportKindV1,
    pub lineage_hash: [u8; HASH_LEN_V1],
    pub inline_authorization_lineage_v1: Option<AuthorizationLineageV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationEnvelopeV1Decision {
    Accept { lineage_hash: [u8; HASH_LEN_V1] },
    Reject(AuthorizationEnvelopeV1Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationEnvelopeV1Error {
    InvalidVersion {
        expected: u8,
        actual: u8,
    },
    ReservedFlagsNonZero {
        field: &'static str,
        actual: u16,
    },
    InvalidFieldCombination {
        reason: &'static str,
    },
    HashMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidNonce {
        reason: &'static str,
    },
    ModeConflict {
        reason: &'static str,
    },
}

impl fmt::Display for AuthorizationEnvelopeV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid envelope version: expected {expected}, got {actual}"
                )
            }
            Self::ReservedFlagsNonZero { field, actual } => {
                write!(f, "{field} reserved bits non-zero: 0x{actual:04x}")
            }
            Self::InvalidFieldCombination { reason } => {
                write!(f, "invalid field combination: {reason}")
            }
            Self::HashMismatch { expected, actual } => write!(
                f,
                "lineage hash mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::InvalidNonce { reason } => write!(f, "invalid nonce: {reason}"),
            Self::ModeConflict { reason } => write!(f, "mode conflict: {reason}"),
        }
    }
}

impl std::error::Error for AuthorizationEnvelopeV1Error {}

impl AuthorizationEnvelopeValidityBoundsV1 {
    fn validate(&self) -> Result<(), AuthorizationEnvelopeV1Error> {
        if self.validity_flags
            & !(VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS
                | VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS
                | VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER
                | VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER)
            != 0
        {
            return Err(AuthorizationEnvelopeV1Error::ReservedFlagsNonZero {
                field: "envelope_validity_flags",
                actual: self.validity_flags,
            });
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS,
        ) && self.not_before_unix_seconds != 0
        {
            return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "not_before_unix_seconds_must_be_zero_when_absent",
            });
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS,
        ) && self.not_after_unix_seconds != 0
        {
            return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "not_after_unix_seconds_must_be_zero_when_absent",
            });
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER,
        ) && self.not_before_batch_number != 0
        {
            return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "not_before_batch_number_must_be_zero_when_absent",
            });
        }

        if !has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER,
        ) && self.not_after_batch_number != 0
        {
            return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "not_after_batch_number_must_be_zero_when_absent",
            });
        }

        if has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_UNIX_SECONDS,
        ) && has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_UNIX_SECONDS,
        ) && self.not_after_unix_seconds <= self.not_before_unix_seconds
        {
            return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "invalid_unix_validity_window",
            });
        }

        if has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_BEFORE_BATCH_NUMBER,
        ) && has_flag_u16(
            self.validity_flags,
            VALIDITY_FLAG_HAS_NOT_AFTER_BATCH_NUMBER,
        ) && self.not_after_batch_number <= self.not_before_batch_number
        {
            return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "invalid_batch_validity_window",
            });
        }

        Ok(())
    }
}

impl AuthorizationEnvelopeV1 {
    pub fn validate(
        &self,
        freshness_context: &AuthorizationEnvelopeFreshnessContextV1,
    ) -> AuthorizationEnvelopeV1Decision {
        match self.validate_inner(freshness_context) {
            Ok(lineage_hash) => AuthorizationEnvelopeV1Decision::Accept { lineage_hash },
            Err(error) => AuthorizationEnvelopeV1Decision::Reject(error),
        }
    }

    fn validate_inner(
        &self,
        freshness_context: &AuthorizationEnvelopeFreshnessContextV1,
    ) -> Result<[u8; HASH_LEN_V1], AuthorizationEnvelopeV1Error> {
        if self.auth_version != 1 {
            return Err(AuthorizationEnvelopeV1Error::InvalidVersion {
                expected: 1,
                actual: self.auth_version,
            });
        }

        self.envelope_validity_bounds.validate()?;

        match self.lineage_transport_kind {
            AuthorizationEnvelopeLineageTransportKindV1::InlineAuthorizationLineageV1 => {}
            AuthorizationEnvelopeLineageTransportKindV1::ProofMediatedLineageStatementV1 => {
                return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                    reason: "proof_mediated_lineage_statement_not_implemented_in_thin_slice",
                });
            }
        }

        let lineage = self.inline_authorization_lineage_v1.ok_or(
            AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                reason: "inline_authorization_lineage_v1_missing",
            },
        )?;

        match lineage.validate() {
            Ok(()) => {}
            Err(AuthorizationLineageV1Error::InvalidVersion { expected, actual }) => {
                return Err(AuthorizationEnvelopeV1Error::InvalidVersion { expected, actual });
            }
            Err(AuthorizationLineageV1Error::LineageFlagsReservedBitsNonZero { actual }) => {
                return Err(AuthorizationEnvelopeV1Error::ReservedFlagsNonZero {
                    field: "lineage_flags",
                    actual,
                });
            }
            Err(error) => {
                return Err(map_lineage_error(error));
            }
        }

        if lineage.dcm_commitment_kind != DcmCommitmentKindV1::DcmRootCommitmentV1 {
            return Err(AuthorizationEnvelopeV1Error::ModeConflict {
                reason: "legacy_dcm_commitment_kind_not_allowed",
            });
        }

        if lineage.intent_type != IntentTypeV1::AuraLayer4IntentHashV1 {
            return Err(AuthorizationEnvelopeV1Error::ModeConflict {
                reason: "legacy_or_non_native_intent_type_not_allowed",
            });
        }

        if matches!(
            lineage.freshness_mode,
            FreshnessModeV1::LegacyV1ChallengeFreshness
        ) {
            return Err(AuthorizationEnvelopeV1Error::ModeConflict {
                reason: "legacy_freshness_mode_not_allowed",
            });
        }

        if has_flag_u16(
            lineage.lineage_flags,
            LINEAGE_FLAG_HAS_PROOF_MATERIAL_V1_HASH,
        ) || has_flag_u16(lineage.lineage_flags, LINEAGE_FLAG_HAS_FRACTAL_KEY_V1_HASH)
        {
            return Err(AuthorizationEnvelopeV1Error::ModeConflict {
                reason: "legacy_compatibility_fields_not_allowed",
            });
        }

        let recomputed_lineage_hash = lineage.lineage_hash().map_err(map_lineage_error)?;

        if recomputed_lineage_hash != self.lineage_hash {
            return Err(AuthorizationEnvelopeV1Error::HashMismatch {
                expected: self.lineage_hash,
                actual: recomputed_lineage_hash,
            });
        }

        validate_freshness(&lineage, freshness_context)?;

        Ok(recomputed_lineage_hash)
    }
}

fn validate_freshness(
    lineage: &AuthorizationLineageV1,
    freshness_context: &AuthorizationEnvelopeFreshnessContextV1,
) -> Result<(), AuthorizationEnvelopeV1Error> {
    if is_zero32(&lineage.freshness_nonce) {
        return Err(AuthorizationEnvelopeV1Error::InvalidNonce {
            reason: "freshness_nonce_must_not_be_zero",
        });
    }

    match lineage.freshness_mode {
        FreshnessModeV1::NonceOnly => {
            if lineage.freshness_reference != 0 {
                return Err(AuthorizationEnvelopeV1Error::InvalidFieldCombination {
                    reason: "nonce_only_requires_zero_freshness_reference",
                });
            }
        }
        FreshnessModeV1::NoncePlusUnixTimeSeconds | FreshnessModeV1::NoncePlusSlotNumber => {}
        FreshnessModeV1::LegacyV1ChallengeFreshness => {
            return Err(AuthorizationEnvelopeV1Error::ModeConflict {
                reason: "legacy_freshness_mode_not_allowed",
            });
        }
    }

    if let Some(previous_nonce) = freshness_context.previous_nonce {
        if lineage.freshness_nonce <= previous_nonce {
            return Err(AuthorizationEnvelopeV1Error::InvalidNonce {
                reason: "freshness_nonce_not_monotonic_under_placeholder_policy",
            });
        }
    }

    Ok(())
}

fn map_lineage_error(error: AuthorizationLineageV1Error) -> AuthorizationEnvelopeV1Error {
    match error {
        AuthorizationLineageV1Error::LineageFlagsReservedBitsNonZero { actual } => {
            AuthorizationEnvelopeV1Error::ReservedFlagsNonZero {
                field: "lineage_flags",
                actual,
            }
        }
        AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyIntentType
        | AuthorizationLineageV1Error::NativeDcmRootedCannotUseLegacyFreshnessMode
        | AuthorizationLineageV1Error::NativeDcmRootedCannotCarryProofMaterialV1Hash
        | AuthorizationLineageV1Error::NativeDcmRootedCannotCarryFractalKeyV1Hash
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresZeroDcmCommitmentRoot
        | AuthorizationLineageV1Error::LegacyCompatibilityCannotCarryDcmTraceCommitment
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyIntentType
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresLegacyFreshnessMode
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresProofMaterialV1Hash
        | AuthorizationLineageV1Error::LegacyCompatibilityRequiresFractalKeyV1Hash => {
            AuthorizationEnvelopeV1Error::ModeConflict {
                reason: error.reject_reason(),
            }
        }
        _ => AuthorizationEnvelopeV1Error::InvalidFieldCombination {
            reason: error.reject_reason(),
        },
    }
}

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

fn has_flag_u16(flags: u16, flag: u16) -> bool {
    flags & flag != 0
}

fn has_flag_u8(flags: u8, flag: u8) -> bool {
    flags & flag != 0
}

fn is_zero32(bytes: &[u8; HASH_LEN_V1]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
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
