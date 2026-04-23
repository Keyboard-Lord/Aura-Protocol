//! Layer 4 state-transition prototype for the thin executable slice.
//! This is not the final Merkle state engine or settlement implementation.

use core::fmt;
use std::collections::BTreeMap;

use crate::{
    sha256_bytes, AuraLayer4IntentBodyV1, AuraLayer4IntentHashV1Error, AuraLayer4OperationBodyV1,
    AuraLayer4TxKindV1, AuthorizationEnvelopeFreshnessContextV1, AuthorizationEnvelopeV1,
    AuthorizationEnvelopeV1Decision, AuthorizationEnvelopeV1Error, LowerHex32,
    SubjectBindingTypeV1, ACCOUNT_UPDATE_FLAG_HAS_NEXT_AUTHORIZATION_POLICY,
    ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT, HASH_LEN_V1,
};

pub const AURA_LAYER4_PROTOTYPE_STATE_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER4_PROTOTYPE_STATE_ACCOUNT_LEAF_V1";
pub const AURA_LAYER4_PROTOTYPE_STATE_ROOT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER4_PROTOTYPE_STATE_ROOT_V1";
pub const AURA_LAYER4_PROTOTYPE_STATE_EMPTY_ROOT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_LAYER4_PROTOTYPE_STATE_EMPTY_ROOT_V1";

pub const AURA_LAYER4_ACCOUNT_STATUS_ACTIVE_V1: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuraLayer4ControllerBindingV1 {
    pub binding_type: SubjectBindingTypeV1,
    pub subject_id: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuraLayer4AccountV1 {
    pub account_id: [u8; HASH_LEN_V1],
    pub controller_binding: AuraLayer4ControllerBindingV1,
    pub nonce: u64,
    pub data_commitment: [u8; HASH_LEN_V1],
    pub status_flags: u8,
    pub last_updated_batch: u64,
}

impl AuraLayer4AccountV1 {
    pub fn is_active(&self) -> bool {
        self.status_flags & AURA_LAYER4_ACCOUNT_STATUS_ACTIVE_V1 != 0
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(114);
        bytes.extend_from_slice(&self.account_id);
        bytes.push(self.controller_binding.binding_type.as_u8());
        bytes.extend_from_slice(&self.controller_binding.subject_id);
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.data_commitment);
        bytes.push(self.status_flags);
        bytes.extend_from_slice(&self.last_updated_batch.to_le_bytes());
        bytes
    }

    pub fn leaf_hash(&self) -> [u8; HASH_LEN_V1] {
        let mut preimage = Vec::with_capacity(
            AURA_LAYER4_PROTOTYPE_STATE_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1.len() + 114,
        );
        preimage.extend_from_slice(AURA_LAYER4_PROTOTYPE_STATE_ACCOUNT_LEAF_DOMAIN_SEPARATOR_V1);
        preimage.extend_from_slice(&self.canonical_bytes());
        sha256_bytes(&preimage)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraLayer4PrototypeStateV1 {
    accounts: BTreeMap<[u8; HASH_LEN_V1], AuraLayer4AccountV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuraLayer4StateTransitionResultV1 {
    pub account_id: [u8; HASH_LEN_V1],
    pub consumed_nonce: u64,
    pub pre_state_root: [u8; HASH_LEN_V1],
    pub post_state_root: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuraLayer4StateTransitionErrorV1 {
    DuplicateAccountId {
        account_id: [u8; HASH_LEN_V1],
    },
    InvalidIntent {
        reason: &'static str,
    },
    InvalidFieldCombination {
        reason: &'static str,
    },
    UnsupportedTxKind {
        actual: AuraLayer4TxKindV1,
    },
    MissingAccount {
        account_id: [u8; HASH_LEN_V1],
    },
    InactiveAccount {
        account_id: [u8; HASH_LEN_V1],
    },
    NonceMismatch {
        expected: u64,
        actual: u64,
    },
    ControlledAccountMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    ControllerMismatch {
        expected_binding_type: SubjectBindingTypeV1,
        expected_subject_id: [u8; HASH_LEN_V1],
        actual_binding_type: SubjectBindingTypeV1,
        actual_subject_id: [u8; HASH_LEN_V1],
    },
    HashMismatch {
        field: &'static str,
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    EnvelopeRejected(AuthorizationEnvelopeV1Error),
}

impl fmt::Display for AuraLayer4StateTransitionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAccountId { account_id } => {
                write!(f, "duplicate account id: {}", LowerHex32(account_id))
            }
            Self::InvalidIntent { reason } => write!(f, "invalid intent: {reason}"),
            Self::InvalidFieldCombination { reason } => {
                write!(f, "invalid field combination: {reason}")
            }
            Self::UnsupportedTxKind { actual } => {
                write!(f, "unsupported tx kind for thin slice: {}", actual.as_u8())
            }
            Self::MissingAccount { account_id } => {
                write!(f, "missing account: {}", LowerHex32(account_id))
            }
            Self::InactiveAccount { account_id } => {
                write!(f, "inactive account: {}", LowerHex32(account_id))
            }
            Self::NonceMismatch { expected, actual } => {
                write!(f, "nonce mismatch: expected {expected}, got {actual}")
            }
            Self::ControlledAccountMismatch { expected, actual } => write!(
                f,
                "controlled account mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::ControllerMismatch {
                expected_binding_type,
                expected_subject_id,
                actual_binding_type,
                actual_subject_id,
            } => write!(
                f,
                "controller mismatch: expected ({}, {}), got ({}, {})",
                expected_binding_type.as_u8(),
                LowerHex32(expected_subject_id),
                actual_binding_type.as_u8(),
                LowerHex32(actual_subject_id)
            ),
            Self::HashMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} mismatch: expected {}, got {}",
                LowerHex32(expected),
                LowerHex32(actual)
            ),
            Self::EnvelopeRejected(error) => write!(f, "envelope rejected: {error}"),
        }
    }
}

impl std::error::Error for AuraLayer4StateTransitionErrorV1 {}

impl AuraLayer4PrototypeStateV1 {
    pub fn new<I>(accounts: I) -> Result<Self, AuraLayer4StateTransitionErrorV1>
    where
        I: IntoIterator<Item = AuraLayer4AccountV1>,
    {
        let mut map = BTreeMap::new();
        for account in accounts {
            if map.insert(account.account_id, account).is_some() {
                return Err(AuraLayer4StateTransitionErrorV1::DuplicateAccountId {
                    account_id: account.account_id,
                });
            }
        }
        Ok(Self { accounts: map })
    }

    pub fn account(&self, account_id: &[u8; HASH_LEN_V1]) -> Option<&AuraLayer4AccountV1> {
        self.accounts.get(account_id)
    }

    pub fn state_root(&self) -> [u8; HASH_LEN_V1] {
        if self.accounts.is_empty() {
            return sha256_bytes(AURA_LAYER4_PROTOTYPE_STATE_EMPTY_ROOT_DOMAIN_SEPARATOR_V1);
        }

        // This is an explicit thin-slice prototype root only. It is deterministic and stable
        // for tests, but it is not the final Merkle or settlement commitment scheme.
        let mut preimage = Vec::with_capacity(
            AURA_LAYER4_PROTOTYPE_STATE_ROOT_DOMAIN_SEPARATOR_V1.len()
                + 8
                + self.accounts.len() * HASH_LEN_V1,
        );
        preimage.extend_from_slice(AURA_LAYER4_PROTOTYPE_STATE_ROOT_DOMAIN_SEPARATOR_V1);
        preimage.extend_from_slice(&(self.accounts.len() as u64).to_le_bytes());
        for (account_id, account) in &self.accounts {
            debug_assert_eq!(account_id, &account.account_id);
            preimage.extend_from_slice(&account.leaf_hash());
        }
        sha256_bytes(&preimage)
    }

    pub fn apply_account_update(
        &mut self,
        intent: &AuraLayer4IntentBodyV1,
        envelope: &AuthorizationEnvelopeV1,
        batch_number: u64,
    ) -> Result<AuraLayer4StateTransitionResultV1, AuraLayer4StateTransitionErrorV1> {
        let pre_state_root = self.state_root();
        let intent_hash = intent.intent_hash().map_err(map_intent_error)?;

        if intent.tx_kind != AuraLayer4TxKindV1::AccountUpdate {
            return Err(AuraLayer4StateTransitionErrorV1::UnsupportedTxKind {
                actual: intent.tx_kind,
            });
        }

        let operation = match intent.operation_body {
            AuraLayer4OperationBodyV1::AccountUpdate(operation) => operation,
            _ => {
                return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
                    reason: "operation_body_does_not_match_tx_kind",
                });
            }
        };

        if operation.account_update_flags & ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT == 0 {
            return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
                reason: "next_data_commitment_required_in_thin_slice",
            });
        }

        if operation.account_update_flags & ACCOUNT_UPDATE_FLAG_HAS_NEXT_AUTHORIZATION_POLICY != 0 {
            return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
                reason: "next_authorization_policy_not_supported_in_thin_slice",
            });
        }

        let account = self.accounts.get(&intent.sender_account_id).ok_or(
            AuraLayer4StateTransitionErrorV1::MissingAccount {
                account_id: intent.sender_account_id,
            },
        )?;

        if !account.is_active() {
            return Err(AuraLayer4StateTransitionErrorV1::InactiveAccount {
                account_id: account.account_id,
            });
        }

        if account.nonce != intent.sender_nonce {
            return Err(AuraLayer4StateTransitionErrorV1::NonceMismatch {
                expected: account.nonce,
                actual: intent.sender_nonce,
            });
        }

        match envelope.validate(&AuthorizationEnvelopeFreshnessContextV1::default()) {
            AuthorizationEnvelopeV1Decision::Accept { .. } => {}
            AuthorizationEnvelopeV1Decision::Reject(error) => {
                return Err(AuraLayer4StateTransitionErrorV1::EnvelopeRejected(error));
            }
        }

        if envelope.controlled_account_id != intent.sender_account_id {
            return Err(
                AuraLayer4StateTransitionErrorV1::ControlledAccountMismatch {
                    expected: intent.sender_account_id,
                    actual: envelope.controlled_account_id,
                },
            );
        }

        validate_envelope_validity_bounds(intent, envelope)?;

        let lineage = envelope.inline_authorization_lineage_v1.ok_or(
            AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
                reason: "inline_authorization_lineage_v1_missing_after_validation",
            },
        )?;

        if lineage.subject_binding_type != account.controller_binding.binding_type
            || lineage.subject_id != account.controller_binding.subject_id
        {
            return Err(AuraLayer4StateTransitionErrorV1::ControllerMismatch {
                expected_binding_type: account.controller_binding.binding_type,
                expected_subject_id: account.controller_binding.subject_id,
                actual_binding_type: lineage.subject_binding_type,
                actual_subject_id: lineage.subject_id,
            });
        }

        if lineage.intent_hash != intent_hash {
            return Err(AuraLayer4StateTransitionErrorV1::HashMismatch {
                field: "intent_hash",
                expected: intent_hash,
                actual: lineage.intent_hash,
            });
        }

        let next_nonce = account.nonce.checked_add(1).ok_or(
            AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
                reason: "sender_nonce_overflow",
            },
        )?;

        let account = self
            .accounts
            .get_mut(&intent.sender_account_id)
            .expect("validated account must exist for mutation");
        account.data_commitment = operation.next_data_commitment;
        account.nonce = next_nonce;
        account.last_updated_batch = batch_number;

        let post_state_root = self.state_root();

        Ok(AuraLayer4StateTransitionResultV1 {
            account_id: intent.sender_account_id,
            consumed_nonce: intent.sender_nonce,
            pre_state_root,
            post_state_root,
        })
    }
}

fn validate_envelope_validity_bounds(
    intent: &AuraLayer4IntentBodyV1,
    envelope: &AuthorizationEnvelopeV1,
) -> Result<(), AuraLayer4StateTransitionErrorV1> {
    if envelope.envelope_validity_bounds.validity_flags != intent.validity_flags {
        return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
            reason: "envelope_validity_flags_must_equal_intent_validity_flags_in_thin_slice",
        });
    }

    if envelope.envelope_validity_bounds.not_before_unix_seconds < intent.not_before_unix_seconds {
        return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
            reason: "envelope_not_before_unix_seconds_expands_intent_window",
        });
    }

    if envelope.envelope_validity_bounds.not_after_unix_seconds > intent.not_after_unix_seconds {
        return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
            reason: "envelope_not_after_unix_seconds_expands_intent_window",
        });
    }

    if envelope.envelope_validity_bounds.not_before_batch_number < intent.not_before_batch_number {
        return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
            reason: "envelope_not_before_batch_number_expands_intent_window",
        });
    }

    if envelope.envelope_validity_bounds.not_after_batch_number > intent.not_after_batch_number {
        return Err(AuraLayer4StateTransitionErrorV1::InvalidFieldCombination {
            reason: "envelope_not_after_batch_number_expands_intent_window",
        });
    }

    Ok(())
}

fn map_intent_error(error: AuraLayer4IntentHashV1Error) -> AuraLayer4StateTransitionErrorV1 {
    AuraLayer4StateTransitionErrorV1::InvalidIntent {
        reason: error.reject_reason(),
    }
}
