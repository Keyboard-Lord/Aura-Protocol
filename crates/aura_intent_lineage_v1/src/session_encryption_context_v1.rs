//! Aura Session Encryption V1 canonical context encoding.

use core::fmt;

use crate::{validate_context_bytes_v1, HASH_LEN_V1, STORM_CONTEXT_V1_LEN};

pub const SESSION_ENCRYPTION_CONTEXT_V1_VERSION: u8 = 0x01;
pub const SESSION_ENCRYPTION_CONTEXT_V1_LEN: usize = 209;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuraSessionEncryptionContextV1 {
    pub version: u8,
    pub storm_claim_digest: [u8; HASH_LEN_V1],
    pub sender_id: [u8; HASH_LEN_V1],
    pub receiver_id: [u8; HASH_LEN_V1],
    pub freshness_nonce: [u8; HASH_LEN_V1],
    pub valid_from: u64,
    pub valid_until: u64,
    pub route_tag: [u8; HASH_LEN_V1],
    pub session_key_id: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormSessionEncryptionFieldsV1 {
    pub freshness_nonce: [u8; HASH_LEN_V1],
    pub valid_from: u64,
    pub valid_until: u64,
    pub route_tag: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEncryptionContextErrorV1 {
    InvalidVersion { expected: u8, actual: u8 },
    InvalidValidityWindow { valid_from: u64, valid_until: u64 },
    InvalidStormContext(crate::StormContextErrorV1),
}

impl fmt::Display for SessionEncryptionContextErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid session encryption context version: expected {expected}, got {actual}"
                )
            }
            Self::InvalidValidityWindow {
                valid_from,
                valid_until,
            } => write!(
                f,
                "invalid session encryption validity window: valid_from {valid_from} exceeds valid_until {valid_until}"
            ),
            Self::InvalidStormContext(error) => {
                write!(f, "invalid lower-layer storm context: {error}")
            }
        }
    }
}

impl std::error::Error for SessionEncryptionContextErrorV1 {}

pub fn encode_session_encryption_context_v1(
    context: &AuraSessionEncryptionContextV1,
) -> Result<[u8; SESSION_ENCRYPTION_CONTEXT_V1_LEN], SessionEncryptionContextErrorV1> {
    validate_session_encryption_context_v1(context)?;

    let mut bytes = [0u8; SESSION_ENCRYPTION_CONTEXT_V1_LEN];
    let mut cursor = 0usize;

    bytes[cursor] = context.version;
    cursor += 1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&context.storm_claim_digest);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&context.sender_id);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&context.receiver_id);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&context.freshness_nonce);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + 8].copy_from_slice(&context.valid_from.to_le_bytes());
    cursor += 8;

    bytes[cursor..cursor + 8].copy_from_slice(&context.valid_until.to_le_bytes());
    cursor += 8;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&context.route_tag);
    cursor += HASH_LEN_V1;

    bytes[cursor..cursor + HASH_LEN_V1].copy_from_slice(&context.session_key_id);

    Ok(bytes)
}

pub fn validate_session_encryption_context_v1(
    context: &AuraSessionEncryptionContextV1,
) -> Result<(), SessionEncryptionContextErrorV1> {
    if context.version != SESSION_ENCRYPTION_CONTEXT_V1_VERSION {
        return Err(SessionEncryptionContextErrorV1::InvalidVersion {
            expected: SESSION_ENCRYPTION_CONTEXT_V1_VERSION,
            actual: context.version,
        });
    }

    if context.valid_from > context.valid_until {
        return Err(SessionEncryptionContextErrorV1::InvalidValidityWindow {
            valid_from: context.valid_from,
            valid_until: context.valid_until,
        });
    }

    Ok(())
}

pub fn extract_storm_session_encryption_fields_v1(
    storm_context_bytes: &[u8],
) -> Result<StormSessionEncryptionFieldsV1, SessionEncryptionContextErrorV1> {
    let canonical = validate_context_bytes_v1(storm_context_bytes)
        .map_err(SessionEncryptionContextErrorV1::InvalidStormContext)?;
    debug_assert_eq!(canonical.len(), STORM_CONTEXT_V1_LEN);

    let mut freshness_nonce = [0u8; HASH_LEN_V1];
    freshness_nonce.copy_from_slice(&canonical[97..129]);

    let mut valid_from_bytes = [0u8; 8];
    valid_from_bytes.copy_from_slice(&canonical[129..137]);

    let mut valid_until_bytes = [0u8; 8];
    valid_until_bytes.copy_from_slice(&canonical[137..145]);

    let mut route_tag = [0u8; HASH_LEN_V1];
    route_tag.copy_from_slice(&canonical[177..209]);

    Ok(StormSessionEncryptionFieldsV1 {
        freshness_nonce,
        valid_from: u64::from_le_bytes(valid_from_bytes),
        valid_until: u64::from_le_bytes(valid_until_bytes),
        route_tag,
    })
}
