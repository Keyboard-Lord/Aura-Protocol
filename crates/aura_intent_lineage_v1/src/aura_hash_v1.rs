//! Legacy byte encoding and SHA-256 root for Aura messages - DEPRECATED.
//!
//! # Deprecated
//! This module implements AURA_HASH_V1 which uses SHA-256 and produces 256-bit output.
//! The active protocol uses AURA_HASH_V2 (H_521 with SHA3-512) via `storm_hash521_v1`.
//!
//! Use `crate::storm_hash521_v1` for all new implementations.
//!
//! This module is preserved only for historical compatibility and testing against
//! known vectors. It will be removed in a future release.

use core::fmt;

use unicode_normalization::UnicodeNormalization;

use crate::{sha256_bytes, HASH_LEN_V1};

pub const AURA_HASH_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_HASH_V1";
pub const AURA_HASH_V1_LENGTH_PREFIX_BYTES: usize = 8;
pub const AURA_HASH_V1_BOM_CODEPOINT: char = '\u{feff}';

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuraHashV1Error {
    InvalidUtf8 { valid_up_to: usize },
    MessageContainsBom { index: usize },
    MessageLengthExceedsU64 { actual: usize },
}

impl AuraHashV1Error {
    pub const fn reject_reason(self) -> &'static str {
        match self {
            Self::InvalidUtf8 { .. } => "message_must_be_valid_utf8",
            Self::MessageContainsBom { .. } => "message_contains_bom",
            Self::MessageLengthExceedsU64 { .. } => "message_length_exceeds_u64",
        }
    }
}

impl fmt::Display for AuraHashV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 { valid_up_to } => {
                write!(f, "message must be valid UTF-8 text, valid up to byte {valid_up_to}")
            }
            Self::MessageContainsBom { index } => {
                write!(f, "message contains a BOM codepoint at character index {index}")
            }
            Self::MessageLengthExceedsU64 { actual } => {
                write!(f, "message length exceeds u64 range: {actual}")
            }
        }
    }
}

impl std::error::Error for AuraHashV1Error {}

pub fn normalize_text_message_v1(message: &str) -> Result<String, AuraHashV1Error> {
    let normalized_nfc = message.nfc().collect::<String>();
    let normalized_line_endings = normalized_nfc.replace("\r\n", "\n").replace('\r', "\n");

    if let Some((index, _)) = normalized_line_endings
        .char_indices()
        .find(|(_, value)| *value == AURA_HASH_V1_BOM_CODEPOINT)
    {
        return Err(AuraHashV1Error::MessageContainsBom { index });
    }

    Ok(normalized_line_endings)
}

pub fn decode_and_normalize_message_utf8_v1(
    message_utf8: &[u8],
) -> Result<String, AuraHashV1Error> {
    let decoded = core::str::from_utf8(message_utf8).map_err(|error| {
        AuraHashV1Error::InvalidUtf8 {
            valid_up_to: error.valid_up_to(),
        }
    })?;
    normalize_text_message_v1(decoded)
}

pub fn canonical_text_payload_bytes_from_text_v1(
    message: &str,
) -> Result<Vec<u8>, AuraHashV1Error> {
    let normalized = normalize_text_message_v1(message)?;
    Ok(normalized.into_bytes())
}

pub fn canonical_text_payload_bytes_v1(
    message_utf8: &[u8],
) -> Result<Vec<u8>, AuraHashV1Error> {
    let normalized = decode_and_normalize_message_utf8_v1(message_utf8)?;
    Ok(normalized.into_bytes())
}

pub fn canonical_message_bytes_v1(message_bytes: &[u8]) -> Result<Vec<u8>, AuraHashV1Error> {
    let length = u64::try_from(message_bytes.len()).map_err(|_| {
        AuraHashV1Error::MessageLengthExceedsU64 {
            actual: message_bytes.len(),
        }
    })?;

    let mut canonical_bytes =
        Vec::with_capacity(AURA_HASH_V1_LENGTH_PREFIX_BYTES + message_bytes.len());
    canonical_bytes.extend_from_slice(&length.to_le_bytes());
    canonical_bytes.extend_from_slice(message_bytes);
    Ok(canonical_bytes)
}

pub fn canonical_message_hash_preimage_v1(
    message_bytes: &[u8],
) -> Result<Vec<u8>, AuraHashV1Error> {
    let canonical_bytes = canonical_message_bytes_v1(message_bytes)?;
    Ok(hash_preimage_from_canonical_message_bytes_v1(&canonical_bytes))
}

pub fn aura_hash_v1(message_bytes: &[u8]) -> Result<[u8; HASH_LEN_V1], AuraHashV1Error> {
    let preimage = canonical_message_hash_preimage_v1(message_bytes)?;
    Ok(sha256_bytes(&preimage))
}

fn hash_preimage_from_canonical_message_bytes_v1(canonical_bytes: &[u8]) -> Vec<u8> {
    let mut preimage =
        Vec::with_capacity(AURA_HASH_V1_DOMAIN_SEPARATOR.len() + canonical_bytes.len());
    preimage.extend_from_slice(AURA_HASH_V1_DOMAIN_SEPARATOR);
    preimage.extend_from_slice(canonical_bytes);
    preimage
}
