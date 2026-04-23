//! Canonical storm context encoding for the storm lower layer.

use core::fmt;

use sha3::{Digest, Sha3_512};

pub const STORM_CONTEXT_V1_VERSION: u8 = 0x01;
pub const STORM_CONTEXT_V1_LEN: usize = 209;
pub const STORM_CONTEXT_V1_EXECUTION_DOMAIN_LABEL: &[u8] = b"AURA_STORM_EXECUTION_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormContextV1 {
    pub context_version: u8,
    pub network_id: [u8; 32],
    pub intent_hash: [u8; 32],
    pub freshness_nonce: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub controller_id: [u8; 32],
    pub route_tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormContextErrorV1 {
    InvalidLength { expected: usize, actual: usize },
    InvalidContextVersion { expected: u8, actual: u8 },
    InvalidExecutionDomain {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl fmt::Display for StormContextErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid storm context length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidContextVersion { expected, actual } => {
                write!(
                    f,
                    "invalid storm context version: expected {expected:#04x}, got {actual:#04x}"
                )
            }
            Self::InvalidExecutionDomain { .. } => {
                write!(f, "storm context execution domain does not match V1 constant")
            }
        }
    }
}

impl std::error::Error for StormContextErrorV1 {}

impl StormContextV1 {
    pub fn to_bytes(&self) -> [u8; STORM_CONTEXT_V1_LEN] {
        let mut bytes = [0u8; STORM_CONTEXT_V1_LEN];
        let mut cursor = 0usize;

        bytes[cursor] = self.context_version;
        cursor += 1;

        bytes[cursor..cursor + 32].copy_from_slice(&self.network_id);
        cursor += 32;

        let execution_domain = execution_domain_v1();
        bytes[cursor..cursor + 32].copy_from_slice(&execution_domain);
        cursor += 32;

        bytes[cursor..cursor + 32].copy_from_slice(&self.intent_hash);
        cursor += 32;

        bytes[cursor..cursor + 32].copy_from_slice(&self.freshness_nonce);
        cursor += 32;

        bytes[cursor..cursor + 8].copy_from_slice(&self.valid_from.to_le_bytes());
        cursor += 8;

        bytes[cursor..cursor + 8].copy_from_slice(&self.valid_until.to_le_bytes());
        cursor += 8;

        bytes[cursor..cursor + 32].copy_from_slice(&self.controller_id);
        cursor += 32;

        bytes[cursor..cursor + 32].copy_from_slice(&self.route_tag);
        bytes
    }
}

pub fn execution_domain_v1() -> [u8; 32] {
    let digest = Sha3_512::digest(STORM_CONTEXT_V1_EXECUTION_DOMAIN_LABEL);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest[..32]);
    bytes
}

pub fn validate_context_bytes_v1(
    bytes: &[u8],
) -> Result<[u8; STORM_CONTEXT_V1_LEN], StormContextErrorV1> {
    if bytes.len() != STORM_CONTEXT_V1_LEN {
        return Err(StormContextErrorV1::InvalidLength {
            expected: STORM_CONTEXT_V1_LEN,
            actual: bytes.len(),
        });
    }

    let mut canonical = [0u8; STORM_CONTEXT_V1_LEN];
    canonical.copy_from_slice(bytes);

    if canonical[0] != STORM_CONTEXT_V1_VERSION {
        return Err(StormContextErrorV1::InvalidContextVersion {
            expected: STORM_CONTEXT_V1_VERSION,
            actual: canonical[0],
        });
    }

    let mut actual_execution_domain = [0u8; 32];
    actual_execution_domain.copy_from_slice(&canonical[33..65]);
    let expected_execution_domain = execution_domain_v1();
    if actual_execution_domain != expected_execution_domain {
        return Err(StormContextErrorV1::InvalidExecutionDomain {
            expected: expected_execution_domain,
            actual: actual_execution_domain,
        });
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::{
        execution_domain_v1, validate_context_bytes_v1, StormContextErrorV1, StormContextV1,
        STORM_CONTEXT_V1_LEN, STORM_CONTEXT_V1_VERSION,
    };

    fn sample_context() -> StormContextV1 {
        StormContextV1 {
            context_version: STORM_CONTEXT_V1_VERSION,
            network_id: [0x11; 32],
            intent_hash: [0x22; 32],
            freshness_nonce: [0x33; 32],
            valid_from: 17,
            valid_until: 42,
            controller_id: [0x44; 32],
            route_tag: [0x55; 32],
        }
    }

    #[test]
    fn storm_context_serializes_to_exact_209_bytes() {
        let bytes = sample_context().to_bytes();

        assert_eq!(bytes.len(), STORM_CONTEXT_V1_LEN);
        assert_eq!(bytes[0], STORM_CONTEXT_V1_VERSION);
        assert_eq!(&bytes[33..65], execution_domain_v1().as_slice());
    }

    #[test]
    fn validator_rejects_wrong_execution_domain() {
        let mut bytes = sample_context().to_bytes();
        bytes[33] ^= 0xff;

        let error = validate_context_bytes_v1(&bytes).unwrap_err();
        assert!(matches!(
            error,
            StormContextErrorV1::InvalidExecutionDomain { .. }
        ));
    }
}
