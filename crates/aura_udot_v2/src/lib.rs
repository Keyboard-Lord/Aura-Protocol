//! Deterministic Aura UDOT implementation for the frozen UDOT V2 surface,
//! with explicit legacy V1 compatibility where the hardened specs require it.

mod artifact;
mod hash;
mod legacy_v1;
mod v2;

use sha2::{Digest, Sha256};

pub use artifact::{
    parse_udot_artifact, CrestV1, CrestV2, MatrixFormV2, MatrixSequenceV2, ParsedUdotArtifact,
    SealLineV1, SealLineV2, UdotArtifactKind, UdotParseError, UdotValidationError, UdotVersion,
    UDOT_V1_LEGACY_SPEC_VERSION, UDOT_V2_SPEC_VERSION,
};
pub use hash::{AuraHashBytes, UdotHashError, UDOT_HASH_LEN};
pub use legacy_v1::{derive_udot_v1_legacy, UdotLegacyV1Artifacts};
pub use v2::{
    aura_hash_from_wallet_sequence_v1, aura_hash_from_wallet_visual_v1, derive_udot_v2,
    derive_wallet_sequence_v1, derive_wallet_visual_v1, UdotV2Artifacts,
};

pub const UDOT_DIGEST_LEN: usize = 32;
pub const AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_UDOT_SEAL_LINE_V1";
pub const AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_UDOT_SEAL_V1";
pub fn validate_udot_artifact(
    version: UdotVersion,
    kind: UdotArtifactKind,
    aura_hash_bytes: AuraHashBytes,
    candidate: &str,
) -> Result<ParsedUdotArtifact, UdotValidationError> {
    let parsed = parse_udot_artifact(version, kind, candidate)?;
    let expected = expected_artifact(version, kind, aura_hash_bytes)?;

    if parsed.as_str() != expected.as_str() {
        return Err(UdotValidationError::Mismatch {
            version,
            kind,
            expected: expected.to_string(),
            actual: parsed.to_string(),
        });
    }

    Ok(parsed)
}

fn expected_artifact(
    version: UdotVersion,
    kind: UdotArtifactKind,
    aura_hash_bytes: AuraHashBytes,
) -> Result<ParsedUdotArtifact, UdotValidationError> {
    let expected = match (version, kind) {
        (UdotVersion::V1Legacy, UdotArtifactKind::SealLine) => {
            ParsedUdotArtifact::SealLineV1(derive_udot_v1_legacy(aura_hash_bytes).seal_line)
        }
        (UdotVersion::V1Legacy, UdotArtifactKind::Crest) => {
            ParsedUdotArtifact::CrestV1(derive_udot_v1_legacy(aura_hash_bytes).crest)
        }
        (UdotVersion::V2, UdotArtifactKind::SealLine) => {
            ParsedUdotArtifact::SealLineV2(derive_udot_v2(aura_hash_bytes).seal_line)
        }
        (UdotVersion::V2, UdotArtifactKind::Crest) => {
            ParsedUdotArtifact::CrestV2(derive_udot_v2(aura_hash_bytes).crest)
        }
        (UdotVersion::V2, UdotArtifactKind::MatrixSequence) => {
            ParsedUdotArtifact::MatrixSequenceV2(derive_udot_v2(aura_hash_bytes).matrix_sequence)
        }
        (UdotVersion::V2, UdotArtifactKind::MatrixForm) => {
            ParsedUdotArtifact::MatrixFormV2(derive_udot_v2(aura_hash_bytes).matrix_form)
        }
        (version, kind) => {
            return Err(UdotValidationError::Parse(
                UdotParseError::UnsupportedArtifactForVersion { version, kind },
            ))
        }
    };

    Ok(expected)
}

pub(crate) fn sha256_domain_separated(
    domain_separator: &[u8],
    aura_hash_bytes: AuraHashBytes,
) -> [u8; UDOT_DIGEST_LEN] {
    let mut preimage = Vec::with_capacity(domain_separator.len() + UDOT_HASH_LEN);
    preimage.extend_from_slice(domain_separator);
    preimage.extend_from_slice(aura_hash_bytes.as_bytes());

    let digest = Sha256::digest(&preimage);
    let mut output = [0u8; UDOT_DIGEST_LEN];
    output.copy_from_slice(&digest);
    output
}
