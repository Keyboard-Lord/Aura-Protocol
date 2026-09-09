//! Fixed V2 presentation wire. Derivation remains owned by `aura_udot_v2`.
use aura_udot_v2::{derive_udot_v2, AuraHashBytes, UdotHashError};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdotBundleV2 {
    pub proof_hash_hex: String,
    pub seal_line: String,
    pub crest: String,
    pub matrix_sequence: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdotBundleV2Error {
    Hash(UdotHashError),
    ProofHashMismatch,
    ArtifactMismatch { field: &'static str },
}

impl fmt::Display for UdotBundleV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash(error) => write!(f, "invalid proof hash: {error}"),
            Self::ProofHashMismatch => write!(f, "UDOT proof hash does not match the expected reference"),
            Self::ArtifactMismatch { field } => write!(f, "UDOT {field} does not match the proof reference"),
        }
    }
}

impl std::error::Error for UdotBundleV2Error {}

/// Derive the four-field bundle without version inference or input normalization.
pub fn generate_udot_bundle_v2(proof_hash_hex: &str) -> Result<UdotBundleV2, UdotBundleV2Error> {
    let hash = AuraHashBytes::from_canonical_hex(proof_hash_hex).map_err(UdotBundleV2Error::Hash)?;
    let artifacts = derive_udot_v2(hash);
    Ok(UdotBundleV2 {
        proof_hash_hex: proof_hash_hex.to_owned(),
        seal_line: artifacts.seal_line.to_string(),
        crest: artifacts.crest.to_string(),
        matrix_sequence: artifacts.matrix_sequence.to_string(),
    })
}

/// Deserialization establishes shape only. Admission also recomputes every glyph.
pub fn validate_udot_bundle_v2(
    bundle: &UdotBundleV2,
    expected_proof_hash_hex: &str,
) -> Result<UdotBundleV2, UdotBundleV2Error> {
    let expected = generate_udot_bundle_v2(expected_proof_hash_hex)?;
    AuraHashBytes::from_canonical_hex(&bundle.proof_hash_hex).map_err(UdotBundleV2Error::Hash)?;
    if bundle.proof_hash_hex != expected.proof_hash_hex {
        return Err(UdotBundleV2Error::ProofHashMismatch);
    }
    for (field, actual, required) in [
        ("seal_line", &bundle.seal_line, &expected.seal_line),
        ("crest", &bundle.crest, &expected.crest),
        ("matrix_sequence", &bundle.matrix_sequence, &expected.matrix_sequence),
    ] {
        if actual != required {
            return Err(UdotBundleV2Error::ArtifactMismatch { field });
        }
    }
    Ok(expected)
}
