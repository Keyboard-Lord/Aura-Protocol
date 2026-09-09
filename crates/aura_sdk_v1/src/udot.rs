//! Versioned UDOT compatibility and fixed V2 wallet rendering. Canonical bundle: udot_bundle_v2.
use crate::{AuraSdkErrorV1, UdotArtifactKind, UdotVersion};
use aura_udot_v2::{
    aura_hash_from_wallet_visual_v1 as aura_hash_from_wallet_visual_inner,
    derive_udot_v1_legacy, derive_udot_v2, derive_wallet_visual_v1 as derive_wallet_visual_inner,
    parse_udot_artifact as parse_udot_artifact_inner,
    validate_udot_artifact as validate_udot_artifact_inner, AuraHashBytes,
};
use serde::{Deserialize, Serialize};

/// ```compile_fail
/// use aura_sdk_v1::legacy::GenerateUdotArtifactsRequestV1;
///
/// let _ = GenerateUdotArtifactsRequestV1 {
///     aura_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000",
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerateUdotArtifactsRequestV1<'a> {
    pub udot_version: UdotVersion,
    pub aura_hash_hex: &'a str,
}

/// ```compile_fail
/// use aura_sdk_v1::{ParseUdotArtifactRequestV1, UdotArtifactKind};
///
/// let _ = ParseUdotArtifactRequestV1 {
///     artifact_kind: UdotArtifactKind::SealLine,
///     serialized_artifact: "◦◌∘○∘⟡◎○○◦○∘•⟡∙∘",
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseUdotArtifactRequestV1<'a> {
    pub udot_version: UdotVersion,
    pub artifact_kind: UdotArtifactKind,
    pub serialized_artifact: &'a str,
}

/// ```compile_fail
/// use aura_sdk_v1::{UdotArtifactKind, ValidateUdotArtifactRequestV1};
///
/// let _ = ValidateUdotArtifactRequestV1 {
///     artifact_kind: UdotArtifactKind::SealLine,
///     aura_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000",
///     serialized_artifact: "◦◌∘○∘⟡◎○○◦○∘•⟡∙∘",
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidateUdotArtifactRequestV1<'a> {
    pub udot_version: UdotVersion,
    pub artifact_kind: UdotArtifactKind,
    pub aura_hash_hex: &'a str,
    pub serialized_artifact: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdotArtifactEnvelopeV1 {
    pub udot_version: UdotVersion,
    pub artifact_kind: UdotArtifactKind,
    pub serialized_artifact: String,
}

impl UdotArtifactEnvelopeV1 {
    pub fn as_str(&self) -> &str {
        &self.serialized_artifact
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedUdotArtifactsV1 {
    pub udot_version: UdotVersion,
    pub aura_hash_hex: String,
    pub seal_line: UdotArtifactEnvelopeV1,
    pub crest: UdotArtifactEnvelopeV1,
    pub matrix_sequence: Option<UdotArtifactEnvelopeV1>,
    pub matrix_form: Option<UdotArtifactEnvelopeV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateUdotArtifactBundleWireRequestV1 {
    pub udot_version: UdotVersion,
    pub aura_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdotArtifactWireV1 {
    pub udot_version: UdotVersion,
    pub artifact_kind: UdotArtifactKind,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "udot_version", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UdotArtifactBundleWireV1 {
    V1Legacy {
        aura_hash_hex: String,
        seal_line: String,
        crest: String,
    },
    V2 {
        aura_hash_hex: String,
        seal_line: String,
        crest: String,
        matrix_sequence: String,
        matrix_form: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateUdotArtifactWireRequestV1 {
    pub udot_version: UdotVersion,
    pub artifact_kind: UdotArtifactKind,
    pub aura_hash_hex: String,
    pub value: String,
}

pub fn generate_udot_artifacts_v1(
    request: GenerateUdotArtifactsRequestV1<'_>,
) -> Result<GeneratedUdotArtifactsV1, AuraSdkErrorV1> {
    let aura_hash_bytes = normalize_udot_hash(request.aura_hash_hex)?;
    let aura_hash_hex = aura_hash_bytes.to_string();

    let generated = match request.udot_version {
        UdotVersion::V1Legacy => {
            let artifacts = derive_udot_v1_legacy(aura_hash_bytes);
            GeneratedUdotArtifactsV1 {
                udot_version: artifacts.format_version,
                aura_hash_hex,
                seal_line: artifact_envelope(
                    artifacts.format_version,
                    UdotArtifactKind::SealLine,
                    artifacts.seal_line.as_str(),
                ),
                crest: artifact_envelope(
                    artifacts.format_version,
                    UdotArtifactKind::Crest,
                    artifacts.crest.as_str(),
                ),
                matrix_sequence: None,
                matrix_form: None,
            }
        }
        UdotVersion::V2 => {
            let artifacts = derive_udot_v2(aura_hash_bytes);
            GeneratedUdotArtifactsV1 {
                udot_version: artifacts.format_version,
                aura_hash_hex,
                seal_line: artifact_envelope(
                    artifacts.format_version,
                    UdotArtifactKind::SealLine,
                    artifacts.seal_line.as_str(),
                ),
                crest: artifact_envelope(
                    artifacts.format_version,
                    UdotArtifactKind::Crest,
                    artifacts.crest.as_str(),
                ),
                matrix_sequence: Some(artifact_envelope(
                    artifacts.format_version,
                    UdotArtifactKind::MatrixSequence,
                    artifacts.matrix_sequence.as_str(),
                )),
                matrix_form: Some(artifact_envelope(
                    artifacts.format_version,
                    UdotArtifactKind::MatrixForm,
                    artifacts.matrix_form.as_str(),
                )),
            }
        }
    };

    Ok(generated)
}

pub fn generate_udot_artifact_bundle_wire_v1(
    request: GenerateUdotArtifactBundleWireRequestV1,
) -> Result<UdotArtifactBundleWireV1, AuraSdkErrorV1> {
    let generated = generate_udot_artifacts_v1(GenerateUdotArtifactsRequestV1 {
        udot_version: request.udot_version,
        aura_hash_hex: &request.aura_hash_hex,
    })?;

    Ok(artifact_bundle_wire(generated))
}

pub fn parse_udot_artifact_v1(
    request: ParseUdotArtifactRequestV1<'_>,
) -> Result<UdotArtifactEnvelopeV1, AuraSdkErrorV1> {
    parse_udot_artifact_inner(
        request.udot_version,
        request.artifact_kind,
        request.serialized_artifact,
    )
    .map(|parsed| artifact_envelope(parsed.version(), parsed.kind(), parsed.as_str()))
    .map_err(AuraSdkErrorV1::UdotArtifactParseFailed)
}

pub fn parse_udot_artifact_wire_v1(
    payload: UdotArtifactWireV1,
) -> Result<UdotArtifactWireV1, AuraSdkErrorV1> {
    parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
        udot_version: payload.udot_version,
        artifact_kind: payload.artifact_kind,
        serialized_artifact: &payload.value,
    })
    .map(artifact_wire_from_envelope)
}

pub fn parse_udot_artifact_bundle_wire_v1(
    payload: UdotArtifactBundleWireV1,
) -> Result<UdotArtifactBundleWireV1, AuraSdkErrorV1> {
    match payload {
        UdotArtifactBundleWireV1::V1Legacy {
            aura_hash_hex,
            seal_line,
            crest,
        } => {
            let aura_hash_hex = normalize_udot_hash(&aura_hash_hex)?.to_string();
            let seal_line = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
                udot_version: UdotVersion::V1Legacy,
                artifact_kind: UdotArtifactKind::SealLine,
                serialized_artifact: &seal_line,
            })?
            .serialized_artifact;
            let crest = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
                udot_version: UdotVersion::V1Legacy,
                artifact_kind: UdotArtifactKind::Crest,
                serialized_artifact: &crest,
            })?
            .serialized_artifact;

            Ok(UdotArtifactBundleWireV1::V1Legacy {
                aura_hash_hex,
                seal_line,
                crest,
            })
        }
        UdotArtifactBundleWireV1::V2 {
            aura_hash_hex,
            seal_line,
            crest,
            matrix_sequence,
            matrix_form,
        } => {
            let aura_hash_hex = normalize_udot_hash(&aura_hash_hex)?.to_string();
            let seal_line = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
                udot_version: UdotVersion::V2,
                artifact_kind: UdotArtifactKind::SealLine,
                serialized_artifact: &seal_line,
            })?
            .serialized_artifact;
            let crest = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
                udot_version: UdotVersion::V2,
                artifact_kind: UdotArtifactKind::Crest,
                serialized_artifact: &crest,
            })?
            .serialized_artifact;
            let matrix_sequence = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
                udot_version: UdotVersion::V2,
                artifact_kind: UdotArtifactKind::MatrixSequence,
                serialized_artifact: &matrix_sequence,
            })?
            .serialized_artifact;
            let matrix_form = parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
                udot_version: UdotVersion::V2,
                artifact_kind: UdotArtifactKind::MatrixForm,
                serialized_artifact: &matrix_form,
            })?
            .serialized_artifact;

            Ok(UdotArtifactBundleWireV1::V2 {
                aura_hash_hex,
                seal_line,
                crest,
                matrix_sequence,
                matrix_form,
            })
        }
    }
}

pub fn validate_udot_artifact_v1(
    request: ValidateUdotArtifactRequestV1<'_>,
) -> Result<UdotArtifactEnvelopeV1, AuraSdkErrorV1> {
    let aura_hash_bytes = normalize_udot_hash(request.aura_hash_hex)?;
    validate_udot_artifact_inner(
        request.udot_version,
        request.artifact_kind,
        aura_hash_bytes,
        request.serialized_artifact,
    )
    .map(|parsed| artifact_envelope(parsed.version(), parsed.kind(), parsed.as_str()))
    .map_err(AuraSdkErrorV1::UdotArtifactValidationFailed)
}

pub fn validate_udot_artifact_wire_v1(
    request: ValidateUdotArtifactWireRequestV1,
) -> Result<UdotArtifactWireV1, AuraSdkErrorV1> {
    validate_udot_artifact_v1(ValidateUdotArtifactRequestV1 {
        udot_version: request.udot_version,
        artifact_kind: request.artifact_kind,
        aura_hash_hex: &request.aura_hash_hex,
        serialized_artifact: &request.value,
    })
    .map(artifact_wire_from_envelope)
}

pub fn validate_udot_artifact_bundle_wire_v1(
    payload: UdotArtifactBundleWireV1,
    expected_aura_hash_hex: &str,
) -> Result<UdotArtifactBundleWireV1, AuraSdkErrorV1> {
    let expected_aura_hash_hex = normalize_udot_hash(expected_aura_hash_hex)?.to_string();
    let bundle = parse_udot_artifact_bundle_wire_v1(payload)?;
    let bundle_aura_hash_hex = bundle_aura_hash_hex(&bundle).to_owned();

    if bundle_aura_hash_hex != expected_aura_hash_hex {
        return Err(AuraSdkErrorV1::UdotBundleHashMismatch {
            expected_aura_hash_hex,
            bundle_aura_hash_hex,
        });
    }

    match &bundle {
        UdotArtifactBundleWireV1::V1Legacy {
            aura_hash_hex,
            seal_line,
            crest,
        } => {
            validate_udot_bundle_artifact_v1(
                UdotVersion::V1Legacy,
                UdotArtifactKind::SealLine,
                aura_hash_hex,
                seal_line,
            )?;
            validate_udot_bundle_artifact_v1(
                UdotVersion::V1Legacy,
                UdotArtifactKind::Crest,
                aura_hash_hex,
                crest,
            )?;
        }
        UdotArtifactBundleWireV1::V2 {
            aura_hash_hex,
            seal_line,
            crest,
            matrix_sequence,
            matrix_form,
        } => {
            validate_udot_bundle_artifact_v1(
                UdotVersion::V2,
                UdotArtifactKind::SealLine,
                aura_hash_hex,
                seal_line,
            )?;
            validate_udot_bundle_artifact_v1(
                UdotVersion::V2,
                UdotArtifactKind::Crest,
                aura_hash_hex,
                crest,
            )?;
            validate_udot_bundle_artifact_v1(
                UdotVersion::V2,
                UdotArtifactKind::MatrixSequence,
                aura_hash_hex,
                matrix_sequence,
            )?;
            validate_udot_bundle_artifact_v1(
                UdotVersion::V2,
                UdotArtifactKind::MatrixForm,
                aura_hash_hex,
                matrix_form,
            )?;
        }
    }

    Ok(bundle)
}

pub fn generate_wallet_visual_v1(proof_hash_hex: &str) -> Result<String, AuraSdkErrorV1> {
    let proof_hash_bytes = normalize_udot_hash(proof_hash_hex)?;
    Ok(derive_wallet_visual_inner(proof_hash_bytes).to_string())
}

pub fn parse_wallet_visual_v1(wallet_visual_v1: &str) -> Result<String, AuraSdkErrorV1> {
    parse_udot_artifact_v1(ParseUdotArtifactRequestV1 {
        udot_version: UdotVersion::V2,
        artifact_kind: UdotArtifactKind::MatrixForm,
        serialized_artifact: wallet_visual_v1,
    })
    .map(|parsed| parsed.serialized_artifact)
}

pub fn validate_wallet_visual_v1(
    proof_hash_hex: &str,
    wallet_visual_v1: &str,
) -> Result<String, AuraSdkErrorV1> {
    validate_udot_artifact_v1(ValidateUdotArtifactRequestV1 {
        udot_version: UdotVersion::V2,
        artifact_kind: UdotArtifactKind::MatrixForm,
        aura_hash_hex: proof_hash_hex,
        serialized_artifact: wallet_visual_v1,
    })
    .map(|validated| validated.serialized_artifact)
}

pub fn proof_hash_hex_from_wallet_visual_v1(
    wallet_visual_v1: &str,
) -> Result<String, AuraSdkErrorV1> {
    aura_hash_from_wallet_visual_inner(wallet_visual_v1)
        .map(|proof_hash_bytes| proof_hash_bytes.to_string())
        .map_err(AuraSdkErrorV1::UdotArtifactParseFailed)
}

pub(crate) fn normalize_udot_hash(input: &str) -> Result<AuraHashBytes, AuraSdkErrorV1> {
    AuraHashBytes::from_canonical_hex(input).map_err(AuraSdkErrorV1::UdotHashNormalizationFailed)
}

fn artifact_envelope(
    udot_version: UdotVersion,
    artifact_kind: UdotArtifactKind,
    serialized_artifact: &str,
) -> UdotArtifactEnvelopeV1 {
    UdotArtifactEnvelopeV1 {
        udot_version,
        artifact_kind,
        serialized_artifact: serialized_artifact.to_owned(),
    }
}

fn artifact_wire(
    udot_version: UdotVersion,
    artifact_kind: UdotArtifactKind,
    value: &str,
) -> UdotArtifactWireV1 {
    UdotArtifactWireV1 {
        udot_version,
        artifact_kind,
        value: value.to_owned(),
    }
}

fn artifact_wire_from_envelope(envelope: UdotArtifactEnvelopeV1) -> UdotArtifactWireV1 {
    artifact_wire(
        envelope.udot_version,
        envelope.artifact_kind,
        &envelope.serialized_artifact,
    )
}

fn artifact_bundle_wire(generated: GeneratedUdotArtifactsV1) -> UdotArtifactBundleWireV1 {
    match generated.udot_version {
        UdotVersion::V1Legacy => UdotArtifactBundleWireV1::V1Legacy {
            aura_hash_hex: generated.aura_hash_hex,
            seal_line: generated.seal_line.serialized_artifact,
            crest: generated.crest.serialized_artifact,
        },
        UdotVersion::V2 => UdotArtifactBundleWireV1::V2 {
            aura_hash_hex: generated.aura_hash_hex,
            seal_line: generated.seal_line.serialized_artifact,
            crest: generated.crest.serialized_artifact,
            matrix_sequence: generated
                .matrix_sequence
                .expect("UDOT V2 bundle must include matrix_sequence")
                .serialized_artifact,
            matrix_form: generated
                .matrix_form
                .expect("UDOT V2 bundle must include matrix_form")
                .serialized_artifact,
        },
    }
}

fn bundle_aura_hash_hex(bundle: &UdotArtifactBundleWireV1) -> &str {
    match bundle {
        UdotArtifactBundleWireV1::V1Legacy { aura_hash_hex, .. }
        | UdotArtifactBundleWireV1::V2 { aura_hash_hex, .. } => aura_hash_hex,
    }
}

fn validate_udot_bundle_artifact_v1(
    udot_version: UdotVersion,
    artifact_kind: UdotArtifactKind,
    aura_hash_hex: &str,
    value: &str,
) -> Result<(), AuraSdkErrorV1> {
    validate_udot_artifact_wire_v1(ValidateUdotArtifactWireRequestV1 {
        udot_version,
        artifact_kind,
        aura_hash_hex: aura_hash_hex.to_owned(),
        value: value.to_owned(),
    })?;
    Ok(())
}
