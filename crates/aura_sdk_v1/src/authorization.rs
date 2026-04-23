use crate::submission::{validate_submit_proof_request_wire_v1, GenerateSubmitProofRequestV1};
use crate::udot::normalize_udot_hash;
use crate::{generate_submit_proof_request_v1, AuraSdkErrorV1, SubmitProofRequestWireV1};
use serde::{Deserialize, Serialize};

/// ```compile_fail
/// use aura_sdk_v1::{GenerateAuthorizationIntentV1, GenerateSubmitProofRequestV1};
///
/// let _ = GenerateAuthorizationIntentV1 {
///     intent_id_hex: String::from("0000000000000000000000000000000000000000000000000000000000000000"),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateAuthorizationIntentV1 {
    pub intent_id_hex: String,
    pub submit_proof_request: GenerateSubmitProofRequestV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationIntentVersionV1 {
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationSubjectBindingTypeV1 {
    SubmitterPubkeyBase58,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationIntentTypeV1 {
    #[serde(rename = "opaque-intent-hash-32")]
    OpaqueIntentHash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationFreshnessBindingTypeV1 {
    ChallengePubkeyBase58,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLineageBindingV1 {
    pub subject_binding_type: AuthorizationSubjectBindingTypeV1,
    pub subject_binding: String,
    pub intent_type: AuthorizationIntentTypeV1,
    pub intent_commitment_hex: String,
    pub freshness_binding_type: AuthorizationFreshnessBindingTypeV1,
    pub freshness_binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationIntentEnvelopeV1 {
    pub intent_version: AuthorizationIntentVersionV1,
    pub intent_id_hex: String,
    pub authorization_lineage: AuthorizationLineageBindingV1,
    pub submit_proof_request: SubmitProofRequestWireV1,
}

pub fn generate_authorization_intent_v1(
    request: GenerateAuthorizationIntentV1,
) -> Result<AuthorizationIntentEnvelopeV1, AuraSdkErrorV1> {
    let intent_id_hex = normalize_udot_hash(&request.intent_id_hex)?.to_string();
    let submit_proof_request = generate_submit_proof_request_v1(request.submit_proof_request)?;

    validate_authorization_intent_envelope_v1(AuthorizationIntentEnvelopeV1 {
        intent_version: AuthorizationIntentVersionV1::V1,
        intent_id_hex: intent_id_hex.clone(),
        authorization_lineage: AuthorizationLineageBindingV1 {
            subject_binding_type: AuthorizationSubjectBindingTypeV1::SubmitterPubkeyBase58,
            subject_binding: submit_proof_request.submitter_pubkey_base58.clone(),
            intent_type: AuthorizationIntentTypeV1::OpaqueIntentHash32,
            intent_commitment_hex: intent_id_hex,
            freshness_binding_type: AuthorizationFreshnessBindingTypeV1::ChallengePubkeyBase58,
            freshness_binding: submit_proof_request.challenge_pubkey_base58.clone(),
        },
        submit_proof_request,
    })
}

pub fn validate_authorization_intent_envelope_v1(
    payload: AuthorizationIntentEnvelopeV1,
) -> Result<AuthorizationIntentEnvelopeV1, AuraSdkErrorV1> {
    let intent_id_hex = normalize_udot_hash(&payload.intent_id_hex)?.to_string();
    let submit_proof_request = validate_submit_proof_request_wire_v1(payload.submit_proof_request)?;
    let authorization_lineage = validate_authorization_lineage_binding_v1(
        payload.authorization_lineage,
        &intent_id_hex,
        &submit_proof_request,
    )?;

    Ok(AuthorizationIntentEnvelopeV1 {
        intent_version: payload.intent_version,
        intent_id_hex,
        authorization_lineage,
        submit_proof_request,
    })
}

fn validate_authorization_lineage_binding_v1(
    payload: AuthorizationLineageBindingV1,
    intent_id_hex: &str,
    submit_proof_request: &SubmitProofRequestWireV1,
) -> Result<AuthorizationLineageBindingV1, AuraSdkErrorV1> {
    let intent_commitment_hex = normalize_udot_hash(&payload.intent_commitment_hex)?.to_string();

    if payload.subject_binding != submit_proof_request.submitter_pubkey_base58 {
        return Err(AuraSdkErrorV1::AuthorizationIntentFieldMismatch {
            field: "authorization_lineage.subject_binding",
            expected: submit_proof_request.submitter_pubkey_base58.clone(),
            actual: payload.subject_binding,
        });
    }

    if intent_commitment_hex != intent_id_hex {
        return Err(AuraSdkErrorV1::AuthorizationIntentFieldMismatch {
            field: "authorization_lineage.intent_commitment_hex",
            expected: intent_id_hex.to_owned(),
            actual: intent_commitment_hex,
        });
    }

    if payload.freshness_binding != submit_proof_request.challenge_pubkey_base58 {
        return Err(AuraSdkErrorV1::AuthorizationIntentFieldMismatch {
            field: "authorization_lineage.freshness_binding",
            expected: submit_proof_request.challenge_pubkey_base58.clone(),
            actual: payload.freshness_binding,
        });
    }

    Ok(AuthorizationLineageBindingV1 {
        subject_binding_type: payload.subject_binding_type,
        subject_binding: submit_proof_request.submitter_pubkey_base58.clone(),
        intent_type: payload.intent_type,
        intent_commitment_hex: intent_id_hex.to_owned(),
        freshness_binding_type: payload.freshness_binding_type,
        freshness_binding: submit_proof_request.challenge_pubkey_base58.clone(),
    })
}
