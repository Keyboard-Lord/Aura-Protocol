use aura_l2_execution_v1::{
    build_deterministic_transaction_v1, build_token_transaction_authorization_sign_request_v1,
    build_token_transaction_authorization_sign_response_v1,
    build_token_transaction_authorized_notary_input_v1,
    build_token_transaction_notarization_record_v1,
    build_token_transaction_notary_acknowledgement_v1,
    build_token_transaction_notary_receipt_preimage_v1, build_token_transaction_seal_payload_v1,
    sha256_bytes, sign_token_transaction_authorization_payload_v1,
    validate_token_transaction_authorization_sign_response_v1,
    BuildDeterministicTransactionRequestV1, BuildDeterministicTransactionResponseV1,
    DeterministicTransactionPublicStatementWireV1, DeterministicTransactionWireV1,
    TokenTransactionAuthorizationEnvelopeV1, TokenTransactionAuthorizationEnvelopeWireV1,
    TokenTransactionAuthorizationSignRequestWireV1,
    TokenTransactionAuthorizationSignResponseWireV1, TokenTransactionErrorV1,
    TokenTransactionInputV1, TokenTransactionInputWireV1, TokenTransactionOutputV1,
    TokenTransactionOutputWireV1, PRIVATE_TRANSFER_BURN_KIND_V1, TOKEN_TX_VERSION_V1,
};
use aura_notarization_export_v1::{
    build_notarization_export_summary_v1, validate_notarization_record_wire_v1,
    AuraNotarizationExportErrorV1, CanonicalTokenTransactionNotarizationRecordWireV1,
    CanonicalTokenTransactionNotarizationSummaryV1,
};
use aura_notarization_render_v1::{
    render_notarization_summary_html_v1, render_notarization_summary_markdown_v1,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

pub const NOTARIZATION_AUTHORIZATION_SESSION_VERSION_V1: u32 = 1;
pub const NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1: u32 = 1;
pub const AURA_NOTARIZATION_AUTHORIZATION_SESSION_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_NOTARIZATION_AUTHORIZATION_SESSION_V1";
pub const NOTARIZATION_LOCAL_DEV_SIGNER_SCOPE_V1: &str = "local_dev_only";
pub const NOTARIZATION_LOCAL_SUBPROCESS_SIGNER_SCOPE_V1: &str = "local_subprocess_signer_v1";
pub const NOTARIZATION_SIGNER_LAUNCHER_SCOPE_V1: &str = "guided_file_carrier_v1";
const LOCAL_DEV_AUTHORIZATION_SIGNING_KEY_BYTES_V1: [u8; 32] = [0x42; 32];
const LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1: &str =
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const SIGNER_LAUNCHER_ROOT_DIRNAME_V1: &str = "aura_notarization_workbench_v1";
const SIGNER_LAUNCHER_WORKFLOW_DIRNAME_V1: &str = "authorization_signer_v1";
const SIGNER_LAUNCHER_REQUEST_FILENAME_V1: &str = "aura_authorization_sign_carrier_request.json";
const SIGNER_LAUNCHER_RESPONSE_FILENAME_V1: &str = "aura_authorization_sign_carrier_response.json";
const SIGNER_HELPER_BINARY_NAME_V1: &str = "aura_authorization_signer_v1";
const SIGNER_HELPER_PRIVATE_KEY_PLACEHOLDER_V1: &str = "<64 lowercase hex chars>";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationWorkbenchInspectionV1 {
    pub summary: CanonicalTokenTransactionNotarizationSummaryV1,
    pub markdown_receipt: String,
    pub html_receipt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationWorkbenchComposeRequestV1 {
    pub rollup_id_hex: String,
    pub asset_id_hex: String,
    pub anchor_state_root_hex: String,
    pub inputs: Vec<TokenTransactionInputWireV1>,
    pub outputs: Vec<TokenTransactionOutputWireV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationWorkbenchAuthorizationPrepareRequestV1 {
    pub compose_request: NotarizationWorkbenchComposeRequestV1,
    pub signer_public_key_hex: String,
    pub authorization_nonce_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationAuthorizationSessionV1 {
    pub session_version: u32,
    pub session_id_hex: String,
    pub compose_request: NotarizationWorkbenchComposeRequestV1,
    pub burn_summary: NotarizationWorkbenchBurnSummaryV1,
    pub transaction: DeterministicTransactionWireV1,
    pub public_statement: DeterministicTransactionPublicStatementWireV1,
    pub authorization_sign_request: TokenTransactionAuthorizationSignRequestWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationWorkbenchBurnSummaryV1 {
    pub input_count: u64,
    pub output_count: u64,
    pub admission_burn: u64,
    pub notary_burn: u64,
    pub priority_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationWorkbenchAuthorizationPrepareResponseV1 {
    pub burn_summary: NotarizationWorkbenchBurnSummaryV1,
    pub transaction: DeterministicTransactionWireV1,
    pub public_statement: DeterministicTransactionPublicStatementWireV1,
    pub authorization_sign_request: TokenTransactionAuthorizationSignRequestWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationAuthorizationCompletionRequestV1 {
    pub session: NotarizationAuthorizationSessionV1,
    pub sign_response: TokenTransactionAuthorizationSignResponseWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationAuthorizationLocalDevSignResultV1 {
    pub scope: String,
    pub session_id_hex: String,
    pub sign_response: TokenTransactionAuthorizationSignResponseWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationAuthorizationSignCarrierRequestV1 {
    pub carrier_version: u32,
    pub session_id_hex: String,
    pub authorization_sign_request: TokenTransactionAuthorizationSignRequestWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationAuthorizationSignCarrierResponseV1 {
    pub carrier_version: u32,
    pub session_id_hex: String,
    pub authorization_sign_response: TokenTransactionAuthorizationSignResponseWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationAuthorizationCarrierCompletionRequestV1 {
    pub session: NotarizationAuthorizationSessionV1,
    pub sign_carrier_response: NotarizationAuthorizationSignCarrierResponseV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationAuthorizationSignerLaunchRequestV1 {
    pub session: NotarizationAuthorizationSessionV1,
    pub private_key_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationAuthorizationSignerLauncherPlanV1 {
    pub scope: String,
    pub session_id_hex: String,
    pub request_path: String,
    pub response_path: String,
    pub signer_command: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationAuthorizationSignerLauncherLoadResultV1 {
    pub launcher: NotarizationAuthorizationSignerLauncherPlanV1,
    pub sign_carrier_response: NotarizationAuthorizationSignCarrierResponseV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationAuthorizationSignerLaunchResultV1 {
    pub scope: String,
    pub session_id_hex: String,
    pub launcher: NotarizationAuthorizationSignerLauncherPlanV1,
    pub sign_carrier_response: NotarizationAuthorizationSignCarrierResponseV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizationWorkbenchAuthorizedComposeRequestV1 {
    pub compose_request: NotarizationWorkbenchComposeRequestV1,
    pub authorization_envelope: TokenTransactionAuthorizationEnvelopeWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationWorkbenchCompositionV1 {
    pub burn_summary: NotarizationWorkbenchBurnSummaryV1,
    pub transaction: DeterministicTransactionWireV1,
    pub public_statement: DeterministicTransactionPublicStatementWireV1,
    pub notarization_record: CanonicalTokenTransactionNotarizationRecordWireV1,
    pub summary: CanonicalTokenTransactionNotarizationSummaryV1,
    pub markdown_receipt: String,
    pub html_receipt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationWorkbenchExportFileV1 {
    pub filename: String,
    pub media_type: String,
    pub contents: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotarizationWorkbenchComposeExportBundleV1 {
    pub compose_request: NotarizationWorkbenchComposeRequestV1,
    pub transaction: DeterministicTransactionWireV1,
    pub public_statement: DeterministicTransactionPublicStatementWireV1,
    pub notarization_record: CanonicalTokenTransactionNotarizationRecordWireV1,
    pub receipt_markdown: String,
    pub receipt_html: String,
}

#[derive(Debug)]
pub enum AuraNotarizationWorkbenchErrorV1 {
    InvalidJson(serde_json::Error),
    InvalidRecord(AuraNotarizationExportErrorV1),
    InvalidComposition(TokenTransactionErrorV1),
    UnsupportedAuthorizationSessionVersion {
        expected: u32,
        actual: u32,
    },
    UnsupportedAuthorizationSignCarrierVersion {
        expected: u32,
        actual: u32,
    },
    InvalidAuthorizationSession(&'static str),
    AuthorizationSignCarrierSessionMismatch {
        expected: String,
        actual: String,
    },
    UnsupportedLocalDevSignerPublicKey {
        expected: &'static str,
        actual: String,
    },
    SignerLauncherIo {
        action: &'static str,
        path: String,
        source: std::io::Error,
    },
    LocalSignerLaunchFailed(String),
    MissingFixture(std::io::Error),
}

impl core::fmt::Display for AuraNotarizationWorkbenchErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(f, "invalid workbench json: {error}"),
            Self::InvalidRecord(error) => write!(f, "{error}"),
            Self::InvalidComposition(error) => write!(f, "invalid composition request: {error}"),
            Self::UnsupportedAuthorizationSessionVersion { expected, actual } => write!(
                f,
                "unsupported authorization session version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAuthorizationSignCarrierVersion { expected, actual } => write!(
                f,
                "unsupported authorization sign carrier version: expected {expected}, got {actual}"
            ),
            Self::InvalidAuthorizationSession(field) => {
                write!(f, "invalid authorization session: {field}")
            }
            Self::AuthorizationSignCarrierSessionMismatch { expected, actual } => write!(
                f,
                "authorization sign carrier session_id_hex mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedLocalDevSignerPublicKey { expected, actual } => write!(
                f,
                "local dev signer only supports signer public key {expected}, got {actual}"
            ),
            Self::SignerLauncherIo {
                action,
                path,
                source,
            } => write!(
                f,
                "unable to {action} local signer launcher path {path}: {source}"
            ),
            Self::LocalSignerLaunchFailed(detail) => {
                write!(f, "unable to run local signer helper: {detail}")
            }
            Self::MissingFixture(error) => write!(f, "unable to load sample fixture: {error}"),
        }
    }
}

impl std::error::Error for AuraNotarizationWorkbenchErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            Self::InvalidRecord(error) => Some(error),
            Self::InvalidComposition(error) => Some(error),
            Self::UnsupportedAuthorizationSessionVersion { .. } => None,
            Self::UnsupportedAuthorizationSignCarrierVersion { .. } => None,
            Self::InvalidAuthorizationSession(_) => None,
            Self::AuthorizationSignCarrierSessionMismatch { .. } => None,
            Self::UnsupportedLocalDevSignerPublicKey { .. } => None,
            Self::SignerLauncherIo { source, .. } => Some(source),
            Self::LocalSignerLaunchFailed(_) => None,
            Self::MissingFixture(error) => Some(error),
        }
    }
}

impl From<serde_json::Error> for AuraNotarizationWorkbenchErrorV1 {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

impl From<AuraNotarizationExportErrorV1> for AuraNotarizationWorkbenchErrorV1 {
    fn from(error: AuraNotarizationExportErrorV1) -> Self {
        Self::InvalidRecord(error)
    }
}

impl From<TokenTransactionErrorV1> for AuraNotarizationWorkbenchErrorV1 {
    fn from(error: TokenTransactionErrorV1) -> Self {
        Self::InvalidComposition(error)
    }
}

fn encode_hex_lower_v1(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

pub fn inspect_notarization_record_value_v1(
    record_wire_value: serde_json::Value,
) -> Result<NotarizationWorkbenchInspectionV1, AuraNotarizationWorkbenchErrorV1> {
    let record_wire: CanonicalTokenTransactionNotarizationRecordWireV1 =
        serde_json::from_value(record_wire_value)?;
    inspect_notarization_record_wire_v1(record_wire)
}

pub fn inspect_notarization_record_wire_v1(
    record_wire: CanonicalTokenTransactionNotarizationRecordWireV1,
) -> Result<NotarizationWorkbenchInspectionV1, AuraNotarizationWorkbenchErrorV1> {
    let validated = validate_notarization_record_wire_v1(record_wire)?;
    let summary = build_notarization_export_summary_v1(validated)?;
    let markdown_receipt = render_notarization_summary_markdown_v1(&summary);
    let html_receipt = render_notarization_summary_html_v1(&summary);

    Ok(NotarizationWorkbenchInspectionV1 {
        summary,
        markdown_receipt,
        html_receipt,
    })
}

pub fn compose_notarization_value_v1(
    compose_request_value: serde_json::Value,
) -> Result<NotarizationWorkbenchCompositionV1, AuraNotarizationWorkbenchErrorV1> {
    if let Ok(request) = serde_json::from_value::<NotarizationAuthorizationCarrierCompletionRequestV1>(
        compose_request_value.clone(),
    ) {
        return complete_notarization_authorization_from_carrier_v1(request);
    }

    if let Ok(request) = serde_json::from_value::<NotarizationAuthorizationCompletionRequestV1>(
        compose_request_value.clone(),
    ) {
        return complete_notarization_authorization_v1(request);
    }

    let request: NotarizationWorkbenchAuthorizedComposeRequestV1 =
        serde_json::from_value(compose_request_value)?;
    compose_notarization_v1(request)
}

pub fn prepare_notarization_authorization_value_v1(
    prepare_request_value: serde_json::Value,
) -> Result<NotarizationAuthorizationSessionV1, AuraNotarizationWorkbenchErrorV1> {
    let request: NotarizationWorkbenchAuthorizationPrepareRequestV1 =
        serde_json::from_value(prepare_request_value)?;
    prepare_notarization_authorization_v1(request)
}

pub fn prepare_notarization_authorization_v1(
    request: NotarizationWorkbenchAuthorizationPrepareRequestV1,
) -> Result<NotarizationAuthorizationSessionV1, AuraNotarizationWorkbenchErrorV1> {
    let built = build_transaction_from_compose_request_v1(request.compose_request.clone())?;
    let public_statement = built.transaction.proof_placeholder.public_statement.clone();
    let authorization_sign_request = build_token_transaction_authorization_sign_request_v1(
        &built.transaction,
        decode_input_hex_v1("signer_public_key_hex", &request.signer_public_key_hex)?,
        decode_input_hex_v1("authorization_nonce_hex", &request.authorization_nonce_hex)?,
    )?;
    let burn_summary = build_burn_summary_v1(&built)?;
    let transaction = built.transaction.to_wire();
    let public_statement = public_statement.to_wire();
    let session_id_hex = build_authorization_session_id_hex_v1(
        &request.compose_request,
        &authorization_sign_request,
    )?;

    Ok(NotarizationAuthorizationSessionV1 {
        session_version: NOTARIZATION_AUTHORIZATION_SESSION_VERSION_V1,
        session_id_hex,
        compose_request: request.compose_request,
        burn_summary,
        transaction,
        public_statement,
        authorization_sign_request,
    })
}

pub fn complete_notarization_authorization_value_v1(
    completion_request_value: serde_json::Value,
) -> Result<NotarizationWorkbenchCompositionV1, AuraNotarizationWorkbenchErrorV1> {
    if let Ok(request) = serde_json::from_value::<NotarizationAuthorizationCarrierCompletionRequestV1>(
        completion_request_value.clone(),
    ) {
        return complete_notarization_authorization_from_carrier_v1(request);
    }

    let request: NotarizationAuthorizationCompletionRequestV1 =
        serde_json::from_value(completion_request_value)?;
    complete_notarization_authorization_v1(request)
}

pub fn complete_notarization_authorization_v1(
    request: NotarizationAuthorizationCompletionRequestV1,
) -> Result<NotarizationWorkbenchCompositionV1, AuraNotarizationWorkbenchErrorV1> {
    let authorized_request = authorized_compose_request_from_completion_v1(request)?;
    compose_notarization_v1(authorized_request)
}

pub fn complete_notarization_authorization_from_carrier_v1(
    request: NotarizationAuthorizationCarrierCompletionRequestV1,
) -> Result<NotarizationWorkbenchCompositionV1, AuraNotarizationWorkbenchErrorV1> {
    let sign_response = validate_notarization_authorization_sign_carrier_response_v1(
        &request.session,
        &request.sign_carrier_response,
    )?;
    complete_notarization_authorization_v1(NotarizationAuthorizationCompletionRequestV1 {
        session: request.session,
        sign_response,
    })
}

pub fn local_dev_sign_notarization_authorization_value_v1(
    session_value: serde_json::Value,
) -> Result<NotarizationAuthorizationLocalDevSignResultV1, AuraNotarizationWorkbenchErrorV1> {
    let session: NotarizationAuthorizationSessionV1 = serde_json::from_value(session_value)?;
    local_dev_sign_notarization_authorization_session_v1(session)
}

pub fn local_dev_sign_notarization_authorization_session_v1(
    session: NotarizationAuthorizationSessionV1,
) -> Result<NotarizationAuthorizationLocalDevSignResultV1, AuraNotarizationWorkbenchErrorV1> {
    let validated_session = validate_notarization_authorization_session_v1(&session)?;
    let signer_public_key_hex = &validated_session
        .authorization_sign_request
        .payload
        .signer_public_key_hex;
    if signer_public_key_hex != LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1 {
        return Err(
            AuraNotarizationWorkbenchErrorV1::UnsupportedLocalDevSignerPublicKey {
                expected: LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1,
                actual: signer_public_key_hex.clone(),
            },
        );
    }

    let payload = validated_session.authorization_sign_request.validate()?;
    let sign_response = build_token_transaction_authorization_sign_response_v1(
        sign_token_transaction_authorization_payload_v1(
            payload,
            LOCAL_DEV_AUTHORIZATION_SIGNING_KEY_BYTES_V1,
        )?,
    )?;

    Ok(NotarizationAuthorizationLocalDevSignResultV1 {
        scope: NOTARIZATION_LOCAL_DEV_SIGNER_SCOPE_V1.to_owned(),
        session_id_hex: validated_session.session_id_hex,
        sign_response,
    })
}

pub fn run_local_notarization_authorization_signer_value_v1(
    launch_request_value: serde_json::Value,
) -> Result<NotarizationAuthorizationSignerLaunchResultV1, AuraNotarizationWorkbenchErrorV1> {
    let request: NotarizationAuthorizationSignerLaunchRequestV1 =
        serde_json::from_value(launch_request_value)?;
    run_local_notarization_authorization_signer_v1(request)
}

pub fn run_local_notarization_authorization_signer_v1(
    mut request: NotarizationAuthorizationSignerLaunchRequestV1,
) -> Result<NotarizationAuthorizationSignerLaunchResultV1, AuraNotarizationWorkbenchErrorV1> {
    let result = (|| {
        let launcher =
            prepare_notarization_authorization_signer_launcher_v1(request.session.clone())?;
        let launch_strategy = resolve_local_signer_launch_strategy_v1()?;
        run_local_signer_subprocess_v1(
            &launch_strategy,
            &launcher,
            request.private_key_hex.as_str(),
        )?;
        let loaded =
            load_notarization_authorization_signer_launcher_response_v1(request.session.clone())?;

        Ok(NotarizationAuthorizationSignerLaunchResultV1 {
            scope: NOTARIZATION_LOCAL_SUBPROCESS_SIGNER_SCOPE_V1.to_owned(),
            session_id_hex: loaded.launcher.session_id_hex.clone(),
            launcher: loaded.launcher,
            sign_carrier_response: loaded.sign_carrier_response,
        })
    })();

    request.private_key_hex.zeroize();
    result
}

pub fn prepare_notarization_authorization_signer_launcher_value_v1(
    session_value: serde_json::Value,
) -> Result<NotarizationAuthorizationSignerLauncherPlanV1, AuraNotarizationWorkbenchErrorV1> {
    let session: NotarizationAuthorizationSessionV1 = serde_json::from_value(session_value)?;
    prepare_notarization_authorization_signer_launcher_v1(session)
}

pub fn prepare_notarization_authorization_signer_launcher_v1(
    session: NotarizationAuthorizationSessionV1,
) -> Result<NotarizationAuthorizationSignerLauncherPlanV1, AuraNotarizationWorkbenchErrorV1> {
    let validated_session = validate_notarization_authorization_session_v1(&session)?;
    let carrier_request =
        build_notarization_authorization_sign_carrier_request_v1(validated_session.clone())?;
    let launcher_paths = build_signer_launcher_paths_v1(&validated_session.session_id_hex);
    let launcher_plan = build_signer_launcher_plan_v1(&validated_session);

    std::fs::create_dir_all(&launcher_paths.root_dir).map_err(|source| {
        AuraNotarizationWorkbenchErrorV1::SignerLauncherIo {
            action: "create",
            path: path_string_v1(&launcher_paths.root_dir),
            source,
        }
    })?;
    remove_signer_launcher_response_file_if_present_v1(&launcher_paths.response_path)?;
    std::fs::write(
        &launcher_paths.request_path,
        serde_json::to_string_pretty(&carrier_request)?,
    )
    .map_err(
        |source| AuraNotarizationWorkbenchErrorV1::SignerLauncherIo {
            action: "write",
            path: path_string_v1(&launcher_paths.request_path),
            source,
        },
    )?;

    Ok(launcher_plan)
}

pub fn build_notarization_authorization_sign_carrier_request_v1(
    session: NotarizationAuthorizationSessionV1,
) -> Result<NotarizationAuthorizationSignCarrierRequestV1, AuraNotarizationWorkbenchErrorV1> {
    let validated_session = validate_notarization_authorization_session_v1(&session)?;
    Ok(NotarizationAuthorizationSignCarrierRequestV1 {
        carrier_version: NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1,
        session_id_hex: validated_session.session_id_hex,
        authorization_sign_request: validated_session.authorization_sign_request,
    })
}

pub fn sign_notarization_authorization_carrier_request_v1(
    carrier_request: NotarizationAuthorizationSignCarrierRequestV1,
    authorization_signing_key: [u8; 32],
) -> Result<NotarizationAuthorizationSignCarrierResponseV1, AuraNotarizationWorkbenchErrorV1> {
    if carrier_request.carrier_version != NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1 {
        return Err(
            AuraNotarizationWorkbenchErrorV1::UnsupportedAuthorizationSignCarrierVersion {
                expected: NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1,
                actual: carrier_request.carrier_version,
            },
        );
    }

    decode_input_hex_v1("session_id_hex", &carrier_request.session_id_hex)?;
    let payload = carrier_request.authorization_sign_request.validate()?;
    let authorization_sign_response = build_token_transaction_authorization_sign_response_v1(
        sign_token_transaction_authorization_payload_v1(payload, authorization_signing_key)?,
    )?;

    Ok(NotarizationAuthorizationSignCarrierResponseV1 {
        carrier_version: NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1,
        session_id_hex: carrier_request.session_id_hex,
        authorization_sign_response,
    })
}

pub fn load_notarization_authorization_signer_launcher_response_value_v1(
    session_value: serde_json::Value,
) -> Result<NotarizationAuthorizationSignerLauncherLoadResultV1, AuraNotarizationWorkbenchErrorV1> {
    let session: NotarizationAuthorizationSessionV1 = serde_json::from_value(session_value)?;
    load_notarization_authorization_signer_launcher_response_v1(session)
}

pub fn load_notarization_authorization_signer_launcher_response_v1(
    session: NotarizationAuthorizationSessionV1,
) -> Result<NotarizationAuthorizationSignerLauncherLoadResultV1, AuraNotarizationWorkbenchErrorV1> {
    let validated_session = validate_notarization_authorization_session_v1(&session)?;
    let launcher_paths = build_signer_launcher_paths_v1(&validated_session.session_id_hex);
    let launcher_plan = build_signer_launcher_plan_v1(&validated_session);
    let response_text =
        std::fs::read_to_string(&launcher_paths.response_path).map_err(|source| {
            AuraNotarizationWorkbenchErrorV1::SignerLauncherIo {
                action: "read",
                path: path_string_v1(&launcher_paths.response_path),
                source,
            }
        })?;
    let sign_carrier_response: NotarizationAuthorizationSignCarrierResponseV1 =
        serde_json::from_str(&response_text)?;
    validate_notarization_authorization_sign_carrier_response_v1(
        &validated_session,
        &sign_carrier_response,
    )?;

    Ok(NotarizationAuthorizationSignerLauncherLoadResultV1 {
        launcher: launcher_plan,
        sign_carrier_response,
    })
}

pub fn validate_notarization_authorization_sign_carrier_response_v1(
    session: &NotarizationAuthorizationSessionV1,
    carrier_response: &NotarizationAuthorizationSignCarrierResponseV1,
) -> Result<TokenTransactionAuthorizationSignResponseWireV1, AuraNotarizationWorkbenchErrorV1> {
    let validated_session = validate_notarization_authorization_session_v1(session)?;
    if carrier_response.carrier_version != NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1 {
        return Err(
            AuraNotarizationWorkbenchErrorV1::UnsupportedAuthorizationSignCarrierVersion {
                expected: NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1,
                actual: carrier_response.carrier_version,
            },
        );
    }

    decode_input_hex_v1("session_id_hex", &carrier_response.session_id_hex)?;
    if carrier_response.session_id_hex != validated_session.session_id_hex {
        return Err(
            AuraNotarizationWorkbenchErrorV1::AuthorizationSignCarrierSessionMismatch {
                expected: validated_session.session_id_hex,
                actual: carrier_response.session_id_hex.clone(),
            },
        );
    }

    validate_token_transaction_authorization_sign_response_v1(
        &validated_session.authorization_sign_request,
        &carrier_response.authorization_sign_response,
    )?;

    Ok(carrier_response.authorization_sign_response.clone())
}

pub fn compose_notarization_v1(
    request: NotarizationWorkbenchAuthorizedComposeRequestV1,
) -> Result<NotarizationWorkbenchCompositionV1, AuraNotarizationWorkbenchErrorV1> {
    let built = build_transaction_from_compose_request_v1(request.compose_request)?;
    build_composition_response_v1(
        built,
        TokenTransactionAuthorizationEnvelopeV1::from_wire(request.authorization_envelope)?,
    )
}

pub fn load_sample_notarization_record_value_v1(
) -> Result<serde_json::Value, AuraNotarizationWorkbenchErrorV1> {
    let vectors = load_fixture_vectors_v1()?;
    let sample = first_fixture_vector_v1(&vectors);
    Ok(serde_json::to_value(sample_record_wire_v1(sample))?)
}

pub fn load_sample_compose_request_value_v1(
) -> Result<serde_json::Value, AuraNotarizationWorkbenchErrorV1> {
    let vectors = load_fixture_vectors_v1()?;
    let sample = first_fixture_vector_v1(&vectors);
    Ok(serde_json::to_value(sample_compose_request_v1(sample))?)
}

pub fn build_compose_export_bundle_v1(
    compose_request: &NotarizationWorkbenchComposeRequestV1,
    composition: &NotarizationWorkbenchCompositionV1,
) -> Result<Vec<NotarizationWorkbenchExportFileV1>, AuraNotarizationWorkbenchErrorV1> {
    Ok(vec![
        NotarizationWorkbenchExportFileV1 {
            filename: "compose-request.json".to_owned(),
            media_type: "application/json".to_owned(),
            contents: serde_json::to_string_pretty(compose_request)?,
        },
        NotarizationWorkbenchExportFileV1 {
            filename: "transaction.json".to_owned(),
            media_type: "application/json".to_owned(),
            contents: serde_json::to_string_pretty(&composition.transaction)?,
        },
        NotarizationWorkbenchExportFileV1 {
            filename: "public-statement.json".to_owned(),
            media_type: "application/json".to_owned(),
            contents: serde_json::to_string_pretty(&composition.public_statement)?,
        },
        NotarizationWorkbenchExportFileV1 {
            filename: "notarization-record.json".to_owned(),
            media_type: "application/json".to_owned(),
            contents: serde_json::to_string_pretty(&composition.notarization_record)?,
        },
        NotarizationWorkbenchExportFileV1 {
            filename: "receipt.md".to_owned(),
            media_type: "text/markdown".to_owned(),
            contents: composition.markdown_receipt.clone(),
        },
        NotarizationWorkbenchExportFileV1 {
            filename: "receipt.html".to_owned(),
            media_type: "text/html".to_owned(),
            contents: composition.html_receipt.clone(),
        },
    ])
}

pub fn build_compose_export_bundle_json_v1(
    compose_request: &NotarizationWorkbenchComposeRequestV1,
    composition: &NotarizationWorkbenchCompositionV1,
) -> NotarizationWorkbenchComposeExportBundleV1 {
    NotarizationWorkbenchComposeExportBundleV1 {
        compose_request: compose_request.clone(),
        transaction: composition.transaction.clone(),
        public_statement: composition.public_statement.clone(),
        notarization_record: composition.notarization_record.clone(),
        receipt_markdown: composition.markdown_receipt.clone(),
        receipt_html: composition.html_receipt.clone(),
    }
}

pub fn compose_export_bundle_value_v1(
    compose_request_value: serde_json::Value,
) -> Result<NotarizationWorkbenchComposeExportBundleV1, AuraNotarizationWorkbenchErrorV1> {
    let request = parse_authorized_compose_request_value_v1(compose_request_value)?;
    let composition = compose_notarization_v1(request.clone())?;
    Ok(build_compose_export_bundle_json_v1(
        &request.compose_request,
        &composition,
    ))
}

fn build_composition_response_v1(
    built: BuildDeterministicTransactionResponseV1,
    authorization_envelope: TokenTransactionAuthorizationEnvelopeV1,
) -> Result<NotarizationWorkbenchCompositionV1, AuraNotarizationWorkbenchErrorV1> {
    let public_statement = built.transaction.proof_placeholder.public_statement.clone();
    let notary_input = build_token_transaction_authorized_notary_input_v1(
        &built.transaction,
        authorization_envelope,
    )?;
    let receipt = build_token_transaction_notary_receipt_preimage_v1(notary_input)?;
    let acknowledgement = build_token_transaction_notary_acknowledgement_v1(receipt)?;
    let seal_payload = build_token_transaction_seal_payload_v1(acknowledgement)?;
    let notarization_record =
        build_token_transaction_notarization_record_v1(seal_payload)?.to_wire();
    let inspection = inspect_notarization_record_wire_v1(notarization_record.clone())?;

    Ok(NotarizationWorkbenchCompositionV1 {
        burn_summary: build_burn_summary_v1(&built)?,
        transaction: built.transaction.to_wire(),
        public_statement: public_statement.to_wire(),
        notarization_record,
        summary: inspection.summary,
        markdown_receipt: inspection.markdown_receipt,
        html_receipt: inspection.html_receipt,
    })
}

fn build_transaction_from_compose_request_v1(
    request: NotarizationWorkbenchComposeRequestV1,
) -> Result<BuildDeterministicTransactionResponseV1, AuraNotarizationWorkbenchErrorV1> {
    Ok(build_deterministic_transaction_v1(
        BuildDeterministicTransactionRequestV1 {
            tx_version: TOKEN_TX_VERSION_V1,
            tx_kind: PRIVATE_TRANSFER_BURN_KIND_V1,
            rollup_id: decode_input_hex_v1("rollup_id_hex", &request.rollup_id_hex)?,
            asset_id: decode_input_hex_v1("asset_id_hex", &request.asset_id_hex)?,
            anchor_state_root: decode_input_hex_v1(
                "anchor_state_root_hex",
                &request.anchor_state_root_hex,
            )?,
            inputs: request
                .inputs
                .into_iter()
                .map(TokenTransactionInputV1::from_wire)
                .collect::<Result<Vec<_>, _>>()?,
            outputs: request
                .outputs
                .into_iter()
                .map(TokenTransactionOutputV1::from_wire)
                .collect::<Result<Vec<_>, _>>()?,
        },
    )?)
}

fn parse_authorized_compose_request_value_v1(
    value: serde_json::Value,
) -> Result<NotarizationWorkbenchAuthorizedComposeRequestV1, AuraNotarizationWorkbenchErrorV1> {
    if let Ok(request) =
        serde_json::from_value::<NotarizationAuthorizationCarrierCompletionRequestV1>(value.clone())
    {
        return authorized_compose_request_from_carrier_completion_v1(request);
    }

    if let Ok(request) =
        serde_json::from_value::<NotarizationAuthorizationCompletionRequestV1>(value.clone())
    {
        return authorized_compose_request_from_completion_v1(request);
    }

    Ok(serde_json::from_value(value)?)
}

fn authorized_compose_request_from_completion_v1(
    request: NotarizationAuthorizationCompletionRequestV1,
) -> Result<NotarizationWorkbenchAuthorizedComposeRequestV1, AuraNotarizationWorkbenchErrorV1> {
    let session = validate_notarization_authorization_session_v1(&request.session)?;
    let authorization_envelope = validate_token_transaction_authorization_sign_response_v1(
        &session.authorization_sign_request,
        &request.sign_response,
    )?;

    Ok(NotarizationWorkbenchAuthorizedComposeRequestV1 {
        compose_request: session.compose_request,
        authorization_envelope: authorization_envelope.to_wire(),
    })
}

fn authorized_compose_request_from_carrier_completion_v1(
    request: NotarizationAuthorizationCarrierCompletionRequestV1,
) -> Result<NotarizationWorkbenchAuthorizedComposeRequestV1, AuraNotarizationWorkbenchErrorV1> {
    let sign_response = validate_notarization_authorization_sign_carrier_response_v1(
        &request.session,
        &request.sign_carrier_response,
    )?;
    authorized_compose_request_from_completion_v1(NotarizationAuthorizationCompletionRequestV1 {
        session: request.session,
        sign_response,
    })
}

fn validate_notarization_authorization_session_v1(
    session: &NotarizationAuthorizationSessionV1,
) -> Result<NotarizationAuthorizationSessionV1, AuraNotarizationWorkbenchErrorV1> {
    if session.session_version != NOTARIZATION_AUTHORIZATION_SESSION_VERSION_V1 {
        return Err(
            AuraNotarizationWorkbenchErrorV1::UnsupportedAuthorizationSessionVersion {
                expected: NOTARIZATION_AUTHORIZATION_SESSION_VERSION_V1,
                actual: session.session_version,
            },
        );
    }

    let built = build_transaction_from_compose_request_v1(session.compose_request.clone())?;
    let expected_public_statement = built
        .transaction
        .proof_placeholder
        .public_statement
        .to_wire();
    let expected_transaction = built.transaction.to_wire();
    let expected_burn_summary = build_burn_summary_v1(&built)?;
    let payload = session.authorization_sign_request.validate()?;
    let expected_sign_request = build_token_transaction_authorization_sign_request_v1(
        &built.transaction,
        payload.signer_public_key,
        payload.authorization_nonce,
    )?;
    let expected_session_id_hex =
        build_authorization_session_id_hex_v1(&session.compose_request, &expected_sign_request)?;

    if session.burn_summary != expected_burn_summary {
        return Err(AuraNotarizationWorkbenchErrorV1::InvalidAuthorizationSession("burn_summary"));
    }
    if session.transaction != expected_transaction {
        return Err(AuraNotarizationWorkbenchErrorV1::InvalidAuthorizationSession("transaction"));
    }
    if session.public_statement != expected_public_statement {
        return Err(
            AuraNotarizationWorkbenchErrorV1::InvalidAuthorizationSession("public_statement"),
        );
    }
    if session.authorization_sign_request != expected_sign_request {
        return Err(
            AuraNotarizationWorkbenchErrorV1::InvalidAuthorizationSession(
                "authorization_sign_request",
            ),
        );
    }
    if session.session_id_hex != expected_session_id_hex {
        return Err(
            AuraNotarizationWorkbenchErrorV1::InvalidAuthorizationSession("session_id_hex"),
        );
    }

    Ok(session.clone())
}

fn build_authorization_session_id_hex_v1(
    compose_request: &NotarizationWorkbenchComposeRequestV1,
    authorization_sign_request: &TokenTransactionAuthorizationSignRequestWireV1,
) -> Result<String, AuraNotarizationWorkbenchErrorV1> {
    let compose_request_bytes = serde_json::to_vec(compose_request)?;
    let sign_request_bytes = serde_json::to_vec(authorization_sign_request)?;
    let mut preimage = Vec::with_capacity(
        AURA_NOTARIZATION_AUTHORIZATION_SESSION_DOMAIN_SEPARATOR_V1.len()
            + compose_request_bytes.len()
            + sign_request_bytes.len(),
    );
    preimage.extend_from_slice(AURA_NOTARIZATION_AUTHORIZATION_SESSION_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&compose_request_bytes);
    preimage.extend_from_slice(&sign_request_bytes);
    Ok(encode_hex_lower_v1(&sha256_bytes(&preimage)))
}

fn build_burn_summary_v1(
    built: &BuildDeterministicTransactionResponseV1,
) -> Result<NotarizationWorkbenchBurnSummaryV1, AuraNotarizationWorkbenchErrorV1> {
    Ok(NotarizationWorkbenchBurnSummaryV1 {
        input_count: built.transaction.input_count()?,
        output_count: built.transaction.output_count()?,
        admission_burn: built.burns.admission_burn,
        notary_burn: built.burns.notary_burn,
        priority_weight: built.burns.priority_weight,
    })
}

fn decode_input_hex_v1(
    field: &'static str,
    value: &str,
) -> Result<[u8; 32], TokenTransactionErrorV1> {
    if value.len() != 64 {
        return Err(TokenTransactionErrorV1::InvalidHexLength {
            field,
            expected_bytes: 32,
            actual_nibbles: value.len(),
        });
    }

    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble_v1(field, chunk[0])?;
        let low = decode_hex_nibble_v1(field, chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble_v1(field: &'static str, byte: u8) -> Result<u8, TokenTransactionErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TokenTransactionErrorV1::MalformedHex { field }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NotarizationAuthorizationSignerLauncherPathsV1 {
    root_dir: PathBuf,
    request_path: PathBuf,
    response_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NotarizationAuthorizationLocalSignerLaunchStrategyV1 {
    DirectBinary { program_path: PathBuf },
    CargoRun { manifest_path: PathBuf },
}

fn build_signer_launcher_paths_v1(
    session_id_hex: &str,
) -> NotarizationAuthorizationSignerLauncherPathsV1 {
    let root_dir = std::env::temp_dir()
        .join(SIGNER_LAUNCHER_ROOT_DIRNAME_V1)
        .join(SIGNER_LAUNCHER_WORKFLOW_DIRNAME_V1)
        .join(session_id_hex);

    NotarizationAuthorizationSignerLauncherPathsV1 {
        request_path: root_dir.join(SIGNER_LAUNCHER_REQUEST_FILENAME_V1),
        response_path: root_dir.join(SIGNER_LAUNCHER_RESPONSE_FILENAME_V1),
        root_dir,
    }
}

fn build_signer_launcher_plan_v1(
    session: &NotarizationAuthorizationSessionV1,
) -> NotarizationAuthorizationSignerLauncherPlanV1 {
    let launcher_paths = build_signer_launcher_paths_v1(&session.session_id_hex);

    NotarizationAuthorizationSignerLauncherPlanV1 {
        scope: NOTARIZATION_SIGNER_LAUNCHER_SCOPE_V1.to_owned(),
        session_id_hex: session.session_id_hex.clone(),
        request_path: path_string_v1(&launcher_paths.request_path),
        response_path: path_string_v1(&launcher_paths.response_path),
        signer_command: build_signer_launcher_command_v1(&launcher_paths),
    }
}

fn build_signer_launcher_command_v1(
    launcher_paths: &NotarizationAuthorizationSignerLauncherPathsV1,
) -> String {
    format!(
        "cargo run --manifest-path {} --bin {} -- --request {} --response {} --private-key-hex {}",
        shell_quote_v1(&path_string_v1(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
        )),
        SIGNER_HELPER_BINARY_NAME_V1,
        shell_quote_v1(&path_string_v1(&launcher_paths.request_path)),
        shell_quote_v1(&path_string_v1(&launcher_paths.response_path)),
        SIGNER_HELPER_PRIVATE_KEY_PLACEHOLDER_V1,
    )
}

fn resolve_local_signer_launch_strategy_v1(
) -> Result<NotarizationAuthorizationLocalSignerLaunchStrategyV1, AuraNotarizationWorkbenchErrorV1>
{
    for candidate in local_signer_helper_binary_candidates_v1()? {
        if candidate.is_file() {
            return Ok(
                NotarizationAuthorizationLocalSignerLaunchStrategyV1::DirectBinary {
                    program_path: candidate,
                },
            );
        }
    }

    Ok(
        NotarizationAuthorizationLocalSignerLaunchStrategyV1::CargoRun {
            manifest_path: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
        },
    )
}

fn local_signer_helper_binary_candidates_v1(
) -> Result<Vec<PathBuf>, AuraNotarizationWorkbenchErrorV1> {
    let binary_name = format!(
        "{}{}",
        SIGNER_HELPER_BINARY_NAME_V1,
        std::env::consts::EXE_SUFFIX
    );
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut candidates = vec![
        manifest_dir.join("target/debug").join(&binary_name),
        manifest_dir.join("../../target/debug").join(&binary_name),
    ];

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.insert(0, parent.join(&binary_name));
        }
    }

    Ok(candidates)
}

fn run_local_signer_subprocess_v1(
    launch_strategy: &NotarizationAuthorizationLocalSignerLaunchStrategyV1,
    launcher: &NotarizationAuthorizationSignerLauncherPlanV1,
    private_key_hex: &str,
) -> Result<(), AuraNotarizationWorkbenchErrorV1> {
    let mut command = match launch_strategy {
        NotarizationAuthorizationLocalSignerLaunchStrategyV1::DirectBinary { program_path } => {
            let mut command = Command::new(program_path);
            command
                .arg("--request")
                .arg(&launcher.request_path)
                .arg("--response")
                .arg(&launcher.response_path)
                .arg("--private-key-hex")
                .arg(private_key_hex);
            command
        }
        NotarizationAuthorizationLocalSignerLaunchStrategyV1::CargoRun { manifest_path } => {
            let mut command = Command::new("cargo");
            command
                .arg("run")
                .arg("--manifest-path")
                .arg(manifest_path)
                .arg("--bin")
                .arg(SIGNER_HELPER_BINARY_NAME_V1)
                .arg("--")
                .arg("--request")
                .arg(&launcher.request_path)
                .arg("--response")
                .arg(&launcher.response_path)
                .arg("--private-key-hex")
                .arg(private_key_hex);
            command
        }
    };

    let output = command.output().map_err(|source| {
        AuraNotarizationWorkbenchErrorV1::LocalSignerLaunchFailed(format!(
            "subprocess spawn failed: {source}"
        ))
    })?;
    if output.status.success() {
        return Ok(());
    }

    let detail = summarize_local_signer_process_failure_v1(&output);
    Err(AuraNotarizationWorkbenchErrorV1::LocalSignerLaunchFailed(
        detail,
    ))
}

fn summarize_local_signer_process_failure_v1(output: &std::process::Output) -> String {
    let mut detail = if let Some(code) = output.status.code() {
        format!("subprocess exited with status code {code}")
    } else {
        "subprocess terminated by signal".to_owned()
    };
    let stderr = summarize_process_stream_v1(&output.stderr);
    let stdout = summarize_process_stream_v1(&output.stdout);
    if !stderr.is_empty() {
        detail.push_str(": ");
        detail.push_str(&stderr);
    } else if !stdout.is_empty() {
        detail.push_str(": ");
        detail.push_str(&stdout);
    }
    detail
}

fn summarize_process_stream_v1(stream: &[u8]) -> String {
    let text = String::from_utf8_lossy(stream);
    let summary = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .join(" ");

    if summary.len() <= 240 {
        return summary;
    }

    format!("{}...", &summary[..240])
}

fn remove_signer_launcher_response_file_if_present_v1(
    path: &Path,
) -> Result<(), AuraNotarizationWorkbenchErrorV1> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AuraNotarizationWorkbenchErrorV1::SignerLauncherIo {
            action: "clear",
            path: path_string_v1(path),
            source,
        }),
    }
}

fn path_string_v1(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn shell_quote_v1(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }

    let mut output = String::with_capacity(value.len() + 2);
    output.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            output.push_str("'\\''");
        } else {
            output.push(ch);
        }
    }
    output.push('\'');
    output
}

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/v1/deterministic_transaction_v1/test_vectors.json")
}

fn load_fixture_vectors_v1() -> Result<FixtureVectorFileV1, AuraNotarizationWorkbenchErrorV1> {
    let file = std::fs::read_to_string(fixture_path())
        .map_err(AuraNotarizationWorkbenchErrorV1::MissingFixture)?;
    Ok(serde_json::from_str(&file)?)
}

fn first_fixture_vector_v1(vectors: &FixtureVectorFileV1) -> &FixtureVectorV1 {
    vectors
        .vectors
        .first()
        .expect("deterministic transaction fixture vectors must include at least one vector")
}

fn sample_record_wire_v1(
    vector: &FixtureVectorV1,
) -> CanonicalTokenTransactionNotarizationRecordWireV1 {
    CanonicalTokenTransactionNotarizationRecordWireV1 {
        record_version: vector.notarization_summary.record_version,
        proof_statement_type: vector.notarization_summary.proof_statement_type,
        ack_digest_hex: vector.notary_ack_digest_hex.clone(),
        seal_payload_digest_hex: vector.seal_payload_digest_hex.clone(),
        udot_seed_digest_hex: vector.udot_seed_digest_hex.clone(),
        notarization_record_digest_hex: vector.notarization_record_digest_hex.clone(),
    }
}

fn sample_compose_request_v1(vector: &FixtureVectorV1) -> NotarizationWorkbenchComposeRequestV1 {
    NotarizationWorkbenchComposeRequestV1 {
        rollup_id_hex: vector.transaction.rollup_id_hex.clone(),
        asset_id_hex: vector.transaction.asset_id_hex.clone(),
        anchor_state_root_hex: vector.transaction.anchor_state_root_hex.clone(),
        inputs: vector.transaction.inputs.clone(),
        outputs: vector.transaction.outputs.clone(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureVectorFileV1 {
    vectors: Vec<FixtureVectorV1>,
}

#[derive(Debug, Deserialize)]
struct FixtureVectorV1 {
    transaction: DeterministicTransactionWireV1,
    notarization_summary: CanonicalTokenTransactionNotarizationSummaryV1,
    notarization_record_digest_hex: String,
    notary_ack_digest_hex: String,
    seal_payload_digest_hex: String,
    udot_seed_digest_hex: String,
}

#[cfg(test)]
mod tests {
    use super::{
        build_compose_export_bundle_v1, build_notarization_authorization_sign_carrier_request_v1,
        build_signer_launcher_paths_v1, complete_notarization_authorization_from_carrier_v1,
        complete_notarization_authorization_v1, compose_export_bundle_value_v1,
        compose_notarization_v1, compose_notarization_value_v1,
        inspect_notarization_record_value_v1,
        load_notarization_authorization_signer_launcher_response_v1,
        load_sample_compose_request_value_v1, load_sample_notarization_record_value_v1,
        local_dev_sign_notarization_authorization_session_v1,
        prepare_notarization_authorization_signer_launcher_v1,
        prepare_notarization_authorization_v1, run_local_notarization_authorization_signer_v1,
        sign_notarization_authorization_carrier_request_v1,
        validate_notarization_authorization_sign_carrier_response_v1,
        AuraNotarizationWorkbenchErrorV1, NotarizationAuthorizationCarrierCompletionRequestV1,
        NotarizationAuthorizationCompletionRequestV1, NotarizationAuthorizationSessionV1,
        NotarizationAuthorizationSignCarrierRequestV1,
        NotarizationAuthorizationSignCarrierResponseV1,
        NotarizationAuthorizationSignerLaunchRequestV1,
        NotarizationAuthorizationSignerLauncherPlanV1,
        NotarizationWorkbenchAuthorizationPrepareRequestV1,
        NotarizationWorkbenchAuthorizedComposeRequestV1, NotarizationWorkbenchComposeRequestV1,
        NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1, NOTARIZATION_LOCAL_DEV_SIGNER_SCOPE_V1,
        NOTARIZATION_LOCAL_SUBPROCESS_SIGNER_SCOPE_V1, NOTARIZATION_SIGNER_LAUNCHER_SCOPE_V1,
    };
    use aura_l2_execution_v1::{
        build_token_transaction_authorization_sign_response_v1,
        reconstruct_token_transaction_authorization_envelope_from_sign_response_v1,
        sign_token_transaction_authorization_payload_v1,
    };
    use aura_notarization_render_v1::{
        render_notarization_summary_html_v1, render_notarization_summary_markdown_v1,
    };

    const AUTH_SIGNING_KEY_BYTES_V1: [u8; 32] = [0x42; 32];
    const AUTHORIZATION_NONCE_V1: [u8; 32] = [0x55; 32];
    const AUTH_SIGNER_PUBLIC_KEY_HEX_V1: &str =
        "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

    fn encode_hex_lower_v1(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    fn sample_compose_request_v1() -> NotarizationWorkbenchComposeRequestV1 {
        serde_json::from_value(load_sample_compose_request_value_v1().unwrap()).unwrap()
    }

    fn build_prepare_request_v1() -> NotarizationWorkbenchAuthorizationPrepareRequestV1 {
        NotarizationWorkbenchAuthorizationPrepareRequestV1 {
            compose_request: sample_compose_request_v1(),
            signer_public_key_hex: AUTH_SIGNER_PUBLIC_KEY_HEX_V1.to_owned(),
            authorization_nonce_hex: encode_hex_lower_v1(&AUTHORIZATION_NONCE_V1),
        }
    }

    fn build_prepare_request_with_nonce_v1(
        authorization_nonce: [u8; 32],
    ) -> NotarizationWorkbenchAuthorizationPrepareRequestV1 {
        NotarizationWorkbenchAuthorizationPrepareRequestV1 {
            compose_request: sample_compose_request_v1(),
            signer_public_key_hex: AUTH_SIGNER_PUBLIC_KEY_HEX_V1.to_owned(),
            authorization_nonce_hex: encode_hex_lower_v1(&authorization_nonce),
        }
    }

    fn build_authorization_session_v1() -> NotarizationAuthorizationSessionV1 {
        prepare_notarization_authorization_v1(build_prepare_request_v1()).unwrap()
    }

    fn build_authorization_session_with_nonce_v1(
        authorization_nonce: [u8; 32],
    ) -> NotarizationAuthorizationSessionV1 {
        prepare_notarization_authorization_v1(build_prepare_request_with_nonce_v1(
            authorization_nonce,
        ))
        .unwrap()
    }

    fn build_sign_carrier_request_v1() -> NotarizationAuthorizationSignCarrierRequestV1 {
        build_notarization_authorization_sign_carrier_request_v1(build_authorization_session_v1())
            .unwrap()
    }

    fn build_sign_response_for_session_v1(
        session: &NotarizationAuthorizationSessionV1,
    ) -> aura_l2_execution_v1::TokenTransactionAuthorizationSignResponseWireV1 {
        build_token_transaction_authorization_sign_response_v1(
            sign_token_transaction_authorization_payload_v1(
                session.authorization_sign_request.validate().unwrap(),
                AUTH_SIGNING_KEY_BYTES_V1,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn build_sign_carrier_response_v1() -> NotarizationAuthorizationSignCarrierResponseV1 {
        sign_notarization_authorization_carrier_request_v1(
            build_sign_carrier_request_v1(),
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap()
    }

    fn build_sign_carrier_response_for_session_v1(
        session: &NotarizationAuthorizationSessionV1,
    ) -> NotarizationAuthorizationSignCarrierResponseV1 {
        sign_notarization_authorization_carrier_request_v1(
            build_notarization_authorization_sign_carrier_request_v1(session.clone()).unwrap(),
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap()
    }

    fn build_authorized_compose_request_for_session_v1(
        session: &NotarizationAuthorizationSessionV1,
    ) -> NotarizationWorkbenchAuthorizedComposeRequestV1 {
        let sign_response = build_sign_response_for_session_v1(session);
        let authorization_envelope =
            reconstruct_token_transaction_authorization_envelope_from_sign_response_v1(
                sign_response,
            )
            .unwrap();

        NotarizationWorkbenchAuthorizedComposeRequestV1 {
            compose_request: session.compose_request.clone(),
            authorization_envelope: authorization_envelope.to_wire(),
        }
    }

    fn build_local_signer_launch_request_for_session_v1(
        session: &NotarizationAuthorizationSessionV1,
    ) -> NotarizationAuthorizationSignerLaunchRequestV1 {
        NotarizationAuthorizationSignerLaunchRequestV1 {
            session: session.clone(),
            private_key_hex: encode_hex_lower_v1(&AUTH_SIGNING_KEY_BYTES_V1),
        }
    }

    fn build_authorized_compose_request_v1() -> NotarizationWorkbenchAuthorizedComposeRequestV1 {
        build_authorized_compose_request_for_session_v1(&build_authorization_session_v1())
    }

    fn build_completion_request_v1() -> NotarizationAuthorizationCompletionRequestV1 {
        let session = build_authorization_session_v1();
        let sign_response = build_sign_response_for_session_v1(&session);

        NotarizationAuthorizationCompletionRequestV1 {
            session,
            sign_response,
        }
    }

    fn build_carrier_completion_request_v1() -> NotarizationAuthorizationCarrierCompletionRequestV1
    {
        NotarizationAuthorizationCarrierCompletionRequestV1 {
            session: build_authorization_session_v1(),
            sign_carrier_response: build_sign_carrier_response_v1(),
        }
    }

    #[test]
    fn fixture_backed_inspection_matches_canonical_summary_and_receipts() {
        let value = load_sample_notarization_record_value_v1().unwrap();
        let inspection = inspect_notarization_record_value_v1(value).unwrap();

        assert_eq!(inspection.summary.summary_version, 1);
        assert_eq!(
            inspection.markdown_receipt,
            render_notarization_summary_markdown_v1(&inspection.summary)
        );
        assert_eq!(
            inspection.html_receipt,
            render_notarization_summary_html_v1(&inspection.summary)
        );
    }

    #[test]
    fn malformed_input_fails_closed() {
        let error = inspect_notarization_record_value_v1(serde_json::json!({
            "record_version": 1,
            "proof_statement_type": 1,
            "ack_digest_hex": "abcd"
        }))
        .unwrap_err();

        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidJson(_)
            | AuraNotarizationWorkbenchErrorV1::InvalidRecord(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sample_loader_produces_valid_inspectable_record_wire_value() {
        let sample = load_sample_notarization_record_value_v1().unwrap();
        let inspection = inspect_notarization_record_value_v1(sample).unwrap();

        assert_eq!(inspection.summary.summary_version, 1);
        assert_eq!(
            inspection.summary.proof_statement_label,
            "private_transfer_burn_v1"
        );
    }

    #[test]
    fn authorization_session_is_deterministic_and_stable() {
        let first = prepare_notarization_authorization_v1(build_prepare_request_v1()).unwrap();
        let second = prepare_notarization_authorization_v1(build_prepare_request_v1()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.session_version, 1);
        assert_eq!(first.session_id_hex.len(), 64);
        assert_eq!(first.transaction.public_statement, first.public_statement);
        first.authorization_sign_request.validate().unwrap();
    }

    #[test]
    fn prepare_returns_exact_frozen_sign_request() {
        let session = build_authorization_session_v1();
        let payload = session.authorization_sign_request.validate().unwrap();

        assert_eq!(
            session
                .authorization_sign_request
                .payload
                .signer_public_key_hex,
            AUTH_SIGNER_PUBLIC_KEY_HEX_V1
        );
        assert_eq!(
            session.authorization_sign_request.payload_bytes_hex,
            encode_hex_lower_v1(&payload.canonical_bytes().unwrap())
        );
    }

    #[test]
    fn carrier_request_format_is_deterministic_and_stable() {
        let first = build_sign_carrier_request_v1();
        let second = build_sign_carrier_request_v1();
        let expected_value = serde_json::json!({
            "carrier_version": 1,
            "session_id_hex": first.session_id_hex.clone(),
            "authorization_sign_request": first.authorization_sign_request.clone(),
        });

        assert_eq!(first, second);
        assert_eq!(
            first.carrier_version,
            NOTARIZATION_AUTHORIZATION_SIGN_CARRIER_VERSION_V1
        );
        assert_eq!(first.session_id_hex.len(), 64);
        assert_eq!(
            first.authorization_sign_request,
            build_authorization_session_v1().authorization_sign_request
        );
        assert_eq!(serde_json::to_value(&first).unwrap(), expected_value);
    }

    #[test]
    fn external_signer_helper_signs_exact_frozen_payload_bytes() {
        let session = build_authorization_session_v1();
        let carrier_request =
            build_notarization_authorization_sign_carrier_request_v1(session.clone()).unwrap();
        let carrier_response = sign_notarization_authorization_carrier_request_v1(
            carrier_request.clone(),
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap();

        assert_eq!(
            carrier_response.session_id_hex,
            carrier_request.session_id_hex
        );
        assert_eq!(
            carrier_response.authorization_sign_response,
            build_sign_response_for_session_v1(&session)
        );
    }

    #[test]
    fn carrier_response_reconstructs_valid_frozen_sign_response() {
        let session = build_authorization_session_v1();
        let carrier_response = build_sign_carrier_response_v1();
        let sign_response = validate_notarization_authorization_sign_carrier_response_v1(
            &session,
            &carrier_response,
        )
        .unwrap();

        assert_eq!(sign_response, build_sign_response_for_session_v1(&session));
    }

    #[test]
    fn mismatched_sign_carrier_session_id_fails_closed() {
        let session = build_authorization_session_v1();
        let mut carrier_response = build_sign_carrier_response_v1();
        carrier_response.session_id_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();

        let error = validate_notarization_authorization_sign_carrier_response_v1(
            &session,
            &carrier_response,
        )
        .unwrap_err();

        match error {
            AuraNotarizationWorkbenchErrorV1::AuthorizationSignCarrierSessionMismatch {
                ..
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_sign_carrier_files_fail_closed() {
        let malformed_request =
            serde_json::from_value::<NotarizationAuthorizationSignCarrierRequestV1>(
                serde_json::json!({
                    "carrier_version": 1,
                    "session_id_hex": "abcd",
                    "authorization_sign_request": build_authorization_session_v1().authorization_sign_request,
                }),
            )
            .unwrap();
        let error = sign_notarization_authorization_carrier_request_v1(
            malformed_request,
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidComposition(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let malformed_response =
            serde_json::from_value::<NotarizationAuthorizationSignCarrierResponseV1>(
                serde_json::json!({
                    "carrier_version": 999,
                    "session_id_hex": build_authorization_session_v1().session_id_hex,
                    "authorization_sign_response": build_sign_response_for_session_v1(&build_authorization_session_v1()),
                }),
            )
            .unwrap();
        let session = build_authorization_session_v1();
        let error = validate_notarization_authorization_sign_carrier_response_v1(
            &session,
            &malformed_response,
        )
        .unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::UnsupportedAuthorizationSignCarrierVersion {
                ..
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn guided_signer_launcher_writes_exact_carrier_request_to_deterministic_path() {
        let session = build_authorization_session_v1();
        let launcher_plan =
            prepare_notarization_authorization_signer_launcher_v1(session.clone()).unwrap();
        let expected_paths = build_signer_launcher_paths_v1(&session.session_id_hex);
        let expected_command = format!(
            "cargo run --manifest-path '{}' --bin aura_authorization_signer_v1 -- --request '{}' --response '{}' --private-key-hex <64 lowercase hex chars>",
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("Cargo.toml")
                .display(),
            expected_paths.request_path.display(),
            expected_paths.response_path.display(),
        );
        let request_text = std::fs::read_to_string(&expected_paths.request_path).unwrap();
        let request_from_disk: NotarizationAuthorizationSignCarrierRequestV1 =
            serde_json::from_str(&request_text).unwrap();

        assert_eq!(
            launcher_plan,
            NotarizationAuthorizationSignerLauncherPlanV1 {
                scope: NOTARIZATION_SIGNER_LAUNCHER_SCOPE_V1.to_owned(),
                session_id_hex: session.session_id_hex,
                request_path: expected_paths.request_path.display().to_string(),
                response_path: expected_paths.response_path.display().to_string(),
                signer_command: expected_command,
            }
        );
        assert_eq!(request_from_disk, build_sign_carrier_request_v1());
    }

    #[test]
    fn guided_signer_launcher_prepare_clears_stale_response_file() {
        let session = build_authorization_session_with_nonce_v1([0x71; 32]);
        let launcher_plan =
            prepare_notarization_authorization_signer_launcher_v1(session.clone()).unwrap();
        std::fs::write(&launcher_plan.response_path, "{not-json").unwrap();

        let prepared_again =
            prepare_notarization_authorization_signer_launcher_v1(session.clone()).unwrap();

        assert_eq!(prepared_again, launcher_plan);
        assert!(!std::path::Path::new(&launcher_plan.response_path).exists());
    }

    #[test]
    fn guided_signer_launcher_loads_valid_response_and_preserves_downstream_outputs() {
        let session = build_authorization_session_with_nonce_v1([0x66; 32]);
        let launcher_plan =
            prepare_notarization_authorization_signer_launcher_v1(session.clone()).unwrap();
        let sign_carrier_response = build_sign_carrier_response_for_session_v1(&session);
        std::fs::write(
            &launcher_plan.response_path,
            serde_json::to_string_pretty(&sign_carrier_response).unwrap(),
        )
        .unwrap();

        let loaded =
            load_notarization_authorization_signer_launcher_response_v1(session.clone()).unwrap();
        let composition_from_launcher = complete_notarization_authorization_from_carrier_v1(
            NotarizationAuthorizationCarrierCompletionRequestV1 {
                session: session.clone(),
                sign_carrier_response: loaded.sign_carrier_response.clone(),
            },
        )
        .unwrap();
        let composition_from_envelope =
            compose_notarization_v1(build_authorized_compose_request_for_session_v1(&session))
                .unwrap();
        let export_bundle_from_launcher = compose_export_bundle_value_v1(
            serde_json::to_value(NotarizationAuthorizationCarrierCompletionRequestV1 {
                session: session.clone(),
                sign_carrier_response: loaded.sign_carrier_response.clone(),
            })
            .unwrap(),
        )
        .unwrap();

        assert_eq!(loaded.launcher, launcher_plan);
        assert_eq!(loaded.sign_carrier_response, sign_carrier_response);
        assert_eq!(
            composition_from_launcher.transaction,
            composition_from_envelope.transaction
        );
        assert_eq!(
            composition_from_launcher.public_statement,
            composition_from_envelope.public_statement
        );
        assert_eq!(
            composition_from_launcher.notarization_record,
            composition_from_envelope.notarization_record
        );
        assert_eq!(
            export_bundle_from_launcher.transaction,
            composition_from_launcher.transaction
        );
        assert_eq!(
            export_bundle_from_launcher.public_statement,
            composition_from_launcher.public_statement
        );
        assert_eq!(
            export_bundle_from_launcher.notarization_record,
            composition_from_launcher.notarization_record
        );
        assert_eq!(
            export_bundle_from_launcher.compose_request,
            session.compose_request
        );
        assert_eq!(
            export_bundle_from_launcher.receipt_markdown,
            composition_from_launcher.markdown_receipt
        );
        assert_eq!(
            export_bundle_from_launcher.receipt_html,
            composition_from_launcher.html_receipt
        );
    }

    #[test]
    fn guided_signer_launcher_missing_or_mismatched_response_fails_closed() {
        let missing_session = build_authorization_session_with_nonce_v1([0x67; 32]);
        let missing_launcher =
            prepare_notarization_authorization_signer_launcher_v1(missing_session.clone()).unwrap();
        let _ = std::fs::remove_file(&missing_launcher.response_path);

        let error = load_notarization_authorization_signer_launcher_response_v1(missing_session)
            .unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::SignerLauncherIo { action, .. } => {
                assert_eq!(action, "read");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mismatched_session = build_authorization_session_with_nonce_v1([0x68; 32]);
        let mismatched_launcher =
            prepare_notarization_authorization_signer_launcher_v1(mismatched_session.clone())
                .unwrap();
        let mut mismatched_response =
            build_sign_carrier_response_for_session_v1(&mismatched_session);
        mismatched_response.session_id_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        std::fs::write(
            &mismatched_launcher.response_path,
            serde_json::to_string_pretty(&mismatched_response).unwrap(),
        )
        .unwrap();

        let error = load_notarization_authorization_signer_launcher_response_v1(mismatched_session)
            .unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::AuthorizationSignCarrierSessionMismatch {
                ..
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn local_signer_subprocess_executes_same_carrier_flow_and_preserves_outputs() {
        let session = build_authorization_session_with_nonce_v1([0x72; 32]);
        let launch_result = run_local_notarization_authorization_signer_v1(
            build_local_signer_launch_request_for_session_v1(&session),
        )
        .unwrap();
        let composition_from_subprocess = complete_notarization_authorization_from_carrier_v1(
            NotarizationAuthorizationCarrierCompletionRequestV1 {
                session: session.clone(),
                sign_carrier_response: launch_result.sign_carrier_response.clone(),
            },
        )
        .unwrap();
        let composition_from_envelope =
            compose_notarization_v1(build_authorized_compose_request_for_session_v1(&session))
                .unwrap();
        let export_bundle_from_subprocess = compose_export_bundle_value_v1(
            serde_json::to_value(NotarizationAuthorizationCarrierCompletionRequestV1 {
                session: session.clone(),
                sign_carrier_response: launch_result.sign_carrier_response.clone(),
            })
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            launch_result.scope,
            NOTARIZATION_LOCAL_SUBPROCESS_SIGNER_SCOPE_V1
        );
        assert_eq!(launch_result.session_id_hex, session.session_id_hex);
        assert_eq!(
            launch_result.sign_carrier_response,
            build_sign_carrier_response_for_session_v1(&session)
        );
        assert!(
            std::path::Path::new(&launch_result.launcher.request_path).exists(),
            "local signer launch should preserve the deterministic request file"
        );
        assert!(
            std::path::Path::new(&launch_result.launcher.response_path).exists(),
            "local signer launch should write the deterministic response file"
        );
        assert_eq!(
            composition_from_subprocess.transaction,
            composition_from_envelope.transaction
        );
        assert_eq!(
            composition_from_subprocess.public_statement,
            composition_from_envelope.public_statement
        );
        assert_eq!(
            composition_from_subprocess.notarization_record,
            composition_from_envelope.notarization_record
        );
        assert_eq!(
            export_bundle_from_subprocess.transaction,
            composition_from_subprocess.transaction
        );
        assert_eq!(
            export_bundle_from_subprocess.public_statement,
            composition_from_subprocess.public_statement
        );
        assert_eq!(
            export_bundle_from_subprocess.notarization_record,
            composition_from_subprocess.notarization_record
        );
    }

    #[test]
    fn local_signer_subprocess_fails_closed_on_invalid_private_key_input() {
        let session = build_authorization_session_with_nonce_v1([0x73; 32]);
        let error = run_local_notarization_authorization_signer_v1(
            NotarizationAuthorizationSignerLaunchRequestV1 {
                session,
                private_key_hex: "zz".to_owned(),
            },
        )
        .unwrap_err();

        match error {
            AuraNotarizationWorkbenchErrorV1::LocalSignerLaunchFailed(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn valid_authorization_completes_compose_successfully() {
        let completion = build_completion_request_v1();
        let composition = complete_notarization_authorization_v1(completion).unwrap();

        assert_eq!(composition.burn_summary.input_count, 1);
        assert_eq!(composition.burn_summary.output_count, 1);
        assert_eq!(composition.burn_summary.admission_burn, 1);
        assert_eq!(composition.burn_summary.notary_burn, 3);
        assert_eq!(composition.burn_summary.priority_weight, 4);
        assert_eq!(
            composition.transaction.public_statement,
            composition.public_statement
        );
        assert_eq!(
            composition.summary.proof_statement_label,
            "private_transfer_burn_v1"
        );
        assert_eq!(
            composition.summary.notarization_record_digest_hex,
            composition
                .notarization_record
                .notarization_record_digest_hex
        );
        assert!(composition
            .markdown_receipt
            .contains("## Token Notarization Summary"));
        assert!(composition
            .html_receipt
            .contains(r#"<section data-kind="token-notarization-summary-v1">"#));
    }

    #[test]
    fn valid_external_carrier_response_completes_compose_successfully() {
        let composition = complete_notarization_authorization_from_carrier_v1(
            build_carrier_completion_request_v1(),
        )
        .unwrap();

        assert_eq!(composition.burn_summary.input_count, 1);
        assert_eq!(composition.burn_summary.output_count, 1);
        assert_eq!(
            composition.summary.proof_statement_label,
            "private_transfer_burn_v1"
        );
    }

    #[test]
    fn complete_compose_fails_closed_without_authorization() {
        let error = compose_notarization_value_v1(load_sample_compose_request_value_v1().unwrap())
            .unwrap_err();

        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidJson(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_compose_input_fails_closed() {
        let error = compose_notarization_value_v1(serde_json::json!({
            "compose_request": {
                "rollup_id_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "asset_id_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "anchor_state_root_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "inputs": [
                    {
                        "nullifier_hex": "1111111111111111111111111111111111111111111111111111111111111111",
                        "note_commitment_reference_hex": "2121212121212121212121212121212121212121212121212121212121212121"
                    },
                    {
                        "nullifier_hex": "1111111111111111111111111111111111111111111111111111111111111111",
                        "note_commitment_reference_hex": "2222222222222222222222222222222222222222222222222222222222222222"
                    }
                ],
                "outputs": [
                    {
                        "note_commitment_hex": "3131313131313131313131313131313131313131313131313131313131313131"
                    }
                ]
            },
            "authorization_envelope": build_authorized_compose_request_v1().authorization_envelope
        }))
        .unwrap_err();

        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidComposition(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn complete_compose_fails_closed_on_mismatched_or_invalid_authorization() {
        let mut completion = build_completion_request_v1();
        completion.session.compose_request.outputs[0].note_commitment_hex =
            "3232323232323232323232323232323232323232323232323232323232323232".to_owned();

        let error = complete_notarization_authorization_v1(completion).unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidAuthorizationSession(_) => {}
            AuraNotarizationWorkbenchErrorV1::InvalidComposition(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let mut completion = build_completion_request_v1();
        completion.sign_response.envelope.signature_hex = "00".to_owned();
        let error = complete_notarization_authorization_v1(completion).unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidComposition(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn downstream_outputs_are_unchanged_after_valid_authorization_completion() {
        let composition_from_completion =
            complete_notarization_authorization_v1(build_completion_request_v1()).unwrap();
        let composition_from_carrier = complete_notarization_authorization_from_carrier_v1(
            build_carrier_completion_request_v1(),
        )
        .unwrap();
        let composition_from_envelope =
            compose_notarization_v1(build_authorized_compose_request_v1()).unwrap();

        assert_eq!(composition_from_completion, composition_from_envelope);
        assert_eq!(composition_from_carrier, composition_from_envelope);
    }

    #[test]
    fn local_dev_signer_is_explicitly_scoped_and_matches_manual_signing() {
        let session = build_authorization_session_v1();
        let local_dev_result =
            local_dev_sign_notarization_authorization_session_v1(session.clone()).unwrap();

        assert_eq!(
            local_dev_result.scope,
            NOTARIZATION_LOCAL_DEV_SIGNER_SCOPE_V1
        );
        assert_eq!(local_dev_result.session_id_hex, session.session_id_hex);
        assert_eq!(
            local_dev_result.sign_response,
            build_sign_response_for_session_v1(&session)
        );

        let mut unsupported = session;
        unsupported
            .authorization_sign_request
            .payload
            .signer_public_key_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let error = local_dev_sign_notarization_authorization_session_v1(unsupported).unwrap_err();
        match error {
            AuraNotarizationWorkbenchErrorV1::InvalidComposition(_)
            | AuraNotarizationWorkbenchErrorV1::UnsupportedLocalDevSignerPublicKey { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn compose_export_bundle_contains_exact_bounded_artifacts_with_stable_names() {
        let completion = build_completion_request_v1();
        let compose_request = completion.session.compose_request.clone();
        let composition = complete_notarization_authorization_v1(completion).unwrap();
        let bundle = build_compose_export_bundle_v1(&compose_request, &composition).unwrap();

        let filenames = bundle
            .iter()
            .map(|entry| entry.filename.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            filenames,
            vec![
                "compose-request.json",
                "transaction.json",
                "public-statement.json",
                "notarization-record.json",
                "receipt.md",
                "receipt.html",
            ]
        );

        assert_eq!(
            bundle[0].contents,
            serde_json::to_string_pretty(&compose_request).unwrap()
        );
        assert_eq!(
            bundle[1].contents,
            serde_json::to_string_pretty(&composition.transaction).unwrap()
        );
        assert_eq!(
            bundle[2].contents,
            serde_json::to_string_pretty(&composition.public_statement).unwrap()
        );
        assert_eq!(
            bundle[3].contents,
            serde_json::to_string_pretty(&composition.notarization_record).unwrap()
        );
        assert_eq!(bundle[4].contents, composition.markdown_receipt);
        assert_eq!(bundle[5].contents, composition.html_receipt);
    }

    #[test]
    fn compose_export_bundle_json_matches_canonical_compose_result_exactly() {
        let completion = build_completion_request_v1();
        let compose_request = completion.session.compose_request.clone();
        let composition = complete_notarization_authorization_v1(completion.clone()).unwrap();
        let export_bundle =
            compose_export_bundle_value_v1(serde_json::to_value(completion).unwrap()).unwrap();

        assert_eq!(export_bundle.compose_request, compose_request);
        assert_eq!(export_bundle.transaction, composition.transaction);
        assert_eq!(export_bundle.public_statement, composition.public_statement);
        assert_eq!(
            export_bundle.notarization_record,
            composition.notarization_record
        );
        assert_eq!(export_bundle.receipt_markdown, composition.markdown_receipt);
        assert_eq!(export_bundle.receipt_html, composition.html_receipt);
    }

    #[test]
    fn compose_export_bundle_json_matches_external_carrier_completion_exactly() {
        let completion = build_carrier_completion_request_v1();
        let compose_request = completion.session.compose_request.clone();
        let composition =
            complete_notarization_authorization_from_carrier_v1(completion.clone()).unwrap();
        let export_bundle =
            compose_export_bundle_value_v1(serde_json::to_value(completion).unwrap()).unwrap();

        assert_eq!(export_bundle.compose_request, compose_request);
        assert_eq!(export_bundle.transaction, composition.transaction);
        assert_eq!(export_bundle.public_statement, composition.public_statement);
        assert_eq!(
            export_bundle.notarization_record,
            composition.notarization_record
        );
        assert_eq!(export_bundle.receipt_markdown, composition.markdown_receipt);
        assert_eq!(export_bundle.receipt_html, composition.html_receipt);
    }
}
