use crate::HASH_LEN_V1;
use serde::{Deserialize, Serialize};

pub const TOKEN_TX_VERSION_V1: u32 = 1;
pub const PRIVATE_TRANSFER_BURN_KIND_V1: u8 = 1;
pub const EXACT_PUBLIC_STATEMENT_TYPE_V1: u8 = 1;
pub const ADMISSION_BURN_FLOOR_V1: u64 = 1;
pub const NOTARY_BURN_FLOOR_V1: u64 = 1;
pub const NOTARY_BURN_INPUT_WEIGHT_V1: u64 = 1;
pub const NOTARY_BURN_OUTPUT_WEIGHT_V1: u64 = 1;

pub const AURA_TOKEN_PRIVATE_TRANSFER_BURN_BODY_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_PRIVATE_TRANSFER_BURN_BODY_V1";
pub const AURA_TOKEN_PRIVATE_TRANSFER_BURN_COMMITMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_PRIVATE_TRANSFER_BURN_COMMITMENT_V1";
pub const AURA_TOKEN_DETERMINISTIC_TRANSACTION_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_DETERMINISTIC_TRANSACTION_V1";
pub const AURA_TOKEN_DETERMINISTIC_PUBLIC_STATEMENT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_DETERMINISTIC_PUBLIC_STATEMENT_V1";
pub const AURA_TOKEN_PROOF_BINDING_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_TOKEN_PROOF_BINDING_V1";
pub const TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_VERSION_V1: u32 = 1;
pub const TOKEN_TRANSACTION_AUTHORIZATION_ENVELOPE_VERSION_V1: u32 = 1;
pub const TOKEN_TRANSACTION_AUTHORIZATION_SIGN_REQUEST_VERSION_V1: u32 = 1;
pub const TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1: u32 = 1;
pub const TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_KIND_EXACT_PUBLIC_STATEMENT_V1: u8 = 1;
pub const TOKEN_TRANSACTION_AUTHORIZATION_SIGNER_KIND_RAW_ED25519_PUBLIC_KEY_V1: u8 = 1;
pub const TOKEN_TRANSACTION_AUTHORIZATION_SCHEME_ED25519_V1: u8 = 1;
pub const AURA_TOKEN_AUTHORIZATION_PAYLOAD_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_AUTHORIZATION_PAYLOAD_V1";
pub const AURA_TOKEN_NOTARY_INPUT_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_TOKEN_NOTARY_INPUT_V1";
pub const AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_V1";
pub const AURA_TOKEN_NOTARY_RECEIPT_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_TOKEN_NOTARY_RECEIPT_V1";
pub const TOKEN_NOTARY_ACK_VERSION_V1: u32 = 1;
pub const AURA_TOKEN_NOTARY_ACK_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_TOKEN_NOTARY_ACK_V1";
pub const AURA_TOKEN_NOTARY_ACK_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_NOTARY_ACK_DIGEST_V1";
pub const AURA_TOKEN_SYMBOLIC_RECEIPT_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_SYMBOLIC_RECEIPT_V1";
pub const TOKEN_SEAL_PAYLOAD_VERSION_V1: u32 = 1;
pub const AURA_TOKEN_SEAL_PAYLOAD_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_TOKEN_SEAL_PAYLOAD_V1";
pub const AURA_TOKEN_SEAL_PAYLOAD_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_SEAL_PAYLOAD_DIGEST_V1";
pub const AURA_TOKEN_UDOT_SEED_DOMAIN_SEPARATOR_V1: &[u8] = b"AURA_TOKEN_UDOT_SEED_V1";
pub const TOKEN_NOTARIZATION_RECORD_VERSION_V1: u32 = 1;
pub const AURA_TOKEN_NOTARIZATION_RECORD_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_NOTARIZATION_RECORD_V1";
pub const AURA_TOKEN_NOTARIZATION_RECORD_DIGEST_DOMAIN_SEPARATOR_V1: &[u8] =
    b"AURA_TOKEN_NOTARIZATION_RECORD_DIGEST_V1";
pub const TOKEN_NOTARIZATION_SUMMARY_VERSION_V1: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenTransactionInputV1 {
    pub nullifier: [u8; HASH_LEN_V1],
    pub note_commitment_reference: [u8; HASH_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenTransactionOutputV1 {
    pub note_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransferBurnPublicStatementV1 {
    pub tx_version: u32,
    pub tx_kind: u8,
    pub proof_statement_type: u8,
    pub rollup_id: [u8; HASH_LEN_V1],
    pub asset_id: [u8; HASH_LEN_V1],
    pub anchor_state_root: [u8; HASH_LEN_V1],
    pub input_nullifiers: Vec<[u8; HASH_LEN_V1]>,
    pub output_note_commitments: Vec<[u8; HASH_LEN_V1]>,
    pub input_count: u64,
    pub output_count: u64,
    pub admission_burn: u64,
    pub notary_burn: u64,
    pub priority_weight: u64,
    pub tx_commitment: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransferBurnProofPlaceholderV1 {
    pub public_statement: PrivateTransferBurnPublicStatementV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransferBurnTransactionV1 {
    pub tx_version: u32,
    pub tx_kind: u8,
    pub proof_statement_type: u8,
    pub rollup_id: [u8; HASH_LEN_V1],
    pub asset_id: [u8; HASH_LEN_V1],
    pub anchor_state_root: [u8; HASH_LEN_V1],
    pub inputs: Vec<TokenTransactionInputV1>,
    pub outputs: Vec<TokenTransactionOutputV1>,
    pub admission_burn: u64,
    pub notary_burn: u64,
    pub priority_weight: u64,
    pub tx_commitment: [u8; HASH_LEN_V1],
    pub proof_placeholder: PrivateTransferBurnProofPlaceholderV1,
}

pub type DeterministicTransactionV1 = PrivateTransferBurnTransactionV1;
pub type DeterministicTransactionPublicStatementV1 = PrivateTransferBurnPublicStatementV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionProofBindingV1 {
    pub proof_statement_type: u8,
    pub public_statement: DeterministicTransactionPublicStatementV1,
    pub public_statement_bytes: Vec<u8>,
    pub proof_binding_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionAuthorizationPayloadV1 {
    pub payload_version: u32,
    pub payload_kind: u8,
    pub tx_version: u32,
    pub tx_kind: u8,
    pub proof_statement_type: u8,
    pub signer_kind: u8,
    pub signer_public_key: [u8; HASH_LEN_V1],
    pub authorization_nonce: [u8; HASH_LEN_V1],
    pub tx_commitment: [u8; HASH_LEN_V1],
    pub public_statement_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionAuthorizationEnvelopeV1 {
    pub envelope_version: u32,
    pub scheme: u8,
    pub payload: TokenTransactionAuthorizationPayloadV1,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionAuthorizedProofBindingV1 {
    pub authorization_envelope: TokenTransactionAuthorizationEnvelopeV1,
    pub proof_binding: TokenTransactionProofBindingV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionNotaryInputV1 {
    pub proof_statement_type: u8,
    pub proof_binding: TokenTransactionProofBindingV1,
    pub proof_binding_bytes: Vec<u8>,
    pub proof_binding_digest: [u8; HASH_LEN_V1],
    pub notary_input_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionNotaryReceiptPreimageV1 {
    pub proof_statement_type: u8,
    pub notary_input: TokenTransactionNotaryInputV1,
    pub receipt_preimage_bytes: Vec<u8>,
    pub receipt_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionNotaryAcknowledgementV1 {
    pub ack_version: u32,
    pub proof_statement_type: u8,
    pub receipt: TokenTransactionNotaryReceiptPreimageV1,
    pub ack_bytes: Vec<u8>,
    pub ack_digest: [u8; HASH_LEN_V1],
    pub symbolic_receipt_preimage: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionSealPayloadV1 {
    pub seal_version: u32,
    pub proof_statement_type: u8,
    pub acknowledgement: TokenTransactionNotaryAcknowledgementV1,
    pub seal_payload_bytes: Vec<u8>,
    pub seal_payload_digest: [u8; HASH_LEN_V1],
    pub udot_seed_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransactionNotarizationRecordV1 {
    pub record_version: u32,
    pub proof_statement_type: u8,
    pub ack_digest: [u8; HASH_LEN_V1],
    pub seal_payload_digest: [u8; HASH_LEN_V1],
    pub udot_seed_digest: [u8; HASH_LEN_V1],
    pub notarization_record_digest: [u8; HASH_LEN_V1],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionNotarizationSummaryV1 {
    pub summary_version: u32,
    pub record_version: u32,
    pub proof_statement_type: u8,
    pub proof_statement_label: String,
    pub ack_digest_hex: String,
    pub seal_payload_digest_hex: String,
    pub udot_seed_digest_hex: String,
    pub notarization_record_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionNotarizationRecordWireV1 {
    pub record_version: u32,
    pub proof_statement_type: u8,
    pub ack_digest_hex: String,
    pub seal_payload_digest_hex: String,
    pub udot_seed_digest_hex: String,
    pub notarization_record_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionInputWireV1 {
    pub nullifier_hex: String,
    pub note_commitment_reference_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionOutputWireV1 {
    pub note_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicTransactionPublicStatementWireV1 {
    pub tx_version: u32,
    pub tx_kind: u8,
    pub proof_statement_type: u8,
    pub rollup_id_hex: String,
    pub asset_id_hex: String,
    pub anchor_state_root_hex: String,
    pub input_nullifier_hexes: Vec<String>,
    pub output_note_commitment_hexes: Vec<String>,
    pub input_count: u64,
    pub output_count: u64,
    pub admission_burn: u64,
    pub notary_burn: u64,
    pub priority_weight: u64,
    pub transaction_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicTransactionWireV1 {
    pub tx_version: u32,
    pub tx_kind: u8,
    pub proof_statement_type: u8,
    pub rollup_id_hex: String,
    pub asset_id_hex: String,
    pub anchor_state_root_hex: String,
    pub inputs: Vec<TokenTransactionInputWireV1>,
    pub outputs: Vec<TokenTransactionOutputWireV1>,
    pub admission_burn: u64,
    pub notary_burn: u64,
    pub priority_weight: u64,
    pub transaction_commitment_hex: String,
    pub public_statement: DeterministicTransactionPublicStatementWireV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionAuthorizationPayloadWireV1 {
    pub payload_version: u32,
    pub payload_kind: u8,
    pub tx_version: u32,
    pub tx_kind: u8,
    pub proof_statement_type: u8,
    pub signer_kind: u8,
    pub signer_public_key_hex: String,
    pub authorization_nonce_hex: String,
    pub transaction_commitment_hex: String,
    pub public_statement_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionAuthorizationEnvelopeWireV1 {
    pub envelope_version: u32,
    pub scheme: u8,
    pub payload: TokenTransactionAuthorizationPayloadWireV1,
    pub signature_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionAuthorizationSignRequestWireV1 {
    pub request_version: u32,
    pub payload: TokenTransactionAuthorizationPayloadWireV1,
    pub payload_bytes_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTransactionAuthorizationSignResponseWireV1 {
    pub response_version: u32,
    pub envelope: TokenTransactionAuthorizationEnvelopeWireV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurnSummaryV1 {
    pub admission_burn: u64,
    pub notary_burn: u64,
    pub priority_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildDeterministicTransactionRequestV1 {
    pub tx_version: u32,
    pub tx_kind: u8,
    pub rollup_id: [u8; HASH_LEN_V1],
    pub asset_id: [u8; HASH_LEN_V1],
    pub anchor_state_root: [u8; HASH_LEN_V1],
    pub inputs: Vec<TokenTransactionInputV1>,
    pub outputs: Vec<TokenTransactionOutputV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildDeterministicTransactionResponseV1 {
    pub transaction: DeterministicTransactionV1,
    pub burns: BurnSummaryV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenTransactionErrorV1 {
    UnsupportedVersion {
        expected: u32,
        actual: u32,
    },
    UnsupportedTransactionKind {
        expected: u8,
        actual: u8,
    },
    UnsupportedProofStatementType {
        expected: u8,
        actual: u8,
    },
    EmptyInputs,
    EmptyOutputs,
    DuplicateNullifier {
        nullifier: [u8; HASH_LEN_V1],
    },
    InputCountOverflow,
    OutputCountOverflow,
    BurnArithmeticOverflow,
    InsufficientAdmissionBurn {
        minimum: u64,
        actual: u64,
    },
    InvalidAdmissionBurn {
        expected: u64,
        actual: u64,
    },
    InsufficientNotaryBurn {
        required: u64,
        actual: u64,
    },
    InvalidNotaryBurn {
        expected: u64,
        actual: u64,
    },
    InvalidPriorityWeight {
        expected: u64,
        actual: u64,
    },
    InvalidTransactionCommitment {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    UnsupportedAuthorizationPayloadVersion {
        expected: u32,
        actual: u32,
    },
    UnsupportedAuthorizationPayloadKind {
        expected: u8,
        actual: u8,
    },
    UnsupportedAuthorizationSignerKind {
        expected: u8,
        actual: u8,
    },
    AuthorizationSignerPublicKeyMustBeNonZero,
    AuthorizationNonceMustBeNonZero,
    UnsupportedAuthorizationEnvelopeVersion {
        expected: u32,
        actual: u32,
    },
    UnsupportedAuthorizationScheme {
        expected: u8,
        actual: u8,
    },
    UnsupportedAuthorizationSignRequestVersion {
        expected: u32,
        actual: u32,
    },
    UnsupportedAuthorizationSignResponseVersion {
        expected: u32,
        actual: u32,
    },
    AuthorizationPublicKeyInvalid,
    AuthorizationSignatureMalformed,
    AuthorizationSignatureInvalid,
    AuthorizationSignRequestPayloadBytesMismatch,
    AuthorizationSignResponsePayloadMismatch,
    AuthorizationSigningKeyMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    AuthorizationTransactionVersionMismatch {
        expected: u32,
        actual: u32,
    },
    AuthorizationTransactionKindMismatch {
        expected: u8,
        actual: u8,
    },
    AuthorizationProofStatementTypeMismatch {
        expected: u8,
        actual: u8,
    },
    AuthorizationTransactionCommitmentMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    AuthorizationPublicStatementDigestMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidProofBindingBytes,
    InvalidProofBindingDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidNotaryInputDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidNotaryInputProofStatementType {
        expected: u8,
        actual: u8,
    },
    UnsupportedNotaryAcknowledgementVersion {
        expected: u32,
        actual: u32,
    },
    InvalidReceiptDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidReceiptProofStatementType {
        expected: u8,
        actual: u8,
    },
    UnsupportedSealPayloadVersion {
        expected: u32,
        actual: u32,
    },
    InvalidAcknowledgementDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidAcknowledgementProofStatementType {
        expected: u8,
        actual: u8,
    },
    UnsupportedNotarizationRecordVersion {
        expected: u32,
        actual: u32,
    },
    InvalidSealPayloadDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidSealPayloadProofStatementType {
        expected: u8,
        actual: u8,
    },
    InvalidUdotSeedDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidNotarizationRecordDigest {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    PublicStatementMismatch,
    InputCountMismatch {
        expected: u64,
        actual: u64,
    },
    OutputCountMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidHexLength {
        field: &'static str,
        expected_bytes: usize,
        actual_nibbles: usize,
    },
    MalformedHex {
        field: &'static str,
    },
}

impl std::fmt::Display for TokenTransactionErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported token tx version: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedTransactionKind { expected, actual } => write!(
                f,
                "unsupported token tx kind: expected {expected}, got {actual}"
            ),
            Self::UnsupportedProofStatementType { expected, actual } => write!(
                f,
                "unsupported proof statement type: expected {expected}, got {actual}"
            ),
            Self::EmptyInputs => write!(f, "token transaction inputs must be non-empty"),
            Self::EmptyOutputs => write!(f, "token transaction outputs must be non-empty"),
            Self::DuplicateNullifier { nullifier } => {
                write!(
                    f,
                    "duplicate input nullifier: {}",
                    crate::LowerHex32(nullifier)
                )
            }
            Self::InputCountOverflow => write!(f, "input count overflow"),
            Self::OutputCountOverflow => write!(f, "output count overflow"),
            Self::BurnArithmeticOverflow => write!(f, "burn arithmetic overflow"),
            Self::InsufficientAdmissionBurn { minimum, actual } => write!(
                f,
                "insufficient admission burn: minimum {minimum}, got {actual}"
            ),
            Self::InvalidAdmissionBurn { expected, actual } => write!(
                f,
                "invalid admission burn: expected {expected}, got {actual}"
            ),
            Self::InsufficientNotaryBurn { required, actual } => write!(
                f,
                "insufficient notary burn: required {required}, got {actual}"
            ),
            Self::InvalidNotaryBurn { expected, actual } => {
                write!(f, "invalid notary burn: expected {expected}, got {actual}")
            }
            Self::InvalidPriorityWeight { expected, actual } => write!(
                f,
                "invalid priority weight: expected {expected}, got {actual}"
            ),
            Self::InvalidTransactionCommitment { expected, actual } => write!(
                f,
                "invalid transaction commitment: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::UnsupportedAuthorizationPayloadVersion { expected, actual } => write!(
                f,
                "unsupported authorization payload version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAuthorizationPayloadKind { expected, actual } => write!(
                f,
                "unsupported authorization payload kind: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAuthorizationSignerKind { expected, actual } => write!(
                f,
                "unsupported authorization signer kind: expected {expected}, got {actual}"
            ),
            Self::AuthorizationSignerPublicKeyMustBeNonZero => {
                write!(f, "authorization signer public key must be non-zero")
            }
            Self::AuthorizationNonceMustBeNonZero => {
                write!(f, "authorization nonce must be non-zero")
            }
            Self::UnsupportedAuthorizationEnvelopeVersion { expected, actual } => write!(
                f,
                "unsupported authorization envelope version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAuthorizationScheme { expected, actual } => write!(
                f,
                "unsupported authorization scheme: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAuthorizationSignRequestVersion { expected, actual } => write!(
                f,
                "unsupported authorization sign request version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAuthorizationSignResponseVersion { expected, actual } => write!(
                f,
                "unsupported authorization sign response version: expected {expected}, got {actual}"
            ),
            Self::AuthorizationPublicKeyInvalid => {
                write!(
                    f,
                    "authorization signer public key is not a valid ed25519 key"
                )
            }
            Self::AuthorizationSignatureMalformed => {
                write!(f, "authorization signature bytes are malformed")
            }
            Self::AuthorizationSignatureInvalid => {
                write!(f, "authorization signature verification failed")
            }
            Self::AuthorizationSignRequestPayloadBytesMismatch => {
                write!(
                    f,
                    "authorization sign request payload bytes do not match payload"
                )
            }
            Self::AuthorizationSignResponsePayloadMismatch => {
                write!(
                    f,
                    "authorization sign response payload does not match sign request"
                )
            }
            Self::AuthorizationSigningKeyMismatch { expected, actual } => write!(
                f,
                "authorization signing key does not match signer public key: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::AuthorizationTransactionVersionMismatch { expected, actual } => write!(
                f,
                "authorization transaction version mismatch: expected {expected}, got {actual}"
            ),
            Self::AuthorizationTransactionKindMismatch { expected, actual } => write!(
                f,
                "authorization transaction kind mismatch: expected {expected}, got {actual}"
            ),
            Self::AuthorizationProofStatementTypeMismatch { expected, actual } => write!(
                f,
                "authorization proof statement type mismatch: expected {expected}, got {actual}"
            ),
            Self::AuthorizationTransactionCommitmentMismatch { expected, actual } => write!(
                f,
                "authorization transaction commitment mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::AuthorizationPublicStatementDigestMismatch { expected, actual } => write!(
                f,
                "authorization public statement digest mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidProofBindingBytes => {
                write!(
                    f,
                    "invalid proof binding bytes for canonical public statement"
                )
            }
            Self::InvalidProofBindingDigest { expected, actual } => write!(
                f,
                "invalid proof binding digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidNotaryInputDigest { expected, actual } => write!(
                f,
                "invalid notary input digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidNotaryInputProofStatementType { expected, actual } => write!(
                f,
                "invalid notary input proof statement type: expected {expected}, got {actual}"
            ),
            Self::UnsupportedNotaryAcknowledgementVersion { expected, actual } => write!(
                f,
                "unsupported notary acknowledgement version: expected {expected}, got {actual}"
            ),
            Self::InvalidReceiptDigest { expected, actual } => write!(
                f,
                "invalid receipt digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidReceiptProofStatementType { expected, actual } => write!(
                f,
                "invalid receipt proof statement type: expected {expected}, got {actual}"
            ),
            Self::UnsupportedSealPayloadVersion { expected, actual } => write!(
                f,
                "unsupported seal payload version: expected {expected}, got {actual}"
            ),
            Self::InvalidAcknowledgementDigest { expected, actual } => write!(
                f,
                "invalid acknowledgement digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidAcknowledgementProofStatementType { expected, actual } => write!(
                f,
                "invalid acknowledgement proof statement type: expected {expected}, got {actual}"
            ),
            Self::UnsupportedNotarizationRecordVersion { expected, actual } => write!(
                f,
                "unsupported notarization record version: expected {expected}, got {actual}"
            ),
            Self::InvalidSealPayloadDigest { expected, actual } => write!(
                f,
                "invalid seal payload digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidSealPayloadProofStatementType { expected, actual } => write!(
                f,
                "invalid seal payload proof statement type: expected {expected}, got {actual}"
            ),
            Self::InvalidUdotSeedDigest { expected, actual } => write!(
                f,
                "invalid udot seed digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidNotarizationRecordDigest { expected, actual } => write!(
                f,
                "invalid notarization record digest: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::PublicStatementMismatch => {
                write!(f, "proof public statement does not match transaction body")
            }
            Self::InputCountMismatch { expected, actual } => {
                write!(f, "input count mismatch: expected {expected}, got {actual}")
            }
            Self::OutputCountMismatch { expected, actual } => {
                write!(
                    f,
                    "output count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidHexLength {
                field,
                expected_bytes,
                actual_nibbles,
            } => write!(
                f,
                "invalid hex length for {field}: expected {} bytes, got {} hex chars",
                expected_bytes, actual_nibbles
            ),
            Self::MalformedHex { field } => write!(f, "malformed lowercase hex for {field}"),
        }
    }
}

impl std::error::Error for TokenTransactionErrorV1 {}

mod acknowledgement;
mod authorization;
mod notarization_record;
mod notarization_summary;
mod notary_input;
mod proof_binding;
mod receipt;
mod seal_payload;
mod shared;
mod transaction_core;

#[allow(unused_imports)]
pub(crate) use acknowledgement::encode_token_transaction_notary_acknowledgement_bytes_v1;
pub use acknowledgement::{
    build_token_transaction_notary_acknowledgement_v1,
    derive_token_transaction_notary_acknowledgement_digest_v1,
    derive_token_transaction_symbolic_receipt_preimage_v1,
};
pub use authorization::{
    build_token_transaction_authorization_payload_v1,
    build_token_transaction_authorization_sign_request_v1,
    build_token_transaction_authorization_sign_response_v1,
    build_token_transaction_authorized_notary_input_v1,
    build_token_transaction_authorized_proof_binding_v1,
    derive_token_transaction_public_statement_digest_v1,
    reconstruct_token_transaction_authorization_envelope_from_sign_response_v1,
    sign_token_transaction_authorization_payload_v1,
    validate_token_transaction_authorization_envelope_v1,
    validate_token_transaction_authorization_sign_response_v1,
};
#[allow(unused_imports)]
pub(crate) use notarization_record::encode_token_transaction_notarization_record_bytes_v1;
pub use notarization_record::{
    build_token_transaction_notarization_record_v1,
    derive_token_transaction_notarization_record_digest_v1,
};
pub use notarization_summary::build_token_transaction_notarization_summary_v1;
pub use notary_input::{
    build_token_transaction_notary_input_v1, derive_token_transaction_notary_input_digest_v1,
};
pub use proof_binding::{
    build_token_transaction_proof_binding_v1, derive_token_transaction_proof_binding_digest_v1,
};
#[allow(unused_imports)]
pub(crate) use receipt::encode_token_transaction_notary_receipt_preimage_bytes_v1;
pub use receipt::{
    build_token_transaction_notary_receipt_preimage_v1,
    derive_token_transaction_notary_receipt_digest_v1,
};
#[allow(unused_imports)]
pub(crate) use seal_payload::encode_token_transaction_seal_payload_bytes_v1;
pub use seal_payload::{
    build_token_transaction_seal_payload_v1, derive_token_transaction_seal_payload_digest_v1,
    derive_token_transaction_udot_seed_digest_v1,
};
#[allow(unused_imports)]
pub(crate) use shared::{decode_hex_32_v1, encode_hex_lower_v1};
pub use transaction_core::{
    admission_burn_v1, build_deterministic_transaction_v1, burn_summary_v1,
    derive_private_transfer_burn_tx_commitment_v1, notary_burn_v1, priority_weight_v1,
};

/*

pub fn build_deterministic_transaction_v1(
    request: BuildDeterministicTransactionRequestV1,
) -> Result<BuildDeterministicTransactionResponseV1, TokenTransactionErrorV1> {
    if request.tx_version != TOKEN_TX_VERSION_V1 {
        return Err(TokenTransactionErrorV1::UnsupportedVersion {
            expected: TOKEN_TX_VERSION_V1,
            actual: request.tx_version,
        });
    }
    if request.tx_kind != PRIVATE_TRANSFER_BURN_KIND_V1 {
        return Err(TokenTransactionErrorV1::UnsupportedTransactionKind {
            expected: PRIVATE_TRANSFER_BURN_KIND_V1,
            actual: request.tx_kind,
        });
    }

    let transaction = PrivateTransferBurnTransactionV1::new(
        request.rollup_id,
        request.asset_id,
        request.anchor_state_root,
        request.inputs,
        request.outputs,
    )?;
    transaction.validate()?;

    let burns = BurnSummaryV1 {
        admission_burn: transaction.admission_burn,
        notary_burn: transaction.notary_burn,
        priority_weight: transaction.priority_weight,
    };

    Ok(BuildDeterministicTransactionResponseV1 { transaction, burns })
}

pub fn admission_burn_v1() -> u64 {
    ADMISSION_BURN_FLOOR_V1
}

pub fn notary_burn_v1(
    input_count: u64,
    output_count: u64,
) -> Result<u64, TokenTransactionErrorV1> {
    let input_component = NOTARY_BURN_INPUT_WEIGHT_V1
        .checked_mul(input_count)
        .ok_or(TokenTransactionErrorV1::BurnArithmeticOverflow)?;
    let output_component = NOTARY_BURN_OUTPUT_WEIGHT_V1
        .checked_mul(output_count)
        .ok_or(TokenTransactionErrorV1::BurnArithmeticOverflow)?;

    NOTARY_BURN_FLOOR_V1
        .checked_add(input_component)
        .and_then(|value| value.checked_add(output_component))
        .ok_or(TokenTransactionErrorV1::BurnArithmeticOverflow)
}

pub fn priority_weight_v1(
    admission_burn: u64,
    notary_burn: u64,
) -> Result<u64, TokenTransactionErrorV1> {
    admission_burn
        .checked_add(notary_burn)
        .ok_or(TokenTransactionErrorV1::BurnArithmeticOverflow)
}

pub fn burn_summary_v1(
    input_count: u64,
    output_count: u64,
) -> Result<BurnSummaryV1, TokenTransactionErrorV1> {
    let admission_burn = admission_burn_v1();
    let notary_burn = notary_burn_v1(input_count, output_count)?;
    let priority_weight = priority_weight_v1(admission_burn, notary_burn)?;
    Ok(BurnSummaryV1 {
        admission_burn,
        notary_burn,
        priority_weight,
    })
}

impl PrivateTransferBurnTransactionV1 {
    pub fn new(
        rollup_id: [u8; HASH_LEN_V1],
        asset_id: [u8; HASH_LEN_V1],
        anchor_state_root: [u8; HASH_LEN_V1],
        inputs: Vec<TokenTransactionInputV1>,
        outputs: Vec<TokenTransactionOutputV1>,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let input_count =
            u64::try_from(inputs.len()).map_err(|_| TokenTransactionErrorV1::InputCountOverflow)?;
        let output_count = u64::try_from(outputs.len())
            .map_err(|_| TokenTransactionErrorV1::OutputCountOverflow)?;
        let burns = burn_summary_v1(input_count, output_count)?;

        let tx_commitment = derive_private_transfer_burn_tx_commitment_v1(
            TOKEN_TX_VERSION_V1,
            PRIVATE_TRANSFER_BURN_KIND_V1,
            &rollup_id,
            &asset_id,
            &anchor_state_root,
            &inputs,
            &outputs,
            burns.admission_burn,
            burns.notary_burn,
            burns.priority_weight,
        );

        let public_statement = PrivateTransferBurnPublicStatementV1 {
            tx_version: TOKEN_TX_VERSION_V1,
            tx_kind: PRIVATE_TRANSFER_BURN_KIND_V1,
            proof_statement_type: EXACT_PUBLIC_STATEMENT_TYPE_V1,
            rollup_id,
            asset_id,
            anchor_state_root,
            input_nullifiers: inputs.iter().map(|input| input.nullifier).collect(),
            output_note_commitments: outputs.iter().map(|output| output.note_commitment).collect(),
            input_count,
            output_count,
            admission_burn: burns.admission_burn,
            notary_burn: burns.notary_burn,
            priority_weight: burns.priority_weight,
            tx_commitment,
        };

        Ok(Self {
            tx_version: TOKEN_TX_VERSION_V1,
            tx_kind: PRIVATE_TRANSFER_BURN_KIND_V1,
            proof_statement_type: EXACT_PUBLIC_STATEMENT_TYPE_V1,
            rollup_id,
            asset_id,
            anchor_state_root,
            inputs,
            outputs,
            admission_burn: burns.admission_burn,
            notary_burn: burns.notary_burn,
            priority_weight: burns.priority_weight,
            tx_commitment,
            proof_placeholder: PrivateTransferBurnProofPlaceholderV1 { public_statement },
        })
    }

    pub fn input_count(&self) -> Result<u64, TokenTransactionErrorV1> {
        u64::try_from(self.inputs.len()).map_err(|_| TokenTransactionErrorV1::InputCountOverflow)
    }

    pub fn output_count(&self) -> Result<u64, TokenTransactionErrorV1> {
        u64::try_from(self.outputs.len()).map_err(|_| TokenTransactionErrorV1::OutputCountOverflow)
    }

    pub fn canonical_body_bytes(&self) -> Result<Vec<u8>, TokenTransactionErrorV1> {
        encode_private_transfer_burn_body_v1(
            self.tx_version,
            self.tx_kind,
            &self.rollup_id,
            &self.asset_id,
            &self.anchor_state_root,
            &self.inputs,
            &self.outputs,
            self.admission_burn,
            self.notary_burn,
            self.priority_weight,
        )
    }

    pub fn expected_public_statement(
        &self,
    ) -> Result<PrivateTransferBurnPublicStatementV1, TokenTransactionErrorV1> {
        let input_count = self.input_count()?;
        let output_count = self.output_count()?;
        let expected_tx_commitment = derive_private_transfer_burn_tx_commitment_v1(
            self.tx_version,
            self.tx_kind,
            &self.rollup_id,
            &self.asset_id,
            &self.anchor_state_root,
            &self.inputs,
            &self.outputs,
            self.admission_burn,
            self.notary_burn,
            self.priority_weight,
        );

        Ok(PrivateTransferBurnPublicStatementV1 {
            tx_version: self.tx_version,
            tx_kind: self.tx_kind,
            proof_statement_type: self.proof_statement_type,
            rollup_id: self.rollup_id,
            asset_id: self.asset_id,
            anchor_state_root: self.anchor_state_root,
            input_nullifiers: self.inputs.iter().map(|input| input.nullifier).collect(),
            output_note_commitments: self
                .outputs
                .iter()
                .map(|output| output.note_commitment)
                .collect(),
            input_count,
            output_count,
            admission_burn: self.admission_burn,
            notary_burn: self.notary_burn,
            priority_weight: self.priority_weight,
            tx_commitment: expected_tx_commitment,
        })
    }

    pub fn validate(&self) -> Result<(), TokenTransactionErrorV1> {
        if self.tx_version != TOKEN_TX_VERSION_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedVersion {
                expected: TOKEN_TX_VERSION_V1,
                actual: self.tx_version,
            });
        }
        if self.tx_kind != PRIVATE_TRANSFER_BURN_KIND_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedTransactionKind {
                expected: PRIVATE_TRANSFER_BURN_KIND_V1,
                actual: self.tx_kind,
            });
        }
        if self.proof_statement_type != EXACT_PUBLIC_STATEMENT_TYPE_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedProofStatementType {
                expected: EXACT_PUBLIC_STATEMENT_TYPE_V1,
                actual: self.proof_statement_type,
            });
        }
        if self.inputs.is_empty() {
            return Err(TokenTransactionErrorV1::EmptyInputs);
        }
        if self.outputs.is_empty() {
            return Err(TokenTransactionErrorV1::EmptyOutputs);
        }

        let mut seen_nullifiers = BTreeSet::new();
        for input in &self.inputs {
            if !seen_nullifiers.insert(input.nullifier) {
                return Err(TokenTransactionErrorV1::DuplicateNullifier {
                    nullifier: input.nullifier,
                });
            }
        }

        let input_count = self.input_count()?;
        let output_count = self.output_count()?;
        let statement = &self.proof_placeholder.public_statement;
        if statement.input_count != input_count {
            return Err(TokenTransactionErrorV1::InputCountMismatch {
                expected: input_count,
                actual: statement.input_count,
            });
        }
        if statement.output_count != output_count {
            return Err(TokenTransactionErrorV1::OutputCountMismatch {
                expected: output_count,
                actual: statement.output_count,
            });
        }
        let expected_admission_burn = admission_burn_v1();
        if self.admission_burn < expected_admission_burn {
            return Err(TokenTransactionErrorV1::InsufficientAdmissionBurn {
                minimum: expected_admission_burn,
                actual: self.admission_burn,
            });
        }
        if self.admission_burn != expected_admission_burn {
            return Err(TokenTransactionErrorV1::InvalidAdmissionBurn {
                expected: expected_admission_burn,
                actual: self.admission_burn,
            });
        }

        let expected_notary_burn = notary_burn_v1(input_count, output_count)?;
        if self.notary_burn < expected_notary_burn {
            return Err(TokenTransactionErrorV1::InsufficientNotaryBurn {
                required: expected_notary_burn,
                actual: self.notary_burn,
            });
        }
        if self.notary_burn != expected_notary_burn {
            return Err(TokenTransactionErrorV1::InvalidNotaryBurn {
                expected: expected_notary_burn,
                actual: self.notary_burn,
            });
        }

        let expected_priority_weight =
            priority_weight_v1(expected_admission_burn, expected_notary_burn)?;
        if self.priority_weight != expected_priority_weight {
            return Err(TokenTransactionErrorV1::InvalidPriorityWeight {
                expected: expected_priority_weight,
                actual: self.priority_weight,
            });
        }

        let expected_tx_commitment = derive_private_transfer_burn_tx_commitment_v1(
            self.tx_version,
            self.tx_kind,
            &self.rollup_id,
            &self.asset_id,
            &self.anchor_state_root,
            &self.inputs,
            &self.outputs,
            self.admission_burn,
            self.notary_burn,
            self.priority_weight,
        );
        if self.tx_commitment != expected_tx_commitment {
            return Err(TokenTransactionErrorV1::InvalidTransactionCommitment {
                expected: expected_tx_commitment,
                actual: self.tx_commitment,
            });
        }

        let expected_statement = self.expected_public_statement()?;
        if self.proof_placeholder.public_statement != expected_statement {
            return Err(TokenTransactionErrorV1::PublicStatementMismatch);
        }

        Ok(())
    }

    /// Canonical transaction bytes are:
    ///
    /// `D_TX || tx_version:u32_le || tx_kind:u8 || proof_statement_type:u8 ||
    /// rollup_id:32 || asset_id:32 || anchor_state_root:32 ||
    /// input_count:u64_le || (nullifier:32 || note_commitment_reference:32)* ||
    /// output_count:u64_le || note_commitment:32* ||
    /// admission_burn:u64_le || notary_burn:u64_le || priority_weight:u64_le ||
    /// transaction_commitment:32`
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TokenTransactionErrorV1> {
        encode_deterministic_transaction_bytes_v1(self)
    }

    pub fn to_wire(&self) -> DeterministicTransactionWireV1 {
        DeterministicTransactionWireV1 {
            tx_version: self.tx_version,
            tx_kind: self.tx_kind,
            proof_statement_type: self.proof_statement_type,
            rollup_id_hex: encode_hex_lower_v1(&self.rollup_id),
            asset_id_hex: encode_hex_lower_v1(&self.asset_id),
            anchor_state_root_hex: encode_hex_lower_v1(&self.anchor_state_root),
            inputs: self
                .inputs
                .iter()
                .map(|input| TokenTransactionInputWireV1 {
                    nullifier_hex: encode_hex_lower_v1(&input.nullifier),
                    note_commitment_reference_hex: encode_hex_lower_v1(
                        &input.note_commitment_reference,
                    ),
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| TokenTransactionOutputWireV1 {
                    note_commitment_hex: encode_hex_lower_v1(&output.note_commitment),
                })
                .collect(),
            admission_burn: self.admission_burn,
            notary_burn: self.notary_burn,
            priority_weight: self.priority_weight,
            transaction_commitment_hex: encode_hex_lower_v1(&self.tx_commitment),
            public_statement: self.proof_placeholder.public_statement.to_wire(),
        }
    }

    pub fn from_wire(
        payload: DeterministicTransactionWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let transaction = Self {
            tx_version: payload.tx_version,
            tx_kind: payload.tx_kind,
            proof_statement_type: payload.proof_statement_type,
            rollup_id: decode_hex_32_v1("rollup_id_hex", &payload.rollup_id_hex)?,
            asset_id: decode_hex_32_v1("asset_id_hex", &payload.asset_id_hex)?,
            anchor_state_root: decode_hex_32_v1(
                "anchor_state_root_hex",
                &payload.anchor_state_root_hex,
            )?,
            inputs: payload
                .inputs
                .into_iter()
                .map(TokenTransactionInputV1::from_wire)
                .collect::<Result<Vec<_>, _>>()?,
            outputs: payload
                .outputs
                .into_iter()
                .map(TokenTransactionOutputV1::from_wire)
                .collect::<Result<Vec<_>, _>>()?,
            admission_burn: payload.admission_burn,
            notary_burn: payload.notary_burn,
            priority_weight: payload.priority_weight,
            tx_commitment: decode_hex_32_v1(
                "transaction_commitment_hex",
                &payload.transaction_commitment_hex,
            )?,
            proof_placeholder: PrivateTransferBurnProofPlaceholderV1 {
                public_statement: PrivateTransferBurnPublicStatementV1::from_wire(
                    payload.public_statement,
                )?,
            },
        };
        transaction.validate()?;
        Ok(transaction)
    }
}

pub fn derive_private_transfer_burn_tx_commitment_v1(
    tx_version: u32,
    tx_kind: u8,
    rollup_id: &[u8; HASH_LEN_V1],
    asset_id: &[u8; HASH_LEN_V1],
    anchor_state_root: &[u8; HASH_LEN_V1],
    inputs: &[TokenTransactionInputV1],
    outputs: &[TokenTransactionOutputV1],
    admission_burn: u64,
    notary_burn: u64,
    priority_weight: u64,
) -> [u8; HASH_LEN_V1] {
    let body_bytes = encode_private_transfer_burn_body_v1(
        tx_version,
        tx_kind,
        rollup_id,
        asset_id,
        anchor_state_root,
        inputs,
        outputs,
        admission_burn,
        notary_burn,
        priority_weight,
    )
    .expect("private_transfer_burn body encoding overflow");

    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_PRIVATE_TRANSFER_BURN_COMMITMENT_DOMAIN_SEPARATOR_V1.len() + body_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_PRIVATE_TRANSFER_BURN_COMMITMENT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(&body_bytes);
    sha256_bytes(&preimage)
}

impl TokenTransactionInputV1 {
    pub fn from_wire(payload: TokenTransactionInputWireV1) -> Result<Self, TokenTransactionErrorV1> {
        Ok(Self {
            nullifier: decode_hex_32_v1("inputs[].nullifier_hex", &payload.nullifier_hex)?,
            note_commitment_reference: decode_hex_32_v1(
                "inputs[].note_commitment_reference_hex",
                &payload.note_commitment_reference_hex,
            )?,
        })
    }
}

impl TokenTransactionOutputV1 {
    pub fn from_wire(
        payload: TokenTransactionOutputWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        Ok(Self {
            note_commitment: decode_hex_32_v1(
                "outputs[].note_commitment_hex",
                &payload.note_commitment_hex,
            )?,
        })
    }
}

impl PrivateTransferBurnPublicStatementV1 {
    /// Canonical public-statement bytes are:
    ///
    /// `D_PS || tx_version:u32_le || tx_kind:u8 || proof_statement_type:u8 ||
    /// rollup_id:32 || asset_id:32 || anchor_state_root:32 ||
    /// input_count:u64_le || nullifier:32* ||
    /// output_count:u64_le || note_commitment:32* ||
    /// admission_burn:u64_le || notary_burn:u64_le || priority_weight:u64_le ||
    /// transaction_commitment:32`
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TokenTransactionErrorV1> {
        encode_public_statement_bytes_v1(self)
    }

    pub fn validate(&self) -> Result<(), TokenTransactionErrorV1> {
        if self.tx_version != TOKEN_TX_VERSION_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedVersion {
                expected: TOKEN_TX_VERSION_V1,
                actual: self.tx_version,
            });
        }
        if self.tx_kind != PRIVATE_TRANSFER_BURN_KIND_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedTransactionKind {
                expected: PRIVATE_TRANSFER_BURN_KIND_V1,
                actual: self.tx_kind,
            });
        }
        if self.proof_statement_type != EXACT_PUBLIC_STATEMENT_TYPE_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedProofStatementType {
                expected: EXACT_PUBLIC_STATEMENT_TYPE_V1,
                actual: self.proof_statement_type,
            });
        }
        let _ = self.canonical_bytes()?;
        let expected_admission_burn = admission_burn_v1();
        if self.admission_burn < expected_admission_burn {
            return Err(TokenTransactionErrorV1::InsufficientAdmissionBurn {
                minimum: expected_admission_burn,
                actual: self.admission_burn,
            });
        }
        if self.admission_burn != expected_admission_burn {
            return Err(TokenTransactionErrorV1::InvalidAdmissionBurn {
                expected: expected_admission_burn,
                actual: self.admission_burn,
            });
        }
        let expected_notary_burn = notary_burn_v1(self.input_count, self.output_count)?;
        if self.notary_burn < expected_notary_burn {
            return Err(TokenTransactionErrorV1::InsufficientNotaryBurn {
                required: expected_notary_burn,
                actual: self.notary_burn,
            });
        }
        if self.notary_burn != expected_notary_burn {
            return Err(TokenTransactionErrorV1::InvalidNotaryBurn {
                expected: expected_notary_burn,
                actual: self.notary_burn,
            });
        }
        let expected_priority_weight =
            priority_weight_v1(self.admission_burn, self.notary_burn)?;
        if self.priority_weight != expected_priority_weight {
            return Err(TokenTransactionErrorV1::InvalidPriorityWeight {
                expected: expected_priority_weight,
                actual: self.priority_weight,
            });
        }
        Ok(())
    }

    pub fn to_wire(&self) -> DeterministicTransactionPublicStatementWireV1 {
        DeterministicTransactionPublicStatementWireV1 {
            tx_version: self.tx_version,
            tx_kind: self.tx_kind,
            proof_statement_type: self.proof_statement_type,
            rollup_id_hex: encode_hex_lower_v1(&self.rollup_id),
            asset_id_hex: encode_hex_lower_v1(&self.asset_id),
            anchor_state_root_hex: encode_hex_lower_v1(&self.anchor_state_root),
            input_nullifier_hexes: self
                .input_nullifiers
                .iter()
                .map(|nullifier| encode_hex_lower_v1(nullifier))
                .collect(),
            output_note_commitment_hexes: self
                .output_note_commitments
                .iter()
                .map(|commitment| encode_hex_lower_v1(commitment))
                .collect(),
            input_count: self.input_count,
            output_count: self.output_count,
            admission_burn: self.admission_burn,
            notary_burn: self.notary_burn,
            priority_weight: self.priority_weight,
            transaction_commitment_hex: encode_hex_lower_v1(&self.tx_commitment),
        }
    }

    pub fn from_wire(
        payload: DeterministicTransactionPublicStatementWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let input_nullifiers = payload
            .input_nullifier_hexes
            .iter()
            .map(|value| decode_hex_32_v1("input_nullifier_hexes[]", value))
            .collect::<Result<Vec<_>, _>>()?;
        let output_note_commitments = payload
            .output_note_commitment_hexes
            .iter()
            .map(|value| decode_hex_32_v1("output_note_commitment_hexes[]", value))
            .collect::<Result<Vec<_>, _>>()?;

        let expected_input_count = u64::try_from(input_nullifiers.len())
            .map_err(|_| TokenTransactionErrorV1::InputCountOverflow)?;
        let expected_output_count = u64::try_from(output_note_commitments.len())
            .map_err(|_| TokenTransactionErrorV1::OutputCountOverflow)?;
        if payload.input_count != expected_input_count {
            return Err(TokenTransactionErrorV1::InputCountMismatch {
                expected: expected_input_count,
                actual: payload.input_count,
            });
        }
        if payload.output_count != expected_output_count {
            return Err(TokenTransactionErrorV1::OutputCountMismatch {
                expected: expected_output_count,
                actual: payload.output_count,
            });
        }

        let statement = Self {
            tx_version: payload.tx_version,
            tx_kind: payload.tx_kind,
            proof_statement_type: payload.proof_statement_type,
            rollup_id: decode_hex_32_v1("rollup_id_hex", &payload.rollup_id_hex)?,
            asset_id: decode_hex_32_v1("asset_id_hex", &payload.asset_id_hex)?,
            anchor_state_root: decode_hex_32_v1(
                "anchor_state_root_hex",
                &payload.anchor_state_root_hex,
            )?,
            input_nullifiers,
            output_note_commitments,
            input_count: payload.input_count,
            output_count: payload.output_count,
            admission_burn: payload.admission_burn,
            notary_burn: payload.notary_burn,
            priority_weight: payload.priority_weight,
            tx_commitment: decode_hex_32_v1(
                "transaction_commitment_hex",
                &payload.transaction_commitment_hex,
            )?,
        };
        statement.validate()?;
        Ok(statement)
    }
}

impl TokenTransactionProofBindingV1 {
    pub fn from_public_statement(
        public_statement: DeterministicTransactionPublicStatementV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        public_statement.validate()?;
        let public_statement_bytes = public_statement.canonical_bytes()?;
        let proof_binding_digest =
            derive_token_transaction_proof_binding_digest_v1(&public_statement_bytes);

        Ok(Self {
            proof_statement_type: public_statement.proof_statement_type,
            public_statement,
            public_statement_bytes,
            proof_binding_digest,
        })
    }
}

impl TokenTransactionNotaryInputV1 {
    pub fn from_proof_binding(
        proof_binding: TokenTransactionProofBindingV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        proof_binding.public_statement.validate()?;

        let expected_bytes = proof_binding.public_statement.canonical_bytes()?;
        if proof_binding.public_statement_bytes != expected_bytes {
            return Err(TokenTransactionErrorV1::InvalidProofBindingBytes);
        }

        let expected_digest =
            derive_token_transaction_proof_binding_digest_v1(&proof_binding.public_statement_bytes);
        if proof_binding.proof_binding_digest != expected_digest {
            return Err(TokenTransactionErrorV1::InvalidProofBindingDigest {
                expected: expected_digest,
                actual: proof_binding.proof_binding_digest,
            });
        }

        let notary_input_digest = derive_token_transaction_notary_input_digest_v1(
            &proof_binding.public_statement_bytes,
            &proof_binding.proof_binding_digest,
        );

        Ok(Self {
            proof_statement_type: proof_binding.proof_statement_type,
            proof_binding_bytes: proof_binding.public_statement_bytes.clone(),
            proof_binding_digest: proof_binding.proof_binding_digest,
            proof_binding,
            notary_input_digest,
        })
    }
}

impl TokenTransactionNotaryReceiptPreimageV1 {
    pub fn from_notary_input(
        notary_input: TokenTransactionNotaryInputV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_notary_input =
            TokenTransactionNotaryInputV1::from_proof_binding(notary_input.proof_binding.clone())?;
        if notary_input.proof_statement_type != rebuilt_notary_input.proof_statement_type {
            return Err(TokenTransactionErrorV1::InvalidNotaryInputProofStatementType {
                expected: rebuilt_notary_input.proof_statement_type,
                actual: notary_input.proof_statement_type,
            });
        }
        if notary_input.notary_input_digest != rebuilt_notary_input.notary_input_digest {
            return Err(TokenTransactionErrorV1::InvalidNotaryInputDigest {
                expected: rebuilt_notary_input.notary_input_digest,
                actual: notary_input.notary_input_digest,
            });
        }

        let receipt_preimage_bytes = encode_token_transaction_notary_receipt_preimage_bytes_v1(
            notary_input.proof_statement_type,
            &notary_input.notary_input_digest,
            &notary_input.proof_binding_digest,
            &notary_input.proof_binding_bytes,
        );
        let receipt_digest =
            derive_token_transaction_notary_receipt_digest_v1(&receipt_preimage_bytes);

        Ok(Self {
            proof_statement_type: notary_input.proof_statement_type,
            notary_input,
            receipt_preimage_bytes,
            receipt_digest,
        })
    }
}

impl TokenTransactionNotaryAcknowledgementV1 {
    pub fn from_receipt(
        receipt: TokenTransactionNotaryReceiptPreimageV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_receipt =
            TokenTransactionNotaryReceiptPreimageV1::from_notary_input(receipt.notary_input.clone())?;
        if receipt.proof_statement_type != rebuilt_receipt.proof_statement_type {
            return Err(TokenTransactionErrorV1::InvalidReceiptProofStatementType {
                expected: rebuilt_receipt.proof_statement_type,
                actual: receipt.proof_statement_type,
            });
        }
        if receipt.receipt_digest != rebuilt_receipt.receipt_digest {
            return Err(TokenTransactionErrorV1::InvalidReceiptDigest {
                expected: rebuilt_receipt.receipt_digest,
                actual: receipt.receipt_digest,
            });
        }

        let ack_bytes = encode_token_transaction_notary_acknowledgement_bytes_v1(
            TOKEN_NOTARY_ACK_VERSION_V1,
            receipt.proof_statement_type,
            &receipt.receipt_digest,
        );
        let ack_digest = derive_token_transaction_notary_acknowledgement_digest_v1(&ack_bytes);
        let symbolic_receipt_preimage =
            derive_token_transaction_symbolic_receipt_preimage_v1(&ack_digest);

        Ok(Self {
            ack_version: TOKEN_NOTARY_ACK_VERSION_V1,
            proof_statement_type: receipt.proof_statement_type,
            receipt,
            ack_bytes,
            ack_digest,
            symbolic_receipt_preimage,
        })
    }
}

impl TokenTransactionSealPayloadV1 {
    pub fn from_acknowledgement(
        acknowledgement: TokenTransactionNotaryAcknowledgementV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_ack =
            TokenTransactionNotaryAcknowledgementV1::from_receipt(acknowledgement.receipt.clone())?;
        if acknowledgement.ack_version != TOKEN_NOTARY_ACK_VERSION_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedNotaryAcknowledgementVersion {
                expected: TOKEN_NOTARY_ACK_VERSION_V1,
                actual: acknowledgement.ack_version,
            });
        }
        if acknowledgement.proof_statement_type != rebuilt_ack.proof_statement_type {
            return Err(TokenTransactionErrorV1::InvalidAcknowledgementProofStatementType {
                expected: rebuilt_ack.proof_statement_type,
                actual: acknowledgement.proof_statement_type,
            });
        }
        if acknowledgement.ack_digest != rebuilt_ack.ack_digest {
            return Err(TokenTransactionErrorV1::InvalidAcknowledgementDigest {
                expected: rebuilt_ack.ack_digest,
                actual: acknowledgement.ack_digest,
            });
        }

        let seal_payload_bytes = encode_token_transaction_seal_payload_bytes_v1(
            TOKEN_SEAL_PAYLOAD_VERSION_V1,
            acknowledgement.proof_statement_type,
            &acknowledgement.ack_digest,
            &acknowledgement.symbolic_receipt_preimage,
        );
        let seal_payload_digest =
            derive_token_transaction_seal_payload_digest_v1(&seal_payload_bytes);
        let udot_seed_digest = derive_token_transaction_udot_seed_digest_v1(&seal_payload_digest);

        Ok(Self {
            seal_version: TOKEN_SEAL_PAYLOAD_VERSION_V1,
            proof_statement_type: acknowledgement.proof_statement_type,
            acknowledgement,
            seal_payload_bytes,
            seal_payload_digest,
            udot_seed_digest,
        })
    }
}

impl TokenTransactionNotarizationRecordV1 {
    pub fn from_seal_payload(
        seal_payload: TokenTransactionSealPayloadV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_seal =
            TokenTransactionSealPayloadV1::from_acknowledgement(seal_payload.acknowledgement.clone())?;
        if seal_payload.seal_version != TOKEN_SEAL_PAYLOAD_VERSION_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedSealPayloadVersion {
                expected: TOKEN_SEAL_PAYLOAD_VERSION_V1,
                actual: seal_payload.seal_version,
            });
        }
        if seal_payload.proof_statement_type != rebuilt_seal.proof_statement_type {
            return Err(TokenTransactionErrorV1::InvalidSealPayloadProofStatementType {
                expected: rebuilt_seal.proof_statement_type,
                actual: seal_payload.proof_statement_type,
            });
        }
        if seal_payload.seal_payload_digest != rebuilt_seal.seal_payload_digest {
            return Err(TokenTransactionErrorV1::InvalidSealPayloadDigest {
                expected: rebuilt_seal.seal_payload_digest,
                actual: seal_payload.seal_payload_digest,
            });
        }
        if seal_payload.udot_seed_digest != rebuilt_seal.udot_seed_digest {
            return Err(TokenTransactionErrorV1::InvalidUdotSeedDigest {
                expected: rebuilt_seal.udot_seed_digest,
                actual: seal_payload.udot_seed_digest,
            });
        }

        let ack_digest = seal_payload.acknowledgement.ack_digest;
        let notarization_record_bytes = encode_token_transaction_notarization_record_bytes_v1(
            TOKEN_NOTARIZATION_RECORD_VERSION_V1,
            seal_payload.proof_statement_type,
            &ack_digest,
            &seal_payload.seal_payload_digest,
            &seal_payload.udot_seed_digest,
        );
        let notarization_record_digest =
            derive_token_transaction_notarization_record_digest_v1(&notarization_record_bytes);

        Ok(Self {
            record_version: TOKEN_NOTARIZATION_RECORD_VERSION_V1,
            proof_statement_type: seal_payload.proof_statement_type,
            ack_digest,
            seal_payload_digest: rebuilt_seal.seal_payload_digest,
            udot_seed_digest: rebuilt_seal.udot_seed_digest,
            notarization_record_digest,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_token_transaction_notarization_record_bytes_v1(
            self.record_version,
            self.proof_statement_type,
            &self.ack_digest,
            &self.seal_payload_digest,
            &self.udot_seed_digest,
        )
    }

    pub fn to_wire(&self) -> TokenTransactionNotarizationRecordWireV1 {
        TokenTransactionNotarizationRecordWireV1 {
            record_version: self.record_version,
            proof_statement_type: self.proof_statement_type,
            ack_digest_hex: encode_hex_lower_v1(&self.ack_digest),
            seal_payload_digest_hex: encode_hex_lower_v1(&self.seal_payload_digest),
            udot_seed_digest_hex: encode_hex_lower_v1(&self.udot_seed_digest),
            notarization_record_digest_hex: encode_hex_lower_v1(&self.notarization_record_digest),
        }
    }

    pub fn from_wire(
        payload: TokenTransactionNotarizationRecordWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        if payload.record_version != TOKEN_NOTARIZATION_RECORD_VERSION_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedNotarizationRecordVersion {
                expected: TOKEN_NOTARIZATION_RECORD_VERSION_V1,
                actual: payload.record_version,
            });
        }

        let ack_digest = decode_hex_32_v1("ack_digest_hex", &payload.ack_digest_hex)?;
        let seal_payload_digest =
            decode_hex_32_v1("seal_payload_digest_hex", &payload.seal_payload_digest_hex)?;
        let udot_seed_digest = decode_hex_32_v1("udot_seed_digest_hex", &payload.udot_seed_digest_hex)?;
        let notarization_record_digest = decode_hex_32_v1(
            "notarization_record_digest_hex",
            &payload.notarization_record_digest_hex,
        )?;

        let canonical_bytes = encode_token_transaction_notarization_record_bytes_v1(
            payload.record_version,
            payload.proof_statement_type,
            &ack_digest,
            &seal_payload_digest,
            &udot_seed_digest,
        );
        let symbolic_receipt_preimage = derive_token_transaction_symbolic_receipt_preimage_v1(&ack_digest);
        let expected_seal_payload_digest = derive_token_transaction_seal_payload_digest_v1(
            &encode_token_transaction_seal_payload_bytes_v1(
                TOKEN_SEAL_PAYLOAD_VERSION_V1,
                payload.proof_statement_type,
                &ack_digest,
                &symbolic_receipt_preimage,
            ),
        );
        if seal_payload_digest != expected_seal_payload_digest {
            return Err(TokenTransactionErrorV1::InvalidSealPayloadDigest {
                expected: expected_seal_payload_digest,
                actual: seal_payload_digest,
            });
        }
        let expected_digest =
            derive_token_transaction_notarization_record_digest_v1(&canonical_bytes);
        if notarization_record_digest != expected_digest {
            return Err(TokenTransactionErrorV1::InvalidNotarizationRecordDigest {
                expected: expected_digest,
                actual: notarization_record_digest,
            });
        }

        let expected_udot = derive_token_transaction_udot_seed_digest_v1(&seal_payload_digest);
        if udot_seed_digest != expected_udot {
            return Err(TokenTransactionErrorV1::InvalidUdotSeedDigest {
                expected: expected_udot,
                actual: udot_seed_digest,
            });
        }

        Ok(Self {
            record_version: payload.record_version,
            proof_statement_type: payload.proof_statement_type,
            ack_digest,
            seal_payload_digest,
            udot_seed_digest,
            notarization_record_digest,
        })
    }
}

impl TokenTransactionNotarizationSummaryV1 {
    pub fn from_record_wire(
        payload: TokenTransactionNotarizationRecordWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let record = TokenTransactionNotarizationRecordV1::from_wire(payload)?;
        let proof_statement_label = proof_statement_label_v1(record.proof_statement_type)?;

        Ok(Self {
            summary_version: TOKEN_NOTARIZATION_SUMMARY_VERSION_V1,
            record_version: record.record_version,
            proof_statement_type: record.proof_statement_type,
            proof_statement_label: proof_statement_label.to_owned(),
            ack_digest_hex: encode_hex_lower_v1(&record.ack_digest),
            seal_payload_digest_hex: encode_hex_lower_v1(&record.seal_payload_digest),
            udot_seed_digest_hex: encode_hex_lower_v1(&record.udot_seed_digest),
            notarization_record_digest_hex: encode_hex_lower_v1(&record.notarization_record_digest),
        })
    }
}

pub fn build_token_transaction_proof_binding_v1(
    public_statement: DeterministicTransactionPublicStatementV1,
) -> Result<TokenTransactionProofBindingV1, TokenTransactionErrorV1> {
    TokenTransactionProofBindingV1::from_public_statement(public_statement)
}

pub fn build_token_transaction_notary_input_v1(
    proof_binding: TokenTransactionProofBindingV1,
) -> Result<TokenTransactionNotaryInputV1, TokenTransactionErrorV1> {
    TokenTransactionNotaryInputV1::from_proof_binding(proof_binding)
}

pub fn build_token_transaction_notary_receipt_preimage_v1(
    notary_input: TokenTransactionNotaryInputV1,
) -> Result<TokenTransactionNotaryReceiptPreimageV1, TokenTransactionErrorV1> {
    TokenTransactionNotaryReceiptPreimageV1::from_notary_input(notary_input)
}

pub fn build_token_transaction_notary_acknowledgement_v1(
    receipt: TokenTransactionNotaryReceiptPreimageV1,
) -> Result<TokenTransactionNotaryAcknowledgementV1, TokenTransactionErrorV1> {
    TokenTransactionNotaryAcknowledgementV1::from_receipt(receipt)
}

pub fn build_token_transaction_seal_payload_v1(
    acknowledgement: TokenTransactionNotaryAcknowledgementV1,
) -> Result<TokenTransactionSealPayloadV1, TokenTransactionErrorV1> {
    TokenTransactionSealPayloadV1::from_acknowledgement(acknowledgement)
}

pub fn build_token_transaction_notarization_record_v1(
    seal_payload: TokenTransactionSealPayloadV1,
) -> Result<TokenTransactionNotarizationRecordV1, TokenTransactionErrorV1> {
    TokenTransactionNotarizationRecordV1::from_seal_payload(seal_payload)
}

pub fn build_token_transaction_notarization_summary_v1(
    payload: TokenTransactionNotarizationRecordWireV1,
) -> Result<TokenTransactionNotarizationSummaryV1, TokenTransactionErrorV1> {
    TokenTransactionNotarizationSummaryV1::from_record_wire(payload)
}

fn proof_statement_label_v1(proof_statement_type: u8) -> Result<&'static str, TokenTransactionErrorV1> {
    match proof_statement_type {
        EXACT_PUBLIC_STATEMENT_TYPE_V1 => Ok("private_transfer_burn_v1"),
        actual => Err(TokenTransactionErrorV1::UnsupportedProofStatementType {
            expected: EXACT_PUBLIC_STATEMENT_TYPE_V1,
            actual,
        }),
    }
}

fn encode_private_transfer_burn_body_v1(
    tx_version: u32,
    tx_kind: u8,
    rollup_id: &[u8; HASH_LEN_V1],
    asset_id: &[u8; HASH_LEN_V1],
    anchor_state_root: &[u8; HASH_LEN_V1],
    inputs: &[TokenTransactionInputV1],
    outputs: &[TokenTransactionOutputV1],
    admission_burn: u64,
    notary_burn: u64,
    priority_weight: u64,
) -> Result<Vec<u8>, TokenTransactionErrorV1> {
    let input_count =
        u64::try_from(inputs.len()).map_err(|_| TokenTransactionErrorV1::InputCountOverflow)?;
    let output_count =
        u64::try_from(outputs.len()).map_err(|_| TokenTransactionErrorV1::OutputCountOverflow)?;

    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_PRIVATE_TRANSFER_BURN_BODY_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 1
            + (HASH_LEN_V1 * 3)
            + 8
            + (inputs.len() * HASH_LEN_V1 * 2)
            + 8
            + (outputs.len() * HASH_LEN_V1)
            + 24,
    );
    bytes.extend_from_slice(AURA_TOKEN_PRIVATE_TRANSFER_BURN_BODY_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&tx_version.to_le_bytes());
    bytes.push(tx_kind);
    bytes.extend_from_slice(rollup_id);
    bytes.extend_from_slice(asset_id);
    bytes.extend_from_slice(anchor_state_root);
    bytes.extend_from_slice(&input_count.to_le_bytes());
    for input in inputs {
        bytes.extend_from_slice(&input.nullifier);
        bytes.extend_from_slice(&input.note_commitment_reference);
    }
    bytes.extend_from_slice(&output_count.to_le_bytes());
    for output in outputs {
        bytes.extend_from_slice(&output.note_commitment);
    }
    bytes.extend_from_slice(&admission_burn.to_le_bytes());
    bytes.extend_from_slice(&notary_burn.to_le_bytes());
    bytes.extend_from_slice(&priority_weight.to_le_bytes());
    Ok(bytes)
}

fn encode_deterministic_transaction_bytes_v1(
    transaction: &PrivateTransferBurnTransactionV1,
) -> Result<Vec<u8>, TokenTransactionErrorV1> {
    let input_count = transaction.input_count()?;
    let output_count = transaction.output_count()?;

    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_DETERMINISTIC_TRANSACTION_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 1
            + 1
            + (HASH_LEN_V1 * 4)
            + 8
            + (transaction.inputs.len() * HASH_LEN_V1 * 2)
            + 8
            + (transaction.outputs.len() * HASH_LEN_V1)
            + 24,
    );
    bytes.extend_from_slice(AURA_TOKEN_DETERMINISTIC_TRANSACTION_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&transaction.tx_version.to_le_bytes());
    bytes.push(transaction.tx_kind);
    bytes.push(transaction.proof_statement_type);
    bytes.extend_from_slice(&transaction.rollup_id);
    bytes.extend_from_slice(&transaction.asset_id);
    bytes.extend_from_slice(&transaction.anchor_state_root);
    bytes.extend_from_slice(&input_count.to_le_bytes());
    for input in &transaction.inputs {
        bytes.extend_from_slice(&input.nullifier);
        bytes.extend_from_slice(&input.note_commitment_reference);
    }
    bytes.extend_from_slice(&output_count.to_le_bytes());
    for output in &transaction.outputs {
        bytes.extend_from_slice(&output.note_commitment);
    }
    bytes.extend_from_slice(&transaction.admission_burn.to_le_bytes());
    bytes.extend_from_slice(&transaction.notary_burn.to_le_bytes());
    bytes.extend_from_slice(&transaction.priority_weight.to_le_bytes());
    bytes.extend_from_slice(&transaction.tx_commitment);
    Ok(bytes)
}

fn encode_public_statement_bytes_v1(
    statement: &PrivateTransferBurnPublicStatementV1,
) -> Result<Vec<u8>, TokenTransactionErrorV1> {
    let expected_input_count = u64::try_from(statement.input_nullifiers.len())
        .map_err(|_| TokenTransactionErrorV1::InputCountOverflow)?;
    let expected_output_count = u64::try_from(statement.output_note_commitments.len())
        .map_err(|_| TokenTransactionErrorV1::OutputCountOverflow)?;
    if statement.input_count != expected_input_count {
        return Err(TokenTransactionErrorV1::InputCountMismatch {
            expected: expected_input_count,
            actual: statement.input_count,
        });
    }
    if statement.output_count != expected_output_count {
        return Err(TokenTransactionErrorV1::OutputCountMismatch {
            expected: expected_output_count,
            actual: statement.output_count,
        });
    }

    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_DETERMINISTIC_PUBLIC_STATEMENT_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 1
            + 1
            + (HASH_LEN_V1 * 4)
            + 8
            + (statement.input_nullifiers.len() * HASH_LEN_V1)
            + 8
            + (statement.output_note_commitments.len() * HASH_LEN_V1)
            + 24,
    );
    bytes.extend_from_slice(AURA_TOKEN_DETERMINISTIC_PUBLIC_STATEMENT_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&statement.tx_version.to_le_bytes());
    bytes.push(statement.tx_kind);
    bytes.push(statement.proof_statement_type);
    bytes.extend_from_slice(&statement.rollup_id);
    bytes.extend_from_slice(&statement.asset_id);
    bytes.extend_from_slice(&statement.anchor_state_root);
    bytes.extend_from_slice(&statement.input_count.to_le_bytes());
    for nullifier in &statement.input_nullifiers {
        bytes.extend_from_slice(nullifier);
    }
    bytes.extend_from_slice(&statement.output_count.to_le_bytes());
    for commitment in &statement.output_note_commitments {
        bytes.extend_from_slice(commitment);
    }
    bytes.extend_from_slice(&statement.admission_burn.to_le_bytes());
    bytes.extend_from_slice(&statement.notary_burn.to_le_bytes());
    bytes.extend_from_slice(&statement.priority_weight.to_le_bytes());
    bytes.extend_from_slice(&statement.tx_commitment);
    Ok(bytes)
}

pub fn derive_token_transaction_proof_binding_digest_v1(
    public_statement_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_PROOF_BINDING_DOMAIN_SEPARATOR_V1.len() + public_statement_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_PROOF_BINDING_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(public_statement_bytes);
    sha256_bytes(&preimage)
}

pub fn derive_token_transaction_notary_input_digest_v1(
    proof_binding_bytes: &[u8],
    proof_binding_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARY_INPUT_DOMAIN_SEPARATOR_V1.len()
            + proof_binding_digest.len()
            + proof_binding_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARY_INPUT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(proof_binding_digest);
    preimage.extend_from_slice(proof_binding_bytes);
    sha256_bytes(&preimage)
}

fn encode_token_transaction_notary_receipt_preimage_bytes_v1(
    proof_statement_type: u8,
    notary_input_digest: &[u8; HASH_LEN_V1],
    proof_binding_digest: &[u8; HASH_LEN_V1],
    proof_binding_bytes: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_DOMAIN_SEPARATOR_V1.len()
            + 1
            + notary_input_digest.len()
            + proof_binding_digest.len()
            + 8
            + proof_binding_bytes.len(),
    );
    bytes.extend_from_slice(AURA_TOKEN_NOTARY_RECEIPT_PREIMAGE_DOMAIN_SEPARATOR_V1);
    bytes.push(proof_statement_type);
    bytes.extend_from_slice(notary_input_digest);
    bytes.extend_from_slice(proof_binding_digest);
    bytes.extend_from_slice(&(proof_binding_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(proof_binding_bytes);
    bytes
}

pub fn derive_token_transaction_notary_receipt_digest_v1(
    receipt_preimage_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARY_RECEIPT_DOMAIN_SEPARATOR_V1.len() + receipt_preimage_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARY_RECEIPT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(receipt_preimage_bytes);
    sha256_bytes(&preimage)
}

fn encode_token_transaction_notary_acknowledgement_bytes_v1(
    ack_version: u32,
    proof_statement_type: u8,
    receipt_digest: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_NOTARY_ACK_DOMAIN_SEPARATOR_V1.len() + 4 + 1 + receipt_digest.len(),
    );
    bytes.extend_from_slice(AURA_TOKEN_NOTARY_ACK_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&ack_version.to_le_bytes());
    bytes.push(proof_statement_type);
    bytes.extend_from_slice(receipt_digest);
    bytes
}

pub fn derive_token_transaction_notary_acknowledgement_digest_v1(
    ack_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARY_ACK_DIGEST_DOMAIN_SEPARATOR_V1.len() + ack_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARY_ACK_DIGEST_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(ack_bytes);
    sha256_bytes(&preimage)
}

pub fn derive_token_transaction_symbolic_receipt_preimage_v1(
    ack_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_SYMBOLIC_RECEIPT_DOMAIN_SEPARATOR_V1.len() + ack_digest.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_SYMBOLIC_RECEIPT_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(ack_digest);
    sha256_bytes(&preimage)
}

fn encode_token_transaction_seal_payload_bytes_v1(
    seal_version: u32,
    proof_statement_type: u8,
    ack_digest: &[u8; HASH_LEN_V1],
    symbolic_receipt_preimage: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_SEAL_PAYLOAD_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 1
            + ack_digest.len()
            + symbolic_receipt_preimage.len(),
    );
    bytes.extend_from_slice(AURA_TOKEN_SEAL_PAYLOAD_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&seal_version.to_le_bytes());
    bytes.push(proof_statement_type);
    bytes.extend_from_slice(ack_digest);
    bytes.extend_from_slice(symbolic_receipt_preimage);
    bytes
}

pub fn derive_token_transaction_seal_payload_digest_v1(
    seal_payload_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_SEAL_PAYLOAD_DIGEST_DOMAIN_SEPARATOR_V1.len() + seal_payload_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_SEAL_PAYLOAD_DIGEST_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(seal_payload_bytes);
    sha256_bytes(&preimage)
}

pub fn derive_token_transaction_udot_seed_digest_v1(
    seal_payload_digest: &[u8; HASH_LEN_V1],
) -> [u8; HASH_LEN_V1] {
    let mut preimage =
        Vec::with_capacity(AURA_TOKEN_UDOT_SEED_DOMAIN_SEPARATOR_V1.len() + seal_payload_digest.len());
    preimage.extend_from_slice(AURA_TOKEN_UDOT_SEED_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(seal_payload_digest);
    sha256_bytes(&preimage)
}

fn encode_token_transaction_notarization_record_bytes_v1(
    record_version: u32,
    proof_statement_type: u8,
    ack_digest: &[u8; HASH_LEN_V1],
    seal_payload_digest: &[u8; HASH_LEN_V1],
    udot_seed_digest: &[u8; HASH_LEN_V1],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_NOTARIZATION_RECORD_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 1
            + ack_digest.len()
            + seal_payload_digest.len()
            + udot_seed_digest.len(),
    );
    bytes.extend_from_slice(AURA_TOKEN_NOTARIZATION_RECORD_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&record_version.to_le_bytes());
    bytes.push(proof_statement_type);
    bytes.extend_from_slice(ack_digest);
    bytes.extend_from_slice(seal_payload_digest);
    bytes.extend_from_slice(udot_seed_digest);
    bytes
}

pub fn derive_token_transaction_notarization_record_digest_v1(
    notarization_record_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_NOTARIZATION_RECORD_DIGEST_DOMAIN_SEPARATOR_V1.len()
            + notarization_record_bytes.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_NOTARIZATION_RECORD_DIGEST_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(notarization_record_bytes);
    sha256_bytes(&preimage)
}

fn encode_hex_lower_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex_32_v1(
    field: &'static str,
    input: &str,
) -> Result<[u8; HASH_LEN_V1], TokenTransactionErrorV1> {
    if input.len() != HASH_LEN_V1 * 2 {
        return Err(TokenTransactionErrorV1::InvalidHexLength {
            field,
            expected_bytes: HASH_LEN_V1,
            actual_nibbles: input.len(),
        });
    }

    let mut bytes = [0u8; HASH_LEN_V1];
    let input_bytes = input.as_bytes();
    for (index, chunk) in input_bytes.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble_v1(chunk[0]).ok_or(TokenTransactionErrorV1::MalformedHex {
            field,
        })?;
        let low = decode_hex_nibble_v1(chunk[1]).ok_or(TokenTransactionErrorV1::MalformedHex {
            field,
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble_v1(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
*/

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::encode_hex_lower_v1;
    use super::{
        admission_burn_v1, build_deterministic_transaction_v1,
        build_token_transaction_notarization_record_v1,
        build_token_transaction_notarization_summary_v1,
        build_token_transaction_notary_acknowledgement_v1, build_token_transaction_notary_input_v1,
        build_token_transaction_notary_receipt_preimage_v1,
        build_token_transaction_proof_binding_v1, build_token_transaction_seal_payload_v1,
        burn_summary_v1, derive_token_transaction_notarization_record_digest_v1,
        derive_token_transaction_notary_acknowledgement_digest_v1,
        derive_token_transaction_notary_input_digest_v1,
        derive_token_transaction_notary_receipt_digest_v1,
        derive_token_transaction_proof_binding_digest_v1,
        derive_token_transaction_seal_payload_digest_v1,
        derive_token_transaction_symbolic_receipt_preimage_v1,
        derive_token_transaction_udot_seed_digest_v1, notary_burn_v1, priority_weight_v1,
        BuildDeterministicTransactionRequestV1, DeterministicTransactionPublicStatementWireV1,
        DeterministicTransactionWireV1, PrivateTransferBurnTransactionV1, TokenTransactionErrorV1,
        TokenTransactionInputV1, TokenTransactionNotarizationRecordV1,
        TokenTransactionNotarizationRecordWireV1, TokenTransactionNotarizationSummaryV1,
        TokenTransactionNotaryAcknowledgementV1, TokenTransactionNotaryInputV1,
        TokenTransactionNotaryReceiptPreimageV1, TokenTransactionOutputV1,
        TokenTransactionProofBindingV1, TokenTransactionSealPayloadV1, ADMISSION_BURN_FLOOR_V1,
        EXACT_PUBLIC_STATEMENT_TYPE_V1, PRIVATE_TRANSFER_BURN_KIND_V1, TOKEN_TX_VERSION_V1,
    };
    use serde::Deserialize;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn sample_inputs() -> Vec<TokenTransactionInputV1> {
        vec![TokenTransactionInputV1 {
            nullifier: id(0x11),
            note_commitment_reference: id(0x21),
        }]
    }

    fn sample_outputs() -> Vec<TokenTransactionOutputV1> {
        vec![TokenTransactionOutputV1 {
            note_commitment: id(0x31),
        }]
    }

    fn sample_transaction() -> PrivateTransferBurnTransactionV1 {
        PrivateTransferBurnTransactionV1::new(
            id(0xAA),
            id(0xBB),
            id(0xCC),
            sample_inputs(),
            sample_outputs(),
        )
        .unwrap()
    }

    fn sample_build_request() -> BuildDeterministicTransactionRequestV1 {
        BuildDeterministicTransactionRequestV1 {
            tx_version: TOKEN_TX_VERSION_V1,
            tx_kind: PRIVATE_TRANSFER_BURN_KIND_V1,
            rollup_id: id(0xAA),
            asset_id: id(0xBB),
            anchor_state_root: id(0xCC),
            inputs: sample_inputs(),
            outputs: sample_outputs(),
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureVectorFileV1 {
        vectors: Vec<FixtureVectorV1>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureVectorV1 {
        fixture_name: String,
        transaction: DeterministicTransactionWireV1,
        public_statement: DeterministicTransactionPublicStatementWireV1,
        transaction_bytes_hex: String,
        public_statement_bytes_hex: String,
        proof_binding_bytes_hex: String,
        proof_binding_digest_hex: String,
        notary_input_digest_hex: String,
        notary_receipt_preimage_bytes_hex: String,
        notary_receipt_digest_hex: String,
        notary_ack_bytes_hex: String,
        notary_ack_digest_hex: String,
        symbolic_receipt_preimage_hex: String,
        seal_payload_bytes_hex: String,
        seal_payload_digest_hex: String,
        udot_seed_digest_hex: String,
        notarization_record_bytes_hex: String,
        notarization_record_digest_hex: String,
        notarization_summary: TokenTransactionNotarizationSummaryV1,
    }

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/v1/deterministic_transaction_v1/test_vectors.json")
    }

    fn load_fixture_vectors() -> FixtureVectorFileV1 {
        serde_json::from_str(&fs::read_to_string(fixture_path()).unwrap()).unwrap()
    }

    #[test]
    fn canonical_transaction_build_succeeds_on_valid_input() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();

        assert_eq!(built.transaction.tx_version, TOKEN_TX_VERSION_V1);
        assert_eq!(built.transaction.tx_kind, PRIVATE_TRANSFER_BURN_KIND_V1);
        assert_eq!(built.transaction.inputs, sample_inputs());
        assert_eq!(built.transaction.outputs, sample_outputs());
    }

    #[test]
    fn producer_computes_burns_exactly_as_specified() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();

        assert_eq!(built.burns.admission_burn, 1);
        assert_eq!(built.burns.notary_burn, 3);
        assert_eq!(built.transaction.admission_burn, 1);
        assert_eq!(built.transaction.notary_burn, 3);
    }

    #[test]
    fn priority_weight_is_derived_not_manually_injected() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();

        assert_eq!(built.burns.priority_weight, 4);
        assert_eq!(built.transaction.priority_weight, 4);
    }

    #[test]
    fn malformed_caller_input_is_rejected() {
        let mut request = sample_build_request();
        request.inputs.clear();

        let error = build_deterministic_transaction_v1(request).unwrap_err();
        assert_eq!(error, TokenTransactionErrorV1::EmptyInputs);
    }

    #[test]
    fn returned_object_passes_validator_without_mutation() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();

        built.transaction.validate().unwrap();
    }

    #[test]
    fn repeated_identical_input_yields_identical_output() {
        let first = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let second = build_deterministic_transaction_v1(sample_build_request()).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn boundary_cases_for_complexity_driver_behave_correctly() {
        let request = BuildDeterministicTransactionRequestV1 {
            tx_version: TOKEN_TX_VERSION_V1,
            tx_kind: PRIVATE_TRANSFER_BURN_KIND_V1,
            rollup_id: id(0xAA),
            asset_id: id(0xBB),
            anchor_state_root: id(0xCC),
            inputs: vec![
                TokenTransactionInputV1 {
                    nullifier: id(0x10),
                    note_commitment_reference: id(0x20),
                },
                TokenTransactionInputV1 {
                    nullifier: id(0x11),
                    note_commitment_reference: id(0x21),
                },
            ],
            outputs: vec![
                TokenTransactionOutputV1 {
                    note_commitment: id(0x30),
                },
                TokenTransactionOutputV1 {
                    note_commitment: id(0x31),
                },
                TokenTransactionOutputV1 {
                    note_commitment: id(0x32),
                },
            ],
        };

        let built = build_deterministic_transaction_v1(request).unwrap();
        assert_eq!(built.burns.admission_burn, 1);
        assert_eq!(built.burns.notary_burn, 6);
        assert_eq!(built.burns.priority_weight, 7);
    }

    #[test]
    fn valid_transaction_with_minimum_required_burns_passes() {
        let tx = sample_transaction();
        assert_eq!(tx.admission_burn, ADMISSION_BURN_FLOOR_V1);
        assert_eq!(tx.notary_burn, 3);
        assert_eq!(tx.proof_statement_type, EXACT_PUBLIC_STATEMENT_TYPE_V1);
        tx.validate().unwrap();
    }

    #[test]
    fn rejection_when_admission_burn_is_below_floor() {
        let mut tx = sample_transaction();
        tx.admission_burn = 0;

        let error = tx.validate().unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::InsufficientAdmissionBurn {
                minimum: 1,
                actual: 0,
            }
        );
    }

    #[test]
    fn rejection_when_notary_burn_is_below_required_value() {
        let mut tx = sample_transaction();
        tx.notary_burn = 2;

        let error = tx.validate().unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::InsufficientNotaryBurn {
                required: 3,
                actual: 2,
            }
        );
    }

    #[test]
    fn priority_weight_equals_deterministic_formula() {
        let burns = burn_summary_v1(1, 1).unwrap();
        assert_eq!(burns.admission_burn, 1);
        assert_eq!(burns.notary_burn, 3);
        assert_eq!(burns.priority_weight, 4);

        let tx = sample_transaction();
        assert_eq!(tx.priority_weight, 4);
    }

    #[test]
    fn malformed_fields_rejected_fail_closed() {
        let mut tx = sample_transaction();
        tx.inputs.push(tx.inputs[0]);

        let error = tx.validate().unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::DuplicateNullifier {
                nullifier: id(0x11),
            }
        );
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut tx = sample_transaction();
        tx.tx_version = 7;

        let error = tx.validate().unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::UnsupportedVersion {
                expected: TOKEN_TX_VERSION_V1,
                actual: 7,
            }
        );
    }

    #[test]
    fn deterministic_repeatability_across_identical_inputs() {
        let first = sample_transaction();
        let second = sample_transaction();

        assert_eq!(first, second);
        assert_eq!(first.tx_commitment, second.tx_commitment);
        assert_eq!(
            first.proof_placeholder.public_statement,
            second.proof_placeholder.public_statement
        );
    }

    #[test]
    fn integer_boundary_behavior_is_fail_closed() {
        let notary = notary_burn_v1(u64::MAX, 1).unwrap_err();
        assert_eq!(notary, TokenTransactionErrorV1::BurnArithmeticOverflow);

        let priority = priority_weight_v1(u64::MAX, 1).unwrap_err();
        assert_eq!(priority, TokenTransactionErrorV1::BurnArithmeticOverflow);
    }

    #[test]
    fn invalid_priority_derivation_is_rejected() {
        let mut tx = sample_transaction();
        tx.priority_weight = 99;

        let error = tx.validate().unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::InvalidPriorityWeight {
                expected: 4,
                actual: 99,
            }
        );
    }

    #[test]
    fn invalid_commitment_or_statement_consistency_is_rejected() {
        let mut tx = sample_transaction();
        tx.tx_commitment = [0xFF; 32];
        let error = tx.validate().unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidTransactionCommitment { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let mut tx = sample_transaction();
        tx.proof_placeholder.public_statement.tx_commitment = [0xAB; 32];
        let error = tx.validate().unwrap_err();
        assert_eq!(error, TokenTransactionErrorV1::PublicStatementMismatch);
    }

    #[test]
    fn unsupported_transaction_kind_rejected() {
        let mut tx = sample_transaction();
        tx.tx_kind = 9;
        let error = tx.validate().unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::UnsupportedTransactionKind {
                expected: PRIVATE_TRANSFER_BURN_KIND_V1,
                actual: 9,
            }
        );
    }

    #[test]
    fn pure_formula_helpers_are_stable() {
        assert_eq!(admission_burn_v1(), 1);
        assert_eq!(notary_burn_v1(2, 3).unwrap(), 6);
        assert_eq!(priority_weight_v1(1, 6).unwrap(), 7);
    }

    #[test]
    fn transaction_object_serializes_to_exact_frozen_bytes() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let transaction =
                PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
            assert_eq!(
                encode_hex_lower_v1(&transaction.canonical_bytes().unwrap()),
                vector.transaction_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn public_statement_serializes_to_exact_frozen_bytes() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            assert_eq!(
                encode_hex_lower_v1(&statement.canonical_bytes().unwrap()),
                vector.public_statement_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn json_wire_round_trip_succeeds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let transaction_wire = built.transaction.to_wire();
        let statement_wire = built
            .transaction
            .proof_placeholder
            .public_statement
            .to_wire();

        let transaction_json = serde_json::to_string(&transaction_wire).unwrap();
        let statement_json = serde_json::to_string(&statement_wire).unwrap();

        let reparsed_transaction: DeterministicTransactionWireV1 =
            serde_json::from_str(&transaction_json).unwrap();
        let reparsed_statement: DeterministicTransactionPublicStatementWireV1 =
            serde_json::from_str(&statement_json).unwrap();

        assert_eq!(transaction_wire, reparsed_transaction);
        assert_eq!(statement_wire, reparsed_statement);
    }

    #[test]
    fn malformed_wire_input_fails_closed() {
        let malformed_transaction = r#"{
            "tx_version": 1,
            "tx_kind": 1,
            "proof_statement_type": 1,
            "rollup_id_hex": "AA",
            "asset_id_hex": "bb",
            "anchor_state_root_hex": "cc",
            "inputs": [],
            "outputs": [],
            "admission_burn": 1,
            "notary_burn": 1,
            "priority_weight": 2,
            "transaction_commitment_hex": "00",
            "public_statement": {
                "tx_version": 1,
                "tx_kind": 1,
                "proof_statement_type": 1,
                "rollup_id_hex": "aa",
                "asset_id_hex": "bb",
                "anchor_state_root_hex": "cc",
                "input_nullifier_hexes": [],
                "output_note_commitment_hexes": [],
                "input_count": 0,
                "output_count": 0,
                "admission_burn": 1,
                "notary_burn": 1,
                "priority_weight": 2,
                "transaction_commitment_hex": "00"
            }
        }"#;

        let parsed: DeterministicTransactionWireV1 =
            serde_json::from_str(malformed_transaction).unwrap();
        let error = PrivateTransferBurnTransactionV1::from_wire(parsed).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidHexLength { .. }
            | TokenTransactionErrorV1::MalformedHex { .. }
            | TokenTransactionErrorV1::EmptyInputs => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn field_ordering_drift_would_fail_fixture_tests() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let canonical_hex = encode_hex_lower_v1(&built.transaction.canonical_bytes().unwrap());

        let mut drifted = built.transaction.canonical_bytes().unwrap();
        let len = drifted.len();
        drifted.swap(len - 1, len - 2);
        let drifted_hex = encode_hex_lower_v1(&drifted);

        assert_ne!(canonical_hex, drifted_hex);
    }

    #[test]
    fn priority_weight_is_encoded_exactly_without_recomputation_drift() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let bytes = built.transaction.canonical_bytes().unwrap();
        let priority_offset = bytes.len() - 32 - 8;
        let encoded = u64::from_le_bytes(
            bytes[priority_offset..priority_offset + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(encoded, built.transaction.priority_weight);
    }

    #[test]
    fn fixture_backed_tests_pin_canonical_wire_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let transaction =
                PrivateTransferBurnTransactionV1::from_wire(vector.transaction.clone()).unwrap();
            let statement = super::PrivateTransferBurnPublicStatementV1::from_wire(
                vector.public_statement.clone(),
            )
            .unwrap();

            assert_eq!(
                transaction.to_wire(),
                vector.transaction,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                statement.to_wire(),
                vector.public_statement,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn proof_facing_adapter_consumes_canonical_public_statement_directly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement.clone();
        let binding = build_token_transaction_proof_binding_v1(statement.clone()).unwrap();

        assert_eq!(binding.public_statement, statement);
        assert_eq!(
            binding.public_statement_bytes,
            statement.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn proof_facing_bytes_equal_frozen_canonical_public_statement_bytes() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement.clone();
        let binding = build_token_transaction_proof_binding_v1(statement.clone()).unwrap();

        assert_eq!(
            binding.public_statement_bytes,
            statement.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn proof_facing_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = build_token_transaction_proof_binding_v1(statement).unwrap();
            assert_eq!(
                encode_hex_lower_v1(&binding.proof_binding_digest),
                vector.proof_binding_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn malformed_public_statement_fails_closed() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut statement = built.transaction.proof_placeholder.public_statement.clone();
        statement.input_count = 99;

        let error = build_token_transaction_proof_binding_v1(statement).unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::InputCountMismatch {
                expected: 1,
                actual: 99,
            }
        );
    }

    #[test]
    fn proof_binding_repeatability_holds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let first = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement.clone(),
        )
        .unwrap();
        let second = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_tests_pin_adapter_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = TokenTransactionProofBindingV1::from_public_statement(statement).unwrap();

            assert_eq!(
                encode_hex_lower_v1(&binding.public_statement_bytes),
                vector.proof_binding_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&binding.proof_binding_digest),
                vector.proof_binding_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn proof_binding_changes_if_public_statement_ordered_bytes_change() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement;
        let binding = build_token_transaction_proof_binding_v1(statement.clone()).unwrap();

        let mut drifted_bytes = statement.canonical_bytes().unwrap();
        let len = drifted_bytes.len();
        drifted_bytes.swap(len - 1, len - 2);

        assert_ne!(binding.public_statement_bytes, drifted_bytes);
        assert_ne!(
            binding.proof_binding_digest,
            derive_token_transaction_proof_binding_digest_v1(&drifted_bytes)
        );
    }

    #[test]
    fn no_ad_hoc_reconstruction_path_is_introduced() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement.clone(),
        )
        .unwrap();

        let reconstructed =
            build_token_transaction_proof_binding_v1(binding.public_statement.clone()).unwrap();
        assert_eq!(binding, reconstructed);
    }

    #[test]
    fn downstream_consumer_accepts_only_proof_binding_and_preserves_it() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();

        let notary_input = build_token_transaction_notary_input_v1(binding.clone()).unwrap();

        assert_eq!(notary_input.proof_binding, binding);
        assert_eq!(
            notary_input.proof_binding_bytes,
            notary_input.proof_binding.public_statement_bytes
        );
        assert_eq!(
            notary_input.proof_binding_digest,
            notary_input.proof_binding.proof_binding_digest
        );
    }

    #[test]
    fn downstream_consumer_preserves_frozen_proof_binding_bytes_and_digest() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let notary_input = build_token_transaction_notary_input_v1(binding.clone()).unwrap();

        assert_eq!(
            notary_input.proof_binding_bytes,
            binding.public_statement_bytes
        );
        assert_eq!(
            notary_input.proof_binding_digest,
            binding.proof_binding_digest
        );
    }

    #[test]
    fn downstream_consumer_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = build_token_transaction_proof_binding_v1(statement).unwrap();
            let notary_input = build_token_transaction_notary_input_v1(binding).unwrap();

            assert_eq!(
                encode_hex_lower_v1(&notary_input.notary_input_digest),
                vector.notary_input_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn malformed_or_inconsistent_proof_binding_input_fails_closed() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        binding.public_statement_bytes[0] ^= 0x01;

        let error = build_token_transaction_notary_input_v1(binding).unwrap_err();
        assert_eq!(error, TokenTransactionErrorV1::InvalidProofBindingBytes);

        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        binding.proof_binding_digest = [0xAB; 32];

        let error = build_token_transaction_notary_input_v1(binding).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidProofBindingDigest { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn downstream_consumer_repeatability_holds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement;
        let first = build_token_transaction_notary_input_v1(
            build_token_transaction_proof_binding_v1(statement.clone()).unwrap(),
        )
        .unwrap();
        let second = build_token_transaction_notary_input_v1(
            build_token_transaction_proof_binding_v1(statement).unwrap(),
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_tests_pin_downstream_consumer_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = TokenTransactionProofBindingV1::from_public_statement(statement).unwrap();
            let notary_input = TokenTransactionNotaryInputV1::from_proof_binding(binding).unwrap();

            assert_eq!(
                encode_hex_lower_v1(&notary_input.proof_binding_bytes),
                vector.proof_binding_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&notary_input.proof_binding_digest),
                vector.proof_binding_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&notary_input.notary_input_digest),
                vector.notary_input_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn downstream_consumer_detects_binding_drift() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let notary_input = build_token_transaction_notary_input_v1(binding.clone()).unwrap();

        let mut drifted_bytes = binding.public_statement_bytes.clone();
        let len = drifted_bytes.len();
        drifted_bytes.swap(len - 1, len - 2);

        assert_ne!(notary_input.proof_binding_bytes, drifted_bytes);
        assert_ne!(
            notary_input.notary_input_digest,
            derive_token_transaction_notary_input_digest_v1(
                &drifted_bytes,
                &binding.proof_binding_digest,
            )
        );
    }

    #[test]
    fn no_downstream_path_reintroduces_transaction_field_assembly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let direct = build_token_transaction_notary_input_v1(binding.clone()).unwrap();
        let reconstructed = TokenTransactionNotaryInputV1::from_proof_binding(binding).unwrap();

        assert_eq!(direct, reconstructed);
    }

    #[test]
    fn receipt_layer_accepts_only_notary_input_and_preserves_it() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let notary_input = build_token_transaction_notary_input_v1(binding).unwrap();
        let receipt =
            build_token_transaction_notary_receipt_preimage_v1(notary_input.clone()).unwrap();

        assert_eq!(receipt.notary_input, notary_input);
        assert_eq!(
            receipt.proof_statement_type,
            receipt.notary_input.proof_statement_type
        );
        assert_eq!(
            receipt.receipt_digest,
            derive_token_transaction_notary_receipt_digest_v1(&receipt.receipt_preimage_bytes)
        );
    }

    #[test]
    fn receipt_preimage_bytes_are_exactly_frozen() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = build_token_transaction_proof_binding_v1(statement).unwrap();
            let notary_input = build_token_transaction_notary_input_v1(binding).unwrap();
            let receipt = build_token_transaction_notary_receipt_preimage_v1(notary_input).unwrap();

            assert_eq!(
                encode_hex_lower_v1(&receipt.receipt_preimage_bytes),
                vector.notary_receipt_preimage_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn receipt_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = build_token_transaction_proof_binding_v1(statement).unwrap();
            let notary_input = build_token_transaction_notary_input_v1(binding).unwrap();
            let receipt = build_token_transaction_notary_receipt_preimage_v1(notary_input).unwrap();

            assert_eq!(
                encode_hex_lower_v1(&receipt.receipt_digest),
                vector.notary_receipt_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn malformed_or_tampered_notary_input_fails_closed() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let mut notary_input = build_token_transaction_notary_input_v1(binding).unwrap();
        notary_input.notary_input_digest = [0xCD; 32];

        let error = build_token_transaction_notary_receipt_preimage_v1(notary_input).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidNotaryInputDigest { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let mut notary_input = build_token_transaction_notary_input_v1(binding).unwrap();
        notary_input.proof_statement_type = 9;

        let error = build_token_transaction_notary_receipt_preimage_v1(notary_input).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidNotaryInputProofStatementType { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn receipt_repeatability_holds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement;
        let first = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(statement.clone()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let second = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(statement).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_tests_pin_receipt_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let binding = TokenTransactionProofBindingV1::from_public_statement(statement).unwrap();
            let notary_input = TokenTransactionNotaryInputV1::from_proof_binding(binding).unwrap();
            let receipt =
                TokenTransactionNotaryReceiptPreimageV1::from_notary_input(notary_input).unwrap();

            assert_eq!(
                encode_hex_lower_v1(&receipt.receipt_preimage_bytes),
                vector.notary_receipt_preimage_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&receipt.receipt_digest),
                vector.notary_receipt_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn receipt_output_changes_when_lower_layer_binding_changes() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let notary_input = build_token_transaction_notary_input_v1(binding.clone()).unwrap();
        let receipt = build_token_transaction_notary_receipt_preimage_v1(notary_input).unwrap();

        let mut drifted_bytes = binding.public_statement_bytes.clone();
        let len = drifted_bytes.len();
        drifted_bytes.swap(len - 1, len - 2);
        let drifted_notary_digest = derive_token_transaction_notary_input_digest_v1(
            &drifted_bytes,
            &binding.proof_binding_digest,
        );
        let drifted_receipt_preimage_bytes =
            super::encode_token_transaction_notary_receipt_preimage_bytes_v1(
                binding.proof_statement_type,
                &drifted_notary_digest,
                &binding.proof_binding_digest,
                &drifted_bytes,
            );
        let drifted_receipt_digest =
            derive_token_transaction_notary_receipt_digest_v1(&drifted_receipt_preimage_bytes);

        assert_ne!(
            receipt.notary_input.notary_input_digest,
            drifted_notary_digest
        );
        assert_ne!(
            receipt.receipt_preimage_bytes,
            drifted_receipt_preimage_bytes
        );
        assert_ne!(receipt.receipt_digest, drifted_receipt_digest);
    }

    #[test]
    fn no_receipt_path_reintroduces_lower_field_assembly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let binding = build_token_transaction_proof_binding_v1(
            built.transaction.proof_placeholder.public_statement,
        )
        .unwrap();
        let notary_input = build_token_transaction_notary_input_v1(binding).unwrap();
        let direct =
            build_token_transaction_notary_receipt_preimage_v1(notary_input.clone()).unwrap();
        let reconstructed =
            TokenTransactionNotaryReceiptPreimageV1::from_notary_input(notary_input).unwrap();

        assert_eq!(direct, reconstructed);
    }

    #[test]
    fn acknowledgement_layer_accepts_only_frozen_receipt_surface() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let receipt = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(
                    built.transaction.proof_placeholder.public_statement,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let ack = build_token_transaction_notary_acknowledgement_v1(receipt.clone()).unwrap();

        assert_eq!(ack.receipt, receipt);
        assert_eq!(ack.proof_statement_type, ack.receipt.proof_statement_type);
    }

    #[test]
    fn acknowledgement_bytes_are_exactly_frozen() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let ack = build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(statement).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&ack.ack_bytes),
                vector.notary_ack_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn acknowledgement_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let ack = build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(statement).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&ack.ack_digest),
                vector.notary_ack_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn symbolic_receipt_preimage_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let ack = build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(statement).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&ack.symbolic_receipt_preimage),
                vector.symbolic_receipt_preimage_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn malformed_or_tampered_receipt_input_fails_closed() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut receipt = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(
                    built.transaction.proof_placeholder.public_statement,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        receipt.receipt_digest = [0xEF; 32];

        let error = build_token_transaction_notary_acknowledgement_v1(receipt).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidReceiptDigest { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut receipt = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(
                    built.transaction.proof_placeholder.public_statement,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        receipt.proof_statement_type = 9;

        let error = build_token_transaction_notary_acknowledgement_v1(receipt).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidReceiptProofStatementType { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn acknowledgement_repeatability_holds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement;
        let first = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(statement.clone()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let second = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(statement).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_tests_pin_acknowledgement_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let acknowledgement = TokenTransactionNotaryAcknowledgementV1::from_receipt(
                TokenTransactionNotaryReceiptPreimageV1::from_notary_input(
                    TokenTransactionNotaryInputV1::from_proof_binding(
                        TokenTransactionProofBindingV1::from_public_statement(statement).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&acknowledgement.ack_bytes),
                vector.notary_ack_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&acknowledgement.ack_digest),
                vector.notary_ack_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&acknowledgement.symbolic_receipt_preimage),
                vector.symbolic_receipt_preimage_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn lower_layer_drift_changes_acknowledgement_output() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let receipt = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(
                    built.transaction.proof_placeholder.public_statement,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let acknowledgement =
            build_token_transaction_notary_acknowledgement_v1(receipt.clone()).unwrap();

        let mut drifted_receipt = receipt.clone();
        drifted_receipt.receipt_digest = [0xAA; 32];
        let drifted_ack_bytes = super::encode_token_transaction_notary_acknowledgement_bytes_v1(
            super::TOKEN_NOTARY_ACK_VERSION_V1,
            receipt.proof_statement_type,
            &drifted_receipt.receipt_digest,
        );
        let drifted_ack_digest =
            derive_token_transaction_notary_acknowledgement_digest_v1(&drifted_ack_bytes);
        let drifted_symbolic =
            derive_token_transaction_symbolic_receipt_preimage_v1(&drifted_ack_digest);

        assert_ne!(acknowledgement.ack_bytes, drifted_ack_bytes);
        assert_ne!(acknowledgement.ack_digest, drifted_ack_digest);
        assert_ne!(acknowledgement.symbolic_receipt_preimage, drifted_symbolic);
    }

    #[test]
    fn no_acknowledgement_path_reintroduces_upstream_field_assembly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let receipt = build_token_transaction_notary_receipt_preimage_v1(
            build_token_transaction_notary_input_v1(
                build_token_transaction_proof_binding_v1(
                    built.transaction.proof_placeholder.public_statement,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let direct = build_token_transaction_notary_acknowledgement_v1(receipt.clone()).unwrap();
        let reconstructed = TokenTransactionNotaryAcknowledgementV1::from_receipt(receipt).unwrap();

        assert_eq!(direct, reconstructed);
    }

    #[test]
    fn seal_layer_accepts_only_frozen_acknowledgement_surface() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let acknowledgement = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(
                        built.transaction.proof_placeholder.public_statement,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let seal = build_token_transaction_seal_payload_v1(acknowledgement.clone()).unwrap();

        assert_eq!(seal.acknowledgement, acknowledgement);
        assert_eq!(
            seal.proof_statement_type,
            seal.acknowledgement.proof_statement_type
        );
    }

    #[test]
    fn seal_payload_bytes_are_exactly_frozen() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let seal = build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(statement).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&seal.seal_payload_bytes),
                vector.seal_payload_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn seal_payload_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let seal = build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(statement).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&seal.seal_payload_digest),
                vector.seal_payload_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn udot_seed_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let seal = build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(statement).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&seal.udot_seed_digest),
                vector.udot_seed_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn malformed_or_tampered_acknowledgement_input_fails_closed() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut acknowledgement = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(
                        built.transaction.proof_placeholder.public_statement,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        acknowledgement.ack_digest = [0x55; 32];

        let error = build_token_transaction_seal_payload_v1(acknowledgement).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidAcknowledgementDigest { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut acknowledgement = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(
                        built.transaction.proof_placeholder.public_statement,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        acknowledgement.proof_statement_type = 9;

        let error = build_token_transaction_seal_payload_v1(acknowledgement).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidAcknowledgementProofStatementType { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn seal_repeatability_holds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement;
        let first = build_token_transaction_seal_payload_v1(
            build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(statement.clone()).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let second = build_token_transaction_seal_payload_v1(
            build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(statement).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_tests_pin_seal_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let seal = TokenTransactionSealPayloadV1::from_acknowledgement(
                TokenTransactionNotaryAcknowledgementV1::from_receipt(
                    TokenTransactionNotaryReceiptPreimageV1::from_notary_input(
                        TokenTransactionNotaryInputV1::from_proof_binding(
                            TokenTransactionProofBindingV1::from_public_statement(statement)
                                .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&seal.seal_payload_bytes),
                vector.seal_payload_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&seal.seal_payload_digest),
                vector.seal_payload_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&seal.udot_seed_digest),
                vector.udot_seed_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn lower_layer_drift_changes_seal_output() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let acknowledgement = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(
                        built.transaction.proof_placeholder.public_statement,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let seal = build_token_transaction_seal_payload_v1(acknowledgement.clone()).unwrap();

        let drifted_ack_digest = [0x77; 32];
        let drifted_seal_bytes = super::encode_token_transaction_seal_payload_bytes_v1(
            super::TOKEN_SEAL_PAYLOAD_VERSION_V1,
            acknowledgement.proof_statement_type,
            &drifted_ack_digest,
            &acknowledgement.symbolic_receipt_preimage,
        );
        let drifted_seal_digest =
            derive_token_transaction_seal_payload_digest_v1(&drifted_seal_bytes);
        let drifted_udot = derive_token_transaction_udot_seed_digest_v1(&drifted_seal_digest);

        assert_ne!(seal.seal_payload_bytes, drifted_seal_bytes);
        assert_ne!(seal.seal_payload_digest, drifted_seal_digest);
        assert_ne!(seal.udot_seed_digest, drifted_udot);
    }

    #[test]
    fn no_seal_path_reintroduces_upstream_field_assembly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let acknowledgement = build_token_transaction_notary_acknowledgement_v1(
            build_token_transaction_notary_receipt_preimage_v1(
                build_token_transaction_notary_input_v1(
                    build_token_transaction_proof_binding_v1(
                        built.transaction.proof_placeholder.public_statement,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let direct = build_token_transaction_seal_payload_v1(acknowledgement.clone()).unwrap();
        let reconstructed =
            TokenTransactionSealPayloadV1::from_acknowledgement(acknowledgement).unwrap();

        assert_eq!(direct, reconstructed);
    }

    #[test]
    fn export_layer_accepts_only_frozen_downstream_surfaces() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let seal = build_token_transaction_seal_payload_v1(
            build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(
                            built.transaction.proof_placeholder.public_statement,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let record = build_token_transaction_notarization_record_v1(seal.clone()).unwrap();

        assert_eq!(record.proof_statement_type, seal.proof_statement_type);
        assert_eq!(record.ack_digest, seal.acknowledgement.ack_digest);
        assert_eq!(record.seal_payload_digest, seal.seal_payload_digest);
        assert_eq!(record.udot_seed_digest, seal.udot_seed_digest);
    }

    #[test]
    fn canonical_export_bytes_are_exactly_frozen() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let record = build_token_transaction_notarization_record_v1(
                build_token_transaction_seal_payload_v1(
                    build_token_transaction_notary_acknowledgement_v1(
                        build_token_transaction_notary_receipt_preimage_v1(
                            build_token_transaction_notary_input_v1(
                                build_token_transaction_proof_binding_v1(statement).unwrap(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&record.canonical_bytes()),
                vector.notarization_record_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn canonical_export_digest_matches_frozen_fixture() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let record = build_token_transaction_notarization_record_v1(
                build_token_transaction_seal_payload_v1(
                    build_token_transaction_notary_acknowledgement_v1(
                        build_token_transaction_notary_receipt_preimage_v1(
                            build_token_transaction_notary_input_v1(
                                build_token_transaction_proof_binding_v1(statement).unwrap(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&record.notarization_record_digest),
                vector.notarization_record_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn notarization_record_wire_round_trip_succeeds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let record = build_token_transaction_notarization_record_v1(
            build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(
                                built.transaction.proof_placeholder.public_statement,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let wire = record.to_wire();
        let json = serde_json::to_string(&wire).unwrap();
        let reparsed: TokenTransactionNotarizationRecordWireV1 =
            serde_json::from_str(&json).unwrap();
        let roundtrip = TokenTransactionNotarizationRecordV1::from_wire(reparsed).unwrap();

        assert_eq!(wire, roundtrip.to_wire());
        assert_eq!(record.canonical_bytes(), roundtrip.canonical_bytes());
        assert_eq!(
            record.notarization_record_digest,
            roundtrip.notarization_record_digest
        );
    }

    #[test]
    fn malformed_or_tampered_downstream_input_fails_closed() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let mut seal = build_token_transaction_seal_payload_v1(
            build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(
                            built.transaction.proof_placeholder.public_statement,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        seal.seal_payload_digest = [0x66; 32];

        let error = build_token_transaction_notarization_record_v1(seal).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidSealPayloadDigest { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let malformed = r#"{
            "record_version": 1,
            "proof_statement_type": 1,
            "ack_digest_hex": "00",
            "seal_payload_digest_hex": "11",
            "udot_seed_digest_hex": "22",
            "notarization_record_digest_hex": "33"
        }"#;

        let parsed: TokenTransactionNotarizationRecordWireV1 =
            serde_json::from_str(malformed).unwrap();
        let error = TokenTransactionNotarizationRecordV1::from_wire(parsed).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidHexLength { .. }
            | TokenTransactionErrorV1::MalformedHex { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn notarization_record_repeatability_holds() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let statement = built.transaction.proof_placeholder.public_statement;
        let first = build_token_transaction_notarization_record_v1(
            build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(statement.clone()).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let second = build_token_transaction_notarization_record_v1(
            build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(statement).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_tests_pin_export_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let statement =
                super::PrivateTransferBurnPublicStatementV1::from_wire(vector.public_statement)
                    .unwrap();
            let record = TokenTransactionNotarizationRecordV1::from_seal_payload(
                TokenTransactionSealPayloadV1::from_acknowledgement(
                    TokenTransactionNotaryAcknowledgementV1::from_receipt(
                        TokenTransactionNotaryReceiptPreimageV1::from_notary_input(
                            TokenTransactionNotaryInputV1::from_proof_binding(
                                TokenTransactionProofBindingV1::from_public_statement(statement)
                                    .unwrap(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(
                encode_hex_lower_v1(&record.canonical_bytes()),
                vector.notarization_record_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                encode_hex_lower_v1(&record.notarization_record_digest),
                vector.notarization_record_digest_hex,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn lower_layer_drift_changes_export_output() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let seal = build_token_transaction_seal_payload_v1(
            build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(
                            built.transaction.proof_placeholder.public_statement,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let record = build_token_transaction_notarization_record_v1(seal.clone()).unwrap();

        let drifted_seal_digest = [0x44; 32];
        let drifted_udot = derive_token_transaction_udot_seed_digest_v1(&drifted_seal_digest);
        let drifted_record_bytes = super::encode_token_transaction_notarization_record_bytes_v1(
            super::TOKEN_NOTARIZATION_RECORD_VERSION_V1,
            seal.proof_statement_type,
            &seal.acknowledgement.ack_digest,
            &drifted_seal_digest,
            &drifted_udot,
        );
        let drifted_record_digest =
            derive_token_transaction_notarization_record_digest_v1(&drifted_record_bytes);

        assert_ne!(record.canonical_bytes(), drifted_record_bytes);
        assert_ne!(record.notarization_record_digest, drifted_record_digest);
    }

    #[test]
    fn no_export_path_reintroduces_upstream_field_assembly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let seal = build_token_transaction_seal_payload_v1(
            build_token_transaction_notary_acknowledgement_v1(
                build_token_transaction_notary_receipt_preimage_v1(
                    build_token_transaction_notary_input_v1(
                        build_token_transaction_proof_binding_v1(
                            built.transaction.proof_placeholder.public_statement,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let direct = build_token_transaction_notarization_record_v1(seal.clone()).unwrap();
        let reconstructed = TokenTransactionNotarizationRecordV1::from_seal_payload(seal).unwrap();

        assert_eq!(direct, reconstructed);
    }

    #[test]
    fn consumer_module_accepts_only_notarization_record_wire() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let record_wire = build_token_transaction_notarization_record_v1(
            build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(
                                built.transaction.proof_placeholder.public_statement,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
        .to_wire();

        let summary = build_token_transaction_notarization_summary_v1(record_wire.clone()).unwrap();

        assert_eq!(summary.record_version, record_wire.record_version);
        assert_eq!(
            summary.proof_statement_type,
            record_wire.proof_statement_type
        );
        assert_eq!(summary.ack_digest_hex, record_wire.ack_digest_hex);
    }

    #[test]
    fn valid_notarization_record_wire_produces_exact_frozen_summary_output() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let summary = build_token_transaction_notarization_summary_v1(
                TokenTransactionNotarizationRecordWireV1 {
                    record_version: 1,
                    proof_statement_type: vector.notarization_summary.proof_statement_type,
                    ack_digest_hex: vector.notarization_summary.ack_digest_hex.clone(),
                    seal_payload_digest_hex: vector
                        .notarization_summary
                        .seal_payload_digest_hex
                        .clone(),
                    udot_seed_digest_hex: vector.notarization_summary.udot_seed_digest_hex.clone(),
                    notarization_record_digest_hex: vector
                        .notarization_summary
                        .notarization_record_digest_hex
                        .clone(),
                },
            )
            .unwrap();
            assert_eq!(
                summary, vector.notarization_summary,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn bad_notarization_record_digest_is_rejected() {
        let vectors = load_fixture_vectors();
        let mut wire = TokenTransactionNotarizationRecordWireV1 {
            record_version: 1,
            proof_statement_type: vectors.vectors[0].notarization_summary.proof_statement_type,
            ack_digest_hex: vectors.vectors[0]
                .notarization_summary
                .ack_digest_hex
                .clone(),
            seal_payload_digest_hex: vectors.vectors[0]
                .notarization_summary
                .seal_payload_digest_hex
                .clone(),
            udot_seed_digest_hex: vectors.vectors[0]
                .notarization_summary
                .udot_seed_digest_hex
                .clone(),
            notarization_record_digest_hex: vectors.vectors[0]
                .notarization_summary
                .notarization_record_digest_hex
                .clone(),
        };
        wire.notarization_record_digest_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();

        let error = build_token_transaction_notarization_summary_v1(wire).unwrap_err();
        match error {
            TokenTransactionErrorV1::InvalidNotarizationRecordDigest { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unsupported_proof_statement_type_label_mapping_fails_closed() {
        let vectors = load_fixture_vectors();
        let ack_digest = super::decode_hex_32_v1(
            "ack_digest_hex",
            &vectors.vectors[0].notarization_summary.ack_digest_hex,
        )
        .unwrap();
        let symbolic_receipt_preimage =
            derive_token_transaction_symbolic_receipt_preimage_v1(&ack_digest);
        let seal_payload_digest = derive_token_transaction_seal_payload_digest_v1(
            &super::encode_token_transaction_seal_payload_bytes_v1(
                super::TOKEN_SEAL_PAYLOAD_VERSION_V1,
                9,
                &ack_digest,
                &symbolic_receipt_preimage,
            ),
        );
        let udot_seed_digest = derive_token_transaction_udot_seed_digest_v1(&seal_payload_digest);
        let mut wire = TokenTransactionNotarizationRecordWireV1 {
            record_version: 1,
            proof_statement_type: 9,
            ack_digest_hex: encode_hex_lower_v1(&ack_digest),
            seal_payload_digest_hex: encode_hex_lower_v1(&seal_payload_digest),
            udot_seed_digest_hex: encode_hex_lower_v1(&udot_seed_digest),
            notarization_record_digest_hex: vectors.vectors[0]
                .notarization_summary
                .notarization_record_digest_hex
                .clone(),
        };
        let canonical = super::encode_token_transaction_notarization_record_bytes_v1(
            1,
            9,
            &ack_digest,
            &seal_payload_digest,
            &udot_seed_digest,
        );
        wire.notarization_record_digest_hex = encode_hex_lower_v1(
            &derive_token_transaction_notarization_record_digest_v1(&canonical),
        );

        let error = build_token_transaction_notarization_summary_v1(wire).unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::UnsupportedProofStatementType {
                expected: EXACT_PUBLIC_STATEMENT_TYPE_V1,
                actual: 9,
            }
        );
    }

    #[test]
    fn notarization_summary_repeatability_holds() {
        let vectors = load_fixture_vectors();
        let wire = TokenTransactionNotarizationRecordWireV1 {
            record_version: 1,
            proof_statement_type: vectors.vectors[0].notarization_summary.proof_statement_type,
            ack_digest_hex: vectors.vectors[0]
                .notarization_summary
                .ack_digest_hex
                .clone(),
            seal_payload_digest_hex: vectors.vectors[0]
                .notarization_summary
                .seal_payload_digest_hex
                .clone(),
            udot_seed_digest_hex: vectors.vectors[0]
                .notarization_summary
                .udot_seed_digest_hex
                .clone(),
            notarization_record_digest_hex: vectors.vectors[0]
                .notarization_summary
                .notarization_record_digest_hex
                .clone(),
        };
        let first = build_token_transaction_notarization_summary_v1(wire.clone()).unwrap();
        let second = build_token_transaction_notarization_summary_v1(wire).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn fixture_backed_summary_outputs_are_pinned() {
        let vectors = load_fixture_vectors();
        for vector in vectors.vectors {
            let record_wire = TokenTransactionNotarizationRecordWireV1 {
                record_version: 1,
                proof_statement_type: vector.notarization_summary.proof_statement_type,
                ack_digest_hex: vector.notarization_summary.ack_digest_hex.clone(),
                seal_payload_digest_hex: vector
                    .notarization_summary
                    .seal_payload_digest_hex
                    .clone(),
                udot_seed_digest_hex: vector.notarization_summary.udot_seed_digest_hex.clone(),
                notarization_record_digest_hex: vector
                    .notarization_summary
                    .notarization_record_digest_hex
                    .clone(),
            };
            let summary = build_token_transaction_notarization_summary_v1(record_wire).unwrap();
            assert_eq!(
                summary, vector.notarization_summary,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn no_consumer_path_reintroduces_upstream_field_assembly() {
        let built = build_deterministic_transaction_v1(sample_build_request()).unwrap();
        let wire = build_token_transaction_notarization_record_v1(
            build_token_transaction_seal_payload_v1(
                build_token_transaction_notary_acknowledgement_v1(
                    build_token_transaction_notary_receipt_preimage_v1(
                        build_token_transaction_notary_input_v1(
                            build_token_transaction_proof_binding_v1(
                                built.transaction.proof_placeholder.public_statement,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
        .to_wire();

        let direct = build_token_transaction_notarization_summary_v1(wire.clone()).unwrap();
        let json = serde_json::to_string(&wire).unwrap();
        let reparsed: TokenTransactionNotarizationRecordWireV1 =
            serde_json::from_str(&json).unwrap();
        let reconstructed = build_token_transaction_notarization_summary_v1(reparsed).unwrap();

        assert_eq!(direct, reconstructed);
    }
}
