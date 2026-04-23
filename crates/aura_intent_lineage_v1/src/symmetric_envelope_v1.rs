//! Aura Session Encryption V1 symmetric envelope construction.

use core::fmt;

use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

use crate::{
    derive_session_public_key_v1, derive_session_symmetric_key_v1, derive_shared_secret_v1,
    encode_session_encryption_context_v1, encode_storm_encryption_binding_v1,
    sha256_domain_separated, validate_session_encryption_context_v1,
    validate_storm_encryption_binding_v1, AuraSessionEncryptionContextV1,
    SessionKeyDerivationInputV1, SessionKeyV1Error, SessionPublicKeyV1, SessionSecretKeyV1,
    StormEncryptionBindingV1, HASH_LEN_V1,
};

pub const ENCRYPTED_ENVELOPE_V1_VERSION: u8 = 0x01;
pub const ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID: u8 = 0x01;
pub const ENCRYPTED_ENVELOPE_V1_NONCE_LEN: usize = 12;
pub const ENCRYPTED_ENVELOPE_V1_TAG_LEN: usize = 16;
pub const AURA_SESSION_ENCRYPTION_AAD_CONTEXT_HASH_V1_DOMAIN_SEPARATOR: &[u8] =
    b"AURA_SESSION_ENCRYPTION_AAD_CONTEXT_HASH_V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraEncryptedEnvelopeV1 {
    pub version: u8,
    pub algorithm_id: u8,
    pub sender_public_key: SessionPublicKeyV1,
    pub receiver_public_key: SessionPublicKeyV1,
    pub nonce: [u8; ENCRYPTED_ENVELOPE_V1_NONCE_LEN],
    pub aad_context_hash: [u8; HASH_LEN_V1],
    pub ciphertext: Vec<u8>,
    pub session_key_id: [u8; HASH_LEN_V1],
}

#[derive(Debug, PartialEq, Eq)]
pub enum SymmetricEnvelopeErrorV1 {
    InvalidEnvelopeVersion {
        expected: u8,
        actual: u8,
    },
    UnsupportedAlgorithm {
        expected: u8,
        actual: u8,
    },
    InvalidSenderPublicKey,
    InvalidReceiverPublicKey,
    InvalidSessionKeyId,
    InvalidCiphertextLength {
        minimum: usize,
        actual: usize,
    },
    AadContextHashMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    SessionKeyIdMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    InvalidSessionEncryptionContext(crate::SessionEncryptionContextErrorV1),
    InvalidStormEncryptionBinding(crate::StormEncryptionBindingErrorV1),
    InvalidSessionKey(SessionKeyV1Error),
    SecureRandomUnavailable,
    EncryptFailed,
    DecryptFailed,
}

impl fmt::Display for SymmetricEnvelopeErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelopeVersion { expected, actual } => write!(
                f,
                "invalid encrypted envelope version: expected {expected}, got {actual}"
            ),
            Self::UnsupportedAlgorithm { expected, actual } => write!(
                f,
                "unsupported encrypted envelope algorithm: expected {expected}, got {actual}"
            ),
            Self::InvalidSenderPublicKey => write!(f, "invalid sender public key"),
            Self::InvalidReceiverPublicKey => write!(f, "invalid receiver public key"),
            Self::InvalidSessionKeyId => write!(f, "invalid session key id"),
            Self::InvalidCiphertextLength { minimum, actual } => write!(
                f,
                "invalid ciphertext length: expected at least {minimum} bytes, got {actual}"
            ),
            Self::AadContextHashMismatch { expected, actual } => write!(
                f,
                "aad context hash mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::SessionKeyIdMismatch { expected, actual } => write!(
                f,
                "session key id mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::InvalidSessionEncryptionContext(error) => {
                write!(f, "invalid session encryption context: {error}")
            }
            Self::InvalidStormEncryptionBinding(error) => {
                write!(f, "invalid storm encryption binding: {error}")
            }
            Self::InvalidSessionKey(error) => write!(f, "invalid session key: {error}"),
            Self::SecureRandomUnavailable => write!(f, "secure randomness unavailable"),
            Self::EncryptFailed => write!(f, "payload encryption failed"),
            Self::DecryptFailed => write!(f, "payload decryption failed"),
        }
    }
}

impl std::error::Error for SymmetricEnvelopeErrorV1 {}

pub fn encrypt_payload_v1(
    sender_secret_key: &SessionSecretKeyV1,
    receiver_public_key: &SessionPublicKeyV1,
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
    nonce: [u8; ENCRYPTED_ENVELOPE_V1_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, SymmetricEnvelopeErrorV1> {
    let shared_secret = derive_shared_secret_v1(sender_secret_key, receiver_public_key)
        .map_err(SymmetricEnvelopeErrorV1::InvalidSessionKey)?;
    let session_key = derive_session_symmetric_key_v1(&SessionKeyDerivationInputV1 {
        shared_secret,
        session_encryption_context: *session_encryption_context,
        storm_encryption_binding: *storm_encryption_binding,
    })
    .map_err(SymmetricEnvelopeErrorV1::InvalidSessionKey)?;
    let aad_material = build_aad_material_v1(session_encryption_context, storm_encryption_binding)?;

    let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, session_key.as_bytes())
        .map_err(|_| SymmetricEnvelopeErrorV1::EncryptFailed)?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad_material.as_slice()),
            &mut in_out,
        )
        .map_err(|_| SymmetricEnvelopeErrorV1::EncryptFailed)?;
    Ok(in_out)
}

pub fn decrypt_payload_v1(
    receiver_secret_key: &SessionSecretKeyV1,
    sender_public_key: &SessionPublicKeyV1,
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
    nonce: [u8; ENCRYPTED_ENVELOPE_V1_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SymmetricEnvelopeErrorV1> {
    if ciphertext.len() < ENCRYPTED_ENVELOPE_V1_TAG_LEN {
        return Err(SymmetricEnvelopeErrorV1::InvalidCiphertextLength {
            minimum: ENCRYPTED_ENVELOPE_V1_TAG_LEN,
            actual: ciphertext.len(),
        });
    }

    let shared_secret = derive_shared_secret_v1(receiver_secret_key, sender_public_key)
        .map_err(SymmetricEnvelopeErrorV1::InvalidSessionKey)?;
    let session_key = derive_session_symmetric_key_v1(&SessionKeyDerivationInputV1 {
        shared_secret,
        session_encryption_context: *session_encryption_context,
        storm_encryption_binding: *storm_encryption_binding,
    })
    .map_err(SymmetricEnvelopeErrorV1::InvalidSessionKey)?;
    let aad_material = build_aad_material_v1(session_encryption_context, storm_encryption_binding)?;

    let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, session_key.as_bytes())
        .map_err(|_| SymmetricEnvelopeErrorV1::DecryptFailed)?;
    let opening_key = LessSafeKey::new(unbound_key);
    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad_material.as_slice()),
            &mut in_out,
        )
        .map_err(|_| SymmetricEnvelopeErrorV1::DecryptFailed)?;

    Ok(plaintext.to_vec())
}

pub fn build_encrypted_envelope_v1(
    sender_secret_key: &SessionSecretKeyV1,
    receiver_public_key: &SessionPublicKeyV1,
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
    plaintext: &[u8],
    nonce: Option<[u8; ENCRYPTED_ENVELOPE_V1_NONCE_LEN]>,
) -> Result<AuraEncryptedEnvelopeV1, SymmetricEnvelopeErrorV1> {
    let sender_public_key = derive_session_public_key_v1(sender_secret_key);
    let nonce = match nonce {
        Some(nonce) => nonce,
        None => generate_envelope_nonce_v1()?,
    };
    let ciphertext = encrypt_payload_v1(
        sender_secret_key,
        receiver_public_key,
        session_encryption_context,
        storm_encryption_binding,
        nonce,
        plaintext,
    )?;
    let envelope = AuraEncryptedEnvelopeV1 {
        version: ENCRYPTED_ENVELOPE_V1_VERSION,
        algorithm_id: ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
        sender_public_key,
        receiver_public_key: *receiver_public_key,
        nonce,
        aad_context_hash: derive_aad_context_hash_v1(
            session_encryption_context,
            storm_encryption_binding,
        )?,
        ciphertext,
        session_key_id: session_encryption_context.session_key_id,
    };
    validate_encrypted_envelope_v1(
        &envelope,
        session_encryption_context,
        storm_encryption_binding,
    )?;
    Ok(envelope)
}

pub fn validate_encrypted_envelope_v1(
    envelope: &AuraEncryptedEnvelopeV1,
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
) -> Result<(), SymmetricEnvelopeErrorV1> {
    if envelope.version != ENCRYPTED_ENVELOPE_V1_VERSION {
        return Err(SymmetricEnvelopeErrorV1::InvalidEnvelopeVersion {
            expected: ENCRYPTED_ENVELOPE_V1_VERSION,
            actual: envelope.version,
        });
    }

    if envelope.algorithm_id != ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID {
        return Err(SymmetricEnvelopeErrorV1::UnsupportedAlgorithm {
            expected: ENCRYPTED_ENVELOPE_V1_ALGORITHM_ID,
            actual: envelope.algorithm_id,
        });
    }

    if envelope
        .sender_public_key
        .bytes
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(SymmetricEnvelopeErrorV1::InvalidSenderPublicKey);
    }

    if envelope
        .receiver_public_key
        .bytes
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(SymmetricEnvelopeErrorV1::InvalidReceiverPublicKey);
    }

    if session_encryption_context
        .session_key_id
        .iter()
        .all(|byte| *byte == 0)
        || storm_encryption_binding
            .session_key_id
            .iter()
            .all(|byte| *byte == 0)
        || envelope.session_key_id.iter().all(|byte| *byte == 0)
    {
        return Err(SymmetricEnvelopeErrorV1::InvalidSessionKeyId);
    }

    if envelope.ciphertext.len() < ENCRYPTED_ENVELOPE_V1_TAG_LEN {
        return Err(SymmetricEnvelopeErrorV1::InvalidCiphertextLength {
            minimum: ENCRYPTED_ENVELOPE_V1_TAG_LEN,
            actual: envelope.ciphertext.len(),
        });
    }

    validate_session_encryption_context_v1(session_encryption_context)
        .map_err(SymmetricEnvelopeErrorV1::InvalidSessionEncryptionContext)?;
    validate_storm_encryption_binding_v1(storm_encryption_binding)
        .map_err(SymmetricEnvelopeErrorV1::InvalidStormEncryptionBinding)?;

    if envelope.session_key_id != session_encryption_context.session_key_id {
        return Err(SymmetricEnvelopeErrorV1::SessionKeyIdMismatch {
            expected: session_encryption_context.session_key_id,
            actual: envelope.session_key_id,
        });
    }

    if envelope.session_key_id != storm_encryption_binding.session_key_id {
        return Err(SymmetricEnvelopeErrorV1::SessionKeyIdMismatch {
            expected: storm_encryption_binding.session_key_id,
            actual: envelope.session_key_id,
        });
    }

    let expected_aad_context_hash =
        derive_aad_context_hash_v1(session_encryption_context, storm_encryption_binding)?;
    if envelope.aad_context_hash != expected_aad_context_hash {
        return Err(SymmetricEnvelopeErrorV1::AadContextHashMismatch {
            expected: expected_aad_context_hash,
            actual: envelope.aad_context_hash,
        });
    }

    Ok(())
}

pub fn derive_aad_context_hash_v1(
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
) -> Result<[u8; HASH_LEN_V1], SymmetricEnvelopeErrorV1> {
    let aad_material = build_aad_material_v1(session_encryption_context, storm_encryption_binding)?;
    Ok(sha256_domain_separated(
        AURA_SESSION_ENCRYPTION_AAD_CONTEXT_HASH_V1_DOMAIN_SEPARATOR,
        &aad_material,
    ))
}

fn generate_envelope_nonce_v1(
) -> Result<[u8; ENCRYPTED_ENVELOPE_V1_NONCE_LEN], SymmetricEnvelopeErrorV1> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; ENCRYPTED_ENVELOPE_V1_NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|_| SymmetricEnvelopeErrorV1::SecureRandomUnavailable)?;
    Ok(nonce)
}

fn build_aad_material_v1(
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
) -> Result<Vec<u8>, SymmetricEnvelopeErrorV1> {
    let encoded_context = encode_session_encryption_context_v1(session_encryption_context)
        .map_err(SymmetricEnvelopeErrorV1::InvalidSessionEncryptionContext)?;
    let encoded_binding = encode_storm_encryption_binding_v1(storm_encryption_binding)
        .map_err(SymmetricEnvelopeErrorV1::InvalidStormEncryptionBinding)?;
    let mut aad = Vec::with_capacity(encoded_context.len() + encoded_binding.len());
    aad.extend_from_slice(&encoded_context);
    aad.extend_from_slice(&encoded_binding);
    Ok(aad)
}
