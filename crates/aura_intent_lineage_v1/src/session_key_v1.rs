//! Aura Session Encryption V1 session key agreement and symmetric key derivation.

use core::fmt;

use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};
use ring::{
    hkdf,
    rand::{SecureRandom, SystemRandom},
};

use crate::{
    encode_session_encryption_context_v1, encode_storm_encryption_binding_v1,
    sha256_domain_separated, AuraSessionEncryptionContextV1, StormEncryptionBindingV1,
    HASH_LEN_V1,
};

pub const SESSION_KEY_MATERIAL_V1_LEN: usize = 32;
pub const AURA_SESSION_KEY_ID_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_SESSION_KEY_ID_V1";
pub const AURA_SESSION_SYMMETRIC_KEY_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_SESSION_SYMMETRIC_KEY_V1";
pub const AURA_SESSION_SYMMETRIC_KEY_V1_INFO_LABEL: &[u8] = b"AURA_SESSION_SYMMETRIC_KEY_V1_INFO";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionPublicKeyV1 {
    pub bytes: [u8; SESSION_KEY_MATERIAL_V1_LEN],
}

impl fmt::Debug for SessionPublicKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionPublicKeyV1({})", crate::LowerHex32(&self.bytes))
    }
}

impl SessionPublicKeyV1 {
    pub const fn as_bytes(&self) -> &[u8; SESSION_KEY_MATERIAL_V1_LEN] {
        &self.bytes
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionSecretKeyV1 {
    pub bytes: [u8; SESSION_KEY_MATERIAL_V1_LEN],
}

impl fmt::Debug for SessionSecretKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSecretKeyV1([REDACTED])")
    }
}

impl SessionSecretKeyV1 {
    pub const fn as_bytes(&self) -> &[u8; SESSION_KEY_MATERIAL_V1_LEN] {
        &self.bytes
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SharedSecretV1 {
    pub bytes: [u8; SESSION_KEY_MATERIAL_V1_LEN],
}

impl fmt::Debug for SharedSecretV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecretV1([REDACTED])")
    }
}

impl SharedSecretV1 {
    pub const fn as_bytes(&self) -> &[u8; SESSION_KEY_MATERIAL_V1_LEN] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionKeyDerivationInputV1 {
    pub shared_secret: SharedSecretV1,
    pub session_encryption_context: AuraSessionEncryptionContextV1,
    pub storm_encryption_binding: StormEncryptionBindingV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionSymmetricKeyV1 {
    pub bytes: [u8; SESSION_KEY_MATERIAL_V1_LEN],
}

impl fmt::Debug for SessionSymmetricKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSymmetricKeyV1([REDACTED])")
    }
}

impl SessionSymmetricKeyV1 {
    pub const fn as_bytes(&self) -> &[u8; SESSION_KEY_MATERIAL_V1_LEN] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKeyV1Error {
    SecureRandomUnavailable,
    InvalidPeerPublicKey,
    SharedSecretIsIdentity,
    InvalidSessionEncryptionContext,
    InvalidStormEncryptionBinding(crate::StormEncryptionBindingErrorV1),
    StormBindingMismatch {
        field: &'static str,
    },
    SessionKeyIdMismatch {
        expected: [u8; HASH_LEN_V1],
        actual: [u8; HASH_LEN_V1],
    },
    KeyExpansionFailed,
}

impl fmt::Display for SessionKeyV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecureRandomUnavailable => write!(f, "secure randomness unavailable"),
            Self::InvalidPeerPublicKey => write!(f, "invalid peer X25519 public key"),
            Self::SharedSecretIsIdentity => write!(f, "shared secret resolved to the identity"),
            Self::InvalidSessionEncryptionContext => {
                write!(f, "invalid session encryption context")
            }
            Self::InvalidStormEncryptionBinding(error) => {
                write!(f, "invalid storm encryption binding: {error}")
            }
            Self::StormBindingMismatch { field } => {
                write!(f, "storm encryption binding mismatch: {field}")
            }
            Self::SessionKeyIdMismatch { expected, actual } => write!(
                f,
                "session key id mismatch: expected {}, got {}",
                crate::LowerHex32(expected),
                crate::LowerHex32(actual)
            ),
            Self::KeyExpansionFailed => write!(f, "session symmetric key expansion failed"),
        }
    }
}

impl std::error::Error for SessionKeyV1Error {}

pub fn generate_session_keypair_v1(
) -> Result<(SessionSecretKeyV1, SessionPublicKeyV1), SessionKeyV1Error> {
    let rng = SystemRandom::new();
    let mut secret_bytes = [0u8; SESSION_KEY_MATERIAL_V1_LEN];
    rng.fill(&mut secret_bytes)
        .map_err(|_| SessionKeyV1Error::SecureRandomUnavailable)?;
    let secret_key = SessionSecretKeyV1 {
        bytes: secret_bytes,
    };
    let public_key = derive_session_public_key_v1(&secret_key);
    Ok((secret_key, public_key))
}

pub fn derive_shared_secret_v1(
    local_secret_key: &SessionSecretKeyV1,
    peer_public_key: &SessionPublicKeyV1,
) -> Result<SharedSecretV1, SessionKeyV1Error> {
    if peer_public_key.bytes.iter().all(|byte| *byte == 0) {
        return Err(SessionKeyV1Error::InvalidPeerPublicKey);
    }

    let scalar = x25519_scalar_v1(local_secret_key);
    let point = MontgomeryPoint(peer_public_key.bytes);
    let shared_secret = (&scalar * &point).to_bytes();

    if shared_secret.iter().all(|byte| *byte == 0) {
        return Err(SessionKeyV1Error::SharedSecretIsIdentity);
    }

    Ok(SharedSecretV1 {
        bytes: shared_secret,
    })
}

pub fn derive_session_key_id_v1(
    shared_secret: &SharedSecretV1,
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
) -> Result<[u8; HASH_LEN_V1], SessionKeyV1Error> {
    validate_context_and_binding_alignment_v1(session_encryption_context, storm_encryption_binding)?;

    let normalized_context = AuraSessionEncryptionContextV1 {
        session_key_id: [0u8; HASH_LEN_V1],
        ..*session_encryption_context
    };
    let normalized_binding = StormEncryptionBindingV1 {
        session_key_id: [0u8; HASH_LEN_V1],
        ..*storm_encryption_binding
    };
    let context_bytes = encode_session_encryption_context_v1(&normalized_context)
        .map_err(|_| SessionKeyV1Error::InvalidSessionEncryptionContext)?;
    let binding_bytes = encode_storm_encryption_binding_v1(&normalized_binding)
        .map_err(SessionKeyV1Error::InvalidStormEncryptionBinding)?;
    let mut payload =
        Vec::with_capacity(shared_secret.bytes.len() + context_bytes.len() + binding_bytes.len());
    payload.extend_from_slice(&shared_secret.bytes);
    payload.extend_from_slice(&context_bytes);
    payload.extend_from_slice(&binding_bytes);
    Ok(sha256_domain_separated(
        AURA_SESSION_KEY_ID_V1_DOMAIN_SEPARATOR,
        &payload,
    ))
}

pub fn derive_session_symmetric_key_v1(
    input: &SessionKeyDerivationInputV1,
) -> Result<SessionSymmetricKeyV1, SessionKeyV1Error> {
    validate_context_and_binding_alignment_v1(
        &input.session_encryption_context,
        &input.storm_encryption_binding,
    )?;

    let expected_session_key_id = derive_session_key_id_v1(
        &input.shared_secret,
        &input.session_encryption_context,
        &input.storm_encryption_binding,
    )?;
    if input.session_encryption_context.session_key_id != expected_session_key_id {
        return Err(SessionKeyV1Error::SessionKeyIdMismatch {
            expected: expected_session_key_id,
            actual: input.session_encryption_context.session_key_id,
        });
    }
    if input.storm_encryption_binding.session_key_id != expected_session_key_id {
        return Err(SessionKeyV1Error::SessionKeyIdMismatch {
            expected: expected_session_key_id,
            actual: input.storm_encryption_binding.session_key_id,
        });
    }

    let context_bytes = encode_session_encryption_context_v1(&input.session_encryption_context)
        .map_err(|_| SessionKeyV1Error::InvalidSessionEncryptionContext)?;
    let binding_bytes = encode_storm_encryption_binding_v1(&input.storm_encryption_binding)
        .map_err(SessionKeyV1Error::InvalidStormEncryptionBinding)?;
    let mut ikm =
        Vec::with_capacity(input.shared_secret.bytes.len() + context_bytes.len() + binding_bytes.len());
    ikm.extend_from_slice(&input.shared_secret.bytes);
    ikm.extend_from_slice(&context_bytes);
    ikm.extend_from_slice(&binding_bytes);

    let salt = hkdf::Salt::new(
        hkdf::HKDF_SHA256,
        AURA_SESSION_SYMMETRIC_KEY_V1_DOMAIN_SEPARATOR,
    );
    let prk = salt.extract(&ikm);
    let info = [
        AURA_SESSION_SYMMETRIC_KEY_V1_INFO_LABEL,
        context_bytes.as_slice(),
        binding_bytes.as_slice(),
    ];
    let okm = prk
        .expand(&info, SessionSymmetricKeyLenV1)
        .map_err(|_| SessionKeyV1Error::KeyExpansionFailed)?;

    let mut key_bytes = [0u8; SESSION_KEY_MATERIAL_V1_LEN];
    okm.fill(&mut key_bytes)
        .map_err(|_| SessionKeyV1Error::KeyExpansionFailed)?;

    Ok(SessionSymmetricKeyV1 { bytes: key_bytes })
}

pub fn derive_session_public_key_v1(secret_key: &SessionSecretKeyV1) -> SessionPublicKeyV1 {
    let scalar = x25519_scalar_v1(secret_key);
    let public_key = (&scalar * &X25519_BASEPOINT).to_bytes();
    SessionPublicKeyV1 { bytes: public_key }
}

fn x25519_scalar_v1(secret_key: &SessionSecretKeyV1) -> Scalar {
    Scalar::from_bits(clamp_x25519_scalar_bytes_v1(secret_key.bytes))
}

fn clamp_x25519_scalar_bytes_v1(mut scalar_bytes: [u8; SESSION_KEY_MATERIAL_V1_LEN]) -> [u8; 32] {
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    scalar_bytes
}

struct SessionSymmetricKeyLenV1;

impl hkdf::KeyType for SessionSymmetricKeyLenV1 {
    fn len(&self) -> usize {
        SESSION_KEY_MATERIAL_V1_LEN
    }
}

fn validate_context_and_binding_alignment_v1(
    session_encryption_context: &AuraSessionEncryptionContextV1,
    storm_encryption_binding: &StormEncryptionBindingV1,
) -> Result<(), SessionKeyV1Error> {
    if session_encryption_context.storm_claim_digest
        != storm_encryption_binding.storm_claim_digest
    {
        return Err(SessionKeyV1Error::StormBindingMismatch {
            field: "storm_claim_digest",
        });
    }
    if session_encryption_context.sender_id != storm_encryption_binding.sender_id {
        return Err(SessionKeyV1Error::StormBindingMismatch { field: "sender_id" });
    }
    if session_encryption_context.receiver_id != storm_encryption_binding.receiver_id {
        return Err(SessionKeyV1Error::StormBindingMismatch {
            field: "receiver_id",
        });
    }
    Ok(())
}
