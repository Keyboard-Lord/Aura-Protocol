use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};

use crate::HASH_LEN_V1;

use super::proof_binding::{
    build_token_transaction_proof_binding_v1, derive_token_transaction_proof_binding_digest_v1,
};
use super::shared::{decode_hex_32_v1, encode_hex_lower_v1};
use super::{
    build_token_transaction_notary_input_v1, DeterministicTransactionV1,
    TokenTransactionAuthorizationEnvelopeV1, TokenTransactionAuthorizationEnvelopeWireV1,
    TokenTransactionAuthorizationPayloadV1, TokenTransactionAuthorizationPayloadWireV1,
    TokenTransactionAuthorizationSignRequestWireV1,
    TokenTransactionAuthorizationSignResponseWireV1, TokenTransactionAuthorizedProofBindingV1,
    TokenTransactionErrorV1, TokenTransactionNotaryInputV1,
    AURA_TOKEN_AUTHORIZATION_PAYLOAD_DOMAIN_SEPARATOR_V1, EXACT_PUBLIC_STATEMENT_TYPE_V1,
    PRIVATE_TRANSFER_BURN_KIND_V1, TOKEN_TRANSACTION_AUTHORIZATION_ENVELOPE_VERSION_V1,
    TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_KIND_EXACT_PUBLIC_STATEMENT_V1,
    TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_VERSION_V1,
    TOKEN_TRANSACTION_AUTHORIZATION_SCHEME_ED25519_V1,
    TOKEN_TRANSACTION_AUTHORIZATION_SIGNER_KIND_RAW_ED25519_PUBLIC_KEY_V1,
    TOKEN_TRANSACTION_AUTHORIZATION_SIGN_REQUEST_VERSION_V1,
    TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1, TOKEN_TX_VERSION_V1,
};

pub fn build_token_transaction_authorization_payload_v1(
    transaction: &DeterministicTransactionV1,
    signer_public_key: [u8; HASH_LEN_V1],
    authorization_nonce: [u8; HASH_LEN_V1],
) -> Result<TokenTransactionAuthorizationPayloadV1, TokenTransactionErrorV1> {
    TokenTransactionAuthorizationPayloadV1::from_transaction(
        transaction,
        signer_public_key,
        authorization_nonce,
    )
}

pub fn build_token_transaction_authorization_sign_request_v1(
    transaction: &DeterministicTransactionV1,
    signer_public_key: [u8; HASH_LEN_V1],
    authorization_nonce: [u8; HASH_LEN_V1],
) -> Result<TokenTransactionAuthorizationSignRequestWireV1, TokenTransactionErrorV1> {
    TokenTransactionAuthorizationSignRequestWireV1::from_payload(
        build_token_transaction_authorization_payload_v1(
            transaction,
            signer_public_key,
            authorization_nonce,
        )?,
    )
}

pub fn sign_token_transaction_authorization_payload_v1(
    payload: TokenTransactionAuthorizationPayloadV1,
    signing_key_bytes: [u8; 32],
) -> Result<TokenTransactionAuthorizationEnvelopeV1, TokenTransactionErrorV1> {
    TokenTransactionAuthorizationEnvelopeV1::signed(payload, signing_key_bytes)
}

pub fn build_token_transaction_authorization_sign_response_v1(
    envelope: TokenTransactionAuthorizationEnvelopeV1,
) -> Result<TokenTransactionAuthorizationSignResponseWireV1, TokenTransactionErrorV1> {
    TokenTransactionAuthorizationSignResponseWireV1::from_envelope(envelope)
}

pub fn validate_token_transaction_authorization_envelope_v1(
    transaction: &DeterministicTransactionV1,
    envelope: &TokenTransactionAuthorizationEnvelopeV1,
) -> Result<(), TokenTransactionErrorV1> {
    envelope.validate_against_transaction(transaction)
}

pub fn reconstruct_token_transaction_authorization_envelope_from_sign_response_v1(
    response: TokenTransactionAuthorizationSignResponseWireV1,
) -> Result<TokenTransactionAuthorizationEnvelopeV1, TokenTransactionErrorV1> {
    response.into_envelope()
}

pub fn validate_token_transaction_authorization_sign_response_v1(
    request: &TokenTransactionAuthorizationSignRequestWireV1,
    response: &TokenTransactionAuthorizationSignResponseWireV1,
) -> Result<TokenTransactionAuthorizationEnvelopeV1, TokenTransactionErrorV1> {
    response.validate_against_request(request)
}

pub fn build_token_transaction_authorized_proof_binding_v1(
    transaction: &DeterministicTransactionV1,
    authorization_envelope: TokenTransactionAuthorizationEnvelopeV1,
) -> Result<TokenTransactionAuthorizedProofBindingV1, TokenTransactionErrorV1> {
    TokenTransactionAuthorizedProofBindingV1::from_transaction(transaction, authorization_envelope)
}

pub fn build_token_transaction_authorized_notary_input_v1(
    transaction: &DeterministicTransactionV1,
    authorization_envelope: TokenTransactionAuthorizationEnvelopeV1,
) -> Result<TokenTransactionNotaryInputV1, TokenTransactionErrorV1> {
    build_token_transaction_notary_input_from_authorized_proof_binding_v1(
        build_token_transaction_authorized_proof_binding_v1(transaction, authorization_envelope)?,
    )
}

pub fn derive_token_transaction_public_statement_digest_v1(
    public_statement_bytes: &[u8],
) -> [u8; HASH_LEN_V1] {
    derive_token_transaction_proof_binding_digest_v1(public_statement_bytes)
}

fn build_token_transaction_notary_input_from_authorized_proof_binding_v1(
    authorized_proof_binding: TokenTransactionAuthorizedProofBindingV1,
) -> Result<TokenTransactionNotaryInputV1, TokenTransactionErrorV1> {
    authorized_proof_binding.authorization_envelope.validate()?;
    if authorized_proof_binding
        .authorization_envelope
        .payload
        .proof_statement_type
        != authorized_proof_binding.proof_binding.proof_statement_type
    {
        return Err(
            TokenTransactionErrorV1::AuthorizationProofStatementTypeMismatch {
                expected: authorized_proof_binding.proof_binding.proof_statement_type,
                actual: authorized_proof_binding
                    .authorization_envelope
                    .payload
                    .proof_statement_type,
            },
        );
    }
    if authorized_proof_binding
        .authorization_envelope
        .payload
        .tx_commitment
        != authorized_proof_binding
            .proof_binding
            .public_statement
            .tx_commitment
    {
        return Err(
            TokenTransactionErrorV1::AuthorizationTransactionCommitmentMismatch {
                expected: authorized_proof_binding
                    .proof_binding
                    .public_statement
                    .tx_commitment,
                actual: authorized_proof_binding
                    .authorization_envelope
                    .payload
                    .tx_commitment,
            },
        );
    }
    if authorized_proof_binding
        .authorization_envelope
        .payload
        .public_statement_digest
        != authorized_proof_binding.proof_binding.proof_binding_digest
    {
        return Err(
            TokenTransactionErrorV1::AuthorizationPublicStatementDigestMismatch {
                expected: authorized_proof_binding.proof_binding.proof_binding_digest,
                actual: authorized_proof_binding
                    .authorization_envelope
                    .payload
                    .public_statement_digest,
            },
        );
    }

    build_token_transaction_notary_input_v1(authorized_proof_binding.proof_binding)
}

impl TokenTransactionAuthorizationSignRequestWireV1 {
    pub fn from_payload(
        payload: TokenTransactionAuthorizationPayloadV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        Ok(Self {
            request_version: TOKEN_TRANSACTION_AUTHORIZATION_SIGN_REQUEST_VERSION_V1,
            payload_bytes_hex: encode_hex_lower_v1(&payload.canonical_bytes()?),
            payload: payload.to_wire(),
        })
    }

    pub fn validate(
        &self,
    ) -> Result<TokenTransactionAuthorizationPayloadV1, TokenTransactionErrorV1> {
        if self.request_version != TOKEN_TRANSACTION_AUTHORIZATION_SIGN_REQUEST_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationSignRequestVersion {
                    expected: TOKEN_TRANSACTION_AUTHORIZATION_SIGN_REQUEST_VERSION_V1,
                    actual: self.request_version,
                },
            );
        }

        let payload = TokenTransactionAuthorizationPayloadV1::from_wire(self.payload.clone())?;
        if self.payload_bytes_hex != encode_hex_lower_v1(&payload.canonical_bytes()?) {
            return Err(TokenTransactionErrorV1::AuthorizationSignRequestPayloadBytesMismatch);
        }
        Ok(payload)
    }
}

impl TokenTransactionAuthorizationSignResponseWireV1 {
    pub fn from_envelope(
        envelope: TokenTransactionAuthorizationEnvelopeV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        envelope.validate()?;
        Ok(Self {
            response_version: TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1,
            envelope: envelope.to_wire(),
        })
    }

    pub fn into_envelope(
        self,
    ) -> Result<TokenTransactionAuthorizationEnvelopeV1, TokenTransactionErrorV1> {
        if self.response_version != TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationSignResponseVersion {
                    expected: TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1,
                    actual: self.response_version,
                },
            );
        }
        TokenTransactionAuthorizationEnvelopeV1::from_wire(self.envelope)
    }

    pub fn validate_against_request(
        &self,
        request: &TokenTransactionAuthorizationSignRequestWireV1,
    ) -> Result<TokenTransactionAuthorizationEnvelopeV1, TokenTransactionErrorV1> {
        let request_payload = request.validate()?;
        if self.response_version != TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationSignResponseVersion {
                    expected: TOKEN_TRANSACTION_AUTHORIZATION_SIGN_RESPONSE_VERSION_V1,
                    actual: self.response_version,
                },
            );
        }

        let envelope = TokenTransactionAuthorizationEnvelopeV1::from_wire(self.envelope.clone())?;
        if envelope.payload != request_payload {
            return Err(TokenTransactionErrorV1::AuthorizationSignResponsePayloadMismatch);
        }

        Ok(envelope)
    }
}

impl TokenTransactionAuthorizationPayloadV1 {
    pub fn from_transaction(
        transaction: &DeterministicTransactionV1,
        signer_public_key: [u8; HASH_LEN_V1],
        authorization_nonce: [u8; HASH_LEN_V1],
    ) -> Result<Self, TokenTransactionErrorV1> {
        transaction.validate()?;
        let public_statement = &transaction.proof_placeholder.public_statement;
        public_statement.validate()?;
        let public_statement_bytes = public_statement.canonical_bytes()?;

        let payload = Self {
            payload_version: TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_VERSION_V1,
            payload_kind: TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_KIND_EXACT_PUBLIC_STATEMENT_V1,
            tx_version: transaction.tx_version,
            tx_kind: transaction.tx_kind,
            proof_statement_type: transaction.proof_statement_type,
            signer_kind: TOKEN_TRANSACTION_AUTHORIZATION_SIGNER_KIND_RAW_ED25519_PUBLIC_KEY_V1,
            signer_public_key,
            authorization_nonce,
            tx_commitment: transaction.tx_commitment,
            public_statement_digest: derive_token_transaction_public_statement_digest_v1(
                &public_statement_bytes,
            ),
        };
        payload.validate_against_transaction(transaction)?;
        Ok(payload)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TokenTransactionErrorV1> {
        self.validate()?;
        Ok(encode_token_transaction_authorization_payload_bytes_v1(
            self,
        ))
    }

    pub fn validate(&self) -> Result<(), TokenTransactionErrorV1> {
        if self.payload_version != TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationPayloadVersion {
                    expected: TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_VERSION_V1,
                    actual: self.payload_version,
                },
            );
        }
        if self.payload_kind
            != TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_KIND_EXACT_PUBLIC_STATEMENT_V1
        {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationPayloadKind {
                    expected:
                        TOKEN_TRANSACTION_AUTHORIZATION_PAYLOAD_KIND_EXACT_PUBLIC_STATEMENT_V1,
                    actual: self.payload_kind,
                },
            );
        }
        if self.signer_kind != TOKEN_TRANSACTION_AUTHORIZATION_SIGNER_KIND_RAW_ED25519_PUBLIC_KEY_V1
        {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationSignerKind {
                    expected: TOKEN_TRANSACTION_AUTHORIZATION_SIGNER_KIND_RAW_ED25519_PUBLIC_KEY_V1,
                    actual: self.signer_kind,
                },
            );
        }
        if self.tx_version != TOKEN_TX_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::AuthorizationTransactionVersionMismatch {
                    expected: TOKEN_TX_VERSION_V1,
                    actual: self.tx_version,
                },
            );
        }
        if self.tx_kind != PRIVATE_TRANSFER_BURN_KIND_V1 {
            return Err(
                TokenTransactionErrorV1::AuthorizationTransactionKindMismatch {
                    expected: PRIVATE_TRANSFER_BURN_KIND_V1,
                    actual: self.tx_kind,
                },
            );
        }
        if self.proof_statement_type != EXACT_PUBLIC_STATEMENT_TYPE_V1 {
            return Err(
                TokenTransactionErrorV1::AuthorizationProofStatementTypeMismatch {
                    expected: EXACT_PUBLIC_STATEMENT_TYPE_V1,
                    actual: self.proof_statement_type,
                },
            );
        }
        if self.signer_public_key == [0u8; HASH_LEN_V1] {
            return Err(TokenTransactionErrorV1::AuthorizationSignerPublicKeyMustBeNonZero);
        }
        if self.authorization_nonce == [0u8; HASH_LEN_V1] {
            return Err(TokenTransactionErrorV1::AuthorizationNonceMustBeNonZero);
        }
        PublicKey::from_bytes(&self.signer_public_key)
            .map_err(|_| TokenTransactionErrorV1::AuthorizationPublicKeyInvalid)?;
        Ok(())
    }

    pub fn validate_against_transaction(
        &self,
        transaction: &DeterministicTransactionV1,
    ) -> Result<(), TokenTransactionErrorV1> {
        self.validate()?;
        transaction.validate()?;
        let public_statement = &transaction.proof_placeholder.public_statement;
        public_statement.validate()?;

        if self.tx_version != transaction.tx_version {
            return Err(
                TokenTransactionErrorV1::AuthorizationTransactionVersionMismatch {
                    expected: transaction.tx_version,
                    actual: self.tx_version,
                },
            );
        }
        if self.tx_kind != transaction.tx_kind {
            return Err(
                TokenTransactionErrorV1::AuthorizationTransactionKindMismatch {
                    expected: transaction.tx_kind,
                    actual: self.tx_kind,
                },
            );
        }
        if self.proof_statement_type != transaction.proof_statement_type {
            return Err(
                TokenTransactionErrorV1::AuthorizationProofStatementTypeMismatch {
                    expected: transaction.proof_statement_type,
                    actual: self.proof_statement_type,
                },
            );
        }
        if self.tx_commitment != transaction.tx_commitment {
            return Err(
                TokenTransactionErrorV1::AuthorizationTransactionCommitmentMismatch {
                    expected: transaction.tx_commitment,
                    actual: self.tx_commitment,
                },
            );
        }

        let public_statement_digest = derive_token_transaction_public_statement_digest_v1(
            &public_statement.canonical_bytes()?,
        );
        if self.public_statement_digest != public_statement_digest {
            return Err(
                TokenTransactionErrorV1::AuthorizationPublicStatementDigestMismatch {
                    expected: public_statement_digest,
                    actual: self.public_statement_digest,
                },
            );
        }

        Ok(())
    }

    pub fn to_wire(&self) -> TokenTransactionAuthorizationPayloadWireV1 {
        TokenTransactionAuthorizationPayloadWireV1 {
            payload_version: self.payload_version,
            payload_kind: self.payload_kind,
            tx_version: self.tx_version,
            tx_kind: self.tx_kind,
            proof_statement_type: self.proof_statement_type,
            signer_kind: self.signer_kind,
            signer_public_key_hex: encode_hex_lower_v1(&self.signer_public_key),
            authorization_nonce_hex: encode_hex_lower_v1(&self.authorization_nonce),
            transaction_commitment_hex: encode_hex_lower_v1(&self.tx_commitment),
            public_statement_digest_hex: encode_hex_lower_v1(&self.public_statement_digest),
        }
    }

    pub fn from_wire(
        payload: TokenTransactionAuthorizationPayloadWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let result = Self {
            payload_version: payload.payload_version,
            payload_kind: payload.payload_kind,
            tx_version: payload.tx_version,
            tx_kind: payload.tx_kind,
            proof_statement_type: payload.proof_statement_type,
            signer_kind: payload.signer_kind,
            signer_public_key: decode_hex_32_v1(
                "signer_public_key_hex",
                &payload.signer_public_key_hex,
            )?,
            authorization_nonce: decode_hex_32_v1(
                "authorization_nonce_hex",
                &payload.authorization_nonce_hex,
            )?,
            tx_commitment: decode_hex_32_v1(
                "transaction_commitment_hex",
                &payload.transaction_commitment_hex,
            )?,
            public_statement_digest: decode_hex_32_v1(
                "public_statement_digest_hex",
                &payload.public_statement_digest_hex,
            )?,
        };
        result.validate()?;
        Ok(result)
    }
}

impl TokenTransactionAuthorizationEnvelopeV1 {
    pub fn signed(
        payload: TokenTransactionAuthorizationPayloadV1,
        signing_key_bytes: [u8; 32],
    ) -> Result<Self, TokenTransactionErrorV1> {
        payload.validate()?;

        let secret_key = SecretKey::from_bytes(&signing_key_bytes)
            .map_err(|_| TokenTransactionErrorV1::AuthorizationPublicKeyInvalid)?;
        let public_key = PublicKey::from(&secret_key);
        let public_key_bytes = public_key.to_bytes();
        if payload.signer_public_key != public_key_bytes {
            return Err(TokenTransactionErrorV1::AuthorizationSigningKeyMismatch {
                expected: payload.signer_public_key,
                actual: public_key_bytes,
            });
        }

        let keypair = Keypair {
            secret: secret_key,
            public: public_key,
        };
        let signature = keypair.sign(&payload.canonical_bytes()?);

        let envelope = Self {
            envelope_version: TOKEN_TRANSACTION_AUTHORIZATION_ENVELOPE_VERSION_V1,
            scheme: TOKEN_TRANSACTION_AUTHORIZATION_SCHEME_ED25519_V1,
            payload,
            signature: signature.to_bytes(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), TokenTransactionErrorV1> {
        if self.envelope_version != TOKEN_TRANSACTION_AUTHORIZATION_ENVELOPE_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::UnsupportedAuthorizationEnvelopeVersion {
                    expected: TOKEN_TRANSACTION_AUTHORIZATION_ENVELOPE_VERSION_V1,
                    actual: self.envelope_version,
                },
            );
        }
        if self.scheme != TOKEN_TRANSACTION_AUTHORIZATION_SCHEME_ED25519_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedAuthorizationScheme {
                expected: TOKEN_TRANSACTION_AUTHORIZATION_SCHEME_ED25519_V1,
                actual: self.scheme,
            });
        }
        self.payload.validate()?;

        let public_key = PublicKey::from_bytes(&self.payload.signer_public_key)
            .map_err(|_| TokenTransactionErrorV1::AuthorizationPublicKeyInvalid)?;
        let signature = Signature::from_bytes(&self.signature)
            .map_err(|_| TokenTransactionErrorV1::AuthorizationSignatureMalformed)?;
        public_key
            .verify(&self.payload.canonical_bytes()?, &signature)
            .map_err(|_| TokenTransactionErrorV1::AuthorizationSignatureInvalid)?;
        Ok(())
    }

    pub fn validate_against_transaction(
        &self,
        transaction: &DeterministicTransactionV1,
    ) -> Result<(), TokenTransactionErrorV1> {
        self.validate()?;
        self.payload.validate_against_transaction(transaction)?;
        Ok(())
    }

    pub fn to_wire(&self) -> TokenTransactionAuthorizationEnvelopeWireV1 {
        TokenTransactionAuthorizationEnvelopeWireV1 {
            envelope_version: self.envelope_version,
            scheme: self.scheme,
            payload: self.payload.to_wire(),
            signature_hex: encode_hex_lower_v1(&self.signature),
        }
    }

    pub fn from_wire(
        payload: TokenTransactionAuthorizationEnvelopeWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let result = Self {
            envelope_version: payload.envelope_version,
            scheme: payload.scheme,
            payload: TokenTransactionAuthorizationPayloadV1::from_wire(payload.payload)?,
            signature: decode_hex_64_v1("signature_hex", &payload.signature_hex)?,
        };
        result.validate()?;
        Ok(result)
    }
}

impl TokenTransactionAuthorizedProofBindingV1 {
    pub fn from_transaction(
        transaction: &DeterministicTransactionV1,
        authorization_envelope: TokenTransactionAuthorizationEnvelopeV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        authorization_envelope.validate_against_transaction(transaction)?;
        let proof_binding = build_token_transaction_proof_binding_v1(
            transaction.proof_placeholder.public_statement.clone(),
        )?;

        Ok(Self {
            authorization_envelope,
            proof_binding,
        })
    }
}

pub(crate) fn encode_token_transaction_authorization_payload_bytes_v1(
    payload: &TokenTransactionAuthorizationPayloadV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AURA_TOKEN_AUTHORIZATION_PAYLOAD_DOMAIN_SEPARATOR_V1.len()
            + 4
            + 1
            + 4
            + 1
            + 1
            + 1
            + (HASH_LEN_V1 * 4),
    );
    bytes.extend_from_slice(AURA_TOKEN_AUTHORIZATION_PAYLOAD_DOMAIN_SEPARATOR_V1);
    bytes.extend_from_slice(&payload.payload_version.to_le_bytes());
    bytes.push(payload.payload_kind);
    bytes.extend_from_slice(&payload.tx_version.to_le_bytes());
    bytes.push(payload.tx_kind);
    bytes.push(payload.proof_statement_type);
    bytes.push(payload.signer_kind);
    bytes.extend_from_slice(&payload.signer_public_key);
    bytes.extend_from_slice(&payload.authorization_nonce);
    bytes.extend_from_slice(&payload.tx_commitment);
    bytes.extend_from_slice(&payload.public_statement_digest);
    bytes
}

fn decode_hex_64_v1(field: &'static str, input: &str) -> Result<[u8; 64], TokenTransactionErrorV1> {
    if input.len() != 128 {
        return Err(TokenTransactionErrorV1::InvalidHexLength {
            field,
            expected_bytes: 64,
            actual_nibbles: input.len(),
        });
    }

    let mut bytes = [0u8; 64];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble_v1(field, chunk[0])?;
        let low = decode_hex_nibble_v1(field, chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble_v1(field: &'static str, byte: u8) -> Result<u8, TokenTransactionErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TokenTransactionErrorV1::MalformedHex { field }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde::Deserialize;

    use super::{
        build_token_transaction_authorization_payload_v1,
        build_token_transaction_authorization_sign_request_v1,
        build_token_transaction_authorization_sign_response_v1,
        build_token_transaction_authorized_notary_input_v1,
        build_token_transaction_authorized_proof_binding_v1,
        derive_token_transaction_public_statement_digest_v1,
        encode_token_transaction_authorization_payload_bytes_v1,
        reconstruct_token_transaction_authorization_envelope_from_sign_response_v1,
        sign_token_transaction_authorization_payload_v1,
        validate_token_transaction_authorization_envelope_v1,
        validate_token_transaction_authorization_sign_response_v1,
        TokenTransactionAuthorizationEnvelopeV1, TokenTransactionAuthorizationPayloadV1,
    };
    use crate::{
        build_token_transaction_notary_input_v1, build_token_transaction_proof_binding_v1,
        DeterministicTransactionWireV1, PrivateTransferBurnTransactionV1, TokenTransactionErrorV1,
    };

    const AUTH_SIGNING_KEY_BYTES_V1: [u8; 32] = [0x42; 32];
    const AUTHORIZATION_NONCE_V1: [u8; 32] = [0x55; 32];

    #[derive(Debug, Deserialize)]
    struct AuthorizationFixtureFileV1 {
        vectors: Vec<AuthorizationFixtureVectorV1>,
    }

    #[derive(Debug, Deserialize)]
    struct AuthorizationFixtureVectorV1 {
        fixture_name: String,
        transaction: DeterministicTransactionWireV1,
        authorization_payload: super::TokenTransactionAuthorizationPayloadWireV1,
        authorization_payload_bytes_hex: String,
        authorization_envelope: super::TokenTransactionAuthorizationEnvelopeWireV1,
    }

    fn authorization_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/v1/token_transaction_authorization_v1/test_vectors.json")
    }

    fn load_authorization_fixtures() -> AuthorizationFixtureFileV1 {
        serde_json::from_str(&fs::read_to_string(authorization_fixture_path()).unwrap()).unwrap()
    }

    fn load_first_authorization_fixture() -> AuthorizationFixtureVectorV1 {
        let file: AuthorizationFixtureFileV1 =
            serde_json::from_str(&fs::read_to_string(authorization_fixture_path()).unwrap())
                .unwrap();
        file.vectors.into_iter().next().unwrap()
    }

    #[test]
    fn public_statement_digest_alias_matches_existing_proof_binding_digest() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
        let public_statement = transaction.proof_placeholder.public_statement;
        let public_statement_bytes = public_statement.canonical_bytes().unwrap();
        let alias_digest =
            derive_token_transaction_public_statement_digest_v1(&public_statement_bytes);
        let direct =
            crate::derive_token_transaction_proof_binding_digest_v1(&public_statement_bytes);

        assert_eq!(alias_digest, direct);
    }

    #[test]
    fn authorization_payload_and_envelope_are_pinned_to_fixtures() {
        for vector in load_authorization_fixtures().vectors {
            let transaction =
                PrivateTransferBurnTransactionV1::from_wire(vector.transaction.clone()).unwrap();
            let signer_public_key = ed25519_dalek::PublicKey::from(
                &ed25519_dalek::SecretKey::from_bytes(&AUTH_SIGNING_KEY_BYTES_V1).unwrap(),
            )
            .to_bytes();
            let payload = build_token_transaction_authorization_payload_v1(
                &transaction,
                signer_public_key,
                AUTHORIZATION_NONCE_V1,
            )
            .unwrap();
            let envelope = sign_token_transaction_authorization_payload_v1(
                payload.clone(),
                AUTH_SIGNING_KEY_BYTES_V1,
            )
            .unwrap();

            assert_eq!(
                payload.to_wire(),
                vector.authorization_payload,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                crate::encode_hex_lower_v1(
                    &encode_token_transaction_authorization_payload_bytes_v1(&payload,)
                ),
                vector.authorization_payload_bytes_hex,
                "fixture {}",
                vector.fixture_name
            );
            assert_eq!(
                envelope.to_wire(),
                vector.authorization_envelope,
                "fixture {}",
                vector.fixture_name
            );
        }
    }

    #[test]
    fn authorization_envelope_validates_and_binds_into_authorized_proof_binding() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
        let envelope =
            TokenTransactionAuthorizationEnvelopeV1::from_wire(vector.authorization_envelope)
                .unwrap();

        validate_token_transaction_authorization_envelope_v1(&transaction, &envelope).unwrap();
        let authorized =
            build_token_transaction_authorized_proof_binding_v1(&transaction, envelope).unwrap();

        assert_eq!(
            authorized.authorization_envelope.payload.tx_commitment,
            authorized.proof_binding.public_statement.tx_commitment
        );
        assert_eq!(
            authorized
                .authorization_envelope
                .payload
                .public_statement_digest,
            authorized.proof_binding.proof_binding_digest
        );
    }

    #[test]
    fn authorization_sign_request_carries_exact_frozen_payload_bytes() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
        let signer_public_key = ed25519_dalek::PublicKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&AUTH_SIGNING_KEY_BYTES_V1).unwrap(),
        )
        .to_bytes();
        let sign_request = build_token_transaction_authorization_sign_request_v1(
            &transaction,
            signer_public_key,
            AUTHORIZATION_NONCE_V1,
        )
        .unwrap();

        assert_eq!(sign_request.request_version, 1);
        assert_eq!(sign_request.payload, vector.authorization_payload);
        assert_eq!(
            sign_request.payload_bytes_hex,
            vector.authorization_payload_bytes_hex
        );
        sign_request.validate().unwrap();
    }

    #[test]
    fn authorization_sign_response_reconstructs_valid_envelope() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
        let signer_public_key = ed25519_dalek::PublicKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&AUTH_SIGNING_KEY_BYTES_V1).unwrap(),
        )
        .to_bytes();
        let sign_request = build_token_transaction_authorization_sign_request_v1(
            &transaction,
            signer_public_key,
            AUTHORIZATION_NONCE_V1,
        )
        .unwrap();
        let envelope = sign_token_transaction_authorization_payload_v1(
            sign_request.validate().unwrap(),
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap();
        let sign_response =
            build_token_transaction_authorization_sign_response_v1(envelope.clone()).unwrap();

        let validated = validate_token_transaction_authorization_sign_response_v1(
            &sign_request,
            &sign_response,
        )
        .unwrap();
        let reconstructed =
            reconstruct_token_transaction_authorization_envelope_from_sign_response_v1(
                sign_response,
            )
            .unwrap();

        assert_eq!(validated, envelope);
        assert_eq!(reconstructed, envelope);
        validate_token_transaction_authorization_envelope_v1(&transaction, &validated).unwrap();
    }

    #[test]
    fn malformed_signature_or_binding_fails_closed() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
        let signer_public_key = ed25519_dalek::PublicKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&AUTH_SIGNING_KEY_BYTES_V1).unwrap(),
        )
        .to_bytes();
        let payload = build_token_transaction_authorization_payload_v1(
            &transaction,
            signer_public_key,
            AUTHORIZATION_NONCE_V1,
        )
        .unwrap();
        let mut envelope =
            sign_token_transaction_authorization_payload_v1(payload, AUTH_SIGNING_KEY_BYTES_V1)
                .unwrap();
        envelope.signature[0] ^= 0x01;

        let error = validate_token_transaction_authorization_envelope_v1(&transaction, &envelope)
            .unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::AuthorizationSignatureInvalid
        );

        let payload = TokenTransactionAuthorizationPayloadV1::from_transaction(
            &transaction,
            signer_public_key,
            AUTHORIZATION_NONCE_V1,
        )
        .unwrap();
        let mut payload = payload;
        payload.tx_commitment = [0x77; 32];
        let envelope =
            TokenTransactionAuthorizationEnvelopeV1::signed(payload, AUTH_SIGNING_KEY_BYTES_V1)
                .unwrap();

        let error = validate_token_transaction_authorization_envelope_v1(&transaction, &envelope)
            .unwrap_err();
        match error {
            TokenTransactionErrorV1::AuthorizationTransactionCommitmentMismatch { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_authorization_sign_transport_fails_closed() {
        let transaction = PrivateTransferBurnTransactionV1::from_wire(
            load_first_authorization_fixture().transaction,
        )
        .unwrap();
        let signer_public_key = ed25519_dalek::PublicKey::from(
            &ed25519_dalek::SecretKey::from_bytes(&AUTH_SIGNING_KEY_BYTES_V1).unwrap(),
        )
        .to_bytes();
        let sign_request = build_token_transaction_authorization_sign_request_v1(
            &transaction,
            signer_public_key,
            AUTHORIZATION_NONCE_V1,
        )
        .unwrap();

        let mut bad_request = sign_request.clone();
        bad_request.request_version = 9;
        assert_eq!(
            bad_request.validate().unwrap_err(),
            TokenTransactionErrorV1::UnsupportedAuthorizationSignRequestVersion {
                expected: 1,
                actual: 9,
            }
        );

        let mut bad_request = sign_request.clone();
        bad_request.payload_bytes_hex = "00".repeat(32);
        assert_eq!(
            bad_request.validate().unwrap_err(),
            TokenTransactionErrorV1::AuthorizationSignRequestPayloadBytesMismatch
        );

        let envelope = sign_token_transaction_authorization_payload_v1(
            sign_request.validate().unwrap(),
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap();
        let mut bad_response =
            build_token_transaction_authorization_sign_response_v1(envelope.clone()).unwrap();
        bad_response.response_version = 9;
        assert_eq!(
            validate_token_transaction_authorization_sign_response_v1(
                &sign_request,
                &bad_response,
            )
            .unwrap_err(),
            TokenTransactionErrorV1::UnsupportedAuthorizationSignResponseVersion {
                expected: 1,
                actual: 9,
            }
        );

        let mismatched_response = build_token_transaction_authorization_sign_response_v1(
            sign_token_transaction_authorization_payload_v1(
                build_token_transaction_authorization_payload_v1(
                    &transaction,
                    signer_public_key,
                    [0x66; 32],
                )
                .unwrap(),
                AUTH_SIGNING_KEY_BYTES_V1,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            validate_token_transaction_authorization_sign_response_v1(
                &sign_request,
                &mismatched_response,
            )
            .unwrap_err(),
            TokenTransactionErrorV1::AuthorizationSignResponsePayloadMismatch
        );

        let mut malformed_response =
            build_token_transaction_authorization_sign_response_v1(envelope).unwrap();
        malformed_response.envelope.signature_hex = "00".to_owned();
        assert_eq!(
            reconstruct_token_transaction_authorization_envelope_from_sign_response_v1(
                malformed_response,
            )
            .unwrap_err(),
            TokenTransactionErrorV1::InvalidHexLength {
                field: "signature_hex",
                expected_bytes: 64,
                actual_nibbles: 2,
            }
        );
    }

    #[test]
    fn unsupported_authorization_version_or_scheme_fails_closed() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();

        let mut envelope = TokenTransactionAuthorizationEnvelopeV1::from_wire(
            vector.authorization_envelope.clone(),
        )
        .unwrap();
        envelope.envelope_version = 9;
        assert_eq!(
            validate_token_transaction_authorization_envelope_v1(&transaction, &envelope)
                .unwrap_err(),
            TokenTransactionErrorV1::UnsupportedAuthorizationEnvelopeVersion {
                expected: 1,
                actual: 9,
            }
        );

        let mut envelope = TokenTransactionAuthorizationEnvelopeV1::from_wire(
            vector.authorization_envelope.clone(),
        )
        .unwrap();
        envelope.scheme = 9;
        assert_eq!(
            validate_token_transaction_authorization_envelope_v1(&transaction, &envelope)
                .unwrap_err(),
            TokenTransactionErrorV1::UnsupportedAuthorizationScheme {
                expected: 1,
                actual: 9,
            }
        );

        let mut envelope =
            TokenTransactionAuthorizationEnvelopeV1::from_wire(vector.authorization_envelope)
                .unwrap();
        envelope.payload.payload_version = 9;
        assert_eq!(
            validate_token_transaction_authorization_envelope_v1(&transaction, &envelope)
                .unwrap_err(),
            TokenTransactionErrorV1::UnsupportedAuthorizationPayloadVersion {
                expected: 1,
                actual: 9,
            }
        );
    }

    #[test]
    fn authorized_notary_handoff_matches_existing_downstream_path_after_valid_authorization() {
        let vector = load_first_authorization_fixture();
        let transaction = PrivateTransferBurnTransactionV1::from_wire(vector.transaction).unwrap();
        let envelope =
            TokenTransactionAuthorizationEnvelopeV1::from_wire(vector.authorization_envelope)
                .unwrap();

        let authorized_notary_input =
            build_token_transaction_authorized_notary_input_v1(&transaction, envelope).unwrap();
        let direct_notary_input = build_token_transaction_notary_input_v1(
            build_token_transaction_proof_binding_v1(
                transaction.proof_placeholder.public_statement.clone(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(authorized_notary_input, direct_notary_input);
    }

    #[test]
    fn malformed_authorization_wire_fails_closed() {
        let vector = load_first_authorization_fixture();
        let mut wire = vector.authorization_envelope;
        wire.signature_hex = "00".to_owned();

        let error = TokenTransactionAuthorizationEnvelopeV1::from_wire(wire).unwrap_err();
        assert_eq!(
            error,
            TokenTransactionErrorV1::InvalidHexLength {
                field: "signature_hex",
                expected_bytes: 64,
                actual_nibbles: 2,
            }
        );
    }
}
