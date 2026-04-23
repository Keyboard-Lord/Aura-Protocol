use crate::{sha256_bytes, HASH_LEN_V1};

use super::acknowledgement::derive_token_transaction_symbolic_receipt_preimage_v1;
use super::seal_payload::{
    derive_token_transaction_seal_payload_digest_v1, derive_token_transaction_udot_seed_digest_v1,
    encode_token_transaction_seal_payload_bytes_v1,
};
use super::shared::{decode_hex_32_v1, encode_hex_lower_v1};
use super::{
    TokenTransactionErrorV1, TokenTransactionNotarizationRecordV1,
    TokenTransactionNotarizationRecordWireV1, TokenTransactionSealPayloadV1,
    AURA_TOKEN_NOTARIZATION_RECORD_DIGEST_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_NOTARIZATION_RECORD_DOMAIN_SEPARATOR_V1, TOKEN_NOTARIZATION_RECORD_VERSION_V1,
    TOKEN_SEAL_PAYLOAD_VERSION_V1,
};

impl TokenTransactionNotarizationRecordV1 {
    pub fn from_seal_payload(
        seal_payload: TokenTransactionSealPayloadV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_seal = TokenTransactionSealPayloadV1::from_acknowledgement(
            seal_payload.acknowledgement.clone(),
        )?;
        if seal_payload.seal_version != TOKEN_SEAL_PAYLOAD_VERSION_V1 {
            return Err(TokenTransactionErrorV1::UnsupportedSealPayloadVersion {
                expected: TOKEN_SEAL_PAYLOAD_VERSION_V1,
                actual: seal_payload.seal_version,
            });
        }
        if seal_payload.proof_statement_type != rebuilt_seal.proof_statement_type {
            return Err(
                TokenTransactionErrorV1::InvalidSealPayloadProofStatementType {
                    expected: rebuilt_seal.proof_statement_type,
                    actual: seal_payload.proof_statement_type,
                },
            );
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
            return Err(
                TokenTransactionErrorV1::UnsupportedNotarizationRecordVersion {
                    expected: TOKEN_NOTARIZATION_RECORD_VERSION_V1,
                    actual: payload.record_version,
                },
            );
        }

        let ack_digest = decode_hex_32_v1("ack_digest_hex", &payload.ack_digest_hex)?;
        let seal_payload_digest =
            decode_hex_32_v1("seal_payload_digest_hex", &payload.seal_payload_digest_hex)?;
        let udot_seed_digest =
            decode_hex_32_v1("udot_seed_digest_hex", &payload.udot_seed_digest_hex)?;
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
        let symbolic_receipt_preimage =
            derive_token_transaction_symbolic_receipt_preimage_v1(&ack_digest);
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

pub fn build_token_transaction_notarization_record_v1(
    seal_payload: TokenTransactionSealPayloadV1,
) -> Result<TokenTransactionNotarizationRecordV1, TokenTransactionErrorV1> {
    TokenTransactionNotarizationRecordV1::from_seal_payload(seal_payload)
}

pub(crate) fn encode_token_transaction_notarization_record_bytes_v1(
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
