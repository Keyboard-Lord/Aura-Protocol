use crate::{sha256_bytes, HASH_LEN_V1};

use super::{
    TokenTransactionErrorV1, TokenTransactionNotaryAcknowledgementV1,
    TokenTransactionSealPayloadV1, AURA_TOKEN_SEAL_PAYLOAD_DIGEST_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_SEAL_PAYLOAD_DOMAIN_SEPARATOR_V1, AURA_TOKEN_UDOT_SEED_DOMAIN_SEPARATOR_V1,
    TOKEN_NOTARY_ACK_VERSION_V1, TOKEN_SEAL_PAYLOAD_VERSION_V1,
};

impl TokenTransactionSealPayloadV1 {
    pub fn from_acknowledgement(
        acknowledgement: TokenTransactionNotaryAcknowledgementV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
        let rebuilt_ack =
            TokenTransactionNotaryAcknowledgementV1::from_receipt(acknowledgement.receipt.clone())?;
        if acknowledgement.ack_version != TOKEN_NOTARY_ACK_VERSION_V1 {
            return Err(
                TokenTransactionErrorV1::UnsupportedNotaryAcknowledgementVersion {
                    expected: TOKEN_NOTARY_ACK_VERSION_V1,
                    actual: acknowledgement.ack_version,
                },
            );
        }
        if acknowledgement.proof_statement_type != rebuilt_ack.proof_statement_type {
            return Err(
                TokenTransactionErrorV1::InvalidAcknowledgementProofStatementType {
                    expected: rebuilt_ack.proof_statement_type,
                    actual: acknowledgement.proof_statement_type,
                },
            );
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

pub fn build_token_transaction_seal_payload_v1(
    acknowledgement: TokenTransactionNotaryAcknowledgementV1,
) -> Result<TokenTransactionSealPayloadV1, TokenTransactionErrorV1> {
    TokenTransactionSealPayloadV1::from_acknowledgement(acknowledgement)
}

pub(crate) fn encode_token_transaction_seal_payload_bytes_v1(
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
    let mut preimage = Vec::with_capacity(
        AURA_TOKEN_UDOT_SEED_DOMAIN_SEPARATOR_V1.len() + seal_payload_digest.len(),
    );
    preimage.extend_from_slice(AURA_TOKEN_UDOT_SEED_DOMAIN_SEPARATOR_V1);
    preimage.extend_from_slice(seal_payload_digest);
    sha256_bytes(&preimage)
}
