use std::collections::BTreeSet;

use crate::{sha256_bytes, HASH_LEN_V1};

use super::shared::{decode_hex_32_v1, encode_hex_lower_v1};
use super::{
    BuildDeterministicTransactionRequestV1, BuildDeterministicTransactionResponseV1, BurnSummaryV1,
    DeterministicTransactionPublicStatementWireV1, DeterministicTransactionWireV1,
    PrivateTransferBurnProofPlaceholderV1, PrivateTransferBurnPublicStatementV1,
    PrivateTransferBurnTransactionV1, TokenTransactionErrorV1, TokenTransactionInputV1,
    TokenTransactionInputWireV1, TokenTransactionOutputV1, TokenTransactionOutputWireV1,
    ADMISSION_BURN_FLOOR_V1, AURA_TOKEN_DETERMINISTIC_PUBLIC_STATEMENT_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_DETERMINISTIC_TRANSACTION_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_PRIVATE_TRANSFER_BURN_BODY_DOMAIN_SEPARATOR_V1,
    AURA_TOKEN_PRIVATE_TRANSFER_BURN_COMMITMENT_DOMAIN_SEPARATOR_V1,
    EXACT_PUBLIC_STATEMENT_TYPE_V1, NOTARY_BURN_FLOOR_V1, NOTARY_BURN_INPUT_WEIGHT_V1,
    NOTARY_BURN_OUTPUT_WEIGHT_V1, PRIVATE_TRANSFER_BURN_KIND_V1, TOKEN_TX_VERSION_V1,
};

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

pub fn notary_burn_v1(input_count: u64, output_count: u64) -> Result<u64, TokenTransactionErrorV1> {
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
            output_note_commitments: outputs
                .iter()
                .map(|output| output.note_commitment)
                .collect(),
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
    pub fn from_wire(
        payload: TokenTransactionInputWireV1,
    ) -> Result<Self, TokenTransactionErrorV1> {
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
        let expected_priority_weight = priority_weight_v1(self.admission_burn, self.notary_burn)?;
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

pub(crate) fn encode_private_transfer_burn_body_v1(
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

pub(crate) fn encode_deterministic_transaction_bytes_v1(
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

pub(crate) fn encode_public_statement_bytes_v1(
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
