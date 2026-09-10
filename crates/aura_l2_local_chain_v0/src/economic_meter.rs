//! Strict binary owner for the preserved economic meter M.
//!
//! No fixture names, expected results, declared charges or tamper controls enter
//! this type. The explicit legacy adapter below preserves historical encodings.
use super::*;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, LocalChainErrorV1>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeteredAttestationV1 {
    pub attestation_schema_version: u32,
    pub attestation_scope: CanonicalPipelineAttestationScopeV1,
    pub attestation_proof_kind: CanonicalPipelineAttestationProofKindV1,
    pub normalization_policy_version: u32,
    pub attestation_constraints: CanonicalPipelineAttestationConstraintsV1,
    pub claim: CanonicalPipelineAttestationClaimV1,
    pub evidence_items: Vec<CanonicalPipelineAttestationEvidenceItemV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicMeterV1 {
    pub pipeline_schema_version: u32,
    pub pipeline_id: String,
    pub proof_system: ProofSystemSelectionV1,
    pub economic_policy_version: u32,
    pub request_kind: CanonicalPipelineRequestKindV1,
    pub burn_intent: CanonicalPipelineBurnIntentV1,
    pub accounting: CanonicalPipelineAccountingPolicyV1,
    pub ledger: CanonicalPipelineLedgerPolicyV1,
    pub head: CanonicalPipelineSettlementHeadRequestV1,
    pub wallet_binding: CanonicalPipelineWalletBindingV1,
    pub token_anchor: CanonicalPipelineTokenAnchorV1,
    pub attestation: Option<MeteredAttestationV1>,
    pub rollup_id: [u8; 32],
    pub accounts: Vec<LocalAccountV1>,
    pub batch_number: u64,
    pub parent_batch_commitment: [u8; 32],
    pub transactions: Vec<TransferTransactionV1>,
}

fn invalid(message: &str) -> LocalChainErrorV1 {
    LocalChainErrorV1::InvalidFixture(format!("economic meter: {message}"))
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

/// Payer-bound commitment from the existing ledger owner, without report metadata.
pub fn economic_ledger_commitment_v1(ledger: &CanonicalPipelineLedgerPolicyV1) -> Result<[u8; 32]> {
    validate_ledger_policy_fields_v1(ledger)?;
    Ok(canonical_pipeline_ledger_state_commitment_digest_v1(
        ledger.ledger_policy_version,
        ledger.payer_account_id,
        ledger.total_supply,
        ledger.burned_supply,
        &ledger.accounts,
    ))
}

/// Existing ledger commitment preimage, used for durable snapshots. This is not
/// another ledger hash or a JSON projection of economic work.
pub fn economic_ledger_bytes_v1(ledger: &CanonicalPipelineLedgerPolicyV1) -> Result<Vec<u8>> {
    validate_ledger_policy_fields_v1(ledger)?;
    let mut bytes = CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_DOMAIN_SEPARATOR_V1.to_vec();
    extend_canonical_pipeline_ledger_state_bytes_v1(
        &mut bytes,
        ledger.ledger_policy_version,
        ledger.payer_account_id,
        ledger.total_supply,
        ledger.burned_supply,
        &ledger.accounts,
    );
    Ok(bytes)
}

pub fn decode_economic_ledger_v1(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<CanonicalPipelineLedgerPolicyV1> {
    require(bytes.len() <= max_bytes, "ledger byte limit exceeded")?;
    let mut r = Reader { bytes, offset: 0 };
    require(
        r.take(CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_DOMAIN_SEPARATOR_V1.len())?
            == CANONICAL_PIPELINE_LEDGER_STATE_COMMITMENT_DOMAIN_SEPARATOR_V1,
        "wrong ledger domain",
    )?;
    let ledger = r.ledger()?;
    require(r.offset == bytes.len(), "trailing ledger bytes")?;
    require(
        economic_ledger_bytes_v1(&ledger)? == bytes,
        "noncanonical ledger snapshot",
    )?;
    Ok(ledger)
}

/// Pure checked debit. Only the durable coordinator may persist this as a charge.
pub fn debit_economic_ledger_v1(
    ledger: &CanonicalPipelineLedgerPolicyV1,
    burn: u64,
) -> Result<CanonicalPipelineLedgerPolicyV1> {
    validate_ledger_policy_fields_v1(ledger)?;
    let payer = ledger
        .accounts
        .iter()
        .find(|a| a.account_id == ledger.payer_account_id)
        .ok_or_else(|| invalid("payer missing"))?;
    let post = debit_ledger_fields_v1(ledger, payer.balance, burn)?;
    validate_ledger_policy_fields_v1(&post)?;
    Ok(post)
}

impl EconomicMeterV1 {
    /// Decode canonical production M with an explicit operator byte limit.
    /// Counts are bounded against remaining bytes before any allocation.
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self> {
        require(bytes.len() <= max_bytes, "byte limit exceeded")?;
        let mut r = Reader { bytes, offset: 0 };
        require(
            r.take(CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1.len())?
                == CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1,
            "wrong domain",
        )?;
        let result = Self {
            pipeline_schema_version: r.u32()?,
            pipeline_id: r.text()?,
            proof_system: ProofSystemSelectionV1::from_str(&r.text()?)?,
            economic_policy_version: r.u32()?,
            request_kind: CanonicalPipelineRequestKindV1::from_str(&r.text()?)?,
            burn_intent: CanonicalPipelineBurnIntentV1::from_str(&r.text()?)?,
            accounting: CanonicalPipelineAccountingPolicyV1 {
                accounting_policy_version: r.u32()?,
                payment_intent: CanonicalPipelinePaymentIntentV1::from_str(&r.text()?)?,
                settlement_intent: CanonicalPipelineSettlementIntentV1::from_str(&r.text()?)?,
            },
            ledger: r.ledger()?,
            head: CanonicalPipelineSettlementHeadRequestV1 {
                settlement_head_version: r.u32()?,
                previous_head_hash: r.array()?,
                head_sequence_number: r.u64()?,
            },
            wallet_binding: CanonicalPipelineWalletBindingV1 {
                wallet_binding_version: r.u32()?,
                account_id: r.array()?,
                wallet_address: r.text()?,
            },
            token_anchor: r.token_anchor()?,
            attestation: r.optional(Reader::attestation)?,
            rollup_id: r.array()?,
            accounts: r.list(48, |r| {
                Ok(LocalAccountV1 {
                    account_id: r.array()?,
                    balance: r.u64()?,
                    nonce: r.u64()?,
                })
            })?,
            batch_number: r.u64()?,
            parent_batch_commitment: r.array()?,
            transactions: r.list(84, |r| {
                Ok(TransferTransactionV1 {
                    tx_version: r.u32()?,
                    sender_account_id: r.array()?,
                    recipient_account_id: r.array()?,
                    sender_nonce: r.u64()?,
                    amount: r.u64()?,
                })
            })?,
        };
        require(r.offset == bytes.len(), "trailing bytes")?;
        require(result.canonical_bytes()? == bytes, "noncanonical bytes")?;
        Ok(result)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let mut bytes = CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1.to_vec();
        extend_payload(&mut bytes, self, [None, None]);
        Ok(bytes)
    }

    pub fn burn_units(&self) -> Result<u64> {
        let bytes = self.canonical_bytes()?;
        let (items, claim, evidence) = match &self.attestation {
            None => (0, 0, 0),
            Some(a) => (
                a.evidence_items.len() as u64,
                canonical_pipeline_attestation_claim_metered_len_v1(&a.claim)?,
                canonical_pipeline_attestation_evidence_metered_len_v1(&a.evidence_items)?,
            ),
        };
        compute_canonical_pipeline_burn_units_from_inputs_v1(
            &CanonicalPipelineBurnDerivationInputsV1 {
                tx_count: self.transactions.len() as u64,
                metered_request_size_bytes: bytes.len() as u64,
                request_kind: self.request_kind,
                proof_system: self.proof_system,
                attestation_evidence_items: items,
                attestation_claim_bytes: claim,
                attestation_evidence_bytes: evidence,
            },
        )
    }

    /// Structural admission only. Transfer balances/nonces, evidence truth,
    /// normalization and provenance verification belong to chargeable execution.
    pub fn validate_structure(&self) -> Result<()> {
        require(
            self.pipeline_schema_version == CANONICAL_PIPELINE_SCHEMA_VERSION_V1
                && self.pipeline_id == CANONICAL_PIPELINE_ID_V1,
            "unsupported pipeline",
        )?;
        require(
            self.proof_system == ProofSystemSelectionV1::Stark,
            "production requires full verification tariff",
        )?;
        require(
            self.economic_policy_version == CANONICAL_PIPELINE_ECONOMIC_POLICY_VERSION_V1
                && self.accounting.accounting_policy_version
                    == CANONICAL_PIPELINE_ACCOUNTING_POLICY_VERSION_V1,
            "unsupported policy",
        )?;
        validate_ledger_policy_fields_v1(&self.ledger)?;
        require(
            self.head.settlement_head_version == 2 && self.head.head_sequence_number > 0,
            "production requires head V2 linkage with nonzero sequence",
        )?;
        validate_wallet_binding_fields_v1(&self.wallet_binding)?;
        validate_token_anchor_fields_v1(&self.token_anchor)?;
        require(
            self.accounts
                .windows(2)
                .all(|w| w[0].account_id < w[1].account_id),
            "execution accounts must be strictly ordered and unique",
        )?;
        require(
            self.transactions
                .iter()
                .all(|tx| tx.tx_version == TRANSFER_TX_VERSION_V1),
            "unsupported transaction version",
        )?;
        match (&self.request_kind, &self.attestation) {
            (CanonicalPipelineRequestKindV1::Execution, None) => require(
                !self.transactions.is_empty(),
                "execution requires transactions",
            )?,
            (CanonicalPipelineRequestKindV1::Attestation, Some(a)) => {
                require(
                    self.transactions.is_empty(),
                    "attestation forbids transactions",
                )?;
                a.validate_structure()?;
            }
            _ => return Err(invalid("request kind and attestation disagree")),
        }
        Ok(())
    }

    // Called only by the historical fixture writer, never by canonical entry.
    pub(super) fn from_legacy_request(
        r: &CanonicalPipelineRequestV1,
        accounts: &[LocalAccountV1],
    ) -> Self {
        Self {
            pipeline_schema_version: CANONICAL_PIPELINE_SCHEMA_VERSION_V1,
            pipeline_id: r.pipeline_id.clone(),
            proof_system: r.proof_system,
            economic_policy_version: r.economic.economic_policy_version,
            request_kind: r.economic.request_kind,
            burn_intent: r.economic.burn_intent,
            accounting: r.accounting.clone(),
            ledger: r.ledger.clone(),
            head: r.head.clone(),
            wallet_binding: r.wallet_binding.clone(),
            token_anchor: r.token_anchor.clone(),
            attestation: r
                .attestation
                .as_ref()
                .map(MeteredAttestationV1::from_legacy),
            rollup_id: r.rollup_id,
            accounts: accounts.to_vec(),
            batch_number: r.batch_number,
            parent_batch_commitment: r.parent_batch_commitment,
            transactions: r.transactions.clone(),
        }
    }
}

impl MeteredAttestationV1 {
    pub(super) fn from_legacy(a: &CanonicalPipelineAttestationRequestV1) -> Self {
        Self {
            attestation_schema_version: a.attestation_schema_version,
            attestation_scope: a.attestation_scope,
            attestation_proof_kind: a.attestation_proof_kind,
            normalization_policy_version: a.normalization_policy_version,
            attestation_constraints: a.attestation_constraints.clone(),
            claim: a.claim.clone(),
            evidence_items: a.evidence_items.clone(),
        }
    }
    fn validate_structure(&self) -> Result<()> {
        require(
            self.attestation_schema_version == CANONICAL_PIPELINE_ATTESTATION_SCHEMA_VERSION_V2
                && self.normalization_policy_version
                    == CANONICAL_PIPELINE_ATTESTATION_NORMALIZATION_POLICY_VERSION_V1
                && self.attestation_constraints
                    == canonical_pipeline_supported_attestation_constraints_v1(),
            "unsupported attestation policy",
        )?;
        require(
            self.attestation_proof_kind == CanonicalPipelineAttestationProofKindV1::Stark,
            "mock attestation is legacy only",
        )?;
        require(
            !self.evidence_items.is_empty()
                && self.evidence_items.len() as u64
                    <= self.attestation_constraints.max_evidence_items,
            "invalid evidence count",
        )?;
        use CanonicalPipelineAttestationClaimKindV1 as K;
        use CanonicalPipelineAttestationClaimPayloadV1 as P;
        let kind = match &self.claim.claim_payload {
            P::EvidenceRootDigest { .. } => K::EvidenceRootDigest,
            P::NormalizedEvidenceDigest { .. } => K::NormalizedEvidenceDigest,
            P::NormalizedTextContainsUtf8 { .. } => K::NormalizedTextContainsUtf8,
            P::NormalizedJsonFieldEqualsUtf8 { .. } => K::NormalizedJsonFieldEqualsUtf8,
        };
        require(kind == self.claim.claim_kind, "claim kind/payload mismatch")?;
        let mut labels = BTreeSet::new();
        for item in &self.evidence_items {
            require(
                !item.label.trim().is_empty() && labels.insert(&item.label),
                "empty or duplicate evidence label",
            )?;
            let p = &item.provenance;
            require(
                p.provenance_policy_version == CANONICAL_PIPELINE_PROVENANCE_POLICY_VERSION_V1
                    && !p.source_type.trim().is_empty()
                    && !p.source_identifier.trim().is_empty(),
                "invalid provenance structure",
            )?;
            require(
                p.provenance_type != CanonicalPipelineEvidenceProvenanceTypeV1::SignedBlob
                    || p.signature.is_some(),
                "signed blob requires signature",
            )?;
            use CanonicalPipelineAttestationEvidenceKindV1 as E;
            use CanonicalPipelineAttestationEvidencePayloadV1 as V;
            require(
                matches!(
                    (&item.evidence_kind, &item.evidence_payload),
                    (E::InlineUtf8, V::InlineUtf8 { .. })
                        | (E::InlineJsonUtf8, V::InlineJsonUtf8 { .. })
                ),
                "evidence kind/payload mismatch",
            )?;
        }
        Ok(())
    }
}

impl EconomicMeterV1 {
    /// Chargeable local work, using the existing transfer and attestation owners.
    /// Success here is neither Storm verification nor proof authorization.
    pub fn execute_local_work(&self) -> Result<TransitionEnvelopeV1> {
        self.validate_structure()?;
        if let Some(a) = &self.attestation {
            let prepared = prepare_metered_attestation_v1(a)?;
            if let Some((_, reason)) =
                canonical_pipeline_pre_execution_rejection_reason_v1(Some(&prepared))
            {
                return Err(invalid(&reason));
            }
        }
        let state = LocalStateV1::new(self.accounts.clone())?;
        let executed = execute_transfer_batch_v1(
            &state,
            &LocalExecutionConfigV1::new(self.rollup_id),
            &BatchExecutionRequestV1 {
                batch_number: self.batch_number,
                parent_batch_commitment: self.parent_batch_commitment,
                transactions: self.transactions.clone(),
            },
        )?;
        Ok(TransitionEnvelopeV1::from_executed_batch(&executed))
    }

    /// Evaluate only after successful proof/material verification. Bitcoin
    /// publication availability and confirmations are not local settlement inputs.
    pub fn settlement_rejection(&self, executed: &TransitionEnvelopeV1) -> Option<String> {
        let state = match LocalStateV1::new(self.accounts.clone()) {
            Ok(state) => state,
            Err(e) => return Some(e.to_string()),
        };
        let settlement = LocalSettlementStateV1::new(self.rollup_id, state.state_root());
        if let Err(e) =
            aura_l2_local_settlement_v1::validate_transition_context_v1(&settlement, executed)
        {
            return Some(e.to_string());
        }
        if self.wallet_binding.account_id != self.ledger.payer_account_id {
            return Some("wallet binding account does not match economic payer".into());
        }
        if token_anchor_status_v1(&self.token_anchor)
            == CanonicalPipelineExternalAnchorVerificationStatusV1::Rejected
        {
            return Some(canonical_pipeline_external_anchor_rejection_detail_v1());
        }
        None
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn ledger(&mut self) -> Result<CanonicalPipelineLedgerPolicyV1> {
        Ok(CanonicalPipelineLedgerPolicyV1 {
            ledger_policy_version: self.u32()?,
            payer_account_id: self.array()?,
            total_supply: self.u64()?,
            burned_supply: self.u64()?,
            accounts: self.list(40, |r| {
                Ok(CanonicalPipelineLedgerAccountV1 {
                    account_id: r.array()?,
                    balance: r.u64()?,
                })
            })?,
        })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| invalid("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated input"))?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn flag(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("noncanonical flag")),
        }
    }
    fn count(&mut self, minimum_size: usize) -> Result<usize> {
        let n = usize::try_from(self.u64()?).map_err(|_| invalid("length overflow"))?;
        require(
            n <= (self.bytes.len() - self.offset) / minimum_size,
            "count exceeds remaining input",
        )?;
        Ok(n)
    }
    fn text(&mut self) -> Result<String> {
        let n = self.count(1)?;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| invalid("invalid UTF-8"))
    }
    fn optional<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<Option<T>> {
        if self.flag()? {
            Ok(Some(f(self)?))
        } else {
            Ok(None)
        }
    }
    fn list<T>(
        &mut self,
        minimum_size: usize,
        mut f: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        let n = self.count(minimum_size)?;
        (0..n).map(|_| f(self)).collect()
    }
    fn token_anchor(&mut self) -> Result<CanonicalPipelineTokenAnchorV1> {
        Ok(CanonicalPipelineTokenAnchorV1 {
            token_policy_version: self.u32()?,
            network_mode: CanonicalPipelineNetworkModeV1::from_str(&self.text()?)?,
            settlement_anchor_type: CanonicalPipelineSettlementAnchorTypeV1::from_str(
                &self.text()?,
            )?,
            external_balance_reference: self.optional(|r| {
                Ok(CanonicalPipelineExternalBalanceReferenceV1 {
                    reference_id: r.text()?,
                    observed_balance: r.optional(Self::u64)?,
                    observed_slot: r.optional(Self::u64)?,
                    connected: r.flag()?,
                })
            })?,
            enforce_external_match: self.flag()?,
            expected_external_balance: self.optional(Self::u64)?,
        })
    }
    fn claim(&mut self) -> Result<CanonicalPipelineAttestationClaimV1> {
        use CanonicalPipelineAttestationClaimKindV1 as K;
        use CanonicalPipelineAttestationClaimPayloadV1 as P;
        let claim_kind = K::from_str(&self.text()?)?;
        let claim_payload = match claim_kind {
            K::EvidenceRootDigest => P::EvidenceRootDigest {
                expected_evidence_root_digest: self.array()?,
            },
            K::NormalizedEvidenceDigest => P::NormalizedEvidenceDigest {
                target_label: self.text()?,
                expected_evidence_digest: self.array()?,
            },
            K::NormalizedTextContainsUtf8 => P::NormalizedTextContainsUtf8 {
                target_label: self.text()?,
                expected_substring_utf8: self.text()?,
            },
            K::NormalizedJsonFieldEqualsUtf8 => P::NormalizedJsonFieldEqualsUtf8 {
                target_label: self.text()?,
                field_path: self.list(8, Self::text)?,
                expected_value_utf8: self.text()?,
            },
        };
        Ok(CanonicalPipelineAttestationClaimV1 {
            claim_kind,
            claim_payload,
        })
    }
    fn evidence(&mut self) -> Result<CanonicalPipelineAttestationEvidenceItemV1> {
        let label = self.text()?;
        let evidence_kind = CanonicalPipelineAttestationEvidenceKindV1::from_str(&self.text()?)?;
        let payload_utf8 = self.text()?;
        let evidence_payload = match evidence_kind {
            CanonicalPipelineAttestationEvidenceKindV1::InlineUtf8 => {
                CanonicalPipelineAttestationEvidencePayloadV1::InlineUtf8 { payload_utf8 }
            }
            CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8 => {
                CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 { payload_utf8 }
            }
        };
        let provenance = CanonicalPipelineEvidenceProvenanceV1 {
            provenance_policy_version: self.u32()?,
            provenance_type: CanonicalPipelineEvidenceProvenanceTypeV1::from_str(&self.text()?)?,
            source_type: self.text()?,
            source_identifier: self.text()?,
            signature: self.optional(|r| {
                Ok(CanonicalPipelineEvidenceSignatureV1 {
                    signer_public_key: r.array()?,
                    signature: r.array()?,
                })
            })?,
            timestamp_unix_seconds: self.optional(Self::u64)?,
        };
        Ok(CanonicalPipelineAttestationEvidenceItemV1 {
            label,
            evidence_kind,
            evidence_payload,
            provenance,
        })
    }
    fn attestation(&mut self) -> Result<MeteredAttestationV1> {
        let a = MeteredAttestationV1 {
            attestation_schema_version: self.u32()?,
            attestation_scope: CanonicalPipelineAttestationScopeV1::from_str(&self.text()?)?,
            attestation_proof_kind: CanonicalPipelineAttestationProofKindV1::from_str(
                &self.text()?,
            )?,
            normalization_policy_version: self.u32()?,
            attestation_constraints: CanonicalPipelineAttestationConstraintsV1 {
                require_unique_labels: self.flag()?,
                max_evidence_items: self.u64()?,
                max_total_normalized_bytes: self.u64()?,
            },
            claim: self.claim()?,
            evidence_items: self.list(54, Self::evidence)?,
        };
        // Preserve the two historical None tags, but expose no tamper controls.
        require(
            !self.flag()? && !self.flag()?,
            "legacy tamper controls forbidden",
        )?;
        Ok(a)
    }
}
pub(super) fn extend_payload(
    bytes: &mut Vec<u8>,
    request: &EconomicMeterV1,
    legacy_tamper: [Option<&ByteTamperFixtureV1>; 2],
) {
    bytes.extend_from_slice(&request.pipeline_schema_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.pipeline_id.as_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.proof_system.as_fixture_str().as_bytes());
    bytes.extend_from_slice(&request.economic_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.request_kind.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.burn_intent.as_str().as_bytes());
    bytes.extend_from_slice(&request.accounting.accounting_policy_version.to_le_bytes());
    extend_len_prefixed_bytes_v1(bytes, request.accounting.payment_intent.as_str().as_bytes());
    extend_len_prefixed_bytes_v1(
        bytes,
        request.accounting.settlement_intent.as_str().as_bytes(),
    );
    bytes.extend_from_slice(&request.ledger.ledger_policy_version.to_le_bytes());
    bytes.extend_from_slice(&request.ledger.payer_account_id);
    bytes.extend_from_slice(&request.ledger.total_supply.to_le_bytes());
    bytes.extend_from_slice(&request.ledger.burned_supply.to_le_bytes());
    extend_canonical_pipeline_ledger_accounts_bytes_v1(bytes, &request.ledger.accounts);
    extend_canonical_pipeline_head_bytes_v1(bytes, &request.head);
    extend_canonical_pipeline_wallet_binding_bytes_v1(bytes, &request.wallet_binding);
    extend_canonical_pipeline_token_anchor_bytes_v1(bytes, &request.token_anchor);
    extend_attestation(bytes, request.attestation.as_ref(), legacy_tamper);
    bytes.extend_from_slice(&request.rollup_id);
    extend_canonical_pipeline_genesis_accounts_bytes_v1(bytes, &request.accounts);
    bytes.extend_from_slice(&request.batch_number.to_le_bytes());
    bytes.extend_from_slice(&request.parent_batch_commitment);
    extend_canonical_pipeline_transactions_bytes_v1(bytes, &request.transactions);
}

fn extend_attestation(
    bytes: &mut Vec<u8>,
    attestation: Option<&MeteredAttestationV1>,
    legacy_tamper: [Option<&ByteTamperFixtureV1>; 2],
) {
    match attestation {
        Some(attestation) => {
            bytes.push(1);
            bytes.extend_from_slice(&attestation.attestation_schema_version.to_le_bytes());
            extend_len_prefixed_bytes_v1(bytes, attestation.attestation_scope.as_str().as_bytes());
            extend_len_prefixed_bytes_v1(
                bytes,
                attestation
                    .attestation_proof_kind
                    .as_fixture_str()
                    .as_bytes(),
            );
            bytes.extend_from_slice(&attestation.normalization_policy_version.to_le_bytes());
            bytes.push(u8::from(
                attestation.attestation_constraints.require_unique_labels,
            ));
            bytes.extend_from_slice(
                &attestation
                    .attestation_constraints
                    .max_evidence_items
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(
                &attestation
                    .attestation_constraints
                    .max_total_normalized_bytes
                    .to_le_bytes(),
            );
            extend_canonical_pipeline_attestation_claim_bytes_v1(bytes, &attestation.claim);
            bytes.extend_from_slice(
                &u64::try_from(attestation.evidence_items.len())
                    .expect("attestation evidence count fits in u64")
                    .to_le_bytes(),
            );
            for item in &attestation.evidence_items {
                extend_canonical_pipeline_attestation_evidence_item_bytes_v1(bytes, item);
            }
            extend_optional_tamper_bytes_v1(bytes, legacy_tamper[0]);
            extend_optional_tamper_bytes_v1(bytes, legacy_tamper[1]);
        }
        None => bytes.push(0),
    }
}
