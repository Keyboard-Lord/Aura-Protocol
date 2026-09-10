//! Durable economic admission and service-owned finalization. All mutations to
//! charge, head, authorization and publication intent use one SQLite owner.
use super::{
    head::{EconomicHeadV2, EconomicOutcomeV1},
    *,
};
use crate::authorization::{
    reserve_in_transaction, verify_bound_proof, AuthorizationNonceConflictV2, AuthorizerJournalV2,
};
use aura_bitcoin_v1::BitcoinAnchorRequestV1;
use aura_intent_lineage_v1::{
    build_storm_air_public_inputs_v1, build_storm_claim_v1, prove_storm_air_real_v1,
};
use aura_l2_local_chain_v0::{
    economic_meter::{
        debit_economic_ledger_v1, decode_economic_ledger_v1, economic_ledger_bytes_v1,
    },
    CanonicalPipelineLedgerPolicyV1, CanonicalPipelineSettlementHeadRequestV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

/// Trusted migration input, never a successor admission object or relabeled V2 head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyHeadCheckpointV1 {
    pub settlement_head_version: u32,
    pub head_sequence_number: u64,
    pub current_head_hash_hex: String,
}

/// Internal journal representation also exposes an explicit migration checkpoint
/// to operators until its first V2 successor is finalized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "head", deny_unknown_fields)]
pub enum EconomicPriorHeadV1 {
    Current(EconomicHeadV2),
    LegacyV1(LegacyHeadCheckpointV1),
}
impl EconomicPriorHeadV1 {
    fn checkpoint(&self) -> AuthorizationResultV2<(u64, [u8; 32])> {
        match self {
            Self::Current(h) => Ok((h.validate()?, decode_hex_v2(&h.current_head_hash_hex)?)),
            Self::LegacyV1(h) => {
                if h.settlement_head_version != 1 {
                    return Err("migration requires explicit V1 predecessor".into());
                }
                Ok((
                    h.head_sequence_number,
                    decode_hex_v2(&h.current_head_hash_hex)?,
                ))
            }
        }
    }
    pub fn next_linkage(&self) -> AuthorizationResultV2<CanonicalPipelineSettlementHeadRequestV1> {
        let (n, hash) = self.checkpoint()?;
        Ok(CanonicalPipelineSettlementHeadRequestV1 {
            settlement_head_version: 2,
            previous_head_hash: hash,
            head_sequence_number: n.checked_add(1).ok_or("economic head sequence overflow")?,
        })
    }
    fn advance(
        &self,
        network: BitcoinNetworkV1,
        work: &EconomicWorkV1,
        outcome: EconomicOutcomeV1,
        post: &CanonicalPipelineLedgerPolicyV1,
    ) -> AuthorizationResultV2<EconomicHeadV2> {
        let (n, hash) = self.checkpoint()?;
        EconomicHeadV2::from_predecessor(n, hash, network, work, outcome, post)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicReceiptV1 {
    pub attempt_id: i64,
    pub outcome: EconomicOutcomeV1,
    pub burn_units: u64,
    pub head: EconomicHeadV2,
    pub detail: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EconomicAttemptStateV1 {
    Admitted { attempt_id: i64 },
    Terminal(EconomicReceiptV1),
}
impl EconomicAttemptStateV1 {
    pub fn attempt_id(&self) -> i64 {
        match self {
            Self::Admitted { attempt_id } => *attempt_id,
            Self::Terminal(r) => r.attempt_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EconomicOutboxEntryV1 {
    pub attempt_id: i64,
    pub request: BitcoinAnchorRequestV1,
    pub last_publication_txid: Option<String>,
}

struct State {
    ledger: CanonicalPipelineLedgerPolicyV1,
    prior: EconomicPriorHeadV1,
    active: Option<i64>,
}
struct Attempt {
    id: i64,
    work_bytes: Vec<u8>,
    work: EconomicWorkV1,
    consent: EconomicConsentV1,
    auth: AuthorizationEnvelopeV2,
    burn: u64,
    post: CanonicalPipelineLedgerPolicyV1,
    prior: EconomicPriorHeadV1,
    terminal: Option<EconomicReceiptV1>,
}

/// No replacement proof or failure-result argument exists. A service can resume
/// persisted work by id; only its own verification path can produce a receipt.
pub struct EconomicJournalV1 {
    authorizer: AuthorizerJournalV2,
    network: BitcoinNetworkV1,
    limits: EconomicLimitsV1,
}

impl EconomicJournalV1 {
    pub fn create(
        path: &Path,
        network: BitcoinNetworkV1,
        ledger: &CanonicalPipelineLedgerPolicyV1,
        limits: EconomicLimitsV1,
    ) -> AuthorizationResultV2<Self> {
        let authorizer = AuthorizerJournalV2::create(path)?;
        authorizer
            .connection
            .execute_batch("PRAGMA foreign_keys=ON;")?;
        let mut journal = Self {
            authorizer,
            network,
            limits,
        };
        journal.initialize(
            ledger,
            EconomicPriorHeadV1::Current(EconomicHeadV2::genesis()),
        )?;
        journal.audit_state()?;
        Ok(journal)
    }

    /// Extend the existing authorizer database in place, preserving its complete
    /// authorization table. Matching checkpoint/ledger provenance is an explicit
    /// operator responsibility, not something inferred from a supplied hash.
    pub fn migrate_v1(
        path: &Path,
        network: BitcoinNetworkV1,
        ledger: &CanonicalPipelineLedgerPolicyV1,
        checkpoint: LegacyHeadCheckpointV1,
        limits: EconomicLimitsV1,
    ) -> AuthorizationResultV2<Self> {
        let authorizer = AuthorizerJournalV2::open(path)?;
        authorizer
            .connection
            .execute_batch("PRAGMA foreign_keys=ON;")?;
        let mut journal = Self {
            authorizer,
            network,
            limits,
        };
        journal.initialize(ledger, EconomicPriorHeadV1::LegacyV1(checkpoint))?;
        journal.audit_state()?;
        Ok(journal)
    }

    fn initialize(
        &mut self,
        ledger: &CanonicalPipelineLedgerPolicyV1,
        prior: EconomicPriorHeadV1,
    ) -> AuthorizationResultV2<()> {
        prior.checkpoint()?;
        let ledger_bytes = economic_ledger_bytes_v1(ledger)?;
        if ledger_bytes.len() > self.limits.max_meter_bytes {
            return Err("initial ledger exceeds operator byte limit".into());
        }
        let head = serde_json::to_string(&prior)?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Deliberately no IF NOT EXISTS: a second initialization must fail.
        tx.execute_batch("CREATE TABLE economic_attempts (
            id INTEGER PRIMARY KEY, network INTEGER NOT NULL, subject TEXT NOT NULL, nonce TEXT NOT NULL,
            work BLOB NOT NULL, consent TEXT NOT NULL, authorization TEXT NOT NULL, burn TEXT NOT NULL,
            pre_ledger BLOB NOT NULL, post_ledger BLOB NOT NULL, prior TEXT NOT NULL,
            outcome INTEGER CHECK(outcome BETWEEN 0 AND 3), head TEXT, detail TEXT NOT NULL,
            UNIQUE(network,subject,nonce), CHECK((outcome IS NULL) = (head IS NULL)));
          CREATE TABLE economic_state (
            id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1), network INTEGER NOT NULL,
            ledger BLOB NOT NULL, prior TEXT NOT NULL, active INTEGER REFERENCES economic_attempts(id),
            initial_ledger BLOB NOT NULL, initial_prior TEXT NOT NULL);
          CREATE TABLE economic_outbox (
            attempt_id INTEGER PRIMARY KEY REFERENCES economic_attempts(id), request TEXT NOT NULL, txid TEXT);")?;
        tx.execute(
            "INSERT INTO economic_state VALUES(1,1,?1,?2,?3,NULL,?2,?3)",
            params![self.network.tag(), ledger_bytes, head],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn open(
        path: &Path,
        network: BitcoinNetworkV1,
        limits: EconomicLimitsV1,
    ) -> AuthorizationResultV2<Self> {
        let authorizer = AuthorizerJournalV2::open(path)?;
        authorizer
            .connection
            .execute_batch("PRAGMA foreign_keys=ON;")?;
        let journal = Self {
            authorizer,
            network,
            limits,
        };
        journal.audit_state()?;
        Ok(journal)
    }

    /// A payer-bound view of the same coordinated balances. Payer selection must
    /// identify an existing account; it does not change balances or supply.
    pub fn ledger_for_payer(
        &self,
        payer: [u8; 32],
    ) -> AuthorizationResultV2<CanonicalPipelineLedgerPolicyV1> {
        let mut ledger = Self::state(&self.authorizer.connection, self.network)?.ledger;
        ledger.payer_account_id = payer;
        economic_ledger_bytes_v1(&ledger)?;
        Ok(ledger)
    }
    pub fn prior_head(&self) -> AuthorizationResultV2<EconomicPriorHeadV1> {
        Ok(Self::state(&self.authorizer.connection, self.network)?.prior)
    }

    pub fn admit(
        &mut self,
        bytes: &[u8],
        consent: &EconomicConsentV1,
        auth: &AuthorizationEnvelopeV2,
    ) -> AuthorizationResultV2<EconomicAttemptStateV1> {
        let work = EconomicWorkV1::decode(bytes, self.limits)?;
        consent.verify_admission_signatures(self.network, &work, auth)?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let l = &auth.authorization_lineage;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM economic_attempts WHERE network=?1 AND subject=?2 AND nonce=?3",
                params![self.network.tag(), l.subject_binding, l.freshness_binding],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            let a = Self::attempt(&tx, self.network, id)?;
            if a.work_bytes != bytes || a.auth.proof_hash_hex != auth.proof_hash_hex {
                return Err("economic nonce conflicts with different work or target".into());
            }
            return Ok(match a.terminal {
                Some(r) => EconomicAttemptStateV1::Terminal(r),
                None => EconomicAttemptStateV1::Admitted { attempt_id: id },
            });
        }
        let state = Self::state(&tx, self.network)?;
        if state.active.is_some() {
            return Err("economic ledger busy; no charge".into());
        }
        let mut current = state.ledger;
        current.payer_account_id = work.subject();
        if current != work.meter.ledger || state.prior.next_linkage()? != work.meter.head {
            return Err("stale economic ledger or head; no charge".into());
        }
        let burn = work.burn_units()?;
        let post = debit_economic_ledger_v1(&current, burn)?;
        let pre_bytes = economic_ledger_bytes_v1(&current)?;
        let post_bytes = economic_ledger_bytes_v1(&post)?;
        tx.execute("INSERT INTO economic_attempts(network,subject,nonce,work,consent,authorization,burn,pre_ledger,post_ledger,prior,outcome,head,detail)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,'')",
            params![self.network.tag(), l.subject_binding, l.freshness_binding, bytes,
                serde_json::to_string(consent)?, serde_json::to_string(auth)?, burn.to_string(), pre_bytes, post_bytes, serde_json::to_string(&state.prior)?])?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE economic_state SET ledger=?1,active=?2 WHERE id=1",
            params![post_bytes, id],
        )?;
        tx.commit()?;
        Ok(EconomicAttemptStateV1::Admitted { attempt_id: id })
    }

    pub fn submit(
        &mut self,
        bytes: &[u8],
        consent: &EconomicConsentV1,
        auth: &AuthorizationEnvelopeV2,
    ) -> AuthorizationResultV2<EconomicReceiptV1> {
        match self.admit(bytes, consent, auth)? {
            EconomicAttemptStateV1::Terminal(r) => Ok(r),
            EconomicAttemptStateV1::Admitted { attempt_id } => self.resume(attempt_id),
        }
    }

    pub fn resume(&mut self, id: i64) -> AuthorizationResultV2<EconomicReceiptV1> {
        let attempt = Self::attempt(&self.authorizer.connection, self.network, id)?;
        if let Some(receipt) = attempt.terminal {
            return Ok(receipt);
        }
        // Changed operator limits may defer pending computation, never refund or
        // manufacture a terminal outcome. Persisted work/signatures are immutable.
        EconomicWorkV1::decode(&attempt.work_bytes, self.limits)?;
        let (outcome, detail) = match attempt.work.meter.execute_local_work() {
            Err(e) => (EconomicOutcomeV1::ExecutionRejected, e.to_string()),
            Ok(executed) => {
                // Existing fixed V1 compatibility commitment slots use the same
                // zero values as the active Storm proof preparation vectors.
                let claim = build_storm_claim_v1(&attempt.work.storm, [0; 32], [0; 32]);
                let inputs = build_storm_air_public_inputs_v1(&claim);
                let verified = prove_storm_air_real_v1(&claim, &inputs)
                    .map_err(|e| e.to_string())
                    .and_then(|proof| {
                        attempt
                            .auth
                            .verify_signature(self.network)
                            .map_err(|e| e.to_string())?;
                        verify_bound_proof(
                            &attempt.auth,
                            &claim,
                            &proof,
                            self.limits.max_iterations,
                        )
                        .map_err(|e| e.to_string())
                    });
                match verified {
                    Err(e) => (EconomicOutcomeV1::VerificationRejected, e),
                    Ok(()) => match attempt.work.meter.settlement_rejection(&executed) {
                        Some(e) => (EconomicOutcomeV1::SettlementRejected, e),
                        None => (EconomicOutcomeV1::Accepted, String::new()),
                    },
                }
            }
        };
        self.finalize(attempt, outcome, detail)
    }

    fn finalize(
        &mut self,
        attempt: Attempt,
        mut outcome: EconomicOutcomeV1,
        mut detail: String,
    ) -> AuthorizationResultV2<EconomicReceiptV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_attempt = Self::attempt(&tx, self.network, attempt.id)?;
        if let Some(receipt) = current_attempt.terminal {
            return Ok(receipt);
        }
        let state = Self::state(&tx, self.network)?;
        if current_attempt.work_bytes != attempt.work_bytes
            || current_attempt.auth != attempt.auth
            || current_attempt.consent != attempt.consent
            || state.active != Some(attempt.id)
            || state.prior != attempt.prior
            || state.ledger != attempt.post
        {
            return Err("economic finalization ownership or predecessor mismatch".into());
        }
        if outcome == EconomicOutcomeV1::Accepted {
            match reserve_in_transaction(&tx, self.network, &attempt.auth) {
                Ok(_) => (),
                Err(e) if e.is::<AuthorizationNonceConflictV2>() => {
                    outcome = EconomicOutcomeV1::VerificationRejected;
                    detail = e.to_string();
                }
                Err(e) => return Err(e), // Storage failure leaves the admitted job pending.
            }
        }
        let head = attempt
            .prior
            .advance(self.network, &attempt.work, outcome, &attempt.post)?;
        if outcome == EconomicOutcomeV1::Accepted {
            let request =
                BitcoinAnchorRequestV1::new(self.network, attempt.auth.proof_hash_hex.clone())?;
            tx.execute(
                "INSERT INTO economic_outbox(attempt_id,request,txid) VALUES(?1,?2,NULL)",
                params![attempt.id, serde_json::to_string(&request)?],
            )?;
        }
        tx.execute("UPDATE economic_attempts SET outcome=?1,head=?2,detail=?3 WHERE id=?4 AND outcome IS NULL",
            params![outcome as u8, serde_json::to_string(&head)?, detail, attempt.id])?;
        tx.execute(
            "UPDATE economic_state SET prior=?1,active=NULL WHERE id=1",
            params![serde_json::to_string(&EconomicPriorHeadV1::Current(
                head.clone()
            ))?],
        )?;
        tx.commit()?;
        Ok(EconomicReceiptV1 {
            attempt_id: attempt.id,
            outcome,
            burn_units: attempt.burn,
            head,
            detail,
        })
    }

    pub fn pending_attempt(&self) -> AuthorizationResultV2<Option<i64>> {
        Ok(Self::state(&self.authorizer.connection, self.network)?.active)
    }

    pub fn outbox(&self) -> AuthorizationResultV2<Vec<EconomicOutboxEntryV1>> {
        let c = &self.authorizer.connection;
        let mut stmt =
            c.prepare("SELECT attempt_id,request,txid FROM economic_outbox ORDER BY attempt_id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (id, wire, txid) = row?;
            let a = Self::attempt(c, self.network, id)?;
            if a.terminal.as_ref().map(|r| r.outcome) != Some(EconomicOutcomeV1::Accepted) {
                return Err("outbox references unaccepted economic work".into());
            }
            let request: BitcoinAnchorRequestV1 = serde_json::from_str(&wire)?;
            if request != BitcoinAnchorRequestV1::new(self.network, a.auth.proof_hash_hex)? {
                return Err("outbox request mismatch".into());
            }
            if let Some(txid) = &txid {
                decode_hex_v2::<32>(txid)?;
            }
            entries.push(EconomicOutboxEntryV1 {
                attempt_id: id,
                request,
                last_publication_txid: txid,
            });
        }
        Ok(entries)
    }

    /// Publication observation only. Retain the outbox and all economic/auth
    /// history even if the transaction later disappears in a reorganization.
    pub fn record_publication(&mut self, id: i64, txid: &str) -> AuthorizationResultV2<()> {
        decode_hex_v2::<32>(txid)?;
        let attempt = Self::attempt(&self.authorizer.connection, self.network, id)?;
        if attempt.terminal.as_ref().map(|r| r.outcome) != Some(EconomicOutcomeV1::Accepted) {
            return Err("publication requires an accepted attempt".into());
        }
        if self.authorizer.connection.execute(
            "UPDATE economic_outbox SET txid=?1 WHERE attempt_id=?2",
            params![txid, id],
        )? != 1
        {
            return Err("publication requires an accepted outbox entry".into());
        }
        Ok(())
    }

    fn state(c: &Connection, network: BitcoinNetworkV1) -> AuthorizationResultV2<State> {
        let (version, stored_network, ledger, prior, active): (
            u32,
            u8,
            Vec<u8>,
            String,
            Option<i64>,
        ) = c.query_row(
            "SELECT version,network,ledger,prior,active FROM economic_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        if version != 1 || stored_network != network.tag() {
            return Err("economic journal version/network mismatch".into());
        }
        let prior: EconomicPriorHeadV1 = serde_json::from_str(&prior)?;
        prior.checkpoint()?;
        Ok(State {
            ledger: decode_economic_ledger_v1(&ledger, ledger.len())?,
            prior,
            active,
        })
    }

    fn attempt(
        c: &Connection,
        network: BitcoinNetworkV1,
        id: i64,
    ) -> AuthorizationResultV2<Attempt> {
        let row = c.query_row("SELECT network,subject,nonce,work,consent,authorization,burn,pre_ledger,post_ledger,prior,outcome,head,detail FROM economic_attempts WHERE id=?1", [id], |r| {
            Ok((r.get::<_,u8>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,Vec<u8>>(3)?,
                r.get::<_,String>(4)?, r.get::<_,String>(5)?, r.get::<_,String>(6)?, r.get::<_,Vec<u8>>(7)?,
                r.get::<_,Vec<u8>>(8)?, r.get::<_,String>(9)?, r.get::<_,Option<u8>>(10)?, r.get::<_,Option<String>>(11)?, r.get::<_,String>(12)?))
        })?;
        let (
            n,
            subject,
            nonce,
            bytes,
            consent,
            auth,
            burn,
            pre,
            post,
            prior,
            outcome,
            head,
            detail,
        ) = row;
        let work = EconomicWorkV1::decode(
            &bytes,
            EconomicLimitsV1 {
                max_work_bytes: bytes.len(),
                max_meter_bytes: bytes.len(),
                max_iterations: u64::MAX,
            },
        )?;
        let consent: EconomicConsentV1 = serde_json::from_str(&consent)?;
        let auth: AuthorizationEnvelopeV2 = serde_json::from_str(&auth)?;
        consent.verify_admission_signatures(network, &work, &auth)?;
        let burn = super::head::canonical_sequence_v2(&burn)?;
        let post = decode_economic_ledger_v1(&post, post.len())?;
        let prior: EconomicPriorHeadV1 = serde_json::from_str(&prior)?;
        if n != network.tag()
            || subject != auth.authorization_lineage.subject_binding
            || nonce != auth.authorization_lineage.freshness_binding
            || decode_economic_ledger_v1(&pre, pre.len())? != work.meter.ledger
            || burn != work.burn_units()?
            || post != debit_economic_ledger_v1(&work.meter.ledger, burn)?
            || prior.next_linkage()? != work.meter.head
        {
            return Err("corrupt economic attempt binding".into());
        }
        let terminal = match (outcome, head) {
            (None, None) if detail.is_empty() => None,
            (Some(outcome), Some(head)) => {
                let outcome = match outcome {
                    0 => EconomicOutcomeV1::Accepted,
                    1 => EconomicOutcomeV1::ExecutionRejected,
                    2 => EconomicOutcomeV1::VerificationRejected,
                    3 => EconomicOutcomeV1::SettlementRejected,
                    _ => return Err("invalid economic outcome".into()),
                };
                let head: EconomicHeadV2 = serde_json::from_str(&head)?;
                if head != prior.advance(network, &work, outcome, &post)? {
                    return Err("economic receipt head mismatch".into());
                }
                Some(EconomicReceiptV1 {
                    attempt_id: id,
                    outcome,
                    burn_units: burn,
                    head,
                    detail,
                })
            }
            _ => return Err("incomplete economic terminal state".into()),
        };
        let outbox: Option<String> = c
            .query_row(
                "SELECT request FROM economic_outbox WHERE attempt_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if terminal.as_ref().map(|r| r.outcome) == Some(EconomicOutcomeV1::Accepted) {
            let auth_row: (String, String) = c.query_row("SELECT proof_hash,intent FROM authorizations WHERE network=?1 AND subject=?2 AND nonce=?3",
                        params![network.tag(), auth.authorization_lineage.subject_binding, auth.authorization_lineage.freshness_binding], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let anchor: BitcoinAnchorRequestV1 =
                serde_json::from_str(&outbox.ok_or("accepted attempt missing outbox")?)?;
            if auth_row
                != (
                    auth.proof_hash_hex.clone(),
                    auth.authorization_lineage.intent_commitment_hex.clone(),
                )
                || anchor != BitcoinAnchorRequestV1::new(network, auth.proof_hash_hex.clone())?
            {
                return Err("accepted authorization/outbox mismatch".into());
            }
        } else if outbox.is_some() {
            return Err("failed attempt has outbox".into());
        }
        Ok(Attempt {
            id,
            work_bytes: bytes,
            work,
            consent,
            auth,
            burn,
            post,
            prior,
            terminal,
        })
    }

    fn audit_state(&self) -> AuthorizationResultV2<()> {
        // One read snapshot prevents another process's commit from mixing views.
        let read = self.authorizer.connection.unchecked_transaction()?;
        let c: &Connection = &read;
        let state = Self::state(c, self.network)?;
        let (initial_ledger, initial_prior): (Vec<u8>, String) = c.query_row(
            "SELECT initial_ledger,initial_prior FROM economic_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let mut ledger = decode_economic_ledger_v1(&initial_ledger, initial_ledger.len())?;
        let mut prior: EconomicPriorHeadV1 = serde_json::from_str(&initial_prior)?;
        prior.checkpoint()?;
        let mut pending = None;
        let ids = c
            .prepare("SELECT id FROM economic_attempts ORDER BY id")?
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for id in ids {
            if pending.is_some() {
                return Err("attempt follows nonterminal economic work".into());
            }
            let a = Self::attempt(c, self.network, id)?;
            ledger.payer_account_id = a.work.subject();
            if ledger != a.work.meter.ledger || prior != a.prior {
                return Err("economic journal chain mismatch".into());
            }
            ledger = a.post;
            if let Some(r) = a.terminal {
                prior = EconomicPriorHeadV1::Current(r.head);
            } else {
                pending = Some(id);
            }
        }
        if state.ledger != ledger || state.prior != prior || state.active != pending {
            return Err("economic durable state mismatch".into());
        }
        self.outbox()?; // Also checks orphaned outbox entries and observation shape.
        read.commit()?;
        Ok(())
    }
}
