//! Coordinated miner rounds in the existing economic transaction owner. Local
//! API/storage values only: J, W, authorization, proof and anchor wires are reused.
use super::*;
use crate::{
    authorization::fresh_nonce_v2,
    miner::{miner_route_tag_v1, MinerJobPolicyV1, MinerJobV1},
};
use secp256k1::{Keypair, Secp256k1};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod funding;
pub mod publication;
use funding::MinerFundingReservationV1;

/// Explicit trusted deployment limits; no default difficulty, N, reward or window.
#[derive(Clone, Debug)]
pub struct MinerRoundPolicyV1 {
    pub job: MinerJobPolicyV1,
    pub max_duration_secs: u64,
    pub minimum_reward_satoshis: u64,
}

#[derive(Clone, Debug)]
pub struct MinerRoundOpeningV1 {
    pub side_a: [u8; 110],
    pub side_b: [u8; 110],
    pub duration_secs: u64,
    pub reward_satoshis: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinerRoundStateV1 {
    Open,
    Admitted,
    Accepted,
    Rejected,
    Expired,
}

/// Winner identity/proof reference live in the existing accepted authorization.
/// The obligation references that attempt and the job's reward; no second identity.
#[derive(Clone, Debug)]
pub struct MinerRoundV1 {
    pub job: MinerJobV1,
    pub signature: [u8; 64],
    pub state: MinerRoundStateV1,
    pub attempt_id: Option<i64>,
    pub funding: MinerFundingReservationV1,
}

#[derive(Clone, Debug)]
pub struct MinerRewardObligationV1 {
    pub round: MinerRoundV1,
    pub receipt: EconomicReceiptV1,
    pub authorization: AuthorizationEnvelopeV2,
}

// Internal storage only, deliberately distinct from the frozen binary job wire.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    network: BitcoinNetworkV1,
    operator: [u8; 32],
    namespace: [u8; 32],
    epoch: u64,
    n: u64,
    target: [u8; 32],
    work: u64,
    meter: u64,
    duration: u64,
    minimum_reward: u64,
}
impl Policy {
    fn from_public(p: &MinerRoundPolicyV1) -> Self {
        Self {
            network: p.job.network,
            operator: p.job.operator_key,
            namespace: p.job.journal_namespace,
            epoch: p.job.policy_epoch,
            n: p.job.iteration_count,
            target: p.job.target,
            work: p.job.max_work_bytes,
            meter: p.job.max_meter_bytes,
            duration: p.max_duration_secs,
            minimum_reward: p.minimum_reward_satoshis,
        }
    }
    fn job_policy(&self) -> MinerJobPolicyV1 {
        MinerJobPolicyV1 {
            network: self.network,
            operator_key: self.operator,
            journal_namespace: self.namespace,
            policy_epoch: self.epoch,
            iteration_count: self.n,
            target: self.target,
            max_work_bytes: self.work,
            max_meter_bytes: self.meter,
        }
    }
    fn validate(
        &self,
        network: BitcoinNetworkV1,
        limits: EconomicLimitsV1,
    ) -> AuthorizationResultV2<()> {
        if self.network != network
            || self.duration == 0
            || self.minimum_reward == 0
            || self.minimum_reward > funding::MAX_SATOSHIS
            || self.n == 0
            || self.n == u64::MAX
            || self.n > limits.max_iterations
            || self.work == 0
            || self.meter == 0
            || self.work > u64::try_from(limits.max_work_bytes)?
            || self.meter > u64::try_from(limits.max_meter_bytes)?
            || self.target == [0; 32]
            || self.target == [255; 32]
        {
            return Err("invalid miner operator policy/limits".into());
        }
        secp256k1::XOnlyPublicKey::from_byte_array(self.operator)?;
        Ok(())
    }
}
fn historical_limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: usize::MAX,
        max_meter_bytes: usize::MAX,
        max_iterations: u64::MAX,
    }
}
pub(super) fn now() -> AuthorizationResultV2<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn enabled(c: &Connection) -> AuthorizationResultV2<bool> {
    let count: u8 = c.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('miner_control','miner_policies','miner_rounds','miner_rewards')",
        [],
        |r| r.get(0),
    )?;
    match count {
        0 => Ok(false),
        4 => Ok(true),
        _ => Err("incomplete miner coordination schema".into()),
    }
}
fn policy(c: &Connection, epoch: u64, network: BitcoinNetworkV1) -> AuthorizationResultV2<Policy> {
    let wire: String = c.query_row(
        "SELECT policy FROM miner_policies WHERE epoch=?1",
        [epoch.to_string()],
        |r| r.get(0),
    )?;
    let p: Policy = serde_json::from_str(&wire)?;
    p.validate(network, historical_limits())?;
    if p.epoch != epoch {
        return Err("miner policy epoch mismatch".into());
    }
    Ok(p)
}
fn control(c: &Connection) -> AuthorizationResultV2<(u64, u64)> {
    let (v, e, r): (u8, String, String) = c.query_row(
        "SELECT version,epoch,next_round FROM miner_control WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if v != 1 {
        return Err("unsupported miner coordination schema".into());
    }
    Ok((
        super::super::head::canonical_sequence_v2(&e)?,
        super::super::head::canonical_sequence_v2(&r)?,
    ))
}
fn active_round(c: &Connection) -> AuthorizationResultV2<Option<u64>> {
    let r: Option<String> = c
        .query_row(
            "SELECT number FROM miner_rounds WHERE state IN (0,1)",
            [],
            |r| r.get(0),
        )
        .optional()?;
    r.map(|r| super::super::head::canonical_sequence_v2(&r))
        .transpose()
}

impl EconomicJournalV1 {
    /// Explicit extension of this journal. Existing economic-only databases are
    /// still readable; opening one never silently creates miner state.
    pub fn install_miner_policy(
        &mut self,
        value: &MinerRoundPolicyV1,
    ) -> AuthorizationResultV2<()> {
        let p = Policy::from_public(value);
        p.validate(self.network, self.limits)?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if Self::state(&tx, self.network)?.active.is_some() {
            return Err("cannot install miner policy during admission".into());
        }
        tx.execute_batch("CREATE TABLE miner_policies(epoch TEXT PRIMARY KEY,policy TEXT NOT NULL);
          CREATE TABLE miner_control(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),epoch TEXT NOT NULL REFERENCES miner_policies(epoch),next_round TEXT NOT NULL);
          CREATE TABLE miner_rounds(number TEXT PRIMARY KEY,epoch TEXT NOT NULL REFERENCES miner_policies(epoch),job BLOB NOT NULL CHECK(length(job)=471),signature BLOB NOT NULL CHECK(length(signature)=64),ledger BLOB NOT NULL,prior TEXT NOT NULL,
            funding TEXT NOT NULL,funding_txid TEXT NOT NULL,funding_vout INTEGER NOT NULL,
            state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 4),attempt_id INTEGER UNIQUE REFERENCES economic_attempts(id),
            CHECK((state IN (0,4) AND attempt_id IS NULL) OR (state IN (1,2,3) AND attempt_id IS NOT NULL)));
          CREATE UNIQUE INDEX miner_one_active ON miner_rounds((1)) WHERE state IN (0,1);
          CREATE UNIQUE INDEX miner_challenge ON miner_rounds(substr(job,140,32));
          CREATE UNIQUE INDEX miner_funding_owned ON miner_rounds(funding_txid,funding_vout) WHERE state IN (0,1,2);
          CREATE TABLE miner_rewards(attempt_id INTEGER PRIMARY KEY REFERENCES economic_attempts(id),round_number TEXT UNIQUE NOT NULL REFERENCES miner_rounds(number));")?;
        tx.execute(
            "INSERT INTO miner_policies VALUES(?1,?2)",
            params![p.epoch.to_string(), serde_json::to_string(&p)?],
        )?;
        tx.execute(
            "INSERT INTO miner_control VALUES(1,1,?1,'1')",
            [p.epoch.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Policy rotation between rounds only. Keep the journal identity, preserve
    /// every historic epoch, and require an explicit strictly increasing epoch.
    pub fn update_miner_policy(&mut self, value: &MinerRoundPolicyV1) -> AuthorizationResultV2<()> {
        let p = Policy::from_public(value);
        p.validate(self.network, self.limits)?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit(&tx, self.network)?;
        let (e, _) = control(&tx)?;
        let old = policy(&tx, e, self.network)?;
        if active_round(&tx)?.is_some()
            || Self::state(&tx, self.network)?.active.is_some()
            || p.epoch <= e
            || p.operator != old.operator
            || p.namespace != old.namespace
        {
            return Err(
                "miner policy rotation requires idle journal, same identity, newer epoch".into(),
            );
        }
        tx.execute(
            "INSERT INTO miner_policies VALUES(?1,?2)",
            params![p.epoch.to_string(), serde_json::to_string(&p)?],
        )?;
        tx.execute(
            "UPDATE miner_control SET epoch=?1 WHERE id=1",
            [p.epoch.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Trusted service opening. Funding callback executes while the journal pins
    /// its snapshot; return/publish J only after the transaction commits. The Core
    /// wallet lock is custodial, not a cross-system atomic escrow (see funding).
    pub fn open_miner_round(
        &mut self,
        operator: &Keypair,
        opening: MinerRoundOpeningV1,
        reserve: impl FnOnce(&MinerJobV1) -> AuthorizationResultV2<MinerFundingReservationV1>,
    ) -> AuthorizationResultV2<MinerRoundV1> {
        self.open_round_at(operator, opening, reserve, now()?, fresh_nonce_v2()?)
    }
    fn open_round_at(
        &mut self,
        operator: &Keypair,
        opening: MinerRoundOpeningV1,
        reserve: impl FnOnce(&MinerJobV1) -> AuthorizationResultV2<MinerFundingReservationV1>,
        time: u64,
        challenge: [u8; 32],
    ) -> AuthorizationResultV2<MinerRoundV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit(&tx, self.network)?;
        let (epoch, number) = control(&tx)?;
        let p = policy(&tx, epoch, self.network)?;
        p.validate(self.network, self.limits)?;
        let s = Self::state(&tx, self.network)?;
        if active_round(&tx)?.is_some() || s.active.is_some() {
            return Err("round opening requires idle journal".into());
        }
        let EconomicPriorHeadV1::Current(head) = &s.prior else {
            return Err("miner requires an existing V2 head".into());
        };
        if operator.x_only_public_key().0.serialize() != p.operator
            || opening.duration_secs == 0
            || opening.duration_secs > p.duration
            || opening.reward_satoshis < p.minimum_reward
        {
            return Err("invalid round operator/window/reward".into());
        }
        let job = MinerJobV1 {
            job_version: 1,
            network: self.network,
            operator_key: p.operator,
            journal_namespace: p.namespace,
            policy_epoch: epoch,
            round_number: number,
            prior_head_sequence: head.validate()?,
            prior_head_hash: decode_hex_v2(&head.current_head_hash_hex)?,
            challenge,
            side_a: opening.side_a,
            side_b: opening.side_b,
            iteration_count: p.n,
            target: p.target,
            max_work_bytes: p.work,
            max_meter_bytes: p.meter,
            opened_at: time,
            expires_at: time
                .checked_add(opening.duration_secs)
                .ok_or("round expiry overflow")?,
            reward_satoshis: opening.reward_satoshis,
        };
        job.validate_head(head)?;
        let signature = *Secp256k1::new()
            .sign_schnorr_no_aux_rand(&job.signing_digest()?, operator)
            .as_ref();
        job.verify_for_policy(&signature, &p.job_policy(), self.limits)?;
        let next = number.checked_add(1).ok_or("round number exhausted")?;
        let funding = reserve(&job)?;
        funding.validate(&job)?;
        tx.execute(
            "INSERT INTO miner_rounds VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0,NULL)",
            params![
                number.to_string(),
                epoch.to_string(),
                job.canonical_bytes()?,
                signature.as_slice(),
                economic_ledger_bytes_v1(&s.ledger)?,
                serde_json::to_string(&s.prior)?,
                funding.storage()?,
                funding.txid(),
                funding.vout()
            ],
        )?;
        tx.execute(
            "UPDATE miner_control SET next_round=?1 WHERE id=1",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(MinerRoundV1 {
            job,
            signature,
            state: MinerRoundStateV1::Open,
            attempt_id: None,
            funding,
        })
    }

    pub fn miner_round(&self, number: u64) -> AuthorizationResultV2<MinerRoundV1> {
        let tx = self.authorizer.connection.unchecked_transaction()?;
        let r = read_round(&tx, self.network, number)?;
        check_round(&tx, self.network, &r)?;
        tx.commit()?;
        Ok(r)
    }
    /// Does not expire an admitted contender. A released reservation remains in
    /// history; the wallet manager can unlock/reuse it only after this commit.
    pub fn expire_miner_round(&mut self, number: u64) -> AuthorizationResultV2<MinerRoundV1> {
        self.expire_round_at(number, now()?)
    }
    fn expire_round_at(&mut self, number: u64, time: u64) -> AuthorizationResultV2<MinerRoundV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let r = read_round(&tx, self.network, number)?;
        check_round(&tx, self.network, &r)?;
        if r.state == MinerRoundStateV1::Open {
            if time < r.job.expires_at {
                return Err("round has not expired".into());
            }
            tx.execute(
                "UPDATE miner_rounds SET state=4 WHERE number=?1",
                [number.to_string()],
            )?;
        }
        tx.commit()?;
        self.miner_round(number)
    }
    pub fn miner_reward_obligations(&self) -> AuthorizationResultV2<Vec<MinerRewardObligationV1>> {
        let tx = self.authorizer.connection.unchecked_transaction()?;
        audit(&tx, self.network)?;
        let ids = tx
            .prepare("SELECT attempt_id,round_number FROM miner_rewards ORDER BY attempt_id")?
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Vec::new();
        for (id, n) in ids {
            let round = read_round(
                &tx,
                self.network,
                super::super::head::canonical_sequence_v2(&n)?,
            )?;
            let a = Self::attempt(&tx, self.network, id)?;
            out.push(MinerRewardObligationV1 {
                round,
                receipt: a.terminal.ok_or("reward missing receipt")?,
                authorization: a.auth,
            });
        }
        tx.commit()?;
        Ok(out)
    }
}

pub(super) fn is_miner_work(work: &EconomicWorkV1) -> bool {
    work.storm.context_bytes_v1[177..209] == miner_route_tag_v1()
}
pub(super) fn admission_at(
    c: &Connection,
    network: BitcoinNetworkV1,
    limits: EconomicLimitsV1,
    work: &EconomicWorkV1,
    auth: &AuthorizationEnvelopeV2,
    time: u64,
) -> AuthorizationResultV2<Option<u64>> {
    if !enabled(c)? {
        return if is_miner_work(work) {
            Err("miner route requires coordinated funded round".into())
        } else {
            Ok(None)
        };
    }
    let active = active_round(c)?;
    if !is_miner_work(work) {
        return if active.is_some() {
            Err("open miner round pins economic admission; no charge".into())
        } else {
            Ok(None)
        };
    }
    let number = active.ok_or("no open miner round; no charge")?;
    let r = read_round(c, network, number)?;
    check_round(c, network, &r)?;
    let (epoch, _) = control(c)?;
    if r.state != MinerRoundStateV1::Open || r.job.policy_epoch != epoch {
        return Err("miner round already owned or stale".into());
    }
    let p = policy(c, epoch, network)?;
    r.job
        .verify_for_policy(&r.signature, &p.job_policy(), limits)?;
    r.job.validate_window(time, p.duration)?;
    r.job.validate_work_profile(work)?;
    if !r
        .job
        .passes_hash_filter(&decode_hex_v2::<32>(&auth.proof_hash_hex)?)?
    {
        return Err("above-target candidate; no charge".into());
    }
    Ok(Some(number))
}
pub(super) fn claim_round(
    c: &Connection,
    round: Option<u64>,
    id: i64,
) -> AuthorizationResultV2<()> {
    if let Some(n) = round {
        if c.execute(
            "UPDATE miner_rounds SET state=1,attempt_id=?1 WHERE number=?2 AND state=0",
            params![id, n.to_string()],
        )? != 1
        {
            return Err("round admission lost ownership".into());
        }
    }
    Ok(())
}
pub(super) fn finish_round(
    c: &Connection,
    a: &Attempt,
    outcome: EconomicOutcomeV1,
) -> AuthorizationResultV2<()> {
    if !is_miner_work(&a.work) {
        return Ok(());
    }
    let state = if outcome == EconomicOutcomeV1::Accepted {
        2
    } else {
        3
    };
    if c.execute(
        "UPDATE miner_rounds SET state=?1 WHERE attempt_id=?2 AND state=1",
        params![state, a.id],
    )? != 1
    {
        return Err("miner terminal ownership mismatch".into());
    }
    if state == 2 {
        c.execute("INSERT INTO miner_rewards SELECT attempt_id,number FROM miner_rounds WHERE attempt_id=?1",[a.id])?;
    }
    Ok(())
}

fn read_round(
    c: &Connection,
    network: BitcoinNetworkV1,
    number: u64,
) -> AuthorizationResultV2<MinerRoundV1> {
    let (epoch,j,s,f,txid,vout,state,id):(String,Vec<u8>,Vec<u8>,String,String,u32,u8,Option<i64>)=c.query_row("SELECT epoch,job,signature,funding,funding_txid,funding_vout,state,attempt_id FROM miner_rounds WHERE number=?1",[number.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    let job = MinerJobV1::decode(&j)?;
    let p = policy(c, job.policy_epoch, network)?;
    job.verify_for_policy(&s, &p.job_policy(), historical_limits())?;
    if job.round_number != number
        || epoch != job.policy_epoch.to_string()
        || job.expires_at - job.opened_at > p.duration
        || job.reward_satoshis < p.minimum_reward
    {
        return Err("miner durable job mismatch".into());
    }
    let funding: MinerFundingReservationV1 = MinerFundingReservationV1::from_storage(&f)?;
    funding.validate(&job)?;
    if funding.txid() != txid || funding.vout() != vout {
        return Err("miner funding index mismatch".into());
    }
    let state = match state {
        0 => MinerRoundStateV1::Open,
        1 => MinerRoundStateV1::Admitted,
        2 => MinerRoundStateV1::Accepted,
        3 => MinerRoundStateV1::Rejected,
        4 => MinerRoundStateV1::Expired,
        _ => return Err("invalid miner round state".into()),
    };
    if matches!(state, MinerRoundStateV1::Open | MinerRoundStateV1::Expired) != id.is_none() {
        return Err("miner contender state mismatch".into());
    }
    Ok(MinerRoundV1 {
        job,
        signature: s.try_into().map_err(|_| "miner signature size")?,
        state,
        attempt_id: id,
        funding,
    })
}
fn check_round(
    c: &Connection,
    network: BitcoinNetworkV1,
    r: &MinerRoundV1,
) -> AuthorizationResultV2<()> {
    let (ledger, prior): (Vec<u8>, String) = c.query_row(
        "SELECT ledger,prior FROM miner_rounds WHERE number=?1",
        [r.job.round_number.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut ledger = decode_economic_ledger_v1(&ledger, ledger.len())?;
    let prior: EconomicPriorHeadV1 = serde_json::from_str(&prior)?;
    let EconomicPriorHeadV1::Current(head) = &prior else {
        return Err("miner snapshot requires V2 predecessor".into());
    };
    r.job.validate_head(head)?;
    if let Some(id) = r.attempt_id {
        let a = EconomicJournalV1::attempt(c, network, id)?;
        r.job.validate_work_profile(&a.work)?;
        if !r
            .job
            .passes_hash_filter(&decode_hex_v2::<32>(&a.auth.proof_hash_hex)?)?
        {
            return Err("stored miner target mismatch".into());
        }
        ledger.payer_account_id = a.work.subject();
        if ledger != a.work.meter.ledger || prior != a.prior {
            return Err("miner attempt/snapshot mismatch".into());
        }
        let expected = match &a.terminal {
            None => MinerRoundStateV1::Admitted,
            Some(t) if t.outcome == EconomicOutcomeV1::Accepted => MinerRoundStateV1::Accepted,
            Some(_) => MinerRoundStateV1::Rejected,
        };
        if r.state != expected {
            return Err("split miner/economic terminal state".into());
        }
        if r.state == MinerRoundStateV1::Admitted {
            let s = EconomicJournalV1::state(c, network)?;
            if s.active != Some(id) || s.prior != prior || s.ledger != a.post {
                return Err("pending miner ownership mismatch".into());
            }
        }
    } else if r.state == MinerRoundStateV1::Open {
        let s = EconomicJournalV1::state(c, network)?;
        if s.active.is_some() || s.prior != prior || s.ledger != ledger {
            return Err("open miner snapshot mismatch".into());
        }
    }
    let reward: Option<i64> = c
        .query_row(
            "SELECT attempt_id FROM miner_rewards WHERE round_number=?1",
            [r.job.round_number.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    if reward
        != if r.state == MinerRoundStateV1::Accepted {
            r.attempt_id
        } else {
            None
        }
    {
        return Err("split winner/reward obligation".into());
    }
    Ok(())
}
pub(super) fn check_attempt(
    c: &Connection,
    network: BitcoinNetworkV1,
    a: &Attempt,
) -> AuthorizationResultV2<()> {
    if !enabled(c)? {
        return if is_miner_work(&a.work) {
            Err("miner attempt without coordinated round".into())
        } else {
            Ok(())
        };
    }
    let n: Option<String> = c
        .query_row(
            "SELECT number FROM miner_rounds WHERE attempt_id=?1",
            [a.id],
            |r| r.get(0),
        )
        .optional()?;
    if n.is_some() != is_miner_work(&a.work) {
        return Err("miner route/round ownership mismatch".into());
    }
    if let Some(n) = n {
        check_round(
            c,
            network,
            &read_round(c, network, super::super::head::canonical_sequence_v2(&n)?)?,
        )?;
    }
    Ok(())
}
pub(super) fn audit(c: &Connection, network: BitcoinNetworkV1) -> AuthorizationResultV2<()> {
    if !enabled(c)? {
        return Ok(());
    }
    let (epoch, next) = control(c)?;
    let current = policy(c, epoch, network)?;
    let epochs = c
        .prepare("SELECT epoch FROM miner_policies")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for e in epochs {
        let p = policy(c, super::super::head::canonical_sequence_v2(&e)?, network)?;
        if p.epoch > epoch || p.operator != current.operator || p.namespace != current.namespace {
            return Err("miner policy history mismatch".into());
        }
    }
    let numbers = c
        .prepare("SELECT number FROM miner_rounds")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut numbers = numbers
        .iter()
        .map(|n| super::super::head::canonical_sequence_v2(n))
        .collect::<AuthorizationResultV2<Vec<_>>>()?;
    numbers.sort_unstable();
    let mut previous_epoch = 0;
    for (i, n) in numbers.iter().enumerate() {
        if *n
            != u64::try_from(i)?
                .checked_add(1)
                .ok_or("round counter overflow")?
        {
            return Err("miner round sequence gap".into());
        }
        let r = read_round(c, network, *n)?;
        check_round(c, network, &r)?;
        if r.job.policy_epoch < previous_epoch || r.job.policy_epoch > epoch {
            return Err("miner round epoch regression".into());
        }
        previous_epoch = r.job.policy_epoch;
    }
    if next
        != u64::try_from(numbers.len())?
            .checked_add(1)
            .ok_or("round counter overflow")?
    {
        return Err("miner next round mismatch".into());
    }
    let bad:i64=c.query_row("SELECT count(*) FROM miner_rewards w LEFT JOIN miner_rounds r ON w.round_number=r.number WHERE r.number IS NULL OR r.state!=2 OR r.attempt_id!=w.attempt_id",[],|r|r.get(0))?;
    if bad != 0 {
        return Err("orphaned miner reward".into());
    }
    let ids = c
        .prepare("SELECT id FROM economic_attempts")?
        .query_map([], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in ids {
        check_attempt(c, network, &EconomicJournalV1::attempt(c, network, id)?)?;
    }
    publication::audit(c, network)?;
    Ok(())
}

#[cfg(test)]
mod tests;
