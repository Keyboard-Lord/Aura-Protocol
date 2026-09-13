//! C2 durable compute lifecycle in EconomicJournalV1. No Aura debit, authorization,
//! Head transition, miner reward or Bitcoin publication occurs in these methods.
use super::*;
use crate::authorization::decode_hex_v2;
use crate::{compute_job::*, compute_result::*};
use secp256k1::{Keypair, XOnlyPublicKey};
use sha2::{Digest, Sha256};
mod adapters;
pub mod funding;
mod operations;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct ComputeJournalConfigV1 {
    pub coordinator: ComputeCoordinatorV1,
    pub limits: ComputeJobLimitsV1,
    pub max_record_bytes: usize,
    pub delivery_budget_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeJobContentV1 {
    pub payloads: [Vec<u8>; 10],
}
impl ComputeJobContentV1 {
    fn validate(&self, j: &AuraComputeJobV1) -> AuthorizationResultV2<ComputePaymentTermsV1> {
        for (k, b) in ComputeContentKindV1::ALL.into_iter().zip(&self.payloads) {
            j.verify_content(k, b)?;
        }
        j.verify_core_policies(
            &self.payloads[6],
            &self.payloads[7],
            &self.payloads[9],
            &self.payloads[8],
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeBackendV1 {
    Cpu,
    Gpu,
    Fpga,
    AuraAsic,
}
#[derive(Clone, Debug)]
pub struct MeasuredComputeWorkerV1(Measurement);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Measurement {
    worker: [u8; 32],
    adapter: [u8; 32],
    backend: u8,
    at: u64,
    until: u64,
    limits: [u64; 6],
    provenance: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    network: u8,
    key: [u8; 32],
    namespace: [u8; 32],
    limits: [u64; 6],
    max_record_bytes: usize,
    delivery_ms: u64,
}
fn pack_limits(l: &ComputeJobLimitsV1) -> [u64; 6] {
    [
        l.max_input_bytes,
        l.max_output_bytes,
        l.max_evidence_bytes,
        l.max_memory_bytes,
        l.max_scratch_bytes,
        l.max_execution_ms,
    ]
}
fn unpack_limits(l: [u64; 6]) -> ComputeJobLimitsV1 {
    ComputeJobLimitsV1 {
        max_input_bytes: l[0],
        max_output_bytes: l[1],
        max_evidence_bytes: l[2],
        max_memory_bytes: l[3],
        max_scratch_bytes: l[4],
        max_execution_ms: l[5],
    }
}
impl Config {
    fn trusted(&self, n: BitcoinNetworkV1) -> ComputeCoordinatorV1 {
        ComputeCoordinatorV1 {
            network: n,
            coordinator_key: self.key,
            journal_namespace: self.namespace,
        }
    }
    fn validate(&self, n: BitcoinNetworkV1) -> AuthorizationResultV2<()> {
        XOnlyPublicKey::from_byte_array(self.key)?;
        if self.network != n.tag()
            || self.max_record_bytes == 0
            || self.limits[1] == 0
            || self.limits[2] == 0
            || self.limits[3] == 0
            || self.limits[5] == 0
        {
            return Err("invalid compute coordinator policy".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeJobStateV1 {
    Open,
    Assigned,
    ReceiptPending,
    Accepted,
    Rejected,
    Expired,
    Cancelled,
}
impl ComputeJobStateV1 {
    fn from_tag(t: u8) -> AuthorizationResultV2<Self> {
        Ok(match t {
            0 => Self::Open,
            1 => Self::Assigned,
            2 => Self::ReceiptPending,
            3 => Self::Accepted,
            4 => Self::Rejected,
            5 => Self::Expired,
            6 => Self::Cancelled,
            _ => return Err("invalid compute job state".into()),
        })
    }
}
/// Earned customer-funded obligation. No paid flag, payout script or Aura balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeEntitlementV1 {
    pub compute_job_commitment: [u8; 32],
    pub worker_key: [u8; 32],
    pub compensation_satoshis: u64,
    pub fee_allowance_satoshis: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    bytes: Vec<u8>,
    worker_signature: Vec<u8>,
    coordinator_signature: Vec<u8>,
    at: u64,
    measurement: Measurement,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    bytes: Vec<u8>,
    signature: Vec<u8>,
    resources: Vec<u8>,
    output: Vec<u8>,
    evidence: Vec<u8>,
    at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultRecord {
    bytes: Vec<u8>,
    signature: Vec<u8>,
    at: u64,
    retain_until: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    job: Vec<u8>,
    signature: Vec<u8>,
    content: ComputeJobContentV1,
    created: u64,
    state: u8,
    assignment: Option<Assignment>,
    receipt: Option<Receipt>,
    result: Option<ResultRecord>,
    funding: Option<funding::StoredFunding>,
    closed: Option<u64>,
    cancel_signature: Option<Vec<u8>>,
}
fn checksum(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}
fn state_tag(r: &Record) -> AuthorizationResultV2<ComputeJobStateV1> {
    ComputeJobStateV1::from_tag(r.state)
}
fn schema(c: &Connection) -> AuthorizationResultV2<bool> {
    let n:u8=c.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('compute_control','compute_jobs','compute_entitlements')",[],|r|r.get(0))?;
    match n {
        0 => Ok(false),
        3 => Ok(true),
        _ => Err("partial compute schema; recovery required".into()),
    }
}
fn config(c: &Connection, n: BitcoinNetworkV1) -> AuthorizationResultV2<Config> {
    if !schema(c)? {
        return Err("compute extension not installed".into());
    }
    let bytes: u64 = c.query_row(
        "SELECT length(CAST(config AS BLOB)) FROM compute_control WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    if bytes > 16384 {
        return Err("oversized compute configuration".into());
    }
    let (version, s, h): (u8, String, Vec<u8>) = c.query_row(
        "SELECT version,config,checksum FROM compute_control WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if version != 1 || s.len() > 16384 || checksum(s.as_bytes()) != h {
        return Err("corrupt compute coordinator configuration".into());
    }
    let cfg: Config = serde_json::from_str(&s)?;
    cfg.validate(n)?;
    Ok(cfg)
}
fn validate_record(
    r: &Record,
    cfg: &Config,
    n: BitcoinNetworkV1,
) -> AuthorizationResultV2<AuraComputeJobV1> {
    let j = AuraComputeJobV1::decode(&r.job)?;
    j.verify_for_coordinator(&r.signature, &cfg.trusted(n))?;
    let terms = r.content.validate(&j)?;
    j.validate_new_assignment(r.created, cfg.delivery_ms, &unpack_limits(cfg.limits))?;
    let state = state_tag(r)?;
    let a = r
        .assignment
        .as_ref()
        .map(|v| ComputeAssignmentV1::decode(&v.bytes))
        .transpose()?;
    if let Some(a) = &a {
        let s = r.assignment.as_ref().unwrap();
        a.verify_job(&j)?;
        a.verify_worker(s.worker_signature.as_slice().try_into()?)?;
        a.verify_coordinator(&j, s.coordinator_signature.as_slice().try_into()?)?;
        validate_measurement(&s.measurement, &j, a, s.at)?;
        j.validate_new_assignment(s.at, cfg.delivery_ms, &unpack_limits(cfg.limits))?;
        if s.at < r.created {
            return Err("assignment clock precedes registration".into());
        }
    }
    if let Some(f) = &r.funding {
        f.validate(&j, &terms)?;
    }
    if let Some(v) = &r.receipt {
        let a = a.as_ref().ok_or("receipt has no assignment")?;
        let rr = ComputeReceiptV1::decode(&v.bytes)?;
        rr.verify_signature(a, v.signature.as_slice().try_into()?)?;
        rr.verify_content(
            &j,
            &ComputeResourceAccountingV1::decode(&v.resources)?,
            &r.content.payloads[1],
            &v.output,
            &v.evidence,
        )?;
        if v.at >= j.complete_by || v.at < r.assignment.as_ref().unwrap().at {
            return Err("receipt time is not timely".into());
        }
    }
    if let Some(v) = &r.result {
        let rr = r.receipt.as_ref().ok_or("result has no receipt")?;
        VerifiedComputeResultV1::decode(&v.bytes)?.verify_signature(
            &j,
            a.as_ref().ok_or("result has no assignment")?,
            &ComputeReceiptV1::decode(&rr.bytes)?,
            v.signature.as_slice().try_into()?,
        )?;
        if v.at < rr.at
            || v.retain_until
                != (u128::from(v.at) + u128::from(terms.result_availability_seconds)).to_string()
        {
            return Err("corrupt result availability obligation".into());
        }
    }
    let flags = (
        r.assignment.is_some(),
        r.funding.is_some(),
        r.receipt.is_some(),
        r.result.is_some(),
        r.closed.is_some(),
        r.cancel_signature.is_some(),
    );
    let valid = match state {
        ComputeJobStateV1::Open => flags == (false, false, false, false, false, false),
        ComputeJobStateV1::Assigned => flags == (true, true, false, false, false, false),
        ComputeJobStateV1::ReceiptPending => flags == (true, true, true, false, false, false),
        ComputeJobStateV1::Accepted => flags == (true, true, true, true, false, false),
        ComputeJobStateV1::Rejected => flags == (true, true, true, false, true, false),
        ComputeJobStateV1::Expired => {
            (flags == (true, true, false, false, true, false)
                || flags == (false, false, false, false, true, false))
                && r.closed.unwrap()
                    >= (if a.is_some() {
                        j.complete_by
                    } else {
                        j.accept_until
                    })
        }
        ComputeJobStateV1::Cancelled => flags == (false, false, false, false, true, true),
    };
    if !valid {
        return Err("split compute lifecycle state".into());
    }
    if let Some(t) = r.closed {
        if t < r.created || r.receipt.as_ref().is_some_and(|x| t < x.at) {
            return Err("terminal clock regression".into());
        }
    }
    if let Some(s) = &r.cancel_signature {
        ComputeCancelV1 {
            version: 1,
            compute_job_commitment: j.commitment()?,
        }
        .verify_signature(&j, s.as_slice().try_into()?)?;
    }
    Ok(j)
}
fn validate_measurement(
    m: &Measurement,
    j: &AuraComputeJobV1,
    a: &ComputeAssignmentV1,
    now: u64,
) -> AuthorizationResultV2<()> {
    if m.worker != a.worker_key
        || m.adapter != j.adapter_contract_commitment
        || m.backend > 3
        || (m.provenance.is_empty() || m.provenance.len() > 128)
        || m.at > now
        || m.until <= now
    {
        return Err("unsupported or expired compute measurement".into());
    }
    j.validate_new_assignment(now, 0, &unpack_limits(m.limits))
}
fn storage_budget(
    j: &AuraComputeJobV1,
    c: &ComputeJobContentV1,
    cfg: &Config,
) -> AuthorizationResultV2<()> {
    // Conservative JSON storage bound: at most four bytes per u8 plus bounded
    // fixed metadata. Check before assignment so valid maximum-sized output can
    // be durably received under this installed host cap.
    let payload = c.payloads.iter().map(|b| b.len() as u128).sum::<u128>();
    let needed = 16384u128
        + 4 * (payload + u128::from(j.max_output_bytes) + u128::from(j.max_evidence_bytes));
    if needed > cfg.max_record_bytes as u128 {
        return Err("signed result cannot fit durable compute host capacity".into());
    }
    Ok(())
}
fn load(c: &Connection, id: &[u8; 32], cfg: &Config) -> AuthorizationResultV2<Record> {
    let len: u64 = c.query_row(
        "SELECT length(CAST(record AS BLOB)) FROM compute_jobs WHERE id=?1",
        [id.as_slice()],
        |r| r.get(0),
    )?;
    if u128::from(len) > cfg.max_record_bytes as u128 {
        return Err("compute stored record exceeds host bound".into());
    }
    let (requester,nonce,state,txid,vout,s,h):(Vec<u8>,Vec<u8>,u8,Option<String>,Option<u32>,String,Vec<u8>)=c.query_row("SELECT requester,nonce,state,funding_txid,funding_vout,record,checksum FROM compute_jobs WHERE id=?1",[id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?;
    if checksum(s.as_bytes()) != h {
        return Err("corrupt compute durable record".into());
    }
    let r: Record = serde_json::from_str(&s)?;
    let n = network(cfg.network)?;
    let j = validate_record(&r, cfg, n)?;
    if j.commitment()? != *id
        || j.requester_key.as_slice() != requester
        || j.job_nonce.as_slice() != nonce
        || r.state != state
        || txid.as_deref() != r.funding.as_ref().map(|x| x.txid())
        || vout != r.funding.as_ref().map(|x| x.vout())
    {
        return Err("compute index/record mismatch".into());
    }
    let obligation: Option<(Vec<u8>, String, String)> = c
        .query_row(
            "SELECT worker,net,fee FROM compute_entitlements WHERE job=?1",
            [id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if r.state == 3 {
        let t = r.content.validate(&j)?;
        let a = ComputeAssignmentV1::decode(&r.assignment.as_ref().unwrap().bytes)?;
        if obligation
            != Some((
                a.worker_key.to_vec(),
                j.compensation_satoshis.to_string(),
                t.max_payment_fee_satoshis.to_string(),
            ))
        {
            return Err("split accepted result/entitlement".into());
        }
    } else if obligation.is_some() {
        return Err("unearned compute entitlement".into());
    }
    if matches!(r.state, 1..=3) {
        let f = r.funding.as_ref().ok_or("missing assigned backing")?;
        super::funding_registry::available(c, f.txid(), f.vout(), Some(id))?;
    }
    Ok(r)
}
fn network(t: u8) -> AuthorizationResultV2<BitcoinNetworkV1> {
    [
        BitcoinNetworkV1::Mainnet,
        BitcoinNetworkV1::Testnet3,
        BitcoinNetworkV1::Signet,
        BitcoinNetworkV1::Regtest,
        BitcoinNetworkV1::Testnet4,
    ]
    .into_iter()
    .find(|n| n.tag() == t)
    .ok_or_else(|| "invalid compute network".into())
}
fn save(c: &Connection, id: &[u8; 32], r: &Record, cfg: &Config) -> AuthorizationResultV2<()> {
    let j = validate_record(r, cfg, network(cfg.network)?)?;
    if j.commitment()? != *id {
        return Err("compute identity changed".into());
    }
    let s = serde_json::to_string(r)?;
    if s.len() > cfg.max_record_bytes {
        return Err("compute record exceeds host bound".into());
    }
    let n=c.execute("UPDATE compute_jobs SET state=?1,funding_txid=?2,funding_vout=?3,record=?4,checksum=?5 WHERE id=?6",params![r.state,r.funding.as_ref().map(|f|f.txid()),r.funding.as_ref().map(|f|f.vout()),s,checksum(s.as_bytes()),id.as_slice()])?;
    if n != 1 {
        return Err("compute transition lost job ownership".into());
    }
    Ok(())
}
fn hook(_point: &str) -> AuthorizationResultV2<()> {
    #[cfg(test)]
    tests::hook(_point)?;
    Ok(())
}
pub(super) fn audit(c: &Connection, n: BitcoinNetworkV1) -> AuthorizationResultV2<()> {
    if !schema(c)? {
        return Ok(());
    }
    let cfg = config(c, n)?;
    if c.query_row(
        "SELECT EXISTS(SELECT 1 FROM compute_jobs GROUP BY requester,nonce HAVING count(*)>1)",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        return Err("duplicate compute replay scope".into());
    }
    let ids = c
        .prepare("SELECT id FROM compute_jobs")?
        .query_map([], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in ids {
        load(c, &id.as_slice().try_into()?, &cfg)?;
    }
    if c.query_row("SELECT EXISTS(SELECT 1 FROM compute_entitlements e LEFT JOIN compute_jobs j ON j.id=e.job WHERE j.id IS NULL)",[],|r|r.get::<_,bool>(0))?{return Err("orphan compute entitlement".into());}
    Ok(())
}
