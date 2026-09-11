//! Replay-safe sponsor payment publication. Bitcoin Core owns transaction coding
//! and wallet signing; the economic journal owns obligations and payment history.
//! All types here are operational state, not new Aura canonical wires.
use super::*;
use aura_bitcoin_v1::{validate_anchor_outputs_v1, BitcoinOutputV1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};

/// Preserve Core's error code through the host's existing authenticated transport.
/// Only -5 (unknown wallet/mempool transaction) is an absence; all other failures
/// fail closed. RPC messages never determine Aura authorization or economic state.
#[derive(Debug)]
pub struct MinerCoreRpcErrorV1 {
    pub code: i64,
    pub message: String,
}
impl fmt::Display for MinerCoreRpcErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bitcoin Core {}: {}", self.code, self.message)
    }
}
impl std::error::Error for MinerCoreRpcErrorV1 {}

#[derive(Clone, Copy, Debug)]
pub struct MinerPaymentPolicyV1 {
    pub fee_rate_sat_vb: u64,
    pub max_fee_satoshis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MinerPaymentV1 {
    pub attempt_id: i64,
    pub revision: u32,
    pub txid: String,
    pub transaction_hex: String,
    pub fee_satoshis: u64,
    pub virtual_size: u64,
    pub anchor_output_index: usize,
    pub reward_output_index: usize,
    change_script: String,
    // Detect storage corruption before RPC. This is not a proof/payment identity.
    transaction_checksum: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum MinerPaymentObservationV1 {
    Unbroadcast {
        observed_tip: String,
    },
    Pending {
        txid: String,
        observed_tip: String,
    },
    Included {
        txid: String,
        observed_tip: String,
        block_hash: String,
        block_height: u64,
        confirmations: u64,
    },
    Confirmed {
        txid: String,
        observed_tip: String,
        block_hash: String,
        block_height: u64,
        confirmations: u64,
    },
    RecoveryRequired {
        observed_tip: String,
        reason: String,
    },
}
impl MinerPaymentObservationV1 {
    fn txid(&self) -> Option<&str> {
        match self {
            Self::Pending { txid, .. }
            | Self::Included { txid, .. }
            | Self::Confirmed { txid, .. } => Some(txid),
            _ => None,
        }
    }
    fn confirmed(&self) -> bool {
        matches!(self, Self::Included { .. } | Self::Confirmed { .. })
    }
}

fn hex(v: &Value) -> AuthorizationResultV2<String> {
    let s = v.as_str().ok_or("Core hex is not a string")?;
    raw(s)?;
    Ok(s.into())
}
fn raw(s: &str) -> AuthorizationResultV2<Vec<u8>> {
    if s.is_empty()
        || s.len() > 4_000_000
        || s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid or oversized Bitcoin transaction/script hex".into());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<_, _>>()?)
}
fn hash(v: &Value) -> AuthorizationResultV2<String> {
    let s = v.as_str().ok_or("Core hash is not a string")?;
    decode_hex_v2::<32>(s)?;
    Ok(s.into())
}
fn integer(v: &Value) -> AuthorizationResultV2<u64> {
    v.as_u64()
        .ok_or_else(|| "invalid Core unsigned integer".into())
}
fn btc(s: u64) -> AuthorizationResultV2<Value> {
    Ok(serde_json::from_str(&format!(
        "{}.{:08}",
        s / 100_000_000,
        s % 100_000_000
    ))?)
}
fn absent(result: AuthorizationResultV2<Value>) -> AuthorizationResultV2<Option<Value>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(e)
            if e.downcast_ref::<MinerCoreRpcErrorV1>()
                .is_some_and(|e| e.code == -5) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
fn obligation(
    c: &Connection,
    network: BitcoinNetworkV1,
    id: i64,
) -> AuthorizationResultV2<MinerRewardObligationV1> {
    let n: String = c.query_row(
        "SELECT round_number FROM miner_rewards WHERE attempt_id=?1",
        [id],
        |r| r.get(0),
    )?;
    let round = read_round(
        c,
        network,
        super::super::super::head::canonical_sequence_v2(&n)?,
    )?;
    check_round(c, network, &round)?;
    let a = EconomicJournalV1::attempt(c, network, id)?;
    if round.state != MinerRoundStateV1::Accepted || round.attempt_id != Some(id) {
        return Err("publication requires unique Accepted winner".into());
    }
    Ok(MinerRewardObligationV1 {
        round,
        receipt: a.terminal.ok_or("missing accepted receipt")?,
        authorization: a.auth,
    })
}
fn request(o: &MinerRewardObligationV1) -> AuthorizationResultV2<BitcoinAnchorRequestV1> {
    Ok(BitcoinAnchorRequestV1::new(
        o.round.job.network,
        o.authorization.proof_hash_hex.clone(),
    )?)
}
fn reward_script(o: &MinerRewardObligationV1) -> AuthorizationResultV2<Vec<u8>> {
    output_key_script(decode_hex_v2::<32>(
        &o.authorization.authorization_lineage.subject_binding,
    )?)
}

fn output_key_script(key: [u8; 32]) -> AuthorizationResultV2<Vec<u8>> {
    secp256k1::XOnlyPublicKey::from_byte_array(key)?;
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&key);
    Ok(script)
}
fn output_key_address(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    key: [u8; 32],
) -> AuthorizationResultV2<(String, String)> {
    let script = crate::authorization::encode_hex_v2(&output_key_script(key)?);
    let address = rpc("decodescript", json!([script]))?["address"]
        .as_str()
        .ok_or("Core cannot address exact miner output key")?
        .to_string();
    if rpc("validateaddress", json!([address]))?["scriptPubKey"] != script {
        return Err("miner address changes output-key script".into());
    }
    Ok((script, address))
}

/// Before a winner is known, an unsigned template with the operator's same-size
/// output-key script checks Core's current dust/funding/fee policy. It is never
/// signed, persisted as a payment, or broadcast. Actual winner outputs are checked
/// independently during publication. No production fee rate is inferred.
pub(super) fn funding_preflight(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    job: &MinerJobV1,
    txid: &str,
    vout: u32,
    fee_rate: u64,
    fee_budget: u64,
) -> AuthorizationResultV2<()> {
    if fee_rate == 0 {
        return Err("explicit positive preflight fee rate required".into());
    }
    let (_, address) = output_key_address(rpc, job.operator_key)?;
    let anchor = BitcoinAnchorRequestV1::new(job.network, "00".repeat(32))?;
    let payload = crate::authorization::encode_hex_v2(&anchor.script_pubkey()[2..]);
    let funded = rpc(
        "walletcreatefundedpsbt",
        json!([[{"txid":txid,"vout":vout,"sequence":0xffff_fffdu32}],
        [{"data":payload},{(address):btc(job.reward_satoshis)?}],0,{"add_inputs":false,"include_unsafe":false,"minconf":1,"replaceable":true,"fee_rate":fee_rate}]),
    )?;
    if !funded["psbt"].is_string() || funding::sats(&funded["fee"])? > fee_budget {
        return Err("reward preflight exceeds reserved fee budget".into());
    }
    Ok(())
}

fn enabled(c: &Connection) -> AuthorizationResultV2<bool> {
    let n:u8=c.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('miner_payment_versions','miner_payment_observations')",[],|r|r.get(0))?;
    match n {
        0 => Ok(false),
        2 => Ok(true),
        _ => Err("partial miner payment schema".into()),
    }
}
fn versions(c: &Connection, id: i64) -> AuthorizationResultV2<Vec<MinerPaymentV1>> {
    let rows=c.prepare("SELECT revision,txid,payment FROM miner_payment_versions WHERE attempt_id=?1 ORDER BY revision")?.query_map([id],|r|Ok((r.get::<_,u32>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = Vec::new();
    for (index, (revision, txid, wire)) in rows.into_iter().enumerate() {
        let p: MinerPaymentV1 = serde_json::from_str(&wire)?;
        let bytes = raw(&p.transaction_hex)?;
        raw(&p.change_script)?;
        decode_hex_v2::<32>(&p.txid)?;
        if p.attempt_id != id
            || p.revision != revision
            || usize::try_from(revision)? != index + 1
            || p.txid != txid
            || p.fee_satoshis == 0
            || p.virtual_size == 0
            || p.anchor_output_index == p.reward_output_index
            || crate::authorization::encode_hex_v2(&Sha256::digest(bytes)) != p.transaction_checksum
        {
            return Err("corrupt miner payment record".into());
        }
        out.push(p);
    }
    Ok(out)
}
pub(super) fn audit(c: &Connection, network: BitcoinNetworkV1) -> AuthorizationResultV2<()> {
    if !enabled(c)? {
        return Ok(());
    }
    let ids=c.prepare("SELECT DISTINCT attempt_id FROM miner_payment_versions
        UNION SELECT attempt_id FROM miner_payment_observations
        UNION SELECT o.attempt_id FROM economic_outbox o JOIN miner_rewards r ON r.attempt_id=o.attempt_id WHERE o.txid IS NOT NULL")?.query_map([],|r|r.get::<_,i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for id in ids {
        let o = obligation(c, network, id)?;
        let all = versions(c, id)?;
        if all.is_empty() {
            return Err("payment observation without persisted transaction".into());
        }
        let mut previous_fee = 0;
        let mut change = None;
        for p in &all {
            if p.fee_satoshis <= previous_fee
                || p.fee_satoshis > o.round.funding.fee_budget_satoshis()
                || change.as_ref().is_some_and(|s| s != &p.change_script)
            {
                return Err("payment replacement history mismatch".into());
            }
            previous_fee = p.fee_satoshis;
            change = Some(p.change_script.clone());
        }
        let published: Option<String> = c.query_row(
            "SELECT txid FROM economic_outbox WHERE attempt_id=?1",
            [id],
            |r| r.get(0),
        )?;
        if published
            .as_ref()
            .is_some_and(|t| !all.iter().any(|p| &p.txid == t))
        {
            return Err("miner outbox references unknown payment".into());
        }
        let observation: Option<String> = c
            .query_row(
                "SELECT observation FROM miner_payment_observations WHERE attempt_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(wire) = observation {
            let obs: MinerPaymentObservationV1 = serde_json::from_str(&wire)?;
            validate_observation(&obs)?;
            if obs.txid().is_some_and(|t| {
                !all.iter().any(|p| p.txid == t) || published.as_deref() != Some(t)
            }) {
                return Err("observation/payment/outbox mismatch".into());
            }
        } else if published.is_some() {
            return Err("published miner outbox missing its observation".into());
        }
    }
    Ok(())
}

fn validate_observation(obs: &MinerPaymentObservationV1) -> AuthorizationResultV2<()> {
    let tip = match obs {
        MinerPaymentObservationV1::Unbroadcast { observed_tip }
        | MinerPaymentObservationV1::Pending { observed_tip, .. }
        | MinerPaymentObservationV1::RecoveryRequired { observed_tip, .. } => observed_tip,
        MinerPaymentObservationV1::Included {
            observed_tip,
            block_hash,
            confirmations,
            ..
        }
        | MinerPaymentObservationV1::Confirmed {
            observed_tip,
            block_hash,
            confirmations,
            ..
        } => {
            decode_hex_v2::<32>(block_hash)?;
            if *confirmations == 0 {
                return Err("invalid stored confirmation depth".into());
            }
            observed_tip
        }
    };
    decode_hex_v2::<32>(tip)?;
    if let Some(txid) = obs.txid() {
        decode_hex_v2::<32>(txid)?;
    }
    Ok(())
}

fn chain(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    network: BitcoinNetworkV1,
) -> AuthorizationResultV2<Value> {
    funding::check_network(rpc, network)?;
    let info = rpc("getblockchaininfo", json!([]))?;
    hash(&info["bestblockhash"])?;
    integer(&info["blocks"])?;
    Ok(info)
}
fn check_policy(o: &MinerRewardObligationV1, p: MinerPaymentPolicyV1) -> AuthorizationResultV2<()> {
    if p.fee_rate_sat_vb == 0
        || p.max_fee_satoshis == 0
        || p.max_fee_satoshis > o.round.funding.fee_budget_satoshis()
    {
        return Err("explicit fee rate/ceiling must fit reserved budget".into());
    }
    Ok(())
}
fn decoded_outputs(decoded: &Value) -> AuthorizationResultV2<Vec<BitcoinOutputV1>> {
    decoded["vout"]
        .as_array()
        .ok_or("Core output list missing")?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if integer(&v["n"])? != u64::try_from(i)? {
                return Err("Core output index mismatch".into());
            }
            Ok(BitcoinOutputV1 {
                value_sat: funding::sats(&v["value"])?,
                script_pubkey: raw(&hex(&v["scriptPubKey"]["hex"])?)?,
            })
        })
        .collect()
}

/// Inspect actual Core-decoded transaction and all wallet input parents, not a
/// caller-supplied output/fee summary. Only exact reward, anchor and wallet change.
fn check_transaction(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    o: &MinerRewardObligationV1,
    raw_hex: &str,
    change_script: &str,
    max_fee: u64,
    revision: u32,
) -> AuthorizationResultV2<MinerPaymentV1> {
    let bytes = raw(raw_hex)?;
    let decoded = rpc("decoderawtransaction", json!([raw_hex]))?;
    let txid = hash(&decoded["txid"])?;
    let vsize = integer(&decoded["vsize"])?;
    let outputs = decoded_outputs(&decoded)?;
    let anchor = validate_anchor_outputs_v1(&outputs, &request(o)?)?;
    let script = reward_script(o)?;
    let change = raw(change_script)?;
    let mut reward = None;
    let mut changes = 0;
    let mut output_value = 0u64;
    for (i, out) in outputs.iter().enumerate() {
        output_value = output_value
            .checked_add(out.value_sat)
            .ok_or("output value overflow")?;
        if i == anchor {
            continue;
        }
        if out.script_pubkey == script {
            if reward.replace(i).is_some() || out.value_sat != o.round.job.reward_satoshis {
                return Err("incorrect or duplicated miner reward".into());
            }
        } else if out.script_pubkey == change {
            changes += 1;
            if changes > 1 {
                return Err("duplicated change output".into());
            }
        } else {
            return Err("unapproved payment output".into());
        }
    }
    let reward = reward.ok_or("missing exact miner reward")?;
    let mut inputs = HashSet::new();
    let mut reserved = false;
    let mut input_value = 0u64;
    for input in decoded["vin"].as_array().ok_or("missing payment inputs")? {
        let parent = hash(&input["txid"])?;
        let index = u32::try_from(integer(&input["vout"])?)?;
        if !inputs.insert((parent.clone(), index)) || integer(&input["sequence"])? >= 0xffff_fffe {
            return Err("duplicate or non-replaceable payment input".into());
        }
        let parent_tx = rpc("gettransaction", json!([parent]))?;
        let decoded_parent = rpc("decoderawtransaction", json!([hex(&parent_tx["hex"])?]))?;
        if hash(&decoded_parent["txid"])? != parent {
            return Err("payment input parent mismatch".into());
        }
        let parents = decoded_outputs(&decoded_parent)?;
        let prev = parents
            .get(usize::try_from(index)?)
            .ok_or("payment input index missing")?;
        input_value = input_value
            .checked_add(prev.value_sat)
            .ok_or("input value overflow")?;
        if parent == o.round.funding.txid() && index == o.round.funding.vout() {
            if prev.value_sat != o.round.funding.value_satoshis() {
                return Err("reserved outpoint value mismatch".into());
            }
            reserved = true;
        }
    }
    if !reserved {
        return Err("payment does not spend reserved reward outpoint".into());
    }
    let fee = input_value
        .checked_sub(output_value)
        .ok_or("payment creates Bitcoin value")?;
    if fee == 0 || fee > max_fee || fee > o.round.funding.fee_budget_satoshis() || vsize == 0 {
        return Err("payment fee exceeds ceiling/reservation or invalid size".into());
    }
    Ok(MinerPaymentV1 {
        attempt_id: o.receipt.attempt_id,
        revision,
        txid,
        transaction_hex: raw_hex.into(),
        fee_satoshis: fee,
        virtual_size: vsize,
        anchor_output_index: anchor,
        reward_output_index: reward,
        change_script: change_script.into(),
        transaction_checksum: crate::authorization::encode_hex_v2(&Sha256::digest(bytes)),
    })
}
fn recheck(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    o: &MinerRewardObligationV1,
    p: &MinerPaymentV1,
) -> AuthorizationResultV2<()> {
    if check_transaction(
        rpc,
        o,
        &p.transaction_hex,
        &p.change_script,
        o.round.funding.fee_budget_satoshis(),
        p.revision,
    )? != *p
    {
        return Err("persisted payment differs from Core transaction".into());
    }
    Ok(())
}
fn sign_psbt(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    psbt: &Value,
) -> AuthorizationResultV2<String> {
    if !psbt.is_string() {
        return Err("Core PSBT missing".into());
    }
    let signed = rpc("walletprocesspsbt", json!([psbt, true, "ALL"]))?;
    let final_tx = rpc("finalizepsbt", json!([signed["psbt"]]))?;
    if final_tx["complete"] != true {
        return Err("miner payment signing incomplete".into());
    }
    hex(&final_tx["hex"])
}
fn persist(c: &Connection, p: &MinerPaymentV1) -> AuthorizationResultV2<()> {
    c.execute(
        "INSERT INTO miner_payment_versions VALUES(?1,?2,?3,?4)",
        params![p.attempt_id, p.revision, p.txid, serde_json::to_string(p)?],
    )?;
    Ok(())
}
fn save_observation(
    c: &Connection,
    id: i64,
    o: &MinerPaymentObservationV1,
) -> AuthorizationResultV2<()> {
    c.execute("INSERT INTO miner_payment_observations VALUES(?1,?2) ON CONFLICT(attempt_id) DO UPDATE SET observation=excluded.observation",params![id,serde_json::to_string(o)?])?;
    if let Some(txid) = o.txid() {
        if c.execute(
            "UPDATE economic_outbox SET txid=?1 WHERE attempt_id=?2",
            params![txid, id],
        )? != 1
        {
            return Err("reward missing anchor outbox".into());
        }
    }
    Ok(())
}

fn restore_wallet_lock(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    funding: &MinerFundingReservationV1,
) -> AuthorizationResultV2<()> {
    let locks = rpc("listlockunspent", json!([]))?;
    if !locks
        .as_array()
        .ok_or("invalid wallet lock list")?
        .iter()
        .any(|v| v["txid"] == funding.txid() && v["vout"] == funding.vout())
        && rpc(
            "lockunspent",
            json!([false,[{"txid":funding.txid(),"vout":funding.vout()}]]),
        )? != true
    {
        return Err("cannot restore funding lock".into());
    }
    Ok(())
}

fn observe(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    o: &MinerRewardObligationV1,
    all: &[MinerPaymentV1],
    confirmations: u32,
) -> AuthorizationResultV2<MinerPaymentObservationV1> {
    if confirmations == 0 {
        return Err("explicit positive confirmation threshold required".into());
    }
    let before = chain(rpc, o.round.job.network)?;
    let tip = hash(&before["bestblockhash"])?;
    let height = integer(&before["blocks"])?;
    let mut confirmed = None;
    let mut pending = None;
    for p in all {
        recheck(rpc, o, p)?;
        if let Some(wallet) = absent(rpc("gettransaction", json!([p.txid])))? {
            if hex(&wallet["hex"])? != p.transaction_hex {
                return Err("wallet payment differs from persisted transaction".into());
            }
            let count = wallet["confirmations"]
                .as_i64()
                .ok_or("invalid wallet confirmation count")?;
            if count > 0 {
                let block = hash(&wallet["blockhash"])?;
                let header = rpc("getblockheader", json!([block]))?;
                let h = integer(&header["height"])?;
                if h > height
                    || header["confirmations"].as_i64().unwrap_or(0) < 1
                    || rpc("getblockhash", json!([h]))? != block
                {
                    return Err("payment block no longer active; retry observation".into());
                }
                let included = rpc("getrawtransaction", json!([p.txid, true, block]))?;
                if included["txid"] != p.txid || included["hex"] != p.transaction_hex {
                    return Err("payment inclusion mismatch".into());
                }
                let n = height - h + 1;
                let obs = if n >= confirmations.into() {
                    MinerPaymentObservationV1::Confirmed {
                        txid: p.txid.clone(),
                        observed_tip: tip.clone(),
                        block_hash: block,
                        block_height: h,
                        confirmations: n,
                    }
                } else {
                    MinerPaymentObservationV1::Included {
                        txid: p.txid.clone(),
                        observed_tip: tip.clone(),
                        block_hash: block,
                        block_height: h,
                        confirmations: n,
                    }
                };
                if confirmed.replace(obs).is_some() {
                    return Err("conflicting payments both reported confirmed".into());
                }
            }
        }
        if absent(rpc("getmempoolentry", json!([p.txid])))?.is_some() {
            if pending.replace(p.txid.clone()).is_some() {
                return Err("conflicting payments both in mempool".into());
            }
        }
    }
    let result = if let Some(c) = confirmed {
        c
    } else if let Some(txid) = pending {
        MinerPaymentObservationV1::Pending {
            txid,
            observed_tip: tip.clone(),
        }
    } else {
        let live = rpc(
            "gettxout",
            json!([o.round.funding.txid(), o.round.funding.vout(), true]),
        )?;
        if !live.is_null()
            && integer(&live["confirmations"])? > 0
            && funding::sats(&live["value"])? == o.round.funding.value_satoshis()
        {
            restore_wallet_lock(rpc, &o.round.funding)?;
            MinerPaymentObservationV1::Unbroadcast {
                observed_tip: tip.clone(),
            }
        } else {
            MinerPaymentObservationV1::RecoveryRequired{observed_tip:tip.clone(),reason:"reserved outpoint unavailable without a known active payment; reconcile spend/reorg".into()}
        }
    };
    if hash(&chain(rpc, o.round.job.network)?["bestblockhash"])? != tip {
        return Err("Bitcoin tip changed; retry observation".into());
    }
    Ok(result)
}

impl EconomicJournalV1 {
    pub fn install_miner_publication(&mut self) -> AuthorizationResultV2<()> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::audit(&tx, self.network)?;
        control(&tx)?;
        tx.execute_batch("CREATE TABLE miner_payment_versions(attempt_id INTEGER NOT NULL REFERENCES miner_rewards(attempt_id),revision INTEGER NOT NULL CHECK(revision>0),txid TEXT UNIQUE NOT NULL,payment TEXT NOT NULL,PRIMARY KEY(attempt_id,revision));
          CREATE TABLE miner_payment_observations(attempt_id INTEGER PRIMARY KEY REFERENCES miner_rewards(attempt_id),observation TEXT NOT NULL);")?;
        tx.commit()?;
        Ok(())
    }
    pub fn miner_payments(&self, id: i64) -> AuthorizationResultV2<Vec<MinerPaymentV1>> {
        let tx = self.authorizer.connection.unchecked_transaction()?;
        audit(&tx, self.network)?;
        obligation(&tx, self.network, id)?;
        let p = versions(&tx, id)?;
        tx.commit()?;
        Ok(p)
    }
    /// Idempotent preparation. Persist signed bytes before ANY broadcast. Changed
    /// fee settings on retry do not create a new payment; replacement is explicit.
    pub fn prepare_miner_payment(
        &mut self,
        id: i64,
        policy: MinerPaymentPolicyV1,
        mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    ) -> AuthorizationResultV2<MinerPaymentV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let o = obligation(&tx, self.network, id)?;
        check_policy(&o, policy)?;
        audit(&tx, self.network)?;
        if let Some(p) = versions(&tx, id)?.last() {
            return Ok(p.clone());
        }
        chain(&mut rpc, self.network)?;
        let live = rpc(
            "gettxout",
            json!([o.round.funding.txid(), o.round.funding.vout(), true]),
        )?;
        if live.is_null()
            || integer(&live["confirmations"])? == 0
            || funding::sats(&live["value"])? != o.round.funding.value_satoshis()
        {
            return Err(
                "reserved funding is no longer available; no replacement funding permitted".into(),
            );
        }
        restore_wallet_lock(&mut rpc, &o.round.funding)?;
        let (payout, address) = output_key_address(
            &mut rpc,
            decode_hex_v2(&o.authorization.authorization_lineage.subject_binding)?,
        )?;
        let change = rpc("getrawchangeaddress", json!(["bech32m"]))?;
        let change_info = rpc("getaddressinfo", json!([change]))?;
        if change_info["ismine"] != true {
            return Err("change is not owned by sponsor wallet".into());
        }
        let change_script = hex(&change_info["scriptPubKey"])?;
        if change_script == payout {
            return Err("reward and wallet change script coincide".into());
        }
        let anchor = crate::authorization::encode_hex_v2(&request(&o)?.script_pubkey()[2..]);
        let funded = rpc(
            "walletcreatefundedpsbt",
            json!([[{"txid":o.round.funding.txid(),"vout":o.round.funding.vout(),"sequence":0xffff_fffdu32}],
            [{"data":anchor},{(address):btc(o.round.job.reward_satoshis)?}],0,{"add_inputs":false,"include_unsafe":false,"minconf":1,"replaceable":true,"fee_rate":policy.fee_rate_sat_vb,"changeAddress":change}]),
        )?;
        let raw_hex = sign_psbt(&mut rpc, &funded["psbt"])?;
        let p = check_transaction(
            &mut rpc,
            &o,
            &raw_hex,
            &change_script,
            policy.max_fee_satoshis,
            1,
        )?;
        if funding::sats(&funded["fee"])? != p.fee_satoshis {
            return Err("Core funding fee mismatch".into());
        }
        persist(&tx, &p)?;
        tx.commit()?;
        Ok(p)
    }
    pub fn observe_miner_payment(
        &mut self,
        id: i64,
        confirmations: u32,
        mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    ) -> AuthorizationResultV2<MinerPaymentObservationV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let o = obligation(&tx, self.network, id)?;
        audit(&tx, self.network)?;
        let all = versions(&tx, id)?;
        if all.is_empty() {
            return Err("no persisted miner payment".into());
        }
        let obs = observe(&mut rpc, &o, &all, confirmations)?;
        save_observation(&tx, id, &obs)?;
        tx.commit()?;
        Ok(obs)
    }
    /// Broadcast only stored/revalidated bytes. A crash after Core accepted them
    /// but before this commit is recovered by observing the same known txids.
    pub fn publish_miner_payment(
        &mut self,
        id: i64,
        confirmations: u32,
        mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    ) -> AuthorizationResultV2<MinerPaymentObservationV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let o = obligation(&tx, self.network, id)?;
        audit(&tx, self.network)?;
        let all = versions(&tx, id)?;
        let current = all
            .last()
            .ok_or("prepare and persist payment before broadcasting")?;
        let mut obs = observe(&mut rpc, &o, &all, confirmations)?;
        if !obs.confirmed() && obs.txid() != Some(&current.txid) {
            if matches!(obs, MinerPaymentObservationV1::RecoveryRequired { .. }) {
                save_observation(&tx, id, &obs)?;
                tx.commit()?;
                return Ok(obs);
            }
            let acceptance = rpc("testmempoolaccept", json!([[current.transaction_hex]]))?;
            let a = acceptance
                .as_array()
                .filter(|v| v.len() == 1)
                .ok_or("invalid Core acceptance response")?;
            if a[0]["txid"] != current.txid
                || a[0]["allowed"] != true
                || funding::sats(&a[0]["fees"]["base"])? != current.fee_satoshis
            {
                return Err("miner payment not mempool acceptable or fee mismatch".into());
            }
            if rpc("sendrawtransaction", json!([current.transaction_hex]))? != current.txid {
                return Err("miner broadcast txid mismatch".into());
            }
            obs = observe(&mut rpc, &o, &all, confirmations)?;
        }
        save_observation(&tx, id, &obs)?;
        tx.commit()?;
        Ok(obs)
    }
    /// Explicit fee replacement only. Core builds a conflicting PSBT; revalidation
    /// preserves original reserved input, exact reward/anchor and sponsor change.
    pub fn replace_miner_payment(
        &mut self,
        id: i64,
        expected_txid: &str,
        policy: MinerPaymentPolicyV1,
        mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    ) -> AuthorizationResultV2<MinerPaymentV1> {
        decode_hex_v2::<32>(expected_txid)?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let o = obligation(&tx, self.network, id)?;
        check_policy(&o, policy)?;
        audit(&tx, self.network)?;
        let all = versions(&tx, id)?;
        let old = all.last().ok_or("no existing miner payment")?;
        if old.txid != expected_txid {
            return Err("stale payment replacement; inspect durable history".into());
        }
        let obs = observe(&mut rpc, &o, &all, 1)?;
        if !matches!(&obs,MinerPaymentObservationV1::Pending{txid,..} if txid==expected_txid) {
            return Err("replacement requires current known unconfirmed payment".into());
        }
        let bumped = rpc(
            "psbtbumpfee",
            json!([old.txid,{"fee_rate":policy.fee_rate_sat_vb,"replaceable":true}]),
        )?;
        if bumped["errors"].as_array().is_some_and(|e| !e.is_empty()) {
            return Err("Core fee replacement rejected".into());
        }
        let raw_hex = sign_psbt(&mut rpc, &bumped["psbt"])?;
        let p = check_transaction(
            &mut rpc,
            &o,
            &raw_hex,
            &old.change_script,
            policy.max_fee_satoshis,
            old.revision
                .checked_add(1)
                .ok_or("payment revision exhausted")?,
        )?;
        if p.fee_satoshis <= old.fee_satoshis
            || u128::from(p.fee_satoshis) * u128::from(old.virtual_size)
                <= u128::from(old.fee_satoshis) * u128::from(p.virtual_size)
            || funding::sats(&bumped["fee"])? != p.fee_satoshis
        {
            return Err("replacement does not increase exact fee/rate".into());
        }
        persist(&tx, &p)?;
        tx.commit()?;
        Ok(p)
    }
}

#[cfg(test)]
mod tests;
