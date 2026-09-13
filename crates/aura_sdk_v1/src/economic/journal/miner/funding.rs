//! Trusted Bitcoin Core wallet adapter for reserving one explicitly selected
//! sponsor outpoint. RPC transport/authentication stays with the host service.
//! M5 adds an unsigned wallet-policy preflight. Publication owns actual payments.
use super::*;
use serde_json::{json, Value};

pub(in crate::economic::journal) const MAX_SATOSHIS: u64 = 2_100_000_000_000_000;

/// Internal operational evidence, not a protocol wire or a trustless funding proof.
/// Constructed by the Core check below, never from a candidate's `funded=true`.
#[derive(Clone, Debug)]
pub struct MinerFundingReservationV1(StoredFunding);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFunding {
    network: BitcoinNetworkV1,
    txid: String,
    vout: u32,
    value_satoshis: u64,
    reward_satoshis: u64,
    fee_budget_satoshis: u64,
}
impl MinerFundingReservationV1 {
    pub(super) fn storage(&self) -> AuthorizationResultV2<String> {
        Ok(serde_json::to_string(&self.0)?)
    }
    pub(super) fn from_storage(s: &str) -> AuthorizationResultV2<Self> {
        Ok(Self(serde_json::from_str(s)?))
    }
    pub fn txid(&self) -> &str {
        &self.0.txid
    }
    pub fn vout(&self) -> u32 {
        self.0.vout
    }
    pub fn value_satoshis(&self) -> u64 {
        self.0.value_satoshis
    }
    pub fn fee_budget_satoshis(&self) -> u64 {
        self.0.fee_budget_satoshis
    }
    pub(super) fn validate(&self, job: &MinerJobV1) -> AuthorizationResultV2<()> {
        decode_hex_v2::<32>(&self.0.txid)?;
        if self.0.network != job.network
            || self.0.reward_satoshis != job.reward_satoshis
            || self.0.reward_satoshis == 0
            || self.0.fee_budget_satoshis == 0
            || self.0.value_satoshis > MAX_SATOSHIS
            || self
                .0
                .reward_satoshis
                .checked_add(self.0.fee_budget_satoshis)
                .filter(|v| *v <= self.0.value_satoshis)
                .is_none()
        {
            return Err("insufficient or mismatched miner reward/fee reservation".into());
        }
        Ok(())
    }
}

pub(in crate::economic::journal) fn sats(v: &Value) -> AuthorizationResultV2<u64> {
    // Parse Core's decimal amount without binary floating point or truncation.
    let n = v
        .as_number()
        .ok_or("Core amount is not numeric")?
        .to_string();
    let (mantissa, exponent) = n.split_once(['e', 'E']).unwrap_or((&n, "0"));
    let exponent: i32 = exponent.parse()?;
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || whole.len() + fraction.len() > 30
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid Core satoshi precision".into());
    }
    let digits: u128 = format!("{whole}{fraction}").parse()?;
    let shift = 8i32
        .checked_add(exponent)
        .and_then(|s| s.checked_sub(fraction.len() as i32))
        .ok_or("Core decimal exponent overflow")?;
    let s = if shift >= 0 {
        digits
            .checked_mul(
                10u128
                    .checked_pow(shift as u32)
                    .ok_or("Core decimal overflow")?,
            )
            .ok_or("Core amount overflow")?
    } else {
        let divisor = 10u128
            .checked_pow(shift.unsigned_abs())
            .ok_or("Core decimal underflow")?;
        if digits % divisor != 0 {
            return Err("Core amount has sub-satoshi precision".into());
        }
        digits / divisor
    };
    if s > MAX_SATOSHIS.into() {
        return Err("Core amount exceeds supply".into());
    }
    Ok(u64::try_from(s)?)
}

#[test]
fn core_amount_conversion_is_exact_including_exponents() {
    for (wire, expected) in [
        ("0.00000001", 1),
        ("1e-8", 1),
        ("0.00020000", 20_000),
        ("21000000", MAX_SATOSHIS),
    ] {
        assert_eq!(
            sats(&serde_json::from_str(wire).unwrap()).unwrap(),
            expected
        );
    }
    for wire in [
        "-1",
        "0.000000001",
        "0.000200001",
        "21000000.1",
        "1e100",
        "\"0.1\"",
    ] {
        assert!(
            sats(&serde_json::from_str(wire).unwrap()).is_err(),
            "{wire}"
        );
    }
}

/// Call inside `open_miner_round`'s trusted funding callback, with an explicitly
/// budgeted fee ceiling and wallet-policy-approved reward minimum. Core must be a
/// trusted wallet endpoint. A dishonest sponsor can still spend/withhold funds.
///
/// If the later SQLite commit fails, a conservative orphan wallet lock may remain.
/// Reconcile locks with durable rounds before unlocking; never auto-release after
/// an ambiguous commit. Wallet restarts require re-locking owned outpoints before
/// wallet spending/publication. These locks are not Bitcoin consensus reservations.
pub fn reserve_miner_funding_v1(
    mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    job: &MinerJobV1,
    txid: &str,
    vout: u32,
    fee_budget_satoshis: u64,
    fee_rate_sat_vb: u64,
) -> AuthorizationResultV2<MinerFundingReservationV1> {
    job.validate_shape()?;
    decode_hex_v2::<32>(txid)?;
    check_network(&mut rpc, job.network)?;
    let locks = rpc("listlockunspent", json!([]))?;
    let locks = locks.as_array().ok_or("invalid Core wallet lock list")?;
    if locks
        .iter()
        .any(|o| o["txid"].as_str() == Some(txid) && o["vout"].as_u64() == Some(vout.into()))
    {
        return Err("funding outpoint already wallet-reserved".into());
    }
    let coins = rpc("listunspent", json!([1]))?;
    let coins = coins.as_array().ok_or("invalid Core wallet coin list")?;
    let matches: Vec<_> = coins
        .iter()
        .filter(|o| o["txid"].as_str() == Some(txid) && o["vout"].as_u64() == Some(vout.into()))
        .collect();
    if matches.len() != 1 {
        return Err("dedicated funding coin missing or ambiguous".into());
    }
    let coin = matches[0];
    if coin["spendable"] != true
        || coin["solvable"] != true
        || coin["safe"] != true
        || coin["confirmations"].as_u64().unwrap_or(0) == 0
    {
        return Err("funding coin is not safe confirmed wallet spendable".into());
    }
    let reservation = MinerFundingReservationV1(StoredFunding {
        network: job.network,
        txid: txid.into(),
        vout,
        value_satoshis: sats(&coin["amount"])?,
        reward_satoshis: job.reward_satoshis,
        fee_budget_satoshis,
    });
    reservation.validate(job)?;
    // Include the mempool so an already-spent output cannot fund an open round.
    let live = rpc("gettxout", json!([txid, vout, true]))?;
    if live["confirmations"].as_u64().unwrap_or(0) == 0
        || sats(&live["value"])? != reservation.value_satoshis()
        || live["scriptPubKey"]["hex"] != coin["scriptPubKey"]
    {
        return Err("funding coin spent or inconsistent".into());
    }
    super::publication::funding_preflight(
        &mut rpc,
        job,
        txid,
        vout,
        fee_rate_sat_vb,
        fee_budget_satoshis,
    )?;
    if rpc("lockunspent", json!([false,[{"txid":txid,"vout":vout}]]))? != true {
        return Err("Core funding reservation failed".into());
    }
    Ok(reservation)
}

pub(in crate::economic::journal) fn check_network(
    rpc: &mut impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    network: BitcoinNetworkV1,
) -> AuthorizationResultV2<()> {
    let chain = match network {
        BitcoinNetworkV1::Mainnet => "main",
        BitcoinNetworkV1::Testnet3 => "test",
        BitcoinNetworkV1::Signet => "signet",
        BitcoinNetworkV1::Regtest => "regtest",
        BitcoinNetworkV1::Testnet4 => "testnet4",
    };
    if rpc("getblockchaininfo", json!([]))?["chain"].as_str() != Some(chain) {
        return Err("funding Core network mismatch".into());
    }
    Ok(())
}

impl EconomicJournalV1 {
    /// Idempotent wallet-lock cleanup after durable no-winner closure. Holding the
    /// journal transaction prevents a later round from acquiring this coin between
    /// the ownership check and unlock. Never unlock accepted or in-flight funding.
    pub fn release_miner_funding(
        &mut self,
        number: u64,
        mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    ) -> AuthorizationResultV2<()> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let r = read_round(&tx, self.network, number)?;
        check_round(&tx, self.network, &r)?;
        if !matches!(
            r.state,
            MinerRoundStateV1::Rejected | MinerRoundStateV1::Expired
        ) {
            return Err("cannot release live or accepted miner funding".into());
        }
        let owned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM miner_rounds WHERE funding_txid=?1 AND funding_vout=?2 AND state IN (0,1,2))",params![r.funding.txid(),r.funding.vout()],|row|row.get(0))?;
        if owned {
            return Err("funding has a later live owner".into());
        }
        super::super::funding_registry::no_compute_owner(&tx, r.funding.txid(), r.funding.vout())?;
        check_network(&mut rpc, self.network)?;
        let locks = rpc("listlockunspent", json!([]))?;
        let locks = locks.as_array().ok_or("invalid Core wallet lock list")?;
        if locks.iter().any(|o| {
            o["txid"].as_str() == Some(r.funding.txid())
                && o["vout"].as_u64() == Some(r.funding.vout().into())
        }) && rpc(
            "lockunspent",
            json!([true,[{"txid":r.funding.txid(),"vout":r.funding.vout()}]]),
        )? != true
        {
            return Err("Core funding release failed; retry after reconciliation".into());
        }
        tx.commit()?;
        Ok(())
    }
}
