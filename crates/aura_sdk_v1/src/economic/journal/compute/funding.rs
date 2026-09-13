//! Customer custody evidence from the existing trusted Core transport. No payment
//! construction or payout script selection. Amounts are not Aura balances.
use super::super::miner::funding::{check_network, sats, MAX_SATOSHIS};
use super::*;
use serde_json::{json, Value};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredFunding {
    job: [u8; 32],
    txid: String,
    vout: u32,
    value: u64,
    net: u64,
    fee: u64,
}
impl StoredFunding {
    pub(super) fn txid(&self) -> &str {
        &self.txid
    }
    pub(super) fn vout(&self) -> u32 {
        self.vout
    }
    pub(super) fn reserved_satoshis(&self) -> u128 {
        u128::from(self.net) + u128::from(self.fee)
    }
    pub(super) fn validate(
        &self,
        j: &AuraComputeJobV1,
        t: &ComputePaymentTermsV1,
    ) -> AuthorizationResultV2<()> {
        decode_hex_v2::<32>(&self.txid)?;
        if self.job != j.commitment()?
            || self.net != j.compensation_satoshis
            || self.fee != t.max_payment_fee_satoshis
            || self.value > MAX_SATOSHIS
            || self.reserved_satoshis() > u128::from(self.value)
        {
            return Err("compute backing does not cover signed net plus fee".into());
        }
        Ok(())
    }
}
/// Opaque verified backing. Cannot be constructed by deserializing client data.
/// ```compile_fail
/// use aura_sdk_v1::economic::journal::compute::funding::ComputeFundingV1;
/// let forged: ComputeFundingV1 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct ComputeFundingV1(StoredFunding);
impl ComputeFundingV1 {
    pub fn txid(&self) -> &str {
        self.0.txid()
    }
    pub fn vout(&self) -> u32 {
        self.0.vout()
    }
    pub fn reserved_satoshis(&self) -> u128 {
        self.0.reserved_satoshis()
    }
    pub(super) fn into_stored(self) -> StoredFunding {
        self.0
    }
}
/// Trusted service only. Select the customer's prefunded custody outpoint and an
/// explicit confirmation policy; caller identity/account attribution is a service
/// responsibility. Locks are operational, not trustless Bitcoin escrow.
/// Run inside assignment's callback. Ambiguous commits leave conservative locks;
/// never release them until journal ownership has been reconciled.
pub fn reserve_compute_funding_v1(
    mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    j: &AuraComputeJobV1,
    t: &ComputePaymentTermsV1,
    txid: &str,
    vout: u32,
    minimum_confirmations: u64,
) -> AuthorizationResultV2<ComputeFundingV1> {
    j.validate_shape()?;
    t.canonical_bytes()?;
    decode_hex_v2::<32>(txid)?;
    if minimum_confirmations == 0 {
        return Err("explicit positive funding confirmation policy required".into());
    }
    j.verify_content(ComputeContentKindV1::PaymentTerms, &t.canonical_bytes()?)?;
    check_network(&mut rpc, j.network)?;
    let locks = rpc("listlockunspent", json!([]))?;
    let locks = locks.as_array().ok_or("invalid wallet lock list")?;
    if locks
        .iter()
        .any(|x| x["txid"].as_str() == Some(txid) && x["vout"].as_u64() == Some(vout.into()))
    {
        return Err("compute backing already wallet locked".into());
    }
    let coins = rpc("listunspent", json!([minimum_confirmations]))?;
    let matches = coins
        .as_array()
        .ok_or("invalid custody coins")?
        .iter()
        .filter(|x| x["txid"].as_str() == Some(txid) && x["vout"].as_u64() == Some(vout.into()))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("customer custody coin missing or ambiguous".into());
    }
    let coin = matches[0];
    if coin["spendable"] != true
        || coin["solvable"] != true
        || coin["safe"] != true
        || coin["confirmations"].as_u64().unwrap_or(0) < minimum_confirmations
    {
        return Err("unsafe custody backing".into());
    }
    let script = coin["scriptPubKey"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("missing or malformed custody script")?;
    let f = StoredFunding {
        job: j.commitment()?,
        txid: txid.into(),
        vout,
        value: sats(&coin["amount"])?,
        net: j.compensation_satoshis,
        fee: t.max_payment_fee_satoshis,
    };
    f.validate(j, t)?;
    let live = rpc("gettxout", json!([txid, vout, true]))?;
    if live["confirmations"].as_u64().unwrap_or(0) < minimum_confirmations
        || sats(&live["value"])? != f.value
        || live["scriptPubKey"]["hex"].as_str() != Some(script)
    {
        return Err("spent or inconsistent compute backing".into());
    }
    if rpc("lockunspent", json!([false,[{"txid":txid,"vout":vout}]]))? != true {
        return Err("custody lock failed".into());
    }
    Ok(ComputeFundingV1(f))
}
impl EconomicJournalV1 {
    /// Release only unearned, terminal backing. No caller-supplied paid flag exists.
    pub fn release_compute_funding(
        &mut self,
        id: [u8; 32],
        mut rpc: impl FnMut(&str, Value) -> AuthorizationResultV2<Value>,
    ) -> AuthorizationResultV2<()> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cfg = config(&tx, self.network)?;
        let r = load(&tx, &id, &cfg)?;
        if !matches!(r.state, 4 | 5 | 6) {
            return Err("compute funding still reserved or earned".into());
        }
        if let Some(f) = r.funding {
            super::super::funding_registry::available(&tx, f.txid(), f.vout(), None)?;
            check_network(&mut rpc, self.network)?;
            let locks = rpc("listlockunspent", json!([]))?;
            let locks = locks.as_array().ok_or("invalid wallet locks")?;
            if locks.iter().any(|o| {
                o["txid"].as_str() == Some(f.txid()) && o["vout"].as_u64() == Some(f.vout().into())
            }) && rpc(
                "lockunspent",
                json!([true,[{"txid":f.txid(),"vout":f.vout()}]]),
            )? != true
            {
                return Err("custody release failed; reconcile and retry".into());
            }
        }
        tx.commit()?;
        Ok(())
    }
}
