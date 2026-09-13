//! One same-journal ownership check for external backing, not a balance ledger.
use super::*;
pub(super) fn table(c: &Connection, name: &str) -> AuthorizationResultV2<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}
pub(super) fn available(
    c: &Connection,
    txid: &str,
    vout: u32,
    except_compute: Option<&[u8]>,
) -> AuthorizationResultV2<()> {
    if table(c,"miner_rounds")? && c.query_row("SELECT EXISTS(SELECT 1 FROM miner_rounds WHERE funding_txid=?1 AND funding_vout=?2 AND state IN (0,1,2))",params![txid,vout],|r|r.get::<_,bool>(0))? {return Err("backing already owned by miner obligation".into());}
    if table(c,"compute_jobs")? && c.query_row("SELECT EXISTS(SELECT 1 FROM compute_jobs WHERE funding_txid=?1 AND funding_vout=?2 AND state IN (1,2,3) AND (?3 IS NULL OR id<>?3))",params![txid,vout,except_compute],|r|r.get::<_,bool>(0))? {return Err("backing already owned by compute obligation".into());}
    Ok(())
}
// Miner operations already check miner ownership; this additional guard preserves
// their existing behavior while excluding backing owned by the compute extension.
pub(super) fn no_compute_owner(c: &Connection, txid: &str, vout: u32) -> AuthorizationResultV2<()> {
    if table(c,"compute_jobs")? && c.query_row("SELECT EXISTS(SELECT 1 FROM compute_jobs WHERE funding_txid=?1 AND funding_vout=?2 AND state IN (1,2,3))",params![txid,vout],|r|r.get::<_,bool>(0))? {return Err("backing reserved for compute compensation".into());}
    Ok(())
}
