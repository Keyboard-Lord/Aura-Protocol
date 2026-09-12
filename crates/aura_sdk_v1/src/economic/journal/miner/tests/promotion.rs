//! M7 owner reconciliation: approved epoch order and post-snapshot challenge.
use super::*;

#[test]
fn policy_starts_at_zero_rotates_consecutively_and_audits_missing_history() {
    let file = File::new();
    let mut j = EconomicJournalV1::create(&file.0, NETWORK, &fixture().1.ledger, limits()).unwrap();
    let mut p = policy_value();
    p.job.policy_epoch = 1;
    assert!(j.install_miner_policy(&p).is_err());
    assert!(!enabled(&j.authorizer.connection).unwrap());
    p.job.policy_epoch = 0;
    j.install_miner_policy(&p).unwrap();
    for epoch in [0, 2, u64::MAX] {
        p.job.policy_epoch = epoch;
        assert!(j.update_miner_policy(&p).is_err());
        assert_eq!(control(&j.authorizer.connection).unwrap(), (0, 1));
    }
    for epoch in 1..=2 {
        p.job.policy_epoch = epoch;
        j.update_miner_policy(&p).unwrap();
    }
    drop(j);
    let j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(control(&j.authorizer.connection).unwrap(), (2, 1));
    j.authorizer.connection.execute("DELETE FROM miner_policies WHERE epoch='1'", []).unwrap();
    drop(j);
    assert!(EconomicJournalV1::open(&file.0, NETWORK, limits()).is_err());
}

#[test]
fn challenge_is_drawn_under_snapshot_lock_and_rng_failure_does_not_open_round() {
    let file = File::new();
    let mut j = EconomicJournalV1::create(&file.0, NETWORK, &fixture().1.ledger, limits()).unwrap();
    j.install_miner_policy(&policy_value()).unwrap();
    let other = rusqlite::Connection::open(&file.0).unwrap();
    other.busy_timeout(std::time::Duration::ZERO).unwrap();
    let result = j.open_round_with(&key(), opening(), |_| panic!("funding before entropy"), || {
        let error = other.execute_batch("BEGIN IMMEDIATE").unwrap_err();
        assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
        Err("entropy source unavailable".into())
    });
    assert!(result.unwrap_err().to_string().contains("entropy source"));
    assert_eq!(control(&j.authorizer.connection).unwrap(), (0, 1));
    assert!(active_round(&j.authorizer.connection).unwrap().is_none());
    let mut invalid = opening();
    invalid.duration_secs = 0;
    assert!(j.open_round_with(&key(), invalid, reserve, || panic!("invalid opening drew entropy")).is_err());
    let r = j.open_round_with(&key(), opening(), reserve, || {
        let error = other.execute_batch("BEGIN IMMEDIATE").unwrap_err();
        assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
        Ok((TIME, [88; 32]))
    }).unwrap();
    assert_eq!(r.job.challenge, [88; 32]);
    assert_eq!(r.job.opened_at, TIME);
    assert_eq!(r.job.prior_head_sequence, 0);
    assert_eq!(r.job.prior_head_hash, [0; 32]);
    assert_eq!(control(&j.authorizer.connection).unwrap(), (0, 2));
}
