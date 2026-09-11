use super::*;
use crate::{
    authorization::{encode_hex_v2, AuthorizationLineageV2},
    miner_search::{MinerLimitsV1, MinerSessionV1, MinerTrialV1},
};
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use secp256k1::SecretKey;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};

mod adversarial;
const TIME: u64 = 2_000_000_000;
const NETWORK: BitcoinNetworkV1 = BitcoinNetworkV1::Regtest;

fn limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: 100_000,
        max_meter_bytes: 90_000,
        max_iterations: 128,
    }
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn key() -> Keypair {
    let mut s = [0; 32];
    s[31] = 3;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_byte_array(s).unwrap())
}
fn fixture() -> (MinerJobV1, EconomicMeterV1) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../../../fixtures/miner_v1/job_profile_vector_v1.json"
    ))
    .unwrap();
    (
        MinerJobV1::decode(&unhex(v["job_hex"].as_str().unwrap())).unwrap(),
        EconomicMeterV1::decode(&unhex(v["meter_hex"].as_str().unwrap()), 90_000).unwrap(),
    )
}
fn policy_value() -> MinerRoundPolicyV1 {
    let (j, _) = fixture();
    let mut target = [255; 32];
    target[0] = 127;
    MinerRoundPolicyV1 {
        job: MinerJobPolicyV1 {
            network: NETWORK,
            operator_key: j.operator_key,
            journal_namespace: j.journal_namespace,
            policy_epoch: 0,
            iteration_count: 8,
            target,
            max_work_bytes: 100_000,
            max_meter_bytes: 90_000,
        },
        max_duration_secs: 600,
        minimum_reward_satoshis: 1000,
    }
}
fn opening() -> MinerRoundOpeningV1 {
    let (j, _) = fixture();
    MinerRoundOpeningV1 {
        side_a: j.side_a,
        side_b: j.side_b,
        duration_secs: 600,
        reward_satoshis: 10_000,
    }
}
struct File(PathBuf);
impl File {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "aura-m4-{}-{}.db",
            std::process::id(),
            encode_hex_v2(&fresh_nonce_v2().unwrap())
        )))
    }
}
impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn reserve(job: &MinerJobV1) -> AuthorizationResultV2<MinerFundingReservationV1> {
    funding::reserve_miner_funding_v1(
        |method, _| {
            Ok(match method {
                "getblockchaininfo" => json!({"chain":"regtest"}),
                "listlockunspent" => json!([]),
                "listunspent" => {
                    json!([{"txid":"77".repeat(32),"vout":0,"amount":0.0002,"spendable":true,"solvable":true,"safe":true,"confirmations":6,"scriptPubKey":"5120"}])
                }
                "gettxout" => {
                    json!({"value":0.0002,"confirmations":6,"scriptPubKey":{"hex":"5120"}})
                }
                "decodescript" => json!({"address":"test-payout"}),
                "validateaddress" => {
                    json!({"scriptPubKey":"5120".to_owned()+&encode_hex_v2(&job.operator_key)})
                }
                "walletcreatefundedpsbt" => json!({"psbt":"unsigned-test-template","fee":0.00001}),
                "lockunspent" => json!(true),
                _ => panic!("unexpected RPC"),
            })
        },
        job,
        &"77".repeat(32),
        0,
        5000,
        2,
    )
}
fn setup() -> (File, EconomicJournalV1, MinerRoundV1) {
    let file = File::new();
    let (_, m) = fixture();
    let mut j = EconomicJournalV1::create(&file.0, NETWORK, &m.ledger, limits()).unwrap();
    j.install_miner_policy(&policy_value()).unwrap();
    let r = j
        .open_round_at(&key(), opening(), reserve, TIME, [42; 32])
        .unwrap();
    (file, j, r)
}
fn candidate(
    r: &MinerRoundV1,
    meter: Option<EconomicMeterV1>,
    start: u64,
    qualifies: bool,
) -> MinerTrialV1 {
    let (_, m) = fixture();
    let m = meter.unwrap_or(m);
    let p = policy_value();
    let k = key();
    let session = MinerSessionV1::new(
        &r.job,
        &r.signature,
        &p.job,
        &m,
        &k,
        MinerLimitsV1 {
            work: limits(),
            max_proof_bytes: 1_000_000,
        },
    )
    .unwrap();
    // Fixed job, time, challenge and nonce schedule: deterministic, no randomness
    // or rare production target in CI. The fixture has both outcomes in this range.
    for index in start..start + 64 {
        let mut n = [12; 32];
        n[24..].copy_from_slice(&index.to_be_bytes());
        let t = session.trial(n, index).unwrap();
        if t.qualifies() == qualifies {
            return t;
        }
    }
    panic!("bounded deterministic fixture lacks requested outcome")
}
fn auth(work: &EconomicWorkV1, hash: [u8; 32]) -> AuthorizationEnvelopeV2 {
    let mut a = AuthorizationEnvelopeV2 {
        authorization_version: "v2".into(),
        proof_hash_hex: encode_hex_v2(&hash),
        signature_hex: "00".repeat(64),
        authorization_lineage: AuthorizationLineageV2 {
            subject_binding_type: "bip340-xonly-pubkey-hex".into(),
            subject_binding: encode_hex_v2(&work.subject()),
            intent_type: "opaque-intent-hash-32".into(),
            intent_commitment_hex: encode_hex_v2(&work.intent()),
            freshness_binding_type: "nonce-32-hex".into(),
            freshness_binding: encode_hex_v2(&work.nonce()),
        },
    };
    a.signature_hex = encode_hex_v2(
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&a.signing_digest(NETWORK).unwrap(), &key())
            .as_ref(),
    );
    a
}
fn consent(w: &EconomicWorkV1, a: &AuthorizationEnvelopeV2) -> EconomicConsentV1 {
    EconomicConsentV1 {
        economic_consent_version: "v1".into(),
        signature_hex: encode_hex_v2(
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(
                    &EconomicConsentV1::signing_digest(NETWORK, w, a).unwrap(),
                    &key(),
                )
                .as_ref(),
        ),
    }
}
fn admit(j: &mut EconomicJournalV1, t: &MinerTrialV1) -> EconomicAttemptStateV1 {
    let a = auth(t.work(), t.proof_hash());
    j.admit_at(
        &t.work().canonical_bytes().unwrap(),
        &consent(t.work(), &a),
        &a,
        TIME + 1,
    )
    .unwrap()
}
fn counts(j: &EconomicJournalV1) -> (i64, i64, i64, i64) {
    let c = &j.authorizer.connection;
    let count = |table: &str| {
        c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    };
    (
        count("economic_attempts"),
        count("authorizations"),
        count("economic_outbox"),
        count("miner_rewards"),
    )
}

#[test]
fn funded_open_pins_snapshot_and_restart_recovers_published_job() {
    let (file, mut j, r) = setup();
    assert_eq!(counts(&j), (0, 0, 0, 0));
    assert!(j
        .open_round_at(&key(), opening(), reserve, TIME, [43; 32])
        .is_err());
    assert!(j.update_miner_policy(&policy_value()).is_err());
    drop(j);
    let j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    let recovered = j.miner_round(1).unwrap();
    assert_eq!(
        r.job.canonical_bytes().unwrap(),
        recovered.job.canonical_bytes().unwrap()
    );
    assert_eq!(r.signature, recovered.signature);
    assert_eq!(recovered.state, MinerRoundStateV1::Open);
    assert_eq!(recovered.funding.value_satoshis(), 20_000);
}

#[test]
fn candidate_to_atomic_winner_retry_and_restart_without_double_burn() {
    let (file, mut j, r) = setup();
    let t = candidate(&r, None, 0, true);
    let id = admit(&mut j, &t).attempt_id();
    assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Admitted);
    assert_eq!(counts(&j), (1, 0, 0, 0));
    assert_eq!(admit(&mut j, &t).attempt_id(), id);
    assert_eq!(
        j.expire_round_at(1, TIME + 1000).unwrap().state,
        MinerRoundStateV1::Admitted
    );
    drop(j);
    let mut j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    let receipt = j.resume(id).unwrap();
    assert_eq!(receipt.outcome, EconomicOutcomeV1::Accepted);
    assert_eq!(counts(&j), (1, 1, 1, 1));
    assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Accepted);
    let obligations = j.miner_reward_obligations().unwrap();
    assert_eq!(obligations.len(), 1);
    assert_eq!(obligations[0].receipt, receipt);
    assert_eq!(
        obligations[0].authorization.proof_hash_hex,
        encode_hex_v2(&t.proof_hash())
    );
    assert_eq!(
        j.outbox().unwrap()[0].request.proof_hash_hex(),
        encode_hex_v2(&t.proof_hash())
    );
    assert!(j.record_publication(id, &"ab".repeat(32)).is_err());
    let a = auth(t.work(), t.proof_hash());
    let mut c = consent(t.work(), &a);
    c.signature_hex = encode_hex_v2(
        Secp256k1::new()
            .sign_schnorr_with_aux_rand(
                &EconomicConsentV1::signing_digest(NETWORK, t.work(), &a).unwrap(),
                &key(),
                &[77; 32],
            )
            .as_ref(),
    );
    assert_eq!(
        j.admit_at(&t.work().canonical_bytes().unwrap(), &c, &a, TIME + 1000)
            .unwrap(),
        EconomicAttemptStateV1::Terminal(receipt.clone())
    );
    drop(j);
    let mut j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(j.resume(id).unwrap(), receipt);
    assert_eq!(
        j.ledger_for_payer(t.work().subject())
            .unwrap()
            .burned_supply,
        t.work().burn_units().unwrap()
    );
    assert_eq!(counts(&j), (1, 1, 1, 1));
}

#[test]
fn fake_low_hash_is_chargeable_but_never_authorized_or_rewarded() {
    let (file, mut j, r) = setup();
    let w = r.job.build_work(fixture().1, [33; 32]).unwrap();
    let a = auth(&w, [0; 32]);
    let id = j
        .admit_at(
            &w.canonical_bytes().unwrap(),
            &consent(&w, &a),
            &a,
            TIME + 1,
        )
        .unwrap()
        .attempt_id();
    let receipt = j.resume(id).unwrap();
    assert_eq!(receipt.outcome, EconomicOutcomeV1::VerificationRejected);
    assert_eq!(counts(&j), (1, 0, 0, 0));
    assert_eq!(receipt.burn_units, w.burn_units().unwrap());
    assert_eq!(receipt.head.head_sequence_number, "1");
    assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Rejected);
    // Failed round releases the DB reservation: same sponsor outpoint can fund a
    // later round once its wallet lock is reconciled. Previous candidate is stale.
    let next = j
        .open_round_at(&key(), opening(), reserve, TIME + 2, [43; 32])
        .unwrap();
    assert_eq!(next.job.round_number, 2);
    let stale = r.job.build_work(fixture().1, [34; 32]).unwrap();
    let a = auth(&stale, [0; 32]);
    assert!(j
        .admit_at(
            &stale.canonical_bytes().unwrap(),
            &consent(&stale, &a),
            &a,
            TIME + 3
        )
        .is_err());
    drop(j);
    assert!(EconomicJournalV1::open(&file.0, NETWORK, limits()).is_ok());
}

#[test]
fn every_failure_class_retains_existing_burn_head_and_releases_reward() {
    for outcome in [
        EconomicOutcomeV1::ExecutionRejected,
        EconomicOutcomeV1::SettlementRejected,
    ] {
        let (file, mut j, r) = setup();
        let mut m = fixture().1;
        match outcome {
            EconomicOutcomeV1::ExecutionRejected => m.transactions[0].sender_nonce = u64::MAX,
            _ => m.wallet_binding.account_id = [9; 32],
        };
        let t = candidate(&r, Some(m), 0, true);
        let id = admit(&mut j, &t).attempt_id();
        let receipt = j.resume(id).unwrap();
        assert_eq!(receipt.outcome, outcome);
        assert_eq!(receipt.burn_units, t.work().burn_units().unwrap());
        assert_eq!(receipt.head.head_sequence_number, "1");
        assert_eq!(counts(&j), (1, 0, 0, 0));
        assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Rejected);
        drop(j);
        assert!(EconomicJournalV1::open(&file.0, NETWORK, limits()).is_ok());
    }
}

#[test]
fn preadmission_profile_signature_head_target_and_clock_failures_do_not_charge() {
    let (_file, mut j, r) = setup();
    let t = candidate(&r, None, 0, true);
    for case in 0..10 {
        let mut w = t.work().clone();
        let mut hash = t.proof_hash();
        let mut time = TIME + 1;
        match case {
            0 => w.storm.context_bytes_v1[177] ^= 1,
            1 => w.storm.context_bytes_v1[65] ^= 1,
            2 => w.storm.context_bytes_v1[97] ^= 1,
            3 => w.meter.head.previous_head_hash[0] ^= 1,
            4 => w.storm.side_a[0] ^= 1,
            5 => hash = [255; 32],
            6 => time = TIME + 600,
            7 => time = TIME - 1,
            8 => {
                w.meter.ledger.accounts[0].balance -= 1;
                w.meter.ledger.total_supply -= 1;
                w = r.job.build_work(w.meter.clone(), w.nonce()).unwrap();
            }
            _ => {}
        };
        let a = if case == 2 {
            auth(t.work(), hash)
        } else {
            auth(&w, hash)
        };
        let mut c = consent(if case == 2 { t.work() } else { &w }, &a);
        if case == 9 {
            c.signature_hex = "00".repeat(64);
        }
        assert!(
            j.admit_at(&w.canonical_bytes().unwrap(), &c, &a, time)
                .is_err(),
            "case {case}"
        );
        assert_eq!(counts(&j), (0, 0, 0, 0));
    }
    let above = candidate(&r, None, 0, false);
    let a = auth(above.work(), above.proof_hash());
    assert!(j
        .admit_at(
            &above.work().canonical_bytes().unwrap(),
            &consent(above.work(), &a),
            &a,
            TIME + 1
        )
        .is_err());
    assert!(j.expire_round_at(1, TIME + 599).is_err());
    assert_eq!(
        j.expire_round_at(1, TIME + 600).unwrap().state,
        MinerRoundStateV1::Expired
    );
    assert!(j
        .admit_at(
            &t.work().canonical_bytes().unwrap(),
            &consent(t.work(), &auth(t.work(), t.proof_hash())),
            &auth(t.work(), t.proof_hash()),
            TIME + 600
        )
        .is_err());
    assert_eq!(counts(&j), (0, 0, 0, 0));
    assert_eq!(
        j.prior_head().unwrap(),
        EconomicPriorHeadV1::Current(EconomicHeadV2::genesis())
    );
}

#[test]
fn concurrent_contenders_and_finalizers_have_one_owner() {
    let (file, j, r) = setup();
    let t1 = candidate(&r, None, 0, true);
    let t2 = candidate(&r, None, t1.trial_index() + 1, true);
    drop(j);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for t in [t1, t2] {
        let path = file.0.clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut j = EconomicJournalV1::open(&path, NETWORK, limits()).unwrap();
            let a = auth(t.work(), t.proof_hash());
            let c = consent(t.work(), &a);
            b.wait();
            j.admit_at(&t.work().canonical_bytes().unwrap(), &c, &a, TIME + 1)
                .map(|a| a.attempt_id())
        }));
    }
    let result: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(result.iter().filter(|r| r.is_ok()).count(), 1);
    let id = *result.iter().find_map(|r| r.as_ref().ok()).unwrap();
    let b = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = file.0.clone();
            let b = b.clone();
            std::thread::spawn(move || {
                let mut j = EconomicJournalV1::open(&path, NETWORK, limits()).unwrap();
                b.wait();
                j.resume(id).unwrap()
            })
        })
        .collect();
    let receipts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(receipts[0], receipts[1]);
    let j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(counts(&j), (1, 1, 1, 1));
}

#[test]
fn injected_commit_failures_leave_no_split_winner_and_recover_after_restart() {
    for trigger in [
        "CREATE TRIGGER fail BEFORE INSERT ON economic_outbox BEGIN SELECT RAISE(ABORT,'after authorization'); END;",
        "CREATE TRIGGER fail AFTER UPDATE OF prior ON economic_state BEGIN SELECT RAISE(ABORT,'after head'); END;",
        "CREATE TRIGGER fail AFTER UPDATE OF state ON miner_rounds WHEN NEW.state=2 BEGIN SELECT RAISE(ABORT,'after winner'); END;",
        "CREATE TRIGGER fail AFTER INSERT ON miner_rewards BEGIN SELECT RAISE(ABORT,'after reward'); END;",
    ] {
        let (file,mut j,r)=setup();let t=candidate(&r,None,0,true);let id=admit(&mut j,&t).attempt_id();j.authorizer.connection.execute_batch(trigger).unwrap();assert!(j.resume(id).is_err());
        assert_eq!(counts(&j),(1,0,0,0));assert_eq!(j.pending_attempt().unwrap(),Some(id));assert_eq!(j.miner_round(1).unwrap().state,MinerRoundStateV1::Admitted);assert_eq!(j.prior_head().unwrap(),EconomicPriorHeadV1::Current(EconomicHeadV2::genesis()));
        drop(j);let mut j=EconomicJournalV1::open(&file.0,NETWORK,limits()).unwrap();j.authorizer.connection.execute_batch("DROP TRIGGER fail").unwrap();assert_eq!(j.resume(id).unwrap().outcome,EconomicOutcomeV1::Accepted);assert_eq!(counts(&j),(1,1,1,1));
    }
}

#[test]
fn admission_failure_rolls_back_round_and_debit_together() {
    let (_file, mut j, r) = setup();
    let t = candidate(&r, None, 0, true);
    j.authorizer.connection.execute_batch("CREATE TRIGGER fail AFTER UPDATE OF state ON miner_rounds WHEN NEW.state=1 BEGIN SELECT RAISE(ABORT,'after debit'); END;").unwrap();
    let a = auth(t.work(), t.proof_hash());
    assert!(j
        .admit_at(
            &t.work().canonical_bytes().unwrap(),
            &consent(t.work(), &a),
            &a,
            TIME + 1
        )
        .is_err());
    assert_eq!(counts(&j), (0, 0, 0, 0));
    assert_eq!(
        j.ledger_for_payer(t.work().subject())
            .unwrap()
            .burned_supply,
        0
    );
    assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Open);
}

#[test]
fn corrupt_round_reward_signature_and_control_fail_closed_on_restart() {
    for sql in [
        "DELETE FROM miner_rewards",
        "UPDATE miner_rounds SET signature=zeroblob(64)",
        "UPDATE miner_control SET next_round='99'",
        "UPDATE miner_rounds SET funding_txid='bad'",
        "UPDATE miner_rounds SET state=3",
    ] {
        let (file, mut j, r) = setup();
        let t = candidate(&r, None, 0, true);
        let id = admit(&mut j, &t).attempt_id();
        j.resume(id).unwrap();
        j.authorizer.connection.execute_batch(sql).unwrap();
        drop(j);
        assert!(
            EconomicJournalV1::open(&file.0, NETWORK, limits()).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn expired_round_releases_admissions_but_challenge_and_funding_cannot_be_reused_live() {
    let (_file, mut j, _r) = setup();
    j.expire_round_at(1, TIME + 600).unwrap();
    assert!(j
        .open_round_at(&key(), opening(), reserve, TIME + 600, [42; 32])
        .is_err());
    let mut p = policy_value();
    p.job.policy_epoch = 1;
    j.update_miner_policy(&p).unwrap();
    let r = j
        .open_round_at(&key(), opening(), reserve, TIME + 600, [43; 32])
        .unwrap();
    assert_eq!(r.job.round_number, 2);
    assert_eq!(r.job.policy_epoch, 1);
    // Close as accepted using exact policy from this new epoch.
    let mut tjob = r.clone();
    tjob.job.policy_epoch = 0; // old signed job must not pass current admission
    let w = tjob.job.build_work(fixture().1, [13; 32]).unwrap();
    let a = auth(&w, [0; 32]);
    assert!(j
        .admit_at(
            &w.canonical_bytes().unwrap(),
            &consent(&w, &a),
            &a,
            TIME + 601
        )
        .is_err());
}

#[test]
fn core_funding_rejects_network_unspendable_underfunded_and_failed_locks() {
    let (mut job, _) = fixture();
    job.reward_satoshis = 10_000;
    for case in 0..7 {
        let mut lock_called = false;
        let result = funding::reserve_miner_funding_v1(
            |m, _| {
                Ok(match m {
                    "getblockchaininfo" => json!({"chain":if case==0 {"main"}else{"regtest"}}),
                    "listlockunspent" => {
                        if case == 1 {
                            json!([{"txid":"77".repeat(32),"vout":0}])
                        } else {
                            json!([])
                        }
                    }
                    "listunspent" => {
                        json!([{"txid":"77".repeat(32),"vout":0,"amount":if case==2{0.0001}else{0.0002},"spendable":case!=3,"solvable":true,"safe":true,"confirmations":6,"scriptPubKey":"5120"}])
                    }
                    "gettxout" => {
                        if case == 4 {
                            Value::Null
                        } else {
                            json!({"value":if case==5{0.0003}else{0.0002},"confirmations":6,"scriptPubKey":{"hex":"5120"}})
                        }
                    }
                    "decodescript" => json!({"address":"test-payout"}),
                    "validateaddress" => {
                        json!({"scriptPubKey":"5120".to_owned()+&encode_hex_v2(&job.operator_key)})
                    }
                    "walletcreatefundedpsbt" => {
                        json!({"psbt":"unsigned-test-template","fee":0.00001})
                    }
                    "lockunspent" => {
                        lock_called = true;
                        json!(false)
                    }
                    _ => panic!(),
                })
            },
            &job,
            &"77".repeat(32),
            0,
            5000,
            2,
        );
        assert!(result.is_err(), "case {case}");
        assert_eq!(lock_called, case == 6);
    }
}

#[test]
fn copied_proof_reference_under_new_nonce_fails_service_owned_verification() {
    let (_file, mut j, r) = setup();
    let t = candidate(&r, None, 0, true);
    let w = r.job.build_work(t.work().meter.clone(), [99; 32]).unwrap();
    let a = auth(&w, t.proof_hash()); // Correctly signed new lineage, copied low proof reference.
    let id = j
        .admit_at(
            &w.canonical_bytes().unwrap(),
            &consent(&w, &a),
            &a,
            TIME + 1,
        )
        .unwrap()
        .attempt_id();
    assert_eq!(
        j.resume(id).unwrap().outcome,
        EconomicOutcomeV1::VerificationRejected
    );
    assert_eq!(counts(&j), (1, 0, 0, 0));
    assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Rejected);
}

#[test]
fn no_unfunded_publication_and_no_reuse_of_winner_funding() {
    let (_file, mut j, r) = setup();
    let t = candidate(&r, None, 0, true);
    let id = admit(&mut j, &t).attempt_id();
    j.resume(id).unwrap();
    assert!(j
        .open_round_at(
            &key(),
            opening(),
            |_| Err("wallet unavailable".into()),
            TIME + 1,
            [43; 32]
        )
        .is_err());
    // Core adapter observations cannot override the journal's existing obligation.
    assert!(j
        .open_round_at(&key(), opening(), reserve, TIME + 1, [43; 32])
        .is_err());
    assert!(j.miner_round(2).is_err());
    assert_eq!(control(&j.authorizer.connection).unwrap(), (0, 2));
    assert_eq!(counts(&j), (1, 1, 1, 1));
}

#[test]
fn ordinary_work_is_locked_during_round_but_uses_same_pipeline_after_expiry() {
    let (_file, mut j, r) = setup();
    let mut work = r.job.build_work(fixture().1, [77; 32]).unwrap();
    work.storm.context_bytes_v1[177..209].fill(88);
    let claim = build_storm_claim_v1(&work.storm, [0; 32], [0; 32]);
    let inputs = build_storm_air_public_inputs_v1(&claim);
    let proof = prove_storm_air_real_v1(&claim, &inputs).unwrap();
    let bound = crate::prepare_bound_proof_material_v1(
        work.subject(),
        work.nonce(),
        &proof.proof_bytes,
        &inputs.canonical_bytes(),
        &[],
    )
    .unwrap();
    let a = auth(&work, bound.proof_hash);
    let c = consent(&work, &a);
    let bytes = work.canonical_bytes().unwrap();
    assert!(j.admit_at(&bytes, &c, &a, TIME + 1).is_err());
    assert_eq!(counts(&j), (0, 0, 0, 0));
    j.expire_round_at(1, TIME + 600).unwrap();
    let id = j.admit_at(&bytes, &c, &a, TIME + 600).unwrap().attempt_id();
    assert_eq!(j.resume(id).unwrap().outcome, EconomicOutcomeV1::Accepted);
    assert_eq!(counts(&j), (1, 1, 1, 0));
    j.record_publication(id, &"ab".repeat(32)).unwrap();
}

#[test]
fn host_limit_change_defers_pending_contender_without_refund_or_new_winner() {
    let (file, mut j, r) = setup();
    let t = candidate(&r, None, 0, true);
    let id = admit(&mut j, &t).attempt_id();
    drop(j);
    let mut restricted = limits();
    restricted.max_iterations = 1;
    let mut j = EconomicJournalV1::open(&file.0, NETWORK, restricted).unwrap();
    assert!(j.resume(id).is_err());
    assert_eq!(counts(&j), (1, 0, 0, 0));
    assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Admitted);
    drop(j);
    let mut j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(j.resume(id).unwrap().outcome, EconomicOutcomeV1::Accepted);
}

#[test]
fn process_exit_after_round_acquisition_recovers_without_client_or_second_debit() {
    let (file, j, _) = setup();
    drop(j);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "economic::journal::miner::tests::miner_crash_worker",
        ])
        .env("AURA_M4_CRASH_TEST_DB", &file.0)
        .status()
        .unwrap();
    assert!(status.success());
    let mut j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(counts(&j), (1, 0, 0, 0));
    let id = j.pending_attempt().unwrap().unwrap();
    assert_eq!(j.miner_round(1).unwrap().attempt_id, Some(id));
    let receipt = j.resume(id).unwrap();
    assert_eq!(receipt.outcome, EconomicOutcomeV1::Accepted);
    assert_eq!(counts(&j), (1, 1, 1, 1));
    assert_eq!(
        j.ledger_for_payer(key().x_only_public_key().0.serialize())
            .unwrap()
            .burned_supply,
        receipt.burn_units
    );
}

#[test]
fn miner_crash_worker() {
    let Ok(path) = std::env::var("AURA_M4_CRASH_TEST_DB") else {
        return;
    };
    let mut j = EconomicJournalV1::open(Path::new(&path), NETWORK, limits()).unwrap();
    let r = j.miner_round(1).unwrap();
    let t = candidate(&r, None, 0, true);
    admit(&mut j, &t);
    std::process::exit(0); // Deliberately bypass all destructors after the commit.
}

#[test]
fn wallet_release_is_idempotent_and_never_unlocks_live_or_reassigned_funding() {
    let (_file, mut j, r) = setup();
    assert!(j
        .release_miner_funding(1, |_, _| panic!("live reservation must not call wallet"))
        .is_err());
    j.expire_round_at(1, TIME + 600).unwrap();
    let mut locked = true;
    let mut unlocks = 0;
    for _ in 0..2 {
        j.release_miner_funding(1, |m, p| {
            Ok(match m {
                "getblockchaininfo" => json!({"chain":"regtest"}),
                "listlockunspent" => {
                    if locked {
                        json!([{"txid":"77".repeat(32),"vout":0}])
                    } else {
                        json!([])
                    }
                }
                "lockunspent" => {
                    assert_eq!(p, json!([true,[{"txid":"77".repeat(32),"vout":0}]]));
                    unlocks += 1;
                    locked = false;
                    json!(true)
                }
                _ => panic!("unexpected RPC"),
            })
        })
        .unwrap();
    }
    assert_eq!(unlocks, 1);
    let later = j
        .open_round_at(&key(), opening(), reserve, TIME + 600, [43; 32])
        .unwrap();
    assert!(j
        .release_miner_funding(r.job.round_number, |_, _| panic!(
            "reassigned reservation must not call wallet"
        ))
        .is_err());
    let t = candidate(&later, None, 0, true);
    let a = auth(t.work(), t.proof_hash());
    let id = j
        .admit_at(
            &t.work().canonical_bytes().unwrap(),
            &consent(t.work(), &a),
            &a,
            TIME + 601,
        )
        .unwrap()
        .attempt_id();
    j.resume(id).unwrap();
    assert!(j
        .release_miner_funding(later.job.round_number, |_, _| panic!(
            "accepted funding must not call wallet"
        ))
        .is_err());
}
