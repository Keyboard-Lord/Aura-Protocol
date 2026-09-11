//! M6 adversarial coordinator evidence. Uses real canonical Storm/proof owners;
//! funding RPC remains the deterministic fixture (real wallet attacks are regtest).
use super::*;
use aura_l2_local_chain_v0::CanonicalPipelineLedgerAccountV1;

#[test]
fn different_signed_job_fields_and_wrong_identity_never_acquire_round() {
    let (_file, mut j, r) = setup();
    for case in 0..9 {
        let mut wrong = r.job.clone();
        match case {
            0 => wrong.target[0] ^= 1,
            1 => wrong.policy_epoch += 1,
            2 => wrong.round_number += 1,
            3 => wrong.challenge[0] ^= 1,
            4 => wrong.journal_namespace[0] ^= 1,
            5 => wrong.prior_head_hash[0] ^= 1,
            6 => wrong.reward_satoshis += 1,
            7 => {
                wrong.operator_key = SecretKey::from_byte_array([4; 32])
                    .unwrap()
                    .x_only_public_key(&Secp256k1::new())
                    .0
                    .serialize()
            }
            _ => {}
        }
        let mut meter = fixture().1;
        if case == 5 {
            meter.head.previous_head_hash = wrong.prior_head_hash;
        }
        let w = wrong.build_work(meter, [61; 32]).unwrap();
        let mut a = auth(&w, [0; 32]);
        let c = consent(&w, &a);
        if case == 8 {
            a.signature_hex = "00".repeat(64);
        }
        assert!(
            j.admit_at(&w.canonical_bytes().unwrap(), &c, &a, TIME + 1)
                .is_err(),
            "case {case}"
        );
        assert_eq!(counts(&j), (0, 0, 0, 0));
        assert_eq!(j.miner_round(1).unwrap().state, MinerRoundStateV1::Open);
    }
    let mut w = r.job.build_work(fixture().1, [62; 32]).unwrap();
    w.meter.ledger.payer_account_id = [9; 32];
    assert!(w.canonical_bytes().is_err());
    let w = r.job.build_work(fixture().1, [63; 32]).unwrap();
    let a = auth(&w, [0; 32]);
    let c = consent(&w, &a);
    let mut wrong = a.clone();
    wrong.authorization_lineage.subject_binding = encode_hex_v2(
        &SecretKey::from_byte_array([4; 32])
            .unwrap()
            .x_only_public_key(&Secp256k1::new())
            .0
            .serialize(),
    );
    assert!(j
        .admit_at(&w.canonical_bytes().unwrap(), &c, &wrong, TIME + 1)
        .is_err());
    assert_eq!(counts(&j), (0, 0, 0, 0));
}

#[test]
fn nonce_reuse_after_failed_round_conflicts_without_another_burn() {
    let (_file, mut j, r) = setup();
    let w = r.job.build_work(fixture().1, [71; 32]).unwrap();
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
    assert_eq!(
        j.resume(id).unwrap().outcome,
        EconomicOutcomeV1::VerificationRejected
    );
    let next = j
        .open_round_at(&key(), opening(), reserve, TIME + 2, [43; 32])
        .unwrap();
    let mut meter = fixture().1;
    meter.ledger = j.ledger_for_payer(w.subject()).unwrap();
    meter.head = j.prior_head().unwrap().next_linkage().unwrap();
    let rebound = next.job.build_work(meter, w.nonce()).unwrap();
    let auth2 = auth(&rebound, [0; 32]);
    assert!(j
        .admit_at(
            &rebound.canonical_bytes().unwrap(),
            &consent(&rebound, &auth2),
            &auth2,
            TIME + 3
        )
        .is_err());
    assert_eq!(counts(&j), (1, 0, 0, 0));
    assert_eq!(
        j.ledger_for_payer(w.subject()).unwrap().burned_supply,
        w.burn_units().unwrap()
    );
    assert_eq!(
        j.admit_at(
            &w.canonical_bytes().unwrap(),
            &consent(&w, &a),
            &a,
            TIME + 1000
        )
        .unwrap()
        .attempt_id(),
        id
    );
}

#[test]
fn retry_storm_returns_one_receipt_and_one_obligation() {
    let (file, j, r) = setup();
    let t = candidate(&r, None, 0, true);
    drop(j);
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let path = file.0.clone();
            let t = t.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut j = EconomicJournalV1::open(&path, NETWORK, limits()).unwrap();
                barrier.wait();
                let mut receipts = Vec::new();
                for _ in 0..8 {
                    let id = admit(&mut j, &t).attempt_id();
                    receipts.push(j.resume(id).unwrap());
                }
                receipts
            })
        })
        .collect();
    let receipts: Vec<_> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(receipts.len(), 32);
    assert!(receipts.iter().all(|r| r == &receipts[0]));
    let j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(counts(&j), (1, 1, 1, 1));
}

#[test]
fn two_funded_miner_identities_race_for_one_durable_winner() {
    let file = File::new();
    let mut meter = fixture().1;
    let key1 = key();
    let key2 = Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_byte_array([4; 32]).unwrap(),
    );
    meter
        .ledger
        .accounts
        .push(CanonicalPipelineLedgerAccountV1 {
            account_id: key2.x_only_public_key().0.serialize(),
            balance: 1_000_000,
        });
    meter.ledger.accounts.sort_by_key(|a| a.account_id);
    meter.ledger.total_supply += 1_000_000;
    let mut j = EconomicJournalV1::create(&file.0, NETWORK, &meter.ledger, limits()).unwrap();
    j.install_miner_policy(&policy_value()).unwrap();
    let r = j
        .open_round_at(&key1, opening(), reserve, TIME, [42; 32])
        .unwrap();
    let p = policy_value();
    let mut candidates = Vec::new();
    for k in [key1, key2] {
        let mut m = meter.clone();
        m.ledger.payer_account_id = k.x_only_public_key().0.serialize();
        m.wallet_binding.account_id = m.ledger.payer_account_id;
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
        let t = (0..64u64)
            .map(|i| {
                let mut nonce = [81; 32];
                nonce[24..].copy_from_slice(&i.to_be_bytes());
                session.trial(nonce, i).unwrap()
            })
            .find(|t| t.qualifies())
            .unwrap();
        let mut a = auth(t.work(), t.proof_hash());
        a.signature_hex = encode_hex_v2(
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(&a.signing_digest(NETWORK).unwrap(), &k)
                .as_ref(),
        );
        let mut c = consent(t.work(), &a);
        c.signature_hex = encode_hex_v2(
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(
                    &EconomicConsentV1::signing_digest(NETWORK, t.work(), &a).unwrap(),
                    &k,
                )
                .as_ref(),
        );
        candidates.push((t.work().canonical_bytes().unwrap(), a, c));
    }
    drop(j);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = candidates
        .into_iter()
        .map(|(w, a, c)| {
            let path = file.0.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut j = EconomicJournalV1::open(&path, NETWORK, limits()).unwrap();
                barrier.wait();
                j.admit_at(&w, &c, &a, TIME + 1).map(|s| s.attempt_id())
            })
        })
        .collect();
    let ids: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter_map(Result::ok)
        .collect();
    assert_eq!(ids.len(), 1);
    let mut j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
    assert_eq!(
        j.resume(ids[0]).unwrap().outcome,
        EconomicOutcomeV1::Accepted
    );
    assert_eq!(counts(&j), (1, 1, 1, 1));
}

#[test]
fn process_crashes_at_each_economic_commit_boundary_recover_atomically() {
    for phase in [
        "before_debit",
        "admission_before_commit",
        "after_debit",
        "during_verification",
        "after_authorization",
        "after_head",
        "after_reward_obligation",
    ] {
        let (file, j, r) = setup();
        drop(j);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "economic::journal::miner::tests::adversarial::economic_boundary_crash_worker",
            ])
            .env("AURA_M6_CRASH_DB", &file.0)
            .env("AURA_M6_CRASH_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86), "{phase}");
        let mut j = EconomicJournalV1::open(&file.0, NETWORK, limits()).unwrap();
        let before_admission = matches!(phase, "before_debit" | "admission_before_commit");
        assert_eq!(
            counts(&j),
            if before_admission {
                (0, 0, 0, 0)
            } else {
                (1, 0, 0, 0)
            },
            "{phase}"
        );
        assert_eq!(
            j.prior_head().unwrap(),
            EconomicPriorHeadV1::Current(EconomicHeadV2::genesis())
        );
        let id = if before_admission {
            admit(&mut j, &candidate(&r, None, 0, true)).attempt_id()
        } else {
            j.pending_attempt().unwrap().unwrap()
        };
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
}

#[test]
fn economic_boundary_crash_worker() {
    let Ok(path) = std::env::var("AURA_M6_CRASH_DB") else {
        return;
    };
    let phase = std::env::var("AURA_M6_CRASH_PHASE").unwrap();
    let mut j = EconomicJournalV1::open(Path::new(&path), NETWORK, limits()).unwrap();
    let r = j.miner_round(1).unwrap();
    let t = candidate(&r, None, 0, true);
    let id = admit(&mut j, &t).attempt_id();
    if phase == "after_debit" {
        std::process::exit(86);
    }
    j.resume(id).unwrap();
    panic!("crash boundary was not reached");
}

#[test]
fn corrupt_attempt_winner_outbox_and_partial_snapshot_fail_closed() {
    for sql in [
        "UPDATE economic_attempts SET work=zeroblob(length(work))",
        "UPDATE economic_attempts SET authorization='{}'",
        "UPDATE economic_attempts SET post_ledger=pre_ledger",
        "UPDATE economic_state SET ledger=initial_ledger",
        "UPDATE economic_state SET prior=initial_prior",
        "UPDATE miner_rounds SET ledger=zeroblob(length(ledger))",
        "UPDATE economic_outbox SET request='{}'",
        "DELETE FROM authorizations",
        "DELETE FROM miner_rewards",
    ] {
        let (file, mut j, r) = setup();
        let id = admit(&mut j, &candidate(&r, None, 0, true)).attempt_id();
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
fn whole_consistent_snapshot_rollback_requires_external_backup_provenance() {
    // A complete old copy is internally valid. No claim that local SQLite can
    // detect its own complete rollback: operator restore provenance is required.
    let (file, mut j, r) = setup();
    let snapshot = File::new();
    std::fs::copy(&file.0, &snapshot.0).unwrap();
    let id = admit(&mut j, &candidate(&r, None, 0, true)).attempt_id();
    let receipt = j.resume(id).unwrap();
    let old = EconomicJournalV1::open(&snapshot.0, NETWORK, limits()).unwrap();
    assert_eq!(counts(&old), (0, 0, 0, 0));
    assert_ne!(
        old.prior_head().unwrap(),
        EconomicPriorHeadV1::Current(receipt.head)
    );
    assert_eq!(old.miner_round(1).unwrap().state, MinerRoundStateV1::Open);
}

#[test]
fn published_outbox_without_payment_history_is_corruption() {
    let (file, mut j, r) = setup();
    let id = admit(&mut j, &candidate(&r, None, 0, true)).attempt_id();
    j.resume(id).unwrap();
    j.install_miner_publication().unwrap();
    j.authorizer
        .connection
        .execute("UPDATE economic_outbox SET txid=?1", ["88".repeat(32)])
        .unwrap();
    drop(j);
    assert!(EconomicJournalV1::open(&file.0, NETWORK, limits()).is_err());
}
