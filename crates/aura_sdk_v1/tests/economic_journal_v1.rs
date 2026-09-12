#[path = "support/economic_v1.rs"]
mod support;
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_intent_lineage_v1::{
    build_storm_air_public_inputs_v1, build_storm_claim_v1, prove_storm_air_real_v1,
};
use aura_sdk_v1::{
    authorization::{encode_hex_v2, AuthorizationEnvelopeV2, AuthorizerJournalV2},
    economic::{
        head::EconomicOutcomeV1,
        journal::{
            EconomicAttemptStateV1, EconomicJournalV1, EconomicPriorHeadV1, LegacyHeadCheckpointV1,
        },
        EconomicConsentV1, EconomicLimitsV1, EconomicWorkV1,
    },
    prepare_bound_proof_material_v1,
};
use rusqlite::Connection;
use std::{
    path::PathBuf,
    sync::{atomic::{AtomicU64, Ordering}, Arc, Barrier},
    time::{SystemTime, UNIX_EPOCH},
};
const N: BitcoinNetworkV1 = BitcoinNetworkV1::Regtest;
fn limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: 100_000,
        max_meter_bytes: 90_000,
        max_iterations: 100,
    }
}
struct File(PathBuf);
impl File {
    fn new() -> Self {
        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        Self(
            std::env::temp_dir().join(format!(
                "aura-economic-{}-{}-{}.db",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            )),
        )
    }
}
impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn counts(file: &File) -> (i64, i64, i64) {
    let c = Connection::open(&file.0).unwrap();
    (
        c.query_row("SELECT count(*) FROM economic_attempts", [], |r| r.get(0))
            .unwrap(),
        c.query_row("SELECT count(*) FROM authorizations", [], |r| r.get(0))
            .unwrap(),
        c.query_row("SELECT count(*) FROM economic_outbox", [], |r| r.get(0))
            .unwrap(),
    )
}
fn resign_auth(a: &mut AuthorizationEnvelopeV2) {
    a.signature_hex = encode_hex_v2(
        secp256k1::Secp256k1::new()
            .sign_schnorr_no_aux_rand(&a.signing_digest(N).unwrap(), &support::keypair())
            .as_ref(),
    );
}
fn refresh(
    work: &mut EconomicWorkV1,
    auth: &mut AuthorizationEnvelopeV2,
    nonce: u8,
) -> EconomicConsentV1 {
    work.storm.context_bytes_v1[97..129].fill(nonce);
    auth.authorization_lineage.freshness_binding = format!("{nonce:02x}").repeat(32);
    let claim = build_storm_claim_v1(&work.storm, [0; 32], [0; 32]);
    let inputs = build_storm_air_public_inputs_v1(&claim);
    let proof = prove_storm_air_real_v1(&claim, &inputs).unwrap();
    let bound = prepare_bound_proof_material_v1(
        work.subject(),
        work.nonce(),
        &proof.proof_bytes,
        &inputs.canonical_bytes(),
        &[],
    )
    .unwrap();
    auth.proof_hash_hex = encode_hex_v2(&bound.proof_hash);
    resign_auth(auth);
    support::sign(work, auth)
}

#[test]
fn admission_debit_restart_idempotence_and_publication_are_separate() {
    let (work, consent, auth, _, _) = support::sample();
    let file = File::new();
    let burn = work.burn_units().unwrap();
    let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
    let bytes = work.canonical_bytes().unwrap();
    let admitted = j.admit(&bytes, &consent, &auth).unwrap();
    let id = admitted.attempt_id();
    assert_eq!(
        admitted,
        EconomicAttemptStateV1::Admitted { attempt_id: id }
    );
    assert_eq!(counts(&file), (1, 0, 0));
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap().burned_supply,
        burn
    );
    assert_eq!(j.admit(&bytes, &consent, &auth).unwrap(), admitted);
    drop(j);
    let mut j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    assert_eq!(j.pending_attempt().unwrap(), Some(id));
    let receipt = j.resume(id).unwrap();
    assert_eq!(receipt.outcome, EconomicOutcomeV1::Accepted);
    assert_eq!(counts(&file), (1, 1, 1));
    assert_eq!(j.pending_attempt().unwrap(), None);
    assert_eq!(j.submit(&bytes, &consent, &auth).unwrap(), receipt);
    let mut resigned = consent.clone();
    resigned.signature_hex = encode_hex_v2(
        secp256k1::Secp256k1::new()
            .sign_schnorr_with_aux_rand(
                &EconomicConsentV1::signing_digest(N, &work, &auth).unwrap(),
                &support::keypair(),
                &[7; 32],
            )
            .as_ref(),
    );
    assert_eq!(j.submit(&bytes, &resigned, &auth).unwrap(), receipt);
    let outbox = j.outbox().unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].request.proof_hash_hex(), auth.proof_hash_hex);
    assert_eq!(outbox[0].request.script_pubkey()[..2], [0x6a, 0x26]);
    j.record_publication(id, &"77".repeat(32)).unwrap();
    drop(j);
    let mut j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    assert_eq!(j.submit(&bytes, &consent, &auth).unwrap(), receipt);
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap().burned_supply,
        burn
    );
    assert_eq!(
        j.outbox().unwrap()[0].last_publication_txid,
        Some("77".repeat(32))
    );
}

#[test]
fn all_terminal_failures_consume_one_full_burn_and_advance_the_same_head() {
    for expected in [
        EconomicOutcomeV1::ExecutionRejected,
        EconomicOutcomeV1::VerificationRejected,
        EconomicOutcomeV1::SettlementRejected,
    ] {
        let (mut work, _, mut auth, _, _) = support::sample();
        match expected {
            EconomicOutcomeV1::ExecutionRejected => {
                work.meter.transactions[0].sender_nonce = u64::MAX
            }
            EconomicOutcomeV1::VerificationRejected => {
                auth.proof_hash_hex = "ee".repeat(32);
                resign_auth(&mut auth);
            }
            EconomicOutcomeV1::SettlementRejected => work.meter.wallet_binding.account_id = [9; 32],
            _ => unreachable!(),
        }
        let consent = support::sign(&work, &auth);
        let file = File::new();
        let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
        let bytes = work.canonical_bytes().unwrap();
        let burn = work.burn_units().unwrap();
        let r = j.submit(&bytes, &consent, &auth).unwrap();
        assert_eq!(r.outcome, expected);
        assert_eq!(r.burn_units, burn);
        assert_eq!(r.head.head_sequence_number, "1");
        assert_eq!(counts(&file), (1, 0, 0));
        assert_eq!(j.pending_attempt().unwrap(), None);
        drop(j);
        let mut j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
        assert_eq!(j.submit(&bytes, &consent, &auth).unwrap(), r);
        assert_eq!(
            j.ledger_for_payer(work.subject()).unwrap().burned_supply,
            burn
        );
    }
}

#[test]
fn unauthenticated_stale_insufficient_busy_and_conflicting_work_do_not_charge() {
    let (work, consent, auth, _, _) = support::sample();
    let file = File::new();
    let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
    let mut bad = consent.clone();
    bad.signature_hex = "00".repeat(64);
    assert!(j
        .admit(&work.canonical_bytes().unwrap(), &bad, &auth)
        .is_err());
    let mut stale = work.clone();
    stale.meter.head.head_sequence_number = 2;
    assert!(j
        .admit(
            &stale.canonical_bytes().unwrap(),
            &support::sign(&stale, &auth),
            &auth
        )
        .is_err());
    assert_eq!(counts(&file), (0, 0, 0));
    let id = j
        .admit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .unwrap()
        .attempt_id();
    let mut different = work.clone();
    different.meter.transactions[0].amount += 1;
    let error = j
        .admit(
            &different.canonical_bytes().unwrap(),
            &support::sign(&different, &auth),
            &auth,
        )
        .unwrap_err();
    assert!(error.to_string().contains("conflicts"));
    let mut target = auth.clone();
    target.proof_hash_hex = "aa".repeat(32);
    resign_auth(&mut target);
    assert!(j
        .admit(
            &work.canonical_bytes().unwrap(),
            &support::sign(&work, &target),
            &target
        )
        .is_err());
    let (mut busy, _, mut busy_auth, _, _) = support::sample();
    let busy_consent = refresh(&mut busy, &mut busy_auth, 0x33);
    assert!(j
        .admit(&busy.canonical_bytes().unwrap(), &busy_consent, &busy_auth)
        .unwrap_err()
        .to_string()
        .contains("busy"));
    assert_eq!(counts(&file), (1, 0, 0));
    assert_eq!(j.pending_attempt().unwrap(), Some(id));
    j.resume(id).unwrap();
    assert!(j
        .admit(&busy.canonical_bytes().unwrap(), &busy_consent, &busy_auth)
        .unwrap_err()
        .to_string()
        .contains("stale"));
    assert_eq!(counts(&file), (1, 1, 1));

    let file2 = File::new();
    let mut poor = work.clone();
    poor.meter.ledger.total_supply = 1;
    poor.meter.ledger.accounts[0].balance = 1;
    let mut j = EconomicJournalV1::create(&file2.0, N, &poor.meter.ledger, limits()).unwrap();
    assert!(j
        .admit(
            &poor.canonical_bytes().unwrap(),
            &support::sign(&poor, &auth),
            &auth
        )
        .is_err());
    assert_eq!(counts(&file2), (0, 0, 0));
}

#[test]
fn successive_outcomes_and_old_retries_use_durable_ledger_and_head() {
    let (mut work, consent, mut auth, _, _) = support::sample();
    let old_bytes = work.canonical_bytes().unwrap();
    let old_auth = auth.clone();
    let file = File::new();
    let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
    let first = j.submit(&old_bytes, &consent, &auth).unwrap();
    work.meter.ledger = j.ledger_for_payer(work.subject()).unwrap();
    work.meter.head = j.prior_head().unwrap().next_linkage().unwrap();
    let next = refresh(&mut work, &mut auth, 0x23);
    let second = j
        .submit(&work.canonical_bytes().unwrap(), &next, &auth)
        .unwrap();
    assert_eq!(second.head.head_sequence_number, "2");
    assert_eq!(
        second.head.previous_head_hash_hex,
        first.head.current_head_hash_hex
    );
    assert_eq!(j.submit(&old_bytes, &consent, &old_auth).unwrap(), first);
    assert_eq!(counts(&file), (2, 2, 2));
    drop(j);
    EconomicJournalV1::open(&file.0, N, limits()).unwrap();
}

#[test]
fn transaction_failures_roll_back_admission_and_atomic_authorization_outbox() {
    let (work, consent, auth, _, _) = support::sample();
    let file = File::new();
    let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
    let sql = Connection::open(&file.0).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_admit BEFORE UPDATE OF ledger ON economic_state BEGIN SELECT RAISE(ABORT,'injected debit commit failure'); END;").unwrap();
    assert!(j
        .admit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .is_err());
    assert_eq!(counts(&file), (0, 0, 0));
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap(),
        work.meter.ledger
    );
    sql.execute_batch("DROP TRIGGER fail_admit").unwrap();
    let id = j
        .admit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .unwrap()
        .attempt_id();
    sql.execute_batch("CREATE TRIGGER fail_outbox BEFORE INSERT ON economic_outbox BEGIN SELECT RAISE(ABORT,'injected finalization failure'); END;").unwrap();
    assert!(j.resume(id).is_err());
    assert_eq!(counts(&file), (1, 0, 0));
    assert_eq!(j.pending_attempt().unwrap(), Some(id));
    drop(j);
    let mut j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    sql.execute_batch("DROP TRIGGER fail_outbox; CREATE TRIGGER fail_head BEFORE UPDATE OF prior ON economic_state BEGIN SELECT RAISE(ABORT,'injected head commit failure'); END;").unwrap();
    assert!(j.resume(id).is_err());
    assert_eq!(counts(&file), (1, 0, 0));
    assert_eq!(j.pending_attempt().unwrap(), Some(id));
    sql.execute_batch("DROP TRIGGER fail_head").unwrap();
    assert_eq!(j.resume(id).unwrap().outcome, EconomicOutcomeV1::Accepted);
    assert_eq!(counts(&file), (1, 1, 1));
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap().burned_supply,
        work.burn_units().unwrap()
    );
}

#[test]
fn competing_connections_retry_one_admission_and_one_finalization() {
    let (work, consent, auth, _, _) = support::sample();
    let file = File::new();
    drop(EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let path = file.0.clone();
            let barrier = barrier.clone();
            let work = work.clone();
            let consent = consent.clone();
            let auth = auth.clone();
            std::thread::spawn(move || {
                let mut j = EconomicJournalV1::open(&path, N, limits()).unwrap();
                barrier.wait();
                let receipt = j
                    .submit(&work.canonical_bytes().unwrap(), &consent, &auth)
                    .unwrap();
                assert_eq!(j.resume(receipt.attempt_id).unwrap(), receipt);
                receipt
            })
        })
        .collect();
    let receipts: Vec<_> = workers.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(receipts.iter().all(|r| r == &receipts[0]));
    assert_eq!(counts(&file), (1, 1, 1));
    let j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap().burned_supply,
        work.burn_units().unwrap()
    );
}

#[test]
fn process_exit_after_debit_recovers_without_client_completion_or_reburn() {
    let (work, _, _, _, _) = support::sample();
    let file = File::new();
    drop(EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap());
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "economic_crash_worker"])
        .env("AURA_ECONOMIC_CRASH_TEST_DB", &file.0)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(counts(&file), (1, 0, 0));
    let mut j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    let id = j.pending_attempt().unwrap().unwrap();
    assert_eq!(j.resume(id).unwrap().outcome, EconomicOutcomeV1::Accepted);
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap().burned_supply,
        work.burn_units().unwrap()
    );
}
#[test]
fn economic_crash_worker() {
    let Ok(path) = std::env::var("AURA_ECONOMIC_CRASH_TEST_DB") else {
        return;
    };
    let (work, consent, auth, _, _) = support::sample();
    let mut j = EconomicJournalV1::open(std::path::Path::new(&path), N, limits()).unwrap();
    j.admit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .unwrap();
    std::process::exit(0); // Skip all destructors after the durable debit commit.
}

#[test]
fn explicit_v1_checkpoint_preserves_authorization_history_and_initializes_once() {
    let (mut work, _, mut auth, claim, proof) = support::sample();
    let file = File::new();
    let mut legacy = AuthorizerJournalV2::create(&file.0).unwrap();
    legacy.accept(N, &auth, &claim, &proof, 100).unwrap();
    drop(legacy);
    assert!(EconomicJournalV1::open(&file.0, N, limits()).is_err());
    let checkpoint = LegacyHeadCheckpointV1 {
        settlement_head_version: 1,
        head_sequence_number: 7,
        current_head_hash_hex: "55".repeat(32),
    };
    let mut j =
        EconomicJournalV1::migrate_v1(&file.0, N, &work.meter.ledger, checkpoint.clone(), limits())
            .unwrap();
    assert_eq!(
        j.prior_head().unwrap(),
        EconomicPriorHeadV1::LegacyV1(checkpoint.clone())
    );
    assert!(
        EconomicJournalV1::migrate_v1(&file.0, N, &work.meter.ledger, checkpoint, limits())
            .is_err()
    );
    work.meter.head = j.prior_head().unwrap().next_linkage().unwrap();
    let consent = refresh(&mut work, &mut auth, 0x24);
    let r = j
        .submit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .unwrap();
    assert_eq!(r.head.settlement_head_version, 2);
    assert_eq!(r.head.head_sequence_number, "8");
    assert_eq!(r.head.previous_head_hash_hex, "55".repeat(32));
    assert_eq!(counts(&file), (1, 2, 1));
    drop(j);
    let j = EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    assert_eq!(
        j.prior_head().unwrap(),
        EconomicPriorHeadV1::Current(r.head)
    );
}

#[test]
fn missing_corrupt_uninitialized_wrong_network_and_missing_outbox_fail_closed() {
    let (work, consent, auth, _, _) = support::sample();
    let file = File::new();
    assert!(EconomicJournalV1::open(&file.0, N, limits()).is_err());
    let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
    assert!(EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).is_err());
    assert!(EconomicJournalV1::open(&file.0, BitcoinNetworkV1::Mainnet, limits()).is_err());
    j.submit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .unwrap();
    Connection::open(&file.0)
        .unwrap()
        .execute("DELETE FROM economic_outbox", [])
        .unwrap();
    assert!(j
        .submit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .is_err());
    drop(j);
    assert!(EconomicJournalV1::open(&file.0, N, limits()).is_err());
    std::fs::write(&file.0, b"corrupt journal").unwrap();
    assert!(EconomicJournalV1::open(&file.0, N, limits()).is_err());
}

#[test]
fn attestation_truth_and_local_batch_lineage_keep_their_chargeable_outcomes() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/economic_admission_v1/meter_vectors.json"
    ))
    .unwrap();
    for (name, expected) in [
        ("attestation", EconomicOutcomeV1::Accepted),
        ("root_digest", EconomicOutcomeV1::ExecutionRejected),
    ] {
        let (mut work, _, auth, _, _) = support::sample();
        let hex = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()["meter_hex"]
            .as_str()
            .unwrap();
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut meter =
            aura_l2_local_chain_v0::economic_meter::EconomicMeterV1::decode(&bytes, bytes.len())
                .unwrap();
        meter.ledger = work.meter.ledger.clone();
        meter.wallet_binding = work.meter.wallet_binding.clone();
        meter.head = work.meter.head.clone();
        work.meter = meter;
        let consent = support::sign(&work, &auth);
        let file = File::new();
        let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
        assert_eq!(
            j.submit(&work.canonical_bytes().unwrap(), &consent, &auth)
                .unwrap()
                .outcome,
            expected
        );
        assert_eq!(
            j.ledger_for_payer(work.subject()).unwrap().burned_supply,
            work.burn_units().unwrap()
        );
    }
    for bad_parent in [false, true] {
        let (mut work, _, auth, _, _) = support::sample();
        if bad_parent {
            work.meter.parent_batch_commitment = [1; 32];
        } else {
            work.meter.batch_number = 1;
        }
        let file = File::new();
        let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
        let consent = support::sign(&work, &auth);
        assert_eq!(
            j.submit(&work.canonical_bytes().unwrap(), &consent, &auth)
                .unwrap()
                .outcome,
            EconomicOutcomeV1::SettlementRejected
        );
        assert_eq!(counts(&file), (1, 0, 0));
    }
}

#[test]
fn existing_authorization_conflict_rejects_without_releasing_old_reservation() {
    let (work, consent, auth, _, _) = support::sample();
    let file = File::new();
    let mut j = EconomicJournalV1::create(&file.0, N, &work.meter.ledger, limits()).unwrap();
    let mut alternative = work.clone();
    alternative.storm.side_a[0] ^= 1;
    let mut other_auth = auth.clone();
    refresh(&mut alternative, &mut other_auth, 0x22);
    let claim = build_storm_claim_v1(&alternative.storm, [0; 32], [0; 32]);
    let proof = prove_storm_air_real_v1(&claim, &build_storm_air_public_inputs_v1(&claim)).unwrap();
    AuthorizerJournalV2::open(&file.0)
        .unwrap()
        .accept(N, &other_auth, &claim, &proof, 100)
        .unwrap();
    let r = j
        .submit(&work.canonical_bytes().unwrap(), &consent, &auth)
        .unwrap();
    assert_eq!(r.outcome, EconomicOutcomeV1::VerificationRejected);
    assert_eq!(counts(&file), (1, 1, 0));
    assert_eq!(
        j.ledger_for_payer(work.subject()).unwrap().burned_supply,
        work.burn_units().unwrap()
    );
    drop(j);
    EconomicJournalV1::open(&file.0, N, limits()).unwrap();
    AuthorizerJournalV2::open(&file.0)
        .unwrap()
        .accept(N, &other_auth, &claim, &proof, 100)
        .unwrap();
}
