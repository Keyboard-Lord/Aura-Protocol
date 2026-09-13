use super::*;
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use secp256k1::{Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
};
thread_local! {static ERROR:RefCell<Option<&'static str>>=const{RefCell::new(None)};}
pub(super) fn hook(point: &str) -> AuthorizationResultV2<()> {
    if std::env::var("AURA_C2_CRASH").as_deref() == Ok(point) {
        std::process::exit(86);
    }
    if ERROR.with(|e| e.borrow().as_ref().is_some_and(|p| *p == point)) {
        return Err("injected infrastructure failure".into());
    }
    Ok(())
}
fn key(n: u8) -> Keypair {
    let mut b = [0; 32];
    b[31] = n;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_byte_array(b).unwrap())
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
const NET: BitcoinNetworkV1 = BitcoinNetworkV1::Regtest;
fn limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: 100000,
        max_meter_bytes: 90000,
        max_iterations: 100,
    }
}
fn meter() -> EconomicMeterV1 {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../../../fixtures/miner_v1/job_profile_vector_v1.json"
    ))
    .unwrap();
    let b = unhex(v["meter_hex"].as_str().unwrap());
    EconomicMeterV1::decode(&b, b.len()).unwrap()
}
fn job(nonce: u8) -> (AuraComputeJobV1, ComputeJobContentV1) {
    let mut payloads: [Vec<u8>; 10] = std::array::from_fn(|_| vec![1]);
    for (i, b) in [
        (0, b"C2_TEST_ONLY_REVERSE_V1".as_slice()),
        (1, b"customer requested bytes"),
        (2, b"test reverse"),
        (3, b"test bounded"),
        (4, b"test exact bytes"),
        (5, b"test replay verifier"),
    ] {
        payloads[i] = b.to_vec();
    }
    payloads[8] = ComputePaymentTermsV1 {
        max_payment_fee_satoshis: 42,
        result_availability_seconds: 3600,
    }
    .canonical_bytes()
    .unwrap()
    .to_vec();
    let d: Vec<_> = ComputeContentKindV1::ALL
        .into_iter()
        .zip(&payloads)
        .map(|(k, b)| compute_content_commitment_v1(k, b).unwrap())
        .collect();
    (
        AuraComputeJobV1 {
            job_version: 1,
            network: NET,
            coordinator_key: key(1).x_only_public_key().0.serialize(),
            journal_namespace: [4; 32],
            requester_key: key(3).x_only_public_key().0.serialize(),
            job_nonce: [nonce; 32],
            workload_class: 0,
            adapter_contract_commitment: d[0],
            input_commitment: d[1],
            program_commitment: d[2],
            execution_spec_commitment: d[3],
            output_spec_commitment: d[4],
            verification_class: 1,
            verification_spec_commitment: d[5],
            privacy_class: 1,
            privacy_policy_commitment: d[6],
            hardware_requirements_commitment: d[7],
            max_input_bytes: 4096,
            max_output_bytes: 4096,
            max_evidence_bytes: 4096,
            max_memory_bytes: 65536,
            max_scratch_bytes: 4096,
            max_execution_ms: 1000,
            accept_until: 200,
            complete_by: 300,
            compensation_satoshis: 10000,
            payment_terms_commitment: d[8],
            data_rights_commitment: d[9],
            mining_mode: 1,
        },
        ComputeJobContentV1 { payloads },
    )
}
fn policy() -> ComputeJournalConfigV1 {
    let j = job(1).0;
    ComputeJournalConfigV1 {
        coordinator: ComputeCoordinatorV1 {
            network: NET,
            coordinator_key: j.coordinator_key,
            journal_namespace: j.journal_namespace,
        },
        limits: unpack_limits([4096, 4096, 4096, 65536, 4096, 1000]),
        max_record_bytes: 100000,
        delivery_budget_ms: 100,
    }
}
struct Db(PathBuf);
impl Db {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "aura-c2-{}-{}-{}.db",
            std::process::id(),
            super::super::miner::now().unwrap(),
            N.fetch_add(1, Ordering::SeqCst)
        )))
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{s}", self.0.display()));
        }
    }
}
fn create(d: &Db) -> EconomicJournalV1 {
    let mut j = EconomicJournalV1::create(&d.0, NET, &meter().ledger, limits()).unwrap();
    j.install_compute(&policy()).unwrap();
    j
}
fn reopen(d: &Db) -> EconomicJournalV1 {
    EconomicJournalV1::open(&d.0, NET, limits()).unwrap()
}
fn register(q: &mut EconomicJournalV1, n: u8) -> [u8; 32] {
    let (j, c) = job(n);
    q.register_compute_with_clock(
        &j.canonical_bytes().unwrap(),
        &j.sign_request(&key(3)).unwrap(),
        &c,
        || Ok(100),
    )
    .unwrap()
}
fn rpc(txid: &str, vout: u32, method: &str, _: Value) -> AuthorizationResultV2<Value> {
    Ok(match method {
        "getblockchaininfo" => json!({"chain":"regtest"}),
        "listlockunspent" => json!([]),
        "listunspent" => {
            json!([{"txid":txid,"vout":vout,"amount":0.00010042,"spendable":true,"safe":true,"solvable":true,"confirmations":10,"scriptPubKey":"51"}])
        }
        "gettxout" => json!({"confirmations":10,"value":0.00010042,"scriptPubKey":{"hex":"51"}}),
        "lockunspent" => json!(true),
        _ => return Err("unexpected custody RPC".into()),
    })
}
fn fund(
    j: &AuraComputeJobV1,
    t: &ComputePaymentTermsV1,
    coin: u8,
) -> AuthorizationResultV2<funding::ComputeFundingV1> {
    let txid = format!("{coin:02x}").repeat(32);
    funding::reserve_compute_funding_v1(|m, p| rpc(&txid, 0, m, p), j, t, &txid, 0, 1)
}
fn assignment(id: [u8; 32], worker: u8) -> ComputeAssignmentV1 {
    ComputeAssignmentV1 {
        version: 1,
        compute_job_commitment: id,
        worker_key: key(worker).x_only_public_key().0.serialize(),
    }
}
fn assign(
    q: &mut EconomicJournalV1,
    id: [u8; 32],
    worker: u8,
    coin: u8,
) -> AuthorizationResultV2<[u8; 64]> {
    let a = assignment(id, worker);
    let m = q.measure_compute_at(id, a.worker_key, ComputeBackendV1::Cpu, 250, 110)?;
    q.assign_compute_with_clock(
        &a,
        &a.sign_worker(&key(worker))?,
        &key(1),
        &m,
        |j, t| fund(j, t, coin),
        || Ok(120),
    )
}
fn receipt(
    nonce: u8,
    worker: u8,
    valid: bool,
) -> (
    ComputeReceiptV1,
    ComputeResourceAccountingV1,
    Vec<u8>,
    Vec<u8>,
) {
    let (j, c) = job(nonce);
    let a = assignment(j.commitment().unwrap(), worker);
    let mut output: Vec<u8> = c.payloads[1].iter().rev().copied().collect();
    if !valid {
        output[0] ^= 1;
    }
    let mut h = Sha256::new();
    h.update(j.commitment().unwrap());
    h.update(&output);
    let evidence = h.finalize().to_vec();
    let r = ComputeResourceAccountingV1 {
        version: 1,
        input_bytes: c.payloads[1].len() as u64,
        output_bytes: output.len() as u64,
        evidence_bytes: evidence.len() as u64,
    };
    (
        ComputeReceiptV1 {
            version: 1,
            assignment_commitment: a.commitment().unwrap(),
            output_commitment: compute_result_content_commitment_v1(
                ComputeResultContentKindV1::Output,
                &output,
            )
            .unwrap(),
            execution_evidence_commitment: compute_result_content_commitment_v1(
                ComputeResultContentKindV1::ExecutionEvidence,
                &evidence,
            )
            .unwrap(),
            resource_accounting_commitment: r.commitment().unwrap(),
        },
        r,
        output,
        evidence,
    )
}
fn receive(
    q: &mut EconomicJournalV1,
    n: u8,
    w: u8,
    valid: bool,
    time: u64,
) -> AuthorizationResultV2<ComputeJobStateV1> {
    let (r, c, o, e) = receipt(n, w, valid);
    let a = assignment(job(n).0.commitment()?, w);
    q.receive_compute_with_clock(
        &r,
        &r.sign(&a, &key(w))?,
        &c,
        &o,
        &e,
        a.compute_job_commitment,
        || Ok(time),
    )
}
fn frozen(q: &EconomicJournalV1) -> (String, usize, usize, usize) {
    (
        serde_json::to_string(&q.prior_head().unwrap()).unwrap(),
        q.authorizer
            .connection
            .query_row("SELECT count(*) FROM economic_attempts", [], |r| r.get(0))
            .unwrap(),
        q.outbox().unwrap().len(),
        q.authorizer
            .connection
            .query_row("SELECT count(*) FROM authorizations", [], |r| r.get(0))
            .unwrap(),
    )
}
#[test]
fn accepted_lifecycle_is_durable_idempotent_and_has_no_aura_effects() {
    let d = Db::new();
    let mut q = create(&d);
    let before = frozen(&q);
    let ledger = q.ledger_for_payer(meter().ledger.payer_account_id).unwrap();
    let id = register(&mut q, 1);
    let ack = assign(&mut q, id, 2, 7).unwrap();
    assert_eq!(ack, assign(&mut q, id, 2, 99).unwrap());
    assert!(assign(&mut q, id, 4, 8).is_err());
    receive(&mut q, 1, 2, true, 150).unwrap();
    drop(q);
    let mut q = reopen(&d);
    assert_eq!(
        q.verify_compute_with_clock(id, &key(1), || Ok(400))
            .unwrap(),
        ComputeJobStateV1::Accepted
    );
    let (result, sig) = q.compute_verified_result(id).unwrap().unwrap();
    result
        .verify_signature(&job(1).0, &assignment(id, 2), &receipt(1, 2, true).0, &sig)
        .unwrap();
    let hash = result.commitment().unwrap();
    assert_eq!(
        q.compute_entitlement(id)
            .unwrap()
            .unwrap()
            .compensation_satoshis,
        10000
    );
    assert_eq!(
        q.compute_entitlement(id)
            .unwrap()
            .unwrap()
            .fee_allowance_satoshis,
        42
    );
    assert_eq!(
        q.compute_accepted_output(id).unwrap(),
        receipt(1, 2, true).2
    );
    assert_eq!(
        receive(&mut q, 1, 2, true, 9999).unwrap(),
        ComputeJobStateV1::Accepted
    );
    assert!(receive(&mut q, 1, 2, false, 9999).is_err());
    assert_eq!(
        q.verify_compute_with_clock(id, &key(1), || panic!("retry consulted clock"))
            .unwrap(),
        ComputeJobStateV1::Accepted
    );
    assert!(q
        .release_compute_funding(id, |_, _| panic!("earned funding release"))
        .is_err());
    assert_eq!(
        hash,
        q.compute_verified_result(id)
            .unwrap()
            .unwrap()
            .0
            .commitment()
            .unwrap()
    );
    assert_eq!(before, frozen(&q));
    assert_eq!(
        ledger,
        q.ledger_for_payer(meter().ledger.payer_account_id).unwrap()
    );
    q.audit_state().unwrap();
}
#[test]
fn pending_receipt_survives_deadline_and_infrastructure_failure() {
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    assign(&mut q, id, 2, 7).unwrap();
    receive(&mut q, 1, 2, true, 299).unwrap();
    assert_eq!(
        q.expire_compute_with_clock(id, || Ok(999)).unwrap(),
        ComputeJobStateV1::ReceiptPending
    );
    ERROR.with(|e| *e.borrow_mut() = Some("during_verification"));
    assert!(q
        .verify_compute_with_clock(id, &key(1), || Ok(1000))
        .is_err());
    ERROR.with(|e| *e.borrow_mut() = None);
    drop(q);
    let mut q = reopen(&d);
    assert_eq!(
        q.compute_job_state(id).unwrap(),
        ComputeJobStateV1::ReceiptPending
    );
    assert!(q.release_compute_funding(id, |_, _| panic!()).is_err());
    q.verify_compute_with_clock(id, &key(1), || Ok(1000))
        .unwrap();
}
#[test]
fn immutable_failure_requires_new_nonce_funding_assignment_and_receipt() {
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    assign(&mut q, id, 2, 7).unwrap();
    receive(&mut q, 1, 2, false, 150).unwrap();
    assert_eq!(
        q.verify_compute_with_clock(id, &key(1), || Ok(151))
            .unwrap(),
        ComputeJobStateV1::Rejected
    );
    assert!(q.compute_entitlement(id).unwrap().is_none());
    assert!(receive(&mut q, 1, 2, true, 152).is_err());
    assert!(assign(&mut q, id, 4, 8).is_err());
    assert_eq!(register(&mut q, 1), id);
    assert_eq!(
        q.compute_job_state(id).unwrap(),
        ComputeJobStateV1::Rejected
    );
    q.release_compute_funding(id, |m, p| rpc(&"07".repeat(32), 0, m, p))
        .unwrap();
    let next = register(&mut q, 2);
    assert_ne!(next, id);
    assign(&mut q, next, 4, 8).unwrap();
    receive(&mut q, 2, 4, true, 150).unwrap();
    q.verify_compute_with_clock(next, &key(1), || Ok(160))
        .unwrap();
    assert!(q.compute_entitlement(next).unwrap().is_some());
}
#[test]
fn cancellation_deadline_fences_replay_and_host_capacity() {
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    let c = ComputeCancelV1 {
        version: 1,
        compute_job_commitment: id,
    };
    let sig = c.sign(&job(1).0, &key(3)).unwrap();
    assert!(q
        .cancel_compute_with_clock(&c, &[0; 64], || Ok(101))
        .is_err());
    q.cancel_compute_with_clock(&c, &sig, || Ok(101)).unwrap();
    q.cancel_compute_with_clock(&c, &sig, || panic!()).unwrap();
    assert!(assign(&mut q, id, 2, 7).is_err());
    let (mut j, content) = job(1);
    j.compensation_satoshis += 1;
    assert!(q
        .register_compute_with_clock(
            &j.canonical_bytes().unwrap(),
            &j.sign_request(&key(3)).unwrap(),
            &content,
            || Ok(100)
        )
        .is_err());
    let id = register(&mut q, 2);
    assign(&mut q, id, 2, 7).unwrap();
    let c = ComputeCancelV1 {
        version: 1,
        compute_job_commitment: id,
    };
    assert!(q
        .cancel_compute_with_clock(&c, &c.sign(&job(2).0, &key(3)).unwrap(), || Ok(121))
        .is_err());
    assert!(receive(&mut q, 2, 2, true, 300).is_err());
    q.expire_compute_with_clock(id, || Ok(300)).unwrap();
    assert!(receive(&mut q, 2, 2, true, 299).is_err());
    assert!(q.compute_entitlement(id).unwrap().is_some() == false);
    let id = register(&mut q, 3);
    assert!(q.expire_compute_with_clock(id, || Ok(199)).is_err());
    q.expire_compute_with_clock(id, || Ok(200)).unwrap();
    assert!(assign(&mut q, id, 2, 8).is_err());
    let (mut j, c) = job(4);
    j.max_output_bytes = 5000;
    assert!(q
        .register_compute_with_clock(
            &j.canonical_bytes().unwrap(),
            &j.sign_request(&key(3)).unwrap(),
            &c,
            || Ok(100)
        )
        .is_err());
}
#[test]
fn concurrent_workers_and_verifiers_cannot_split_assignment_or_entitlement() {
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    drop(q);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [2, 4]
        .into_iter()
        .map(|worker| {
            let path = d.0.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let mut q = EconomicJournalV1::open(&path, NET, limits()).unwrap();
                b.wait();
                (worker, assign(&mut q, id, worker, worker).is_ok())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.1).count(), 1);
    let worker = results.iter().find(|r| r.1).unwrap().0;
    let mut q = reopen(&d);
    receive(&mut q, 1, worker, true, 150).unwrap();
    drop(q);
    let b = Arc::new(Barrier::new(2));
    let hs: Vec<_> = (0..2)
        .map(|_| {
            let p = d.0.clone();
            let b = b.clone();
            std::thread::spawn(move || {
                let mut q = EconomicJournalV1::open(&p, NET, limits()).unwrap();
                b.wait();
                q.verify_compute_with_clock(id, &key(1), || Ok(160))
                    .unwrap()
            })
        })
        .collect();
    for h in hs {
        assert_eq!(h.join().unwrap(), ComputeJobStateV1::Accepted);
    }
    reopen(&d).audit_state().unwrap();
}
#[test]
fn custody_checks_exact_fee_zero_insufficient_and_overlap() {
    let (j, c) = job(1);
    let t = c.validate(&j).unwrap();
    let txid = "07".repeat(32);
    for bad in [
        "network",
        "spent",
        "amount",
        "unsafe",
        "locked",
        "lock_failure",
        "missing_script",
        "duplicate_coin",
    ] {
        let r = funding::reserve_compute_funding_v1(
            |m, p| {
                let mut r = rpc(&txid, 0, m, p)?;
                match (bad, m) {
                    ("network", "getblockchaininfo") => r = json!({"chain":"main"}),
                    ("spent", "gettxout") => r = Value::Null,
                    ("amount", "listunspent") => r[0]["amount"] = json!(0.00010041),
                    ("unsafe", "listunspent") => r[0]["safe"] = json!(false),
                    ("locked", "listlockunspent") => r = json!([{"txid":txid,"vout":0}]),
                    ("lock_failure", "lockunspent") => r = json!(false),
                    ("missing_script", "listunspent") => r[0]["scriptPubKey"] = Value::Null,
                    ("missing_script", "gettxout") => r["scriptPubKey"]["hex"] = Value::Null,
                    ("duplicate_coin", "listunspent") => r = json!([r[0], r[0]]),
                    _ => (),
                }
                Ok(r)
            },
            &j,
            &t,
            &txid,
            0,
            1,
        );
        assert!(r.is_err(), "{bad}");
    }
    let mut zero = j.clone();
    let terms = ComputePaymentTermsV1 {
        max_payment_fee_satoshis: 0,
        result_availability_seconds: 1,
    };
    zero.payment_terms_commitment = terms.commitment().unwrap();
    assert_eq!(fund(&zero, &terms, 7).unwrap().reserved_satoshis(), 10000);
    let mut too = j.clone();
    too.compensation_satoshis = u64::MAX;
    assert!(fund(&too, &t, 7).is_err());
    let d = Db::new();
    let mut q = create(&d);
    let first = register(&mut q, 1);
    let second = register(&mut q, 2);
    assign(&mut q, first, 2, 7).unwrap();
    assert!(assign(&mut q, second, 4, 7).is_err());
    assert_eq!(
        q.compute_job_state(second).unwrap(),
        ComputeJobStateV1::Open
    );
    assert!(
        super::super::funding_registry::no_compute_owner(&q.authorizer.connection, &txid, 0)
            .is_err()
    );
}
#[test]
fn corrupted_records_artifacts_entitlements_and_partial_schema_fail_closed() {
    for attack in ["record", "index", "artifact", "entitlement", "partial"] {
        let d = Db::new();
        let mut q = create(&d);
        let id = register(&mut q, 1);
        assign(&mut q, id, 2, 7).unwrap();
        receive(&mut q, 1, 2, true, 150).unwrap();
        q.verify_compute_with_clock(id, &key(1), || Ok(160))
            .unwrap();
        drop(q);
        let c = Connection::open(&d.0).unwrap();
        match attack {
            "record" => {
                c.execute("UPDATE compute_jobs SET checksum=zeroblob(32)", [])
                    .unwrap();
            }
            "index" => {
                c.execute("UPDATE compute_jobs SET state=2", []).unwrap();
            }
            "artifact" => {
                let s: String = c
                    .query_row("SELECT record FROM compute_jobs", [], |r| r.get(0))
                    .unwrap();
                let mut v: Value = serde_json::from_str(&s).unwrap();
                v["receipt"]["output"][0] = json!(0);
                let s = serde_json::to_string(&v).unwrap();
                c.execute(
                    "UPDATE compute_jobs SET record=?1,checksum=?2",
                    params![s, checksum(s.as_bytes())],
                )
                .unwrap();
            }
            "entitlement" => {
                c.execute("DELETE FROM compute_entitlements", []).unwrap();
            }
            "partial" => {
                c.execute("DROP TABLE compute_entitlements", []).unwrap();
            }
            _ => unreachable!(),
        }
        drop(c);
        assert!(
            EconomicJournalV1::open(&d.0, NET, limits()).is_err(),
            "{attack}"
        );
    }
}
#[test]
fn crash_child() {
    let Ok(path) = std::env::var("AURA_C2_DB") else {
        return;
    };
    let mut q = EconomicJournalV1::open(Path::new(&path), NET, limits()).unwrap();
    let id = register(&mut q, 1);
    assign(&mut q, id, 2, 7).unwrap();
    receive(&mut q, 1, 2, true, 150).unwrap();
    q.verify_compute_with_clock(id, &key(1), || Ok(160))
        .unwrap();
}
#[test]
fn process_exit_recovery_preserves_atomic_boundaries() {
    for point in [
        "before_reservation",
        "after_reservation",
        "assignment_before_commit",
        "assignment_after_commit",
        "receipt_before_commit",
        "receipt_after_commit",
        "during_verification",
        "after_result_record",
        "after_entitlement",
        "finalize_before_commit",
        "finalize_after_commit",
    ] {
        let d = Db::new();
        drop(create(&d));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "economic::journal::compute::tests::crash_child",
                "--nocapture",
            ])
            .env("AURA_C2_DB", &d.0)
            .env("AURA_C2_CRASH", point)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86), "{point}");
        let mut q = reopen(&d);
        let id = register(&mut q, 1);
        let state = q.compute_job_state(id).unwrap();
        let expected = match point {
            "before_reservation" | "after_reservation" | "assignment_before_commit" => {
                ComputeJobStateV1::Open
            }
            "assignment_after_commit" | "receipt_before_commit" => ComputeJobStateV1::Assigned,
            "finalize_after_commit" => ComputeJobStateV1::Accepted,
            _ => ComputeJobStateV1::ReceiptPending,
        };
        assert_eq!(state, expected, "{point}");
        assign(&mut q, id, 2, 7).unwrap();
        receive(&mut q, 1, 2, true, 150).unwrap();
        q.verify_compute_with_clock(id, &key(1), || Ok(160))
            .unwrap();
        assert_eq!(
            q.compute_job_state(id).unwrap(),
            ComputeJobStateV1::Accepted
        );
        q.audit_state().unwrap();
    }
}

#[test]
fn compute_and_miner_backing_collisions_reject_in_both_directions() {
    use super::super::miner::{
        funding::reserve_miner_funding_v1, MinerRoundOpeningV1, MinerRoundPolicyV1,
    };
    use crate::miner::{MinerJobPolicyV1, MinerJobV1};
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../../../fixtures/miner_v1/job_profile_vector_v1.json"
    ))
    .unwrap();
    let m = MinerJobV1::decode(&unhex(vector["job_hex"].as_str().unwrap())).unwrap();
    let mut target = [255; 32];
    target[0] = 127;
    let policy = MinerRoundPolicyV1 {
        job: MinerJobPolicyV1 {
            network: NET,
            operator_key: key(1).x_only_public_key().0.serialize(),
            journal_namespace: [4; 32],
            policy_epoch: 0,
            iteration_count: 8,
            target,
            max_work_bytes: 100000,
            max_meter_bytes: 90000,
        },
        max_duration_secs: 600,
        minimum_reward_satoshis: 1000,
    };
    for compute_first in [true, false] {
        let d = Db::new();
        let mut q = create(&d);
        q.install_miner_policy(&policy).unwrap();
        let id = register(&mut q, 1);
        if compute_first {
            assign(&mut q, id, 2, 7).unwrap();
        }
        let open=q.open_miner_round(&key(1),MinerRoundOpeningV1{side_a:m.side_a,side_b:m.side_b,duration_secs:600,reward_satoshis:10000},|j|{
            let txid="07".repeat(32);
            reserve_miner_funding_v1(|method,args|Ok(match method{
                "decodescript"=>json!({"address":"test-only"}),
                "validateaddress"=>json!({"scriptPubKey":format!("5120{}",crate::authorization::encode_hex_v2(&j.operator_key))}),
                "walletcreatefundedpsbt"=>json!({"psbt":"test-only","fee":0.00000001}),
                _=>rpc(&txid,0,method,args)?,
            }),j,&txid,0,42,1)
        });
        assert_eq!(open.is_err(), compute_first);
        if !compute_first {
            assert!(assign(&mut q, id, 2, 7).is_err());
            assert_eq!(q.compute_job_state(id).unwrap(), ComputeJobStateV1::Open);
        }
        q.audit_state().unwrap();
        drop(q);
        reopen(&d).audit_state().unwrap();
    }
}
#[test]
fn assignment_cancel_and_distinct_receipt_races_have_one_durable_owner() {
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    drop(q);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|action| {
            let b = barrier.clone();
            let path = d.0.clone();
            std::thread::spawn(move || {
                let mut q = EconomicJournalV1::open(&path, NET, limits()).unwrap();
                b.wait();
                if action == 0 {
                    assign(&mut q, id, 2, 7).is_ok()
                } else {
                    let cancel = ComputeCancelV1 {
                        version: 1,
                        compute_job_commitment: id,
                    };
                    q.cancel_compute_with_clock(
                        &cancel,
                        &cancel.sign(&job(1).0, &key(3)).unwrap(),
                        || Ok(120),
                    )
                    .is_ok()
                }
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .filter_map(|h| h.join().unwrap().then_some(()))
            .count(),
        1
    );
    reopen(&d).audit_state().unwrap();
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    assign(&mut q, id, 2, 7).unwrap();
    drop(q);
    let b = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [true, false]
        .into_iter()
        .map(|valid| {
            let b = b.clone();
            let path = d.0.clone();
            std::thread::spawn(move || {
                let mut q = EconomicJournalV1::open(&path, NET, limits()).unwrap();
                b.wait();
                (valid, receive(&mut q, 1, 2, valid, 150).is_ok())
            })
        })
        .collect();
    let winners: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|(_, ok)| *ok)
        .collect();
    assert_eq!(winners.len(), 1);
    let mut q = reopen(&d);
    assert_eq!(
        q.verify_compute_with_clock(id, &key(1), || Ok(160))
            .unwrap(),
        if winners[0].0 {
            ComputeJobStateV1::Accepted
        } else {
            ComputeJobStateV1::Rejected
        }
    );
    q.audit_state().unwrap();
}
#[test]
fn capacity_measurement_signer_and_assignment_time_fail_before_funding() {
    let d = Db::new();
    let mut q = create(&d);
    let id = register(&mut q, 1);
    let a = assignment(id, 2);
    assert!(q
        .measure_compute_at(id, a.worker_key, ComputeBackendV1::Gpu, 250, 110)
        .is_err());
    let measured = q
        .measure_compute_at(id, a.worker_key, ComputeBackendV1::Cpu, 250, 110)
        .unwrap();
    for now in [99, 200, 250] {
        assert!(q
            .assign_compute_with_clock(
                &a,
                &a.sign_worker(&key(2)).unwrap(),
                &key(1),
                &measured,
                |_, _| panic!("invalid time reached funding"),
                || Ok(now)
            )
            .is_err());
    }
    assert!(q
        .assign_compute_with_clock(
            &a,
            &a.sign_worker(&key(2)).unwrap(),
            &key(9),
            &measured,
            |_, _| panic!("wrong signer reached funding"),
            || Ok(120)
        )
        .is_err());
    assert!(q
        .assign_compute_with_clock(
            &a,
            &[0; 64],
            &key(1),
            &measured,
            |_, _| panic!("wrong worker reached funding"),
            || Ok(120)
        )
        .is_err());
    for after_custody in [119, 200, 250] {
        let mut calls = 0;
        assert!(q
            .assign_compute_with_clock(
                &a,
                &a.sign_worker(&key(2)).unwrap(),
                &key(1),
                &measured,
                |j, t| fund(j, t, 7),
                || {
                    calls += 1;
                    Ok(if calls == 1 { 120 } else { after_custody })
                }
            )
            .is_err());
        assert_eq!(calls, 2);
        assert_eq!(q.compute_job_state(id).unwrap(), ComputeJobStateV1::Open);
        assert!(q.compute_entitlement(id).unwrap().is_none());
        let cfg = config(&q.authorizer.connection, NET).unwrap();
        let r = load(&q.authorizer.connection, &id, &cfg).unwrap();
        assert!(r.assignment.is_none() && r.funding.is_none());
        q.audit_state().unwrap();
    }
    let (j, c) = job(2);
    assert!(q
        .register_compute_with_clock(&j.canonical_bytes().unwrap(), &[0; 64], &c, || Ok(100))
        .is_err());
    let d = Db::new();
    let mut q = EconomicJournalV1::create(&d.0, NET, &meter().ledger, limits()).unwrap();
    let mut p = policy();
    p.max_record_bytes = 20000;
    q.install_compute(&p).unwrap();
    assert!(q
        .register_compute_with_clock(
            &j.canonical_bytes().unwrap(),
            &j.sign_request(&key(3)).unwrap(),
            &c,
            || Ok(100)
        )
        .is_err());
}
