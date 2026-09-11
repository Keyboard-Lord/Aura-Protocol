use super::*;
use crate::authorization::encode_hex_v2;
use aura_intent_lineage_v1::{derive_phi_n, derive_psi_n, execute_storm_v1};
use secp256k1::{Secp256k1, SecretKey};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
struct Sample {
    job: MinerJobV1,
    meter: EconomicMeterV1,
    key: Keypair,
    policy: MinerJobPolicyV1,
    signature: [u8; 64],
    limits: MinerLimitsV1,
}
impl Sample {
    fn new(target_high_byte: u8) -> Self {
        let v: Value = serde_json::from_str(include_str!(
            "../../../../fixtures/miner_v1/job_profile_vector_v1.json"
        ))
        .unwrap();
        let mut job = MinerJobV1::decode(&unhex(v["job_hex"].as_str().unwrap())).unwrap();
        job.iteration_count = 8;
        job.target = [255; 32];
        job.target[0] = target_high_byte;
        if target_high_byte == 0 {
            job.target = [0; 32];
            job.target[31] = 1;
        }
        let meter =
            EconomicMeterV1::decode(&unhex(v["meter_hex"].as_str().unwrap()), 90_000).unwrap();
        let key = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array(
                unhex(v["test_only_operator_secret_hex"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        );
        let signature = *Secp256k1::new()
            .sign_schnorr_no_aux_rand(&job.signing_digest().unwrap(), &key)
            .as_ref();
        let policy = MinerJobPolicyV1 {
            network: job.network,
            operator_key: job.operator_key,
            journal_namespace: job.journal_namespace,
            policy_epoch: job.policy_epoch,
            iteration_count: job.iteration_count,
            target: job.target,
            max_work_bytes: job.max_work_bytes,
            max_meter_bytes: job.max_meter_bytes,
        };
        Self {
            job,
            meter,
            key,
            policy,
            signature,
            limits: MinerLimitsV1 {
                work: EconomicLimitsV1 {
                    max_work_bytes: 100_000,
                    max_meter_bytes: 90_000,
                    max_iterations: 128,
                },
                max_proof_bytes: 1_000_000,
            },
        }
    }
    fn session(&self) -> MinerSessionV1<'_> {
        MinerSessionV1::new(
            &self.job,
            &self.signature,
            &self.policy,
            &self.meter,
            &self.key,
            self.limits,
        )
        .unwrap()
    }
}
fn nonce(index: u64) -> [u8; 32] {
    let mut n = [0x42; 32];
    n[24..].copy_from_slice(&index.to_be_bytes());
    n
}
fn config(max_trials: u64) -> MinerSearchConfigV1 {
    MinerSearchConfigV1 {
        max_trials,
        max_duration: Duration::from_secs(30),
        nonce_mode: MinerNonceModeV1::ResearchSequential { first: nonce(0) },
    }
}
fn search(sample: &Sample, config: MinerSearchConfigV1) -> MinerSearchOutcomeV1 {
    sample
        .session()
        .mine_with_sources(
            config,
            &AtomicBool::new(false),
            || Ok(sample.job.opened_at),
            || panic!("research search must not use RNG"),
        )
        .unwrap()
}
fn assert_same(a: &MinerTrialV1, b: &MinerTrialV1) {
    assert_eq!(
        a.work.canonical_bytes().unwrap(),
        b.work.canonical_bytes().unwrap()
    );
    assert_eq!(a.claim.canonical_bytes(), b.claim.canonical_bytes());
    assert_eq!(a.proof, b.proof);
    assert_eq!(a.prepared, b.prepared);
    assert_eq!(a.qualifies, b.qualifies);
    assert_eq!(a.trial_index, b.trial_index);
}

#[test]
fn deterministic_trial_matches_independent_canonical_owners() {
    let s = Sample::new(0x7f);
    let a = s.session().trial(nonce(0), 0).unwrap();
    assert_same(&a, &s.session().trial(nonce(0), 0).unwrap());
    let w = s.job.build_work(s.meter.clone(), nonce(0)).unwrap();
    let claim = build_storm_claim_v1(&w.storm, [0; 32], [0; 32]);
    let inputs = build_storm_air_public_inputs_v1(&claim);
    let proof = prove_storm_air_real_v1(&claim, &inputs).unwrap();
    verify_storm_air_real_v1(&inputs, &proof).unwrap();
    let prepared = prepare_bound_proof_material_v1(
        w.subject(),
        w.nonce(),
        &proof.proof_bytes,
        &inputs.canonical_bytes(),
        &[],
    )
    .unwrap();
    assert_eq!(a.work, w);
    assert_eq!(a.claim, claim);
    assert_eq!(a.proof, proof);
    assert_eq!(a.prepared, prepared);
    assert_eq!(
        verify_miner_trial_v1(&s.job, &a, s.limits).unwrap(),
        a.qualifies()
    );
    assert!(a.timings.total >= a.timings.storm_execution_and_claim);
}

#[test]
fn nonce_changes_forcing_every_noninitial_row_root_proof_and_reference() {
    let s = Sample::new(0x7f);
    let session = s.session();
    let a = session.trial(nonce(0), 0).unwrap();
    let b = session.trial(nonce(1), 1).unwrap();
    let x = &a.work.storm;
    let y = &b.work.storm;
    let ex = execute_storm_v1(x);
    let ey = execute_storm_v1(y);
    assert_ne!(x.context_bytes_v1, y.context_bytes_v1);
    assert_eq!(ex.initial_state, ey.initial_state); // Side-only precomputation is legitimate.
    assert_ne!(ex.a, ey.a);
    assert_ne!(ex.b, ey.b);
    for n in 0..8 {
        assert_ne!(
            derive_phi_n(&x.side_a, &x.side_b, &x.context_bytes_v1, n),
            derive_phi_n(&y.side_a, &y.side_b, &y.context_bytes_v1, n)
        );
        assert_ne!(
            derive_psi_n(&x.side_a, &x.side_b, &x.context_bytes_v1, n),
            derive_psi_n(&y.side_a, &y.side_b, &y.context_bytes_v1, n)
        );
    }
    for (a, b) in ex.trace[1..].iter().zip(&ey.trace[1..]) {
        assert_ne!(a, b);
    }
    assert_ne!(a.claim.trace_root, b.claim.trace_root);
    assert_ne!(a.proof.proof_bytes, b.proof.proof_bytes);
    assert_ne!(a.proof_hash(), b.proof_hash());
}

#[test]
fn copied_proof_and_cheap_outer_rebinding_never_verify_as_new_nonce_work() {
    let s = Sample::new(0x7f);
    let session = s.session();
    let a = session.trial(nonce(0), 0).unwrap();
    let mut copied = session.trial(nonce(1), 1).unwrap();
    copied.proof = a.proof.clone();
    assert!(verify_miner_trial_v1(&s.job, &copied, s.limits).is_err());
    // Keep one proof. Rebind only existing FractalKey freshness bytes, cheaply.
    // A low outer hash must still fail full profile/proof binding.
    let inputs = build_storm_air_public_inputs_v1(a.claim()).canonical_bytes();
    let mut low_rebindings = 0;
    for index in 100..116 {
        let n = nonce(index);
        let mut forged = a.clone();
        forged.work = s.job.build_work(s.meter.clone(), n).unwrap();
        forged.prepared = prepare_bound_proof_material_v1(
            a.work.subject(),
            n,
            &a.proof.proof_bytes,
            &inputs,
            &[],
        )
        .unwrap();
        if s.job.passes_hash_filter(&forged.proof_hash()).unwrap() {
            low_rebindings += 1;
        }
        assert!(verify_miner_trial_v1(&s.job, &forged, s.limits).is_err());
        // Even rewriting claim context and deriving artifact metadata cannot fix the witness.
        forged.claim.context_bytes_v1 = forged.work.storm.context_bytes_v1;
        assert!(verify_miner_trial_v1(&s.job, &forged, s.limits).is_err());
    }
    assert!(low_rebindings > 0); // Fixed deterministic corpus, no probabilistic CI search.
}

#[test]
fn altered_witness_with_recomputed_metadata_and_material_fails_actual_verification() {
    let s = Sample::new(0x7f);
    let mut a = s.session().trial(nonce(0), 0).unwrap();
    // Alter canonical witness field bytes without altering the embedded claim.
    let last = a.proof.proof_bytes.len() - 1;
    a.proof.proof_bytes[last] ^= 1;
    let (_, proof) = decode_storm_air_real_artifact_v1(a.proof.proof_bytes.clone()).unwrap();
    a.proof = proof;
    let inputs = build_storm_air_public_inputs_v1(&a.claim).canonical_bytes();
    a.prepared = prepare_bound_proof_material_v1(
        a.work.subject(),
        a.nonce(),
        &a.proof.proof_bytes,
        &inputs,
        &[],
    )
    .unwrap();
    assert!(verify_miner_trial_v1(&s.job, &a, s.limits).is_err());
    let mut a = s.session().trial(nonce(0), 0).unwrap();
    a.prepared.proof_hash = [0; 32];
    assert!(s.job.passes_hash_filter(&a.proof_hash()).unwrap());
    assert!(verify_miner_trial_v1(&s.job, &a, s.limits).is_err());
    let mut a = s.session().trial(nonce(0), 0).unwrap();
    a.prepared.proof_material_hash[0] ^= 1;
    assert!(verify_miner_trial_v1(&s.job, &a, s.limits).is_err());
}

#[test]
fn diagnostic_thresholds_do_not_change_computation_but_signed_job_target_does() {
    let s = Sample::new(0x7f);
    let a = s.session().trial(nonce(0), 0).unwrap();
    let snapshot = a.clone();
    let h = a.proof_hash();
    let mut diagnostic = s.job.clone();
    diagnostic.target = h;
    assert!(diagnostic.passes_hash_filter(&h).unwrap());
    diagnostic.target = next_research_nonce(h).unwrap();
    assert!(diagnostic.passes_hash_filter(&h).unwrap());
    let mut lower = h;
    for byte in lower.iter_mut().rev() {
        let (value, borrow) = byte.overflowing_sub(1);
        *byte = value;
        if !borrow {
            break;
        }
    }
    diagnostic.target = lower;
    assert!(!diagnostic.passes_hash_filter(&h).unwrap());
    assert_same(&a, &snapshot);
    // Diagnostics never make this differently signed job a valid profile for a.
    assert!(verify_miner_trial_v1(&diagnostic, &a, s.limits).is_err());
    let changed = diagnostic.build_work(s.meter.clone(), a.nonce()).unwrap();
    assert_ne!(
        changed.storm.context_bytes_v1,
        a.work.storm.context_bytes_v1
    );
}

#[test]
fn bounded_success_reproduces_first_qualifying_independent_trial() {
    let s = Sample::new(0x7f);
    let MinerSearchOutcomeV1::Qualified(a) = search(&s, config(16)) else {
        panic!("fixed easy corpus must qualify");
    };
    let MinerSearchOutcomeV1::Qualified(b) = search(&s, config(16)) else {
        panic!("deterministic repeat");
    };
    assert_same(&a, &b);
    for i in 0..=a.trial_index() {
        let t = s.session().trial(nonce(i), i).unwrap();
        assert_eq!(t.qualifies(), i == a.trial_index());
        if i == a.trial_index() {
            assert_same(&a, &t);
        }
    }
}

#[test]
fn exhaustion_and_zero_trial_budget_are_exact() {
    let s = Sample::new(0);
    for count in [0, 2] {
        assert!(
            matches!(search(&s,config(count)),MinerSearchOutcomeV1::Stopped {reason:MinerSearchStopV1::TrialLimit,trials_completed} if trials_completed==count)
        );
    }
}

#[test]
fn cancellation_deadline_and_expiry_discard_results_at_trial_boundaries() {
    let s = Sample::new(0x7f);
    let session = s.session();
    assert!(matches!(
        session.mine(config(2), &AtomicBool::new(true)).unwrap(),
        MinerSearchOutcomeV1::Stopped {
            reason: MinerSearchStopV1::Cancelled,
            trials_completed: 0
        }
    ));
    let mut c = config(2);
    c.max_duration = Duration::ZERO;
    assert!(matches!(
        session.mine(c, &AtomicBool::new(false)).unwrap(),
        MinerSearchOutcomeV1::Stopped {
            reason: MinerSearchStopV1::TimeLimit,
            trials_completed: 0
        }
    ));
    let mut calls = 0;
    let result = session
        .mine_with_sources(
            config(2),
            &AtomicBool::new(false),
            || {
                calls += 1;
                Ok(if calls == 1 {
                    s.job.opened_at
                } else {
                    s.job.expires_at
                })
            },
            || panic!(),
        )
        .unwrap();
    assert!(matches!(
        result,
        MinerSearchOutcomeV1::Stopped {
            reason: MinerSearchStopV1::JobExpired,
            trials_completed: 1
        }
    ));
    let flag = AtomicBool::new(false);
    let result = session
        .mine_with_sources(
            config(2),
            &flag,
            || {
                flag.store(true, Ordering::Relaxed);
                Ok(s.job.opened_at)
            },
            || panic!(),
        )
        .unwrap();
    assert!(matches!(
        result,
        MinerSearchOutcomeV1::Stopped {
            reason: MinerSearchStopV1::Cancelled,
            trials_completed: 1
        }
    ));
    assert!(session
        .mine_with_sources(
            config(1),
            &AtomicBool::new(false),
            || Ok(s.job.opened_at - 1),
            || panic!()
        )
        .is_err());
}

#[test]
fn nonce_sequence_cannot_wrap_and_rng_duplicates_fail_closed() {
    assert_eq!(next_research_nonce([255; 32]), None);
    let s = Sample::new(0);
    let mut c = config(2);
    c.nonce_mode = MinerNonceModeV1::ResearchSequential { first: [255; 32] };
    assert!(matches!(
        search(&s, c),
        MinerSearchOutcomeV1::Stopped {
            reason: MinerSearchStopV1::NonceSpaceExhausted,
            trials_completed: 1
        }
    ));
    c.nonce_mode = MinerNonceModeV1::SecureRandom;
    let error = s
        .session()
        .mine_with_sources(
            c,
            &AtomicBool::new(false),
            || Ok(s.job.opened_at),
            || Ok(nonce(0)),
        )
        .unwrap_err();
    assert!(error.to_string().contains("duplicate mining nonce"));
}

#[test]
fn invalid_identity_job_and_host_limits_fail_without_qualifying() {
    let mut s = Sample::new(0x7f);
    s.signature[0] ^= 1;
    assert!(
        MinerSessionV1::new(&s.job, &s.signature, &s.policy, &s.meter, &s.key, s.limits).is_err()
    );
    let mut s = Sample::new(0x7f);
    s.limits.work.max_iterations = 7;
    assert!(
        MinerSessionV1::new(&s.job, &s.signature, &s.policy, &s.meter, &s.key, s.limits).is_err()
    );
    let mut s = Sample::new(0x7f);
    s.meter.ledger.payer_account_id = [0; 32];
    assert!(
        MinerSessionV1::new(&s.job, &s.signature, &s.policy, &s.meter, &s.key, s.limits).is_err()
    );
    let mut s = Sample::new(0x7f);
    s.limits.max_proof_bytes = 1;
    assert!(s.session().trial(nonce(0), 0).is_err());
}

#[test]
fn parallel_independent_trials_are_byte_identical_to_isolated_execution() {
    let s = Sample::new(0x7f);
    let session = s.session();
    let parallel = std::thread::scope(|scope| {
        let a = scope.spawn(|| session.trial(nonce(0), 0).unwrap());
        let b = scope.spawn(|| session.trial(nonce(1), 1).unwrap());
        [a.join().unwrap(), b.join().unwrap()]
    });
    for (i, trial) in parallel.iter().enumerate() {
        assert_same(trial, &session.trial(nonce(i as u64), i as u64).unwrap());
    }
}

#[test]
fn side_only_initial_state_reuse_is_equivalent_but_partial_trace_reuse_fails() {
    use aura_intent_lineage_v1::{
        build_storm_trace_witness_v1, canonical_storm_trace_witness_bytes_v1, storm_step,
    };
    let s = Sample::new(0x7f);
    let a = s.session().trial(nonce(0), 0).unwrap();
    let b = s.session().trial(nonce(1), 1).unwrap();
    let ea = execute_storm_v1(&a.work.storm);
    let eb = execute_storm_v1(&b.work.storm);
    let mut state = ea.initial_state;
    for n in 0..8 {
        let i = &b.work.storm;
        state = storm_step(
            &state,
            &eb.a,
            &eb.b,
            &derive_phi_n(&i.side_a, &i.side_b, &i.context_bytes_v1, n),
            &derive_psi_n(&i.side_a, &i.side_b, &i.context_bytes_v1, n),
        );
        assert_eq!(state, eb.trace[n as usize + 1]);
    }
    let mut witness = build_storm_trace_witness_v1(&b.claim).unwrap();
    witness.trace[1..5].copy_from_slice(&ea.trace[1..5]);
    for (step, pair) in witness.steps.iter_mut().zip(witness.trace.windows(2)) {
        step.state = pair[0];
        step.next_state = pair[1];
    }
    let mut forged = b;
    let witness_offset = 8 + forged.claim.canonical_bytes().len() + 8;
    let replacement = canonical_storm_trace_witness_bytes_v1(&witness);
    assert_eq!(
        replacement.len(),
        forged.proof.proof_bytes.len() - witness_offset
    );
    forged.proof.proof_bytes[witness_offset..].copy_from_slice(&replacement);
    let (_, proof) = decode_storm_air_real_artifact_v1(forged.proof.proof_bytes).unwrap();
    forged.proof = proof;
    let inputs = build_storm_air_public_inputs_v1(&forged.claim).canonical_bytes();
    forged.prepared = prepare_bound_proof_material_v1(
        forged.work.subject(),
        forged.nonce(),
        &forged.proof.proof_bytes,
        &inputs,
        &[],
    )
    .unwrap();
    assert!(verify_miner_trial_v1(&s.job, &forged, s.limits).is_err());
}

#[test]
fn frozen_m3_existing_objects_match() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/miner_v1/trial_vector_v1.json"
    ))
    .unwrap();
    let s = Sample::new(0x7f);
    let trial = s.session().trial(nonce(0), 0).unwrap();
    assert_eq!(
        encode_hex_v2(&trial.work.canonical_bytes().unwrap()),
        v["work_hex"]
    );
    assert_eq!(
        encode_hex_v2(&trial.claim.canonical_bytes()),
        v["claim_hex"]
    );
    assert_eq!(encode_hex_v2(&trial.proof.proof_bytes), v["proof_hex"]);
    assert_eq!(
        encode_hex_v2(&build_storm_air_public_inputs_v1(&trial.claim).canonical_bytes()),
        v["public_inputs_hex"]
    );
    assert_eq!(
        encode_hex_v2(&trial.prepared.proof_material.canonical_bytes()),
        v["material_hex"]
    );
    assert_eq!(
        encode_hex_v2(&trial.prepared.fractal_key.canonical_bytes()),
        v["fractal_key_hex"]
    );
    assert_eq!(encode_hex_v2(&trial.proof_hash()), v["proof_hash_hex"]);
    assert_eq!(trial.qualifies(), v["qualifies"].as_bool().unwrap());
}
