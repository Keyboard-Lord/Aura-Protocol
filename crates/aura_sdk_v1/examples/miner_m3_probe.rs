//! Deterministic local research evidence. Never an admission or reward producer.
use aura_intent_lineage_v1::{
    build_storm_air_public_inputs_v1, derive_phi_n, derive_psi_n, execute_storm_v1,
    STORM_STATE_521_ROW_BYTE_LEN_V1,
};
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use aura_sdk_v1::{
    authorization::encode_hex_v2,
    economic::EconomicLimitsV1,
    miner::{MinerJobPolicyV1, MinerJobV1},
    miner_search::{MinerLimitsV1, MinerSessionV1},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::time::Instant;

fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn nonce(i: u64) -> [u8; 32] {
    let mut n = [0x42; 32];
    n[24..].copy_from_slice(&i.to_be_bytes());
    n
}
fn ms(seconds: f64) -> f64 {
    (seconds * 1_000_000.0).round() / 1000.0
}
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let vector = args.as_slice() == ["--vector"];
    let n = if vector {
        8
    } else {
        args.first()
            .ok_or("usage: miner_m3_probe N trials | --vector")?
            .parse::<u64>()?
    };
    let trials = if vector {
        1
    } else {
        args.get(1)
            .ok_or("missing bounded trial count")?
            .parse::<u64>()?
    };
    if ![8, 16, 32, 64, 128].contains(&n) || !(1..=512).contains(&trials) {
        return Err("probe bounds: N in 8,16,32,64,128 and 1..512 trials".into());
    }
    let v: Value = serde_json::from_str(include_str!(
        "../../../fixtures/miner_v1/job_profile_vector_v1.json"
    ))?;
    let mut job = MinerJobV1::decode(&bytes(v["job_hex"].as_str().unwrap()))?;
    job.iteration_count = n;
    job.target = [255; 32];
    job.target[0] = 0x7f;
    let meter = EconomicMeterV1::decode(&bytes(v["meter_hex"].as_str().unwrap()), 90_000)?;
    let key = Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_byte_array(
            bytes(v["test_only_operator_secret_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )?,
    );
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(&job.signing_digest()?, &key);
    // Locally generated, explicitly trusted research policy; never inferred from network input.
    let policy = MinerJobPolicyV1 {
        network: job.network,
        operator_key: job.operator_key,
        journal_namespace: job.journal_namespace,
        policy_epoch: job.policy_epoch,
        iteration_count: n,
        target: job.target,
        max_work_bytes: job.max_work_bytes,
        max_meter_bytes: job.max_meter_bytes,
    };
    let limits = MinerLimitsV1 {
        work: EconomicLimitsV1 {
            max_work_bytes: 100_000,
            max_meter_bytes: 90_000,
            max_iterations: 128,
        },
        max_proof_bytes: 1_000_000,
    };
    let session = MinerSessionV1::new(&job, signature.as_ref(), &policy, &meter, &key, limits)?;
    if vector {
        let t = session.trial(nonce(0), 0)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "classification":"FROZEN M3 TEST EVIDENCE; existing canonical objects only, not a candidate wire",
                "job_hex":encode_hex_v2(&job.canonical_bytes()?), "job_signature_hex":encode_hex_v2(signature.as_ref()),
                "nonce_hex":encode_hex_v2(&t.nonce()), "iteration_count":n,
                "work_hex":encode_hex_v2(&t.work().canonical_bytes()?), "claim_hex":encode_hex_v2(&t.claim().canonical_bytes()),
                "proof_hex":encode_hex_v2(&t.proof().proof_bytes),
                "public_inputs_hex":encode_hex_v2(&build_storm_air_public_inputs_v1(t.claim()).canonical_bytes()),
                "material_hex":encode_hex_v2(&t.prepared().proof_material.canonical_bytes()),
                "proof_material_hash_hex":encode_hex_v2(&t.prepared().proof_material_hash),
                "fractal_key_hex":encode_hex_v2(&t.prepared().fractal_key.canonical_bytes()),
                "proof_hash_hex":encode_hex_v2(&t.proof_hash()), "qualifies":t.qualifies(),
            }))?
        );
        return Ok(());
    }
    let mut durations = Vec::new();
    let mut stages = [0.0; 5];
    let mut hashes = Vec::new();
    let mut hits = [0u64; 3];
    let mut first_two = Vec::new();
    let mut proof_bytes = 0;
    let mut witness_bytes = 0;
    // Warm up one independently verified trial. Excluded from the measured sample.
    session.trial(nonce(u64::MAX), u64::MAX)?;
    let started = Instant::now();
    for index in 0..trials {
        let t = session.trial(nonce(index), index)?;
        let timing = t.timings();
        durations.push(timing.total.as_secs_f64());
        for (sum, d) in stages.iter_mut().zip([
            timing.work_profile,
            timing.storm_execution_and_claim,
            timing.proof_construction,
            timing.proof_verification,
            timing.material_binding,
        ]) {
            *sum += d.as_secs_f64();
        }
        // Same completed reference, no new execution and no qualification override.
        let hash = t.proof_hash();
        for (count, high) in hits.iter_mut().zip([0x7f, 0x3f, 0x0f]) {
            let mut threshold = [255; 32];
            threshold[0] = high;
            if hash <= threshold {
                *count += 1;
            }
        }
        assert_eq!(t.qualifies(), hash <= job.target);
        hashes.push(encode_hex_v2(&hash));
        proof_bytes = t.proof().proof_bytes.len();
        // Observable size of the existing framed witness; no new serializer.
        witness_bytes = proof_bytes - t.claim().canonical_bytes().len() - 16;
        if index < 2 {
            first_two.push(t);
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let mean = durations.iter().sum::<f64>() / trials as f64;
    durations.sort_by(f64::total_cmp);
    let mid = durations.len() / 2;
    let median = if durations.len() % 2 == 0 {
        (durations[mid - 1] + durations[mid]) / 2.0
    } else {
        durations[mid]
    };
    let propagation = if first_two.len() == 2 {
        let a = &first_two[0].work().storm;
        let b = &first_two[1].work().storm;
        let pure_execution_start = Instant::now();
        let x = execute_storm_v1(a);
        let y = execute_storm_v1(b);
        let pure_execution_mean_ms = ms(pure_execution_start.elapsed().as_secs_f64() / 2.0);
        let all_forcing = (0..n).all(|i| {
            derive_phi_n(&a.side_a, &a.side_b, &a.context_bytes_v1, i)
                != derive_phi_n(&b.side_a, &b.side_b, &b.context_bytes_v1, i)
                && derive_psi_n(&a.side_a, &a.side_b, &a.context_bytes_v1, i)
                    != derive_psi_n(&b.side_a, &b.side_b, &b.context_bytes_v1, i)
        });
        let changed_rows = x.trace[1..]
            .iter()
            .zip(&y.trace[1..])
            .filter(|(a, b)| a != b)
            .count();
        assert!(all_forcing && changed_rows == n as usize && x.a != y.a && x.b != y.b);
        json!({"all_forcing_pairs_changed":all_forcing,"changed_noninitial_rows":changed_rows,
            "pure_execution_diagnostic_runs":2,"pure_execution_diagnostic_mean_ms":pure_execution_mean_ms,
            "initial_state_invariant":x.initial_state==y.initial_state,"parameters_changed":true,
            "trace_root_changed":first_two[0].claim().trace_root!=first_two[1].claim().trace_root,
            "proof_changed":first_two[0].proof().proof_bytes!=first_two[1].proof().proof_bytes})
    } else {
        Value::Null
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "classification":"M3 IMPLEMENTATION MEASUREMENTS; not protocol constants or security proof",
            "N":n,"trials":trials,"warmup_trials":1,"build":"release expected","debug_assertions":cfg!(debug_assertions),
            "nonce_sequence":"24 bytes 0x42 || u64_be(index), research only",
            "job_hex":encode_hex_v2(&job.canonical_bytes()?),"job_commitment_hex":encode_hex_v2(&job.commitment()?),
            "total_runtime_ms":ms(elapsed),"mean_trial_ms":ms(mean),"median_trial_ms":ms(median),
            "trials_per_second":(trials as f64/elapsed*100.0).round()/100.0,
            "mean_work_profile_ms":ms(stages[0]/trials as f64),
            "mean_storm_execution_and_claim_ms":ms(stages[1]/trials as f64),
            "mean_proof_construction_ms":ms(stages[2]/trials as f64),
            "mean_proof_verification_ms":ms(stages[3]/trials as f64),
            "mean_material_binding_ms":ms(stages[4]/trials as f64),
            "proof_bytes":proof_bytes,"witness_bytes":witness_bytes,"trace_rows":n+1,
            "canonical_trace_row_bytes":(n+1)*STORM_STATE_521_ROW_BYTE_LEN_V1 as u64,
            "qualifying_hashes_observed":hits[0],"expected_hit_probability":0.5,"observed_hit_rate":hits[0] as f64/trials as f64,
            "diagnostic_hits":{"q_1_2":hits[0],"q_1_4":hits[1],"q_1_16":hits[2]},
            "proof_hashes_hex":hashes,"nonce_propagation":propagation,
            "timing_note":"Instant wall times rounded to 0.001 ms. Claim stage includes Storm and TRACE_ROOT; prove/verify include internal replays. Total includes sample collection. Propagation diagnostics excluded."
        }))?
    );
    Ok(())
}
