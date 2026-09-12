//! C1 boundary tests. No adapter, journal, burn, Aura proof verdict or payment.
#[path = "support/compute_job_vectors.rs"]
mod support;
use aura_sdk_v1::{
    compute_job::*,
    economic::EconomicLimitsV1,
    miner::{MinerJobPolicyV1, MinerJobV1},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use support::*;
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/compute_job_v1/job_vectors_v1.json"
    ))
    .unwrap()
}
fn data(v: &Value, k: &str) -> Vec<u8> {
    unhex(v[k].as_str().unwrap())
}
fn host() -> ComputeJobLimitsV1 {
    ComputeJobLimitsV1 {
        max_input_bytes: u64::MAX,
        max_output_bytes: u64::MAX,
        max_evidence_bytes: u64::MAX,
        max_memory_bytes: u64::MAX,
        max_scratch_bytes: u64::MAX,
        max_execution_ms: u64::MAX,
    }
}
fn policy(j: &MinerJobV1) -> MinerJobPolicyV1 {
    MinerJobPolicyV1 {
        network: j.network,
        operator_key: j.operator_key,
        journal_namespace: j.journal_namespace,
        policy_epoch: j.policy_epoch,
        iteration_count: j.iteration_count,
        target: j.target,
        max_work_bytes: j.max_work_bytes,
        max_meter_bytes: j.max_meter_bytes,
    }
}

#[test]
fn independent_typed_construction_matches_all_shared_bytes() {
    let v = vector();
    assert_eq!(snapshot(), v);
    let j = job();
    let b = data(&v["base"], "job_hex");
    assert_eq!(COMPUTE_JOB_V1_BYTE_LEN, 546);
    assert_eq!(j.canonical_bytes().unwrap(), b);
    assert_eq!(AuraComputeJobV1::decode(&b).unwrap(), j);
    for x in v["valid_jobs"].as_array().unwrap() {
        let bytes = data(x, "job_hex");
        let j = AuraComputeJobV1::decode(&bytes).unwrap();
        assert_eq!(j.canonical_bytes().unwrap(), bytes);
        assert_eq!(
            j.commitment().unwrap().as_slice(),
            data(x, "commitment_hex")
        );
        assert_eq!(
            j.signing_digest().unwrap().as_slice(),
            data(x, "signing_digest_hex")
        );
        j.verify_request(&data(x, "signature_hex")).unwrap();
    }
    assert_eq!(&b[473..481], &10000u64.to_le_bytes());
}
#[test]
fn every_job_and_signature_byte_is_bound_without_normalization() {
    let v = vector();
    let b = data(&v["base"], "job_hex");
    let sig = data(&v["base"], "signature_hex");
    let expected = v["single_bit_mutation_decodes"]
        .as_str()
        .unwrap()
        .as_bytes();
    assert_eq!(expected.len(), 546);
    for i in 0..546 {
        let mut changed = b.clone();
        changed[i] ^= 1;
        let result = AuraComputeJobV1::decode(&changed);
        assert_eq!(result.is_ok(), expected[i] == b'1', "decode {i}");
        if let Ok(c) = result {
            assert_eq!(c.canonical_bytes().unwrap(), changed);
            assert_ne!(c.commitment().unwrap(), job().commitment().unwrap());
            assert!(c.verify_request(&sig).is_err(), "signature byte {i}");
        }
    }
    for i in 0..64 {
        let mut s = sig.clone();
        s[i] ^= 1;
        assert!(job().verify_request(&s).is_err());
    }
    for n in [0, 1, 32, 63, 65, 128] {
        assert!(job().verify_request(&vec![0; n]).is_err());
    }
}
#[test]
fn framing_classes_invalid_keys_and_numeric_negatives() {
    let v = vector();
    let b = data(&v["base"], "job_hex");
    for n in 0..546 {
        assert!(AuraComputeJobV1::decode(&b[..n]).is_err());
    }
    for n in [1, 32, 546] {
        let mut c = b.clone();
        c.extend(vec![0; n]);
        assert!(AuraComputeJobV1::decode(&c).is_err());
    }
    for x in v["invalid_patches"].as_array().unwrap() {
        let mut c = b.clone();
        let p = data(x, "replacement_hex");
        let o = x["offset"].as_u64().unwrap() as usize;
        c[o..o + p.len()].copy_from_slice(&p);
        assert!(AuraComputeJobV1::decode(&c).is_err(), "{}", x["name"]);
    }
    for (offset, first) in [(20, 5), (311, 8), (344, 5), (545, 2)] {
        for tag in first..=255 {
            let mut c = b.clone();
            c[offset] = tag;
            assert!(AuraComputeJobV1::decode(&c).is_err());
        }
    }
    let mut c = job();
    c.workload_class = u16::MAX;
    assert!(c.canonical_bytes().is_err());
}
#[test]
fn signatures_scopes_and_pure_replay_classification() {
    let v = vector();
    let j = job();
    let s = data(&v["base"], "signature_hex");
    let t = ComputeCoordinatorV1 {
        network: j.network,
        coordinator_key: j.coordinator_key,
        journal_namespace: j.journal_namespace,
    };
    j.verify_for_coordinator(&s, &t).unwrap();
    for f in [0, 1, 2] {
        let mut bad = t.clone();
        match f {
            0 => bad.network = aura_bitcoin_v1::BitcoinNetworkV1::Mainnet,
            1 => bad.coordinator_key = key(4).x_only_public_key().0.serialize(),
            _ => bad.journal_namespace[0] ^= 1,
        };
        assert!(j.verify_for_coordinator(&s, &bad).is_err());
    }
    for (i, x) in v["retry_cases"].as_array().unwrap().iter().enumerate() {
        let incoming = AuraComputeJobV1::decode(&data(x, "job_hex")).unwrap();
        let expected = if i == 0 {
            ComputeRetryV1::Idempotent
        } else if i == 1 || i == 7 {
            ComputeRetryV1::Conflict
        } else {
            ComputeRetryV1::DistinctScope
        };
        assert_eq!(
            j.classify_retry(&incoming, &data(x, "signature_hex"))
                .unwrap(),
            expected
        );
        assert!(j.classify_retry(&incoming, &[0; 64]).is_err());
    }
    let alt = data(&v, "alternate_signature_hex");
    assert_ne!(s, alt);
    assert!(j
        .validate_new_assignment(j.complete_by, 0, &host())
        .is_err());
    assert_eq!(
        j.classify_retry(&j, &alt).unwrap(),
        ComputeRetryV1::Idempotent
    );
    j.verify_request(&j.sign_request(&key(3)).unwrap()).unwrap();
    assert!(j.sign_request(&key(4)).is_err());
}
#[test]
fn host_limits_exclusive_deadline_and_overflow_safe_budget() {
    let j = job();
    j.validate_new_assignment(2000000000, 1000, &host())
        .unwrap();
    assert!(j
        .validate_new_assignment(j.accept_until, 0, &host())
        .is_err());
    let mut c = j.clone();
    c.accept_until = 2;
    c.complete_by = 3;
    c.max_execution_ms = 1000;
    c.validate_new_assignment(1, 999, &host()).unwrap();
    assert!(c.validate_new_assignment(1, 1000, &host()).is_err());
    for n in 0..6 {
        let mut h = host();
        match n {
            0 => h.max_input_bytes = 0,
            1 => h.max_output_bytes = 0,
            2 => h.max_evidence_bytes = 0,
            3 => h.max_memory_bytes = 0,
            4 => {
                c.max_scratch_bytes = 1;
                h.max_scratch_bytes = 0;
            }
            _ => h.max_execution_ms = 0,
        };
        assert!(c.validate_new_assignment(1, 0, &h).is_err());
    }
    c.accept_until = u64::MAX - 1;
    c.complete_by = u64::MAX;
    c.max_execution_ms = u64::MAX;
    c.validate_new_assignment(0, u64::MAX, &host()).unwrap(); // exact u128, no overflow
    assert!(c
        .validate_new_assignment(u64::MAX - 2, u64::MAX, &host())
        .is_err());
}
#[test]
fn content_binding_domain_length_and_exact_payload() {
    let j = job();
    for k in ComputeContentKindV1::ALL {
        let p = payload(k);
        j.verify_content(k, &p).unwrap();
        for i in 0..p.len() {
            let mut q = p.clone();
            q[i] ^= 1;
            assert!(j.verify_content(k, &q).is_err());
        }
        let mut extra = p.clone();
        extra.push(0);
        assert!(j.verify_content(k, &extra).is_err());
        for other in ComputeContentKindV1::ALL {
            if k != other {
                assert_ne!(
                    compute_content_commitment_v1(k, &p).unwrap(),
                    compute_content_commitment_v1(other, &p).unwrap()
                );
            }
        }
    }
    let mut c = j;
    c.max_input_bytes = 0;
    assert!(c
        .verify_content(
            ComputeContentKindV1::Input,
            &payload(ComputeContentKindV1::Input)
        )
        .is_err());
}
#[test]
fn result_expansion_and_existing_signed_miner_profile_are_bound() {
    let v = vector();
    let j = job();
    let limits = EconomicLimitsV1 {
        max_work_bytes: 100000,
        max_meter_bytes: 90000,
        max_iterations: 100,
    };
    let draft: Value = serde_json::from_str(include_str!(
        "../../../reports/compute_network_v1/c1_binding_candidate_vectors.json"
    ))
    .unwrap();
    for (index, x) in v["bindings"].as_array().unwrap().iter().enumerate() {
        let r: [u8; 32] = data(x, "result_hex").try_into().unwrap();
        let m = MinerJobV1::decode(&data(x, "miner_job_hex")).unwrap();
        j.validate_miner_binding(&m, &r).unwrap();
        m.verify_for_policy(&data(x, "miner_signature_hex"), &policy(&m), limits)
            .unwrap();
        for lane in 0..2 {
            let side = compute_miner_side_v1(&r, lane).unwrap();
            assert_eq!(
                hex(&side),
                draft["cases"][index]["lanes"][lane as usize]["side_hex"]
                    .as_str()
                    .unwrap()
            );
        }
        let mut wrong = r;
        wrong[31] ^= 1;
        assert!(j.validate_miner_binding(&m, &wrong).is_err());
        let mut changed = m.clone();
        std::mem::swap(&mut changed.side_a, &mut changed.side_b);
        assert!(j.validate_miner_binding(&changed, &r).is_err());
        assert!(changed
            .verify_for_policy(&data(x, "miner_signature_hex"), &policy(&changed), limits)
            .is_err());
        // A one-based counter is another encoding, and cannot be accepted.
        let alt: Vec<u8> = (1u32..=4)
            .flat_map(|i| {
                let mut h = Sha256::new();
                h.update(b"AURA_COMPUTE_MINER_SIDE_V1");
                h.update([0]);
                h.update(r);
                h.update(i.to_le_bytes());
                h.finalize().to_vec()
            })
            .collect();
        changed = m.clone();
        changed.side_a.copy_from_slice(&alt[..110]);
        assert!(j.validate_miner_binding(&changed, &r).is_err());
        changed = m.clone();
        changed.side_a[109] ^= 1;
        assert!(j.validate_miner_binding(&changed, &r).is_err());
        let mut disabled = j.clone();
        disabled.mining_mode = 0;
        assert!(disabled.validate_miner_binding(&m, &r).is_err());
        assert!(j.validate_miner_binding(&base_miner(), &r).is_err()); // M-only/post-proof attachment cannot repair J
        assert!(compute_miner_side_v1(&r, 2).is_err());
    }
}
