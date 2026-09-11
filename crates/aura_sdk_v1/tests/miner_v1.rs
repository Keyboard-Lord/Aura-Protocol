//! M2 codec/profile evidence only: no search, admission, winner or payout loop.
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_intent_lineage_v1::{build_storm_claim_v1, StormClaim521V1};
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use aura_sdk_v1::{
    authorization::{encode_hex_v2, AuthorizationEnvelopeV2},
    economic::{head::EconomicHeadV2, EconomicConsentV1, EconomicLimitsV1, EconomicWorkV1},
    miner::{miner_route_tag_v1, MinerJobPolicyV1, MinerJobV1, MINER_JOB_V1_BYTE_LEN},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

fn vector() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../fixtures/miner_v1/job_profile_vector_v1.json"
        ))
        .unwrap()
    })
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn bytes(key: &str) -> Vec<u8> {
    unhex(vector()[key].as_str().unwrap())
}
fn limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: 100_000,
        max_meter_bytes: 90_000,
        max_iterations: 100,
    }
}
fn keypair() -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_byte_array(bytes("test_only_operator_secret_hex").try_into().unwrap())
            .unwrap(),
    )
}
fn meter() -> EconomicMeterV1 {
    EconomicMeterV1::decode(&bytes("meter_hex"), limits().max_meter_bytes).unwrap()
}
fn job() -> MinerJobV1 {
    // Independent typed construction, not decode followed by re-encode alone.
    let old: Value = serde_json::from_str(include_str!(
        "../../../fixtures/economic_admission_v1/contract_vector.json"
    ))
    .unwrap();
    let old_work =
        EconomicWorkV1::decode(&unhex(old["work_hex"].as_str().unwrap()), limits()).unwrap();
    let mut target = [255; 32];
    target[0] = 15;
    MinerJobV1 {
        job_version: 1,
        network: BitcoinNetworkV1::Regtest,
        operator_key: keypair().x_only_public_key().0.serialize(),
        journal_namespace: Sha256::digest(b"RESEARCH_ONLY_MINER_NAMESPACE").into(),
        policy_epoch: 0,
        round_number: 1,
        prior_head_sequence: 0,
        prior_head_hash: [0; 32],
        challenge: Sha256::digest(b"RESEARCH_ONLY_JOB_CHALLENGE").into(),
        side_a: old_work.storm.side_a,
        side_b: old_work.storm.side_b,
        iteration_count: 64,
        target,
        max_work_bytes: 100_000,
        max_meter_bytes: 90_000,
        opened_at: 2_000_000_000,
        expires_at: 2_000_000_600,
        reward_satoshis: 10_000,
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
fn work() -> EconomicWorkV1 {
    job()
        .build_work(meter(), bytes("nonce_hex").try_into().unwrap())
        .unwrap()
}
fn bound() -> (AuthorizationEnvelopeV2, EconomicConsentV1) {
    (
        serde_json::from_value(vector()["binding_authorization"].clone()).unwrap(),
        serde_json::from_value(vector()["binding_consent"].clone()).unwrap(),
    )
}

#[test]
fn frozen_job_digest_signature_intent_route_context_and_work_bytes() {
    let j = job();
    let w = work();
    assert_eq!(MINER_JOB_V1_BYTE_LEN, 471);
    assert_eq!(j.canonical_bytes().unwrap(), bytes("job_hex"));
    assert_eq!(j.canonical_bytes().unwrap().len(), 471);
    assert_eq!(MinerJobV1::decode(&bytes("job_hex")).unwrap(), j);
    assert_eq!(
        j.commitment().unwrap().as_slice(),
        bytes("job_commitment_hex")
    );
    assert_eq!(
        j.signing_digest().unwrap().as_slice(),
        bytes("job_signing_digest_hex")
    );
    assert_eq!(
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&j.signing_digest().unwrap(), &keypair())
            .as_ref()
            .as_slice(),
        bytes("job_signature_hex")
    );
    j.verify_for_policy(&bytes("job_signature_hex"), &policy(&j), limits())
        .unwrap();
    assert_eq!(
        j.intent_commitment(&meter()).unwrap().as_slice(),
        bytes("intent_commitment_hex")
    );
    assert_eq!(miner_route_tag_v1().as_slice(), bytes("route_tag_hex"));
    assert_eq!(w.storm.context_bytes_v1.as_slice(), bytes("context_hex"));
    assert_eq!(w.meter.canonical_bytes().unwrap(), bytes("meter_hex"));
    assert_eq!(w.canonical_bytes().unwrap(), bytes("work_hex"));
    assert_eq!(
        EconomicWorkV1::decode(&bytes("work_hex"), limits())
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        bytes("work_hex")
    );
    for v in vector()["valid_job_variants"].as_array().unwrap() {
        let b = unhex(v["job_hex"].as_str().unwrap());
        assert_eq!(
            MinerJobV1::decode(&b).unwrap().canonical_bytes().unwrap(),
            b,
            "{}",
            v["name"]
        );
    }
}

#[test]
fn every_job_byte_has_identical_decode_and_signature_rejection() {
    let original = bytes("job_hex");
    let j = job();
    let p = policy(&j);
    let expected = vector()["single_bit_mutation_decodes"]
        .as_str()
        .unwrap()
        .as_bytes();
    assert_eq!(expected.len(), 471);
    for i in 0..original.len() {
        let mut b = original.clone();
        b[i] ^= 1;
        let result = MinerJobV1::decode(&b);
        assert_eq!(result.is_ok(), expected[i] == b'1', "decode byte {i}");
        if let Ok(changed) = result {
            assert_eq!(
                changed.canonical_bytes().unwrap(),
                b,
                "no normalization byte {i}"
            );
            assert_ne!(changed.commitment().unwrap(), j.commitment().unwrap());
            assert_ne!(
                changed.signing_digest().unwrap(),
                j.signing_digest().unwrap()
            );
            assert!(
                changed
                    .verify_for_policy(&bytes("job_signature_hex"), &p, limits())
                    .is_err(),
                "signed byte {i}"
            );
        }
    }
    for i in 0..64 {
        let mut sig = bytes("job_signature_hex");
        sig[i] ^= 1;
        assert!(
            j.verify_for_policy(&sig, &p, limits()).is_err(),
            "signature byte {i}"
        );
    }
    for n in [0, 1, 32, 63, 65] {
        assert!(j.verify_for_policy(&vec![0; n], &p, limits()).is_err());
    }
}

#[test]
fn framing_invalid_fields_and_noncanonical_extremes_reject() {
    let b = bytes("job_hex");
    for n in 0..471 {
        assert!(MinerJobV1::decode(&b[..n]).is_err(), "truncation {n}");
    }
    for extra in [1, 32, 471] {
        let mut extended = b.clone();
        extended.extend(vec![0; extra]);
        assert!(MinerJobV1::decode(&extended).is_err());
    }
    for v in vector()["invalid_job_patches"].as_array().unwrap() {
        let mut changed = b.clone();
        let offset = v["offset"].as_u64().unwrap() as usize;
        let patch = unhex(v["replacement_hex"].as_str().unwrap());
        changed[offset..offset + patch.len()].copy_from_slice(&patch);
        assert!(MinerJobV1::decode(&changed).is_err(), "{}", v["name"]);
    }
    for tag in 5..=255 {
        let mut c = b.clone();
        c[18] = tag;
        assert!(MinerJobV1::decode(&c).is_err());
    }
}

#[test]
fn trusted_policy_host_bounds_and_half_open_window() {
    let j = job();
    let p = policy(&j);
    let sig = bytes("job_signature_hex");
    let mutations: [fn(&mut MinerJobPolicyV1); 8] = [
        |p| p.network = BitcoinNetworkV1::Mainnet,
        |p| p.operator_key = keypair_for_two(),
        |p| p.journal_namespace[0] ^= 1,
        |p| p.policy_epoch += 1,
        |p| p.iteration_count += 1,
        |p| p.target[31] ^= 1,
        |p| p.max_work_bytes += 1,
        |p| p.max_meter_bytes += 1,
    ];
    for mutate in mutations {
        let mut changed = p.clone();
        mutate(&mut changed);
        assert!(j.verify_for_policy(&sig, &changed, limits()).is_err());
    }
    for host in [
        EconomicLimitsV1 {
            max_work_bytes: 99_999,
            ..limits()
        },
        EconomicLimitsV1 {
            max_meter_bytes: 89_999,
            ..limits()
        },
        EconomicLimitsV1 {
            max_iterations: 63,
            ..limits()
        },
    ] {
        assert!(j.verify_for_policy(&sig, &p, host).is_err());
    }
    for t in [j.opened_at, j.expires_at - 1] {
        j.validate_window(t, 600).unwrap();
    }
    for t in [j.opened_at - 1, j.expires_at, u64::MAX] {
        assert!(j.validate_window(t, 600).is_err());
    }
    assert!(j.validate_window(j.opened_at, 599).is_err());
}
fn keypair_for_two() -> [u8; 32] {
    let mut k = [0; 32];
    k[31] = 2;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_byte_array(k).unwrap())
        .x_only_public_key()
        .0
        .serialize()
}

#[test]
fn stale_head_and_overflow_reject_without_changing_head_rules() {
    let j = job();
    let genesis = EconomicHeadV2::genesis();
    j.validate_head(&genesis).unwrap();
    let mut c = j.clone();
    c.prior_head_sequence = 1;
    assert!(c.validate_head(&genesis).is_err());
    c = j.clone();
    c.prior_head_hash[0] = 1;
    assert!(c.validate_head(&genesis).is_err());
    let mut bad = genesis.clone();
    bad.current_head_hash_hex = "01".repeat(32);
    assert!(j.validate_head(&bad).is_err());
    // Construct a valid extreme predecessor with the existing head formula.
    let mut max = genesis;
    max.head_sequence_number = u64::MAX.to_string();
    let mut hash = Sha256::new();
    hash.update(b"AURA_ECONOMIC_HEAD_V1");
    hash.update(2u32.to_le_bytes());
    hash.update(u64::MAX.to_le_bytes());
    hash.update([0; 32]);
    max.current_head_hash_hex = encode_hex_v2(&hash.finalize());
    max.validate().unwrap();
    c = j;
    c.prior_head_sequence = u64::MAX;
    c.prior_head_hash = unhex(&max.current_head_hash_hex).try_into().unwrap();
    assert!(c.validate_head(&max).is_err());
}

#[test]
fn all_work_bytes_are_bound_and_nonce_variation_is_detected_by_authentication() {
    let j = job();
    let w = work();
    let (auth, consent) = bound();
    consent
        .verify_admission_signatures(j.network, &w, &auth)
        .unwrap();
    let b = w.canonical_bytes().unwrap();
    for i in 0..b.len() {
        let mut c = b.clone();
        c[i] ^= 1;
        if let Ok(changed) = EconomicWorkV1::decode(&c, limits()) {
            assert!(
                consent
                    .verify_admission_signatures(j.network, &changed, &auth)
                    .is_err(),
                "work byte {i}"
            );
        }
    }
    // Every context field is fixed by the profile except the existing nonce.
    for i in 0..209 {
        let mut c = w.clone();
        c.storm.context_bytes_v1[i] ^= 1;
        assert_eq!(
            j.validate_work_profile(&c).is_ok(),
            (97..129).contains(&i),
            "context byte {i}"
        );
    }
    let mut nonce = w.nonce();
    nonce[0] ^= 1;
    let changed = j.build_work(meter(), nonce).unwrap();
    assert_ne!(changed.canonical_bytes().unwrap(), b);
    assert!(consent
        .verify_admission_signatures(j.network, &changed, &auth)
        .is_err());
    let mut changed_auth = auth;
    changed_auth.authorization_lineage.freshness_binding = encode_hex_v2(&nonce);
    // Updating the lineage alone still cannot reuse economic consent over old W.
    assert!(consent
        .verify_admission_signatures(j.network, &changed, &changed_auth)
        .is_err());
}

#[test]
fn work_tuple_meter_payer_linkage_and_actual_byte_limits() {
    let j = job();
    let w = work();
    let mutations: [fn(&mut EconomicWorkV1); 7] = [
        |w| w.storm.side_a[0] ^= 1,
        |w| w.storm.side_b[0] ^= 1,
        |w| w.storm.iteration_count += 1,
        |w| w.meter.ledger.payer_account_id = keypair_for_two(),
        |w| w.meter.batch_number += 1,
        |w| w.meter.head.previous_head_hash[0] ^= 1,
        |w| w.meter.head.head_sequence_number += 1,
    ];
    for mutate in mutations {
        let mut c = w.clone();
        mutate(&mut c);
        assert!(j.validate_work_profile(&c).is_err());
    }
    let mut m = meter();
    m.batch_number += 1;
    assert_ne!(j.intent_commitment(&m).unwrap(), w.intent());
    j.build_work(m, w.nonce()).unwrap(); // New M requires a newly derived I, never normalization of old W.
    let mut m = meter();
    m.head.head_sequence_number += 1;
    assert!(j.build_work(m, w.nonce()).is_err());
    let mut m = meter();
    m.head.previous_head_hash[0] = 1;
    assert!(j.build_work(m, w.nonce()).is_err());
    let mut m = meter();
    m.head.settlement_head_version = 1;
    assert!(j.build_work(m, w.nonce()).is_err());
    let mut tight = j.clone();
    tight.max_work_bytes = w.canonical_bytes().unwrap().len() as u64;
    tight.max_meter_bytes = w.meter.canonical_bytes().unwrap().len() as u64;
    tight.build_work(meter(), w.nonce()).unwrap();
    tight.max_work_bytes -= 1;
    assert!(tight.build_work(meter(), w.nonce()).is_err());
    tight.max_work_bytes += 1;
    tight.max_meter_bytes -= 1;
    assert!(tight.build_work(meter(), w.nonce()).is_err());
}

#[test]
fn fixed_claim_profile_is_not_a_poc_verdict() {
    let j = job();
    let w = work();
    let claim = build_storm_claim_v1(&w.storm, [0; 32], [0; 32]);
    j.validate_claim_profile(&w, &claim, &[]).unwrap();
    claim.validate().unwrap();
    let changes: [fn(&mut StormClaim521V1); 8] = [
        |c| c.version += 1,
        |c| c.modulus_id += 1,
        |c| c.iteration_count += 1,
        |c| c.side_a[0] ^= 1,
        |c| c.side_b[0] ^= 1,
        |c| c.context_bytes_v1[97] ^= 1,
        |c| c.legacy_commitment_root[0] = 1,
        |c| c.legacy_trace_commitment[0] = 1,
    ];
    for change in changes {
        let mut c = claim.clone();
        change(&mut c);
        assert!(j.validate_claim_profile(&w, &c, &[]).is_err());
    }
    assert!(j.validate_claim_profile(&w, &claim, &[0]).is_err());
    let mut corrupt = claim;
    corrupt.trace_root[0] ^= 1;
    j.validate_claim_profile(&w, &corrupt, &[]).unwrap();
    assert!(j.passes_hash_filter(&[0; 32]).unwrap());
    assert!(corrupt.validate().is_err()); // Actual existing claim owner catches the invalid trace.
}

#[test]
fn frozen_raw_big_endian_target_endpoints_and_no_numeric_shortcuts() {
    for v in vector()["target_cases"].as_array().unwrap() {
        let mut j = job();
        j.target = unhex(v["target_hex"].as_str().unwrap()).try_into().unwrap();
        assert_eq!(
            j.passes_hash_filter(&unhex(v["proof_hash_hex"].as_str().unwrap()))
                .unwrap(),
            v["passes"].as_bool().unwrap()
        );
    }
    for n in [0, 4, 31, 33, 64] {
        assert!(job().passes_hash_filter(&vec![0; n]).is_err());
    }
    let mut j = job();
    j.target = [0; 32];
    assert!(j.passes_hash_filter(&[0; 32]).is_err());
    j.target = [255; 32];
    assert!(j.passes_hash_filter(&[0; 32]).is_err());
}
