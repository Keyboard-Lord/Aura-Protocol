//! Test inputs/output only. Never a protocol JSON wire or supported policy registry.
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use aura_sdk_v1::{
    compute_job::*,
    miner::{miner_route_tag_v1, MinerJobV1},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{json, Value};

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
pub fn m2() -> Value {
    serde_json::from_str(include_str!(
        "../../../../fixtures/miner_v1/job_profile_vector_v1.json"
    ))
    .unwrap()
}
pub fn base_miner() -> MinerJobV1 {
    MinerJobV1::decode(&unhex(m2()["job_hex"].as_str().unwrap())).unwrap()
}
pub fn key(n: u8) -> Keypair {
    let mut s = [0; 32];
    s[31] = n;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_byte_array(s).unwrap())
}
pub fn payload(k: ComputeContentKindV1) -> Vec<u8> {
    [b"TEST_ONLY/".as_slice(), k.domain(), &[0, 255]].concat()
}
pub fn content(k: ComputeContentKindV1) -> [u8; 32] {
    compute_content_commitment_v1(k, &payload(k)).unwrap()
}
pub fn job() -> AuraComputeJobV1 {
    use ComputeContentKindV1::*;
    let m = base_miner();
    AuraComputeJobV1 {
        job_version: 1,
        network: BitcoinNetworkV1::Regtest,
        coordinator_key: m.operator_key,
        journal_namespace: m.journal_namespace,
        requester_key: key(3).x_only_public_key().0.serialize(),
        job_nonce: std::array::from_fn(|i| i as u8),
        workload_class: 0,
        adapter_contract_commitment: content(AdapterContract),
        input_commitment: content(Input),
        program_commitment: content(Program),
        execution_spec_commitment: content(ExecutionSpec),
        output_spec_commitment: content(OutputSpec),
        verification_class: 0,
        verification_spec_commitment: content(VerificationSpec),
        privacy_class: 1,
        privacy_policy_commitment: content(PrivacyPolicy),
        hardware_requirements_commitment: content(HardwareRequirements),
        max_input_bytes: 4096,
        max_output_bytes: 8192,
        max_evidence_bytes: 16384,
        max_memory_bytes: 1048576,
        max_scratch_bytes: 0,
        max_execution_ms: 1000,
        accept_until: 2000000100,
        complete_by: 2000000200,
        compensation_satoshis: 10000,
        payment_terms_commitment: content(PaymentTerms),
        data_rights_commitment: content(DataRights),
        mining_mode: 1,
    }
}
pub fn signature(j: &AuraComputeJobV1, n: u8, aux: u8) -> Vec<u8> {
    Secp256k1::new()
        .sign_schnorr_with_aux_rand(&j.signing_digest().unwrap(), &key(n), &[aux; 32])
        .to_byte_array()
        .to_vec()
}
pub fn job_record(name: &str, j: &AuraComputeJobV1, secret: u8) -> Value {
    json!({"name":name,"job_hex":hex(&j.canonical_bytes().unwrap()),"commitment_hex":hex(&j.commitment().unwrap()),
        "signing_digest_hex":hex(&j.signing_digest().unwrap()),"signature_hex":hex(&signature(j,secret,0))})
}
pub fn snapshot() -> Value {
    let j = job();
    let b = j.canonical_bytes().unwrap();
    let mut variants = Vec::new();
    for (name, n) in [
        ("mainnet", BitcoinNetworkV1::Mainnet),
        ("testnet3", BitcoinNetworkV1::Testnet3),
        ("signet", BitcoinNetworkV1::Signet),
        ("regtest", BitcoinNetworkV1::Regtest),
        ("testnet4", BitcoinNetworkV1::Testnet4),
    ] {
        let mut c = j.clone();
        c.network = n;
        variants.push(job_record(name, &c, 3));
    }
    for amount in [1, 9007199254740993, u64::MAX] {
        let mut c = j.clone();
        c.compensation_satoshis = amount;
        variants.push(job_record(&format!("compensation_{amount}"), &c, 3));
    }
    let mut c = j.clone();
    c.workload_class = 10;
    c.verification_class = 7;
    c.privacy_class = 4;
    c.mining_mode = 0;
    c.max_input_bytes = 0;
    c.max_scratch_bytes = u64::MAX;
    c.max_memory_bytes = u64::MAX;
    c.complete_by = u64::MAX;
    variants.push(job_record("class_limit_extremes", &c, 3));
    let mutation_decodes: String = (0..b.len())
        .map(|i| {
            let mut c = b.clone();
            c[i] ^= 1;
            if AuraComputeJobV1::decode(&c).is_ok() {
                '1'
            } else {
                '0'
            }
        })
        .collect();
    let mut invalid = Vec::new();
    for (name, off, data) in [
        ("version", 19, vec![2]),
        ("network", 20, vec![255]),
        ("coordinator", 21, vec![255; 32]),
        ("requester", 85, vec![255; 32]),
        ("workload", 149, vec![11, 0]),
        ("workload_big_endian", 149, vec![0, 10]),
        ("verification", 311, vec![8]),
        ("privacy", 344, vec![5]),
        ("output_zero", 417, vec![0; 8]),
        ("evidence_zero", 425, vec![0; 8]),
        ("memory_zero", 433, vec![0; 8]),
        ("execution_zero", 449, vec![0; 8]),
        ("accept_zero", 457, vec![0; 8]),
        (
            "equal_deadlines",
            465,
            j.accept_until.to_le_bytes().to_vec(),
        ),
        ("reward_zero", 473, vec![0; 8]),
        ("mining_mode", 545, vec![2]),
    ] {
        invalid.push(json!({"name":name,"offset":off,"replacement_hex":hex(&data)}));
    }
    let mut retry = Vec::new();
    for (name, change) in [
        ("same", 0),
        ("new_compensation", 1),
        ("new_nonce", 2),
        ("new_namespace", 3),
        ("new_network", 4),
        ("new_coordinator", 5),
        ("new_requester", 6),
        ("new_deadline", 7),
    ] {
        let mut c = j.clone();
        let mut signer = 3;
        match change {
            1 => c.compensation_satoshis += 1,
            2 => c.job_nonce[0] ^= 1,
            3 => c.journal_namespace[0] ^= 1,
            4 => c.network = BitcoinNetworkV1::Mainnet,
            5 => c.coordinator_key = key(4).x_only_public_key().0.serialize(),
            6 => {
                c.requester_key = key(4).x_only_public_key().0.serialize();
                signer = 4;
            }
            7 => c.complete_by += 1,
            _ => {}
        }
        let sig = signature(&c, signer, 1);
        let expected = match j.classify_retry(&c, &sig).unwrap() {
            ComputeRetryV1::Idempotent => "idempotent",
            ComputeRetryV1::Conflict => "conflict",
            ComputeRetryV1::DistinctScope => "distinct_scope",
        };
        retry.push(json!({"name":name,"job_hex":hex(&c.canonical_bytes().unwrap()),"signature_hex":hex(&sig),"outcome":expected}));
    }
    let old = m2();
    let meter = EconomicMeterV1::decode(&unhex(old["meter_hex"].as_str().unwrap()), 90000).unwrap();
    let nonce: [u8; 32] = unhex(old["nonce_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let operator = Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_byte_array(
            unhex(old["test_only_operator_secret_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
        .unwrap(),
    );
    let mut bindings = Vec::new();
    for (name, r) in [
        ("zero", [0; 32]),
        ("incrementing", std::array::from_fn(|i| i as u8)),
        ("one_bit", {
            let mut r = [0; 32];
            r[0] = 1;
            r
        }),
        ("all_ff", [255; 32]),
    ] {
        let mut m = base_miner();
        m.side_a = compute_miner_side_v1(&r, 0).unwrap();
        m.side_b = compute_miner_side_v1(&r, 1).unwrap();
        let w = m.build_work(meter.clone(), nonce).unwrap();
        bindings.push(json!({"name":name,"result_hex":hex(&r),"side_a_hex":hex(&m.side_a),"side_b_hex":hex(&m.side_b),
            "miner_job_hex":hex(&m.canonical_bytes().unwrap()),"miner_commitment_hex":hex(&m.commitment().unwrap()),"miner_signing_digest_hex":hex(&m.signing_digest().unwrap()),
            "miner_signature_hex":hex(&Secp256k1::new().sign_schnorr_no_aux_rand(&m.signing_digest().unwrap(),&operator).to_byte_array()),
            "intent_hex":hex(&m.intent_commitment(&meter).unwrap()),"context_hex":hex(&w.storm.context_bytes_v1),"work_hex":hex(&w.canonical_bytes().unwrap()),"route_hex":hex(&miner_route_tag_v1())}));
    }
    json!({"classification":"C1 CODEC VECTORS; TEST-ONLY KEYS/POLICY PAYLOADS; NOT FUNDED OR VERIFIED COMPUTE",
        "base":job_record("base",&j,3),"alternate_signature_hex":hex(&signature(&j,3,1)),"valid_jobs":variants,
        "single_bit_mutation_decodes":mutation_decodes,"invalid_patches":invalid,"retry_cases":retry,
        "contents":ComputeContentKindV1::ALL.map(|k| json!({"domain":String::from_utf8(k.domain().to_vec()).unwrap(),"payload_hex":hex(&payload(k)),"commitment_hex":hex(&content(k))})),
        "bindings":bindings})
}

/// C1-P1 contracts, with test-only numeric parameters and synthetic adapter data.
pub fn core_policy_snapshot() -> Value {
    let fixed = [
        ComputeContentKindV1::PrivacyPolicy,
        ComputeContentKindV1::HardwareRequirements,
        ComputeContentKindV1::DataRights,
    ];
    let profiles: Vec<Value> = fixed.iter().map(|&kind| {
        let p = compute_fixed_core_policy_payload_v1(kind).unwrap();
        json!({"domain":String::from_utf8(kind.domain().to_vec()).unwrap(),"payload_hex":hex(&p),"commitment_hex":hex(&compute_content_commitment_v1(kind,&p).unwrap())})
    }).collect();
    let mut payments = Vec::new();
    for (fee, seconds) in [
        (0, 1),
        (42, 3600),
        (9007199254740993, 9007199254740995),
        (u64::MAX, u64::MAX),
    ] {
        let terms = ComputePaymentTermsV1 {
            max_payment_fee_satoshis: fee,
            result_availability_seconds: seconds,
        };
        let mut checks = vec![(0, true), (fee, true)];
        if fee < u64::MAX {
            checks.push((fee + 1, false));
        }
        let mut jobs = Vec::new();
        for privacy_class in [0, 1] {
            let mut j = job();
            j.privacy_class = privacy_class;
            j.privacy_policy_commitment = compute_content_commitment_v1(fixed[0], &[1]).unwrap();
            j.hardware_requirements_commitment =
                compute_content_commitment_v1(fixed[1], &[1]).unwrap();
            j.data_rights_commitment = compute_content_commitment_v1(fixed[2], &[1]).unwrap();
            j.payment_terms_commitment = terms.commitment().unwrap();
            jobs.push(job_record(
                if privacy_class == 0 {
                    "public"
                } else {
                    "sandboxed"
                },
                &j,
                3,
            ));
        }
        let b = terms.canonical_bytes().unwrap();
        let mutation_decodes: String = (0..17)
            .map(|i| {
                let mut v = b;
                v[i] ^= 1;
                if ComputePaymentTermsV1::decode(&v).is_ok() {
                    '1'
                } else {
                    '0'
                }
            })
            .collect();
        payments.push(json!({"max_payment_fee_satoshis":fee.to_string(),"result_availability_seconds":seconds.to_string(),
            "payload_hex":hex(&b),"commitment_hex":hex(&terms.commitment().unwrap()),"single_bit_mutation_decodes":mutation_decodes,
            "fee_checks":checks.iter().map(|(fee,ok)|json!({"fee_satoshis":fee.to_string(),"allowed":ok})).collect::<Vec<_>>(),"jobs":jobs}));
    }
    json!({"classification":"C1-P1 CORE POLICY CONTRACT VECTORS; TEST PARAMETERS ONLY; NO WORKLOAD OR PAYMENT EXECUTION","fixed_profiles":profiles,"payments":payments})
}
