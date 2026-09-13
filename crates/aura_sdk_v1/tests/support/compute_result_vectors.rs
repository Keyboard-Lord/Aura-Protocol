#![allow(dead_code)]
#[path = "compute_job_vectors.rs"]
mod previous;
use aura_sdk_v1::{compute_job::*, compute_result::*};
pub use previous::{hex, key};
use secp256k1::Secp256k1;
use serde_json::{json, Value};
pub fn unhex(s: &str) -> Vec<u8> {
    previous::unhex(s)
}
pub fn job() -> AuraComputeJobV1 {
    let mut j = previous::job();
    j.coordinator_key = key(1).x_only_public_key().0.serialize();
    j
}
pub fn sign(d: &[u8; 32], k: u8) -> Vec<u8> {
    Secp256k1::new()
        .sign_schnorr_no_aux_rand(d, &key(k))
        .as_ref()
        .to_vec()
}
pub fn input() -> Vec<u8> {
    previous::payload(ComputeContentKindV1::Input)
}
fn item(
    b: Vec<u8>,
    commit: Option<[u8; 32]>,
    digests: Vec<(&str, [u8; 32], u8)>,
    decode: impl Fn(&[u8]) -> bool,
) -> Value {
    let mut mutation = String::new();
    for i in 0..b.len() {
        let mut m = b.clone();
        m[i] ^= 1;
        mutation.push(if decode(&m) { '1' } else { '0' });
    }
    json!({"bytes_hex":hex(&b),"commitment_hex":commit.map(|c|hex(&c)),"signatures":digests.into_iter().map(|(role,d,k)|json!({"role":role,"key_hex":hex(&key(k).x_only_public_key().0.serialize()),"digest_hex":hex(&d),"signature_hex":hex(&sign(&d,k))})).collect::<Vec<_>>(),"single_bit_mutation_decodes":mutation})
}
pub fn snapshot() -> Value {
    let j = job();
    let mut cases = vec![];
    for (worker, out, evidence) in [
        (1, vec![], vec![]),
        (2, vec![0, 255, 1], vec![5, 6, 255]),
        (4, vec![255; 32], vec![0; 32]),
    ] {
        let a = ComputeAssignmentV1 {
            version: 1,
            compute_job_commitment: j.commitment().unwrap(),
            worker_key: key(worker).x_only_public_key().0.serialize(),
        };
        let c = ComputeResourceAccountingV1 {
            version: 1,
            input_bytes: input().len() as u64,
            output_bytes: out.len() as u64,
            evidence_bytes: evidence.len() as u64,
        };
        let r = ComputeReceiptV1 {
            version: 1,
            assignment_commitment: a.commitment().unwrap(),
            output_commitment: compute_result_content_commitment_v1(
                ComputeResultContentKindV1::Output,
                &out,
            )
            .unwrap(),
            execution_evidence_commitment: compute_result_content_commitment_v1(
                ComputeResultContentKindV1::ExecutionEvidence,
                &evidence,
            )
            .unwrap(),
            resource_accounting_commitment: c.commitment().unwrap(),
        };
        let v = VerifiedComputeResultV1 {
            version: 1,
            receipt_commitment: r.commitment().unwrap(),
            verification_verdict: 1,
        };
        cases.push(json!({"worker_secret_test_only":worker,"output_hex":hex(&out),"evidence_hex":hex(&evidence),
          "assignment":item(a.canonical_bytes().unwrap(),Some(a.commitment().unwrap()),vec![("worker",a.worker_digest().unwrap(),worker),("coordinator",a.coordinator_digest().unwrap(),1)],|b|ComputeAssignmentV1::decode(b).is_ok()),
          "accounting":item(c.canonical_bytes().unwrap(),Some(c.commitment().unwrap()),vec![],|b|ComputeResourceAccountingV1::decode(b).is_ok()),
          "receipt":item(r.canonical_bytes().unwrap(),Some(r.commitment().unwrap()),vec![("worker",r.signing_digest().unwrap(),worker)],|b|ComputeReceiptV1::decode(b).is_ok()),
          "result":item(v.canonical_bytes().unwrap(),Some(v.commitment().unwrap()),vec![("coordinator",v.signing_digest().unwrap(),1)],|b|VerifiedComputeResultV1::decode(b).is_ok()),
          "miner_side_a_hex":hex(&compute_miner_side_v1(&v.commitment().unwrap(),0).unwrap()),"miner_side_b_hex":hex(&compute_miner_side_v1(&v.commitment().unwrap(),1).unwrap())}));
    }
    let cancel = ComputeCancelV1 {
        version: 1,
        compute_job_commitment: j.commitment().unwrap(),
    };
    let accounting:Vec<_>=[(0,0,0),(1,9007199254740993,u64::MAX),(u64::MAX,u64::MAX,u64::MAX)].into_iter().map(|(i,o,e)|{let r=ComputeResourceAccountingV1{version:1,input_bytes:i,output_bytes:o,evidence_bytes:e};json!({"input_bytes":i.to_string(),"output_bytes":o.to_string(),"evidence_bytes":e.to_string(),"bytes_hex":hex(&r.canonical_bytes().unwrap()),"commitment_hex":hex(&r.commitment().unwrap())})}).collect();
    json!({"classification":"C2 CODEC TEST VECTORS; NO VERIFIER ACCEPTANCE, HARDWARE OR PAYMENT CLAIM","job_hex":hex(&j.canonical_bytes().unwrap()),"request_signature_hex":hex(&sign(&j.signing_digest().unwrap(),3)),"input_hex":hex(&input()),"cases":cases,"cancel":item(cancel.canonical_bytes().unwrap(),None,vec![("requester",cancel.signing_digest().unwrap(),3)],|b|ComputeCancelV1::decode(b).is_ok()),"accounting_extremes":accounting})
}
