#[path = "support/compute_result_vectors.rs"]
mod support;
use aura_sdk_v1::{compute_job::*, compute_result::*};
use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
use serde_json::Value;
use support::*;
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/compute_result_v1/result_vectors_v1.json"
    ))
    .unwrap()
}
fn raw(v: &Value) -> Vec<u8> {
    unhex(v["bytes_hex"].as_str().unwrap())
}
fn sig(v: &Value, i: usize) -> [u8; 64] {
    unhex(v["signatures"][i]["signature_hex"].as_str().unwrap())
        .try_into()
        .unwrap()
}
#[test]
fn independent_rust_construction_matches_all_shared_canonical_bytes() {
    assert_eq!(snapshot(), vector());
    assert_eq!(
        (
            COMPUTE_ASSIGNMENT_V1_BYTE_LEN,
            COMPUTE_RECEIPT_V1_BYTE_LEN,
            COMPUTE_RESULT_V1_BYTE_LEN,
            COMPUTE_CANCEL_V1_BYTE_LEN,
            COMPUTE_RESOURCE_ACCOUNTING_V1_BYTE_LEN
        ),
        (91, 152, 56, 55, 25)
    );
}
#[test]
fn complete_lineage_signatures_content_result_and_mining_binding() {
    let v = vector();
    let j = AuraComputeJobV1::decode(&unhex(v["job_hex"].as_str().unwrap())).unwrap();
    j.verify_request(&unhex(v["request_signature_hex"].as_str().unwrap()))
        .unwrap();
    for x in v["cases"].as_array().unwrap() {
        let a = ComputeAssignmentV1::decode(&raw(&x["assignment"])).unwrap();
        let r = ComputeReceiptV1::decode(&raw(&x["receipt"])).unwrap();
        let c = ComputeResourceAccountingV1::decode(&raw(&x["accounting"])).unwrap();
        let result = VerifiedComputeResultV1::decode(&raw(&x["result"])).unwrap();
        a.verify_job(&j).unwrap();
        a.verify_worker(&sig(&x["assignment"], 0)).unwrap();
        a.verify_coordinator(&j, &sig(&x["assignment"], 1)).unwrap();
        r.verify_signature(&a, &sig(&x["receipt"], 0)).unwrap();
        r.verify_content(
            &j,
            &c,
            &input(),
            &unhex(x["output_hex"].as_str().unwrap()),
            &unhex(x["evidence_hex"].as_str().unwrap()),
        )
        .unwrap();
        result
            .verify_signature(&j, &a, &r, &sig(&x["result"], 0))
            .unwrap();
        assert_eq!(
            hex(&result.commitment().unwrap()),
            x["result"]["commitment_hex"]
        );
        for lane in 0..2 {
            assert_eq!(
                hex(&compute_miner_side_v1(&result.commitment().unwrap(), lane).unwrap()),
                x[if lane == 0 {
                    "miner_side_a_hex"
                } else {
                    "miner_side_b_hex"
                }]
            );
        }
        let mut changed = a.clone();
        changed.worker_key = key(7).x_only_public_key().0.serialize();
        assert!(r
            .verify_signature(&changed, &sig(&x["receipt"], 0))
            .is_err());
        changed = a.clone();
        changed.compute_job_commitment[0] ^= 1;
        assert!(result.verify_lineage(&j, &changed, &r).is_err());
        let mut bad_receipt = r.clone();
        bad_receipt.output_commitment[0] ^= 1;
        assert!(result
            .verify_signature(&j, &a, &bad_receipt, &sig(&x["result"], 0))
            .is_err());
        let mut bad_job = j.clone();
        bad_job.program_commitment[0] ^= 1;
        assert!(result.verify_lineage(&bad_job, &a, &r).is_err());
        assert!(a.sign_worker(&key(9)).is_err());
        assert!(a.sign_coordinator(&j, &key(9)).is_err());
        assert!(r.sign(&a, &key(9)).is_err());
        assert!(result.sign(&j, &a, &r, &key(9)).is_err());
    }
    let cancel = ComputeCancelV1::decode(&raw(&v["cancel"])).unwrap();
    cancel.verify_signature(&j, &sig(&v["cancel"], 0)).unwrap();
    assert!(cancel.sign(&j, &key(9)).is_err());
}
fn mutations<T>(
    x: &Value,
    decode: impl Fn(&[u8]) -> ComputeJobResultV1<T>,
    encode: impl Fn(&T) -> ComputeJobResultV1<Vec<u8>>,
    digest: impl Fn(&T, &str) -> ComputeJobResultV1<[u8; 32]>,
) {
    let b = raw(x);
    for n in 0..b.len() {
        assert!(decode(&b[..n]).is_err());
    }
    for n in [1, 32, 200] {
        let mut p = b.clone();
        p.extend(vec![0; n]);
        assert!(decode(&p).is_err());
    }
    for i in 0..b.len() {
        let mut changed = b.clone();
        changed[i] ^= 1;
        let d = decode(&changed);
        assert_eq!(
            d.is_ok(),
            x["single_bit_mutation_decodes"]
                .as_str()
                .unwrap()
                .as_bytes()[i]
                == b'1'
        );
        if let Ok(d) = d {
            assert_eq!(encode(&d).unwrap(), changed);
            for s in x["signatures"].as_array().unwrap() {
                let signature = Signature::from_byte_array(
                    unhex(s["signature_hex"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                );
                let key = XOnlyPublicKey::from_byte_array(
                    unhex(s["key_hex"].as_str().unwrap()).try_into().unwrap(),
                )
                .unwrap();
                assert!(
                    Secp256k1::verification_only()
                        .verify_schnorr(
                            &signature,
                            &digest(&d, s["role"].as_str().unwrap()).unwrap(),
                            &key
                        )
                        .is_err(),
                    "byte {i}"
                );
            }
        }
    }
    let d = decode(&b).unwrap();
    for s in x["signatures"].as_array().unwrap() {
        let bytes = unhex(s["signature_hex"].as_str().unwrap());
        let key = XOnlyPublicKey::from_byte_array(
            unhex(s["key_hex"].as_str().unwrap()).try_into().unwrap(),
        )
        .unwrap();
        for i in 0..64 {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            assert!(Secp256k1::verification_only()
                .verify_schnorr(
                    &Signature::from_byte_array(changed.try_into().unwrap()),
                    &digest(&d, s["role"].as_str().unwrap()).unwrap(),
                    &key
                )
                .is_err());
        }
    }
}
#[test]
fn every_object_and_signature_byte_is_bound_and_framing_is_strict() {
    let v = vector();
    for x in v["cases"].as_array().unwrap() {
        mutations(
            &x["assignment"],
            ComputeAssignmentV1::decode,
            ComputeAssignmentV1::canonical_bytes,
            |a, role| {
                if role == "worker" {
                    a.worker_digest()
                } else {
                    a.coordinator_digest()
                }
            },
        );
        mutations(
            &x["receipt"],
            ComputeReceiptV1::decode,
            ComputeReceiptV1::canonical_bytes,
            |r, _| r.signing_digest(),
        );
        mutations(
            &x["result"],
            VerifiedComputeResultV1::decode,
            VerifiedComputeResultV1::canonical_bytes,
            |r, _| r.signing_digest(),
        );
        mutations(
            &x["accounting"],
            ComputeResourceAccountingV1::decode,
            ComputeResourceAccountingV1::canonical_bytes,
            |r, _| r.commitment(),
        );
    }
    mutations(
        &v["cancel"],
        ComputeCancelV1::decode,
        ComputeCancelV1::canonical_bytes,
        |r, _| r.signing_digest(),
    );
}
#[test]
fn signature_roles_cannot_substitute_even_with_the_same_key() {
    let v = vector();
    let x = &v["cases"][0];
    let a = ComputeAssignmentV1::decode(&raw(&x["assignment"])).unwrap();
    let r = ComputeReceiptV1::decode(&raw(&x["receipt"])).unwrap();
    let result = VerifiedComputeResultV1::decode(&raw(&x["result"])).unwrap();
    let j = job();
    let signatures = [
        sig(&x["assignment"], 0),
        sig(&x["assignment"], 1),
        sig(&x["receipt"], 0),
        sig(&x["result"], 0),
    ];
    for (i, s) in signatures.iter().enumerate() {
        assert_eq!(a.verify_worker(s).is_ok(), i == 0);
        assert_eq!(a.verify_coordinator(&j, s).is_ok(), i == 1);
        assert_eq!(r.verify_signature(&a, s).is_ok(), i == 2);
        assert_eq!(result.verify_signature(&j, &a, &r, s).is_ok(), i == 3);
    }
    let new = Secp256k1::new()
        .sign_schnorr_with_aux_rand(&result.signing_digest().unwrap(), &key(1), &[2; 32])
        .to_byte_array();
    assert_ne!(new, signatures[3]);
    result.verify_signature(&j, &a, &r, &new).unwrap();
    assert_eq!(
        hex(&result.commitment().unwrap()),
        x["result"]["commitment_hex"]
    );
}
#[test]
fn unsupported_versions_keys_verdicts_and_false_resource_claims_reject() {
    let v = vector();
    let x = &v["cases"][1];
    for tag in 0..=255u8 {
        if tag == 1 {
            continue;
        }
        for (name, offset) in [
            ("assignment", 26),
            ("receipt", 23),
            ("result", 22),
            ("accounting", 0),
        ] {
            let mut b = raw(&x[name]);
            b[offset] = tag;
            assert!(match name {
                "assignment" => ComputeAssignmentV1::decode(&b).is_err(),
                "receipt" => ComputeReceiptV1::decode(&b).is_err(),
                "result" => VerifiedComputeResultV1::decode(&b).is_err(),
                _ => ComputeResourceAccountingV1::decode(&b).is_err(),
            });
        }
        let mut b = raw(&x["result"]);
        b[55] = tag;
        assert!(VerifiedComputeResultV1::decode(&b).is_err());
        let mut b = raw(&v["cancel"]);
        b[22] = tag;
        assert!(ComputeCancelV1::decode(&b).is_err());
    }
    let mut a = ComputeAssignmentV1::decode(&raw(&x["assignment"])).unwrap();
    a.worker_key = [255; 32];
    assert!(a.canonical_bytes().is_err());
    let j = job();
    let r = ComputeReceiptV1::decode(&raw(&x["receipt"])).unwrap();
    let c = ComputeResourceAccountingV1::decode(&raw(&x["accounting"])).unwrap();
    let output = unhex(x["output_hex"].as_str().unwrap());
    let evidence = unhex(x["evidence_hex"].as_str().unwrap());
    for field in 0..3 {
        let mut changed = c.clone();
        match field {
            0 => changed.input_bytes += 1,
            1 => changed.output_bytes += 1,
            _ => changed.evidence_bytes += 1,
        }
        assert!(r
            .verify_content(&j, &changed, &input(), &output, &evidence)
            .is_err());
    }
    for x in v["accounting_extremes"].as_array().unwrap() {
        let r = ComputeResourceAccountingV1::decode(&raw(x)).unwrap();
        assert_eq!(r.input_bytes.to_string(), x["input_bytes"]);
        assert_eq!(r.output_bytes.to_string(), x["output_bytes"]);
        assert_eq!(r.evidence_bytes.to_string(), x["evidence_bytes"]);
        assert_eq!(hex(&r.commitment().unwrap()), x["commitment_hex"]);
    }
}
