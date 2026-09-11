use super::*;
use crate::authorization::AuthorizationLineageV2;

fn sample() -> (MinerRewardObligationV1, Value, String) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../../../../fixtures/miner_v1/job_profile_vector_v1.json"
    ))
    .unwrap();
    let job = MinerJobV1::decode(&raw(v["job_hex"].as_str().unwrap()).unwrap()).unwrap();
    let funding=MinerFundingReservationV1::from_storage(&json!({"network":"regtest","txid":"11".repeat(32),"vout":0,"value_satoshis":20_000,"reward_satoshis":10_000,"fee_budget_satoshis":5000}).to_string()).unwrap();
    let o = MinerRewardObligationV1 {
        round: MinerRoundV1 {
            job: job.clone(),
            signature: [0; 64],
            state: MinerRoundStateV1::Accepted,
            attempt_id: Some(1),
            funding,
        },
        receipt: EconomicReceiptV1 {
            attempt_id: 1,
            outcome: EconomicOutcomeV1::Accepted,
            burn_units: 0,
            head: EconomicHeadV2::genesis(),
            detail: String::new(),
        },
        authorization: AuthorizationEnvelopeV2 {
            authorization_version: "v2".into(),
            proof_hash_hex: "ab".repeat(32),
            signature_hex: "00".repeat(64),
            authorization_lineage: AuthorizationLineageV2 {
                subject_binding_type: "bip340-xonly-pubkey-hex".into(),
                subject_binding: crate::authorization::encode_hex_v2(&job.operator_key),
                intent_type: "opaque-intent-hash-32".into(),
                intent_commitment_hex: "22".repeat(32),
                freshness_binding_type: "nonce-32-hex".into(),
                freshness_binding: "33".repeat(32),
            },
        },
    };
    let change = "5120".to_owned() + &"44".repeat(32);
    let decoded = json!({"txid":"55".repeat(32),"vsize":200,"vin":[{"txid":"11".repeat(32),"vout":0,"sequence":0xffff_fffdu32}],"vout":[
        {"n":0,"value":0,"scriptPubKey":{"hex":crate::authorization::encode_hex_v2(&request(&o).unwrap().script_pubkey())}},
        {"n":1,"value":0.0001,"scriptPubKey":{"hex":crate::authorization::encode_hex_v2(&reward_script(&o).unwrap())}},
        {"n":2,"value":0.00009,"scriptPubKey":{"hex":change}}
    ]});
    (o, decoded, change)
}
fn inspect(
    o: &MinerRewardObligationV1,
    decoded: &Value,
    change: &str,
    max_fee: u64,
) -> AuthorizationResultV2<MinerPaymentV1> {
    check_transaction(
        &mut |method, args| {
            Ok(match method {
                "decoderawtransaction" if args[0] == "01000000" => decoded.clone(),
                "decoderawtransaction" => {
                    json!({"txid":decoded["vin"][0]["txid"],"vout":[{"n":0,"value":0.0002,"scriptPubKey":{"hex":"51"}}]})
                }
                "gettransaction" => json!({"hex":"aa"}),
                _ => panic!("unexpected RPC"),
            })
        },
        o,
        "01000000",
        change,
        max_fee,
        1,
    )
}

#[test]
fn exact_reward_anchor_input_and_integer_fee_are_bound_to_core_transaction() {
    let (o, decoded, change) = sample();
    let p = inspect(&o, &decoded, &change, 5000).unwrap();
    assert_eq!(p.fee_satoshis, 1000);
    assert_eq!(p.reward_output_index, 1);
    assert_eq!(p.anchor_output_index, 0);
    for case in 0..11 {
        let mut d = decoded.clone();
        match case {
            0 => d["vout"][1]["value"] = json!(0.00009999),
            1 => d["vout"][1]["scriptPubKey"]["hex"] = json!("5120".to_owned() + &"66".repeat(32)),
            2 => {
                let mut extra = d["vout"][1].clone();
                extra["n"] = json!(3);
                d["vout"].as_array_mut().unwrap().push(extra);
            }
            3 => {
                d["vout"][0]["scriptPubKey"]["hex"] =
                    json!("6a26415552410103".to_owned() + &"cd".repeat(32))
            }
            4 => d["vout"][0]["value"] = json!(0.00000001),
            5 => d["vin"][0]["txid"] = json!("77".repeat(32)),
            6 => d["vin"][0]["sequence"] = json!(0xffff_ffffu32),
            7 => d["vout"][2]["scriptPubKey"]["hex"] = json!("51"),
            8 => d["vout"][2]["value"] = json!(0.00001),
            9 => d["vout"][2]["value"] = json!(0.0002),
            _ => {
                let input = d["vin"][0].clone();
                d["vin"].as_array_mut().unwrap().push(input);
            }
        }
        assert!(inspect(&o, &d, &change, 5000).is_err(), "case {case}");
    }
    assert!(inspect(&o, &decoded, &change, 999).is_err());
}

#[test]
fn rpc_absence_and_policy_fail_closed_without_error_string_guessing() {
    assert!(absent(Err(MinerCoreRpcErrorV1 {
        code: -5,
        message: "unknown".into()
    }
    .into()))
    .unwrap()
    .is_none());
    assert!(absent(Err(MinerCoreRpcErrorV1 {
        code: -28,
        message: "warming up".into()
    }
    .into()))
    .is_err());
    assert!(absent(Err("unknown transaction".into())).is_err());
    let (o, _, _) = sample();
    for p in [
        MinerPaymentPolicyV1 {
            fee_rate_sat_vb: 0,
            max_fee_satoshis: 1,
        },
        MinerPaymentPolicyV1 {
            fee_rate_sat_vb: 1,
            max_fee_satoshis: 0,
        },
        MinerPaymentPolicyV1 {
            fee_rate_sat_vb: 1,
            max_fee_satoshis: 5001,
        },
    ] {
        assert!(check_policy(&o, p).is_err());
    }
}
