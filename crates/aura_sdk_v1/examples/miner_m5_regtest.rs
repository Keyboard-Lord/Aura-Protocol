//! Reproducible regtest adapter/evidence, not a deployment default or new wire.
//! The public test key is frozen in M2. Core CLI supplies authenticated RPC;
//! real applications provide their existing transport to the same journal APIs.
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use aura_sdk_v1::{
    authorization::{
        encode_hex_v2, AuthorizationEnvelopeV2, AuthorizationLineageV2, AuthorizationResultV2,
    },
    economic::{
        head::EconomicOutcomeV1,
        journal::{
            miner::{
                funding::reserve_miner_funding_v1,
                publication::{MinerCoreRpcErrorV1, MinerPaymentPolicyV1},
                MinerRoundOpeningV1, MinerRoundPolicyV1,
            },
            EconomicJournalV1,
        },
        EconomicConsentV1, EconomicLimitsV1, EconomicWorkV1,
    },
    miner::{MinerJobPolicyV1, MinerJobV1},
    miner_search::{
        MinerLimitsV1, MinerNonceModeV1, MinerSearchConfigV1, MinerSearchOutcomeV1, MinerSessionV1,
    },
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{path::Path, sync::atomic::AtomicBool, time::Duration};

const NETWORK: BitcoinNetworkV1 = BitcoinNetworkV1::Regtest;
fn limits() -> EconomicLimitsV1 {
    EconomicLimitsV1 {
        max_work_bytes: 100_000,
        max_meter_bytes: 90_000,
        max_iterations: 128,
    }
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn rpc(method: &str, params: Value) -> AuthorizationResultV2<Value> {
    let args = params.as_array().ok_or("RPC params must be an array")?;
    let mut cmd = std::process::Command::new(std::env::var("BITCOINCLI")?);
    cmd.arg("-regtest")
        .arg("-rpcclienttimeout=30")
        .arg(format!(
            "-datadir={}",
            std::env::var("AURA_M5_CORE_DATADIR")?
        ))
        .arg(format!("-rpcport={}", std::env::var("AURA_M5_CORE_PORT")?))
        .arg("-rpcwallet=aura-miner-test")
        .arg(method);
    for arg in args {
        cmd.arg(if let Some(s) = arg.as_str() {
            s.into()
        } else {
            serde_json::to_string(arg)?
        });
    }
    let output = cmd.output()?;
    if !output.status.success() {
        let message = String::from_utf8(output.stderr)?;
        let code = message
            .lines()
            .find_map(|l| l.strip_prefix("error code: ").and_then(|s| s.parse().ok()))
            .ok_or_else(|| format!("Core CLI failed: {message}"))?;
        return Err(MinerCoreRpcErrorV1 { code, message }.into());
    }
    let result = String::from_utf8(output.stdout)?;
    // bitcoin-cli prints string results unquoted, JSON arrays/objects/numbers as JSON.
    let value =
        serde_json::from_str(result.trim()).unwrap_or_else(|_| Value::String(result.trim().into()));
    if method == "sendrawtransaction"
        && std::env::var("AURA_M5_CRASH_AFTER_BROADCAST").as_deref() == Ok("1")
    {
        std::process::exit(86);
    }
    if method == "finalizepsbt"
        && std::env::var("AURA_M6_CRASH_AFTER_TRANSACTION").as_deref() == Ok("1")
    {
        std::process::exit(87);
    }
    Ok(value)
}
fn main() -> AuthorizationResultV2<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        return Err("miner_m5_regtest COMMAND JOURNAL [ARGS]".into());
    }
    let path = Path::new(&args[2]);
    let candidate_path = path.with_extension("candidate.json");
    if args[1] == "setup" {
        let reward: u64 = args
            .get(3)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(10_000);
        let preflight_rate: u64 = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(2);
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/miner_v1/job_profile_vector_v1.json"
        ))?;
        let template = MinerJobV1::decode(&unhex(fixture["job_hex"].as_str().unwrap()))?;
        let meter =
            EconomicMeterV1::decode(&unhex(fixture["meter_hex"].as_str().unwrap()), 90_000)?;
        let key = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array(
                unhex(fixture["test_only_operator_secret_hex"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            )?,
        );
        let mut target = [255; 32];
        target[0] = 127;
        let policy = MinerRoundPolicyV1 {
            job: MinerJobPolicyV1 {
                network: NETWORK,
                operator_key: template.operator_key,
                journal_namespace: template.journal_namespace,
                policy_epoch: 0,
                iteration_count: 8,
                target,
                max_work_bytes: 100_000,
                max_meter_bytes: 90_000,
            },
            max_duration_secs: 900,
            minimum_reward_satoshis: reward,
        };
        let mut journal = EconomicJournalV1::create(path, NETWORK, &meter.ledger, limits())?;
        journal.install_miner_policy(&policy)?;
        journal.install_miner_publication()?;
        let coins = rpc("listunspent", json!([1]))?;
        let coin = coins
            .as_array()
            .ok_or("no wallet coin list")?
            .iter()
            .find(|c| c["spendable"] == true && c["safe"] == true)
            .ok_or("regtest wallet has no funding")?;
        let txid = coin["txid"].as_str().ok_or("coin txid")?;
        let vout = u32::try_from(coin["vout"].as_u64().ok_or("coin vout")?)?;
        let round = journal.open_miner_round(
            &key,
            MinerRoundOpeningV1 {
                side_a: template.side_a,
                side_b: template.side_b,
                duration_secs: 900,
                reward_satoshis: reward,
            },
            |job| reserve_miner_funding_v1(rpc, job, txid, vout, 20_000, preflight_rate),
        )?;
        let session = MinerSessionV1::new(
            &round.job,
            &round.signature,
            &policy.job,
            &meter,
            &key,
            MinerLimitsV1 {
                work: limits(),
                max_proof_bytes: 1_000_000,
            },
        )?;
        let mined = session.mine(
            MinerSearchConfigV1 {
                max_trials: 128,
                max_duration: Duration::from_secs(30),
                nonce_mode: MinerNonceModeV1::ResearchSequential { first: [42; 32] },
            },
            &AtomicBool::new(false),
        )?;
        let MinerSearchOutcomeV1::Qualified(candidate) = mined else {
            return Err("bounded easy-target regtest search exhausted".into());
        };
        let work = candidate.work();
        let mut auth = AuthorizationEnvelopeV2 {
            authorization_version: "v2".into(),
            proof_hash_hex: encode_hex_v2(&candidate.proof_hash()),
            signature_hex: "00".repeat(64),
            authorization_lineage: AuthorizationLineageV2 {
                subject_binding_type: "bip340-xonly-pubkey-hex".into(),
                subject_binding: encode_hex_v2(&work.subject()),
                intent_type: "opaque-intent-hash-32".into(),
                intent_commitment_hex: encode_hex_v2(&work.intent()),
                freshness_binding_type: "nonce-32-hex".into(),
                freshness_binding: encode_hex_v2(&work.nonce()),
            },
        };
        auth.signature_hex = encode_hex_v2(
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(&auth.signing_digest(NETWORK)?, &key)
                .as_ref(),
        );
        let consent = EconomicConsentV1 {
            economic_consent_version: "v1".into(),
            signature_hex: encode_hex_v2(
                Secp256k1::new()
                    .sign_schnorr_no_aux_rand(
                        &EconomicConsentV1::signing_digest(NETWORK, work, &auth)?,
                        &key,
                    )
                    .as_ref(),
            ),
        };
        std::fs::write(
            &candidate_path,
            serde_json::to_vec(
                &json!({"work_hex":encode_hex_v2(&work.canonical_bytes()?),"auth":auth,"consent":consent}),
            )?,
        )?;
        let id = journal
            .admit(&work.canonical_bytes()?, &consent, &auth)?
            .attempt_id();
        drop(journal);
        let mut journal = EconomicJournalV1::open(path, NETWORK, limits())?;
        let receipt = journal.resume(id)?;
        if receipt.outcome != EconomicOutcomeV1::Accepted {
            return Err("regtest contender was not accepted".into());
        }
        println!(
            "{}",
            json!({"attempt_id":id,"proof_hash":auth.proof_hash_hex,"subject":auth.authorization_lineage.subject_binding,"reward_satoshis":round.job.reward_satoshis,
            "funding_txid":round.funding.txid(),"funding_vout":round.funding.vout(),"funding_value":round.funding.value_satoshis(),"burn_units":receipt.burn_units,"head":receipt.head})
        );
        return Ok(());
    }
    let mut journal = EconomicJournalV1::open(path, NETWORK, limits())?;
    let id = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(1);
    let result = match args[1].as_str() {
        "wrong-network" => {
            let mut round = journal.miner_round(1)?;
            round.job.network = BitcoinNetworkV1::Signet;
            reserve_miner_funding_v1(
                rpc,
                &round.job,
                round.funding.txid(),
                round.funding.vout(),
                20_000,
                2,
            )?;
            return Err("wrong Core network unexpectedly accepted".into());
        }
        "prepare" => serde_json::to_value(journal.prepare_miner_payment(
            id,
            MinerPaymentPolicyV1 {
                fee_rate_sat_vb: args[4].parse()?,
                max_fee_satoshis: args[5].parse()?,
            },
            rpc,
        )?)?,
        "replace" => serde_json::to_value(journal.replace_miner_payment(
            id,
            &args[4],
            MinerPaymentPolicyV1 {
                fee_rate_sat_vb: args[5].parse()?,
                max_fee_satoshis: args[6].parse()?,
            },
            rpc,
        )?)?,
        "publish" => {
            serde_json::to_value(journal.publish_miner_payment(id, args[4].parse()?, rpc)?)?
        }
        "observe" => {
            serde_json::to_value(journal.observe_miner_payment(id, args[4].parse()?, rpc)?)?
        }
        "payments" => serde_json::to_value(journal.miner_payments(id)?)?,
        "retry" => {
            let v: Value = serde_json::from_slice(&std::fs::read(candidate_path)?)?;
            let w = EconomicWorkV1::decode(&unhex(v["work_hex"].as_str().unwrap()), limits())?;
            let receipt = journal.submit(
                &w.canonical_bytes()?,
                &serde_json::from_value(v["consent"].clone())?,
                &serde_json::from_value(v["auth"].clone())?,
            )?;
            json!({"attempt_id":receipt.attempt_id,"head":receipt.head,"burn_units":receipt.burn_units})
        }
        "status" => {
            let obligations = journal.miner_reward_obligations()?;
            let o = obligations.first().ok_or("no accepted obligation")?;
            let ledger = journal.ledger_for_payer(aura_sdk_v1::authorization::decode_hex_v2(
                &o.authorization.authorization_lineage.subject_binding,
            )?)?;
            json!({"head":journal.prior_head()?,"burned_supply":ledger.burned_supply,"obligations":obligations.len(),"outbox":journal.outbox()?.iter().map(|e|json!({"attempt_id":e.attempt_id,"request":e.request,"txid":e.last_publication_txid})).collect::<Vec<_>>()})
        }
        _ => return Err("unknown regtest command".into()),
    };
    println!("{result}");
    Ok(())
}
