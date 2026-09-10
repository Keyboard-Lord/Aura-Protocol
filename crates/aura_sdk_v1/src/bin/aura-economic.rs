//! Operator adapter for durable economic admission. JSON responses are diagnostic
//! journal views; W and the existing Bitcoin request retain their owning encodings.
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_l2_local_chain_v0::economic_meter::economic_ledger_commitment_v1;
use aura_sdk_v1::{
    authorization::{decode_hex_v2, encode_hex_v2, AuthorizationEnvelopeV2, AuthorizationResultV2},
    economic::{
        journal::{
            EconomicAttemptStateV1, EconomicJournalV1, EconomicPriorHeadV1, EconomicReceiptV1,
            LegacyHeadCheckpointV1,
        },
        EconomicConsentV1, EconomicLimitsV1, EconomicWorkV1,
    },
};
use serde_json::json;
use std::{io::Read, path::Path};

fn read_bounded(path: &str, limit: usize) -> AuthorizationResultV2<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("economic command input byte limit exceeded".into());
    }
    Ok(bytes)
}
fn receipt(r: &EconomicReceiptV1) -> serde_json::Value {
    json!({"state":"terminal", "attempt_id":r.attempt_id.to_string(), "outcome":format!("{:?}",r.outcome),
        "burn_units":r.burn_units.to_string(), "head":r.head, "detail":r.detail})
}
fn main() -> AuthorizationResultV2<()> {
    let args: Vec<_> = std::env::args().collect();
    let usage = "usage: aura-economic COMMAND JOURNAL NETWORK MAX_ITERATIONS MAX_WORK_BYTES [INPUTS]\ncommands: init WORK_BYTES | migrate-v1 WORK_BYTES CHECKPOINT_JSON | admit/submit WORK_BYTES CONSENT_JSON AUTHORIZATION_JSON | resume ATTEMPT_ID | outbox | record-publication ATTEMPT_ID TXID | status PAYER_HEX";
    if args.len() < 6 {
        return Err(usage.into());
    }
    let network: BitcoinNetworkV1 = serde_json::from_value(json!(&args[3]))?;
    let limit: usize = args[5].parse()?;
    let limits = EconomicLimitsV1 {
        max_work_bytes: limit,
        max_meter_bytes: limit,
        max_iterations: args[4].parse()?,
    };
    let path = Path::new(&args[2]);
    match (args[1].as_str(), &args[6..]) {
        ("init", [work_file]) => {
            let work = EconomicWorkV1::decode(&read_bounded(work_file, limit)?, limits)?;
            let genesis = EconomicPriorHeadV1::Current(
                aura_sdk_v1::economic::head::EconomicHeadV2::genesis(),
            );
            if work.meter.head != genesis.next_linkage()? {
                return Err(
                    "new economic journal requires genesis linkage; use explicit migration for V1"
                        .into(),
                );
            }
            EconomicJournalV1::create(path, network, &work.meter.ledger, limits)?;
        }
        ("migrate-v1", [work_file, checkpoint_file]) => {
            let work = EconomicWorkV1::decode(&read_bounded(work_file, limit)?, limits)?;
            let checkpoint: LegacyHeadCheckpointV1 =
                serde_json::from_slice(&read_bounded(checkpoint_file, 4096)?)?;
            if work.meter.head
                != EconomicPriorHeadV1::LegacyV1(checkpoint.clone()).next_linkage()?
            {
                return Err("migration work/checkpoint linkage mismatch".into());
            }
            EconomicJournalV1::migrate_v1(path, network, &work.meter.ledger, checkpoint, limits)?;
        }
        (command @ ("admit" | "submit"), [work_file, consent_file, auth_file]) => {
            let bytes = read_bounded(work_file, limit)?;
            let consent: EconomicConsentV1 =
                serde_json::from_slice(&read_bounded(consent_file, 4096)?)?;
            let auth: AuthorizationEnvelopeV2 =
                serde_json::from_slice(&read_bounded(auth_file, 4096)?)?;
            let mut journal = EconomicJournalV1::open(path, network, limits)?;
            let value = if command == "submit" {
                receipt(&journal.submit(&bytes, &consent, &auth)?)
            } else {
                match journal.admit(&bytes, &consent, &auth)? {
                    EconomicAttemptStateV1::Admitted { attempt_id } => {
                        json!({"state":"admitted", "attempt_id":attempt_id.to_string()})
                    }
                    EconomicAttemptStateV1::Terminal(r) => receipt(&r),
                }
            };
            println!("{}", value);
        }
        ("resume", [id]) => {
            let mut journal = EconomicJournalV1::open(path, network, limits)?;
            println!("{}", receipt(&journal.resume(id.parse()?)?));
        }
        ("outbox", []) => {
            let journal = EconomicJournalV1::open(path, network, limits)?;
            let entries: Vec<_> = journal
                .outbox()?
                .into_iter()
                .map(|e| {
                    json!({"attempt_id":e.attempt_id.to_string(),
                "request":e.request, "last_publication_txid":e.last_publication_txid})
                })
                .collect();
            println!("{}", serde_json::to_string(&entries)?);
        }
        ("record-publication", [id, txid]) => {
            EconomicJournalV1::open(path, network, limits)?
                .record_publication(id.parse()?, txid)?;
        }
        ("status", [payer]) => {
            let journal = EconomicJournalV1::open(path, network, limits)?;
            let ledger = journal.ledger_for_payer(decode_hex_v2(payer)?)?;
            println!(
                "{}",
                json!({"total_supply":ledger.total_supply.to_string(), "burned_supply":ledger.burned_supply.to_string(),
                "ledger_state_commitment_hex":encode_hex_v2(&economic_ledger_commitment_v1(&ledger)?),
                "prior_head":journal.prior_head()?, "pending_attempt_id":journal.pending_attempt()?.map(|id|id.to_string())})
            );
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}
