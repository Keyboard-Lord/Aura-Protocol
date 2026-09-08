//! Thin command adapter to canonical Rust admission; outputs no request on failure.
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_intent_lineage_v1::decode_storm_air_real_artifact_v1;
use aura_sdk_v1::authorization::{AuthorizerJournalV2, AuthorizationEnvelopeV2, AuthorizationDispositionV2, AuthorizationResultV2};
use std::{io::Read, path::Path};

fn read_bounded(path: &str, limit: u64) -> AuthorizationResultV2<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err("authorizer input byte limit exceeded".into()); }
    Ok(bytes)
}
fn main() -> AuthorizationResultV2<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "init" {
        AuthorizerJournalV2::create(Path::new(&args[2]))?;
        return Ok(());
    }
    if args.len() != 8 || args[1] != "accept" {
        return Err("usage: aura-authorizer init JOURNAL | accept JOURNAL NETWORK AUTHORIZATION_JSON PROOF_BYTES MAX_ITERATIONS MAX_PROOF_BYTES".into());
    }
    let network: BitcoinNetworkV1 = serde_json::from_value(serde_json::Value::String(args[3].clone()))?;
    let envelope: AuthorizationEnvelopeV2 = serde_json::from_slice(&read_bounded(&args[4], 4096)?)?;
    let limit: u64 = args[6].parse()?;
    let proof_bytes = read_bounded(&args[5], args[7].parse()?)?;
    let (claim, proof) = decode_storm_air_real_artifact_v1(proof_bytes)?;
    let accepted = AuthorizerJournalV2::open(Path::new(&args[2]))?
        .accept(network, &envelope, &claim, &proof, limit)?;
    eprintln!("{}", match accepted.disposition() {
        AuthorizationDispositionV2::Reserved => "reserved",
        AuthorizationDispositionV2::SameActionRetry => "same_action_retry",
    });
    println!("{}", serde_json::to_string(accepted.request())?);
    Ok(())
}
