// Deterministic TEST-ONLY key and nonce. Does not authorize any real assets.
#[path = "../tests/support/authorization_v2.rs"] mod support;
use aura_sdk_v1::authorization::encode_hex_v2;
use aura_intent_lineage_v1::build_storm_air_public_inputs_v1;
use aura_proof_material_v1::ProofMaterialV1;
use aura_bitcoin_v1::BitcoinNetworkV1;
fn main() {
    let (authorization, claim, proof) = support::sample(0x11);
    let inputs = build_storm_air_public_inputs_v1(&claim).canonical_bytes();
    let material = ProofMaterialV1::build(&proof.proof_bytes, &inputs, &[]);
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "test_only_secret_key_hex": format!("{}03", "00".repeat(31)), "network":"regtest",
        "authorization": authorization,
        "signing_digest_hex": encode_hex_v2(&authorization.signing_digest(BitcoinNetworkV1::Regtest).unwrap()),
        "proof_bytes_hex": encode_hex_v2(&proof.proof_bytes),
        "public_inputs_hex": encode_hex_v2(&inputs),
        "proof_material_hash_hex": encode_hex_v2(&material.proof_material_hash()),
    })).unwrap());
}
