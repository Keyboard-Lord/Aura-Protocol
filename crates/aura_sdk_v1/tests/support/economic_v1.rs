#[path = "authorization_v2.rs"]
mod authorization;
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_intent_lineage_v1::{
    StormAirRealProofArtifactV1, StormClaim521V1, StormExecutionInputsV1,
};
use aura_l2_local_chain_v0::{economic_meter::EconomicMeterV1, CanonicalPipelineLedgerAccountV1};
use aura_sdk_v1::{
    authorization::{encode_hex_v2, AuthorizationEnvelopeV2},
    economic::{EconomicConsentV1, EconomicWorkV1},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};

pub fn keypair() -> Keypair {
    let mut secret = [0; 32];
    secret[31] = 3;
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_byte_array(secret).unwrap(),
    )
}

pub fn sample() -> (
    EconomicWorkV1,
    EconomicConsentV1,
    AuthorizationEnvelopeV2,
    StormClaim521V1,
    StormAirRealProofArtifactV1,
) {
    let (auth, claim, proof) = authorization::sample(0x11);
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/economic_admission_v1/meter_vectors.json"
    ))
    .unwrap();
    let hex = vector[0]["meter_hex"].as_str().unwrap();
    let bytes: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut meter = EconomicMeterV1::decode(&bytes, bytes.len()).unwrap();
    let subject = keypair().x_only_public_key().0.serialize();
    meter.ledger.payer_account_id = subject;
    meter.ledger.accounts = vec![CanonicalPipelineLedgerAccountV1 {
        account_id: subject,
        balance: 1_000_000,
    }];
    meter.ledger.total_supply = 1_000_000;
    meter.ledger.burned_supply = 0;
    meter.wallet_binding.account_id = subject;
    meter.head.head_sequence_number = 1;
    meter.head.previous_head_hash = [0; 32];
    let work = EconomicWorkV1 {
        meter,
        storm: StormExecutionInputsV1 {
            side_a: claim.side_a,
            side_b: claim.side_b,
            context_bytes_v1: claim.context_bytes_v1,
            iteration_count: claim.iteration_count,
        },
    };
    let consent = sign(&work, &auth);
    (work, consent, auth, claim, proof)
}

pub fn sign(work: &EconomicWorkV1, auth: &AuthorizationEnvelopeV2) -> EconomicConsentV1 {
    let digest = EconomicConsentV1::signing_digest(BitcoinNetworkV1::Regtest, work, auth).unwrap();
    EconomicConsentV1 {
        economic_consent_version: "v1".into(),
        signature_hex: encode_hex_v2(
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(&digest, &keypair())
                .as_ref(),
        ),
    }
}
