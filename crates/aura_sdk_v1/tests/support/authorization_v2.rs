use aura_sdk_v1::authorization::{encode_hex_v2, AuthorizationEnvelopeV2, AuthorizationLineageV2};
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_fractal_key_v1::{FractalKeyBuilderInputV1, FractalKeyV1};
use aura_intent_lineage_v1::{build_storm_claim_v1, build_storm_air_public_inputs_v1, prove_storm_air_real_v1,
    StormContextV1, StormExecutionInputsV1, StormClaim521V1, StormAirRealProofArtifactV1};
use aura_proof_material_v1::ProofMaterialV1;
use secp256k1::{Secp256k1, SecretKey, Keypair};

pub fn sample(side: u8) -> (AuthorizationEnvelopeV2, StormClaim521V1, StormAirRealProofArtifactV1) {
    let secp = Secp256k1::new();
    let mut secret = [0; 32]; secret[31] = 3;
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(secret).unwrap());
    let subject = keypair.x_only_public_key().0.serialize();
    let claim = build_storm_claim_v1(&StormExecutionInputsV1 {
        side_a: [side; 110], side_b: [0x55; 110], iteration_count: 3,
        context_bytes_v1: StormContextV1 { context_version: 1, network_id: [0x33; 32], intent_hash: [0x44; 32],
          freshness_nonce: [0x22; 32], valid_from: 0, valid_until: 100, controller_id: subject, route_tag: [0x66; 32] }.to_bytes(),
    }, [0; 32], [0; 32]);
    let inputs = build_storm_air_public_inputs_v1(&claim);
    let proof = prove_storm_air_real_v1(&claim, &inputs).unwrap();
    let material = ProofMaterialV1::build(&proof.proof_bytes, &inputs.canonical_bytes(), &[]);
    let proof_hash = FractalKeyV1::build(FractalKeyBuilderInputV1 { subject_binding: subject,
        challenge_binding: [0x22; 32], proof_material_hash: material.proof_material_hash() }).proof_hash();
    let mut envelope = AuthorizationEnvelopeV2 { authorization_version: "v2".into(), proof_hash_hex: encode_hex_v2(&proof_hash),
        authorization_lineage: AuthorizationLineageV2 { subject_binding_type: "bip340-xonly-pubkey-hex".into(),
          subject_binding: encode_hex_v2(&subject), intent_type: "opaque-intent-hash-32".into(),
          intent_commitment_hex: "44".repeat(32), freshness_binding_type: "nonce-32-hex".into(), freshness_binding: "22".repeat(32) },
        signature_hex: "00".repeat(64) };
    envelope.signature_hex = encode_hex_v2(secp.sign_schnorr_no_aux_rand(&envelope.signing_digest(BitcoinNetworkV1::Regtest).unwrap(), &keypair).as_ref());
    (envelope, claim, proof)
}
