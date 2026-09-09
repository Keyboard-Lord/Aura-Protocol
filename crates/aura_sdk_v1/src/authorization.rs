//! Canonical v2 authorization. Legacy account-bound objects are not accepted here.
use aura_bitcoin_v1::{BitcoinAnchorRequestV1, BitcoinNetworkV1};
use crate::prepare_bound_proof_material_v1;
use aura_intent_lineage_v1::{build_storm_air_public_inputs_v1, verify_storm_air_real_v1, StormAirRealProofArtifactV1, StormClaim521V1};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, path::Path, time::Duration};

pub type AuthorizationResultV2<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLineageV2 {
    pub subject_binding_type: String,
    pub subject_binding: String,
    pub intent_type: String,
    pub intent_commitment_hex: String,
    pub freshness_binding_type: String,
    pub freshness_binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationEnvelopeV2 {
    pub authorization_version: String,
    pub proof_hash_hex: String,
    pub authorization_lineage: AuthorizationLineageV2,
    pub signature_hex: String,
}

pub fn decode_hex_v2<const N: usize>(value: &str) -> AuthorizationResultV2<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("non-canonical authorization hex".into());
    }
    let mut bytes = [0; N];
    for (i, byte) in bytes.iter_mut().enumerate() { *byte = u8::from_str_radix(&value[i*2..i*2+2], 16)?; }
    Ok(bytes)
}
pub fn encode_hex_v2(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

impl AuthorizationEnvelopeV2 {
    pub fn validate_shape(&self) -> AuthorizationResultV2<()> {
        let lineage = &self.authorization_lineage;
        if self.authorization_version != "v2" || lineage.subject_binding_type != "bip340-xonly-pubkey-hex"
            || lineage.freshness_binding_type != "nonce-32-hex" || lineage.intent_type != "opaque-intent-hash-32" {
            return Err("unsupported authorization version or lineage type".into());
        }
        XOnlyPublicKey::from_byte_array(decode_hex_v2(&lineage.subject_binding)?)?;
        decode_hex_v2::<32>(&lineage.freshness_binding)?;
        decode_hex_v2::<32>(&lineage.intent_commitment_hex)?;
        decode_hex_v2::<32>(&self.proof_hash_hex)?;
        decode_hex_v2::<64>(&self.signature_hex)?;
        Ok(())
    }
    pub fn signing_digest(&self, network: BitcoinNetworkV1) -> AuthorizationResultV2<[u8; 32]> {
        self.validate_shape()?;
        let tag = Sha256::digest(b"AURA_AUTHORIZATION_V2");
        let mut hash = Sha256::new();
        hash.update(tag); hash.update(tag);
        hash.update([network.tag()]);
        hash.update(decode_hex_v2::<32>(&self.proof_hash_hex)?);
        hash.update(decode_hex_v2::<32>(&self.authorization_lineage.intent_commitment_hex)?);
        Ok(hash.finalize().into())
    }
    pub fn verify_signature(&self, network: BitcoinNetworkV1) -> AuthorizationResultV2<()> {
        let digest = self.signing_digest(network)?;
        let key = XOnlyPublicKey::from_byte_array(decode_hex_v2(&self.authorization_lineage.subject_binding)?)?;
        let signature = Signature::from_byte_array(decode_hex_v2(&self.signature_hex)?);
        Secp256k1::verification_only().verify_schnorr(&signature, &digest, &key)?;
        Ok(())
    }
}

pub fn fresh_nonce_v2() -> AuthorizationResultV2<[u8; 32]> {
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("nonce generation failed: {e}"))?;
    Ok(nonce)
}

/// Actual Storm witness-backend verification, without changing that backend's semantics.
/// This backend has no external verification key: material commits the empty key bytes.
/// The resource limit is explicit authorizer policy, not a new Storm protocol limit.
fn verify_bound_proof(
    envelope: &AuthorizationEnvelopeV2, claim: &StormClaim521V1,
    artifact: &StormAirRealProofArtifactV1, max_iterations: u64,
) -> AuthorizationResultV2<()> {
    if claim.iteration_count > max_iterations { return Err("authorizer iteration limit exceeded".into()); }
    let inputs = build_storm_air_public_inputs_v1(claim);
    let claim_bytes = claim.canonical_bytes();
    if artifact.proof_bytes.get(8..8 + claim_bytes.len()) != Some(claim_bytes.as_slice()) {
        return Err("proof claim binding mismatch".into());
    }
    verify_storm_air_real_v1(&inputs, artifact)?;
    let lineage = &envelope.authorization_lineage;
    let subject = decode_hex_v2::<32>(&lineage.subject_binding)?;
    let nonce = decode_hex_v2::<32>(&lineage.freshness_binding)?;
    let intent = decode_hex_v2::<32>(&lineage.intent_commitment_hex)?;
    if claim.context_bytes_v1[65..97] != intent || claim.context_bytes_v1[97..129] != nonce
        || claim.context_bytes_v1[145..177] != subject {
        return Err("proof context and authorization lineage mismatch".into());
    }
    let prepared = prepare_bound_proof_material_v1(
        subject, nonce, &artifact.proof_bytes, &inputs.canonical_bytes(), &[],
    )?;
    if prepared.proof_hash != decode_hex_v2::<32>(&envelope.proof_hash_hex)? {
        return Err("proof material binding mismatch".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDispositionV2 { Reserved, SameActionRetry }

#[derive(Clone, Debug)]
pub struct AuthorizedAnchorV2 {
    request: BitcoinAnchorRequestV1,
    disposition: AuthorizationDispositionV2,
}
impl AuthorizedAnchorV2 {
    pub fn request(&self) -> &BitcoinAnchorRequestV1 { &self.request }
    pub fn disposition(&self) -> AuthorizationDispositionV2 { self.disposition }
}

/// The only durable acceptance path. No reset, delete-reservation, or implicit-create API.
pub struct AuthorizerJournalV2 { connection: Connection }
impl AuthorizerJournalV2 {
    pub fn create(path: &Path) -> AuthorizationResultV2<Self> {
        let mut options = OpenOptions::new(); options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        options.open(path)?.sync_all()?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;
            BEGIN IMMEDIATE;
            PRAGMA application_id=0x41555241; PRAGMA user_version=2;
            CREATE TABLE authorizations(network INTEGER NOT NULL, subject TEXT NOT NULL, nonce TEXT NOT NULL,
              proof_hash TEXT NOT NULL, intent TEXT NOT NULL, PRIMARY KEY(network,subject,nonce)) WITHOUT ROWID;
            COMMIT;")?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        drop(connection);
        Self::open(path)
    }
    pub fn open(path: &Path) -> AuthorizationResultV2<Self> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;")?;
        let id: u32 = connection.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if id != 0x41555241 || version != 2 || integrity != "ok" { return Err("invalid authorizer journal; recovery required".into()); }
        connection.prepare("SELECT network,subject,nonce,proof_hash,intent FROM authorizations")?;
        Ok(Self { connection })
    }
    pub fn accept(
        &mut self, network: BitcoinNetworkV1, envelope: &AuthorizationEnvelopeV2,
        claim: &StormClaim521V1, proof: &StormAirRealProofArtifactV1, max_iterations: u64,
    ) -> AuthorizationResultV2<AuthorizedAnchorV2> {
        envelope.verify_signature(network)?;
        verify_bound_proof(envelope, claim, proof, max_iterations)?;
        let l = &envelope.authorization_lineage;
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = tx.query_row(
            "SELECT proof_hash,intent FROM authorizations WHERE network=?1 AND subject=?2 AND nonce=?3",
            params![network.tag(), l.subject_binding, l.freshness_binding], |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        let disposition = match existing {
            Some((proof_hash, intent)) if proof_hash == envelope.proof_hash_hex && intent == l.intent_commitment_hex => AuthorizationDispositionV2::SameActionRetry,
            Some(_) => return Err("nonce already reserved for a different action".into()),
            None => {
                tx.execute("INSERT INTO authorizations VALUES (?1,?2,?3,?4,?5)",
                    params![network.tag(), l.subject_binding, l.freshness_binding, envelope.proof_hash_hex, l.intent_commitment_hex])?;
                AuthorizationDispositionV2::Reserved
            }
        };
        tx.commit()?;
        Ok(AuthorizedAnchorV2 { request: BitcoinAnchorRequestV1::new(network, envelope.proof_hash_hex.clone())?, disposition })
    }
}
