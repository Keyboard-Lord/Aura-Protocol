//! Approved economic work/consent codecs. Signature checks here are pre-admission
//! checks, not proof authorization, a debit, or Bitcoin publication.
use crate::authorization::{
    decode_hex_v2, encode_hex_v2, AuthorizationEnvelopeV2, AuthorizationResultV2,
};
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_intent_lineage_v1::StormExecutionInputsV1;
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod head;
pub mod journal;

const WORK_DOMAIN: &[u8] = b"AURA_ECONOMIC_WORK_REQUEST_V1";
const STORM_TUPLE_BYTES: usize = 110 + 110 + 209 + 8;

/// Explicit operator policy; these bounds do not redefine the tariff or Storm.
#[derive(Clone, Copy, Debug)]
pub struct EconomicLimitsV1 {
    pub max_work_bytes: usize,
    pub max_meter_bytes: usize,
    pub max_iterations: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicWorkV1 {
    pub meter: EconomicMeterV1,
    pub storm: StormExecutionInputsV1,
}

impl EconomicWorkV1 {
    pub fn decode(bytes: &[u8], limits: EconomicLimitsV1) -> AuthorizationResultV2<Self> {
        if bytes.len() > limits.max_work_bytes || !bytes.starts_with(WORK_DOMAIN) {
            return Err("invalid economic work domain or byte limit".into());
        }
        let prefix = WORK_DOMAIN.len() + 8;
        let len = bytes
            .get(WORK_DOMAIN.len()..prefix)
            .ok_or("truncated economic work")?;
        let len = usize::try_from(u64::from_le_bytes(len.try_into()?))?;
        let end = prefix
            .checked_add(len)
            .ok_or("economic work length overflow")?;
        if end.checked_add(STORM_TUPLE_BYTES) != Some(bytes.len()) || len > limits.max_meter_bytes {
            return Err("invalid economic work framing or meter limit".into());
        }
        let tuple = &bytes[end..];
        let work = Self {
            meter: EconomicMeterV1::decode(&bytes[prefix..end], limits.max_meter_bytes)?,
            storm: StormExecutionInputsV1 {
                side_a: tuple[..110].try_into()?,
                side_b: tuple[110..220].try_into()?,
                context_bytes_v1: tuple[220..429].try_into()?,
                iteration_count: u64::from_le_bytes(tuple[429..].try_into()?),
            },
        };
        if work.storm.iteration_count > limits.max_iterations {
            return Err("economic iteration limit exceeded".into());
        }
        if work.canonical_bytes()? != bytes {
            return Err("noncanonical economic work".into());
        }
        Ok(work)
    }

    pub fn canonical_bytes(&self) -> AuthorizationResultV2<Vec<u8>> {
        self.storm.validate()?;
        let subject = self.subject();
        XOnlyPublicKey::from_byte_array(subject)?;
        if self.meter.ledger.payer_account_id != subject {
            return Err("economic payer and controller mismatch".into());
        }
        let meter = self.meter.canonical_bytes()?;
        let mut bytes = WORK_DOMAIN.to_vec();
        bytes.extend_from_slice(&u64::try_from(meter.len())?.to_le_bytes());
        bytes.extend_from_slice(&meter);
        bytes.extend_from_slice(&self.storm.side_a);
        bytes.extend_from_slice(&self.storm.side_b);
        bytes.extend_from_slice(&self.storm.context_bytes_v1);
        bytes.extend_from_slice(&self.storm.iteration_count.to_le_bytes());
        Ok(bytes)
    }

    pub fn subject(&self) -> [u8; 32] {
        self.storm.context_bytes_v1[145..177].try_into().unwrap()
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.storm.context_bytes_v1[97..129].try_into().unwrap()
    }
    pub fn intent(&self) -> [u8; 32] {
        self.storm.context_bytes_v1[65..97].try_into().unwrap()
    }

    pub fn burn_units(&self) -> AuthorizationResultV2<u64> {
        Ok(self.meter.burn_units()?)
    }

    /// Auth shape/context consistency only, before actual proof verification.
    fn bind_envelope(&self, auth: &AuthorizationEnvelopeV2) -> AuthorizationResultV2<()> {
        auth.validate_shape()?;
        let l = &auth.authorization_lineage;
        if self.subject() != decode_hex_v2::<32>(&l.subject_binding)?
            || self.nonce() != decode_hex_v2::<32>(&l.freshness_binding)?
            || self.intent() != decode_hex_v2::<32>(&l.intent_commitment_hex)?
        {
            return Err("economic work and authorization lineage mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicConsentV1 {
    pub economic_consent_version: String,
    pub signature_hex: String,
}

impl EconomicConsentV1 {
    pub fn validate_shape(&self) -> AuthorizationResultV2<()> {
        if self.economic_consent_version != "v1" {
            return Err("unsupported economic consent version".into());
        }
        decode_hex_v2::<64>(&self.signature_hex)?;
        Ok(())
    }

    pub fn signing_digest(
        network: BitcoinNetworkV1,
        work: &EconomicWorkV1,
        auth: &AuthorizationEnvelopeV2,
    ) -> AuthorizationResultV2<[u8; 32]> {
        work.bind_envelope(auth)?;
        let bytes = work.canonical_bytes()?;
        let tag = Sha256::digest(b"AURA_ECONOMIC_CONSENT_V1");
        let mut h = Sha256::new();
        h.update(tag);
        h.update(tag);
        h.update([network.tag()]);
        h.update(work.burn_units()?.to_le_bytes());
        h.update(bytes);
        h.update(decode_hex_v2::<32>(&auth.proof_hash_hex)?);
        Ok(h.finalize().into())
    }

    /// Both signatures are required before debit. This does not reserve a nonce
    /// or establish proof/material acceptance; the durable coordinator owns that.
    pub fn verify_admission_signatures(
        &self,
        network: BitcoinNetworkV1,
        work: &EconomicWorkV1,
        auth: &AuthorizationEnvelopeV2,
    ) -> AuthorizationResultV2<()> {
        self.validate_shape()?;
        let digest = Self::signing_digest(network, work, auth)?;
        let key = XOnlyPublicKey::from_byte_array(work.subject())?;
        let signature = Signature::from_byte_array(decode_hex_v2(&self.signature_hex)?);
        Secp256k1::verification_only().verify_schnorr(&signature, &digest, &key)?;
        auth.verify_signature(network)?;
        Ok(())
    }
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex_v2(&Sha256::digest(bytes))
}
