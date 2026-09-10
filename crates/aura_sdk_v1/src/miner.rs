//! Approved miner job/profile codecs. These checks do not verify PoC, reserve a
//! round, debit a ledger, grant authorization, or determine a winner.
use crate::{
    authorization::AuthorizationResultV2,
    economic::{head::EconomicHeadV2, EconomicLimitsV1, EconomicWorkV1},
};
use aura_bitcoin_v1::BitcoinNetworkV1;
use aura_intent_lineage_v1::{
    StormClaim521V1, StormContextV1, StormExecutionInputsV1, STORM_CLAIM_521_V1_VERSION,
    STORM_CONTEXT_V1_VERSION, STORM_MODULUS_ID_521_V1,
};
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub const MINER_JOB_V1_BYTE_LEN: usize = 471;
const JOB_DOMAIN: &[u8] = b"AURA_MINER_JOB_V1";

/// One binary representation. Deliberately no alternate JSON job wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerJobV1 {
    pub job_version: u8,
    pub network: BitcoinNetworkV1,
    pub operator_key: [u8; 32],
    pub journal_namespace: [u8; 32],
    pub policy_epoch: u64,
    pub round_number: u64,
    pub prior_head_sequence: u64,
    pub prior_head_hash: [u8; 32],
    pub challenge: [u8; 32],
    pub side_a: [u8; 110],
    pub side_b: [u8; 110],
    pub iteration_count: u64,
    pub target: [u8; 32],
    pub max_work_bytes: u64,
    pub max_meter_bytes: u64,
    pub opened_at: u64,
    pub expires_at: u64,
    pub reward_satoshis: u64,
}

/// Trusted local epoch configuration, not a protocol wire or a value to infer
/// from an untrusted job. The coordinator will own its persistence/history.
#[derive(Clone, Debug)]
pub struct MinerJobPolicyV1 {
    pub network: BitcoinNetworkV1,
    pub operator_key: [u8; 32],
    pub journal_namespace: [u8; 32],
    pub policy_epoch: u64,
    pub iteration_count: u64,
    pub target: [u8; 32],
    pub max_work_bytes: u64,
    pub max_meter_bytes: u64,
}

pub fn miner_route_tag_v1() -> [u8; 32] {
    Sha256::digest(b"AURA_MINER_PROTOCOL_V1").into()
}

impl MinerJobV1 {
    pub fn validate_shape(&self) -> AuthorizationResultV2<()> {
        if self.job_version != 1 {
            return Err("unsupported miner job version".into());
        }
        XOnlyPublicKey::from_byte_array(self.operator_key)?;
        // The frozen Storm trace contains N+1 rows, which must fit u64.
        if self.iteration_count == 0 || self.iteration_count == u64::MAX {
            return Err("invalid miner iteration count".into());
        }
        if self.target == [0; 32] || self.target == [0xff; 32] {
            return Err("invalid miner target".into());
        }
        if self.opened_at >= self.expires_at || self.reward_satoshis == 0 {
            return Err("invalid miner window or reward".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> AuthorizationResultV2<Vec<u8>> {
        self.validate_shape()?;
        let mut b = Vec::with_capacity(MINER_JOB_V1_BYTE_LEN);
        b.extend_from_slice(JOB_DOMAIN);
        b.extend_from_slice(&[self.job_version, self.network.tag()]);
        b.extend_from_slice(&self.operator_key);
        b.extend_from_slice(&self.journal_namespace);
        for n in [self.policy_epoch, self.round_number, self.prior_head_sequence] {
            b.extend_from_slice(&n.to_le_bytes());
        }
        b.extend_from_slice(&self.prior_head_hash);
        b.extend_from_slice(&self.challenge);
        b.extend_from_slice(&self.side_a);
        b.extend_from_slice(&self.side_b);
        b.extend_from_slice(&self.iteration_count.to_le_bytes());
        b.extend_from_slice(&self.target);
        for n in [self.max_work_bytes, self.max_meter_bytes, self.opened_at, self.expires_at, self.reward_satoshis] {
            b.extend_from_slice(&n.to_le_bytes());
        }
        Ok(b)
    }

    pub fn decode(bytes: &[u8]) -> AuthorizationResultV2<Self> {
        if bytes.len() != MINER_JOB_V1_BYTE_LEN || !bytes.starts_with(JOB_DOMAIN) {
            return Err("invalid miner job framing".into());
        }
        let mut r = Reader(&bytes[JOB_DOMAIN.len()..]);
        let job_version = r.fixed::<1>()?[0];
        let tag = r.fixed::<1>()?[0];
        // The Bitcoin owner supplies tag values; enumerate its supported variants.
        let network = [BitcoinNetworkV1::Mainnet, BitcoinNetworkV1::Testnet3,
            BitcoinNetworkV1::Signet, BitcoinNetworkV1::Regtest, BitcoinNetworkV1::Testnet4]
            .into_iter().find(|network| network.tag() == tag).ok_or("unknown Bitcoin network")?;
        let job = Self {
            job_version, network, operator_key: r.fixed()?, journal_namespace: r.fixed()?,
            policy_epoch: r.u64()?, round_number: r.u64()?, prior_head_sequence: r.u64()?,
            prior_head_hash: r.fixed()?, challenge: r.fixed()?, side_a: r.fixed()?, side_b: r.fixed()?,
            iteration_count: r.u64()?, target: r.fixed()?, max_work_bytes: r.u64()?,
            max_meter_bytes: r.u64()?, opened_at: r.u64()?, expires_at: r.u64()?, reward_satoshis: r.u64()?,
        };
        if !r.0.is_empty() || job.canonical_bytes()? != bytes {
            return Err("noncanonical miner job".into());
        }
        Ok(job)
    }

    pub fn commitment(&self) -> AuthorizationResultV2<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn signing_digest(&self) -> AuthorizationResultV2<[u8; 32]> {
        let tag = Sha256::digest(b"AURA_MINER_JOB_SIGNATURE_V1");
        let mut hash = Sha256::new();
        hash.update(tag);
        hash.update(tag);
        hash.update(self.canonical_bytes()?);
        Ok(hash.finalize().into())
    }

    /// Authenticates the job against caller-supplied trusted epoch policy. This
    /// does not establish publication, funding, freshness, head or round ownership.
    pub fn verify_for_policy(
        &self, signature: &[u8], policy: &MinerJobPolicyV1, host: EconomicLimitsV1,
    ) -> AuthorizationResultV2<()> {
        self.validate_shape()?;
        if self.network != policy.network || self.operator_key != policy.operator_key
            || self.journal_namespace != policy.journal_namespace || self.policy_epoch != policy.policy_epoch
            || self.iteration_count != policy.iteration_count || self.target != policy.target
            || self.max_work_bytes != policy.max_work_bytes || self.max_meter_bytes != policy.max_meter_bytes
            || self.iteration_count > host.max_iterations
            || self.max_work_bytes > u64::try_from(host.max_work_bytes)?
            || self.max_meter_bytes > u64::try_from(host.max_meter_bytes)?
        {
            return Err("miner job does not match trusted epoch/host policy".into());
        }
        let signature = Signature::from_byte_array(signature.try_into()?);
        let key = XOnlyPublicKey::from_byte_array(policy.operator_key)?;
        Secp256k1::verification_only().verify_schnorr(&signature, &self.signing_digest()?, &key)?;
        Ok(())
    }

    /// For new admission only. Existing admitted retries must not be expired.
    pub fn validate_window(&self, now: u64, max_duration: u64) -> AuthorizationResultV2<()> {
        self.validate_shape()?;
        if now < self.opened_at || now >= self.expires_at || self.expires_at - self.opened_at > max_duration {
            return Err("miner job outside admission window".into());
        }
        Ok(())
    }

    pub fn validate_head(&self, current: &EconomicHeadV2) -> AuthorizationResultV2<()> {
        self.validate_shape()?;
        if current.validate()? != self.prior_head_sequence
            || crate::authorization::decode_hex_v2::<32>(&current.current_head_hash_hex)? != self.prior_head_hash
            || self.prior_head_sequence.checked_add(1).is_none()
        {
            return Err("miner job predecessor mismatch or overflow".into());
        }
        Ok(())
    }

    pub fn intent_commitment(&self, meter: &EconomicMeterV1) -> AuthorizationResultV2<[u8; 32]> {
        let m = meter.canonical_bytes()?;
        let mut hash = Sha256::new();
        hash.update(b"AURA_MINER_INTENT_V1");
        hash.update(self.commitment()?);
        hash.update(u64::try_from(m.len())?.to_le_bytes());
        hash.update(m);
        Ok(hash.finalize().into())
    }

    /// The supplied nonce must be generated with the existing fresh_nonce_v2
    /// producer. Accepting bytes cannot verify how their entropy was obtained.
    pub fn build_work(&self, meter: EconomicMeterV1, nonce: [u8; 32]) -> AuthorizationResultV2<EconomicWorkV1> {
        let context = self.context(&meter, nonce)?;
        let work = EconomicWorkV1 {
            meter,
            storm: StormExecutionInputsV1 { side_a: self.side_a, side_b: self.side_b,
                context_bytes_v1: context, iteration_count: self.iteration_count },
        };
        self.validate_work_profile(&work)?;
        Ok(work)
    }

    fn context(&self, meter: &EconomicMeterV1, nonce: [u8; 32]) -> AuthorizationResultV2<[u8; 209]> {
        Ok(StormContextV1 { context_version: STORM_CONTEXT_V1_VERSION,
            network_id: self.journal_namespace, intent_hash: self.intent_commitment(meter)?,
            freshness_nonce: nonce, valid_from: 0, valid_until: 0,
            controller_id: meter.ledger.payer_account_id, route_tag: miner_route_tag_v1() }.to_bytes())
    }

    /// Structural job/W binding only. Local execution and actual proof checks
    /// remain chargeable work under the existing economic coordinator.
    pub fn validate_work_profile(&self, work: &EconomicWorkV1) -> AuthorizationResultV2<()> {
        self.validate_shape()?;
        let bytes = work.canonical_bytes()?;
        let m = work.meter.canonical_bytes()?;
        if u64::try_from(bytes.len())? > self.max_work_bytes || u64::try_from(m.len())? > self.max_meter_bytes
            || work.storm.side_a != self.side_a || work.storm.side_b != self.side_b
            || work.storm.iteration_count != self.iteration_count
            || work.storm.context_bytes_v1 != self.context(&work.meter, work.nonce())?
            || work.meter.head.settlement_head_version != 2
            || work.meter.head.previous_head_hash != self.prior_head_hash
            || Some(work.meter.head.head_sequence_number) != self.prior_head_sequence.checked_add(1)
        {
            return Err("miner work does not match job profile".into());
        }
        Ok(())
    }

    /// Checks the existing claim's input/profile fields and fixed empty VK only.
    /// It does NOT validate boundary states, TRACE_ROOT, witness or proof soundness.
    /// Actual proof decoding and verification remain with the existing Rust owner.
    pub fn validate_claim_profile(
        &self, work: &EconomicWorkV1, claim: &StormClaim521V1, verification_key: &[u8],
    ) -> AuthorizationResultV2<()> {
        self.validate_work_profile(work)?;
        if !verification_key.is_empty() || claim.version != STORM_CLAIM_521_V1_VERSION
            || claim.modulus_id != STORM_MODULUS_ID_521_V1 || claim.iteration_count != self.iteration_count
            || claim.side_a != work.storm.side_a || claim.side_b != work.storm.side_b
            || claim.context_bytes_v1 != work.storm.context_bytes_v1
            || claim.legacy_commitment_root != [0; 32] || claim.legacy_trace_commitment != [0; 32]
        {
            return Err("unsupported miner claim profile or verification key".into());
        }
        Ok(())
    }

    /// A low reference is only an unverified submission filter, never valid PoW.
    /// Fixed-width lexicographic comparison is exactly unsigned big-endian <= T.
    pub fn passes_hash_filter(&self, proof_hash: &[u8]) -> AuthorizationResultV2<bool> {
        self.validate_shape()?;
        let hash: [u8; 32] = proof_hash.try_into()?;
        Ok(hash <= self.target)
    }
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn fixed<const N: usize>(&mut self) -> AuthorizationResultV2<[u8; N]> {
        let value = self.0.get(..N).ok_or("truncated miner job")?.try_into()?;
        self.0 = &self.0[N..];
        Ok(value)
    }
    fn u64(&mut self) -> AuthorizationResultV2<u64> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
}
