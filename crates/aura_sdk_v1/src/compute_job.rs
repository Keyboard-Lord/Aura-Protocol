//! C1 compute request codec/profile only. No admission, funding, result verdict,
//! journal mutation, burn, Head V2 advance, or proof authorization.
use crate::miner::MinerJobV1;
use aura_bitcoin_v1::BitcoinNetworkV1;
use secp256k1::{schnorr::Signature, Keypair, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub type ComputeJobResultV1<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const COMPUTE_JOB_V1_BYTE_LEN: usize = 546;
const DOMAIN: &[u8] = b"AURA_COMPUTE_JOB_V1";

/// One binary representation; deliberately no serde/JSON wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraComputeJobV1 {
    pub job_version: u8,
    pub network: BitcoinNetworkV1,
    pub coordinator_key: [u8; 32],
    pub journal_namespace: [u8; 32],
    pub requester_key: [u8; 32],
    pub job_nonce: [u8; 32],
    pub workload_class: u16,
    pub adapter_contract_commitment: [u8; 32],
    pub input_commitment: [u8; 32],
    pub program_commitment: [u8; 32],
    pub execution_spec_commitment: [u8; 32],
    pub output_spec_commitment: [u8; 32],
    pub verification_class: u8,
    pub verification_spec_commitment: [u8; 32],
    pub privacy_class: u8,
    pub privacy_policy_commitment: [u8; 32],
    pub hardware_requirements_commitment: [u8; 32],
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_scratch_bytes: u64,
    pub max_execution_ms: u64,
    pub accept_until: u64,
    pub complete_by: u64,
    pub compensation_satoshis: u64,
    pub payment_terms_commitment: [u8; 32],
    pub data_rights_commitment: [u8; 32],
    pub mining_mode: u8,
}

/// Trusted local identity, not inferred from the incoming request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeCoordinatorV1 {
    pub network: BitcoinNetworkV1,
    pub coordinator_key: [u8; 32],
    pub journal_namespace: [u8; 32],
}
/// Local caps, not another canonical job representation.
#[derive(Clone, Debug)]
pub struct ComputeJobLimitsV1 {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_scratch_bytes: u64,
    pub max_execution_ms: u64,
}

/// Pure comparison of authenticated requests; no replay state is reserved here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeRetryV1 {
    DistinctScope,
    Idempotent,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeContentKindV1 {
    AdapterContract,
    Input,
    Program,
    ExecutionSpec,
    OutputSpec,
    VerificationSpec,
    PrivacyPolicy,
    HardwareRequirements,
    PaymentTerms,
    DataRights,
}
impl ComputeContentKindV1 {
    pub const ALL: [Self; 10] = [
        Self::AdapterContract,
        Self::Input,
        Self::Program,
        Self::ExecutionSpec,
        Self::OutputSpec,
        Self::VerificationSpec,
        Self::PrivacyPolicy,
        Self::HardwareRequirements,
        Self::PaymentTerms,
        Self::DataRights,
    ];
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::AdapterContract => b"AURA_COMPUTE_ADAPTER_CONTRACT_V1",
            Self::Input => b"AURA_COMPUTE_INPUT_V1",
            Self::Program => b"AURA_COMPUTE_PROGRAM_V1",
            Self::ExecutionSpec => b"AURA_COMPUTE_EXECUTION_SPEC_V1",
            Self::OutputSpec => b"AURA_COMPUTE_OUTPUT_SPEC_V1",
            Self::VerificationSpec => b"AURA_COMPUTE_VERIFICATION_SPEC_V1",
            Self::PrivacyPolicy => b"AURA_COMPUTE_PRIVACY_POLICY_V1",
            Self::HardwareRequirements => b"AURA_COMPUTE_HARDWARE_REQUIREMENTS_V1",
            Self::PaymentTerms => b"AURA_COMPUTE_PAYMENT_TERMS_V1",
            Self::DataRights => b"AURA_COMPUTE_DATA_RIGHTS_V1",
        }
    }
}
/// Commits exact payload bytes. Does not establish supported contract semantics.
pub fn compute_content_commitment_v1(
    kind: ComputeContentKindV1,
    payload: &[u8],
) -> ComputeJobResultV1<[u8; 32]> {
    content_digest(kind.domain(), payload)
}
// Shared compute content framing; callers own their disjoint domain registries.
pub(crate) fn content_digest(domain: &[u8], payload: &[u8]) -> ComputeJobResultV1<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(u64::try_from(payload.len())?.to_le_bytes());
    h.update(payload);
    Ok(h.finalize().into())
}

/// The three fixed C1-P1 payloads share a byte, not a commitment domain.
pub fn compute_fixed_core_policy_payload_v1(
    kind: ComputeContentKindV1,
) -> ComputeJobResultV1<[u8; 1]> {
    match kind {
        ComputeContentKindV1::PrivacyPolicy
        | ComputeContentKindV1::HardwareRequirements
        | ComputeContentKindV1::DataRights => Ok([1]),
        _ => Err("not a fixed compute core policy kind".into()),
    }
}

pub fn validate_compute_fixed_core_policy_v1(
    kind: ComputeContentKindV1,
    payload: &[u8],
) -> ComputeJobResultV1<()> {
    if payload != compute_fixed_core_policy_payload_v1(kind)? {
        return Err("unsupported or noncanonical compute core policy".into());
    }
    Ok(())
}

pub const COMPUTE_PAYMENT_TERMS_V1_BYTE_LEN: usize = 17;

/// Profile 01: exact net-worker-payment terms; no transport or lifecycle state.
/// The fixed profile marker belongs to the wire, not an optional/default field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputePaymentTermsV1 {
    pub max_payment_fee_satoshis: u64,
    pub result_availability_seconds: u64,
}
impl ComputePaymentTermsV1 {
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<[u8; 17]> {
        if self.result_availability_seconds == 0 {
            return Err("compute result availability must be positive".into());
        }
        let mut bytes = [0; 17];
        bytes[0] = 1;
        bytes[1..9].copy_from_slice(&self.max_payment_fee_satoshis.to_le_bytes());
        bytes[9..17].copy_from_slice(&self.result_availability_seconds.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> ComputeJobResultV1<Self> {
        if bytes.len() != COMPUTE_PAYMENT_TERMS_V1_BYTE_LEN || bytes[0] != 1 {
            return Err("invalid compute payment terms framing/profile".into());
        }
        let terms = Self {
            max_payment_fee_satoshis: u64::from_le_bytes(bytes[1..9].try_into()?),
            result_availability_seconds: u64::from_le_bytes(bytes[9..17].try_into()?),
        };
        if terms.canonical_bytes()? != bytes {
            return Err("noncanonical compute payment terms".into());
        }
        Ok(terms)
    }
    pub fn commitment(&self) -> ComputeJobResultV1<[u8; 32]> {
        compute_content_commitment_v1(ComputeContentKindV1::PaymentTerms, &self.canonical_bytes()?)
    }
    /// A zero ceiling permits exactly zero. Never subtract this fee from net pay.
    pub fn validate_publication_fee(&self, fee_satoshis: u64) -> ComputeJobResultV1<()> {
        self.canonical_bytes()?;
        if fee_satoshis > self.max_payment_fee_satoshis {
            return Err("compute payment fee exceeds signed ceiling".into());
        }
        Ok(())
    }
}
impl AuraComputeJobV1 {
    pub fn validate_shape(&self) -> ComputeJobResultV1<()> {
        if self.job_version != 1
            || self.workload_class > 10
            || self.verification_class > 7
            || self.privacy_class > 4
            || self.mining_mode > 1
        {
            return Err("unsupported compute job version/class/mode".into());
        }
        XOnlyPublicKey::from_byte_array(self.coordinator_key)?;
        XOnlyPublicKey::from_byte_array(self.requester_key)?;
        if self.max_output_bytes == 0
            || self.max_evidence_bytes == 0
            || self.max_memory_bytes == 0
            || self.max_execution_ms == 0
            || self.accept_until == 0
            || self.accept_until >= self.complete_by
            || self.compensation_satoshis == 0
        {
            return Err("invalid compute limits/deadline/compensation".into());
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<Vec<u8>> {
        self.validate_shape()?;
        let mut b = Vec::with_capacity(COMPUTE_JOB_V1_BYTE_LEN);
        b.extend_from_slice(DOMAIN);
        b.extend_from_slice(&[self.job_version]);
        b.extend_from_slice(&[self.network.tag()]);
        b.extend_from_slice(&self.coordinator_key);
        b.extend_from_slice(&self.journal_namespace);
        b.extend_from_slice(&self.requester_key);
        b.extend_from_slice(&self.job_nonce);
        b.extend_from_slice(&self.workload_class.to_le_bytes());
        b.extend_from_slice(&self.adapter_contract_commitment);
        b.extend_from_slice(&self.input_commitment);
        b.extend_from_slice(&self.program_commitment);
        b.extend_from_slice(&self.execution_spec_commitment);
        b.extend_from_slice(&self.output_spec_commitment);
        b.extend_from_slice(&[self.verification_class]);
        b.extend_from_slice(&self.verification_spec_commitment);
        b.extend_from_slice(&[self.privacy_class]);
        b.extend_from_slice(&self.privacy_policy_commitment);
        b.extend_from_slice(&self.hardware_requirements_commitment);
        b.extend_from_slice(&self.max_input_bytes.to_le_bytes());
        b.extend_from_slice(&self.max_output_bytes.to_le_bytes());
        b.extend_from_slice(&self.max_evidence_bytes.to_le_bytes());
        b.extend_from_slice(&self.max_memory_bytes.to_le_bytes());
        b.extend_from_slice(&self.max_scratch_bytes.to_le_bytes());
        b.extend_from_slice(&self.max_execution_ms.to_le_bytes());
        b.extend_from_slice(&self.accept_until.to_le_bytes());
        b.extend_from_slice(&self.complete_by.to_le_bytes());
        b.extend_from_slice(&self.compensation_satoshis.to_le_bytes());
        b.extend_from_slice(&self.payment_terms_commitment);
        b.extend_from_slice(&self.data_rights_commitment);
        b.extend_from_slice(&[self.mining_mode]);
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> ComputeJobResultV1<Self> {
        if bytes.len() != COMPUTE_JOB_V1_BYTE_LEN || !bytes.starts_with(DOMAIN) {
            return Err("invalid compute job framing".into());
        }
        let mut r = Reader(&bytes[DOMAIN.len()..]);
        let job = Self {
            job_version: r.fixed::<1>()?[0],
            network: r.network()?,
            coordinator_key: r.fixed()?,
            journal_namespace: r.fixed()?,
            requester_key: r.fixed()?,
            job_nonce: r.fixed()?,
            workload_class: u16::from_le_bytes(r.fixed()?),
            adapter_contract_commitment: r.fixed()?,
            input_commitment: r.fixed()?,
            program_commitment: r.fixed()?,
            execution_spec_commitment: r.fixed()?,
            output_spec_commitment: r.fixed()?,
            verification_class: r.fixed::<1>()?[0],
            verification_spec_commitment: r.fixed()?,
            privacy_class: r.fixed::<1>()?[0],
            privacy_policy_commitment: r.fixed()?,
            hardware_requirements_commitment: r.fixed()?,
            max_input_bytes: u64::from_le_bytes(r.fixed()?),
            max_output_bytes: u64::from_le_bytes(r.fixed()?),
            max_evidence_bytes: u64::from_le_bytes(r.fixed()?),
            max_memory_bytes: u64::from_le_bytes(r.fixed()?),
            max_scratch_bytes: u64::from_le_bytes(r.fixed()?),
            max_execution_ms: u64::from_le_bytes(r.fixed()?),
            accept_until: u64::from_le_bytes(r.fixed()?),
            complete_by: u64::from_le_bytes(r.fixed()?),
            compensation_satoshis: u64::from_le_bytes(r.fixed()?),
            payment_terms_commitment: r.fixed()?,
            data_rights_commitment: r.fixed()?,
            mining_mode: r.fixed::<1>()?[0],
        };
        if !r.0.is_empty() || job.canonical_bytes()? != bytes {
            return Err("noncanonical compute job".into());
        }
        Ok(job)
    }
    pub fn commitment(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
    pub fn signing_digest(&self) -> ComputeJobResultV1<[u8; 32]> {
        let tag = Sha256::digest(b"AURA_COMPUTE_JOB_SIGNATURE_V1");
        let mut h = Sha256::new();
        h.update(tag);
        h.update(tag);
        h.update(self.canonical_bytes()?);
        Ok(h.finalize().into())
    }
    /// Fresh BIP340 signing randomness; this is not the public job/mining nonce.
    pub fn sign_request(&self, key: &Keypair) -> ComputeJobResultV1<[u8; 64]> {
        if key.x_only_public_key().0.serialize() != self.requester_key {
            return Err("compute requester mismatch".into());
        }
        let aux = crate::authorization::fresh_nonce_v2()?;
        Ok(Secp256k1::new()
            .sign_schnorr_with_aux_rand(&self.signing_digest()?, key, &aux)
            .to_byte_array())
    }
    pub fn verify_request(&self, signature: &[u8]) -> ComputeJobResultV1<()> {
        let sig = Signature::from_byte_array(signature.try_into()?);
        Secp256k1::verification_only().verify_schnorr(
            &sig,
            &self.signing_digest()?,
            &XOnlyPublicKey::from_byte_array(self.requester_key)?,
        )?;
        Ok(())
    }
    pub fn verify_for_coordinator(
        &self,
        signature: &[u8],
        trusted: &ComputeCoordinatorV1,
    ) -> ComputeJobResultV1<()> {
        if self.network != trusted.network
            || self.coordinator_key != trusted.coordinator_key
            || self.journal_namespace != trusted.journal_namespace
        {
            return Err("compute coordinator scope mismatch".into());
        }
        self.verify_request(signature)
    }
    /// Existing must be an authenticated stored request. Signature authentication
    /// of incoming precedes comparison; live expiry is deliberately not re-applied.
    pub fn classify_retry(
        &self,
        incoming: &Self,
        signature: &[u8],
    ) -> ComputeJobResultV1<ComputeRetryV1> {
        self.validate_shape()?;
        incoming.verify_request(signature)?;
        if self.network != incoming.network
            || self.coordinator_key != incoming.coordinator_key
            || self.journal_namespace != incoming.journal_namespace
            || self.requester_key != incoming.requester_key
            || self.job_nonce != incoming.job_nonce
        {
            return Ok(ComputeRetryV1::DistinctScope);
        }
        Ok(if self.canonical_bytes()? == incoming.canonical_bytes()? {
            ComputeRetryV1::Idempotent
        } else {
            ComputeRetryV1::Conflict
        })
    }
    /// New assignment preflight only. Support, funding, receipt timing and actual
    /// resource enforcement are separate coordinator/adapter obligations.
    pub fn validate_new_assignment(
        &self,
        now: u64,
        delivery_budget_ms: u64,
        host: &ComputeJobLimitsV1,
    ) -> ComputeJobResultV1<()> {
        self.validate_shape()?;
        if now >= self.accept_until {
            return Err("compute assignment deadline elapsed".into());
        }
        if self.max_input_bytes > host.max_input_bytes {
            return Err("compute host limit exceeded".into());
        }
        if self.max_output_bytes > host.max_output_bytes {
            return Err("compute host limit exceeded".into());
        }
        if self.max_evidence_bytes > host.max_evidence_bytes {
            return Err("compute host limit exceeded".into());
        }
        if self.max_memory_bytes > host.max_memory_bytes {
            return Err("compute host limit exceeded".into());
        }
        if self.max_scratch_bytes > host.max_scratch_bytes {
            return Err("compute host limit exceeded".into());
        }
        if self.max_execution_ms > host.max_execution_ms {
            return Err("compute host limit exceeded".into());
        }
        // Exact wide arithmetic; receipt must be strictly before complete_by.
        let budget = u128::from(self.max_execution_ms) + u128::from(delivery_budget_ms);
        if budget >= u128::from(self.complete_by - now) * 1000 {
            return Err("insufficient compute completion window".into());
        }
        Ok(())
    }
    /// Checks bytes against the job commitment, not support or policy meaning.
    pub fn verify_content(
        &self,
        kind: ComputeContentKindV1,
        payload: &[u8],
    ) -> ComputeJobResultV1<()> {
        self.validate_shape()?;
        if kind == ComputeContentKindV1::Input
            && u64::try_from(payload.len())? > self.max_input_bytes
        {
            return Err("input exceeds compute limit".into());
        }
        let expected = match kind {
            ComputeContentKindV1::AdapterContract => self.adapter_contract_commitment,
            ComputeContentKindV1::Input => self.input_commitment,
            ComputeContentKindV1::Program => self.program_commitment,
            ComputeContentKindV1::ExecutionSpec => self.execution_spec_commitment,
            ComputeContentKindV1::OutputSpec => self.output_spec_commitment,
            ComputeContentKindV1::VerificationSpec => self.verification_spec_commitment,
            ComputeContentKindV1::PrivacyPolicy => self.privacy_policy_commitment,
            ComputeContentKindV1::HardwareRequirements => self.hardware_requirements_commitment,
            ComputeContentKindV1::PaymentTerms => self.payment_terms_commitment,
            ComputeContentKindV1::DataRights => self.data_rights_commitment,
        };
        if compute_content_commitment_v1(kind, payload)? != expected {
            return Err("compute content commitment mismatch".into());
        }
        Ok(())
    }
    /// Checks the four approved core schemas and their job commitments. This is
    /// not adapter support, measured hardware, isolation enforcement, funding,
    /// result acceptance or a durable coordinator transaction.
    pub fn verify_core_policies(
        &self,
        privacy: &[u8],
        hardware: &[u8],
        rights: &[u8],
        payment: &[u8],
    ) -> ComputeJobResultV1<ComputePaymentTermsV1> {
        self.validate_shape()?;
        if self.privacy_class > 1 {
            return Err("compute privacy class is not supported by profile 01".into());
        }
        for (kind, payload) in [
            (ComputeContentKindV1::PrivacyPolicy, privacy),
            (ComputeContentKindV1::HardwareRequirements, hardware),
            (ComputeContentKindV1::DataRights, rights),
        ] {
            validate_compute_fixed_core_policy_v1(kind, payload)?;
            self.verify_content(kind, payload)?;
        }
        let terms = ComputePaymentTermsV1::decode(payment)?;
        self.verify_content(ComputeContentKindV1::PaymentTerms, payment)?;
        Ok(terms)
    }
    /// Structural association only: R must independently resolve to this job's
    /// verified result. This method cannot manufacture that C2 verification.
    pub fn validate_miner_binding(
        &self,
        miner: &MinerJobV1,
        result: &[u8; 32],
    ) -> ComputeJobResultV1<()> {
        self.validate_shape()?;
        miner.validate_shape()?;
        if self.mining_mode != 1 {
            return Err("compute mining mode disabled".into());
        }
        if miner.side_a != compute_miner_side_v1(result, 0)?
            || miner.side_b != compute_miner_side_v1(result, 1)?
        {
            return Err("compute result is not bound by signed miner inputs".into());
        }
        Ok(())
    }
}
/// The approved four-block expansion, with no alternative lanes or encodings.
pub fn compute_miner_side_v1(result: &[u8; 32], lane: u8) -> ComputeJobResultV1<[u8; 110]> {
    if lane > 1 {
        return Err("invalid compute miner side lane".into());
    }
    let mut expanded = [0u8; 128];
    for i in 0u32..4 {
        let mut h = Sha256::new();
        h.update(b"AURA_COMPUTE_MINER_SIDE_V1");
        h.update([lane]);
        h.update(result);
        h.update(i.to_le_bytes());
        expanded[i as usize * 32..(i as usize + 1) * 32].copy_from_slice(&h.finalize());
    }
    Ok(expanded[..110].try_into()?)
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn fixed<const N: usize>(&mut self) -> ComputeJobResultV1<[u8; N]> {
        if self.0.len() < N {
            return Err("truncated compute job".into());
        }
        let value = self.0[..N].try_into()?;
        self.0 = &self.0[N..];
        Ok(value)
    }
    fn network(&mut self) -> ComputeJobResultV1<BitcoinNetworkV1> {
        let tag = self.fixed::<1>()?[0];
        [
            BitcoinNetworkV1::Mainnet,
            BitcoinNetworkV1::Testnet3,
            BitcoinNetworkV1::Signet,
            BitcoinNetworkV1::Regtest,
            BitcoinNetworkV1::Testnet4,
        ]
        .into_iter()
        .find(|n| n.tag() == tag)
        .ok_or_else(|| "unknown compute Bitcoin network".into())
    }
}
