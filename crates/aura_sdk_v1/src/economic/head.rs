//! Economic head V2. Linkage is derived from the validated durable predecessor.
use super::*;
use aura_l2_local_chain_v0::{
    economic_meter::economic_ledger_commitment_v1, CanonicalPipelineLedgerPolicyV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EconomicOutcomeV1 {
    Accepted = 0,
    ExecutionRejected = 1,
    VerificationRejected = 2,
    SettlementRejected = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicHeadV2 {
    pub settlement_head_version: u32,
    pub head_sequence_number: String,
    pub previous_head_hash_hex: String,
    pub canonical_head_commitment_hex: String,
    pub current_head_hash_hex: String,
}

pub fn canonical_sequence_v2(text: &str) -> AuthorizationResultV2<u64> {
    if text.is_empty()
        || !text.bytes().all(|c| c.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("noncanonical economic head sequence".into());
    }
    Ok(text.parse()?)
}

fn head_hash(sequence: u64, commitment: [u8; 32]) -> String {
    let mut bytes = b"AURA_ECONOMIC_HEAD_V1".to_vec();
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&commitment);
    sha256_hex(&bytes)
}

impl EconomicHeadV2 {
    /// Only explicit journal initialization may pin this as durable genesis.
    pub fn genesis() -> Self {
        Self {
            settlement_head_version: 2,
            head_sequence_number: "0".into(),
            previous_head_hash_hex: "00".repeat(32),
            canonical_head_commitment_hex: "00".repeat(32),
            current_head_hash_hex: "00".repeat(32),
        }
    }

    pub fn validate(&self) -> AuthorizationResultV2<u64> {
        if self.settlement_head_version != 2 {
            return Err("unsupported economic head version".into());
        }
        let n = canonical_sequence_v2(&self.head_sequence_number)?;
        let previous = decode_hex_v2::<32>(&self.previous_head_hash_hex)?;
        let c = decode_hex_v2::<32>(&self.canonical_head_commitment_hex)?;
        let current = decode_hex_v2::<32>(&self.current_head_hash_hex)?;
        if n == 0 {
            if previous != [0; 32] || c != [0; 32] || current != [0; 32] {
                return Err("invalid economic genesis".into());
            }
        } else if head_hash(n, c) != self.current_head_hash_hex {
            return Err("economic head hash mismatch".into());
        }
        Ok(n)
    }

    pub fn advance(
        &self,
        network: BitcoinNetworkV1,
        work: &EconomicWorkV1,
        outcome: EconomicOutcomeV1,
        post_debit_ledger: &CanonicalPipelineLedgerPolicyV1,
    ) -> AuthorizationResultV2<Self> {
        Self::from_predecessor(
            self.validate()?,
            decode_hex_v2(&self.current_head_hash_hex)?,
            network,
            work,
            outcome,
            post_debit_ledger,
        )
    }

    // Also used after explicit migration of a trusted V1 checkpoint. Such an
    // import is outside canonical admission; never fabricate/relabel a V2 head.
    pub(super) fn from_predecessor(
        prior_sequence: u64,
        prior_hash: [u8; 32],
        network: BitcoinNetworkV1,
        work: &EconomicWorkV1,
        outcome: EconomicOutcomeV1,
        post_debit_ledger: &CanonicalPipelineLedgerPolicyV1,
    ) -> AuthorizationResultV2<Self> {
        let n = prior_sequence
            .checked_add(1)
            .ok_or("economic head sequence overflow")?;
        let linkage = &work.meter.head;
        if linkage.settlement_head_version != 2
            || linkage.head_sequence_number != n
            || linkage.previous_head_hash != prior_hash
        {
            return Err("metered head linkage does not match durable predecessor".into());
        }
        let work_bytes = work.canonical_bytes()?;
        let burn = work.burn_units()?;
        let expected_post = aura_l2_local_chain_v0::economic_meter::debit_economic_ledger_v1(
            &work.meter.ledger,
            burn,
        )?;
        if &expected_post != post_debit_ledger {
            return Err("economic post-debit ledger mismatch".into());
        }
        let pre = economic_ledger_commitment_v1(&work.meter.ledger)?;
        let post = economic_ledger_commitment_v1(post_debit_ledger)?;
        let mut bytes = b"AURA_ECONOMIC_HEAD_COMMITMENT_V1".to_vec();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.push(network.tag());
        bytes.extend_from_slice(&prior_hash);
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.extend_from_slice(&u64::try_from(work_bytes.len())?.to_le_bytes());
        bytes.extend_from_slice(&work_bytes);
        bytes.push(outcome as u8);
        bytes.extend_from_slice(&pre);
        bytes.extend_from_slice(&post);
        bytes.extend_from_slice(&burn.to_le_bytes());
        let commitment = sha256_hex(&bytes);
        Ok(Self {
            settlement_head_version: 2,
            head_sequence_number: n.to_string(),
            previous_head_hash_hex: encode_hex_v2(&prior_hash),
            current_head_hash_hex: head_hash(n, decode_hex_v2(&commitment)?),
            canonical_head_commitment_hex: commitment,
        })
    }
}
