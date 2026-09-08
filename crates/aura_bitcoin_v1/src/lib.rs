//! Bitcoin anchor encoding. A valid anchor is publication evidence, not proof verification.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetworkV1 {
    Mainnet,
    Testnet3,
    Signet,
    Regtest,
    Testnet4,
}

impl BitcoinNetworkV1 {
    pub fn tag(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet3 => 1,
            Self::Signet => 2,
            Self::Regtest => 3,
            Self::Testnet4 => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, AnchorErrorV1> {
        match tag {
            0 => Ok(Self::Mainnet),
            1 => Ok(Self::Testnet3),
            2 => Ok(Self::Signet),
            3 => Ok(Self::Regtest),
            4 => Ok(Self::Testnet4),
            _ => Err(AnchorErrorV1("unknown Bitcoin network")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RequestFields")]
pub struct BitcoinAnchorRequestV1 {
    anchor_version: AnchorVersionV1,
    network: BitcoinNetworkV1,
    proof_hash_hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AnchorVersionV1 {
    V1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestFields {
    anchor_version: AnchorVersionV1,
    network: BitcoinNetworkV1,
    proof_hash_hex: String,
}

impl TryFrom<RequestFields> for BitcoinAnchorRequestV1 {
    type Error = AnchorErrorV1;
    fn try_from(fields: RequestFields) -> Result<Self, Self::Error> {
        let AnchorVersionV1::V1 = fields.anchor_version;
        Self::new(fields.network, fields.proof_hash_hex)
    }
}

impl BitcoinAnchorRequestV1 {
    pub fn new(network: BitcoinNetworkV1, proof_hash_hex: String) -> Result<Self, AnchorErrorV1> {
        if proof_hash_hex.len() != 64
            || !proof_hash_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(AnchorErrorV1(
                "proof_hash_hex must be canonical lowercase 64-hex",
            ));
        }
        Ok(Self {
            anchor_version: AnchorVersionV1::V1,
            network,
            proof_hash_hex,
        })
    }

    pub fn network(&self) -> BitcoinNetworkV1 {
        self.network
    }
    pub fn proof_hash_hex(&self) -> &str {
        &self.proof_hash_hex
    }

    pub fn script_pubkey(&self) -> [u8; 40] {
        let mut script = [0u8; 40];
        script[..8].copy_from_slice(&[0x6a, 38, b'A', b'U', b'R', b'A', 1, self.network.tag()]);
        for (i, pair) in self.proof_hash_hex.as_bytes().chunks_exact(2).enumerate() {
            script[8 + i] = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
        script
    }

    pub fn from_script(script: &[u8]) -> Result<Self, AnchorErrorV1> {
        if script.len() != 40 || script[..7] != [0x6a, 38, b'A', b'U', b'R', b'A', 1] {
            return Err(AnchorErrorV1("non-canonical Aura anchor script"));
        }
        let network = BitcoinNetworkV1::from_tag(script[7])?;
        let hash = script[8..].iter().map(|b| format!("{b:02x}")).collect();
        Self::new(network, hash)
    }
}

fn nibble(b: u8) -> u8 {
    if b.is_ascii_digit() {
        b - b'0'
    } else {
        b - b'a' + 10
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinOutputV1 {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}

/// Validate decoded transaction outputs against an expected Aura request.
/// Callers must obtain outputs from the actual transaction, not an unbound summary.
pub fn validate_anchor_outputs_v1(
    outputs: &[BitcoinOutputV1],
    expected: &BitcoinAnchorRequestV1,
) -> Result<usize, AnchorErrorV1> {
    let mut found = None;
    for (index, output) in outputs.iter().enumerate() {
        if !is_aura_candidate(&output.script_pubkey) {
            continue;
        }
        if found.is_some() {
            return Err(AnchorErrorV1("duplicate Aura anchor output"));
        }
        if output.value_sat != 0 {
            return Err(AnchorErrorV1("Aura output must have zero value"));
        }
        if BitcoinAnchorRequestV1::from_script(&output.script_pubkey)? != *expected {
            return Err(AnchorErrorV1(
                "Aura anchor does not match expected network and proof reference",
            ));
        }
        found = Some(index);
    }
    found.ok_or(AnchorErrorV1("missing Aura anchor output"))
}

// Recognize the namespace even with non-minimal pushdata, so a malformed second
// Aura output cannot hide beside the canonical output. Canonical decoding rejects it.
fn is_aura_candidate(script: &[u8]) -> bool {
    if script.first() != Some(&0x6a) {
        return false;
    }
    let offset = match script.get(1) {
        Some(1..=75) => 2,
        Some(0x4c) => 3,
        Some(0x4d) => 4,
        Some(0x4e) => 6,
        _ => return false,
    };
    script.get(offset..offset + 4) == Some(b"AURA")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorErrorV1(pub &'static str);
impl fmt::Display for AnchorErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AnchorErrorV1 {}
