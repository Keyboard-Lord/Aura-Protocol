//! Approved C2 lifecycle objects. Encoding/signature validity is not a verifier verdict.
use crate::compute_job::{AuraComputeJobV1, ComputeJobResultV1};
use secp256k1::{schnorr::Signature, Keypair, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub const COMPUTE_ASSIGNMENT_V1_BYTE_LEN: usize = 91;
pub const COMPUTE_RECEIPT_V1_BYTE_LEN: usize = 152;
pub const COMPUTE_RESULT_V1_BYTE_LEN: usize = 56;
pub const COMPUTE_CANCEL_V1_BYTE_LEN: usize = 55;
pub const COMPUTE_RESOURCE_ACCOUNTING_V1_BYTE_LEN: usize = 25;

fn frame(domain: &[u8], version: u8, fields: &[&[u8]]) -> ComputeJobResultV1<Vec<u8>> {
    if version != 1 {
        return Err("unsupported compute lifecycle version".into());
    }
    let mut b = domain.to_vec();
    b.push(version);
    for f in fields {
        b.extend_from_slice(f);
    }
    Ok(b)
}
fn payload<'a>(b: &'a [u8], domain: &[u8], len: usize) -> ComputeJobResultV1<&'a [u8]> {
    if b.len() != len || !b.starts_with(domain) || b[domain.len()] != 1 {
        return Err("noncanonical compute lifecycle framing".into());
    }
    Ok(&b[domain.len() + 1..])
}
fn tagged(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(bytes);
    h.finalize().into()
}
fn verify(key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> ComputeJobResultV1<()> {
    Secp256k1::verification_only().verify_schnorr(
        &Signature::from_byte_array(*signature),
        digest,
        &XOnlyPublicKey::from_byte_array(*key)?,
    )?;
    Ok(())
}
fn sign(key: &Keypair, expected: &[u8; 32], digest: &[u8; 32]) -> ComputeJobResultV1<[u8; 64]> {
    if key.x_only_public_key().0.serialize() != *expected {
        return Err("compute signing identity mismatch".into());
    }
    Ok(*Secp256k1::new()
        .sign_schnorr_with_aux_rand(digest, key, &crate::authorization::fresh_nonce_v2()?)
        .as_ref())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeAssignmentV1 {
    pub version: u8,
    pub compute_job_commitment: [u8; 32],
    pub worker_key: [u8; 32],
}
impl ComputeAssignmentV1 {
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<Vec<u8>> {
        XOnlyPublicKey::from_byte_array(self.worker_key)?;
        frame(
            b"AURA_COMPUTE_ASSIGNMENT_V1",
            self.version,
            &[&self.compute_job_commitment, &self.worker_key],
        )
    }
    pub fn decode(b: &[u8]) -> ComputeJobResultV1<Self> {
        let p = payload(
            b,
            b"AURA_COMPUTE_ASSIGNMENT_V1",
            COMPUTE_ASSIGNMENT_V1_BYTE_LEN,
        )?;
        let x = Self {
            version: 1,
            compute_job_commitment: p[..32].try_into()?,
            worker_key: p[32..].try_into()?,
        };
        x.canonical_bytes()?;
        Ok(x)
    }
    pub fn commitment(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
    pub fn worker_digest(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(tagged(
            b"AURA_COMPUTE_ASSIGN_WORKER_V1",
            &self.canonical_bytes()?,
        ))
    }
    pub fn coordinator_digest(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(tagged(
            b"AURA_COMPUTE_ASSIGN_COORDINATOR_V1",
            &self.canonical_bytes()?,
        ))
    }
    pub fn verify_job(&self, j: &AuraComputeJobV1) -> ComputeJobResultV1<()> {
        self.canonical_bytes()?;
        if self.compute_job_commitment != j.commitment()? {
            return Err("assignment job mismatch".into());
        }
        Ok(())
    }
    pub fn verify_worker(&self, s: &[u8; 64]) -> ComputeJobResultV1<()> {
        verify(&self.worker_key, &self.worker_digest()?, s)
    }
    pub fn sign_worker(&self, k: &Keypair) -> ComputeJobResultV1<[u8; 64]> {
        sign(k, &self.worker_key, &self.worker_digest()?)
    }
    pub fn verify_coordinator(&self, j: &AuraComputeJobV1, s: &[u8; 64]) -> ComputeJobResultV1<()> {
        self.verify_job(j)?;
        verify(&j.coordinator_key, &self.coordinator_digest()?, s)
    }
    pub fn sign_coordinator(
        &self,
        j: &AuraComputeJobV1,
        k: &Keypair,
    ) -> ComputeJobResultV1<[u8; 64]> {
        self.verify_job(j)?;
        sign(k, &j.coordinator_key, &self.coordinator_digest()?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeResultContentKindV1 {
    Output,
    ExecutionEvidence,
    ResourceAccounting,
}
impl ComputeResultContentKindV1 {
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::Output => b"AURA_COMPUTE_OUTPUT_V1",
            Self::ExecutionEvidence => b"AURA_COMPUTE_EXECUTION_EVIDENCE_V1",
            Self::ResourceAccounting => b"AURA_COMPUTE_RESOURCE_ACCOUNTING_V1",
        }
    }
}
pub fn compute_result_content_commitment_v1(
    k: ComputeResultContentKindV1,
    b: &[u8],
) -> ComputeJobResultV1<[u8; 32]> {
    crate::compute_job::content_digest(k.domain(), b)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeResourceAccountingV1 {
    pub version: u8,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub evidence_bytes: u64,
}
impl ComputeResourceAccountingV1 {
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<Vec<u8>> {
        frame(
            b"",
            self.version,
            &[
                &self.input_bytes.to_le_bytes(),
                &self.output_bytes.to_le_bytes(),
                &self.evidence_bytes.to_le_bytes(),
            ],
        )
    }
    pub fn decode(b: &[u8]) -> ComputeJobResultV1<Self> {
        let p = payload(b, b"", COMPUTE_RESOURCE_ACCOUNTING_V1_BYTE_LEN)?;
        Ok(Self {
            version: 1,
            input_bytes: u64::from_le_bytes(p[..8].try_into()?),
            output_bytes: u64::from_le_bytes(p[8..16].try_into()?),
            evidence_bytes: u64::from_le_bytes(p[16..].try_into()?),
        })
    }
    pub fn commitment(&self) -> ComputeJobResultV1<[u8; 32]> {
        compute_result_content_commitment_v1(
            ComputeResultContentKindV1::ResourceAccounting,
            &self.canonical_bytes()?,
        )
    }
    pub fn validate(
        &self,
        j: &AuraComputeJobV1,
        input: &[u8],
        output: &[u8],
        evidence: &[u8],
    ) -> ComputeJobResultV1<()> {
        self.canonical_bytes()?;
        j.verify_content(crate::compute_job::ComputeContentKindV1::Input, input)?;
        if self.input_bytes != u64::try_from(input.len())?
            || self.output_bytes != u64::try_from(output.len())?
            || self.evidence_bytes != u64::try_from(evidence.len())?
            || self.output_bytes > j.max_output_bytes
            || self.evidence_bytes > j.max_evidence_bytes
        {
            return Err("compute resource accounting mismatch or limit".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeReceiptV1 {
    pub version: u8,
    pub assignment_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub execution_evidence_commitment: [u8; 32],
    pub resource_accounting_commitment: [u8; 32],
}
impl ComputeReceiptV1 {
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<Vec<u8>> {
        frame(
            b"AURA_COMPUTE_RECEIPT_V1",
            self.version,
            &[
                &self.assignment_commitment,
                &self.output_commitment,
                &self.execution_evidence_commitment,
                &self.resource_accounting_commitment,
            ],
        )
    }
    pub fn decode(b: &[u8]) -> ComputeJobResultV1<Self> {
        let p = payload(b, b"AURA_COMPUTE_RECEIPT_V1", COMPUTE_RECEIPT_V1_BYTE_LEN)?;
        Ok(Self {
            version: 1,
            assignment_commitment: p[..32].try_into()?,
            output_commitment: p[32..64].try_into()?,
            execution_evidence_commitment: p[64..96].try_into()?,
            resource_accounting_commitment: p[96..].try_into()?,
        })
    }
    pub fn commitment(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
    pub fn signing_digest(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(tagged(
            b"AURA_COMPUTE_RECEIPT_SIGNATURE_V1",
            &self.canonical_bytes()?,
        ))
    }
    pub fn verify_assignment(&self, a: &ComputeAssignmentV1) -> ComputeJobResultV1<()> {
        if self.assignment_commitment != a.commitment()? {
            return Err("receipt assignment mismatch".into());
        }
        Ok(())
    }
    pub fn verify_signature(
        &self,
        a: &ComputeAssignmentV1,
        s: &[u8; 64],
    ) -> ComputeJobResultV1<()> {
        self.verify_assignment(a)?;
        verify(&a.worker_key, &self.signing_digest()?, s)
    }
    pub fn sign(&self, a: &ComputeAssignmentV1, k: &Keypair) -> ComputeJobResultV1<[u8; 64]> {
        self.verify_assignment(a)?;
        sign(k, &a.worker_key, &self.signing_digest()?)
    }
    pub fn verify_content(
        &self,
        j: &AuraComputeJobV1,
        r: &ComputeResourceAccountingV1,
        input: &[u8],
        output: &[u8],
        evidence: &[u8],
    ) -> ComputeJobResultV1<()> {
        self.canonical_bytes()?;
        r.validate(j, input, output, evidence)?;
        if self.output_commitment
            != compute_result_content_commitment_v1(ComputeResultContentKindV1::Output, output)?
            || self.execution_evidence_commitment
                != compute_result_content_commitment_v1(
                    ComputeResultContentKindV1::ExecutionEvidence,
                    evidence,
                )?
            || self.resource_accounting_commitment != r.commitment()?
        {
            return Err("receipt content mismatch".into());
        }
        Ok(())
    }
}
/// Structurally accepted verdict only. Construction does not confer coordinator acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedComputeResultV1 {
    pub version: u8,
    pub receipt_commitment: [u8; 32],
    pub verification_verdict: u8,
}
impl VerifiedComputeResultV1 {
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<Vec<u8>> {
        if self.verification_verdict != 1 {
            return Err("not a verified compute verdict".into());
        }
        frame(
            b"AURA_COMPUTE_RESULT_V1",
            self.version,
            &[&self.receipt_commitment, &[self.verification_verdict]],
        )
    }
    pub fn decode(b: &[u8]) -> ComputeJobResultV1<Self> {
        let p = payload(b, b"AURA_COMPUTE_RESULT_V1", COMPUTE_RESULT_V1_BYTE_LEN)?;
        let x = Self {
            version: 1,
            receipt_commitment: p[..32].try_into()?,
            verification_verdict: p[32],
        };
        x.canonical_bytes()?;
        Ok(x)
    }
    pub fn commitment(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
    pub fn signing_digest(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(tagged(
            b"AURA_COMPUTE_RESULT_SIGNATURE_V1",
            &self.canonical_bytes()?,
        ))
    }
    pub fn verify_lineage(
        &self,
        j: &AuraComputeJobV1,
        a: &ComputeAssignmentV1,
        r: &ComputeReceiptV1,
    ) -> ComputeJobResultV1<()> {
        a.verify_job(j)?;
        r.verify_assignment(a)?;
        if self.receipt_commitment != r.commitment()? {
            return Err("result receipt mismatch".into());
        }
        self.canonical_bytes()?;
        Ok(())
    }
    pub fn verify_signature(
        &self,
        j: &AuraComputeJobV1,
        a: &ComputeAssignmentV1,
        r: &ComputeReceiptV1,
        s: &[u8; 64],
    ) -> ComputeJobResultV1<()> {
        self.verify_lineage(j, a, r)?;
        verify(&j.coordinator_key, &self.signing_digest()?, s)
    }
    pub fn sign(
        &self,
        j: &AuraComputeJobV1,
        a: &ComputeAssignmentV1,
        r: &ComputeReceiptV1,
        k: &Keypair,
    ) -> ComputeJobResultV1<[u8; 64]> {
        self.verify_lineage(j, a, r)?;
        sign(k, &j.coordinator_key, &self.signing_digest()?)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeCancelV1 {
    pub version: u8,
    pub compute_job_commitment: [u8; 32],
}
impl ComputeCancelV1 {
    pub fn canonical_bytes(&self) -> ComputeJobResultV1<Vec<u8>> {
        frame(
            b"AURA_COMPUTE_CANCEL_V1",
            self.version,
            &[&self.compute_job_commitment],
        )
    }
    pub fn decode(b: &[u8]) -> ComputeJobResultV1<Self> {
        let p = payload(b, b"AURA_COMPUTE_CANCEL_V1", COMPUTE_CANCEL_V1_BYTE_LEN)?;
        Ok(Self {
            version: 1,
            compute_job_commitment: p.try_into()?,
        })
    }
    pub fn signing_digest(&self) -> ComputeJobResultV1<[u8; 32]> {
        Ok(tagged(
            b"AURA_COMPUTE_CANCEL_SIGNATURE_V1",
            &self.canonical_bytes()?,
        ))
    }
    fn verify_job(&self, j: &AuraComputeJobV1) -> ComputeJobResultV1<()> {
        if self.compute_job_commitment != j.commitment()? {
            return Err("cancellation job mismatch".into());
        }
        Ok(())
    }
    pub fn verify_signature(&self, j: &AuraComputeJobV1, s: &[u8; 64]) -> ComputeJobResultV1<()> {
        self.verify_job(j)?;
        verify(&j.requester_key, &self.signing_digest()?, s)
    }
    pub fn sign(&self, j: &AuraComputeJobV1, k: &Keypair) -> ComputeJobResultV1<[u8; 64]> {
        self.verify_job(j)?;
        sign(k, &j.requester_key, &self.signing_digest()?)
    }
}
