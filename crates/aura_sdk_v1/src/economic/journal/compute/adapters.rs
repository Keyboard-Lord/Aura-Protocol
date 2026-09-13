//! Sealed verifier registry. No customer-selected function or accepted=true API.
//! C3 will add the reviewed real proving adapter; production C2 has none registered.
use super::*;
pub(super) trait Adapter {
    fn check_job(
        &self,
        j: &AuraComputeJobV1,
        content: &ComputeJobContentV1,
    ) -> AuthorizationResultV2<()>;
    fn measure(&self, backend: ComputeBackendV1) -> AuthorizationResultV2<ComputeJobLimitsV1>;
    fn check_receipt(&self, output: &[u8], evidence: &[u8]) -> AuthorizationResultV2<()>;
    fn verify(
        &self,
        j: &AuraComputeJobV1,
        content: &ComputeJobContentV1,
        output: &[u8],
        evidence: &[u8],
    ) -> AuthorizationResultV2<bool>;
}
pub(super) fn resolve(
    j: &AuraComputeJobV1,
    c: &ComputeJobContentV1,
) -> AuthorizationResultV2<&'static dyn Adapter> {
    #[cfg(test)]
    {
        if c.payloads[0] == b"C2_TEST_ONLY_REVERSE_V1" {
            static A: Fixture = Fixture;
            A.check_job(j, c)?;
            return Ok(&A);
        }
    }
    let _ = (j, c);
    Err("no reviewed compute adapter registered for this job".into())
}
#[cfg(test)]
struct Fixture;
#[cfg(test)]
impl Adapter for Fixture {
    fn check_job(
        &self,
        j: &AuraComputeJobV1,
        c: &ComputeJobContentV1,
    ) -> AuthorizationResultV2<()> {
        if j.workload_class != 0
            || j.verification_class != 1
            || c.payloads[2] != b"test reverse"
            || c.payloads[3] != b"test bounded"
            || c.payloads[4] != b"test exact bytes"
            || c.payloads[5] != b"test replay verifier"
        {
            return Err("unsupported test adapter relation".into());
        }
        Ok(())
    }
    fn measure(&self, b: ComputeBackendV1) -> AuthorizationResultV2<ComputeJobLimitsV1> {
        if b != ComputeBackendV1::Cpu {
            return Err("test fixture supports CPU only".into());
        }
        Ok(ComputeJobLimitsV1 {
            max_input_bytes: 4096,
            max_output_bytes: 4096,
            max_evidence_bytes: 4096,
            max_memory_bytes: 65536,
            max_scratch_bytes: 4096,
            max_execution_ms: 1000,
        })
    }
    fn check_receipt(&self, _: &[u8], e: &[u8]) -> AuthorizationResultV2<()> {
        if e.len() != 32 {
            return Err("test evidence requires exact digest".into());
        }
        Ok(())
    }
    fn verify(
        &self,
        j: &AuraComputeJobV1,
        c: &ComputeJobContentV1,
        o: &[u8],
        e: &[u8],
    ) -> AuthorizationResultV2<bool> {
        tests::hook("during_verification")?;
        let want: Vec<_> = c.payloads[1].iter().rev().copied().collect();
        let mut h = Sha256::new();
        h.update(j.commitment()?);
        h.update(&want);
        Ok(o == want && e == &h.finalize()[..])
    }
}
