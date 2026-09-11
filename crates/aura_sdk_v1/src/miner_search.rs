//! Local M3 computation only. No admission, authorization reservation, journal,
//! winner, head, reward or Bitcoin effects. All objects below are local API values,
//! not a new wire. M4 must revalidate inputs at its own trust/admission boundary.
use crate::{
    authorization::{fresh_nonce_v2, AuthorizationResultV2},
    economic::{EconomicLimitsV1, EconomicWorkV1},
    miner::{MinerJobPolicyV1, MinerJobV1},
    prepare_bound_proof_material_v1, PreparedBoundProofMaterialV1,
};
use aura_intent_lineage_v1::{
    build_storm_air_public_inputs_v1, build_storm_claim_v1, decode_storm_air_real_artifact_v1,
    prove_storm_air_real_v1, verify_storm_air_real_v1, StormAirPublicInputsV1,
    StormAirRealProofArtifactV1, StormClaim521V1,
};
use aura_l2_local_chain_v0::economic_meter::EconomicMeterV1;
use secp256k1::Keypair;
use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug)]
pub struct MinerLimitsV1 {
    pub work: EconomicLimitsV1,
    pub max_proof_bytes: usize,
}

/// Durations of actual owner calls, not protocol data or physical work claims.
/// Claim construction includes Storm execution and TRACE_ROOT construction.
/// Proving and verification include the existing owners' own replay work.
#[derive(Clone, Copy, Debug)]
pub struct MinerTrialTimingsV1 {
    pub work_profile: Duration,
    pub storm_execution_and_claim: Duration,
    pub proof_construction: Duration,
    pub proof_verification: Duration,
    pub material_binding: Duration,
    pub total: Duration,
}

/// Read-only completed local computation. Accessors reuse canonical owners and
/// derive nonce/proof_hash from them instead of storing duplicate identifiers.
#[derive(Clone, Debug)]
pub struct MinerTrialV1 {
    work: EconomicWorkV1,
    claim: StormClaim521V1,
    proof: StormAirRealProofArtifactV1,
    prepared: PreparedBoundProofMaterialV1,
    trial_index: u64,
    qualifies: bool,
    timings: MinerTrialTimingsV1,
}
impl MinerTrialV1 {
    pub fn work(&self) -> &EconomicWorkV1 {
        &self.work
    }
    pub fn claim(&self) -> &StormClaim521V1 {
        &self.claim
    }
    pub fn proof(&self) -> &StormAirRealProofArtifactV1 {
        &self.proof
    }
    pub fn prepared(&self) -> &PreparedBoundProofMaterialV1 {
        &self.prepared
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.work.nonce()
    }
    pub fn proof_hash(&self) -> [u8; 32] {
        self.prepared.proof_hash
    }
    pub fn trial_index(&self) -> u64 {
        self.trial_index
    }
    /// Fully verified local PoC + job target only; never a journal winner verdict.
    pub fn qualifies(&self) -> bool {
        self.qualifies
    }
    pub fn timings(&self) -> MinerTrialTimingsV1 {
        self.timings
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MinerNonceModeV1 {
    /// Every trial calls the existing secure producer. A collision fails closed.
    SecureRandom,
    /// Reproducible tests/probes only; sequential BE256 values, no wraparound.
    /// This is NOT the approved production CSPRNG nonce producer.
    ResearchSequential { first: [u8; 32] },
}
#[derive(Clone, Copy, Debug)]
pub struct MinerSearchConfigV1 {
    pub max_trials: u64,
    pub max_duration: Duration,
    pub nonce_mode: MinerNonceModeV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinerSearchStopV1 {
    TrialLimit,
    TimeLimit,
    Cancelled,
    JobExpired,
    NonceSpaceExhausted,
}
#[derive(Clone, Debug)]
pub enum MinerSearchOutcomeV1 {
    Qualified(MinerTrialV1),
    Stopped {
        reason: MinerSearchStopV1,
        trials_completed: u64,
    },
}

/// An immutable local session authenticated against explicit trusted job policy.
/// Key ownership is supplied by a keypair; only its public key is needed/retained.
/// No live head, round publication or sponsor-funding assertion is made here.
pub struct MinerSessionV1<'a> {
    job: &'a MinerJobV1,
    meter: &'a EconomicMeterV1,
    limits: MinerLimitsV1,
}
impl<'a> MinerSessionV1<'a> {
    pub fn new(
        job: &'a MinerJobV1,
        job_signature: &[u8],
        policy: &MinerJobPolicyV1,
        meter: &'a EconomicMeterV1,
        identity: &Keypair,
        limits: MinerLimitsV1,
    ) -> AuthorizationResultV2<Self> {
        job.verify_for_policy(job_signature, policy, limits.work)?;
        if identity.x_only_public_key().0.serialize() != meter.ledger.payer_account_id {
            return Err("miner identity must equal metered payer/controller".into());
        }
        if limits.max_proof_bytes == 0 {
            return Err("miner proof byte limit must be positive".into());
        }
        // Validate canonical immutable M/head/profile before starting expensive work.
        job.build_work(meter.clone(), [0; 32])?;
        Ok(Self { job, meter, limits })
    }

    /// One offline trial with an explicit nonce. Search-session uniqueness, RNG,
    /// expiry and cancellation are enforced by mine(), not this reproducible primitive.
    pub fn trial(&self, nonce: [u8; 32], trial_index: u64) -> AuthorizationResultV2<MinerTrialV1> {
        let total = Instant::now();
        let start = Instant::now();
        let work = self.job.build_work(self.meter.clone(), nonce)?;
        let work_profile = start.elapsed();
        let start = Instant::now();
        let claim = build_storm_claim_v1(&work.storm, [0; 32], [0; 32]);
        let storm_execution_and_claim = start.elapsed();
        let start = Instant::now();
        let public_inputs = build_storm_air_public_inputs_v1(&claim);
        let proof = prove_storm_air_real_v1(&claim, &public_inputs)?;
        let proof_construction = start.elapsed();
        let start = Instant::now();
        verify_profile_and_proof(self.job, &work, &claim, &proof, self.limits)?;
        let proof_verification = start.elapsed();
        let start = Instant::now();
        // This owner verifies ProofMaterial and FractalKey binding before returning.
        let prepared = prepare_bound_proof_material_v1(
            work.subject(),
            work.nonce(),
            &proof.proof_bytes,
            &public_inputs.canonical_bytes(),
            &[],
        )?;
        let material_binding = start.elapsed();
        let qualifies = self.job.passes_hash_filter(&prepared.proof_hash)?;
        Ok(MinerTrialV1 {
            work,
            claim,
            proof,
            prepared,
            trial_index,
            qualifies,
            timings: MinerTrialTimingsV1 {
                work_profile,
                storm_execution_and_claim,
                proof_construction,
                proof_verification,
                material_binding,
                total: total.elapsed(),
            },
        })
    }

    /// Bounded, serial local search. Time/expiry/cancellation checks occur before
    /// and after each indivisible canonical trial. No winner is returned after
    /// cancellation/expiry/deadline. An in-flight trial can exceed the time budget;
    /// its work is bounded by the explicit host N cap, not preempted inside crypto.
    pub fn mine(
        &self,
        config: MinerSearchConfigV1,
        cancelled: &AtomicBool,
    ) -> AuthorizationResultV2<MinerSearchOutcomeV1> {
        self.mine_with_sources(
            config,
            cancelled,
            || Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()),
            fresh_nonce_v2,
        )
    }

    fn mine_with_sources(
        &self,
        config: MinerSearchConfigV1,
        cancelled: &AtomicBool,
        mut clock: impl FnMut() -> AuthorizationResultV2<u64>,
        mut random_nonce: impl FnMut() -> AuthorizationResultV2<[u8; 32]>,
    ) -> AuthorizationResultV2<MinerSearchOutcomeV1> {
        let started = Instant::now();
        let mut seen = HashSet::new();
        let mut sequential = match config.nonce_mode {
            MinerNonceModeV1::ResearchSequential { first } => Some(first),
            _ => None,
        };
        let stop = |reason, trials_completed| MinerSearchOutcomeV1::Stopped {
            reason,
            trials_completed,
        };
        for index in 0..config.max_trials {
            if cancelled.load(Ordering::Relaxed) {
                return Ok(stop(MinerSearchStopV1::Cancelled, index));
            }
            if started.elapsed() >= config.max_duration {
                return Ok(stop(MinerSearchStopV1::TimeLimit, index));
            }
            let now = clock()?;
            if now >= self.job.expires_at {
                return Ok(stop(MinerSearchStopV1::JobExpired, index));
            }
            self.job
                .validate_window(now, self.job.expires_at - self.job.opened_at)?;
            let nonce = match config.nonce_mode {
                MinerNonceModeV1::SecureRandom => {
                    let value = random_nonce()?;
                    if !seen.insert(value) {
                        return Err("duplicate mining nonce from secure producer".into());
                    }
                    value
                }
                MinerNonceModeV1::ResearchSequential { .. } => {
                    let Some(value) = sequential else {
                        return Ok(stop(MinerSearchStopV1::NonceSpaceExhausted, index));
                    };
                    sequential = next_research_nonce(value);
                    value
                }
            };
            let trial = self.trial(nonce, index)?;
            let completed = index + 1; // index < max_trials <= u64::MAX
            if cancelled.load(Ordering::Relaxed) {
                return Ok(stop(MinerSearchStopV1::Cancelled, completed));
            }
            if started.elapsed() >= config.max_duration {
                return Ok(stop(MinerSearchStopV1::TimeLimit, completed));
            }
            if clock()? >= self.job.expires_at {
                return Ok(stop(MinerSearchStopV1::JobExpired, completed));
            }
            if trial.qualifies {
                return Ok(MinerSearchOutcomeV1::Qualified(trial));
            }
        }
        Ok(stop(MinerSearchStopV1::TrialLimit, config.max_trials))
    }
}

fn next_research_nonce(mut nonce: [u8; 32]) -> Option<[u8; 32]> {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            return Some(nonce);
        }
    }
    None
}

fn verify_profile_and_proof(
    job: &MinerJobV1,
    work: &EconomicWorkV1,
    claim: &StormClaim521V1,
    proof: &StormAirRealProofArtifactV1,
    limits: MinerLimitsV1,
) -> AuthorizationResultV2<StormAirPublicInputsV1> {
    if claim.iteration_count > limits.work.max_iterations
        || proof.proof_bytes.len() > limits.max_proof_bytes
        || work.canonical_bytes()?.len() > limits.work.max_work_bytes
        || work.meter.canonical_bytes()?.len() > limits.work.max_meter_bytes
    {
        return Err("miner host resource limit exceeded".into());
    }
    job.validate_claim_profile(work, claim, &[])?;
    let (embedded_claim, canonical_artifact) =
        decode_storm_air_real_artifact_v1(proof.proof_bytes.clone())?;
    if &embedded_claim != claim || &canonical_artifact != proof {
        return Err("miner embedded claim or artifact mismatch".into());
    }
    let inputs = build_storm_air_public_inputs_v1(claim);
    verify_storm_air_real_v1(&inputs, proof)?;
    Ok(inputs)
}

/// Revalidate local objects through the actual proof owner and both existing
/// material/binding owners; only then apply the frozen job target. No signature,
/// funding, admission or winner state is conferred by this return value.
pub fn verify_miner_trial_v1(
    job: &MinerJobV1,
    trial: &MinerTrialV1,
    limits: MinerLimitsV1,
) -> AuthorizationResultV2<bool> {
    let inputs = verify_profile_and_proof(job, &trial.work, &trial.claim, &trial.proof, limits)?;
    let expected = prepare_bound_proof_material_v1(
        trial.work.subject(),
        trial.work.nonce(),
        &trial.proof.proof_bytes,
        &inputs.canonical_bytes(),
        &[],
    )?;
    if trial.prepared != expected {
        return Err("miner proof/material/FractalKey binding mismatch".into());
    }
    job.passes_hash_filter(&expected.proof_hash)
}

#[cfg(test)]
mod tests;
