// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use std::time::Instant;

use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1, prove_dcm_air_real_stark_v1,
    verify_dcm_air_real_stark_v1, DcmAirTraceV1, DcmConfig521V1, DcmExecution521V1, DcmInput521V1,
};

#[test]
#[ignore = "benchmark-style measurement; run manually with --ignored --nocapture"]
fn benchmark_real_stark_pipeline_reports_trace_prove_verify_and_size() {
    let cases = [
        (
            "canonical_32",
            DcmConfig521V1 {
                iteration_count: 32,
            },
            DcmInput521V1::from_u64(1, 1),
        ),
        (
            "structured_128",
            DcmConfig521V1 {
                iteration_count: 128,
            },
            DcmInput521V1::from_seed_bytes(
                b"benchmark_structured_entropy_v1",
                b"benchmark_structured_challenge_v1",
            ),
        ),
    ];

    for (name, config, input) in cases {
        let trace_started = Instant::now();
        let execution = DcmExecution521V1::run(&config, &input).unwrap();
        let trace = DcmAirTraceV1::new(execution.states.clone());
        let claim = build_dcm_claim_521_v1(&config, &input, &execution);
        let public_inputs = dcm_air_public_inputs_from_claim_521_v1(&claim);
        let trace_elapsed = trace_started.elapsed();

        let prove_started = Instant::now();
        let proof = prove_dcm_air_real_stark_v1(&public_inputs, &trace).unwrap();
        let prove_elapsed = prove_started.elapsed();

        let verify_started = Instant::now();
        let acceptance = verify_dcm_air_real_stark_v1(&public_inputs, &proof).unwrap();
        let verify_elapsed = verify_started.elapsed();

        println!(
            "BENCHMARK {} trace_ms={} prove_ms={} verify_ms={} proof_bytes={} trace_width={} backend_constraints={} internal_trace_length={}",
            name,
            trace_elapsed.as_secs_f64() * 1_000.0,
            prove_elapsed.as_secs_f64() * 1_000.0,
            verify_elapsed.as_secs_f64() * 1_000.0,
            proof.proof_bytes.len(),
            proof.trace_width,
            proof.backend_constraint_count,
            acceptance.verified_internal_trace_length,
        );
    }
}
