// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
use std::sync::OnceLock;

use aura_intent_lineage_v1::{
    build_dcm_claim_521_v1, dcm_air_public_inputs_from_claim_521_v1,
    derive_dcm_air_stark_public_input_digest_v1, prove_dcm_air_real_stark_v1,
    verify_dcm_air_real_stark_v1, DcmAirPublicInputsV1, DcmAirRealStarkProofArtifactV1,
    DcmAirRealStarkVerifierErrorV1, DcmAirTraceV1, DcmConfig521V1, DcmExecution521V1,
    DcmInput521V1, DcmState521V1, FieldElement521V1,
    DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1, DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1,
    DCM_AIR_REAL_STARK_PROOF_VERSION_V1, DCM_AIR_REAL_STARK_TRACE_WIDTH_V1,
    FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
};

static CANONICAL_PROOF: OnceLock<DcmAirRealStarkProofArtifactV1> = OnceLock::new();

#[test]
fn stark_prove_and_verify_accepts_canonical_case() {
    let proof = canonical_proof();
    let acceptance = verify_dcm_air_real_stark_v1(&canonical_public_inputs(), proof).unwrap();

    assert_eq!(proof.backend_kind, DCM_AIR_REAL_STARK_BACKEND_WINTERFELL_V1);
    assert_eq!(proof.proof_version, DCM_AIR_REAL_STARK_PROOF_VERSION_V1);
    assert_eq!(
        acceptance.verified_public_input_digest,
        proof.public_input_digest
    );
    assert_eq!(
        acceptance.verified_proof_bytes_digest,
        proof.proof_bytes_digest
    );
    assert_eq!(
        acceptance.verified_proof_binding_digest,
        proof.proof_binding_digest
    );
    assert_eq!(
        acceptance.verified_internal_trace_length,
        proof.internal_trace_length
    );
    assert_eq!(
        usize::from(proof.trace_width),
        DCM_AIR_REAL_STARK_TRACE_WIDTH_V1
    );
    assert_eq!(
        usize::from(proof.backend_constraint_count),
        DCM_AIR_REAL_STARK_BACKEND_CONSTRAINT_COUNT_V1
    );
}

#[test]
fn stark_verifier_rejects_tampered_proof_bytes() {
    let mut proof = canonical_proof().clone();
    proof.proof_bytes[0] ^= 0x01;

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&canonical_public_inputs(), &proof).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::ProofBytesDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_modified_initial_x() {
    let mut public_inputs = canonical_public_inputs();
    public_inputs.initial_state = state(zero(), small_value(1));

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&public_inputs, canonical_proof()).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_modified_initial_y() {
    let mut public_inputs = canonical_public_inputs();
    public_inputs.initial_state = state(pinned_x0(), small_value(2));

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&public_inputs, canonical_proof()).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_modified_final_x() {
    let mut public_inputs = canonical_public_inputs();
    public_inputs.final_state = state(small_value(2), small_value(2));

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&public_inputs, canonical_proof()).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_modified_final_y() {
    let mut public_inputs = canonical_public_inputs();
    public_inputs.final_state = state(small_value(1), small_value(3));

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&public_inputs, canonical_proof()).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_modified_iteration_count() {
    let mut public_inputs = canonical_public_inputs();
    public_inputs.iteration_count = 3;

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&public_inputs, canonical_proof()).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::UnsupportedTraceShape { .. }
            | DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_modified_public_input_digest() {
    let mut proof = canonical_proof().clone();
    proof.public_input_digest = [0x77; 32];

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&canonical_public_inputs(), &proof).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_verifier_rejects_tampered_commitment_root() {
    let mut public_inputs = canonical_public_inputs();
    public_inputs.commitment_root[0] ^= 0x01;

    assert!(matches!(
        verify_dcm_air_real_stark_v1(&public_inputs, canonical_proof()).unwrap_err(),
        DcmAirRealStarkVerifierErrorV1::PublicInputDigestMismatch { .. }
    ));
}

#[test]
fn stark_proof_binds_to_canonical_dcm_claim_521_v1() {
    let execution = canonical_execution();
    let claim = build_dcm_claim_521_v1(&canonical_config(), &canonical_input(), &execution);
    let public_inputs = dcm_air_public_inputs_from_claim_521_v1(&claim);
    let proof = canonical_proof();

    assert_eq!(public_inputs, canonical_public_inputs());
    assert_eq!(
        proof.public_input_digest,
        derive_dcm_air_stark_public_input_digest_v1(&public_inputs)
    );
}

#[test]
fn canonical_fixture_is_deterministic_for_real_stark_path() {
    let first =
        prove_dcm_air_real_stark_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();
    let second =
        prove_dcm_air_real_stark_v1(&canonical_public_inputs(), &canonical_trace()).unwrap();

    assert_eq!(first.proof_bytes_digest, second.proof_bytes_digest);
    assert_eq!(first.proof_binding_digest, second.proof_binding_digest);
    assert_eq!(first.proof_bytes, second.proof_bytes);
}

#[test]
fn stark_prove_and_verify_accepts_structured_seed_matrix() {
    let cases = [
        (
            DcmConfig521V1 { iteration_count: 0 },
            DcmInput521V1::from_u64(0, 0),
        ),
        (
            DcmConfig521V1 { iteration_count: 1 },
            DcmInput521V1::from_u64(1, 0),
        ),
        (
            DcmConfig521V1 { iteration_count: 2 },
            DcmInput521V1 {
                x0: pinned_x0(),
                y0: small_value(1),
            },
        ),
        (
            DcmConfig521V1 { iteration_count: 4 },
            DcmInput521V1::from_u64(5, 8),
        ),
    ];

    for (config, input) in cases {
        let execution = DcmExecution521V1::run(&config, &input).unwrap();
        let trace = DcmAirTraceV1::new(execution.states.clone());
        let public_inputs = dcm_air_public_inputs_from_claim_521_v1(&build_dcm_claim_521_v1(
            &config, &input, &execution,
        ));
        let proof = prove_dcm_air_real_stark_v1(&public_inputs, &trace).unwrap();

        verify_dcm_air_real_stark_v1(&public_inputs, &proof).unwrap();
    }
}

fn canonical_proof() -> &'static DcmAirRealStarkProofArtifactV1 {
    CANONICAL_PROOF.get_or_init(|| {
        prove_dcm_air_real_stark_v1(&canonical_public_inputs(), &canonical_trace()).unwrap()
    })
}

fn canonical_trace() -> DcmAirTraceV1 {
    DcmAirTraceV1::new(canonical_execution().states)
}

fn canonical_execution() -> DcmExecution521V1 {
    DcmExecution521V1::run(&canonical_config(), &canonical_input()).unwrap()
}

fn canonical_config() -> DcmConfig521V1 {
    DcmConfig521V1 { iteration_count: 2 }
}

fn canonical_input() -> DcmInput521V1 {
    DcmInput521V1 {
        x0: pinned_x0(),
        y0: small_value(1),
    }
}

fn canonical_public_inputs() -> DcmAirPublicInputsV1 {
    let claim = build_dcm_claim_521_v1(
        &canonical_config(),
        &canonical_input(),
        &canonical_execution(),
    );
    dcm_air_public_inputs_from_claim_521_v1(&claim)
}

fn state(x: FieldElement521V1, y: FieldElement521V1) -> DcmState521V1 {
    DcmState521V1 { x, y }
}

fn zero() -> FieldElement521V1 {
    FieldElement521V1::zero()
}

fn small_value(value: u64) -> FieldElement521V1 {
    FieldElement521V1::from_u64(value)
}

fn pinned_x0() -> FieldElement521V1 {
    let mut bytes = FIELD_MODULUS_521_V1;
    bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;
    FieldElement521V1::from_bytes(bytes).unwrap()
}
