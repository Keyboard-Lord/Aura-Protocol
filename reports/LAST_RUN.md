<!-- DOC_STATUS_HEADER_START -->
> Status: RESEARCH / SUPPORTING
> Concept: Last Run
> Scope Boundary: Supporting report material only. It records evidence, measurements, or operator state and does not create active or frozen protocol authority.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as supporting context only. Candidate, future, audit, or comparison language in the body is non-authoritative unless promoted elsewhere.
> Implementation State: Supporting, research, audit, planning, or non-authoritative.
<!-- DOC_STATUS_HEADER_END -->

# Last Run

## Active Capability
Aura core-stack realignment

## Task
Realign the repository to Aura Core Stack v1

## Phase
Architecture realignment and consistency pass

## Objective
Correct the repository doctrine so Aura is presented as a four-layer system rooted in the DCM core, then align public docs, Layer 4 subsystem docs, package/crate metadata, and module descriptions without changing frozen Aura v1 semantics.

## Developer Deliverable
A docs-first realignment pass that:

- adds an authoritative four-layer doctrine
- adds disciplined Layer 1, Layer 2, and Layer 3 placeholder/spec docs
- repositions the L2/stateful material as a subordinate Layer 4 subsystem
- preserves the frozen Aura v1 baseline as a valid implemented slice
- updates repo-facing surfaces so they no longer imply Aura is only a generic L2 or only a proof-hash MVP

## Files Changed
- `README.md`
- `Cargo.toml`
- `src/lib.rs`
- `docs/AURA_CORE_STACK_V1.md`
- `docs/AURA_DCM_CORE_V1.md`
- `docs/AURA_DCM_TRACE_COMMITMENT_V1.md`
- `docs/AURA_DCM_STARK_SPEC_V1.md`
- `docs/ARCHITECTURE_STACK.md`
- `docs/AURA_CRYPTOGRAPHIC_CORE_V1.md`
- `docs/FOUNDATION_BASELINE_V1.md`
- `docs/AURA_L2_FOUNDATION_SCOPE_V1.md`
- `docs/AURA_L2_SEQUENCER_DATA_MODEL_V1.md`
- `docs/AURA_L2_STATE_TRANSITION_RULES_V1.md`
- `docs/AURA_L2_AUTHORIZATION_RULES_V1.md`
- `docs/aura-solana-core-v2-foundation.md`
- `docs/AURA_STATE_RECONCILIATION_REPORT.md`
- `docs/AURA_WHITEPAPER_REWRITE_V1_V2.md`
- `docs/AGENT_RULES.md`
- `crates/aura_cli_v1/Cargo.toml`
- `crates/aura_fractal_key_integration_v1/Cargo.toml`
- `crates/aura_fractal_key_integration_v1/src/lib.rs`
- `crates/aura_fractal_key_v1/Cargo.toml`
- `crates/aura_fractal_key_v1/src/lib.rs`
- `crates/aura_proof_material_v1/Cargo.toml`
- `crates/aura_proof_material_v1/src/lib.rs`
- `crates/aura_proof_material_v2/Cargo.toml`
- `crates/aura_proof_material_v2/src/lib.rs`
- `crates/aura_reference_demo_v1/Cargo.toml`
- `crates/aura_reference_demo_v1/README.md`
- `crates/aura_sdk_v1/Cargo.toml`
- `crates/aura_sdk_v1/src/lib.rs`
- `crates/aura_submission_client_v1/Cargo.toml`
- `crates/aura_submission_client_v1/src/lib.rs`
- `crates/aura_verifier_adapter_v2/Cargo.toml`
- `crates/aura_verifier_adapter_v2/src/lib.rs`
- `packages/aura_sdk_v1_ts/package.json`
- `packages/aura_sdk_v1_ts/README.md`
- `packages/aura_submission_client_v1_ts/package.json`
- `packages/aura_submission_client_v1_ts/README.md`
- `tasks/CURRENT_TASK.md`
- `reports/LAST_RUN.md`

## Validations Run
- `cargo test --offline`
- `for manifest in crates/*/Cargo.toml; do cargo test --manifest-path "$manifest" --offline || exit 1; done`
- `for dir in packages/aura_sdk_v1_ts packages/aura_submission_client_v1_ts; do (cd "$dir" && node --test) || exit 1; done`

## Result
Pass.

The repository now has an authoritative four-layer Aura doctrine, explicit Layer 1 to Layer 3 placeholder/spec boundaries, a corrected Layer 4 subsystem framing, and aligned repo-facing metadata and module descriptions. Frozen Aura v1 behavior remains unchanged.

## Scope Notes
- the DCM core is documented as foundational but still unimplemented in repository code
- Layer 2 DCM-rooted authorization lineage is documented but still unimplemented in repository code
- the STARK proving layer is documented but still unimplemented in repository code
- the Layer 4 L2/stateful subsystem remains specification-only beyond the narrower frozen Aura v1 Solana MVP
- historical docs that previously acted as conflicting architecture centers now carry compatibility or historical-only status

## Risks / Notes
- the repository is not inside a visible `.git` checkout in the current environment, so filesystem contents were used as the source of truth
- existing `solana_program::entrypoint!` `unexpected cfg` warnings remain
- the existing `solana-client v1.18.26` future-incompatibility notice remains
- `tarpc::client` OpenTelemetry warnings remain during Solana program-test runs
- no new protocol functionality was implemented for Layers 1 through 4 in code; this pass is doctrinal and consistency-focused

## Capability Status
Completed

## Recommended Next Task
Define the first implementation-grade proving-handoff contract that connects the Layer 2 lineage boundary to a future Layer 3 proof interface without claiming a completed prover or settlement integration.
