# AURA_VECTOR_MATRIX_V1

**Classification:** `VALIDATION`  
**Purpose:** Define the frozen validation surface  
**Status:** `ACTIVE`

> **VALIDATION — TEST AND FIXTURE REGISTRY**
> This document maps validation fixtures and tests to protocol layers.
> Frozen fixtures provide cross-language parity guarantees.

## L0

- `fixtures/v1/aura_hash_v1/canonical_message_hash_v1.json`
- Rust: `tests/aura_hash_v1.rs`
- Rust: `tests/aura_text_canonicalization_profile_v1.rs`
- TypeScript: `tests/aura_hash_v1.test.ts`
- TypeScript: `tests/aura_text_canonicalization_profile_v1.test.ts`

## L1-L2

- `fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json`
- Rust: `tests/storm_execution_v1.rs`
- Rust: `tests/storm_trace_commitment_v1.rs`
- Rust: `tests/storm_claim_v1.rs`
- Rust: `tests/storm_hash_quantum_hardening_v1.rs`
- TypeScript: `src/stormExecutionV1.test.ts`
- TypeScript: `src/stormTraceCommitmentV1.test.ts`
- TypeScript: `src/stormClaimV1.test.ts`
- TypeScript: `tests/storm_parity_v1.test.ts`
- TypeScript: `tests/storm_hash_quantum_hardening_v1.test.ts`

## L3-L5

- `fixtures/v1/canonical_prepare/*`
- `fixtures/v1/canonical_pipeline_v1/*`
- `fixtures/v1/udot_v1/test_vectors.json`
- Rust: `crates/aura_sdk_v1/tests/prepared_proof_pipeline_v1.rs`
- Rust: `crates/aura_sdk_v1/tests/authorization_intent_v1.rs`
- TypeScript: `tests/canonical_pipeline_v1.test.ts`
- TypeScript: `tests/prepared_proof_pipeline_v1.test.ts`
- TypeScript: `tests/udot_sdk_v1_ts.test.ts`

## Local Settlement

- `fixtures/l2_canonical_pipeline_v1/*`
- `fixtures/l2_canonical_pipeline_v1/continuous_chain_v1/*`
- `fixtures/layer4_v1/*.json`
- `scripts/run_canonical_pipeline_v1.sh`
- `packages/aura_sdk_v0_ts/src/index.test.ts`

## Bitcoin Anchoring

- Shared Rust/TypeScript vectors: `fixtures/bitcoin_v1/anchor_vectors_v1.json`
- Focused gate: `scripts/verify_bitcoin_foundation_v1.sh`
- Core transport integration: `scripts/verify_bitcoin_regtest_v1.mjs`
- Regtest coverage establishes transport behavior, not end-to-end Aura proof acceptance.
