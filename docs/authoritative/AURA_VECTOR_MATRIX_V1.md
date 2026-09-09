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

- Unchanged material/binding vectors: `fixtures/v1/canonical_prepare/*`.
  Rust: `crates/aura_sdk_v1/tests/aura_sdk_v1.rs`;
  TypeScript: `packages/aura_sdk_v1_ts/tests/aura_sdk_v1_ts.test.ts`.
- Canonical authorization and actual proof/material binding:
  `fixtures/authorization_v2/authorization_vector_v2.json`,
  `crates/aura_sdk_v1/tests/authorization_v2.rs`,
  `packages/aura_sdk_v1_ts/tests/authorization_v2.test.ts`.
- Canonical UDOT bundles: `fixtures/udot_v2/bundles.json`,
  `crates/aura_sdk_v1/tests/udot_bundle_v2.rs`,
  `packages/aura_sdk_v1_ts/tests/udot_bundle_v2.test.ts`.
- SDK export isolation: Rust compilation/doc tests and
  `packages/aura_sdk_v1_ts/tests/public_boundary_v2.test.ts`.

Historical SDK proof/authorization/settlement envelopes in
`fixtures/v1/canonical_pipeline_v1/*` test explicit `legacy` APIs only. Their
passing tests do not establish canonical authorization conformance. The unchanged
`fixtures/v1/udot_v1/test_vectors.json` retains both V2 glyph regression evidence
and the explicitly classified legacy V1 case; `scripts/test_udot_parity.sh` checks
the canonical bundle and preserved compatibility vectors separately.

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
- Regtest invokes actual Rust proof/authorization admission before Core publication,
  and checks failed admission, confirmation, reorg and durable idempotent retry.
  It does not establish economic ledger/burn integration.
