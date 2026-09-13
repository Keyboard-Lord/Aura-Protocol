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
- Core export isolation: `cargo test -p aura_intent_lineage_v1 --doc --offline`
  checks canonical Storm imports, explicit legacy imports, and rejection of retired
  cat-map, mixed-session and former authorization/state APIs at the crate root.

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

Canonical economic admission:

- `fixtures/economic_admission_v1/meter_vectors.json`: strict M and existing tariffs
- `fixtures/economic_admission_v1/contract_vector.json`: W, B, consent signature,
  unchanged Authorization V2, ledger commitments and all four head V2 outcomes
- Rust: local-chain `economic_meter::tests`, SDK `economic_contract_v1` and
  `economic_journal_v1` integration tests
- TS: `packages/aura_sdk_v0_ts/src/economic_meter.test.ts` and
  `packages/aura_sdk_v1_ts/src/economicV1.test.ts`
- Durable tests cover pre-admission/chargeable failure, retry, competing writers,
  process exit/restart, atomic rollback, corrupt state and explicit V1 migration.

Historical local-runner compatibility (unchanged bytes):

- `fixtures/l2_canonical_pipeline_v1/*`
- `fixtures/l2_canonical_pipeline_v1/continuous_chain_v1/*`
- `fixtures/layer4_v1/*.json`
- `scripts/run_canonical_pipeline_v1.sh`
- `packages/aura_sdk_v0_ts/src/index.test.ts`

## Bitcoin Anchoring

- Shared Rust/TypeScript vectors: `fixtures/bitcoin_v1/anchor_vectors_v1.json`
- Focused gate: `scripts/verify_bitcoin_foundation_v1.sh`
- Core transport integration: `scripts/verify_bitcoin_regtest_v1.mjs`
- Regtest invokes economic consent/admission, checks the durable debit, resumes in
  another process, verifies the actual Storm proof/material/authorization, and
  publishes the atomic outbox. Fee failure and reorg retry retain the same charge,
  head, authorization and outbox request.

## Coordinated Miner V1

- `fixtures/miner_v1/job_profile_vector_v1.json`: frozen M2 job/profile/signature,
  intent/route/work bytes and exact target boundaries; Rust `tests/miner_v1.rs`
  and TS `src/minerV1.test.ts` compare the same bytes.
- `fixtures/miner_v1/trial_vector_v1.json`: existing proof/claim/material/FractalKey
  objects; Rust `src/miner_search/tests.rs` performs actual PoC; TS
  `src/minerSearchV1.test.ts` checks its codec/material boundary only.
- `crates/aura_sdk_v1/src/economic/journal/miner/tests.rs`, child `adversarial.rs`
  and `promotion.rs`: atomic rounds, failures/retries, crashes/corruption, initial
  and consecutive epochs, challenge generation under the pinned snapshot lock.
- `scripts/verify_miner_program_v1.mjs`: reproducible owner regressions, SDK compile
  and adversarial real Core regtest. M3 measurements and M6/M7 results are evidence
  under `reports/miner_protocol_v1/`, not production parameter constants.
- [Miner operations](../AURA_MINER_OPERATIONS_V1.md) describes reproduction and the
  distinction between implementation readiness and separately approved activation.

## Compute Job V1 (C1)

- Owner: [compute contract](AURA_COMPUTE_NETWORK_V1.md). C1 is frozen; supported
  contract bytes do not imply workload execution or durable payment acceptance.
- `fixtures/compute_job_v1/job_vectors_v1.json`: exact job/signature/content bytes,
  pure replay cases, compensation extremes and existing signed-miner expansion.
  Synthetic policy payloads here test structural binding, not supported policies.
- `fixtures/compute_job_v1/core_policy_vectors_v1.json`: supported core payloads,
  independent domain commitments, exact payment terms and signed-job bindings.
- Rust: `crates/aura_sdk_v1/tests/compute_job_v1.rs`; independent TS:
  `packages/aura_sdk_v1_ts/src/computeJobV1.test.ts`. All-byte mutations, framing,
  unsupported profiles/classes, fee and availability boundaries are covered.
- `scripts/verify_compute_job_v1.mjs`: C1 tests, frozen M2 regression, affected
  SDK compile and Node syntax/public exports. No fixture regeneration, durable
  compute state, adapter execution or Bitcoin deployment in this gate.
- Evidence: `reports/compute_network_v1/c1_freeze_results.json` and
  `reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md`; fixture notes distinguish synthetic
  test parameters from any future production values.

## Compute Lifecycle V1 (C2)

- Owner: [compute lifecycle](AURA_COMPUTE_NETWORK_V1.md#c2-assignment-receipt-and-verified-result).
- `fixtures/compute_result_v1/result_vectors_v1.json`: exact assignment, receipt,
  result, cancellation and byte-accounting wires; all signature roles, result
  commitments and unchanged C1 side derivation. No worker telemetry enters R.
- Rust: `crates/aura_sdk_v1/tests/compute_result_v1.rs`; independent TS:
  `packages/aura_sdk_v1_ts/src/computeResultV1.test.ts`.
- `crates/aura_sdk_v1/src/economic/journal/compute/tests.rs`: sealed test-only
  adapter, atomic reservation/assignment/receipt/entitlement, races, immutable
  retries, expiry, corruption, funding overlap and process-exit recovery.
- `scripts/verify_compute_result_v1.mjs`: C2 parity/durability plus full frozen C1/M2
  gate and affected existing miner/economic journal regressions. Includes compile
  rejection of client-deserialized backing tokens. No live Bitcoin execution.
- `reports/compute_network_v1/c2_freeze_results.json`: commands, environment,
  fixture hashes and results; the C2 evidence report states actual claim limits.
