<!-- DOC_STATUS_HEADER_START -->
> Status: RESEARCH / SUPPORTING
> Concept: Aura Production Audit V1
> Scope Boundary: Supporting or non-authoritative material for the named surface only. It may record research, audits, planning, or supporting-layer doctrine, but it does not create active or frozen protocol authority.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Read the body as supporting context only. Candidate, future, audit, or comparison language in the body is non-authoritative unless promoted elsewhere.
> Implementation State: Supporting, research, audit, planning, or non-authoritative.
<!-- DOC_STATUS_HEADER_END -->

# Aura Production Audit V1

## Scope

This document records the final production-hardening pass for the frozen Aura v1 canonical pipeline.

Audited implementation surfaces:

- `crates/aura_udot_v2`
- `crates/aura_submission_client_v1`
- `crates/aura_sdk_v1`
- `crates/aura_cli_v1`
- `crates/aura_intent_lineage_v1`
- `packages/aura_sdk_v1_ts`
- `packages/aura_submission_client_v1_ts`

The pass was constrained to production hardening only. It did not redesign the protocol and did not change frozen semantics.

## Frozen Invariants Preserved

The following invariants remain unchanged:

- envelope nesting is unchanged from UDOT through L4 settlement
- the final Solana payload remains `tag || proof_hash`
- the `proof_hash` settlement rule is unchanged
- `udot_version` remains explicit and required
- no auto-detection or inference was introduced
- the UDOT -> L4 settlement pipeline remains frozen

Layer separation remains explicit:

- math layer: Arnold cat map
- proof layer: STARK / AIR
- binding layer: authorization intent and lineage binding
- representation layer: UDOT

## Production Hardening Results

### 1. Deterministic cross-language canonical serialization

The canonical off-chain pipeline is now pinned by byte-exact repository fixtures in:

- `/Users/keyboard_lord/Documents/AURA/fixtures/v1/canonical_pipeline_v1/submit_proof_request_v1.json`
- `/Users/keyboard_lord/Documents/AURA/fixtures/v1/canonical_pipeline_v1/authorization_intent_v1.json`
- `/Users/keyboard_lord/Documents/AURA/fixtures/v1/canonical_pipeline_v1/stark_proof_envelope_v1.json`
- `/Users/keyboard_lord/Documents/AURA/fixtures/v1/canonical_pipeline_v1/solana_settlement_request_v1.json`

Rust and TypeScript both regenerate these exact minified JSON bytes from the same frozen preparation inputs and lower-layer constants.

### 2. Strict canonical byte equality

Canonical path enforcement is fail-closed:

- canonical proof-hash text must already be canonical lowercase hex
- canonical fixed-width proof/state fields reject non-canonical encodings
- canonical settlement JSON requires explicit `solana_rpc_url` field presence
- nested canonical objects remain nested through the L4 envelope
- canonical fixture checks compare exact serialized bytes, not normalized JSON

No silent normalization was retained on canonical wire paths.

### 3. No implicit defaults in canonical paths

The production path now rejects omitted canonical fields instead of filling them implicitly.

In particular:

- `udot_version` remains explicit inside the nested submit request
- `solana_rpc_url` must be present on settlement-wire deserialization
- canonical hash parsing rejects uppercase and other non-canonical spellings instead of repairing them

### 4. End-to-end golden test

The repository now contains a canonical golden-path integration test that covers:

`UDOT -> submit -> intent -> proof -> settlement -> verification`

Reference tests:

- `/Users/keyboard_lord/Documents/AURA/crates/aura_sdk_v1/tests/canonical_pipeline_v1.rs`
- `/Users/keyboard_lord/Documents/AURA/packages/aura_sdk_v1_ts/tests/canonical_pipeline_v1.test.ts`

These tests:

- derive the canonical `proof_hash` from the frozen preparation fixture
- produce a real lower-layer STARK session and acceptance record
- build all four nested wire objects
- compare exact serialized bytes against checked-in fixtures
- verify nested continuity of `proof_hash`
- reject uppercase proof-hash text
- reject missing `solana_rpc_url`

### 5. Fail-closed error handling

The canonical production path is hardened to reject malformed or ambiguous inputs rather than normalize them.

Representative fail-closed behavior now covers:

- non-canonical lowercase-hex violations
- missing required canonical settlement fields
- mismatched nested UDOT bundle content
- mismatched submitter key ownership at client submission boundaries
- non-matching `proof_hash` vs nested UDOT representation

## VERIFIED vs HOST-SIDE Boundary

Aura continues to separate cryptographically proven statements from host-enforced binding and transport logic.

### VERIFIED

The following are in the AIR / proof domain:

- the Arnold cat-map recurrence over the configured field
- lower-layer state evolution and claimed initial/final states
- the lower-layer STARK proof acceptance path
- the commitment root carried by the accepted lower-layer claim
- proof/session material tied into the lower-layer proving transcript

### HOST-SIDE

The following remain host-side by design:

- authorization intent assembly
- lineage binding packaging
- UDOT glyph representation and JSON transport
- base58-facing Solana transport fields
- CLI / SDK envelope production and parsing
- final handoff from nested off-chain envelopes to the on-chain `tag || proof_hash` payload

This boundary is intentional and unchanged.

## Verification Evidence

The hardening pass was validated with the following commands:

```text
cargo test --manifest-path crates/aura_udot_v2/Cargo.toml
cargo test --manifest-path crates/aura_intent_lineage_v1/Cargo.toml
cargo test --manifest-path crates/aura_sdk_v1/Cargo.toml
cargo test --manifest-path crates/aura_submission_client_v1/Cargo.toml
cargo test --manifest-path crates/aura_cli_v1/Cargo.toml
node --test packages/aura_sdk_v1_ts/tests/*.test.ts
node --test packages/aura_submission_client_v1_ts/tests/*.test.ts
```

The full submission-client package test run completed successfully, including the canonical nested settlement-wire coverage.

## Residual Notes

The following observations remain informational only and do not change protocol behavior:

- `solana-client v1.18.26` emits a future-incompatibility warning under current Rust tooling
- `tarpc::client` emits OpenTelemetry warning lines during some submission-client tests
- Solana macro-related `unexpected cfg` warnings may appear in Solana-facing crate builds

None of these warnings changed the verified outputs or canonical fixture bytes during this pass.

## Final Pipeline Guarantee

No remaining deferred boundary in the canonical pipeline.
