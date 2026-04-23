# AURA_CANONICAL_PIPELINE_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L3`  
**Purpose:** Define the single active object pipeline  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — PIPELINE STAGES**
> This document defines the exact stage ordering of the canonical pipeline.
> No alternate stage order is valid. Each stage emits exactly one artifact.

Implementation:

- Rust preparation: `crates/aura_sdk_v1/src/lib.rs`
- Rust submission pipeline: `crates/aura_sdk_v1/src/submission.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/index.ts`
- Frozen fixtures: `fixtures/v1/canonical_prepare/*` and `fixtures/v1/canonical_pipeline_v1/*`

There is exactly one canonical pipeline:

`request -> proof_material_hash -> proof_hash -> udot_bundle_v2 -> authorization -> storm -> trace -> proof -> settlement`

## Stage Map

`request`

- one fully normalized canonical request object

Legacy normalization, compatibility lifting, and version selection happen strictly before this
stage.

`proof_material_hash`

- `proof_material_hash`

`proof_hash`

- `proof_hash`

`udot_bundle_v2`

- `UdotBundleV2`

`authorization`

- `AuthorizationIntentEnvelopeV1`

`storm`

- `StormClaim521V1`

`trace`

- `TRACE_ROOT`

`proof`

- `StarkProofEnvelopeV1`

`settlement`

- `SolanaSettlementRequestWireV1`

No alternate stage order is valid.

## Purity Rule

Each stage emits exactly one artifact.

Every stage output is a pure function of its stage inputs with no representational degrees of
freedom.

No canonical stage output may contain:

- optional fields
- `null`
- alternate encodings
- duplicated substructures from another canonical object

Downstream stages reference upstream artifacts by canonical identifiers, principally
`proof_hash_hex`; they do not carry exact nested copies of upstream objects.

## Fail-Closed Enforcement

**MUST:** Any pipeline deviation results in immediate fail-closed rejection with full burn.

Specific rejections:

- Alternate stage order → `PIPELINE_WIRE_INVALID` → reject + burn
- Missing required field → `PIPELINE_WIRE_INVALID` → reject + burn
- Unexpected field present → `PIPELINE_WIRE_INVALID` → reject + burn
- `null` in canonical field → `PIPELINE_WIRE_INVALID` → reject + burn
- Non-canonical hex encoding → `PIPELINE_WIRE_INVALID` → reject + burn
- Optional fields in stage output → reject + burn
- Embedded upstream objects (instead of reference) → reject + burn

Full burn is consumed on every terminal outcome. No partial success. No exceptions.
