# AURA_REPORT_CONTRACT_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L3`  
**Purpose:** Define the final pipeline settlement object  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — SETTLEMENT WIRE FORMAT**
> This document defines the canonical settlement request format.
> Only proof_hash_hex is carried on-chain. No embedded upstream objects.

Implementation:

- Rust: `crates/aura_sdk_v1/src/settlement.rs`
- TypeScript: `packages/aura_sdk_v1_ts/src/index.ts`
- Frozen fixture: `fixtures/v1/canonical_pipeline_v1/solana_settlement_request_v1.json`

## Final Object

`SolanaSettlementRequestWireV1` is:

- `settlement_version`
- `solana_rpc_url`
- `commitment_config`
- `proof_hash_hex`

## Wire Rules

- `settlement_version` MUST be `v1`
- `solana_rpc_url` MUST be present and MUST NOT be `null`
- `commitment_config` MUST be `processed`, `confirmed`, or `finalized`
- `proof_hash_hex` MUST be canonical lowercase 64-hex
- unexpected fields are invalid

## Reference Rule

The final object carries only the canonical proof reference.

It MUST NOT embed:

- `stark_proof_envelope`
- `authorization_intent`
- `udot_bundle`
- any other upstream canonical object

## Fail-Closed Enforcement

**MUST:** Any settlement wire deviation results in immediate fail-closed rejection.

Specific rejections:

- Invalid settlement_version → `SETTLEMENT_INVALID` → reject + burn
- Missing proof_hash_hex → `SETTLEMENT_INVALID` → reject + burn
- Non-canonical hex encoding → `SETTLEMENT_INVALID` → reject + burn
- Embedded upstream objects → `SETTLEMENT_INVALID` → reject + burn
- Unexpected fields → `SETTLEMENT_INVALID` → reject + burn

Full burn consumed on all terminal outcomes. No settlement without valid proof reference.
