# AURA_LEDGER_AND_BURN_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L4`  
**Purpose:** Define the local ledger and burn rules  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — ECONOMIC LAYER**
> This document defines ledger validation and burn calculation rules.
> Full burn is consumed on every terminal outcome (fail-closed).

Implementation:

- Rust: `crates/aura_l2_local_chain_v0`
- TypeScript: `packages/aura_sdk_v0_ts/src/index.ts`
- Frozen fixtures: `fixtures/l2_canonical_pipeline_v1/*`

## Request Fields

The request carries:

- `economic`
- `accounting`
- `ledger`

`burn_intent` is `canonical_report`.

`payment_intent` is `burn_to_produce_canonical_truth`.

`settlement_intent` is `record_canonical_outcome`.

## Ledger Rules

The ledger is valid only when:

- `ledger_policy_version = 1`
- accounts are ordered
- account ids are unique
- the payer account exists
- `sum(account.balance) + burned_supply = total_supply`

## Burn Function

`burn_units = 10 + request_kind_units + proof_system_units + 4*tx_count + ceil(metered_request_size_bytes / 32)`

Where:

- `request_kind_units(execution) = 5`
- `request_kind_units(attestation) = 2`
- `proof_system_units(stark) = 3`
- `proof_system_units(mock) = 1`

## Fail-Closed Rule

Full burn is consumed on:

- `Accepted`
- `ExecutionRejected`
- `VerificationRejected`
- `SettlementRejected`

## Settlement Construction Rule

Local settlement consumes a canonical report together with a prior head object.

Caller-supplied previous-head and sequence fields are not part of canonical settlement
construction.
