# AURA_FAILURE_CLASSES_V1

**Classification:** `VALIDATION`  
**Purpose:** Define the canonical failure classes  
**Status:** `ACTIVE`

> **VALIDATION — FAILURE CLASSIFICATION**
> This document defines all canonical failure classes and their settlement outcomes.
> Acceptance is fail-closed. An authenticated chargeable failure consumes its burn
> without successful authorization; publication failure does not undo Accepted.

## Classes

- `HASH_INPUT_INVALID`: length overflow or malformed raw input
- `HASH_TEXT_INVALID`: invalid UTF-8 or BOM in text mode
- `FIELD_ENCODING_INVALID`: invalid top bits, out-of-range value, or non-canonical field bytes
- `STORM_CONTEXT_INVALID`: invalid length, version byte, or execution domain
- `STORM_CLAIM_INVALID`: invalid version, modulus id, boundary state, or `TRACE_ROOT`
- `TRACE_COMMITMENT_INVALID`: invalid row width, leaf order, or Merkle construction
- `PROVER_BINDING_INVALID`: malformed canonical proof input or broken cryptographic binding between compact public inputs, boundary states, and `TRACE_ROOT`
- `UDOT_INVALID`: malformed canonical v2 glyph encoding or invalid canonical matrix sequence
- `PIPELINE_WIRE_INVALID`: missing required field, unexpected field, `null`, or non-canonical hex/reference encoding
- `AUTHORIZATION_INVALID`: malformed envelope/lineage/reference, invalid signature,
  actual proof/material/lineage mismatch or replay conflict. Same-action retry is valid.
- `LEDGER_INVALID`: payer missing, duplicate account, unsorted account list, or supply mismatch
- `BURN_INVALID`: invalid burn arithmetic or partial-burn attempt
- `SETTLEMENT_INVALID`: malformed settlement reference, malformed head derivation input, or invalid commitment configuration
- `ECONOMIC_ADMISSION_INVALID`: invalid consent/work, unsupported policy, resource
  limit, payer mismatch, insufficient burn funds, stale snapshot, busy ledger or
  conflicting attempt identity; no debit or new economic record
- `ECONOMIC_EXECUTION_REJECTED`: admitted transfer, evidence normalization/truth or
  provenance failure; retain full burn, advance head, no new authorization/outbox
- `ECONOMIC_VERIFICATION_REJECTED`: admitted actual proof/backend/witness/digest,
  material/FractalKey/lineage or authorization replay failure; retain full burn
- `ECONOMIC_SETTLEMENT_REJECTED`: verified work rejected by local batch/parent,
  wallet or external-descriptor settlement rules; retain full burn
- `JOURNAL_UNAVAILABLE`: missing, corrupt, uninitialized or failed storage. Fail
  closed; an already committed admitted attempt remains pending for recovery.
- `BITCOIN_PUBLICATION_UNAVAILABLE`: transport, fee or chain-observation failure;
  retry the durable outbox without changing the terminal outcome or nonce history

## Miner failure mapping

The [miner owner's lifecycle](AURA_AURAFARMING_NODES.md#6-lifecycle-accounting-and-head-competition)
uses these existing classes. Invalid jobs/profiles, expired/stale rounds and
above-target references are pre-admission failures. An admitted fabricated low
reference becomes verification rejection and retains the charge. Round contention
does not invent another terminal outcome. Corrupt round/payment state is journal
unavailability; an unknown reserved-input spend produces operational
`RecoveryRequired` under publication unavailability. It never authorizes replacement
funding, a refund or another winner. No new canonical error wire is introduced.

## Excluded Classes

Failure classes for duplicated representations, equivalence mismatch, or cross-representation drift
are invalid by design and do not exist in the canonical system.

Historical `HEAD_INVALID` labels do not define V2 acceptance. V2 checks malformed
heads and metered linkage as above; construction itself derives the successor.
