# AURA_FAILURE_CLASSES_V1

**Classification:** `VALIDATION`  
**Purpose:** Define the canonical failure classes  
**Status:** `ACTIVE`

> **VALIDATION — FAILURE CLASSIFICATION**
> This document defines all canonical failure classes and their settlement outcomes.
> All failures are fail-closed. No partial success is permitted.

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
- `AUTHORIZATION_INVALID`: malformed canonical lineage encoding or malformed canonical proof reference
- `LEDGER_INVALID`: payer missing, duplicate account, unsorted account list, or supply mismatch
- `BURN_INVALID`: invalid burn arithmetic or partial-burn attempt
- `SETTLEMENT_INVALID`: malformed settlement reference, malformed head derivation input, or invalid commitment configuration

## Excluded Classes

Failure classes for duplicated representations, equivalence mismatch, or cross-representation drift
are invalid by design and do not exist in the canonical system.

`HEAD_INVALID` is retired because canonical settlement construction does not admit independently
encoded previous-head or sequence fields.
