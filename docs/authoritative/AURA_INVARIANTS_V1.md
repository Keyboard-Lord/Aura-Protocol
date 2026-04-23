# AURA_INVARIANTS_V1

**Classification:** `VALIDATION`  
**Purpose:** List the non-negotiable system invariants  
**Status:** `ACTIVE`

> **VALIDATION — SYSTEM INVARIANTS**
> This document lists the non-negotiable invariants enforced by the active protocol.
> These invariants are derived from the root authority (AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2).

## Core

- `HASH_V2` is the sole active canonical identity function (521-bit SHA3-512-based).
- `HASH_V1` is FROZEN LEGACY, maintained for historical reference only.
- The active protocol uses `H_521(m) = Reduce_N(SHA3-512(m))` exclusively.
- `MESSAGE_ROOT` uses exactly one `u64_le` length prefix.
- text mode is NFC + LF with BOM rejection only.

## Storm

- field elements are canonical 66-byte values below `2^521 - 1`
- `STORM_V1_1` uses only the fixed domain-separated derivations
- `TRACE_ROOT` is the ordered SHA3-256 Merkle root of the full trace
- `StormClaim521V1` reproduces the derived initial state, final state, and `TRACE_ROOT`
- `StormPublicInputs521V1` binds side hashes, context hash, boundary states, and `TRACE_ROOT`

## Pipeline

- `proof_hash_hex`, `intent_id_hex`, and `proof_session_id_hex` are canonical lowercase 64-hex
- each canonical object owns exactly one representation of each concept
- downstream canonical objects reference upstream artifacts by `proof_hash_hex`; they do not embed
  exact nested copies of upstream canonical objects
- canonical UDOT is v2-only, derived from `proof_hash_hex`, and carries no `aura_hash_hex` alias
  or canonical `matrix_form`
- canonical authorization lineage has exactly one six-field encoding
- legacy normalization and version selection happen before canonical pipeline entry
- unknown wire fields are rejected

## Ledger And Settlement

- `sum(account.balance) + burned_supply = total_supply`
- the payer account exists before burn
- full burn is consumed on every terminal outcome
- settlement head sequence is derived from the prior head
- previous head hash is derived from the prior head
