# AURA_INVARIANTS_V1

**Classification:** `VALIDATION`  
**Purpose:** List the non-negotiable system invariants  
**Status:** `ACTIVE`

> **VALIDATION — SYSTEM INVARIANTS**
> This document lists the non-negotiable invariants enforced by the active protocol.
> These invariants are derived from the root authority (AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2).

## Core

- `AURA_HASH_V2` owns the existing SHA3-512-based H_521 field derivation; each
  purpose-specific message, trace, material, proof, signature and head hash retains
  its own algorithm/framing. H_521 does not replace their SHA256/SHA3-256 bindings.
- Frozen HASH_V1 message encodings and outputs remain unchanged under their owner.
- `MESSAGE_ROOT` uses exactly one `u64_le` length prefix.
- text mode is NFC + LF with BOM rejection only.

## Storm

- field elements are canonical 66-byte values below `2^521 - 1`
- `STORM_V1_1` uses only the fixed domain-separated derivations
- `TRACE_ROOT` is the ordered SHA3-256 Merkle root of the full trace
- `StormClaim521V1` reproduces the derived initial state, final state, and `TRACE_ROOT`
- `StormPublicInputs521V1` binds side hashes, context hash, boundary states, and `TRACE_ROOT`

## Pipeline

- `proof_hash_hex` is canonical lowercase 64-hex; intent identity lives only in
  Authorization V2 lineage. Retired envelope-level intent/session aliases are not
  canonical entry fields.
- each canonical object owns exactly one representation of each concept
- downstream canonical objects reference upstream artifacts by `proof_hash_hex`; they do not embed
  exact nested copies of upstream canonical objects
- canonical UDOT is v2-only, derived from `proof_hash_hex`, and carries no `aura_hash_hex` alias
  or canonical `matrix_form`
- canonical authorization lineage has exactly one six-field encoding
- legacy adapters remain outside canonical entry; no implicit upgrade or normalization
- unknown wire fields are rejected

## Ledger And Settlement

- `sum(account.balance) + burned_supply = total_supply`
- the payer account exists before burn
- separately authenticated economic consent binds exact work, reference and charge
- full burn is consumed on every admitted terminal outcome; pre-admission errors do not debit
- one nonterminal economic attempt owns a coordinated ledger/head; retry does not reburn
- successful authorization, terminal Accepted, head and outbox commit atomically
- settlement head sequence is derived from the prior head
- previous head hash is derived from the prior head

## Coordinated mining

Derived from [the miner owner](AURA_AURAFARMING_NODES.md): exact signed-job profile
and actual PoC verification precede winner eligibility; a low reference is only a
filter. One journal owns admission, winner and reward obligation without a second
economic path. Frozen crypto/head/anchor identities remain unchanged. Replay,
publication and reorg tests must preserve the same charge and entitlement.
