# AURA_LEDGER_AND_BURN_V1

**Classification:** `ACTIVE AUTHORITY`  
**Layer:** `L4`  
**Purpose:** Define the local ledger and burn rules  
**Status:** `ACTIVE`

> **ACTIVE AUTHORITY — ECONOMIC LAYER**
> This document defines ledger validation and burn calculation rules.
> Full burn is consumed on every terminal outcome (fail-closed).

Implementation:

- Rust meter: `crates/aura_l2_local_chain_v0/src/economic_meter.rs`
- TypeScript: `packages/aura_sdk_v0_ts/src/index.ts`
- Meter parity: `fixtures/economic_admission_v1/meter_vectors.json`
- Historical economic regressions: `fixtures/l2_canonical_pipeline_v1/*`

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

## Metered Work

Canonical production `M` uses the existing burn-metering domain and payload
encoding. `EconomicMeterV1` owns strict binary decoding in Rust; the matching TS
owner exports `decodeEconomicMeterV1` and `encodeEconomicMeterV1`. Both use the
same payload writer as their explicit legacy fixture path. No fixture labels,
declared fees or outer tamper controls enter the canonical type. The two existing
attestation tamper-presence bytes remain fixed zero bytes; nonzero values are
rejected, preserving the original framing and charge size.

Production decoding requires explicit head version 2 and the existing `STARK`
full-verification tariff. `MOCK` and head V1 remain legacy profiles; they are never
inferred or upgraded at canonical entry. This tariff does not make Storm witness
verification a succinct STARK. The burn formula and constants above are unchanged.

Decode with an explicit operator byte bound. Reject truncation, trailing bytes,
invalid UTF-8, noncanonical flags/enums, unsupported versions, unordered or duplicate
accounts, malformed ledger totals and inconsistent structural request variants.
Re-encoding must reproduce every input byte. Preserve evidence payload bytes and
order; evidence normalization and truth/provenance verification happen during
chargeable work, as do transfer nonce and balance checks. Structural admission
does not assert successful execution or authorization.

Meter codec availability alone does not authorize a debit or proof publication.
The durable coordinator below owns those state changes.

## Economic Consent V1

`EconomicConsentV1` contains exactly required string fields
`economic_consent_version = "v1"` and `signature_hex` (64 BIP340 signature bytes,
lowercase hex). Reject unknown, missing, null or aliased fields. No subject, nonce,
intent or proof reference is duplicated into this object. JSON key order is not
a signing input.

Let `T = SHA256(ASCII("AURA_ECONOMIC_CONSENT_V1"))`. Its signed BIP340 message is:

```text
SHA256(T || T || network_byte || u64_le(B) || W || target_proof_hash32)
```

The [pipeline owner](AURA_CANONICAL_PIPELINE_V1.md) owns `W`; `B` is the unchanged
burn computed from `M`, not W/signature/JSON size or Bitcoin fees. The existing
Authorization V2 envelope supplies the target proof reference. Network encoding
remains owned by [the report contract](AURA_REPORT_CONTRACT_V1.md). Verify using
the existing Storm context controller x-only key, which must equal the ledger payer.
Context intent stays opaque and nonce generation stays cryptographically random.

Consent authenticates the exact work, reference and charge, including chargeable
failure. Pre-admission requires both valid signatures and matching context/lineage.
These checks do not verify the actual proof or reserve successful authorization.
The existing [authorization owner](AURA_AUTHORIZATION_LINEAGE_V1.md) still requires
actual proof, material/FractalKey binding, lineage and replay checks before acceptance.
The consent digest is an internal signing message, not a second proof identifier.

Owners: Rust `aura_sdk_v1::economic::EconomicConsentV1`; TS `economicV1.ts`.
`fixtures/economic_admission_v1/contract_vector.json` freezes bytes, charge, digest
and deterministic test signature. The vector secret/nonce are public test material.

## Fail-Closed Rule

Full burn is consumed on:

- `Accepted`
- `ExecutionRejected`
- `VerificationRejected`
- `SettlementRejected`

## Settlement Construction Rule

The [head owner](AURA_CONTINUOUS_SETTLEMENT_V1.md) defines construction from durable
prior state, exact admitted work, outcome and ledger snapshots. Metered linkage is
checked against that state; it cannot choose the successor independently.

## Durable admission and finalization

Rust `aura_sdk_v1::economic::journal::EconomicJournalV1` coordinates one ledger/head
and configured Bitcoin network in the same SQLite database as Authorization V2.
Accounts, balances and supply are coordinated state. Each request selects its
existing payer account through the authenticated controller; payer selection does
not change balances. The unchanged ledger commitment binds that request's payer.

Before admission, require bounded canonical W/M/context, valid ledger structure,
supported policies, exact metering, controller/payer binding and both signatures.
Malformed or unauthenticated input, insufficient burn funds, stale ledger/head or
a busy ledger causes no charge, attempt, head change or authorization reservation.
Transfer nonce/balance errors, false or inconsistent attestations, normalization
failure and failed proof/material verification remain chargeable work outcomes.

Within an immediate transaction, look up `(network, subject, nonce)` before checking
the current ledger snapshot. Identical W and target proof reference with valid
signatures returns or resumes the existing attempt without charging again. A new
signature does not create an attempt. Different work/reference under that tuple
fails, including after terminal rejection. Require exactly one admitted nonterminal
attempt per coordinated ledger/head; competing new work receives busy/no-charge.

Atomically debit B, increase burned supply by B, preserve total supply, persist
exact W and both envelopes plus charge, pre/post debit ledgers and prior head, and
reserve the in-flight slot. Commit before execution. This creates no successful
authorization record. The legacy local execution, attestation normalization/truth,
provenance and settlement-context owners still validate their respective work;
Storm proves its own recurrence, not those ledger transitions.

The service reconstructs the deterministic Storm proof from persisted inputs and
uses the existing proof/material/FractalKey and Authorization V2 verifier. No
external completion, replacement proof or failure message can finish an attempt.
On Accepted, atomically reserve successful authorization, record the terminal
economic result, advance the head, release the slot and persist the existing Bitcoin
request in the outbox. ExecutionRejected, VerificationRejected and SettlementRejected
retain the full debit and atomically advance the head/release the slot, with no new
successful authorization or outbox entry. Existing authorization history is never
deleted. Check attempt ownership, prior head and post-debit ledger under finalization.

Storage failure rolls back its transaction and leaves an already admitted job
pending. Restart resumes it without another debit. Changed resource limits may
defer pending computation; timeout, process death or dependency unavailability does
not invent a terminal result or refund. Corrupt, missing or uninitialized journals
fail closed. Reopening audits the economic chain and authorization/outbox bindings
under a consistent read snapshot. Backup recovery must retain coordinated history.

Accepted means local settlement plus durable publication intent. Bitcoin fee/RPC
errors, delayed publication and reorgs do not change the charge, terminal head or
nonce history. Keep the outbox for retry/rediscovery, including a crash after Core
broadcast but before recording its transaction id. No global nonce uniqueness is
claimed beyond a coordinated journal.

Local burn units and the retained wallet/external-reference metering descriptors
do not create Bitcoin balances, a token bridge or Bitcoin-enforced ledger rules.
The existing anchor wire and validating Core observer retain their own authority.
