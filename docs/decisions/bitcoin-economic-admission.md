# Bitcoin migration: economic admission boundary

**Status: APPROVED FOR IMPLEMENTATION.** Following the direction approval on
2026-09-09, the user explicitly approved the complete contract below, including
EconomicConsentV1, W, payer/signature binding, tariffs, attempt identity, atomic
charging/finalization, recovery and settlement head V2 with explicit V1 migration.
Preserve burn invariants, Authorization V2 acceptance order, Storm/proof semantics,
FractalKey/proof identity and the Bitcoin anchor wire. Economic consent remains
distinct from successful proof authorization. Approval is not evidence that the
coordinator is implemented; implementation status is tracked in
`aura-runtime/SLICE.md`. Existing authoritative owners receive each implemented
definition once. This decision retains the approved design and rationale.

## Original decision

Choose the charging authority and admission lifecycle that connects the existing
local ledger/burn rules to Storm proof verification, BIP340 authorization and
Bitcoin publication. Approving a Bitcoin anchor or signature does not specify who
may debit a payer, what request is metered, or how rejected attempts are charged.

## Current evidence and constraints

- [Ledger owner](../authoritative/AURA_LEDGER_AND_BURN_V1.md) requires the existing
  deterministic burn formula and full burn on Accepted, ExecutionRejected,
  VerificationRejected and SettlementRejected terminal outcomes. Local units are
  distinct from Bitcoin miner fees; the approved anchoring decision creates no
  Bitcoin burn, token bridge or Bitcoin-enforced balance ledger.
- `crates/aura_l2_local_chain_v0/src/lib.rs` owns `CanonicalPipelineLedgerPolicyV1`
  (payer account, balances and supply), `compute_canonical_pipeline_burn_units_from_inputs_v1`,
  and `canonical_pipeline_burn_metered_bytes_v1`. Its metered bytes contain the
  local execution/attestation request, proof-system selector, accounts, prior head,
  wallet/token bindings and transaction data. A Storm proof byte count is not an
  equivalent input to this existing function.
- [Authorization owner](../authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md) requires
  signature, actual proof, material and lineage verification before nonce
  reservation. `AuthorizerJournalV2::accept` implements that order. Rejected proofs
  do not reserve authorization nonces. Accepted retries are idempotent, and reorgs
  cannot release reservations.
- The approved lineage has an opaque intent commitment. It does not yet define an
  economic request encoding, payer-to-subject relation, spending consent, or burn
  admission record. Inferring any of these from an arbitrary 32-byte intent would
  introduce unapproved semantics.
- The active Storm backend replays its witness. It does not prove the local
  runner's ledger transitions or implement its cat-map Winterfell proof selection.
  Wiring those outputs together without an explicit binding would not establish
  that the charged request and the authorized proof describe the same action.

## Viable directions

| Direction | Benefit | Tradeoff and required approval |
| --- | --- | --- |
| Authenticated economic admission before execution/proof verification; durable burn records and separately tracked successful authorization | Preserves charging on terminal failures while preventing an unauthenticated request from charging someone else's account; permits atomic, restart-safe accounting | Requires a reviewed economic consent/request contract, payer mapping, exact metering input and retry identity. A failed economic attempt must not be represented as successful authorization. |
| Operator-sponsored execution using an explicitly designated payer | Retains local burn behavior without asserting that a signature grants spending authority over an arbitrary account | Operator funds all admitted failures. Requires explicit sponsorship and admission limits, and still needs an exact request/proof binding and durable accounting. |
| Charge only after valid proof acceptance | Fits the existing successful-authorization transaction most simply | Changes the required full-burn failure semantics. It is a protocol change, not an implementation-only migration. |

## Recommendation

Choose authenticated economic admission before execution/proof verification, with
durable economic records distinct from successful authorization reservations.
This preserves the intended failure charging rule and the approved authorization
acceptance order. Use one transactional persistence owner where atomic changes
are needed; distinguish economic records from authorization records, not separate
uncoordinated writers. Reorgs must not reopen either completed economic attempts
or authorization reservations, and retrying the same attempt must not burn twice.

The following sections record the approved contract. They do not replace the
existing canonical authorization or claim objects, or introduce another proof hash.

During implementation, the ledger, authorization, pipeline and continuous-settlement
owners must each describe their own portion once. This decision must not become
a parallel authoritative specification.

## Approved ownership and inputs

Economic admission is the single production coordinator around the existing
execution, ledger, Storm, authorization and publication owners. It uses one durable
database transaction owner. Standalone hash/proof/codec helpers remain usable as
primitives; they do not constitute economic admission.

The caller supplies four separate inputs: the configured Bitcoin network, a
canonical work request byte string `W`, `EconomicConsentV1`, and the existing
Authorization V2 envelope. There is no nested proof, authorization envelope or
anchor request in the consent object. The client prepares the deterministic Storm
proof reference and both signatures before submission; service admission precedes
service execution and proof verification. Receiving those signatures is not
successful authorization.

The exact consent envelope is now owned by [the economic owner](../authoritative/AURA_LEDGER_AND_BURN_V1.md#economic-consent-v1).

### Work bytes and preserved metering

The exact W framing is now owned by [the canonical pipeline](../authoritative/AURA_CANONICAL_PIPELINE_V1.md#approved-economic-work-boundary).

`M` is the existing canonical burn-metering byte string emitted by
`canonical_pipeline_burn_metered_bytes_v1`, including its existing domain. Its
encoding remains owned by the ledger/metering implementation, not redefined here.
Extract that owner and its checked decoder without changing its bytes. Keep the
old fixture JSON, tamper knobs and expected-result labels outside canonical entry.
An explicitly invoked legacy adapter may produce `M`; canonical admission must
decode and validate `M` directly, reject trailing/noncanonical encodings, and never
repair order, duplicate accounts, or malformed values. Decoder round-trip equality
is required but is not a substitute for ledger and request semantic validation.

The remaining fields reuse the existing `StormExecutionInputsV1` and context
encodings. They are supplied explicitly, not derived through a new side-input hash
or by rewriting the context. The work request has one binary representation; any
file transport uses those bytes, not an alternate JSON projection.

Compute charge `B` using the existing checked burn function and the decoded `M`:
the original request-kind units, transaction count and `len(M)` remain the inputs.
Do not meter JSON formatting, consent/signature bytes, Bitcoin fees or the wrapper
length instead. The canonical production proof always receives actual Storm
verification. The retained full-verification tariff is 3 units; the historical
`STARK` metering selector denotes that tariff here, not a claim that witness replay
is a succinct STARK. `MOCK` remains a historical test tariff and is rejected at this
production boundary. This explicit tariff mapping is part of the approved contract.

This preserves existing economic metering rather than inventing an iteration-based
fee. Explicit operator iteration, byte and work limits apply before admission;
adjusting those limits does not redefine `B`.

### Payer and signature

The payer account identifier is exactly the BIP340 x-only key in
`StormContextV1.controller_id`. It must identify the payer in `M` and the current
durable ledger. No implicit delegated payer, key translation, or Bitcoin-address
mapping is permitted in this contract.

The attempt nonce is the existing context's `freshness_nonce`; producers generate
it cryptographically at random under the existing authorization requirement. The
context's intent remains opaque application identity. This contract introduces no
second intent commitment, economic proof hash, or inferred intent preimage.

The economic owner now defines the exact tagged signing message and payer binding. Consent authenticates work, target and charge separately from successful authorization.
Authorization V2 keeps its existing tag and message bytes unchanged.

## Admission, retry and outcomes

1. Before a debit, enforce resource bounds; decode canonical work/context; validate
   payer/key, supported policy/versions, structural validity, exact metering and
   consent signature. Also require canonical Authorization V2 shape and a valid
   signature for this network, with subject/nonce/intent equal to the work context.
   Proof/material verification and successful authorization reservation still
   occur later. There is no admitted state waiting for another client signature.
   Malformed, unauthenticated or inadmissible requests are pre-admission errors:
   no economic record, balance change, head transition or authorization reservation.
   Invalid transfer nonces/balances, false or inconsistent attestation claims and
   failed computation/proof verification remain chargeable execution/verification
   outcomes. Do not move those checks into the free structural-admission phase.
2. Begin an immediate database transaction. Look up the economic attempt key
   `(network, subject, nonce)` before testing a new request's ledger snapshot.
   A byte-identical `W` and identical target proof reference with valid signatures
   is a retry: return/resume its recorded
   state without another charge, including when the original ledger has advanced.
   A different `W` or target reference under that key is a conflict and cannot
   charge again. Independently re-signing the same work/reference is not a new attempt.
3. Each coordinated economic ledger/head permits exactly one admitted, nonterminal
   attempt. A different attempt while that slot is occupied receives a pre-admission
   busy response and no charge. Retry/recovery of the occupying attempt remains
   available. This intentionally serializes finalization; parallel workers do not
   grant concurrent ownership of one ledger/head.
   For a new attempt, validate its ledger/prior-head inputs against the coordinated
   durable state while holding the transaction. Insufficient funds or stale state
   rejects admission. Atomically debit exactly `B`, increase burned supply by `B`,
   preserve total supply, and store the exact work, both envelopes and charge record.
   Reserve the in-flight slot in that same transaction, and persist the pre/post
   debit ledger snapshots and the durable prior head. Commit before starting
   chargeable execution. No successful-authorization row
   is created at this point.
4. Execute the admitted economic work using its existing owner. Execute the supplied
   Storm input tuple and produce its deterministic canonical witness-backend proof
   through the existing owner; verify that actual proof and its exact expected claim.
   Reconstruct its material/FractalKey reference and require equality with the target
   signed by both envelopes. A mismatch is attributable to authenticated admission
   and records VerificationRejected; it does not authorize the target reference.
   The service does not accept externally supplied replacement proof/completion
   material for this admitted job. Standalone proof verification remains a primitive.
5. Internal workers finalize only the exact persisted attempt they own. An
   unauthenticated completion message cannot terminate it. Authenticated work that
   reaches ExecutionRejected, VerificationRejected or SettlementRejected consumes
   the same full charge already recorded and creates no successful authorization.
   The terminal-failure transaction records its outcome, advances the economic
   head and releases the in-flight slot atomically. It neither debits again nor
   emits an anchor request. Failure outcomes advance the head as successful ones do.
6. For a successful local settlement, perform the existing proof/signature/material/
   lineage checks before authorization reservation. Atomically record the successful
   authorization reservation, terminal Accepted economic outcome, existing local
   head transition, releases the in-flight slot, and writes an outbox entry
   containing the existing Bitcoin anchor request. The outbox is durable before
   any publication side effect. The finalizer checks its recorded attempt ownership
   and prior-head identity under the same transaction before making these changes.

Economic attempt records and successful authorization reservations use separate
tables/state domains even when their tuple values coincide. A failed economic
attempt is never represented as a successful authorization reservation. Economic
retry restrictions do not release or modify previously accepted authorization
reservations. Neither table claims uniqueness beyond its coordinated journal.

The work/consent record authenticates the association between economic work and
the supplied Storm inputs. Storm still proves only its existing recurrence/claim;
it does not thereby become a STARK for local ledger transitions. The local execution
and ledger owners must independently validate those transitions. Reports must make
that verification boundary explicit.

### Completion attribution and liveness

Both signatures and the target reference are available before the first debit.
Economic consent binds the target even before the proof/material check binds the
mutable lineage fields of Authorization V2. The service reconstructs its proof from
the signed input tuple rather than allowing a third party holding public consent
to choose bad completion bytes. Retries cannot replace the stored work or target.
Thus a disconnected client cannot leave the ledger waiting for a future signature.

The successful path still performs every existing Authorization V2 acceptance
check before writing its reservation. Early signature checks do not replace actual
proof verification, material/lineage binding or replay checks. No alternate material
hash or new Storm proof-generation algorithm is introduced.

### Head construction and metered linkage

The head hash and sequence present inside `M` are signed metering evidence only.
Compare them with linkage derived by the head owner from the durable prior head;
never use them as caller-selected inputs to settlement construction. Canonical
construction consumes the durable prior head and the finalized economic outcome.

The approved contract includes an explicit successor head format. The old
local head preimage includes a fixture-oriented request digest and report digest;
the request digest includes fixture name, tamper knobs and expected-result fields
that are deliberately absent from `W`. It cannot be reused unchanged by inventing
hidden fixture defaults. Preserve its historical vectors and classify that format
as legacy alongside the approved successor.

The approved successor is `settlement_head_version = 2`. Its formulas, exact fields, genesis and explicit predecessor migration are now owned by [continuous settlement](../authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md). These local head values are not proof references or Bitcoin wire fields. Historical head bytes remain unchanged.

## Recovery and publication

- Crash before admission commit: no charge or attempt exists. Crash after commit:
  replay the durable admitted work without charging again. Preserve deterministic
  intermediate results or recompute them through their original owners.
- Pending execution or an unavailable dependency remains pending. Process death,
  observation timeout or operator restart alone is not a terminal work outcome.
  There is no automatic refund, nonce release or failure inferred from missing
  worker activity. A terminal result is recorded exactly once.
- Resume successful publication from the outbox. A crash after Core accepted a
  transaction but before recording its observation may require rediscovery or
  duplicate publication; neither creates a new charge or authorized action.
- Accepted denotes validated local settlement with durable publication intent.
  Core unavailability, fee-policy rejection and reorgs affect publication/confirmation
  state, not the already terminal local economic outcome. Local SettlementRejected
  must be decided before a successful authorization/outbox transaction.
- Open only an explicitly initialized journal. Missing, corrupt, incompatible or
  incompletely restored state fails closed. Backup recovery must preserve both
  economic attempts and successful authorization history consistently.

## Review and implementation acceptance

The user approved the exact consent message, work framing, payer mapping, tariff,
head successor and admission lifecycle. Update the existing owning authoritative documents; keep this file as the
decision record rather than a second protocol definition.

Required evidence before calling the economic migration implemented:

- Rust/TypeScript equality for `M`, `W`, `B`, signing digest and consent signature;
  preserved metering/burn fixtures, plus valid and invalid consent vectors.
- Mutation of every signed input; wrong payer/network; malformed and overflowing
  lengths/amounts; missing/extra consent fields; invalid ledger and stale snapshot.
- All four terminal outcomes debit once and preserve supply. Invalid consent and
  pre-admission failures debit nothing. Failed work creates no authorization row.
- Same-work retries, changed-work nonce conflicts, independently re-signed retries,
  concurrent workers and restart recovery at each transaction boundary.
- Copied consent cannot replace stored work/target or inject a rejected completion.
  A valid proof reference for a different tuple cannot complete the paid work.
  Client disconnection after admission does not block signature acquisition.
- Actual consent → debit → work/proof verification → Authorization V2 → outbox →
  Bitcoin regtest publication, including crash recovery and reorg retry without a
  second burn or released authorization reservation.
- One production coordinator; no canonical command may bypass economic admission
  when presenting itself as the complete protocol pipeline. Preserve separately
  named verification primitives and explicit historical fixtures for regression.
