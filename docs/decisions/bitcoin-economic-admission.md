# Bitcoin migration: economic admission boundary

**Status: PROPOSED — NOT APPROVED.** This is a decision request, not protocol
authority or permission to change ledger/burn behavior. Existing authoritative
owners continue to govern. No new economic implementation accompanies this proposal.

## Decision required

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

This direction requires a bounded contract review before code: define the exact
payer-to-subject binding, authenticated economic request and consent bytes,
metering inputs for the preserved Storm backend, failed-attempt identity, and
crash/terminal-outcome handling. Preserve the existing burn constants, balance and
supply invariants, Storm bytes, proof/material hashes, authorization v2 message and
Bitcoin anchor wire. If a reviewed design cannot satisfy those constraints, bring
the precise conflict back for approval rather than silently adjusting them.

After approval, the ledger, authorization, pipeline and continuous-settlement
owners must each describe their own portion once. This proposal must not become
a parallel authoritative specification.
