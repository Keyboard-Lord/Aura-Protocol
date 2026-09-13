# C2 — Approval and freeze evidence

Classification: IMPLEMENTATION / APPROVAL EVIDENCE; NON-AUTHORITATIVE.
Date: 2026-09-12. C2 DONE; C3 READY, not started.
DOC = CODE for C2 codecs and durable lifecycle. Real workloads/payment remain C3 work.

Definitions now live solely in the registered
[compute owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md#c2-assignment-receipt-and-verified-result),
with transaction ownership in the
[existing ledger owner](../docs/authoritative/AURA_LEDGER_AND_BURN_V1.md#useful-compute-coordinator-extension).
The prior proposal is retained in repository history, not as parallel authority.

## Controlling approval

The user APPROVED C2-D1 and C2-D2 as documented, then explicitly clarified:

- Distinct assignment, receipt and verified-result objects/signature domains; one
  canonical result commitment, with operational hardware/time telemetry outside it.
- Exactly one durable assignment and immutable timely receipt for each signed job.
- Full net compensation plus the signed fee allowance is reserved **at assignment**.
  An open registered request alone is not funded and authorizes no execution.
- Timely pending verification keeps funding reserved. Accepted work earns full net
  compensation. Terminal retry requires a new signed job/nonce and new lifecycle.
- Exact-transition retries are idempotent; they cannot create duplicate assignments,
  receipts, entitlements or payments. A replayed acknowledgement is not a new lease.
- Existing C1/Miner/Aura semantics remain unchanged. Freeze is conditional on parity,
  negative vectors, replay, funding and crash/recovery evidence.

The at-assignment timing supersedes the earlier draft table's pre-assignment wording.
No payout script, concrete funding coin, deployment confirmation count, fee ceiling,
retention default, live monetary workload or public worker execution was selected.

## Implementation

- [Rust lifecycle owner](../crates/aura_sdk_v1/src/compute_result.rs) and
  [TypeScript counterpart](../packages/aura_sdk_v1_ts/src/computeResultV1.ts) implement
  strict encodings, content commitments, separate signature roles and resolved
  lineage. Shared C1 content framing was factored into one helper without changing
  its bytes. Canonical objects have no serde/JSON wire or telemetry fields.
- [Journal extension](../crates/aura_sdk_v1/src/economic/journal/compute/mod.rs)
  explicitly installs compute state inside EconomicJournalV1. Complete bounded
  content/output/evidence are stored in the existing SQLite transaction system.
  There is no second ledger, authorizer, filesystem execution area or Bitcoin writer.
- [Operations](../crates/aura_sdk_v1/src/economic/journal/compute/operations.rs)
  enforce authenticated registration, storage-budget preflight, measured-capability
  eligibility, single assignment, receipt immutability, trusted receipt time,
  internal verification, cancellation/expiry and atomic result/entitlement retention.
  No public accepted=true or paid=true method exists.
- [Custody token](../crates/aura_sdk_v1/src/economic/journal/compute/funding.rs)
  validates trusted Core observations and locks explicit customer backing. The token
  cannot be fabricated through client deserialization. Funding reserves net and fee
  separately, including exactly zero fees. It does not construct a payment.
- [Shared ownership guard](../crates/aura_sdk_v1/src/economic/journal/funding_registry.rs)
  prevents compute/miner backing collisions in both directions. Existing miner open
  and funding-release paths gained only this guard; shared exact amount/network
  helpers retain their original behavior.

Opening validates schema, configuration, canonical bytes/signatures, content and
index consistency, replay scopes, reservation ownership, lifecycle and entitlement.
Infrastructure errors preserve pending verification and its reservation. Only a
registered verifier's rejection creates an invalid-result terminal state. Earned
funding cannot be released; no customer acknowledgement can veto acceptance.

## Validation evidence

Reproduce: `node scripts/verify_compute_result_v1.mjs`.
[Recorded full gate](compute_network_v1/c2_freeze_results.json): PASS, nine stages.
It embeds the passing C1 gate and records commands, environment and fixture hashes.

| Check | Passed |
| --- | --- |
| Rust C2 canonical vectors/mutations | 5 |
| Independent TS C2 parity/mutations | 6 |
| Rust C2 journal lifecycle | 12 |
| Compile-fail: backing cannot deserialize client claims | 1 |
| Existing miner journal regression | 32 |
| Existing economic journal regression | 12 |
| Frozen C1/M2 gate | 10 + 9 Rust; 13 + 10 TS |
| Affected SDK library/examples, TS syntax and public exports | Passed |

The 12 journal tests include one subprocess entry point and a parent test that
executes 11 real process-exit cases. Counts do not substitute for their coverage.
Environment: macOS arm64, Node v22.22.2, rustc 1.88.0. Native Node TS checks are not
represented as a standalone tsc typecheck. No full Bitcoin migration gate was rerun.

[Shared vectors](../fixtures/compute_result_v1/result_vectors_v1.json) cover three
resolved assignment/receipt/result chains, all detached signature roles, cancellation,
resource-accounting extremes and existing C1 result-to-signed-miner side expansion.
Rust sha2/libsecp256k1 and TS Node SHA256/Noble independently reproduce complete
byte strings, signatures, commitments and mutation classifications. Test-only
requester/worker keys and amounts are not production settings or real accepted work.

Security/failure evidence:

- Every lifecycle byte and detached signature byte mutated; all truncations,
  trailing bytes, invalid versions/verdicts/keys and TS extra/missing/accessor/coercion
  cases rejected or detected through binding. Same-key cross-role signatures fail.
- Wrong job, worker, program, receipt, output/evidence and resource counts reject.
  Signature re-randomization changes no result commitment. Telemetry is rejected
  from canonical objects, not silently normalized away.
- New jobs acquire funds at assignment; duplicate assignment, competing workers,
  cancellation/assignment races, distinct receipt races and concurrent verifiers
  cannot create a second owner/result/entitlement. Failed jobs cannot recycle.
- Exact retries survive restart and deadlines. A timely receipt survives expiry and
  verifier infrastructure failure. Late/partial/unauthenticated input cannot consume
  a receipt slot; an immutable invalid proof cannot be replaced with a valid one.
- Wrong network, spent/unsafe/ambiguous/malformed backing, lock failure, insufficient
  net-plus-fee, zero fee and oversized sums checked. Real journal APIs reject both
  compute-first and miner-first collisions using explicit Core test responses.
- Process exit before/after reservation, assignment commit, receipt commit,
  during verification, after result, after entitlement and around final commit:
  reopening preserves the correct pending/terminal state and resumes once.
- Corrupt record/index/artifact, missing entitlement and partial schema fail closed.
  No split result/entitlement survives restart. Host storage capacity and assignment
  timing reject before funding or worker execution authorization. Slow custody
  verification cannot backdate assignment: trusted time is checked again before
  persistence, and deadline crossing or clock regression aborts the assignment.
- Ordinary compute preserves Aura ledger balances, prior head, economic attempts,
  authorization nonce count and Bitcoin outbox. No automatic burn or Head advance.

## Frozen baseline and remaining boundaries

C1/M2 fixtures and all earlier Aura fixtures remain byte-identical. HASH_V2, field,
Storm/TRACE_ROOT, proof/material/FractalKey/proof_hash, Authorization V2, burn tariff,
Head V2, UDOT and Bitcoin anchor definitions/bytes are unchanged. The existing SDK
and journal received additive compute integration only. No mining execution change.

C2 uses a sealed deterministic replay adapter compiled exclusively for tests.
Production has no registered workload until C3 supplies the reviewed real proving
backend, capability/isolation checks and GPU path. This is not a ZK or useful-work
performance claim. Customer-facing authenticated delivery routing and actual compute
payment publication/discharge remain unimplemented; accepted obligations stay owed.
No caller can declare them paid. Real payment must extend the existing shared owner.

Core RPC fixtures establish the custody adapter checks, not live Bitcoin funding.
The host must attribute customer custody correctly and reconcile wallet locks after
ambiguous commits/restart. Whole coherent database rollback needs verified external
backup provenance; checksums do not establish anti-rollback or trustless escrow.
No live funds, public worker execution or deployment defaults were activated.

Local links, authoritative ownership, proposed/frozen layout correspondence and
whitespace are checked at closure. No additional benchmark was required in C2;
recorded gate timings are test execution evidence only.

## Milestone boundary

C0 DONE; C1 DONE; C2 DONE; C3 READY; C4–C10 BLOCKED. Stop here.
C3 is the next Priority 0 real proving adapter milestone. It was not started.
