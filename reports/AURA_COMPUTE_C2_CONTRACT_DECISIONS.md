# C2 — Worker/result contract decisions

Classification: APPROVED IMPLEMENTATION DIRECTION / EVIDENCE; NON-AUTHORITATIVE.
Date: 2026-09-12. C2 IN PROGRESS; C2-D1/D2 APPROVED; implementation and freeze evidence pending.
C1 remains DONE and frozen. No C2 runtime or canonical wire is implemented here.

## Scope and direct evidence

The [C1 owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md) freezes request
identity, core policy promises and result-to-miner side expansion. It explicitly
leaves the result preimage, assignments, durable receipts and lifecycle to C2.
[C0 approval](AURA_COMPUTE_NETWORK_V1.md#9-controlling-approval-record--d1d4-approved)
requires one coordinator, independent compensation and hardware-neutral meaning.

| Direct owner | Evidence and consequence |
| --- | --- |
| [Compute codec](../crates/aura_sdk_v1/src/compute_job.rs) | C1 request authentication, pure retry comparison and supported policies exist; no worker/result contract. Reuse unchanged. |
| [EconomicJournalV1](../crates/aura_sdk_v1/src/economic/journal.rs) | Owns the existing SQLite connection. `admit_with_clock` debits burn; `finalize` advances the head. Ordinary compute must extend this owner with its own authenticated operations, not invoke those effects. |
| [Miner coordination](../crates/aura_sdk_v1/src/economic/journal/miner.rs) | Atomic owner/obligation transactions and funding uniqueness exist for miner rounds. Compute reservations must also prevent cross-use of already reserved mining funds. |
| [Miner publisher](../crates/aura_sdk_v1/src/economic/journal/miner/publication.rs) | `obligation` requires an Accepted miner round/attempt; payment also has an Aura anchor. It cannot directly publish ordinary compute compensation. No dummy winner or fake proof reference is permitted. |

No Bitcoin migration or miner re-audit was performed. This is the first C2 design
checkpoint after the full C1 freeze gate. Existing source and fixtures are untouched.

## C2-D1 — Approved canonical receipt/result and authentication

**Conflict:** C1 binds a 32-byte result commitment into signed mining inputs but
deliberately does not define its preimage. New worker authentication and result
bytes cannot be inferred from the existing requester or Aura authorization wire.

**Recommendation:** one worker assignment, one worker receipt and one verifier-issued
result, each referencing its upstream object by commitment. Bind job-owned fields
transitively; do not repeat independently editable input/program/verifier fields.
Signatures and measured hardware/time telemetry remain outside result identity.

### Proposed exact bytes

All domains below are literal ASCII without terminators. Each object starts with
its domain and mandatory `u8(version=1)`. Digests and x-only keys are raw 32-byte
values. Signatures are detached 64-byte BIP340 values, never inside hashed bytes.
No optional fields, normalization, JSON wire, extra nonce or implicit versions.

| Object | Fields after domain and version, in order | Total bytes |
| --- | --- | --- |
| `ComputeAssignmentV1` / `AURA_COMPUTE_ASSIGNMENT_V1` | `compute_job_commitment[32]`, `worker_key[32]` | 91 |
| `ComputeReceiptV1` / `AURA_COMPUTE_RECEIPT_V1` | `assignment_commitment[32]`, `output_commitment[32]`, `execution_evidence_commitment[32]`, `resource_accounting_commitment[32]` | 152 |
| `VerifiedComputeResultV1` / `AURA_COMPUTE_RESULT_V1` | `receipt_commitment[32]`, `verification_verdict=u8(1)` | 56 |
| `ComputeCancelV1` / `AURA_COMPUTE_CANCEL_V1` | `compute_job_commitment[32]` | 55 |

For assignment and receipt, their commitment is SHA256 of their complete canonical
bytes. `compute_result_commitment` is SHA256 of the complete result bytes; it is the
only verified-result commitment. Verdict 1 means accepted; every other value
rejects in this verified-result type. Invalid work has a failure record, not a
second form of verified result. Cancellation has no new canonical identifier.

Use the existing C1 domain/length content framing for three new result content kinds:

| Content kind | Domain | Exact payload |
| --- | --- | --- |
| Output | `AURA_COMPUTE_OUTPUT_V1` | Adapter-defined canonical output bytes |
| Execution evidence | `AURA_COMPUTE_EXECUTION_EVIDENCE_V1` | Adapter-defined canonical evidence bytes |
| Resource accounting | `AURA_COMPUTE_RESOURCE_ACCOUNTING_V1` | `01 || u64_le(input_bytes) || u64_le(output_bytes) || u64_le(evidence_bytes)`; exactly 25 bytes |

The three resource counts are independently derived from the committed payloads,
checked against the signed limits, and must match exactly. They are not worker
runtime, FLOPs, power or hardware claims. No payment scales with these counters.
Physical measurements stay in attributed implementation evidence. A valid proof
does not establish device identity, resource enforcement or actual physical cost.

The complete resolution path is:

```text
verified result -> receipt -> assignment -> frozen C1 job
                   |                        |
                   output/evidence/counts   input/program/adapter/verifier/policies
```

This binds all approved C0-D3 facts without copying upstream objects into downstream
wires. Resolution must verify every content hash and relationship, including the
requester's signature, assigned worker and pinned adapter/verifier. Merely hashing
a fabricated `verification_verdict=1` does not make it an accepted result.

The trusted coordinator independently runs the pinned verifier against immutable
content. Only its successful internal verification path can finalize acceptance.
Result consumers authenticate the coordinator's result signature and resolve the
associated contracts/evidence. A boolean supplied by a worker or arbitrary customer
verifier is insufficient. C2 uses explicitly test-only adapters; the real Priority 0
backend and its approval remain C3.

### Proposed detached signatures

Each digest uses C1's tagged-SHA256 construction over that object's exact bytes.
Reuse existing BIP340 primitives; none is an Authorization V2 message.

| Signed object | Signing key | Tag |
| --- | --- | --- |
| Assignment acceptance | Assignment worker | `AURA_COMPUTE_ASSIGN_WORKER_V1` |
| Durable assignment acknowledgement | Job coordinator | `AURA_COMPUTE_ASSIGN_COORDINATOR_V1` |
| Receipt | Assigned worker | `AURA_COMPUTE_RECEIPT_SIGNATURE_V1` |
| Verified result | Job coordinator | `AURA_COMPUTE_RESULT_SIGNATURE_V1` |
| Cancellation | Job requester | `AURA_COMPUTE_CANCEL_SIGNATURE_V1` |

The job already binds network, coordinator, namespace, requester and unique nonce.
Assignment/receipt/result inheritance supplies that scope; no global replay claim
or separate mining nonce is introduced. The worker signs voluntary acceptance of
the exact job before durable assignment. The coordinator countersigns in the same
transaction that acquires assignment. Workers execute only after authenticated
acknowledgement. Signature re-randomization changes no object commitment.

Coordinator-observed assignment/receipt/acceptance times are durable journal
metadata. They enforce deadlines and retention but are excluded from R, preventing
timestamp or signature variation from manufacturing result identities. Backend
class, device/vendor, telemetry and measured capability evidence likewise remain
outside R. Identical canonical result content produces identical R across equivalent
backends. Different workers, actual outputs or canonical proof bytes are different
content; hardware neutrality does not claim all randomized proofs are byte-identical.

Capabilities are operational, bound to worker identity and the pinned adapter.
Record CPU/GPU/FPGA/Aura-ASIC class, measured limits, supported isolation, measurement
provenance and freshness. Self-declared performance is not sufficient eligibility.
No network capability wire, public scheduler, device-specific job meaning or future
ASIC instruction set is selected here. Unsupported privacy/isolation refuses work.

**Alternative:** flatten job/result fields or include physical telemetry in R.
Flattening duplicates ownership; telemetry changes identity across equivalent
backends and gives an avoidable source of cheap result variation. Recommended:
the referenced structure and deterministic byte-count accounting above.

## C2-D2 — Approved assignment, receipt and reservation fencing

**Conflict:** C1 fixes payment promises but not whether workers can be replaced or
submit different receipt revisions under one paid job. These choices decide which
work can earn compensation and cannot be treated as arbitrary storage details.

**Recommendation:** one assignment and one immutable timely receipt per job in V1.
No automatic replacement worker, lease recycling or first-to-finish competition.
A fresh attempt after terminal failure requires a new requester-signed job/nonce
and its own funding; no worker is silently assigned an unpaid replacement attempt.

### Proposed transitions in EconomicJournalV1

| Transition | Required behavior |
| --- | --- |
| Authenticated request -> funded/open | Reuse C1 request signature/replay checks; validate supported content, adapter and core policies. Reserve the full signed net compensation plus signed fee ceiling against verified customer custody backing before assignment. Use wide arithmetic and reject over-allocation; this is a reservation, not an Aura or synthetic balance. |
| Open -> cancelled/expired | Requester-signed cancellation before assignment, or server-observed assignment expiry. Release the unused job reservation; refund eligibility is recorded separately from actual payment publication. Replay tombstone remains. |
| Open -> assigned | Under one immediate transaction, check funding, capability support, worker opt-in/signature and C1 assignment budget; sample trusted time after acquiring the lock. Acquire exactly one worker and persist the coordinator acknowledgement atomically. |
| Assigned -> receipt pending | Authenticate that worker, resolve exact assignment, enforce payload bounds and core/adaptor framing. Make complete immutable output/evidence durably available before receipt commit; sample receipt time under the write lock, strictly before `complete_by`. Persist receipt identity and time once. |
| Assigned -> expired | Deadline passed with no durable timely receipt. No compute compensation; unused funding becomes releasable. A pending timely receipt prevents this transition. |
| Receipt pending -> accepted/owed | Re-read immutable artifacts, run the pinned workload verifier and validate job/public-input/count bindings. Atomically persist result, coordinator signature, retention obligation and one full-net worker entitlement. No burn, authorization nonce, Head or miner winner is created. |
| Receipt pending -> rejected | Definitive verifier rejection of the committed timely receipt earns no compensation. Different receipt bytes cannot replace it. Transport, storage or verifier-infrastructure failure is not proof of invalid work and leaves recovery pending. |
| Accepted/owed -> publication pending | Future shared payment transport owns publication, replacement and confirmation. C2 may record an obligation but cannot mark it paid from a caller boolean or invented transaction ID. Fee shortfall never releases an earned entitlement or shortens required retention. |

Same authenticated bytes retry idempotently, even after deadlines or response loss.
Different worker assignments or receipt bytes conflict; they do not erase an earlier
valid record. A losing assignment race is rejected before execution is authorized.
Malformed/unauthenticated or incomplete submissions rejected before durable receipt
creation do not consume the one receipt slot. After durable receipt commit, even
an invalid proof is immutable and can terminally fail that requested attempt.

The coordinator controls receipt time, not the worker clock or upload start. A hash,
URI or partial upload alone is not durable output delivery. Artifact persistence
must precede the receipt transaction; a crash may leave unreferenced staged objects,
but never an accepted reference to a missing object. Live referenced content cannot
be reclaimed while verification, required availability or payment is pending.
Verification retries after a timely receipt can complete after the job deadline.
No infrastructure timeout silently converts pending verification to unpaid failure.

One same-journal reservation owner must reject overlap between compute assignments
and miner funding. Keep refund/fee remainder, earned net entitlement and Bitcoin
transaction observations separate. No duplicate obligation can result from retry,
restart, replacement or reorg. Reorg may invalidate backing or require payment
recovery; it cannot erase an earned result or invoke another burn/head transition.
An unsafe funding observation stops new assignment and preserves recovery evidence.

No concrete outpoint, payout script, transport, confirmation count, fee default,
retention default or production capacity is selected. The worker key identifies
the beneficiary; it does not silently select a Bitcoin payout script. C2's tests
can exercise custody and publication interfaces with clearly identified fixtures;
real payment discharge must use the reviewed shared transport in later work.

**Alternative:** allow replacement leases or multiple durable receipt revisions.
That needs extra fencing, paid-work attribution and deadline arbitration. It can
improve recovery/worker correction but expands the economic contract. Recommended:
the single-assignment/receipt model, with its explicit lost-work/retry limitation.

## Implementation order after approval

1. Rust/TS assignment, receipt, result, accounting and cancellation codecs and
   distinct signatures; exact positive/negative vectors. Preserve the entire C1 gate.
2. Add explicit compute schema installation/audit to EconomicJournalV1; implement
   authenticated request replay, custody reservations, cancellation and assignment.
   No silent migration and no separate database or generic Aura debit path.
3. Add durable artifact receipt and internal adapter-verification boundary, then
   atomic result/retention/entitlement finalization. No public `accept(true)` escape.
4. Test restart, competing workers, cancellation/assignment races, duplicate receipts,
   byte mutations, invalid proofs, corrupt/missing artifacts, time boundaries,
   pending verification, failed infrastructure and atomic rollback. Test funding
   cross-use with miner obligations and unchanged burn/head/authorization state.
5. Record bounded C2 evidence, promote only approved definitions into the existing
   compute owner and relevant coordinator owner, then mark C2 DONE/C3 READY and stop.

C2 closes only when those tests establish durable behavior; this proposal does not
close C2. It does not select a real prover backend or claim useful compute, safe
public execution, live payment, fairness against a dishonest coordinator or a
succinct/zero-knowledge Aura Storm proof.

## Validation of this checkpoint

Direct-owner inspection and proposed layout arithmetic only. No Rust/TS C2 parity
or durable lifecycle test is claimed before contract approval. Existing C1/Miner
gates were not repeated for this documentation-only checkpoint. Local links and
the proposed byte lengths are checked before recording the decision request.

## Controlling approval

The user explicitly APPROVED C2-D1/D2 as documented, including distinct object
bytes/signature domains, one immutable assignment/receipt and full-net entitlement.
The user clarified that the full compensation plus fee reservation is acquired
**at assignment**. An open registered request is not a funded or assigned job.
No same-job reassignment/replacement is allowed; terminal retry needs a new signed
job and nonce, funding, assignment and receipt. Exact-transition retries remain
idempotent. This approval supersedes the earlier table's pre-assignment reservation
timing. Existing C0/C1/Miner/Aura meanings remain unchanged.

Freeze requires passing Rust/TS parity, mutation/negative vectors, replay,
funding and crash/recovery tests. C3 remains blocked until C2 is complete.
