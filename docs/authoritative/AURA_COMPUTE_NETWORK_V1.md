# AURA_COMPUTE_NETWORK_V1

**Classification:** `ACTIVE AUTHORITY — COMPUTE CONTRACT`  
**Status:** `ACTIVE — C1/C2 FROZEN (2026-09-12)`
**Scope:** C1 job/core policy/binding and C2 worker/result/durable lifecycle contracts; no activated workloads or live payment.

## Ownership and implementation boundary

This document owns the common useful-compute contract. The approved C0 and C1
[decision/evidence record](../../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md) records
approval and validation; it is not another normative definition.

One job requests one useful unit. Customer-prefunded net compute compensation is
independent of optional sponsor-funded mining rewards. EconomicJournalV1 remains
the sole durable coordinator. Core owns common envelopes, commitments and policy;
adapters own execution, output and workload-specific verification. CPU/GPU/FPGA/
Aura-ASIC backends are replaceable implementations of the pinned adapter relation.

The SDK implements C1 codecs, authentication, content/core-policy checks and
signed-side derivation. C2 adds worker/result codecs and EconomicJournalV1's durable
registration, assignment/funding, immutable receipt, verification and entitlement
lifecycle. Complete output/evidence are stored in the same SQLite transaction as
the receipt; accepted output can be read by the owning service. No payment is
published here. C2's only adapter is compiled exclusively into tests; no production
workload is registered until C3 adds its reviewed real proving/verifier backend.
No supported workload, public worker execution or live monetary activation follows
from this contract freeze. No deployment fee ceiling, retention duration, payout
transport, funding outpoint or production default is selected.

Existing [Miner V1](AURA_AURAFARMING_NODES.md), [economics](AURA_LEDGER_AND_BURN_V1.md),
[Authorization V2](AURA_AUTHORIZATION_LINEAGE_V1.md),
[Head V2](AURA_CONTINUOUS_SETTLEMENT_V1.md) and
[Bitcoin wire](AURA_REPORT_CONTRACT_V1.md) retain their owners and semantics.
Ordinary useful-compute acceptance causes no automatic Miner burn, Head advance
or Aura issuance. Entering the existing mining path invokes its unchanged rules.

## Job encoding

Exactly **546 bytes**, fixed order below. Offsets are zero-based. All u64
and u16 values use unsigned little-endian bytes. Fixed fields have no length prefix.
No signature is embedded in job bytes. No JSON wire, optional fields, normalization,
implicit defaults, missing/null mining values or alternate encodings.

| Offset | Bytes | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 19 | `domain` | ASCII `AURA_COMPUTE_JOB_V1`, no terminator |
| 19 | 1 | `job_version` | u8, exactly 1 |
| 20 | 1 | `network` | Existing BitcoinNetworkV1 tag; no new network numbering |
| 21 | 32 | `coordinator_key` | Valid BIP340 x-only key for the intended coordinator |
| 53 | 32 | `journal_namespace` | Explicit coordinator journal namespace |
| 85 | 32 | `requester_key` | Valid BIP340 x-only customer key |
| 117 | 32 | `job_nonce` | Customer-generated CSPRNG bytes; producer obligation |
| 149 | 2 | `workload_class` | u16 LE, registered workload family; not a verifier selector |
| 151 | 32 | `adapter_contract_commitment` | Pinned adapter/version contract |
| 183 | 32 | `input_commitment` | Exact adapter-defined input artifact bytes |
| 215 | 32 | `program_commitment` | Exact program/model artifact bytes |
| 247 | 32 | `execution_spec_commitment` | Pinned parameters, runtime contract and deterministic seed policy |
| 279 | 32 | `output_spec_commitment` | Pinned output format and acceptance relation |
| 311 | 1 | `verification_class` | Explicit verification-strength class |
| 312 | 32 | `verification_spec_commitment` | Pinned verifier/version/key/public-input relation |
| 344 | 1 | `privacy_class` | Explicit privacy capability requirement |
| 345 | 32 | `privacy_policy_commitment` | Exact supporting privacy/locality policy |
| 377 | 32 | `hardware_requirements_commitment` | Capability predicates; no selected worker/device identity |
| 409 | 8 | `max_input_bytes` | u64 LE |
| 417 | 8 | `max_output_bytes` | u64 LE |
| 425 | 8 | `max_evidence_bytes` | u64 LE |
| 433 | 8 | `max_memory_bytes` | u64 LE; total allowed execution allocation, with enforcement defined by adapter |
| 441 | 8 | `max_scratch_bytes` | u64 LE |
| 449 | 8 | `max_execution_ms` | u64 LE; hard elapsed execution bound |
| 457 | 8 | `accept_until` | u64 LE Unix seconds; exclusive assignment deadline |
| 465 | 8 | `complete_by` | u64 LE Unix seconds; exclusive coordinator receipt deadline |
| 473 | 8 | `compensation_satoshis` | u64 LE; positive fixed amount owed to worker for accepted unit |
| 481 | 32 | `payment_terms_commitment` | Immutable purchase/reservation/fee/refund policy, not a transaction ID |
| 513 | 32 | `data_rights_commitment` | Explicit policy preserving approved requester ownership by default |
| 545 | 1 | `mining_mode` | u8: 0 disabled, 1 optional result-bound Miner V1 participation permitted |

Reject truncated/trailing bytes, wrong domain/version, unknown network/tag values,
invalid x-only keys and integer overflow. No sentinel zero digest means "unspecified".
Every commitment denotes exact content; retrieval failure is not permission to
substitute a default. Any 32-byte digest is structurally representable, but admission
requires matching available content and supported reviewed contracts.

Approved codec tags (decoding is not active adapter registration):

- Workload class u16: 0 proving/crypto, 1 inference, 2 molecular, 3 media,
  4 Monte Carlo, 5 general science, 6 genomics, 7 optimization, 8 builds/CI,
  9 small training/fine-tuning, 10 EDA. All other values reject in V1.
- Verification u8: 0 cryptographic proof, 1 deterministic replay, 2 cheap result
  verification, 3 redundant execution, 4 probabilistic sampling, 5 trusted
  attestation, 6 TEE attestation, 7 verifiable ML. These are distinct guarantees.
- Privacy u8: 0 PUBLIC, 1 SANDBOXED, 2 CONFIDENTIAL, 3 TEE_REQUIRED,
  4 LOCALITY_RESTRICTED. No class implies support merely because its tag decodes.

No workload is activated by these tags. Supported adapter/privacy/verifier policy
must be checked before admission, assignment or release of data. PUBLIC requires
isolation too; SANDBOXED is not confidentiality from the worker.

Limits must bound host allocation and verifier input, not just worker claims.
Require positive output/evidence/memory/execution bounds and `0 < accept_until <
complete_by`; zero input/scratch may be legitimate exact bounds, not unlimited.
Resource limits must satisfy adapter minimums and local caps without arithmetic
wraparound. Admission time must be before accept_until; an assignment must leave
sufficient time for its allowed execution/delivery budget. C2 owns trusted receipt
timing, leases, retries and cancellation; worker clocks never establish acceptance.

## Commitment, authentication and replay

For job bytes B:

```text
compute_job_commitment = SHA256(B)
request_signature_digest = tagged_SHA256("AURA_COMPUTE_JOB_SIGNATURE_V1", B)
tagged_SHA256(tag, B) = SHA256(SHA256(ASCII(tag)) || SHA256(ASCII(tag)) || B)
```

A detached 64-byte BIP340 signature by requester_key authenticates B. The chosen
coordinator_key and namespace scope the request to one configured service/journal;
the request does not assert that coordinator acceptance or funding already occurred.
Different valid signatures over the same B do not change job identity.

Approved separate compute replay scope within EconomicJournalV1:
`(network, coordinator_key, journal_namespace, requester_key, job_nonce)`.
An authenticated retry with exactly the same B is idempotent; different B in the
same scope fails, even after expiry/cancellation. No global uniqueness claim, no
implicit reservation of a mining freshness_nonce and no Authorization V2 conversion.
Signature validity grants no worker assignment, result acceptance, compensation
payment or Aura proof authorization by itself. C2 defines durable transitions.

For each referenced object X, use one content commitment:

```text
C_X = SHA256(ASCII(domain_X) || u64_le(payload_length) || exact_payload_bytes)
```

Domains are exactly `AURA_COMPUTE_` plus one of
`ADAPTER_CONTRACT`, `INPUT`, `PROGRAM`, `EXECUTION_SPEC`, `OUTPUT_SPEC`,
`VERIFICATION_SPEC`, `PRIVACY_POLICY`, `HARDWARE_REQUIREMENTS`, `PAYMENT_TERMS`,
`DATA_RIGHTS`, followed by `_V1`. No null terminator. Commit raw canonical artifact
bytes, not a hex string or an unpinned URI. The domain maps to exactly one job field.
Locators/transport mirrors are operational metadata and cannot change the content.
This is the approved upstream content-addressing rule, not a change to HASH_V2.

Adapter contracts must specify one canonical encoding for each workload-owned
payload and the exact relation between input, program, parameters, output and
verifier public inputs. Opaque commitments do not make arbitrary JSON canonical
or a customer-selected always-true verifier trustworthy. The supported core policy schemas are defined below. Adapter payloads require
their own reviewed contracts before workload admission; a digest alone does not
establish executable or verified meaning.

## Funding and hardware invariants

Use fixed net BTC compensation per accepted requested unit, positive integer
satoshis. No resource-claim-based pricing, token balance or automatic mining burn.
The customer must prefund that compensation and the approved fee policy before an
assignment can earn. A funding/fee shortage may prevent assignment; it cannot
silently reduce the signed amount owed for already accepted useful work.

The immutable payment_terms_commitment describes purchase and reservation terms.
Actual funding outpoints, change scripts, funding transactions, payment transaction
IDs, replacement attempts, batching and channel routes remain durable operational
metadata linked to compute_job_commitment in the existing coordinator. Changing
those transport details cannot mutate B, reduce the obligation or mint another job.
C2 must prove reservation uniqueness, no over-allocation and replay-safe discharge.
No live settlement, payout script, deployment fee amount or channel is chosen.
Ordinary payment does not fabricate an Aura proof_hash/OP_RETURN or mining winner.

Hardware predicates identify capabilities required by the task, not who executes
it. The adapter pins semantic program/model/kernel and runtime relation; equivalent
CPU/GPU/FPGA/ASIC backends implement that relation. Actual device identity,
benchmarks, placement and telemetry do not enter job bytes or serve as correctness.
All implementations still must meet the signed resource/privacy contract. A backend
migration that cannot meet it is not equivalent and cannot silently weaken it.

C2 must preserve one result identity from the same canonical result content across
backends. Raw device logs cannot become alternate result serializers. Genuine
randomized outputs/proof evidence require the adapter's explicit canonical policy;
C1 does not assert byte parity merely because two proofs verify the same statement.
Execution grants the worker no ownership rights. data_rights_commitment must resolve
to the supported requester-control/minimum-temporary-rights policy below.
An alternate open-license profile requires separate approval before support.

## Result-to-signed-miner-input derivation

Input R is the single 32-byte compute_result_commitment from an accepted verified
result. C2 owns R's full preimage, including all C0-D3 bindings. Synthetic values
in the [binding fixtures](../../fixtures/compute_job_v1/job_vectors_v1.json)
test this derivation only, not valid result acceptance.

Define one expansion E(R, lane), with lane u8 exactly 0 or 1:

```text
D = ASCII("AURA_COMPUTE_MINER_SIDE_V1")
block_i = SHA256(D || u8(lane) || R || u32_le(i))    for i = 0,1,2,3
E(R, lane) = first_110_bytes(block_0 || block_1 || block_2 || block_3)
J.side_a = E(R, 0)
J.side_b = E(R, 1)
```

The final block contributes its first 14 bytes. No hex, byte reversal, field
reduction, sorting, extra salt, random padding, normalization, optional lane or
alternative hash. These are existing raw 110-byte side inputs; existing Storm
owners interpret them exactly as before. This is upstream input derivation only.

The coordinator must authenticate/resolve the verified record and its canonical R,
check both derived sides, then use its existing round-opening owner to sign J.
Current policy supplies N/T/limits; existing opening pins head/round/reward/challenge.
A linked job must not be made by editing an already-signed J. Do not derive sides
from J.commitment, which itself includes those sides. No result binding solely
through M is permitted for this profile.

```text
R → both sides in J → existing J signature and job_commitment
→ existing J/M intent and nonce-bound context → Storm/TRACE_ROOT
→ existing proof/material/FractalKey → existing proof_hash <= signed T
```

Full external result verification and existing Aura PoC remain separate checks.
A matching side derivation from an arbitrary digest is not a verified useful result.
Result availability precedes a compute-linked round; useful compensation never
waits for that round to open or succeed. Legacy/unlinked Miner V1 is unchanged.
The existing miner winner identity still determines its bonus; this derivation
alone neither restricts round contenders to the useful worker nor redirects the
bonus to R's worker. Such a restriction would require a separate explicit decision.

## Supported core policies — C1-P1

Each payload below is committed through its corresponding content domain/length
construction above. A policy profile is the first literal byte, not inferred from
payload length. No missing fields, normalization, alternate encodings or defaults.

| Job reference | Exact payload | Supported meaning |
| --- | --- | --- |
| `privacy_policy_commitment` | `01` (one byte) | Isolated PUBLIC/SANDBOXED execution only; no host secrets, no outbound network, no confidentiality claim. |
| `hardware_requirements_commitment` | `01` (one byte) | Any measured/supported CPU/GPU/FPGA/Aura-ASIC backend satisfying the pinned adapter contract, signed limits and adapter minimum capabilities. No device/vendor identity in canonical job meaning. |
| `data_rights_commitment` | `01` (one byte) | Requester retains control/ownership; worker receives only minimum temporary execution rights. No automatic reuse, publication, ownership transfer or unrelated retention. |
| `payment_terms_commitment` | `01 || u64_le(max_payment_fee_satoshis) || u64_le(result_availability_seconds)` (17 bytes) | Customer-funded fee ceiling separate from the job's net compensation; positive result availability duration. No transport/funding identifiers. |

Only profile `01` is supported in each domain. The three identical one-byte
payloads have distinct commitments because their domains differ. Reject every
other profile and truncated/trailing payload. Payment duration must be positive;
zero fee budget means exactly zero, never unlimited. u64 values are exact integers
with no floating-point conversion. Compensation is owned solely by the signed job;
the payment payload does not duplicate it.

A supported core-policy check requires all four exact payloads, matching job
commitments and privacy class PUBLIC or SANDBOXED. Other privacy class tags remain
structurally decodable, but are unsupported until separately approved. Hash equality
does not make a malformed or unapproved policy supported. Valid core schemas do not
attest actual isolation, measured hardware, adapter support or funded admission.
Requester content and output rights do not grant Aura automatic ownership; retain
protocol commitments/evidence needed for verification/accounting, not unrelated
customer content. Different licensing requires a separately approved profile.

### Payment lifecycle contract

- Requester cancellation/refund is allowed only before assignment.
- After assignment, compensation remains reserved until valid timely completion
  or terminal failure. A timely durable receipt pending verification keeps the
  reservation; verification delay alone cannot turn it into an expired failure.
- Requester acknowledgement cannot veto otherwise valid contracted output.
- An accepted verified result earns the full signed `compensation_satoshis`.
  Failure/expiry without a valid timely result earns no compute compensation.
- Customer-funded publication fees are bounded by the signed ceiling and never
  reduce worker net compensation. Fee shortfall cannot erase an earned entitlement.
- Accepted output remains available for at least the signed
  `result_availability_seconds` after acceptance and while compensation is pending.

C2 enforces reservation, immutable receipt, verifier finalization, entitlement and
retention state through the existing coordinator. C1's pure fee predicate remains
unchanged; actual payment publication/discharge is future shared-transport work.

## C2 assignment, receipt and verified result

C2-D1/D2 are explicitly approved. One immutable assignment and one immutable timely
receipt belong to each signed job. Exact-transition retries return their original
record; they do not authorize new work after terminal closure. New execution after
failure needs a new signed job/nonce, funding reservation, assignment and receipt.

### Exact lifecycle bytes

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

### Detached lifecycle signatures

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

### Durable lifecycle in EconomicJournalV1

| Transition | Required behavior |
| --- | --- |
| Authenticated request -> open | Reuse C1 request signature/replay checks; validate supported content, adapter and core policies, deadlines and durable storage capacity. Registration alone creates no funding reservation or execution permission. |
| Open -> cancelled/expired | Requester-signed cancellation before assignment, or server-observed assignment expiry. No assignment reservation exists; any customer custody refund remains distinct from payment publication. Replay tombstone remains. |
| Open -> assigned | Under one immediate transaction, reserve `compensation_satoshis + max_payment_fee_satoshis` against verified customer custody backing using wide arithmetic, excluding other compute/miner owners; check capability support, worker opt-in/signature and C1 assignment budget. Sample trusted time under the lock before and after custody verification; reject clock regression and recheck capability validity and the assignment budget against the latter time. Acquire exactly one worker and persist that assignment time and the coordinator acknowledgement atomically. |
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
the beneficiary; it does not silently select a Bitcoin payout script. C2 validates custody with explicit trusted Core RPC fixtures; real payment
discharge must use the reviewed shared transport in later work.

### Implemented durability and capability boundary

The compute extension is explicitly installed in EconomicJournalV1's existing
SQLite database. It does not create a ledger, currency, authorizer or independent
Bitcoin publisher. Canonical objects are stored as their exact bytes; indexed
fields and internal JSON records are implementation state, not alternate wires.
Opening audits record/index consistency, signatures, resolved bindings, lifecycle,
reservations and earned obligations. Ordinary compute never calls the Aura debit
or Head/authorization finalizer.

The trusted service supplies exact content and an explicit host capacity policy.
Before assignment it must have room for the signed maximum output/evidence plus
metadata. A sealed adapter owns verification and capability measurement; successful
measurement requires support for the job's pinned adapter and core isolation policy.
Failure to enforce required owner/resource/privacy bounds must refuse assignment.
Worker self-reports and arbitrary customer callbacks cannot register a verifier.
C2's test probe does not establish actual GPU/ASIC performance or public sandboxing.

The backing token can only be constructed through trusted Core validation, not
client deserialization. It binds the job and separately reserved net/fee amounts.
The host attributes the selected custody coin to the requester and supplies an
explicit confirmation policy; no deployment value is chosen. Shared journal guards
prevent the coin from backing another compute or miner obligation. Ambiguous commit
or wallet restart requires reconciliation and re-locking before wallet spending;
an orphan lock is not permission to release a potentially committed reservation.

The existing synchronization/backup requirements in the
[ledger owner](AURA_LEDGER_AND_BURN_V1.md#useful-compute-coordinator-extension)
apply. Checksums detect corruption, not a maliciously replaced coherent database.
No anti-rollback, trustless escrow or fairness against a dishonest custodian is
claimed. Production proof backend, authenticated customer download routing, actual
worker isolation and shared payment publication remain later implementation work.

## Implementation and validation map

- Rust: [compute_job.rs](../../crates/aura_sdk_v1/src/compute_job.rs), exported by
  `aura_sdk_v1::compute_job`. No serde job wire or second proof representation.
- TS: [computeJobV1.ts](../../packages/aura_sdk_v1_ts/src/computeJobV1.ts), exported
  by the existing SDK; exact bigint integers and strict typed-input validation.
- Tests: [Rust](../../crates/aura_sdk_v1/tests/compute_job_v1.rs),
  [TS](../../packages/aura_sdk_v1_ts/src/computeJobV1.test.ts).
- [Fixture registry](AURA_VECTOR_MATRIX_V1.md#compute-job-v1-c1) and
  [C1 evidence](../../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md#validation-evidence)
  identify the frozen vectors and bounded reproduction gate.

C2 implementation:

- [Rust lifecycle codecs](../../crates/aura_sdk_v1/src/compute_result.rs) and
  [TypeScript](../../packages/aura_sdk_v1_ts/src/computeResultV1.ts).
- [Journal extension](../../crates/aura_sdk_v1/src/economic/journal/compute/mod.rs),
  including sealed adapter registry, custody token and atomic operations.
- [C2 evidence](../../reports/AURA_COMPUTE_C2_CONTRACT_DECISIONS.md) and
  [C2 fixture registry](AURA_VECTOR_MATRIX_V1.md#compute-lifecycle-v1-c2) identify
  parity, mutation, crash/recovery and regression gates.

Structural decoding, request authentication, supported-policy validation, durable
admission, a workload verifier's verdict, compute entitlement, and Aura PoC/PoW are
separate checks. None may be inferred from another's successful return value.
