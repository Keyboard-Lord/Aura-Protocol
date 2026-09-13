# AURA_COMPUTE_NETWORK_V1

**Classification:** `ACTIVE AUTHORITY — COMPUTE CONTRACT`  
**Status:** `ACTIVE — C1 FROZEN (2026-09-12)`  
**Scope:** C1 job, authentication, core policy and upstream mining-binding contracts only.

## Ownership and implementation boundary

This document owns the common useful-compute contract. The approved C0 and C1
[decision/evidence record](../../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md) records
approval and validation; it is not another normative definition.

One job requests one useful unit. Customer-prefunded net compute compensation is
independent of optional sponsor-funded mining rewards. EconomicJournalV1 remains
the sole durable coordinator. Core owns common envelopes, commitments and policy;
adapters own execution, output and workload-specific verification. CPU/GPU/FPGA/
Aura-ASIC backends are replaceable implementations of the pinned adapter relation.

The C1 SDK implements codecs, authentication, pure retry comparison, content/core
policy checks and signed-side derivation. It does not implement assignment, durable
compute reservation/replay, result verification, output delivery or payment.
The lifecycle requirements below constrain C2; they are not a claim of enforcement.
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

These are approved requirements for the existing coordinator's future compute
extension. C1's fee predicate only checks the signed ceiling; it does not reserve
funds, publish a payment or implement these durable transitions.

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

Structural decoding, request authentication, supported-policy validation, durable
admission, a workload verifier's verdict, compute entitlement, and Aura PoC/PoW are
separate checks. None may be inferred from another's successful return value.
