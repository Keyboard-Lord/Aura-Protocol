# AuraComputeJobV1 — C1 contract and freeze evidence

Classification: APPROVED IMPLEMENTATION DIRECTION / NON-AUTHORITATIVE; NOT YET FROZEN.
Date: 2026-09-12. C1-D1–D3 APPROVED by the user; C1 IN PROGRESS.
DOC = CODE for the request codec/profile; referenced core policy semantics remain pending.
C0 approval: [controlling D1–D4](AURA_COMPUTE_NETWORK_V1.md#9-controlling-approval-record--d1d4-approved).
Rust/TS request codec/profile implementations and shared regression vectors now exist.
No adapter, journal migration, useful-result verdict or payment implementation is added.
Canonical freeze requires the test evidence AND complete referenced core contracts below.

## 1. Existing boundary and design obligations

The approved C0 decisions establish independent prefunded compensation, one
EconomicJournalV1, no automatic useful-work burn/head transition, requester data
rights, hardware neutrality and signed-job result binding. The user approved
C1-D1–D3 for contract design and Rust/TS parity work, explicitly withholding canonical
freeze until the required checks pass. This implementation preserves those decisions.

Direct owners inspected:

- [MinerJobV1](../crates/aura_sdk_v1/src/miner.rs): exact J encoding, signature,
  J/M intent and work-profile checks; both side fields are signed 110-byte arrays.
- [Round opening](../crates/aura_sdk_v1/src/economic/journal/miner.rs):
  MinerRoundOpeningV1 supplies both sides before J is signed/persisted; current
  policy still supplies N/T/limits and the journal supplies head/challenge/round.
- [Miner authority](../docs/authoritative/AURA_AURAFARMING_NODES.md): unchanged
  471-byte wire and inclusive proof_hash target rule.
- [Authorization owner](../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md):
  existing BIP340 authorizations bind Aura proof references. A new job signature
  authenticates a compute request only; it must not reuse Authorization V2's tag.

A compute job describes one requested useful unit before its result exists. It
must not contain a future compute_result_commitment or signed MinerJobV1 commitment:
that would create a job → result → job dependency cycle. Optional mining is a mode;
its actual signed job is created after the verified result exists.

## 2. Approved job encoding — C1-D1 (freeze pending)

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

## 3. Commitment, authentication and replay — C1-D1

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
or a customer-selected always-true verifier trustworthy. Core-owned privacy,
hardware, payment and rights policy encodings also need reviewed definitions or
pinned supported contracts before C1 can be frozen. This draft does not hide
unfinished semantics behind a 32-byte digest.

## 4. Funding and hardware invariants — C1-D2

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
No live settlement, payout script, fee amount, refund penalty or channel is chosen.
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
to the requester-control/minimum-temporary-rights policy or an explicitly selected
open-license policy, as required by approved C0-D4.

## 5. Approved result-to-signed-input derivation — C1-D3 (freeze pending)

Input R is the single 32-byte compute_result_commitment from an accepted verified
result. C2 owns R's full preimage, including all C0-D3 bindings. Synthetic values
in the [draft binding vectors](compute_network_v1/c1_binding_candidate_vectors.json)
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

Why this candidate: SHA256 is already used by the miner job/intent owners; fixed
counter/lane framing uses both existing fields without changing J or selecting a
new hash primitive. A SHAKE/XOF expansion or direct digest-plus-padding would also
be possible, but choosing multiple permitted encodings would violate canonicality.
C1-D3 approves this single expansion; cross-language vectors now pass. No alternate
expansion is accepted by the implemented profile.

## 6. Required freeze evidence — core contract gate still open

Before adapters depend on this boundary:

1. Freeze complete job and referenced core contract semantics/encodings, including
   policy commitments, supported versions, explicit deadlines and hard limits.
2. One Rust codec/commitment/signature owner and matching TS bytes; fixed full-job
   encode/decode, signature digest/signature and each content-commitment vector.
3. Reject/detect mutation of every field; domain/version/length/trailing bytes,
   invalid keys/tags, endian mistakes, swapped commitments, signed amount changes,
   deadline/limit violations, wrong namespace/coordinator and same-nonce new job.
4. Shared result-binding vectors for at least R=zero, R=incrementing bytes, a
   one-bit mutation and all-ff. Freeze both sides, all four blocks, resulting J
   bytes/commitment/signature digest and existing deterministic profile output.
5. Reject swapped lanes, alternate counters, R hex/text hashing, padding variants,
   wrong R, changed signed sides, reused old signature and post-proof attachment.
6. Preserve existing M2 fixtures byte-for-byte. Check through existing Rust/TS job
   owners, not another test codec that can agree with itself while bypassing J.
7. Distinguish structural validity, signature authentication, funded admission,
   verified result, compute entitlement and existing mining PoC/PoW in test names.

C1 is NOT DONE and no canonical freeze is claimed. Items 2–7 have executable
codec/profile evidence (section 10); item 1 still needs the core policy contracts
in section 9. Pure replay comparison is not a durable admission test; that state
owner remains C2. No workload adapter or live monetary path is started.

## 7. C1-D1–D3 approval record

The user explicitly APPROVED C1-D1–D3 for continued contract design and Rust/TS
parity/vector work. The approval is NOT the canonical freeze. Freeze only after
exact byte layout, signing/replay vectors, compensation vectors, side-expansion
vectors, mutation/negative coverage and independent Rust/TS parity pass.

- C1-D1: the 546-byte envelope, SHA256 commitments, detached BIP340 requester
  signature and journal-scoped replay direction are approved.
- C1-D2: fixed positive net BTC compensation and exclusion of funding/payment
  transport from job identity are approved.
- C1-D3: the four-block/two-lane SHA256 derivation into existing signed 110-byte
  MinerJobV1 sides is approved.

Prior alternatives remain design history, not permitted additional encodings.
No approval is inferred for unspecified core policy schemas, payout behavior,
a new winner restriction, a proof backend, live funds or public execution.

## 8. Historical design-check evidence (before implementation)

- Layout arithmetic: 30 fields with contiguous offsets, 546 bytes including the
  exact 19-byte domain. No implemented encoder/decoder is claimed.
- Python hashlib generated four synthetic result-binding cases. An independent
  `node --input-type=module` check using node:crypto reconstructed every preimage
  and SHA256 block: 32 blocks passed, producing eight distinct 110-byte sides.
  This is draft derivation evidence, not Rust/TS SDK parity or a frozen vector.
- Local document links/anchors and whitespace checked; `git diff --check` passed.
- Changes are confined to C0/C1 design, the slice register and provisional vectors.
  Source, authoritative documents and frozen fixtures are unchanged; the archived
  M7 register remains byte-identical to `97ff01f`.
- No Aura runtime, mining, Bitcoin, adapter or live monetary tests were run for
  this design-only change. The C1 freeze checklist above remains outstanding.

## 9. USER_DECISION — first supported core contracts

The approved envelope commits privacy, hardware, payment and rights payloads, but
those payloads have no approved exact schemas yet. The executable vectors use
clearly marked synthetic content, not an alleged supported policy. Freezing these
placeholders would leave job meaning undefined; passing hash tests cannot fix that.

Recommended smallest initial profile set, for review only:

| Job reference | Proposed exact payload before existing content-hash framing | Proposed meaning |
| --- | --- | --- |
| privacy_policy_commitment | Single byte `01` | Isolated PUBLIC/SANDBOXED work; no host secrets or outbound network; no confidentiality claim. Other privacy classes remain unsupported until separately specified. |
| hardware_requirements_commitment | Single byte `01` | Any measured/supported backend satisfying the committed adapter relation and job limits; no device/vendor identity in job meaning. Adapter minimum capabilities remain mandatory. |
| data_rights_commitment | Single byte `01` | Approved requester-control/minimum-temporary-execution-rights policy. No automatic reuse, ownership transfer or publication; evidence retention only for verification/accounting. An alternate open-license policy needs its own explicit supported profile. |
| payment_terms_commitment | `01 || u64_le(max_payment_fee_satoshis) || u64_le(result_availability_seconds)` (17 bytes) | Fixed net compensation owned solely by the job; customer-funded fee ceiling separate from that net amount; positive committed result availability duration. No outpoints/transaction IDs in these bytes. |

These bytes would be interpreted only by the respective content kind and wrapped
in its already-approved domain/length commitment. They are not implemented or
frozen by this checkpoint. No concrete fee ceiling or availability duration is
selected as a deployment default. Zero fee budget would be an exact limit, not
unlimited fees; runtime funding/fee policy must be satisfiable before assignment.

Payment lifecycle meaning needed before this profile is safe to freeze:

- Recommend requester cancellation/refund eligibility before assignment only;
  after assignment, reserve funds until a valid timely result or terminal failure.
- A timely durable receipt pending verification retains its reservation. Customer
  acknowledgement is not a veto over valid, available contracted output.
- An accepted result earns the full fixed amount; failures/expiry without a valid
  timely receipt earn none, with no automatic Miner burn or Head V2 transition.
- Customer funds publication fees up to the signed ceiling; they never reduce net
  compensation. A shortfall cannot erase an already-earned entitlement.
- Retain the output at least for the signed availability duration after acceptance
  and while compensation remains pending. Detailed atomic transitions/recovery
  stay in C2; this defines the promise they must implement.

Existing approved behavior: prefunding, separate obligations, one journal, fixed
net compensation, requester rights and no automatic useful-work burn/head advance.
New meaning requiring a decision: the supported policy payloads, cancellation
boundary, fee responsibility and result-availability promise above.
Smallest decision: approve or amend this initial profile set and those promises.
Alternative: design richer capability/privacy/licensing and cancellation contracts
now; that expands the initial contract surface. Do not silently move missing core
meaning to adapter-controlled JSON or mark the entire C1 node complete without it.

## 10. Current implementation and validation evidence

Owners:

- [Rust codec/profile](../crates/aura_sdk_v1/src/compute_job.rs), exported from the
  existing SDK. No serde job wire, journal, balance or proof implementation.
- [TypeScript codec/profile](../packages/aura_sdk_v1_ts/src/computeJobV1.ts), using
  Node SHA256 and Noble BIP340 independently of Rust sha2/libsecp256k1.
- [Shared vectors](../fixtures/compute_job_v1/job_vectors_v1.json), generated by
  explicit [Rust test-vector producer](../crates/aura_sdk_v1/examples/compute_job_vectors_v1.rs).
  [Independent TS construction](../packages/aura_sdk_v1_ts/tests/support/computeJobVectorsV1.ts)
  produces the same exact job/signature/content/side/miner-profile bytes.

Validation:

- `cargo test -p aura_sdk_v1 --offline --test compute_job_v1`: 7 tests passed.
- `node --test packages/aura_sdk_v1_ts/src/computeJobV1.test.ts`: 9 tests passed.
- Existing M2 regression: `cargo test -p aura_sdk_v1 --offline --test miner_v1`
  (9 passed) and `node --test packages/aura_sdk_v1_ts/src/minerV1.test.ts`
  (10 passed as part of the 19-test combined C1/M2 run).
- `cargo check -p aura_sdk_v1 --offline --lib --examples`: passed.
- `node --check packages/aura_sdk_v1_ts/src/computeJobV1.ts` and dynamic import of
  the public SDK: passed. No standalone TypeScript compiler is installed; Node's
  native TS runtime checks are not represented as a tsc typecheck.

The suite checks every offset/width; 546 byte mutations and 64 signature mutations;
all truncation lengths; unsupported tags, keys, zero bounds, zero compensation,
strict deadlines, all five networks, amount 1 / 2^53+1 / u64::MAX, distinct
coordinator/requester/namespace/nonce scopes, same-byte/different-signature retry,
expiry-independent retry classification, exact content domain/length hashing,
four result expansions and their existing J/signature/intent/context/work bytes.
Wrong/swapped/padded sides, alternative counters, R hex/width mistakes, old signed J,
disabled compute mining mode and post-proof/M-only attachment are rejected.

Assignment budget arithmetic is exact: `max_execution_ms + delivery_budget_ms <
(complete_by - now) * 1000`, after `now < accept_until`. Rust uses u128 internally;
TS uses bigint. This is a local preflight, not proof of delivery time or enforcement.
Retry comparison authenticates incoming bytes and never mutates replay state.
Content matching is not supported-policy validation; miner-side matching is not
external result verification or Aura PoC. Those distinctions remain explicit.

No existing fixture or cryptographic/economic/Bitcoin owner is changed. C1 does
not execute a workload, debit a balance, advance a head or construct a Bitcoin
transaction. The core contract decision above is the remaining freeze blocker.
