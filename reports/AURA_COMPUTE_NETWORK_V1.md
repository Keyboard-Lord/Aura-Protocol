# Aura Compute Network V1 — C0 architecture and owner map

Classification: APPROVED C0 ARCHITECTURE / IMPLEMENTATION EVIDENCE; NOT ACTIVE PROTOCOL AUTHORITY.
Date: 2026-09-12. Baseline: completed Miner V1 at `97ff01f`.
Status: C0 DONE. D1–D4 APPROVED with the user's controlling amendments in section 9.
Subsequent C1 approval, implementation and freeze state: [C1 evidence](AURA_COMPUTE_JOB_V1_C1_DESIGN.md).
Reconciliation: C1's codec/core contracts are now frozen and implemented; later
compute lifecycle/workloads remain DOC > CODE. This C0 record preserves architecture
and approval history. Current definitions live in the
[compute owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md); current execution
state lives in the slice register. Miner V1 and Bitcoin migration remain unchanged.

## 1. Architectural contract

One compute job requests one useful unit of work. A worker voluntarily accepts
that unit under explicit limits. Successful workload verification and durable
customer availability establish its compute-payment entitlement, independent of
mining difficulty, round participation or a mining winner. Duplicate execution is
not an implicit auction in which only the fastest worker is paid. Initial scheduling
assigns one funded unit to one worker; any deliberately purchased redundant work
must be explicitly funded as separate requested units.

There are two distinct rewards:

| Obligation | Source | Eligibility | Existing Aura relationship |
| --- | --- | --- | --- |
| Compute compensation | Customer funds the requested useful unit | Authorized assignment, contract-valid verified result, durable delivery availability | Authenticated additive compute accounting in EconomicJournalV1 and the shared payment owner; no automatic Aura burn, Head V2 transition or target predicate |
| Optional mining bonus | Existing Miner V1 sponsor funding | Unchanged Miner V1 PoC, target, admission and Accepted winner | Existing mining round, authorization, Head V2, reward obligation and Bitcoin publication |

Useful outputs and compute entitlements survive a failed target test, round expiry,
another miner winning, or the worker choosing never to mine. Losing mining trials
must not repeat or discard completed customer computation. Neither payment is an
Aura token issuance, burn refund or conversion of Bitcoin fees into Aura balances.

The proposed lifecycle is:

```text
customer-funded job → bounded assignment → isolated useful execution
→ workload verifier → durable result available to customer + compute obligation
→ authenticated compute acceptance/accounting → shared payment owner pays worker

independently, if worker opts in:
verified result commitment → derived existing MinerJobV1-controlled inputs
→ operator signs/publishes J → existing profile → nonce-conditioned Storm search
→ existing full PoC + proof_hash target → existing coordinated mining bonus
```

Normal compensation needs no mining winner and no automatic Aura burn or Head V2
advance. Authenticated compute admission, result acceptance and payment accounting
extend EconomicJournalV1; they do not pretend to be existing Aura authorization.
The unchanged burn/Authorization V2/Head V2 rules apply when a result enters the
existing Aura mining/settlement path. Do not apply those charges twice.

Output availability, compensation owed, payment broadcast and payment confirmed
are distinct states. C1 designs commitments only; live monetary settlement remains
unimplemented and unapproved. Sharing a payment owner does not permit claiming
that today's miner-only publisher already pays ordinary compute obligations.

## 2. Direct C0 baseline evidence

| Existing owner | Established dependency / gap |
| --- | --- |
| [Registry](../docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md) | At C0: 25 authority documents, no compute owner. C1 now registers the approved compute contract; its evidence records the freeze. |
| [Miner profile](../crates/aura_sdk_v1/src/miner.rs) | Frozen J/profile. Intent commits J and exact M. Caller-selected context/route/side/target alternatives reject. |
| [Economic meter](../crates/aura_l2_local_chain_v0/src/economic_meter.rs) | One canonical M; existing attestation evidence can bind data. Its local digest/truth checks do not verify an arbitrary external proof system. |
| [Economic coordinator](../crates/aura_sdk_v1/src/economic/journal.rs) | Existing admission/debit and service execution, actual Aura proof verification, atomic authorization/head/outbox. Accepted does not currently mean external workload verification. |
| [Funding/payment owner](../crates/aura_sdk_v1/src/economic/journal/miner/publication.rs) | `obligation` joins `miner_rewards` to an Accepted round. It cannot pay a non-winning compute worker. General compensation requires an approved additive obligation kind and shared publication ownership. |
| [Authorization](../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md), [economic consent](../docs/authoritative/AURA_LEDGER_AND_BURN_V1.md) | Existing economic consent and Authorization V2 bind completed Aura work/reference. New authenticated compute admission/result acceptance needs its own contract; it must not fabricate either existing envelope or automatically invoke their burn/head path. |
| [Head V2](../docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md), [Bitcoin](../docs/authoritative/AURA_REPORT_CONTRACT_V1.md) | Preserve formulas, anchor wire, fees/burn separation and reorg behavior. Ordinary compute accounting does not itself advance Head V2. Payment orchestration must extend the shared owner without claiming an unapproved new anchor identity. |

Only these direct boundaries were inspected. Existing M7 acceptance remains the
frozen baseline; no migration, mining or cryptographic gate was rerun for C0.

## 3. Approved ownership boundary — D4

Aura core owns the common compute contracts; adapters own workload semantics and
hardware remains replaceable. The registered neutral
[compute owner](../docs/authoritative/AURA_COMPUTE_NETWORK_V1.md) now holds C1's
approved common definitions. C0 itself did not change registry membership;
C1 promoted the contract after approval and full gate evidence. C2 definitions
remain future work and must not acquire authority implicitly.

| Concept | Single intended owner |
| --- | --- |
| AuraComputeJobV1 identity, customer authorization, versioned routing/resource/privacy policy | New compute owner; one Rust codec with matching TS bytes in C1 |
| Worker assignment/identity, execution receipt, verified-result envelope and adapter registration | Same compute owner; C2 defines distinct worker claims and verifier-issued acceptance |
| Input/program/output/evidence meaning | Versioned workload adapter specification referenced by the job; core treats content as committed opaque bytes |
| Actual external proof acceptance | Pinned workload-specific verifier; never the scheduler or a worker-supplied boolean |
| Existing W/M and Aura economic debit/authorization | Existing pipeline/ledger/authorization owners, invoked under their unchanged rules only when entering the existing Aura mining/settlement path |
| Compute obligation, authenticated acceptance and payment-state integration | Existing economic journal/ledger owner; operational job/assignment/obligation tables, not a new account/balance ledger |
| Bitcoin funding/publication/replacement/observation | Existing report contract and shared funding/payment implementation; original miner adapter retains its exact behavior |
| Optional mining eligibility and bonus | Existing Aurafarming/Miner V1 owner; no competing proof identifier or compute-only fork choice |
| Scheduler policy, capability selection and market scoring | Compute owner defines the contract; scheduler implementation never owns proof correctness or payment entitlement |
| CPU/GPU/FPGA/ASIC execution | Adapter/backend owns execution. Hardware implements the same committed task relation, not another job or result meaning |

Job and result commitments identify upstream objects, as Miner V1's job commitment
already does. They are not alternate Aura proof identities and never replace
`proof_hash` in authorization, Head V2 or OP_RETURN.

Do not copy job-owned input/program/verifier fields into the result as competing
authoritative values. The result references the job commitment and resolves those
bindings through it. C2 distinguishes an untrusted worker execution receipt from
a verified result; deserializing an envelope never manufactures verification.

## 4. Canonical contracts — bounded C1/C2 work

C1 freezes job framing, integer/length rules, identity/freshness, customer signing,
versioned workload/verifier references, execution/output specifications, resource
and deadline policy, privacy/hardware requirements and compensation/mining policy.
Unknown or unavailable adapters/privacy methods reject before execution or data
release. No ambiguous JSON, hidden defaults, inferred versions or normalization.
Optional mining is an explicit tagged mode; it is not missing/null fields. The
actual signed mining target remains owned by MinerJobV1, not duplicated into a
compute job as another authoritative difficulty setting.

Each job references immutable input and program/model content plus an explicit
adapter/version and verifier configuration. C1 must specify what every commitment
covers, including program/public-input relation, verifier/key provenance and limits.
Byte framing and commitment algorithms are not silently frozen by this C0 proposal.
Rust/TS positive and negative vectors precede production consumers.

C2 freezes worker-authenticated assignments/receipts and VerifiedComputeResultV1,
including job/assignment linkage, output/evidence references, verification class,
verifier outcome and attribution. Hardware/resource/time claims retain their
provenance; a proof of an answer does not prove a GPU model, physical runtime or
power use. Fixed-price compensation must not depend on self-reported resource use.
Customer/work signatures are distinct from existing Aura Authorization V2.

C2 also resolves lease fencing, retries, deadline receipt authority, cancellation,
unused-funding return, partial failure, delivery retention and atomic payment
transitions before coding production state. Worker clock claims cannot alone prove
timely completion. No speculative first-to-finish redundancy or unbounded unpaid
replacement lease is allowed. Customer acknowledgement must not be a discretionary
veto after valid contracted work and durable delivery availability.

## 5. Approved compensation and coordination — D1/D2

The requester prefunds compensation before workers can earn against a job. A
durable coordinator reservation protects that commitment. Compute compensation
and sponsor-funded mining rewards remain separate obligations. Bitcoin is the
intended external payment asset; no Aura token, issuance, inflation or synthetic
balance is introduced. C1 may design funding/payment commitments, not live settlement.
Later batching or payment channels must not change compute-job identity.

EconomicJournalV1 is the only durable coordinator. Authenticated compute-job
admission and result acceptance extend that owner, using compute records in the
same durable transaction system rather than another ledger. Useful completion
alone consumes no existing Miner V1 burn and advances no Head V2. Normal compute
compensation does not depend on mining qualification. Existing burn, Authorization
V2 and Head V2 apply exactly as already defined on entry to Aura mining/settlement.

The earlier recommendation to make the coordinator automatically burn and advance
Head V2 for every ordinary compute payment is SUPERSEDED by approved D2. Do not
implement it or treat the C0 approval as acceptance of that earlier recommendation.

C2 must define authentication, durable reservation/assignment/result/payment
transitions, retries, cancellation/refunds and recovery before production use.
One accepted useful unit creates at most one compute obligation. Payment failures
must not relabel valid delivered work as invalid or require winning a mining round.
Requester acknowledgement cannot become an unreviewed veto after contracted valid
delivery. Existing Bitcoin fees and Aura burn remain separate accounting concepts.

The current miner publication implementation requires an Accepted miner attempt;
D2 does not change that implementation today. Ordinary compute publication needs
an additive shared-owner extension. It must not invent a dummy miner winner,
a fake proof_hash, automatic burn/head transition or a copied second publisher.
Specific payment/anchor transaction behavior is later contract work, not silently
chosen here. No on-chain trustless escrow or fair-exchange guarantee is established.

Immutable output/evidence storage must become durable before accepted references
and entitlement are committed. An output hash alone is not delivery. Detailed
retention, unavailable/corrupt objects and coordinated recovery belong to C2.

## 6. Approved result binding — D3

There is exactly one canonical compute_result_commitment. It binds the canonical
compute-job commitment, worker, input, program/model, output, execution evidence,
verification method and verdict, and resource-accounting commitment. C2 will own
the exact result-envelope preimage. Job-owned fields must resolve unambiguously
through the job; there must not be independently editable duplicate definitions.
The result commitment is an upstream object commitment, not another Aura proof ID.

For compute-linked mining the binding MUST be in signed MinerJobV1-controlled
computation inputs before qualification. C1 must freeze and vector one
domain-separated result-to-input derivation without changing the frozen J wire.

```text
verified result commitment → prescribed existing J inputs
→ operator signs/publishes J → existing J + M intent/profile
→ nonce-conditioned Storm → TRACE_ROOT → proof/material/FractalKey
→ existing proof_hash → existing signed-target predicate
```

A result reference added only to miner-selected M evidence is INSUFFICIENT and the
earlier M-only recommendation is SUPERSEDED. A mutable post-proof attachment is
also insufficient. A result cannot be attached retroactively to an already-signed
unbound round; it must be known before that compute-linked J is signed.

The existing round-opening API already accepts side_a and side_b as 110-byte
inputs, and the existing J signature and profile bind both. This is the C1 design
boundary; exact derivation is not approved merely because these fields exist.
Changing signed target still changes the prescribed computation. No additional
nonce, mining_hash, alternate proof/settlement identifier or changed winner rule.

Workload verification establishes external correctness; Storm still verifies its
own prescribed computation. Useful outputs and normal compute payment remain
available without mining. Original Miner V1 remains intact; worker-exclusive bonus
rules or a mandatory compute-only mining pool are not introduced by this approval.

## 7. Adapters, hardware and hostile execution

Core validates contracts, ownership, lifecycle and verification provenance.
Adapters define committed execution/output meaning, hardware compatibility and
verification. A registered verifier is pinned by code/version/key or another exact
approved verification configuration. A customer-provided "verifier" that always
returns success cannot self-register as cryptographic verification. Engine identity
alone is insufficient: public inputs and program/model identity must be checked.

Priority 0 is a real externally requested proof-generation relation with an actual
verifier, targeting GPU execution first. Select and approve a concrete proof backend
and GPU environment before C3; no backend has been chosen in C0. Aura's existing
Storm witness replay must not be relabelled as the new general ZK service. CPU
reference execution and candidate stable proof kernels support parity and the
future Proof ASIC lane, not a CPU-only substitution for C3's GPU acceptance.

C3 needs minimal isolation even though general sandboxed workers are C6. Use a
pinned approved prover/verifier implementation, bounded input/proof/program sizes,
CPU/RAM/GPU/time/output limits, isolated work directories and denied host secrets/
unapproved networking. Untrusted guest programs need the backend's reviewed guest
boundary. Do not execute arbitrary customer native binaries on a volunteer host.
General containers, inference engines and arbitrary plugins remain later nodes.

Worker owner policy always constrains scheduling: opt-in workload categories,
availability/idle schedule, CPU/GPU/RAM/VRAM limits, network/storage, battery,
thermal/power controls, minimum payment and privacy restrictions. Refuse work when
a requested hard limit cannot be enforced on the platform; do not pretend a
percentage setting is universally enforceable. Revocation/cancellation behavior
must distinguish a safely stopped assignment from a completed payable result.

CPU/GPU/Aura Proof ASIC/Aura Matrix ASIC are capability classes, not separate
protocols or proof-strength claims. Accept measured/attested capabilities only to
the extent the measurement supports them; advertisements are untrusted hints.
The fixed-price candidate in C1 needs no performance premium from an unverified
claim. C8 freezes hardware interfaces only after real kernel/backend measurements;
no ASIC instruction set, wattage or throughput is invented at C0.

Privacy policy names anticipate PUBLIC, SANDBOXED, CONFIDENTIAL, TEE_REQUIRED and
LOCALITY_RESTRICTED. PUBLIC never means arbitrary host access; SANDBOXED does not
provide confidentiality from the worker. Unsupported confidential/TEE/locality
requirements reject before data distribution. Verification methods remain distinct:
cryptographic proof, replay, cheap validity check, redundancy, sampling, trusted or
TEE attestation, and verifiable ML. None implies the guarantees of another class.
Future sensitive genomic/model/customer data is not routed to arbitrary workers.

## 8. Dependency order and acceptance boundaries

| Node | Dependency and bounded output |
| --- | --- |
| C0 | DONE: D1–D4 approved as amended in section 9; C1 design authorized. |
| C1 | C0: freeze universal job bytes, signatures/commitments, limits/identity and Rust/TS negative vectors; no workload implementation. |
| C2 | C1: capability/assignment/receipt/verified-result contracts, independent compensation state machine and shared payment extension design; freeze binding and lifecycle before adapters. |
| C3 | C2: one real GPU-oriented Priority 0 proving adapter, minimal necessary isolation, actual verification/delivery/compute payment and optional unchanged mining path. |
| C4 | C3: deterministic/open-model inference first; stronger verification only when implemented. Proprietary Astra execution is not assumed. |
| C5 | C4: molecular/docking, then rendering/media, then Monte Carlo; one adapter at a time. |
| C6 | C5: general sandboxed CPU/GPU worker; science, optimization and builds/CI only behind that boundary. |
| C7 | C6: justified confidential/TEE/locality capabilities before sensitive AI/genomics/finance/EDA data. |
| C8 | C7 and measured P0 kernels: Proof ASIC host/I/O/verification interface, widths, bandwidth and measured performance/power requirements; no invented silicon metrics. |
| C9 | C8: measured capability discovery, pricing/bidding/routing and reliability; preserve proof/payment ownership. |
| C10 | C9: adversarial complete-network validation, CPU/GPU/ASIC parity where actually available, restart/partition/payment/privacy/sandbox attacks and explicit activation decision. |

Fine-tuning/small training and EDA remain lower-priority adapters behind the required
isolation/privacy/market facilities; do not start them while a higher-priority node
is active. Tightly coupled MPI/CFD/global models, giant synchronous training, databases
and latency-sensitive serving remain deferred. No mandatory proprietary hardware.

Threat tests belong to their owning node: fabricated evidence/public-input mismatch,
job/result/nonce replay, copied-worker identity, duplicate leases/payments, fake
resource/capability claims, withholding, cancellation races, collusion, sandbox escape,
host credential/network access, privacy downgrade, unavailable verifier/objects,
stale snapshots and Bitcoin replacement/reorg. No correctness or payment claim
is inferred from a successful scheduler dispatch.

## 9. Controlling approval record — D1–D4 APPROVED

Source: the user's explicit approval in this task on 2026-09-12. This record
supersedes the pre-approval recommendations; it approves C0 only and C1 design,
not unspecified C1 bytes, adapters, live funds or public worker execution.

### D1 — FUNDING CUSTODY — APPROVED

- Customer-prefunded compensation with durable coordinator reservation.
- Requester funds useful compute before workers can earn against the job.
- Compute compensation and Miner V1 rewards are separate economic obligations.
- No Aura token, inflation, issuance or synthetic balance.
- Bitcoin remains the intended external payment asset unless separately approved.
- C1 may define funding/payment commitments; no live monetary settlement yet.
- Future batching/payment-channel optimizations may be additive and must not
  change compute-job identity.

### D2 — COORDINATOR / AUTHORIZATION / BURN — APPROVED

- EconomicJournalV1 remains the sole durable coordinator.
- Useful-job admission/result acceptance must be authenticated and coordinated
  through an additive extension of that owner, not a second ledger/coordinator.
- Completing useful compute does NOT automatically consume existing Miner V1 burn
  and does NOT automatically advance Head V2.
- Normal compute compensation is independent of mining qualification.
- Existing Aura burn, Authorization V2 and Head V2 apply exactly as already defined
  when a verified result enters the existing Aura mining/settlement path.
- Do not double-burn a result simply because it was useful work. Preserve frozen
  Miner V1 economics.

### D3 — RESULT BINDING — APPROVED

- One canonical compute_result_commitment binds at minimum: canonical job
  commitment, worker identity, input commitment, program/model commitment, output
  commitment, execution-evidence commitment, verification method, verification
  verdict and resource-accounting commitment.
- No second Aura proof identity, mining_hash or alternate settlement identifier.
- A useful result made mining-eligible MUST be cryptographically included in the
  signed Miner V1 job/computation before qualification is evaluated.
- Preserve frozen MinerJobV1 wire and existing proof_hash.
- C1 must vector/freeze one domain-separated derivation from the result commitment
  into existing signed MinerJobV1-controlled inputs before adapters depend on it.

### D4 — COMPUTE OWNERSHIP — APPROVED

- Aura core owns job/result envelopes, commitments, coordination, verification
  verdict, accounting state and settlement state.
- Workload adapters own workload-specific execution and verification semantics.
- CPU/GPU/FPGA/Aura ASIC backends are replaceable and must not change job meaning
  or result identity. Hardware neutrality is mandatory.
- Requester retains ownership/control of inputs and useful output by default.
- Workers receive only minimum temporary execution rights; execution grants no
  ownership of inputs, model weights or outputs.
- Aura retains commitments/evidence needed for verification/accounting, not
  automatic ownership of customer content.
- Public/open workloads may explicitly opt into different licensing.

This approval closed C0 and opened C1. Subsequent C1 approvals and the completed
freeze are recorded in [C1 evidence](AURA_COMPUTE_JOB_V1_C1_DESIGN.md). Neither
approval is blanket approval of later compute implementation or public activation.

## 10. Prior C0 proposal verification evidence

At the pre-approval checkpoint, validated 24 local links across this proposal, the active slice register and the
archived miner register. The archive is byte-identical to the completed register
at `97ff01f`. Changed-file scope is exactly those three documentation/register
files; source, authoritative documents and frozen fixtures are unchanged.
Whitespace checks, including `git diff --check`, passed. No runtime tests or new
performance measurements were needed for this architecture-only node.
