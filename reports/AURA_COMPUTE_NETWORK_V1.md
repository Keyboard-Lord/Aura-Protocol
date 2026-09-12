# Aura Compute Network V1 — C0 architecture and owner map

Classification: PROPOSED DESIGN / IMPLEMENTATION EVIDENCE; NOT ACTIVE AUTHORITY.
Date: 2026-09-12. Baseline: completed Miner V1 at `97ff01f`.
Status: C0 architecture prepared; decisions D1–D4 below require approval before C1.
No compute codec, workload adapter, payment contract or public worker is implemented
by this document. It does not reopen the completed Miner V1 or Bitcoin migration.

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
| Compute compensation | Customer funds the requested useful unit | Authorized assignment, contract-valid verified result, durable delivery availability | Proposed ordinary economic finalization and payment through the existing journal/publisher; no target predicate |
| Optional mining bonus | Existing Miner V1 sponsor funding | Unchanged Miner V1 PoC, target, admission and Accepted winner | Existing mining round, authorization, Head V2, reward obligation and Bitcoin publication |

Useful outputs and compute entitlements survive a failed target test, round expiry,
another miner winning, or the worker choosing never to mine. Losing mining trials
must not repeat or discard completed customer computation. Neither payment is an
Aura token issuance, burn refund or conversion of Bitcoin fees into Aura balances.

The proposed lifecycle is:

```text
customer-funded job → bounded assignment → isolated useful execution
→ workload verifier → durable result available to customer + compute obligation
→ ordinary existing Aura finalization → existing Bitcoin publisher pays worker

independently, if worker opts in:
same finalized result reference + a current signed MinerJobV1
→ existing meter/profile → nonce-conditioned Storm search
→ existing full PoC + proof_hash target → existing coordinated mining bonus
```

Normal compensation needs no mining winner. Aura binding/authorization must precede
Bitcoin publication because that is the existing settlement boundary; a literal
"pay first, then authenticate the payment" implementation would bypass it. Workload
output availability can precede Bitcoin confirmation. Payment owed, payment broadcast
and payment confirmed are distinct durable states, not interchangeable success flags.

## 2. Direct current-state evidence

| Existing owner | Established dependency / gap |
| --- | --- |
| [Registry](../docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md) | Exactly 25 current authority documents. No general compute job/result owner is registered. |
| [Miner profile](../crates/aura_sdk_v1/src/miner.rs) | Frozen J/profile. Intent commits J and exact M. Caller-selected context/route/side/target alternatives reject. |
| [Economic meter](../crates/aura_l2_local_chain_v0/src/economic_meter.rs) | One canonical M; existing attestation evidence can bind data. Its local digest/truth checks do not verify an arbitrary external proof system. |
| [Economic coordinator](../crates/aura_sdk_v1/src/economic/journal.rs) | Existing admission/debit and service execution, actual Aura proof verification, atomic authorization/head/outbox. Accepted does not currently mean external workload verification. |
| [Funding/payment owner](../crates/aura_sdk_v1/src/economic/journal/miner/publication.rs) | `obligation` joins `miner_rewards` to an Accepted round. It cannot pay a non-winning compute worker. General compensation requires an approved additive obligation kind and shared publication ownership. |
| [Authorization](../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md), [economic consent](../docs/authoritative/AURA_LEDGER_AND_BURN_V1.md) | Both signatures bind a specific completed Aura work/reference. A customer's pre-execution job signature cannot implicitly authorize an unknown future Aura proof_hash. |
| [Head V2](../docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md), [Bitcoin](../docs/authoritative/AURA_REPORT_CONTRACT_V1.md) | Preserve formulas, wire, fees/burn separation and reorg behavior. More authorized payments are additional instances of the same path, not another settlement protocol. |

Only these direct boundaries were inspected. Existing M7 acceptance remains the
frozen baseline; no migration, mining or cryptographic gate was rerun for C0.

## 3. Ownership proposal — D4

Add one neutral compute specification to the registry after approval:
`docs/authoritative/AURA_COMPUTE_NETWORK_V1.md`. This would be the 26th document,
not a replacement for the Aurafarming/Miner V1 owner. Do not create it as active
authority until approved contracts and their implementation evidence are ready.
C1/C2 may develop reviewed candidate contracts in this report area first.

| Concept | Single intended owner |
| --- | --- |
| AuraComputeJobV1 identity, customer authorization, versioned routing/resource/privacy policy | New compute owner; one Rust codec with matching TS bytes in C1 |
| Worker assignment/identity, execution receipt, verified-result envelope and adapter registration | Same compute owner; C2 defines distinct worker claims and verifier-issued acceptance |
| Input/program/output/evidence meaning | Versioned workload adapter specification referenced by the job; core treats content as committed opaque bytes |
| Actual external proof acceptance | Pinned workload-specific verifier; never the scheduler or a worker-supplied boolean |
| Existing W/M and Aura economic debit/authorization | Existing pipeline/ledger/authorization owners, extended by explicit compute integration references only |
| Compute obligation, atomic finalization and payment-state integration | Existing economic journal/ledger owner; operational job/assignment/obligation tables, not a new account/balance ledger |
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

## 5. Compensation and Aura authorization — D1/D2

Recommended initial compensation: a fixed customer-funded BTC amount for the
requested unit, reserved before assignment in an operator-custodied dedicated
outpoint. The existing Bitcoin payment owner is generalized once to consume either
a compute entitlement or an unchanged miner entitlement; two independently copied
publishers are not acceptable. Fee budgets remain explicit and separate from burn.
No new service fee, pricing curve, refund charge, transferable credit or token is
selected here. C2 must freeze the funding/cancellation/refund details before use.

The useful worker is the payment beneficiary, not necessarily the actor paying
Aura's existing local burn. Recommended D2: a configured coordinator account pays
that unchanged burn and signs the ordinary Aura work after workload verification.
The customer's job authorization covers the compute purchase; the worker signs
its result; the coordinator's existing two envelopes cover Aura finalization.
There is no fabricated pre-signed future proof_hash, implicit delegation, signature
conversion, Authorization V2 bypass or Bitcoin-fee-to-Aura conversion.

A valid delivered result creates one durable compute entitlement. The existing
Aura finalization must succeed before the Bitcoin publisher can discharge it.
Coordinator outage, stale head, insufficient coordinator burn balance or Bitcoin
failure keeps the valid worker's entitlement pending; it must not be relabelled as
bad work or conditioned on winning a mining round. C2 must define retry ownership
so only one Accepted payment attempt discharges that obligation, without duplicate
payment or release of existing nonce reservations. Customer/worker results remain
available while settlement recovers. A reconstructed Aura wrapper never requires
redoing the already verified useful task merely to get another mining nonce.

Use the same SQLite transaction owner for job/assignment/result/payment metadata
and the existing economic history. There is no second ledger/head or replicated
consensus assumption. Object storage holds immutable output/evidence; staged blobs
must be durable before committing the result/entitlement reference. Recovery must
handle abandoned staged blobs and missing/corrupt objects without paying fabricated
results. An output commitment alone is not delivery or data availability.

Existing open miner rounds pin the ledger until expiry/admission. Compute payment
may wait for that bounded current owner, but must not wait for a mining winner.
The initial scheduler should serve ready compute finalizations before opening a
new optional bonus round. It cannot preempt an already admitted Miner V1 attempt.
C2 must test this scheduling interaction without changing Miner V1 expiry/burn rules.

Custody prevents customer discretion from being required after execution, but the
operator still controls funds and can fail or misbehave. This is not trustless
escrow or atomic fair exchange. Approval must acknowledge that trust boundary.

## 6. Optional mining binding — D3

Recommended carrier: the existing M attestation-evidence surface. C1/C2 freeze a
strict reference-only compute binding profile whose ASCII/binary representation
is unambiguous and unaffected by the existing evidence normalization. Tests must
prove that property; C0 does not declare an untested encoding canonical.

```text
final verified result commitment
→ exact existing M evidence reference
→ existing MinerJobV1.build_work / job-and-meter intent
→ existing context, fresh nonce, Storm, TRACE_ROOT, proof/material/FractalKey
→ existing proof_hash and signed target
```

The immutable verified record must bind the worker and job before association.
The external verifier establishes workload validity; the existing M attestation
only establishes its defined evidence/digest relation. Storm still proves Storm.
Never describe this composition as a new succinct proof of GPU execution or as
the external proof backend replacing Aura's witness backend.

Ordinary Miner V1 remains available unchanged. A compute worker may use its own
verified receipt when constructing a normal miner candidate. A copied reference
does not transfer compute compensation or verified-worker attribution. An unlinked
ordinary miner can still win under existing rules; this proposal introduces no
compute-only mining pool, mandatory useful-work quota, one-use compute credit or
changed winner predicate. Those would be additional protocol decisions.

Compute payment and optional bonus use distinct existing economic attempts and
funding obligations. Both use the same canonical machinery and Bitcoin publisher;
they are not two competing proof formats or ledger chains. The signed target stays
inside J and therefore inside the existing computation dependency. No outer-hash
loop, extra mining nonce, claim-slot reuse, side-input substitution or mutable
post-proof result field is introduced.

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
Initial fixed-price assignments need no performance premium from an unverified
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
| C0 | This map and D1–D4 approval. Resolve authority/payment/binding architecture before implementation. |
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

## 9. Decisions required before C1

These choices are proposals, not changes to existing authority or implementation.

| ID | Exact decision and recommendation | Viable alternative / tradeoff |
| --- | --- | --- |
| D1 — compute compensation | Fixed customer-prefunded BTC, custodial reservation, independent compute entitlement and extension of the existing journal/Bitcoin publisher. No target/winner condition. | Trustless Bitcoin escrow would reduce custody trust but needs a separately designed on-chain contract/dispute model; it is not supplied by Miner V1 or the current OP_RETURN. |
| D2 — Aura signer and burn payer | A configured coordinator account signs the ordinary compute-settlement W/reference and pays the unchanged Aura burn after workload verification. Customer job authorization and worker receipt remain separate. | Worker signs and pays that burn from an existing Aura account; preserves direct worker authorization but requires onboarding/funding and additional worker completion availability. Requiring customer post-result approval risks withholding and is not recommended. |
| D3 — optional result binding | Bind the finalized verified-result reference through a strict profile of existing M attestation evidence; retain all Miner V1 bytes, eligibility and normal unlinked mining. | Bind each result through freshly signed J side inputs; needs per-result job publication, changes the requested Storm trajectory and is less reusable. Neither choice makes Storm verify the external workload. |
| D4 — ownership | One new neutral compute owner, registered as the 26th authoritative document when contracts/implementation are ready; existing generic economic/Bitcoin/miner owners retain their concepts. | Expand the current Aurafarming owner to cover non-mining compute; avoids a registry addition but conflates a universal compute lifecycle with optional mining. |

Approval requested is for these architectural directions and subsequent C1/C2
contract design. It is not approval of unspecified canonical bytes, a particular
proof backend, confidential execution, new tariffs, live funds or public execution.
C0 stops here; C1 is blocked until this owner/economic/binding decision is resolved.

## 10. C0 verification evidence

Validated 24 local links across this proposal, the active slice register and the
archived miner register. The archive is byte-identical to the completed register
at `97ff01f`. Changed-file scope is exactly those three documentation/register
files; source, authoritative documents and frozen fixtures are unchanged.
Whitespace checks, including `git diff --check`, passed. No runtime tests or new
performance measurements were needed for this architecture-only node.
