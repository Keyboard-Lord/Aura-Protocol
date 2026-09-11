# AURA_MINER_PROTOCOL_V1

**Classification: APPROVED DESIGN DECISION / NOT ACTIVE PROTOCOL AUTHORITY.**
**Status: DESIGN COMPLETE — D1–D6 APPROVED; M4 DONE, M5 READY.**
Baseline: completed Bitcoin migration at `f64fb4f`, including its economic integration.
Design approval: 2026-09-10. Implementation status updated: 2026-09-11.
The Rust/TS job/profile boundary, Rust local mining and durable miner coordination
are implemented; Bitcoin reward publication remains next. Existing canonical outputs and
authoritative specifications are unchanged. The review below is an internal design review, not an
independent cryptographic audit or proof of economic security.

## 1. Approved architecture and decision boundary

Build V1 as **coordinated, sponsor-funded Storm computation mining** over the existing
economic journal. Miners compete to find a fully verified, nonce-bound Storm proof
whose existing `proof_hash`, interpreted as an unsigned big-endian integer, meets
the signed job target. One journal selects one admitted contender per round; only
an Accepted contender is a winner. Bitcoin publishes the same proof reference.

This provides a concrete PoC/PoW eligibility rule, not permissionless consensus.
The journal operator remains trusted for job release, ordering, availability and
reward custody. The frozen baseline neither rolls back admitted burns nor selects
among independently maintained economic forks. Introducing cumulative-work fork
choice would require a separately approved replicated state/authorization model.

V1's useful task is narrowly **customer-requested nonce-conditioned Storm trajectory
generation**, for consumers that want those trajectories themselves. It is not a
claim that Storm proves arbitrary application work, that all losing trials are
useful, or that a commercial customer exists. A fixed-answer external job cannot
simultaneously remain unchanged and have its entire Storm trace varied by every
mining nonce. Splitting off cheap nonce hashing would establish hash work instead
of the intended Storm work. That alternative is not this proposal.

On 2026-09-10 the user replied **“yes approved”** to the explicit request to approve
decisions D1–D6 as the V1 design contract. Section 13 records that approval. These
requirements define the approved implementation design and do not supersede the
active protocol owners. M2's codecs, M3's local search and M4's coordinated rounds
are implemented; section 11 links their evidence separately from future publication.

## 2. Current-state dependency map

| Existing owner | Miner dependency / implication |
| --- | --- |
| [Storm execution](../crates/aura_intent_lineage_v1/src/storm_execution_v1.rs), [derivations](../docs/authoritative/AURA_DERIVATION_FUNCTIONS_V1.md) | Sides determine initial state; the complete context determines parameters and every step's forcing. Nonce changes can affect computation without changing recurrence. |
| [Proof boundary](../docs/authoritative/AURA_STARK_SPEC_V1.md), [binding](../docs/authoritative/AURA_PROVER_BINDING_V1.md) | Canonical claim plus full witness; Rust verifies by replay. No succinctness, ZK, runtime measurement or proof of exclusive miner execution. |
| [Artifact owner](../docs/authoritative/AURA_ARTIFACT_STRUCTURE_V1.md) | Exactly one material → FractalKey → `proof_hash` path. Outer subject/nonce must match the verified context. |
| [Economic W](../crates/aura_sdk_v1/src/economic.rs), [meter](../crates/aura_l2_local_chain_v0/src/economic_meter.rs) | W carries exact M plus the Storm tuple. Burn uses M, not iteration count or Bitcoin fees. Existing full-verification tariff remains fixed. |
| [Journal](../crates/aura_sdk_v1/src/economic/journal.rs), [ledger rules](../docs/authoritative/AURA_LEDGER_AND_BURN_V1.md) | One admitted attempt per ledger/head; debit before service execution; every terminal outcome retains its burn and advances the head. No Aura reward-credit operation exists here. |
| [Authorization](../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md) | Miner is controller/payer/subject; both existing signatures required. Successful reservation follows actual proof/material/lineage verification. |
| [Head V2](../docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md) | Commits exact W, predecessor, outcome and debit snapshots. It is a durable linear economic history, not a PoW chain-selection mechanism. |
| [Bitcoin publication](../docs/authoritative/AURA_REPORT_CONTRACT_V1.md) | OP_RETURN contains only the existing proof reference. Reorgs revoke confirmation, not economic or authorization history. |
| [Aurafarming research](../docs/authoritative/AURA_AURAFARMING_NODES.md), [hierarchy experiment](AURA_STORM_HIERARCHY_V2_EXPERIMENT.md) | Research only. Twenty-node topology, EMA forgetting and proof-convergence claims do not establish consensus, proof soundness or rewards. Hierarchical V2 does not feed macro state back into micro execution and is not needed here. |

The production path remains W → admission/debit → Storm → TRACE_ROOT → proof →
material → proof_hash → Authorization V2 → Head V2/outbox → Bitcoin. Private miner
evaluation uses these same computational primitives; it cannot settle, reserve
authorization or create an alternate production path.

## 3. Exact approved mining inputs

### Signed job J

One approved fixed binary job encoding, **471 bytes**, in this exact order:

| Field | Bytes / encoding |
| --- | --- |
| domain | ASCII `AURA_MINER_JOB_V1` |
| job_version | u8 = 1 |
| network | Existing Bitcoin network byte |
| operator_key | Valid BIP340 x-only key, 32 bytes, pinned by deployment policy |
| journal_namespace | 32 bytes, explicitly initialized once per coordinated journal |
| policy_epoch, round_number | Two u64 little-endian integers |
| prior_head_sequence | u64 little-endian |
| prior_head_hash | Existing Head V2 current hash, 32 bytes |
| challenge | Fresh CSPRNG 32 bytes, generated after prior state is fixed |
| side_A, side_B | Two existing 110-byte inputs, supplied by the task customer |
| iteration_count N | u64 little-endian; strictly positive and within configured resource limits |
| target T | Exactly 32 bytes, unsigned big-endian; `1 <= T < 2^256 - 1` |
| max_work_bytes, max_meter_bytes | Two u64 little-endian bounds, also bounded by the operator's host policy |
| opened_at, expires_at | Two u64 little-endian Unix seconds; `opened_at < expires_at` |
| reward_satoshis R | u64 little-endian, positive for a funded job; must satisfy wallet amount/output policy |

No optional fields, extra nonce, alternate serialization, sorting or normalization.
Reject unknown versions/networks, invalid keys, overflow and any other byte length.
The job signature is a detached 64-byte BIP340 signature over
`TaggedSHA256("AURA_MINER_JOB_SIGNATURE_V1", J)`. The operator is also the sponsor
in V1; a multi-party job market is outside this contract. Its key is authenticated
against deployment policy, not trusted merely because it appears inside J.

`job_commitment = SHA256(J)` is an internal job binding, not another proof identifier.
Its domain is already in J. Store the raw J once; downstream records reference it.
Opening a round atomically pins the current ledger/head, reserves the sponsor's
reward funding and records J before publication. No unpublished or replayed job is
eligible. Round numbers increase without reuse within the namespace, including
empty or failed rounds; overflow stops new work. Job expiry uses the trusted
operator clock, not Bitcoin timestamps or a decentralized time oracle.

### Candidate construction

The miner supplies the existing canonical M, with its existing account as payer,
matching the pinned ledger and next-head linkage. All existing structural rules,
full-verification tariff and local execution/settlement rules apply. M may describe
any work admitted by those existing rules; it is not interpreted as arbitrary
computation proved by Storm. The separately purchased task is J's trajectory.

Derive the existing context's intent, without a cycle through W or proof_hash:

```text
I = SHA256("AURA_MINER_INTENT_V1" || job_commitment || u64_le(len(M)) || M)
```

| Existing Storm context / input | Required mining profile value |
| --- | --- |
| context_version and execution domain | Existing V1 constants |
| network_id | J.journal_namespace; this explicit miner profile mapping does not change generic Aura network semantics |
| intent_hash | I; mirrored only in the existing authorization lineage owner |
| freshness_nonce | Miner-generated CSPRNG 32 bytes; the sole mining nonce, also the existing authorization nonce |
| valid_from, valid_until | Both zero; no new interpretation of generic context time fields |
| controller_id | Miner x-only public key, equal to M's payer |
| route_tag | `SHA256(ASCII("AURA_MINER_PROTOCOL_V1"))`, an explicit miner route discriminator |
| side_A, side_B, iteration_count | Exactly J's values |

Construct W using the existing owner. The miner never supplies an independently
chosen intent, target, side input, work count or route field. A different valid M
changes I and therefore Storm's parameters/forcing, preventing a cheap post-proof
choice of economic work. Payer/key changes also change the context. Changing only
signature randomness never changes mining eligibility.

Build the existing deterministic claim/proof with both historical trailing claim
commitments fixed to zero, derived compact public inputs and empty verification-key
bytes, exactly as the completed economic coordinator already does. No alternate
witness ordering, proof backend or mutable trailing slot is eligible. Sign the
unchanged EconomicConsentV1 and Authorization V2 envelopes. Nonce generation is a
producer requirement; a verifier cannot establish RNG quality from one nonce.
The 32-byte mining nonce is distinct from a Schnorr signing nonce.

Candidate identity is the existing `(network, subject, freshness_nonce)` plus the
stored W/target equality rule. References use only `proof_hash`; there is no
`mining_hash`, candidate-hash alias or second serialization of a proof.

## 4. Exact PoC and PoW predicates

Let `Inputs(J,M,key,r)` be the construction above, `C` its canonical Storm claim,
`P` its existing witness-backend proof, and `PI(C)` its derived compact inputs.

```text
PoC(J, M, key, r, C, P) :=
    exact_mining_profile(J, M, key, r, C)
    AND existing_verify_storm_air_real_v1(P, PI(C)) succeeds
    AND P's decoded claim equals C
    AND existing_material_and_FractalKey_binding(P, PI(C), empty_VK, key, r)
        equals the signed proof_hash

s = OS2IP_BE(proof_hash[0..32])
PoW_valid := PoC AND 0 <= s <= T
eligible := PoW_valid AND existing_signatures_and_lineage_valid
            AND current_job_and_ledger_admissible
winner := eligible AND owned_admitted_round AND existing_terminal_outcome = Accepted
```

Comparison is inclusive; exactly T passes and T+1 fails. No reversed display hash,
floating point, compact Bitcoin nBits interpretation, hash of a signature, extra
post-trace nonce, or hashing of a claim that omits the full proof binding.

PoC proves correctness of the prescribed input-bound trace: initialization,
parameters, every forcing pair and recurrence step, state ordering, final state,
TRACE_ROOT and canonical witness. It does not prove elapsed time, energy spent,
which physical machine executed it, non-outsourcing or useful application semantics.
PoW adds a probabilistic scarcity condition to a valid PoC; it does not strengthen
PoC correctness. A failed difficulty test is not an invalid computation.

The service does **not** accept an external replacement proof or completion verdict.
It reconstructs and verifies the existing proof after admission. The supplied low
`proof_hash` is only a cheap pre-admission filter until this verification finishes.
Moving expensive chargeable proof checks into free admission would change the
frozen burn boundary and is not proposed.

## 5. Usefulness and computational scarcity

The explicit customer contract is: receive the complete reproducible Storm
trajectory/proof for the signed sides, job/intent, miner key, nonce and N. The
customer accepts nonce-conditioned, threshold-selected samples for experiments,
analysis or regression corpora about Storm itself. The selected sample is not
advertised as unbiased randomness; a miner can withhold samples or grind identities.
The coordinator must retain J and W so the exact proof/trajectory remains
reconstructible. A future general-purpose compute market needs its own verified
relation and an approved task-to-work reduction.

Calling this **useful PoW** is conditional on independent customer demand for that
specific output. A sponsor rewarding a meaningless hash search does not establish
utility. Losing local trials need not be published or rewarded and may have no
application value. A requirement that every trial solve the same externally fixed
job would reject this profile; it is not resolved by renaming randomness as work.

Under a random-output heuristic and independent eligible trial assumptions:

```text
q = (T + 1) / 2^256
E[trials per qualifying PoC] = 1/q
E[miner computation] ~= C_storm_and_canonical_material(N) / q
```

These are probabilistic expectations, not per-winner lower bounds: a miner can win
on its first trial. N controls work per trial; T controls expected trials. A larger
N is not additional chain weight, and the unchanged Aura burn does not scale with
N. Verification currently replays O(N) work and the witness has O(N) size. Honest
mining can evaluate many trials locally while the coordinator verifies only
submitted contenders, but fabricated low references can still force costly admitted
failures. Fixed limits, existing funded payer accounts, queue bounds and operator
rate control are required; a signature alone is not anti-Sybil protection.

No theorem currently establishes Storm's sequential hardness, non-amortization,
ASIC resistance or minimum energy cost. The dependencies obstruct obvious
trace-reuse attacks but are not such a theorem. The finite-field quadratic map is
not injective; uniqueness must never be inferred from its final state alone.

## 6. Difficulty and adjustment model

**Approved V1: fixed N and T per explicitly configured policy epoch; no automatic
retarget.** Within an epoch every job uses the same N, T and maximum byte bounds.
Job expiry/reward/side inputs may vary; the target may not be selected by a miner.
The operator can start the next consecutive epoch only after the previous round
has closed and no attempt remains in flight. New parameters must be published and
persisted before generating/releasing that epoch's first job challenge. Changing
policy never changes existing candidate eligibility retroactively.

The adjustment algorithm is therefore `T_next = T_current, N_next = N_current`
unless an explicit operator epoch transition occurs. Epoch zero has explicit
configuration, not inferred defaults. This deliberately accepts centralized target
policy; it is not a permissionless difficulty algorithm. Wall-clock reports,
self-reported hash rate and invalid/withheld candidates never automatically retarget.

Calibrate deployment configuration from measured full trial and verification cost,
memory, proof size, sustained request capacity and the sponsor budget. Production
numbers are not guessed here. A benchmark selects explicit limits before activation;
it may not change the approved equations or burn tariff. If the frozen tariff plus
admission controls cannot bound attack costs, do not launch: changing that tariff
requires a separate USER_DECISION. The probe uses N=64 and T=2^252−1 (q=1/16) only
as reproducible research inputs, not as economically secure deployment settings.

An automatic observed-time retarget or cumulative-work competition is a viable
future alternative, but needs an agreed clock/history, manipulation analysis and
fork semantics. It is not silently included as an optional V1 mode.

## 7. Lifecycle, accounting and head competition

The existing journal remains the sole state writer. New miner metadata is
composed into its transactions, not committed in a second database afterward.

| Stage / event | Economic and miner effect |
| --- | --- |
| Open funded job | Require no active attempt; pin head/ledger and reserve reward funding. No burn, authorization or Head V2 transition. |
| Private trial / above-target result | Local compute only; no admission or Aura charge. Unpublished attempts cannot be metered by the service. |
| Malformed, expired, stale, unsupported, underfunded or above-target submission | Reject before admission; no new attempt or burn. |
| Candidate admission | Verify J/profile, canonical inputs and both signatures; apply the existing ledger/nonce checks. Atomically claim the round and perform the existing debit/attempt commit. |
| In-flight contender | Run the unchanged work/proof pipeline. Job expiry does not cancel it or manufacture a failure. |
| Accepted + verified target | Existing authorization/head/outbox finalization plus winner and reward-obligation records in the same transaction. One winner. |
| ExecutionRejected / VerificationRejected / SettlementRejected | Existing full burn/head advance, no new authorization/anchor. Close the round without a winner; release the unused reward reservation. Other candidates are stale. |
| Process death/storage failure | Existing admitted work stays pending. Resume from J/W and durable ownership, with no future signature or external completion message needed. |
| Valid retry of an existing attempt | Existing tuple/W/target lookup takes precedence over closed/expired job or current-head checks. Same receipt/charge/reward obligation; re-signing is not new work. |
| Open job expires with no admission | Close without head advance or Aura charge. Release funding; a new round must use a new challenge and number. |

The first contender that passes pre-admission checks and acquires the journal's
immediate transaction wins **admission**, not a reward. Its outcome determines
whether there is a winner. A fabricated low target can acquire admission but cannot
win authorization or reward; it pays the existing burn if admitted. This can also
stale honest work, a material griefing risk, not a solved fairness problem.

Opening a job locks new admissions against its pinned ledger/head until admission
or expiry. Existing non-mining work can run between rounds through the same
coordinator. This scheduling change is approved by D1; otherwise ordinary
head advances would invalidate mining snapshots unpredictably. Round expiry must
be bounded by deployment policy; clocks and job scheduling remain operator trust.

There is no "lowest hash seen so far" replacement, late-winner override, uncle
reward, cumulative chain work or rollback of an admitted failed head. Simultaneous
submissions are ordered by durable journal acquisition; network arrival order is
not globally observable. Audit records can show the chosen order but cannot prove
the operator did not censor a candidate. Equivocating operators/independent
journals are unsupported forks: fail closed and recover coordinated history rather
than applying a newly invented merge or heaviest-chain rule.

## 8. Reward model and Bitcoin interaction

**Approved source: the job sponsor's pre-existing BTC.** No Aura issuance, burned
unit recycling, reward credit to the frozen Aura ledger, or conversion of Bitcoin
fees into Aura burn. The miner needs an existing funded Aura payer account and
consents to its own admitted burn. Reward and fees are sponsor expenditures; R is
not a promise of profitability and need not cover a miner's discarded trials.

The sponsor reserves a dedicated spendable Bitcoin outpoint and sufficient fee
budget before publishing J. This is custodial funding management, not a trustless
escrow or Bitcoin enforcement of a mining predicate. A dishonest/insolvent sponsor
can still withhold or double-spend its funds. The reward obligation becomes durable
exactly when the economic contender is Accepted, regardless of later confirmation.

Pay exactly R to `OP_1 PUSH32 <miner_xonly_key>` (`0x51 0x20 || key`) as a BIP341
key-path output. The miner key is used as the output key, not interpreted as an
internal key requiring an undeclared wallet tweak. The miner must control the
corresponding key. This approved payout convention is a new miner policy, not a
change to Aura's BIP340 signatures. [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
defines these output/key-path rules.

Approved publication puts that payout alongside the **unchanged** canonical
Aura OP_RETURN in one Bitcoin transaction. The existing codec already permits
unrelated outputs; an additive reward-output validator must require the exact
script and amount. The canonical anchor request gains no fields. Wallet fee/dust
policy must be checked before a job opens and again before broadcast.

Before broadcasting, durably persist the signed transaction and reward-to-funding
outpoint association. Retry rebroadcasts the same transaction. Any fee replacement
must spend that same reserved outpoint and retain the exact reward and Aura output;
all payment versions therefore conflict with each other and cannot both confirm
in one chain. Never independently fund a second payout because the first observation
is missing. Additional fee inputs do not remove the required conflicting input.
Unknown spend or inconsistent recovery blocks payment for operator recovery.

The existing anchor outbox and new reward obligation remain distinct records with
one owning economic attempt. A miner-origin anchor must use the combined publisher;
the generic publisher cannot acknowledge that reward obligation without checking
its payout. Actual Bitcoin payment observations, txids and fee replacements are
operational evidence, not new canonical Aura identifiers.

Reorgs update confirmation of the payment/anchor and may require rebroadcast or
fee replacement; they do not reopen the round, choose another miner, refund a burn,
release a nonce or create another reward entitlement. A reward remains owed until
its valid payment is observed; "confirmed" is always reversible chain evidence.

## 9. What is committed, and what is not

| Surface | Commitment / verification boundary |
| --- | --- |
| Existing proof_hash | Unchanged canonical proof/material/FractalKey path; binds miner, nonce, input-bound trace and compact inputs. Proposed context I additionally binds J and exact M, including prior head, difficulty and reward promise transitively. |
| Existing Head V2 | Unchanged owner formula binds W, predecessor, terminal outcome, pre/post debit commitments and B. The completed service verifies the target reference before Accepted. No new head field or reward-balance term. |
| Bitcoin OP_RETURN | Exactly the same network + proof_hash payload. No mining score, target, head, job, proof or reward object added. |
| Proposed signed J / journal records | Job policy, chosen contender, winner and reward obligation remain available off-chain. The proof commits a job promise, not proof the sponsor funded or paid it. |
| Bitcoin payout | Bitcoin enforces its actual spend/output rules, not Aura PoC, winner selection, local balances or the operator's honesty. |

The current terminal Head V2 cannot be embedded into the proof that precedes it
without creating a cycle. J binds the **prior** head; auditors with W, the terminal
outcome and journal evidence can derive the successor. An anchor alone is not a
certificate that a particular journal selected that successor or paid a reward.
No new Bitcoin commitment mechanism is needed for the recommended coordinated V1.

## 10. Threat review

| Threat | Required defense / residual assumption |
| --- | --- |
| Cheap outer nonce/key grinding | Match FractalKey subject/nonce to the fully verified context. The probe demonstrates signature/material-only acceptance is insufficient. |
| Signature, VK, historical-slot or encoding grinding | Exclude signatures from score; pin zero historical slots, empty VK, derived PI and the one deterministic proof encoding. Reject alternate backends/encodings. |
| Work swapping after finding a proof | I binds exact canonical M and signed J; changing either changes Storm forcing. Verify this binding before charging. |
| Precomputation / coordinator advantage | Fresh job challenge after state/policy fixation; bind round, namespace, head and sides. The trusted operator can leak/grind challenges; no unbiased beacon claim. |
| N=0 or cheaper task selection | Positive epoch-fixed N, fixed sides and profile; no per-candidate lower N or difficulty. Exact full witness verification. |
| Shortcuts / many-instance amortization | No proof currently excludes them. Benchmark optimized attacks; independent review before meaningful monetary exposure. Do not claim a VDF or sequential lower bound. |
| Forged low hash / cheap verification bypass | A low supplied reference is a filter only. Existing paid service reconstruction, full verification and binding must succeed before winner/auth/reward. Bound N/bytes and ingress. |
| Nonce reuse / copied work / front-running | Existing tuple journal and W/target retry rules. Copied candidate still pays/rewards its original signer; it cannot redirect identity without recomputation/signatures. |
| Difficulty manipulation | Operator-signed fixed epoch policy, immutable job; no miner timestamps or reported throughput in a retarget. Malicious operator policy remains a trust risk. |
| Withholding / selfish mining | Withheld work earns nothing; expiry or head advance stales it. There is no private heavier branch, but latency advantage, censorship and strategic round disruption remain. |
| Duplicate work / Sybil keys | One claim/winner per round and one economic attempt key. Identical retries earn nothing extra. Extra keys do not prove extra humans and can evade per-key quotas. |
| Failed-candidate griefing | An admitted lie can consume a burn and invalidate other work. Freeze existing fees, bound exposure/round duration and pause on overload; do not assert tariff adequacy without measurement. |
| State split / rollback | One coordinated transactional writer and consistent backups. Competing independent histories are not resolved by Bitcoin anchor order. |
| Reward replay / broadcast crash | One obligation per Accepted attempt, persisted signed tx, all replacements share its funding input. Never release nonce/entitlement on reorg. |
| Consumer usefulness / sample bias | Explicit task demand and acceptance of nonce-conditioned threshold samples. No claim of generic useful computation or an unbiased randomness beacon. |
| Data withholding | Persist J/W and enable deterministic reconstruction; an unavailable witness is not magically available from OP_RETURN. Operator liveness remains necessary. |

The research literature distinguishes PoW correctness from proving many-instance
non-amortization; Aura inherits no hardness theorem merely by using a recurrence.
See Ball et al., [Proofs of Work from Worst-Case Assumptions](https://eprint.iacr.org/2018/559).
BIP340 domain-separated signing uses the existing reviewed algorithm, with fresh
signature nonce handling kept separate from the public mining nonce.
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

## 11. Design evidence and limits

Reproduce the bounded probe:

```sh
cargo build -p aura_sdk_v1 --offline --bin aura-authorizer
node reports/miner_protocol_v1/design_probe.mjs
```

[Captured output](miner_protocol_v1/design_probe.json) records N=64 nonce changes
affecting both parameters, all 64 forcing pairs and TRACE_ROOT; exact W round-trip;
M/job commitment sensitivity; the N=0 trace-reuse counterexample; target endpoint
checks; and a concrete cheap outer-nonce rebinding that passes TS signature/material
checks but is rejected by the full existing Rust authorizer. It reproduces the
existing frozen authorization proof_hash before attempting that attack.

The probe is executable design evidence, not full miner security validation or a
production winner state machine. It remains unchanged and reproduced byte-identical
output during M2 closure. Atomic integration/reward tests and deployment calibration
remain later work.

M2 is implemented in [Rust](../crates/aura_sdk_v1/src/miner.rs) and
[TypeScript](../packages/aura_sdk_v1_ts/src/minerV1.ts). The
[shared frozen codec/profile evidence](../fixtures/miner_v1/README.md) pins J,
decoding, commitments, signature digest/signature, I, route, context, W and target
comparison using exact bytes. Focused tests cover every job/signature/work byte,
malformed inputs, trusted policy, limits, stale heads and profile bindings. Nine
Rust and ten TypeScript miner tests pass, together with targeted SDK checks and
existing authorization/economic/claim regressions. Profile and low-hash filters
remain distinct from actual PoC verification and durable authorization acceptance.

M3 is implemented in [Rust local search](../crates/aura_sdk_v1/src/miner_search.rs).
[M3 evidence](AURA_MINER_M3_EVIDENCE.md) records actual proof verification and
material/FractalKey binding, deterministic search/limits, existing-object vectors,
nonce/reuse experiments and measured N scaling. It also records the user's explicit
section 8 clarification: target remains bound through J/I/context; multiple
diagnostic thresholds compare the same completed hashes only. M3 has no admission,
winner, reward, head or Bitcoin publication effects. No new proof wire was introduced.

M4 composes durable round ownership and reward obligations into the existing
economic journal. [M4 evidence](AURA_MINER_M4_EVIDENCE.md) records server re-verification,
atomic debit/finalization, funded opening, guarded wallet-lock release, race/retry/
crash recovery and unchanged baseline regressions. Core funding RPC is contract-tested;
real payout/anchor publication and regtest recovery belong to M5.

## 12. Frozen components and minimal implementation DAG

No modification required to HASH_V2, field arithmetic, Storm initialization/
recurrence, trace encoding/Merkle reduction, claim/proof bytes, material hashing,
FractalKey, proof_hash, Authorization V2 envelope/signing, economic consent/W/M
encodings, burn constants/supply invariant, Head V2 formula/genesis, UDOT or Bitcoin
OP_RETURN. No hierarchical/macro Storm change is required.

The job/profile codec (M2), local search (M3), and transactionally composed
round/winner/reward records (M4) are complete. M5 adds the reward-aware publisher
using the existing Bitcoin transport. No bypass or alternative settlement API
was introduced; remaining milestones validate integration and activation readiness.

| Slice | Dependencies | Bounded work and stop criterion |
| --- | --- | --- |
| M0 — design evidence | Baseline | This proposal and probe; frozen dependency map established. DONE. |
| M1 — semantic approval | M0 | User explicitly approved D1–D6 on 2026-09-10. DONE. |
| M2 — job/profile parity | M1 | DONE. Rust/TS job codec/signature, context binding and strict limits; shared frozen bytes, every-byte mutations, target endianness/endpoints, zero-N/slot/VK/route rejection. |
| M3 — miner computation | M2 | DONE. Existing Storm/proof/material owners; secure and deterministic research nonce modes, bounded search/cancellation/expiry, full local PoC and exact target predicate. Frozen existing-object vector, reuse/security tests and N=8–128 measurements. |
| M4 — coordinator composition | M3 (master-goal execution order) | DONE. Same SQLite admission/finalization owner plus policy/job/snapshot/funding/round/reward records. All four outcomes, race/retry, expiry, process-exit recovery and injected rollback tests passed. Original non-mining regressions unchanged. |
| M5 — reward publication | M4 | READY. Reserved outpoint, exact payout + unchanged anchor, persisted transaction, conflicting fee replacements; no duplicate entitlement/payment. Core regtest with broadcast-crash, fee rejection and reorg. |
| M6 — adversarial integration | M3, M5 | BLOCKED. Actual candidate → debit → full proof → winner/head/outbox → payout/anchor; fake low hashes, copied work, competing miners, wrong-job/nonce, publication recovery. Confirm baseline outputs unchanged. |
| M7 — authority and activation | M6 | BLOCKED. Promote approved definitions into existing owners; archive conflicting Aurafarming research without losing evidence. Publish measured N/target/bounds and funded limits, review unresolved attacks, then explicitly authorize monetary deployment. |

M5 is the next READY node under the user's M3–M7 master goal. Stop after each
milestone closure; M4 completion does not implement reward transaction publication.

During implementation, the existing Aurafarming document can own miner job/competition
semantics; pipeline/ledger/authorization/head/report owners reference it for their
specific integration obligations. Do not add a parallel authoritative spec or copy
the frozen owners' formulas into a new wire. M7 is gated on implementation evidence,
not just renaming a research document.

## 13. Approved decisions and remaining conditions

All six decisions below are **APPROVED** by the user's 2026-09-10 response. The
alternatives remain unselected; they are not optional modes within this contract.

| ID | Approved V1 decision | Unselected alternative and consequence |
| --- | --- | --- |
| D1 | Coordinated sponsored mining, one journal and first admitted contender; lock ordinary admissions during bounded open rounds; admitted failures close the round without rollback. | Permissionless cumulative-work consensus requires a new replicated economic state, fork/rollback and authorization-history contract. It cannot be slipped above frozen Head V2. |
| D2 | Customer-requested nonce-conditioned Storm trajectories; exact J/I/context profile above; existing proof_hash is the sole difficulty value. | Fixed-answer application computation requires another verified task relation or separate hash work. Do not claim the present Storm trace proves it. |
| D3 | Epoch-fixed N/T and bounds, explicit operator adjustment between epochs, no automatic retarget. | Automatic adjustment needs agreed timing/history and manipulation rules. No arbitrary release parameters or security claims are approved by the probe's example. |
| D4 | Private losing trials pay compute cost only; pre-admission rejects pay no Aura burn; every admitted outcome retains the unchanged burn; only Accepted wins. | Charging every private trial is unenforceable without metered admission per trial, which would serialize search and advance heads on losers. A subsidy/fee change needs a new economic decision. |
| D5 | Positive pre-funded sponsor BTC rewards, custodial dedicated outpoint, exact miner-key payout alongside unchanged OP_RETURN; no Aura issuance or burn recycling. | Aura-denominated issuance/transfers require new reward/ledger conservation rules. Trustless Bitcoin escrow needs a separate reviewed construction. |
| D6 | Add atomic miner scheduling/winner/reward metadata and route enforcement to the existing coordinator; preserve formats; implement/test on regtest before separately approving monetary activation. | A standalone miner settlement endpoint would create a competing canonical path and is rejected. |

Approval of D1–D6 establishes the bounded implementation design, not proof of Storm
hardness, customer utility, fair ordering or funded mainnet readiness. M2 enforces
the job/profile boundary, M3 performs local verified mining, and M4 adds durable
coordination. Reward publication is not yet implemented.
There are no unresolved semantic
decisions within the approved coordinated V1 scope. Numerical deployment policy
must be measured and explicitly configured under D3; monetary activation remains
separately gated by D6. A change to these approved semantics requires a new decision.

The design-only goal is complete: dependencies, exact predicates, lifecycle,
economics, head/Bitcoin boundaries, threat review and implementation DAG are ready.
M2–M4 implementation validation is complete. Reward publication, adversarial
integration and activation readiness remain M5–M7 work.
