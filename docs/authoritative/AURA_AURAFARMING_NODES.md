# AURA_AURAFARMING_NODES — Coordinated Miner Protocol V1

**Classification:** `ACTIVE AUTHORITY`

**Layer:** `MINER PROFILE / COORDINATION`

**Purpose:** Own the approved job, mining profile, eligibility, round and reward policy

**Status:** `IMPLEMENTED; MONETARY ACTIVATION SEPARATELY GATED`

## 1. Authority and active boundary

This stable registry identity now owns the approved `AURA_MINER_PROTOCOL_V1`
contract. D1–D6 approval and rationale remain in the
[design decision record](../../reports/AURA_MINER_PROTOCOL_V1.md). Its previous
20-node/EMA proposal is preserved as [historical research](../research_assets/AURA_AURAFARMING_NODES_RESEARCH_V0_2.md);
it defines no active topology, proof, reward or consensus behavior.

V1 is coordinated sponsor-funded Storm computation mining. A local valid proof
and difficulty hit is only a candidate. The existing economic journal owns the
single admitted contender, re-verification and atomic terminal state. No independent
miner chain, permissionless fork choice or second canonical execution path exists.

This document owns only miner-specific rules. W, M, consent, authorization,
Storm/claim/proof, artifact/proof_hash, Head V2, UDOT and Bitcoin anchor bytes remain
owned by the documents assigned in [the registry](AURA_BUILD_SOURCE_OF_TRUTH.md).
The [pipeline](AURA_CANONICAL_PIPELINE_V1.md), [ledger](AURA_LEDGER_AND_BURN_V1.md),
[head](AURA_CONTINUOUS_SETTLEMENT_V1.md) and [Bitcoin report contract](AURA_REPORT_CONTRACT_V1.md)
retain their generic semantics. Installing a miner policy enables this profile on
that coordinator; it does not replace the ordinary work path between rounds.

## 2. Exact approved mining inputs

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

The signed target remains part of J: target → J → job_commitment → I → Storm
context → forcing → TRACE_ROOT → proof_hash. Changing the signed target defines a
different prescribed computation. Comparing one completed proof_hash with several
diagnostic thresholds does not change or recompute that execution and never
replaces the signed target for eligibility.

Candidate identity is the existing `(network, subject, freshness_nonce)` plus the
stored W/target equality rule. References use only `proof_hash`; there is no
`mining_hash`, candidate-hash alias or second serialization of a proof.

## 3. Exact PoC and PoW predicates

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
frozen burn boundary and is not permitted by this contract.

## 4. Usefulness and computational scarcity

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

## 5. Difficulty and adjustment model

**Approved V1: fixed N and T per explicitly configured policy epoch; no automatic
retarget.** Within an epoch every job uses the same N, T and maximum byte bounds.
Job expiry/reward/side inputs may vary; the target may not be selected by a miner.
The operator can start the next consecutive epoch only after the previous round
has closed and no attempt remains in flight. New parameters must be published and
persisted before generating/releasing that epoch's first job challenge. Changing
policy never changes existing candidate eligibility retroactively.

The adjustment algorithm is therefore `T_next = T_current, N_next = N_current`
unless an explicit operator epoch transition occurs. Initialization requires explicit epoch zero. Rotation requires exactly the current
epoch plus one with checked u64 arithmetic; gaps and overflow reject. No defaults
are inferred. Persist and audit every epoch, including those with no opened round. This deliberately accepts centralized target
policy; it is not a permissionless difficulty algorithm. Wall-clock reports,
self-reported hash rate and invalid/withheld candidates never automatically retarget.

Calibrate deployment configuration from measured full trial and verification cost,
memory, proof size, sustained request capacity and the sponsor budget. Production
numbers are not guessed here. A benchmark selects explicit limits before activation;
it may not change the approved equations or burn tariff. If the frozen tariff plus
admission controls cannot bound attack costs, do not launch: changing that tariff
requires a separate USER_DECISION. Measurement evidence is linked below; none of its inputs are deployment defaults.

An automatic observed-time retarget or cumulative-work competition is a viable
future alternative, but needs an agreed clock/history, manipulation analysis and
fork semantics. It is not silently included as an optional V1 mode.

## 6. Lifecycle, accounting and head competition

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

## 7. Reward model and Bitcoin interaction

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
unrelated outputs; the combined publisher must require the exact
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

## 8. What is committed, and what is not

| Surface | Commitment / verification boundary |
| --- | --- |
| Existing proof_hash | Unchanged canonical proof/material/FractalKey path; binds miner, nonce, input-bound trace and compact inputs. Context I additionally binds J and exact M, including prior head, difficulty and reward promise transitively. |
| Existing Head V2 | Unchanged owner formula binds W, predecessor, terminal outcome, pre/post debit commitments and B. The completed service verifies the target reference before Accepted. No new head field or reward-balance term. |
| Bitcoin OP_RETURN | Exactly the same network + proof_hash payload. No mining score, target, head, job, proof or reward object added. |
| Signed J / journal records | Job policy, chosen contender, winner and reward obligation remain available off-chain. The proof commits a job promise, not proof the sponsor funded or paid it. |
| Bitcoin payout | Bitcoin enforces its actual spend/output rules, not Aura PoC, winner selection, local balances or the operator's honesty. |

The current terminal Head V2 cannot be embedded into the proof that precedes it
without creating a cycle. J binds the **prior** head; auditors with W, the terminal
outcome and journal evidence can derive the successor. An anchor alone is not a
certificate that a particular journal selected that successor or paid a reward.
The existing Bitcoin commitment mechanism is retained.

## 9. Threat review

| Threat | Required defense / residual assumption |
| --- | --- |
| Cheap outer nonce/key grinding | Match FractalKey subject/nonce to the fully verified context. Signature/material-only acceptance is insufficient; actual proof verification is required. |
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

## 10. Implementation and evidence

- Codec/profile: `crates/aura_sdk_v1/src/miner.rs` and `packages/aura_sdk_v1_ts/src/minerV1.ts`.
- Local search and real PoC: `crates/aura_sdk_v1/src/miner_search.rs`. TypeScript does not implement the Storm verifier.
- Sole round/economic owner: `crates/aura_sdk_v1/src/economic/journal/miner.rs` within `EconomicJournalV1`.
- Funding/publication: that module's `funding.rs` and `publication.rs`; Core owns transaction construction/signing.
- Frozen vectors and acceptance coverage: [vector registry](AURA_VECTOR_MATRIX_V1.md).
- Measured computation: [M3 evidence](../../reports/AURA_MINER_M3_EVIDENCE.md); adversarial path: [M6 evidence](../../reports/AURA_MINER_M6_EVIDENCE.md).
- Operator procedure and measured deployment boundaries: [miner operations](../AURA_MINER_OPERATIONS_V1.md), implementation metadata, not another protocol definition.

SQLite commits serialize coordinated state; Core wallet locks are custodial and
not atomic Bitcoin escrow. An interrupted open may leave an orphan wallet lock,
which requires reconciliation against durable rounds before release. Complete
internally consistent database rollback cannot be detected by that database alone;
restoration requires trustworthy latest-backup provenance and external publication
reconciliation. Neither SQLite nor Bitcoin anchor ordering supplies fork choice.

Implementation readiness does not select a production N/target, reward, duration,
request capacity or confirmation policy. Monetary exposure requires separate explicit
approval after the intended deployment's measurements and operating limits are reviewed.
No sequential/non-amortization/ASIC/physical-energy, universal-usefulness, Sybil-proof,
permissionless-consensus, succinctness or zero-knowledge claim is made.
