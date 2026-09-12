# Aura Miner M6 — adversarial system acceptance

Classification: IMPLEMENTATION / TEST EVIDENCE, not active protocol authority.
Date: 2026-09-11. Status: M6 DONE; M7 READY and not started.
Design owner: [approved miner design](AURA_MINER_PROTOCOL_V1.md).
No monetary activation or M7 authority promotion is included.

## Reproducible acceptance boundary

[Full gate](../scripts/verify_miner_program_v1.mjs) runs the direct canonical
owners' regressions, miner attacks and [isolated Core harness](../scripts/verify_miner_regtest_v1.mjs)
in adversarial mode. [Machine-readable results](miner_protocol_v1/m6_acceptance_results.json)
record every command, exit status, test-summary counts, elapsed time and Core result.
The gate fails on a failed command, missing expected tests, warnings, or an absent
Core attack result. It never substitutes a mock for the final Bitcoin stage.

```sh
BITCOIND=/path/to/bitcoin-29.0/bin/bitcoind \
BITCOINCLI=/path/to/bitcoin-29.0/bin/bitcoin-cli \
node scripts/verify_miner_program_v1.mjs
```

The run uses temporary journals and a fresh, network-isolated regtest wallet over
loopback. Rust owns actual search, proof verification, admission and publication;
the existing TypeScript RPC owner administers Core. Python's standard SQLite module
creates explicit corruption/rollback fixtures. No real funds are used.

The exercised path is funded signed job → private nonce-conditioned Storm search →
canonical PoC and target-qualified proof_hash → existing economic admission/debit →
independent service proof/material verification → Authorization V2 / Head V2 /
unique winner / obligation / outbox → signed reward plus unchanged Bitcoin anchor →
confirmation → reorg and retry. Candidate submission accepts canonical W and signed
references, not a client proof blob or client `qualifies` assertion. The service
reconstructs and verifies the prescribed proof through the existing owners.

## Changes made for M6

- [Coordinator attack tests](../crates/aura_sdk_v1/src/economic/journal/miner/tests/adversarial.rs)
  add distinct-identity contention, 32 concurrent retries, signed-job mutations,
  cross-round nonce reuse, storage corruption and rollback simulations.
- Test-only crash hooks in the existing journal exit child processes at seven
  transaction/execution boundaries. `#[cfg(test)]` excludes these hooks from the
  production SDK. The regtest adapter additionally exits after transaction
  finalization and after successful Core broadcast, before the respective journal
  commit. These adapter switches are test tooling, not protocol or service APIs.
- The storage experiments exposed a real publication-audit gap: a published outbox
  could retain its txid after all payment and observation history was deleted.
  The existing publication owner now audits published miner outboxes even when
  those tables contain no rows. It also rejects unknown/split observation txids,
  malformed stored hashes and zero inclusion depth. Fresh Core observation remains
  required; stored confirmation status is not independent chain evidence.
- Exact empty-input HASH_V2 bytes are checked in Rust and TypeScript through the
  existing `aura_hash521_v1` / `auraHash521V1` owners. The expected SHA3-512 value
  was independently checked with Python `hashlib`; no new hash function was added.
- Running existing authorization/economic tests concurrently exposed timestamp-only
  temporary filename collisions. Their test helpers now include process-local
  atomic counters. An existing FractalKey assertion also uses the nondeprecated
  slice accessor. These changes affect tests only.
- Real unknown-spend recovery exposed empty/null handling in the regtest CLI
  adapter: Core CLI's empty null output now becomes JSON null. This allows the
  existing publisher to report RecoveryRequired for the unavailable outpoint;
  no production state transition or RPC contract was changed.

No canonical serialization, frozen fixture, cryptographic owner, tariff, Head V2
formula, Bitcoin payload or authoritative document was changed by M6.
Targeted Git comparisons also confirm the M2 vector equals its `fb230dc` version,
the M3 vector equals `8b15578`, and the inspected frozen owners/old fixtures and
authoritative documents are unchanged from Bitcoin baseline `f64fb4f`.

## Attack evidence

The gate reruns existing M2–M5 tests where they already own the relevant boundary;
M6 adds missing integration and recovery experiments rather than duplicate owners.

| Required class | Executed evidence and result |
| --- | --- |
| Copied trace/proof, nonce and FractalKey rebinding | M3 `copied_proof_and_cheap_outer_rebinding_never_verify_as_new_nonce_work` rejects copied proofs and 16 cheap outer rebindings, including low hashes. `side_only_initial_state_reuse_is_equivalent_but_partial_trace_reuse_fails` rejects a reused partial trajectory. M4 `copied_proof_reference_under_new_nonce_fails_service_owned_verification` independently rejects the copied reference after chargeable admission. |
| Altered witness and fake low proof_hash | M3 mutates witness bytes, reconstructs metadata/material and still fails actual verification; a forged zero hash and changed material hash also fail. M4 `fake_low_hash_is_chargeable_but_never_authorized_or_rewarded` records VerificationRejected, one unchanged burn and no authorization/winner/reward. |
| Changed target/job, identity/payer, namespace, policy epoch, prior head | M2 byte/signature/profile mutations plus M4 pre-admission and M6 `different_signed_job_fields_and_wrong_identity_never_acquire_round` reject these without admission/debit. Signed target still changes J/intent/context; diagnostic thresholds only compare a completed hash. |
| Expired/stale/replayed jobs and reused challenge | M4 clock/expiry tests reject both outside-window and explicitly expired admission; the old job cannot enter the next round. Reusing a challenge and submitting the previous policy epoch fail. Same-action old retries return the original receipt, not a new attempt. |
| Reused nonce | M6 `nonce_reuse_after_failed_round_conflicts_without_another_burn` closes a failed round, opens the next, then rejects a different action using the same subject/nonce. Existing Authorization V2 tests retain the network/subject/nonce journal boundary. |
| Simultaneous contenders / transaction races | Two funded miner identities with independently valid canonical candidates race; one gains admission and one durable winner exists. Existing contender/finalizer and rollback tests also run. Four concurrent Core publication retries resolve to the same txid. |
| Retry storms / duplicate submissions | Four workers each submit/resume eight times: 32 equal receipts, one debit, authorization, winner and obligation. Preparation retry with changed fee settings returns the same signed transaction. |
| Crash before debit / after debit / during verification | Child exit 86 before debit and before admission commit leaves no admitted state. Exit after committed debit or during verification leaves one recoverable pending attempt. Restart completes it with one burn. |
| Crash after authorization / Head V2 / reward obligation | Child exits inside the shared finalization transaction roll back all terminal state. Restart observes the previous head and resumes to exactly one consistent authorization/head/winner/obligation. Existing injected SQL failures cover the same atomic ownership. |
| Crash after transaction creation / Bitcoin broadcast | Core adapter exits 87 after finalizing signed bytes but before persistence: no payment or mempool entry. Exit 86 after broadcast but before acknowledgement leaves the persisted payment and null outbox txid; restart discovers the same mempool transaction and records it. |
| Corrupt attempts, winner and outbox | SQL mutation tests reject work, authorization, post-ledger/current ledger, prior head, round snapshot/signature/state/control, deleted authorization/reward, malformed outbox and missing payment history on reopen. No repair fabricates another winner. |
| Corrupt payment/observation records | Real Core harness rejects changed fee metadata, anchor, reward and reserved input; raw mutations recompute their txid and local checksum to exercise binding checks. Deleted history, partial snapshot, unknown outbox txid, malformed observation and observation/outbox disagreement fail closed. |
| Restart during pending round | Existing open-round restart, post-acquisition process exit, seven M6 crash points and host-limit deferral recover the same pinned job/attempt. Core restart restores the live reserved-output wallet lock. |
| Stale snapshots / rollback | Partial inconsistent snapshots fail local audit. A prepared-payment snapshot contradicted by an unknown Core spend enters RecoveryRequired. A complete internally consistent old journal still opens: the explicit limitation below is part of the result, not a claimed rejection. |
| Wrong Bitcoin network / insufficient funding | Actual regtest network mismatch rejects. Dust reward, insufficient dedicated funding and excessive preflight fee reject before opening and leave no wallet lock. Existing unit funding checks also exercise unsafe/unspendable coins and failed lock acquisition. |
| Fee mutation / replacement | Fee-cap violation stores no payment. Replacement spends the same reservation, preserves exact reward and anchor, increases the fee within budget, and conflicts with the old transaction. Stale and post-confirmation replacements reject. |
| Delayed confirmation / duplicate observation | Repeated observations retain Pending before mining; duplicate observations and publication retries retain one winner/obligation. One block gives Included; required depth gives Confirmed. |
| Reorg / rebroadcast | Core invalidates the payment block; fresh observation loses confirmation, rebroadcast/reconfirmation on a new branch preserves burn, head, authorization reservation, winner and obligation. |
| Older payment confirms / unknown funding spend | A prepared later replacement cannot override an older confirmed version. A sponsor spend outside the publisher makes both current and stale journals return RecoveryRequired without selecting replacement funding or creating another obligation. |

## Frozen-output regression scope

| Frozen surface | Gate evidence |
| --- | --- |
| HASH_V2 / field | Existing hash owner, new exact Rust/TS empty-input bytes, all canonical field unit tests. The active API's historical `521_v1` name remains unchanged. |
| Storm / TRACE_ROOT / claim / proof | Existing execution, trace commitment, claim, Rust/TS parity and hash-hardening tests; actual Storm verifier tests; M3 frozen existing-object vector and nonce propagation. |
| ProofMaterial / FractalKey / proof_hash | Both owning crates' tests, shared Authorization V2 artifact/material vector, M3 frozen proof/material/FractalKey/reference bytes and rebinding negatives. |
| Authorization / burn / Head V2 | Existing authorization vectors, consent/W/debit/all-four-outcome head vectors, durable journal and explicit V1 predecessor migration tests. |
| UDOT | Existing `test_udot_parity.sh` Rust and TS checks. |
| Bitcoin anchor | Owning Rust/TS wire/transport tests and exact real transaction OP_RETURN comparison against the accepted canonical proof_hash. |
| Miner M2 | Unmodified 471-byte job/profile vector, exact Rust/TS bytes, all-byte mutations and raw big-endian target endpoints. No alternate candidate identifier or target calculation. |

## Results and measured limits

All **11 stages passed** in the final combined run: **184 top-level Rust test
entries** (including child-process helpers), one additional nested child-test
summary, **58 TypeScript tests**, SDK library/binary/example compilation and
**17 explicit adversarial Core cases** in addition to the positive M5 lifecycle.
No warning was accepted. The machine-readable result preserves the per-command
counts; the numbers are test entries, not a count of independent security claims.

Environment: macOS arm64, Rust 1.88.0, Node 22.22.2, Bitcoin Core 29.0. The Core
stage took 15,929 ms in this run. The main publication measured **214 vbytes**,
**428 sat** initial fee and **2,140 sat** replacement fee. Its one Accepted winner,
one reward obligation, two conflicting payment versions and **48-unit Aura burn**
remained unchanged through restart, replacement, reorg and retry.

Research Core settings: Bitcoin Core 29.0, N=8, target `7f` followed by 31 `ff`
bytes, maximum 128 local trials / 30 seconds, 900-second job window, 10,000 sat
reward, 20,000 sat fee budget, explicit 2/10 sat/vB initial/replacement rates and
two confirmations for the main recovery scenario. These are test inputs, not
deployment defaults. The older-confirmed-version experiment requests one confirmation.
No new throughput calibration is inferred from test durations; the measured N
scaling remains in [M3 evidence](AURA_MINER_M3_EVIDENCE.md).

**Complete-database rollback is not detectable from that database alone.** The
test restores a complete earlier open-round snapshot after the current journal
accepted a winner. The old snapshot remains internally consistent and opens. An
operator must establish latest-backup provenance and reconcile external publication
state before restoration; an old copy must not be treated as a second live journal.
M6 does not add an external monotonic authority or claim rollback resistance. M7
must carry this limitation into backup and recovery requirements.

These are bounded implementation tests and an internal attack review, not an
independent security audit. The operator controls custody, scheduling and journal
availability. No sequential hardness, non-amortization, ASIC resistance, physical
energy guarantee, general commercial usefulness, Sybil-proof or permissionless
consensus, production difficulty security, succinctness or zero knowledge is proved.
Signed target semantics and the known reusable nonce-independent initial state are
unchanged. Live monetary deployment still needs separate explicit approval.
