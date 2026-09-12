# Aura Miner V1 — implementation and operations

**Classification: IMPLEMENTATION / OPERATIONS METADATA.**
Protocol owner: [coordinated Miner V1](authoritative/AURA_AURAFARMING_NODES.md).
This guide selects no production parameters and authorizes no monetary deployment.

## Supported boundary

The implemented system is one coordinated economic journal with local Rust Storm
miners and sponsor-funded Bitcoin publication. The host application supplies job
distribution, authenticated RPC, process supervision, ingress controls and monitoring.
The SDK and regtest adapter are executable; the adapter's public test key and fixture
ledger are not a live service configuration. There is no production miner daemon,
pool protocol, permissionless fork choice or automatic retarget service.

Read the [registry](authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md), then the miner
owner for canonical J/profile/eligibility rules. Follow the existing pipeline,
ledger, authorization, head and report owners for their respective objects. Do not
copy their field lists into an application-specific replacement wire.

| Task | Existing entry point |
| --- | --- |
| Decode/verify a signed job, construct exact work | Rust `crates/aura_sdk_v1/src/miner.rs`; TS `packages/aura_sdk_v1_ts/src/minerV1.ts` |
| Bounded local search / independent candidate verification | Rust `miner_search::{MinerSessionV1, verify_miner_trial_v1}`; TS has no actual Storm verifier |
| Initialize/open the economic journal | `economic::journal::EconomicJournalV1::{create, open}`; explicit V1 migration remains separately owned |
| Install/rotate policy, open/expire/read a round | `install_miner_policy`, `update_miner_policy`, `open_miner_round`, `expire_miner_round`, `miner_round` |
| Admit/finish work | Existing `admit` / `resume` / `submit`; miners do not get another settlement endpoint |
| Read accepted reward obligations | `miner_reward_obligations` |
| Confirm and lock dedicated sponsor funding | `economic::journal::miner::funding::reserve_miner_funding_v1` |
| Enable/read/prepare/publish/observe/replace payments | `install_miner_publication`, `miner_payments`, `prepare_miner_payment`, `publish_miner_payment`, `observe_miner_payment`, `replace_miner_payment` |
| Release unused funding after durable no-winner closure | `release_miner_funding`; never unlock a live/admitted/accepted reservation |

All miner control/payment methods extend the existing journal type. Their returned
views and private SQLite records are implementation state, not a second canonical
job/proof representation. The existing `aura-economic` CLI handles economic work;
miner job control and combined payment publication currently use the Rust library.
The generic `record-publication` command rejects miner attempts.

## Reproduce the tested system

Use the pinned Rust toolchain, Node 22.22.2 or the tested compatible runtime, Python 3
with standard SQLite support, the locked Cargo dependencies, and Bitcoin Core 29.0.
Install the SDK's npm dependencies through its lockfile. The acceptance harness
needs loopback networking and two explicit Core executable paths:

```sh
BITCOIND=/path/to/bitcoin-29.0/bin/bitcoind \
BITCOINCLI=/path/to/bitcoin-29.0/bin/bitcoin-cli \
node scripts/verify_miner_program_v1.mjs
```

It creates and deletes isolated regtest data, mines test funds and uses the actual
Rust coordinator. Never point the fixture adapter at a production journal or wallet.
The gate writes implementation evidence under `reports/miner_protocol_v1/`.
Use `cargo test -p aura_sdk_v1 --offline --lib economic::journal::miner` for focused
coordination checks; use the full gate for a meaningful release boundary. No
Bitcoin migration re-audit is needed for ordinary miner documentation changes.

## Policy and measured deployment limits

Every policy value is explicit. Trust the operator key, Bitcoin network and journal
namespace from operator configuration, not the incoming job. Initialize policy
epoch zero once; rotate only to the next epoch while no round/attempt is active.
The operator key and namespace remain fixed. Retain all epoch history. Overflow,
missing history and policy/host-bound disagreement fail closed.

| Configuration | Operator responsibility / evidence |
| --- | --- |
| N, signed target, maximum W and M bytes | Epoch-fixed values constrained by host `EconomicLimitsV1`; the signed target is part of the computation. No automatic adjustment. |
| Maximum round duration / minimum reward | Explicit `MinerRoundPolicyV1`; each opening supplies bounded duration and a funded positive reward. Trusted wall clock controls expiry. |
| Local search | Explicit finite trials and elapsed-time budget, cancellation flag, work/iteration/proof-byte limits; use `SecureRandom`, not the deterministic research nonce mode. |
| RPC / Bitcoin payment | Explicit network/wallet, bounded RPC timeout, fee rate, maximum fee, reserved fee budget and positive confirmation depth. Replacement is an explicit operation with an expected txid. |
| Ingress / execution capacity | One admitted attempt and one open/admitted round per journal. Bound request sizes, concurrency and queues before application dispatch. There is no measured public-service requests/second limit. |
| Storage growth | Retain policies, rounds, economic/authorization history, payment versions and observations. Audit cost and durable history grow; no compaction/retention deletion contract is implemented. |

The [M3 measurements](../reports/AURA_MINER_M3_EVIDENCE.md) are release-build,
single-worker macOS arm64 samples, 64 trials per N, not service-capacity certification:

| N | Mean trial ms | Trials/s | Proof bytes | Process peak RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| 8 | 4.011 | 249.13 | 5,817 | 2.84 |
| 16 | 7.126 | 140.27 | 10,105 | 2.91 |
| 32 | 13.310 | 75.11 | 18,681 | 3.00 |
| 64 | 25.599 | 39.06 | 35,833 | 3.22 |
| 128 | 50.375 | 19.85 | 70,137 | 3.59 |

These figures include real proof construction and verification. They do not include
a live network queue, secure-mode nonce-set growth, long-running journal audits or
an RPC-heavy production workload. A search deadline is checked at trial boundaries;
it does not preempt an in-flight canonical proof. Bound N to control that overrun.
The side-derived initial state and immutable J/M data can be reused; no general
non-amortization or sequential-hardness result follows from these measurements.

M6's real Core scenario uses N=8, a half-range research target, at most 128 trials
and 30 seconds, a 900-second job, 100,000/90,000-byte W/M host limits, 10,000 sat
reward, 20,000 sat fee budget, 2/10 sat/vB fees and two confirmations. It measured
214 vbytes and 428/2,140 sat fees with an unchanged 48-unit burn. These inputs make
the regression inexpensive; they are not recommended production difficulty,
reward, duration or confirmation values. The older-version confirmation test uses
one confirmation deliberately.

Before monetary activation, measure the intended host's full trial and adversarial
verification cost, sustained bounded ingress, long-lived journal growth/audit time,
RPC latency, proof/memory limits and sponsor exposure. Record the selected explicit
values and rationale, including the expected hit model from the miner owner. The
current evidence does not calibrate tariff adequacy, profitability or production
economic security. Unmeasured higher N/load is not qualified merely because a
configuration accepts the number. Approval of implementation is not approval to
choose deployment values or spend live BTC.

## Operator setup and normal flow

1. Establish one journal identity/network and trusted operator x-only key; keep the
   signing secret outside logs and public job data. Use separate public fixture
   keys only in the isolated harness. Provision the existing Aura ledger/payer
   balances through their approved owner; mining creates no Aura balances.
2. Explicitly create the economic journal with its intended ledger/genesis, or
   open the existing one. Never initialize because `open` failed. Install miner
   policy and publication tables once through their explicit APIs. Schema errors
   require investigation, not dropping tables or resetting history.
3. Use a dedicated Core wallet on the exact configured network, with authenticated
   local RPC or a protected authenticated transport. Preserve typed Core error codes;
   arbitrary errors must not be treated as unknown transactions. Keep RPC/private
   keys off public endpoints. Maintain spendable safe confirmed sponsor UTXOs,
   wallet signing capability, change keys and transaction/block history.
4. Open a round through the journal, providing a callback to the existing funding
   reservation owner. It checks funding/dust/fees and locks the dedicated outpoint
   while the journal pins the snapshot. Publish J/signature and the correct meter
   snapshot only after successful commit. An ambiguous return requires inspecting
   durable rounds and wallet locks before another opening.
5. Each miner authenticates the operator job against trusted policy, checks window
   and host limits, builds the payer-bound M, and performs bounded secure-nonce
   search. Sign the existing economic consent and authorization for the qualifying
   canonical work/reference. Submit through existing admission; a local hit is
   not a winner. Keep the same W and signed reference for idempotent retries.
6. The coordinator resumes committed pending work from durable state. Only the
   resulting Accepted receipt/authorization and reward obligation authorize payment.
   A failed admitted candidate retains its burn and closes the round. Expire an
   unadmitted open round explicitly; in-flight expiry does not cancel admission.
7. Prepare and persist the combined payment through the journal, then publish and
   refresh observation. Inspect all stored versions before replacement; supply the
   expected current txid and explicit bounded fee policy. Confirmation observation
   is reversible and must continue after the first threshold is reached.

## Journal durability and backup

SQLite uses `synchronous=FULL`, `journal_mode=DELETE`, foreign keys and immediate
write transactions; connections use a ten-second busy timeout. Use storage with
reliable locking/fsync and protect database/directory access. Independent copies,
uncoordinated replicas and a filesystem that does not honor SQLite locking are not
supported writers. Network/clock/storage trust is part of this coordinated model.
Do not weaken PRAGMAs, edit rows, prune old epochs or treat an I/O error as rejection.

For a simple consistent backup, quiesce admissions/opening/publication, let active
transactions finish, record the pending attempt if any, and close all journal
connections cleanly. Copy the entire journal only after clean close; do not copy a
live SQLite main file alone or discard a hot rollback journal after a crash. Back up
the Core wallet through its supported wallet backup procedure and retain required
transaction/block history. Keep wallet and journal backups securely separated from
the active host with access controls appropriate to their keys and signed payments.

Record backup provenance outside the copied database: journal identity/network,
time, policy/round position, last durable attempt/head, outstanding obligations,
payment versions and wallet backup identity. This is operator recovery inventory,
not a new canonical checkpoint or consensus object. Maintain a trusted record of
which backup is latest and test restoration in an isolated environment without
broadcasting or admitting work. A consistent stale journal passes its internal
audit; it cannot prove it is the latest copy.

After restoring, keep all writers disabled until that provenance and external Core
publication/funding state agree. Never run the old and restored databases as two
live journals. If later accepted history is missing and cannot be recovered, stop
for operator recovery: do not create a fresh namespace/head or replay old work as a
new winner. No automatic rollback reconciliation or history merge is implemented.

## Monitoring and recovery

Monitor journal open/audit errors, disk/fsync failures, busy timeouts, pending-attempt
age, round expiry, verification failures, debit/head progression, reward backlog,
payment revisions/fees, RPC errors/latency, Core sync/network/tip, wallet locks and
unspent reservations. Refresh included/confirmed payments and alert on reorg,
unknown spend, missing history or observation disagreement. Set alert thresholds
from the intended deployment's measurements; this repository supplies no universal
timeouts, alert SLA, metrics collector or automated supervisor.

| Condition | Recovery action |
| --- | --- |
| Crash before admission commit | Reopen/audit; there is no durable debit. Retry the same signed work only after checking current round state. |
| Committed attempt pending / crash during verification | Resume that attempt ID. Retain its signatures, charge, round ownership and prior head; do not request another nonce or debit. |
| Failure during terminal transaction | Reopen/audit and resume if pending. Authorization/head/winner/obligation are one commit; never repair only one row. |
| Host bounds reduced below pending work | Keep it pending and restore a measured configuration that can execute it, or investigate operationally. No timeout refund or invented terminal result. |
| Open job expired without admission | Expire through the journal, then use guarded funding release. Next round has a new challenge/number. |
| Ambiguous funding/open commit | Reconcile durable rounds and Core locks. Never unlock or reuse an outpoint that may belong to an open/admitted/accepted round. Orphan locks need explicit operator reconciliation. |
| Core restart loses volatile locks | Keep other wallet spending disabled while reconciling all durable reservations. Payment observation/preparation restores a live accepted reservation; open/admitted reservations must be checked and re-locked before other wallet use. |
| Prepared transaction / uncertain broadcast | Read payment history and use the combined publisher to observe/rebroadcast persisted bytes. Never independently fund another transaction for the same obligation. |
| Fee increase needed | Use explicit replacement of the current unconfirmed version; preserve the reserved conflicting input and exact payout/anchor. Stay inside the stored fee budget. |
| Reorg / delayed confirmation | Refresh all known versions and safely rebroadcast. An older version may confirm. Retain the original burn, nonce reservation, winner and entitlement. |
| Unknown reserved-input spend | `RecoveryRequired`: stop payout and reconcile Core/wallet history. The SDK must not select new funding or mint another entitlement. |
| Corrupt/inconsistent or stale backup state | Stop writes, preserve evidence and restore verified coordinated history. No SQL patching, implicit genesis or winner/head merge. |

The validating Core wallet and needed block data must remain available. Pruned or
missing historical data can prevent verification and therefore defers publication;
it does not justify trusting an old observation. A third-party indexer/txindex is
not required by the tested path. Fee/RPC failures do not change Aura burn accounting.

## Security and activation status

M3/M6 evidence demonstrates bounded verified computation, a probabilistic target
filter, coordinated atomic accounting and regtest payment recovery. It does not
prove Storm is sequentially hard, non-amortizable, ASIC-resistant, a minimum-energy
function, universally useful work, Sybil-proof, permissionless/Nakamoto consensus,
or a succinct/ZK proof. Forcing precomputation and repeated owner execution within
a trial remain possible optimization subjects, not a hardness guarantee.

The operator can censor/order jobs, choose policy, leak challenges and control reward
custody. An admitted fabricated low reference can burn funds and stale honest work;
current tests do not establish tariff adequacy against that attack. Sponsor funding
is not trustless escrow. Independent review and deployment-specific measurements
remain necessary before meaningful monetary exposure. Explicit user approval is
still required for live funding/publication; M7 readiness does not grant it.
