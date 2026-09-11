# Aura Miner M4 — coordinated rounds

Classification: IMPLEMENTATION / TEST EVIDENCE, not active protocol authority.
Date: 2026-09-11. Approved design: [AURA_MINER_PROTOCOL_V1](AURA_MINER_PROTOCOL_V1.md).
Status: M4 DONE; M5 READY. No monetary activation.

## Implemented boundary

[Round module](../crates/aura_sdk_v1/src/economic/journal/miner.rs) extends the
[existing economic journal](../crates/aura_sdk_v1/src/economic/journal.rs). It adds
no second execution, debit, authorization or settlement endpoint. The existing
`admit` / `submit` / `resume` methods recognize the frozen miner route.

- `install_miner_policy` explicitly installs the optional journal extension.
  `update_miner_policy` preserves historical policies and journal identity and
  requires an idle journal and a strictly newer epoch. N, target, byte caps,
  maximum duration and minimum reward are explicit operator inputs without defaults.
- `open_miner_round` holds the existing SQLite immediate transaction while it pins
  Head V2, ledger, policy, sequential round number, a CSPRNG challenge, the signed
  frozen 471-byte J, and the dedicated funding reservation. It returns the
  publishable job only after commit. A current V2 head is required; no implicit V1
  head conversion occurs. Only one open/admitted round can exist.
- Opening reserves scheduling against ordinary admissions. New miner admissions
  authenticate existing consent and authorization signatures, verify stored J and
  policy, exact W/profile, current snapshots, expiry and signed target. The clock
  is sampled after acquiring the write transaction. Round acquisition and the
  existing attempt/debit commit together. Same tuple/W/proof-reference retries are
  resolved before current-head or expiry checks; re-signing is idempotent.
- After admission, the existing server path executes M and regenerates the
  canonical Storm claim/proof from persisted W, verifies proof/material/FractalKey
  and lineage binding against the signed proof reference, and applies existing
  settlement checks. A client proof blob or `qualifies` boolean cannot select the
  verdict. M3 candidates supply their existing W and proof reference plus the
  existing authenticated consent/authorization objects. No candidate wire or
  second proof identifier was introduced.
- Accepted finalization commits the authorization reservation, existing Head V2
  and anchor outbox, terminal round/winner and unique reward obligation in the
  same transaction. The obligation references the round and economic attempt;
  winner identity and proof hash remain owned by the accepted authorization,
  reward amount by J. No reward is credited to the Aura ledger.
- All three chargeable failure outcomes retain the existing full burn/head
  transition, close the round and release its unused database funding reservation.
  A never-admitted expired round closes without burn/head effects. Expiry never
  cancels admitted work. Restart resumes persisted W without client completion.
- `miner_round` and `miner_reward_obligations` expose checked local views. Journal
  opening checks round/profile/signature/funding/snapshot/attempt/winner/reward
  consistency. The generic `record_publication` rejects miner-origin attempts;
  M5 must supply the combined reward/anchor publisher.

## Funding and trust boundary

[Funding adapter](../crates/aura_sdk_v1/src/economic/journal/miner/funding.rs):
`reserve_miner_funding_v1` takes the service's authenticated Core RPC callback,
explicit network/outpoint and fee budget. It checks Core's network, wallet locks,
one confirmed safe/spendable/solvable coin, live unspent value/script, sufficient
reward plus fee budget, then requests the wallet lock. Decimal BTC-to-satoshi
conversion rejects sub-satoshi amounts and handles decimal exponents exactly.
The reservation cannot be deserialized through the public SDK API from a client
claim. The same outpoint cannot back two live rounds or an unpaid accepted winner
in this journal.

SQLite and Core do not share an atomic transaction. A failed/ambiguous opening can
leave an orphan wallet lock; reconcile durable rounds before unlocking. Failed or
expired rounds release the **database** reservation; `release_miner_funding` performs idempotent wallet unlock under the journal write
lock, refusing live, accepted or subsequently reassigned funding. Wallet re-lock
and spend reconciliation remain the wallet manager's responsibility. Wallet restarts
must restore locks before wallet spending. These are custodial reservations, not
Bitcoin escrow: a dishonest sponsor can still spend or withhold funds. Fee budget
and the wallet-policy-approved reward minimum are operator inputs; no production
fee, dust, reward or difficulty calibration is claimed. M5 must validate its actual
transaction against wallet policy before publication.

Core RPC responses were contract-tested with deterministic mocks in M4. No live
Core/regtest payout, transaction signing, broadcast, replacement or reorg test was
performed here; that is the next milestone's required integration boundary.

## Validation

Commands run successfully:

```sh
cargo test -p aura_sdk_v1 --offline --lib economic::journal::miner -- --test-threads=2
cargo test -p aura_sdk_v1 --offline --test economic_journal_v1 --test economic_contract_v1 --test authorization_v2 --test miner_v1
node --test packages/aura_sdk_v1_ts/src/minerV1.test.ts packages/aura_sdk_v1_ts/src/minerSearchV1.test.ts
cargo check -p aura_sdk_v1 --offline --lib --bins --examples
cargo test -p aura_sdk_v1 --offline --lib miner_search::tests
git diff --check
```

- M4: **19 test entries passed** (18 checks and the child-process helper)
  in the final focused debug run. No coordination throughput benchmark was run. Deterministic test jobs use N=8 and target `7f` followed by 31 `ff`
  bytes; bounded fixed nonce sequences supply both qualifying and rejected trials.
- Existing journal **12**, economic contract **5**, Authorization V2 **8**, M2
  Rust **9**, M3 Rust **13**, and TS **11** tests passed. TS includes ten M2 parity
  checks and one existing-object M3 interoperability check. No TS coordination
  implementation or new canonical bytes are needed for this Rust journal owner.
- Valid local PoC reaches a server-reverified Accepted winner. Fake low hash and
  a copied valid proof reference under a newly signed nonce fail after one burn,
  with no authorization/anchor/reward. Above-target, bad profile/route/intent,
  signatures, nonce binding, stale ledger/head and out-of-window inputs fail
  before charge. All four existing economic outcomes are covered.
- Two simultaneous contenders produce exactly one admitted attempt; simultaneous
  finalizers return the same receipt. Resigned retries, post-expiry retries,
  pending expiry and stricter host limits never create a second charge/winner.
- A child process exits without destructors after admission; reopening reconstructs
  its round and completes it without client input or a second burn. Injected SQL
  failures after debit, authorization, head, winner and reward writes roll back
  the whole corresponding transaction; restart subsequently completes one winner.
- Restart rejects corrupted signatures, counter, funding index, missing reward and
  inconsistent round terminal state. Funding failures, wallet locks, wrong network,
  unspendable/spent/underfunded coins and inconsistent values fail closed. Reused
  challenges fail, accepted-winner funding cannot fund another round, and wallet
  release retries cannot unlock live, reassigned or accepted-winner funds.
- Ordinary work remains blocked during an open round and follows the unchanged
  coordinator after expiry, without a miner reward obligation.

All pre-existing frozen fixtures and owning cryptographic/economic/Bitcoin files
remain unchanged. The M2 job/profile byte comparisons, existing proof/material/
authorization vector and all four frozen economic Head V2 vectors passed. No full
Bitcoin migration gate was needed. No new performance benchmark was collected;
[M3 measurements](AURA_MINER_M3_EVIDENCE.md) remain the computation-cost evidence.

## Next boundary

M5 must consume the durable obligation and reserved outpoint, preserve the exact
anchor, persist a combined reward transaction before broadcast, and validate
retry/replacement/reorg recovery on Core regtest. M6 adversarial integration and
M7 owner promotion/operations remain blocked. M4 does not claim production
readiness, calibrated difficulty, physical/sequential hardness, succinct/ZK
proofs, permissionless consensus, fair ordering or economic security.
