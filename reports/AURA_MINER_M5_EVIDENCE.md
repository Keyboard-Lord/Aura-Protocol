# Aura Miner M5 — Bitcoin reward publication

Classification: IMPLEMENTATION / TEST EVIDENCE, not active protocol authority.
Date: 2026-09-11. Status: M5 DONE; M6 READY. No monetary deployment authorized.
Design owner: [approved miner design](AURA_MINER_PROTOCOL_V1.md), section 8.

## Implemented boundary

[Publication module](../crates/aura_sdk_v1/src/economic/journal/miner/publication.rs)
extends the same economic journal with explicit `install_miner_publication`,
`prepare_miner_payment`, `publish_miner_payment`, `replace_miner_payment`,
`observe_miner_payment` and `miner_payments` APIs. Core retains transaction
encoding, PSBT construction and wallet signing. Hosts provide authenticated RPC;
the regtest adapter uses Core's CLI and preserves typed RPC errors. Only Core's
specific unknown-transaction code is treated as absence, never a general RPC error.

- Each payment belongs to the existing Accepted attempt/reward obligation. Initial
  construction explicitly selects its dedicated reserved outpoint and disables
  automatic input selection. Actual decoded outputs are checked by the existing
  Aura anchor owner and the approved exact output-key reward predicate. Additional
  outputs may only be the recorded sponsor-wallet change script.
- Signed transaction bytes and their version are committed before broadcast.
  Preparation retries return the stored transaction. Publication rechecks actual
  Core-decoded bytes, wallet input parents, reserved-input inclusion, outputs and
  exact integer fee before using Core's mempool check and broadcast. The internal
  transaction checksum detects storage corruption; it is not another proof or
  payment identity.
- Explicit fee replacement requires the expected current unconfirmed transaction.
  Core builds a replacement PSBT; the journal checks the same reserved input,
  unchanged reward/anchor, sponsor change and increased fee/rate within the reserved
  budget. Revisions therefore conflict on Bitcoin. Stale replacement requests fail
  and must inspect history, rather than create another payment.
- Fresh observation checks all recorded versions, active block inclusion, depth,
  mempool state and a stable chain tip. An older version may be the confirmed
  payment; a newer prepared version cannot override that fact. Unknown spends or
  unavailable funding without a known active payment produce `RecoveryRequired`;
  no independent replacement funding is selected.
- Observations and the existing anchor outbox's publication reference commit
  together. They never change the accepted winner, obligation, burn, authorization
  nonce or Head V2. A crash after Core accepts the send but before that commit is
  recovered by observing the already-persisted transaction. Reorg observations are
  reversible; reward entitlement and economic history are not reopened.
- Core wallet locks are restored when the reserved output is live after wallet
  restart or reorg. Existing guarded release remains limited to no-winner rounds.

[Funding reservation](../crates/aura_sdk_v1/src/economic/journal/miner/funding.rs)
now takes an explicit preflight fee rate in addition to its fee budget. Before
locking/publishing a job, an **unsigned, never-broadcast** wallet template checks
current Core dust/funding/fee policy using the same-sized operator output-key
script. Actual winner payment is checked independently. No M2 or funding-record
encoding changed; M4 test RPC adapters were extended for this operational check.

## Reproducible Core evidence

[Gate](../scripts/verify_miner_regtest_v1.mjs),
[Rust regtest adapter](../crates/aura_sdk_v1/examples/miner_m5_regtest.rs),
[captured final output](miner_protocol_v1/m5_regtest_results.json).

```sh
BITCOIND=/tmp/aura-bitcoin-runtime/bitcoin-29.0/bin/bitcoind \
BITCOINCLI=/tmp/aura-bitcoin-runtime/bitcoin-29.0/bin/bitcoin-cli \
node scripts/verify_miner_regtest_v1.mjs
```

The gate starts an isolated Core 29.0 regtest node with networking disabled and
temporary wallet/journal data. It uses the existing TS RPC transport for node
administration and the Rust journal APIs for the actual funded mining/payment path.
Local loopback required the normal sandbox escalation. No real funds were used.

Research configuration: N=8, target `7f` followed by 31 `ff` bytes, bounded 128-trial
search, 30-second search budget, 900-second job window, 10,000 sat reward, 20,000 sat
fee budget and two confirmations. These are test settings, not deployment values.

The successful run measured a **214-vbyte** combined transaction, **428 sat** fee at
2 sat/vB and **2,140 sat** at 10 sat/vB after replacement. It retained **one Accepted
winner**, **one obligation**, **two conflicting transaction versions**, and the
unchanged **48-unit Aura burn**. No new miner throughput benchmark was collected.

Verified on real Core:

- Dust reward, insufficient dedicated funding and excessive preflight fee reject
  before a job opens, without leaving a wallet lock or admitted candidate.
- Actual local Storm search, canonical proof/material verification, economic
  admission, restart/resume and authorization reach the Accepted obligation.
- The transaction spends the reserved output, pays exactly the approved miner
  output key and amount, and contains the byte-identical existing Aura OP_RETURN.
- Fee-cap failure persists no transaction. Preparing again with different fee
  settings returns identical signed bytes. The bytes survive a fresh process.
- Core is stopped/restarted after preparation; observing the unbroadcast payment
  restores the volatile funding lock and retains the same payment.
- A child process exits immediately after successful `sendrawtransaction`, before
  journal acknowledgement. A new process recovers it without another payment.
- Explicit replacement keeps the same input/reward/anchor; the mempool contains
  only the replacement. Stale and post-confirmation replacement attempts fail.
- One-block inclusion, two-block confirmation, invalidation and a new branch are
  observed. Rebroadcast/reconfirmation and old candidate retry preserve the same
  head, burn, nonce reservation, winner and obligation.

## Targeted validation

```sh
cargo test -p aura_sdk_v1 --offline --lib economic::journal::miner
cargo test -p aura_sdk_v1 --offline --test miner_v1 --test economic_contract_v1 --test economic_journal_v1 --test authorization_v2
cargo check -p aura_sdk_v1 --offline --lib --bins --examples
node --test packages/aura_sdk_v1_ts/src/minerV1.test.ts packages/aura_sdk_v1_ts/src/minerSearchV1.test.ts packages/aura_bitcoin_v1_ts/tests/*.test.ts
git diff --check
```

Passed: **21** miner journal/publication test entries (including the M4 child-process
helper), **9** Rust M2, **5** economic contract, **12** economic journal, **8**
Authorization V2 and **19** TS miner/Bitcoin checks; SDK compile passed. Focused
payment mutations reject wrong/duplicated reward, changed anchor, reserved-input
removal, duplicate/nonreplaceable inputs, unauthorized outputs and bad fees. Existing
frozen work/consent/head, proof/material/authorization and M2 parity vectors passed.

Frozen cryptographic owners, canonical economic/authorization/head formulas, M2/M3
fixtures, Bitcoin anchor codec and `docs/authoritative/` are unchanged. No alternate
candidate/proof wire, Aura issuance or fee-to-burn conversion was introduced. The
full Bitcoin migration gate was not rerun.

## Remaining boundaries

M6 must extend this into the required adversarial full-system acceptance gate;
M7 owns operational/authority promotion. The current evidence does not certify
production readiness, calibrated difficulty, commercial usefulness, sequential
hardness, succinct/ZK proofs or permissionless consensus. Funding remains custodial;
sponsor honesty, node/wallet trust, backups and host RPC timeouts matter. Ambiguous
wallet locks/spends and chain-view failures require reconciliation, never another
independently funded reward. Monetary deployment remains separately gated.
