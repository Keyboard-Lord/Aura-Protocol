# Aura Miner V1 — M7 readiness and master completion

Classification: IMPLEMENTATION / ACCEPTANCE EVIDENCE, not protocol authority.
Date: 2026-09-11. M0–M7 DONE. No monetary activation authorized.

## Delivered boundary

The approved coordinated miner program has one tested implementation path:

`signed funded job → nonce-conditioned Storm search → verified existing PoC →
signed-target proof_hash predicate → durable coordinated admission/debit → service
re-verification → Authorization V2 / Head V2 / unique winner / reward obligation →
persisted sponsor-funded Bitcoin payment + unchanged anchor → observation / reorg recovery`.

The canonical miner definitions now belong to the existing
[Aurafarming owner](../docs/authoritative/AURA_AURAFARMING_NODES.md), registered as
active in the unchanged 25-document topology. The
[design record](AURA_MINER_PROTOCOL_V1.md) keeps D1–D6 rationale/approval and evidence,
and replaces its duplicate normative field lists/formulas with owner references.
Pipeline, ledger, authorization, Head V2 and Bitcoin owners reference the miner
integration while retaining their existing encodings/formulas. No new authority
file, proof identity, external miner wire or independent settlement owner was added.

The prior 20-node/EMA proposal is preserved verbatim after an explicit archive
banner in [historical research](../docs/research_assets/AURA_AURAFARMING_NODES_RESEARCH_V0_2.md).
Its unsupported convergence/protection claims were not promoted into the protocol.
Root/TS/fixture READMEs now point to the active owner and executable implementation.
Old milestone reports retain their dated closure states as historical evidence;
the current DAG is [SLICE.md](../aura-runtime/SLICE.md).

## Reconciliation and bounded fixes

| Surface | Before M7 | Resolved state |
| --- | --- | --- |
| Miner authority / developer map | CODE > DOC: M2–M6 implemented, owner still network research | DOC = CODE: approved contract promoted into that existing owner; research archived; decision history references it |
| Policy sequence | DOC > CODE: approved design required epoch zero and the next consecutive epoch; install/rotation allowed arbitrary increasing epochs | Explicit zero initialization, checked successor, and consecutive persisted-history audit; missing/skipped history rejects |
| Production challenge timing | DOC > CODE: approved design required state/policy fixation before challenge; wrapper drew entropy before transaction acquisition | Clock/challenge callback runs after the immediate transaction pins policy/round/ledger/head; invalid opening or RNG failure opens no round |
| Operator readiness | CODE > DOC: SDK/control/recovery behavior and measurements lacked one operating path | Operations guide maps API ownership, measured limits, setup, monitoring, backup provenance and failure procedures |

The two code corrections enforce the already-approved design, not new semantics.
They modify only `economic/journal/miner.rs` and add two focused `tests/promotion.rs`
tests. Test-only deterministic opening retains its previous inputs. There is no
change to canonical M2 bytes, hash/field, Storm/trace/claim/proof, material/FractalKey,
proof_hash, signatures, tariffs, W/M, Head V2, UDOT or Bitcoin anchor bytes.
Development journals with invalid epoch history fail closed; history is never
silently renumbered or normalized.

## M7 requirement evidence

| Required readiness item | Concrete evidence / boundary |
| --- | --- |
| Exact active miner boundary and one owner | Existing Aurafarming document, registry ownership/status entry, generic-owner cross-references; one EconomicJournalV1 |
| Implementation map and safe developer path | Root README, TS README, fixture notes and [operations guide](../docs/AURA_MINER_OPERATIONS_V1.md#supported-boundary) map canonical owners, APIs and tests |
| Operator requirements | Guide setup: trusted key/network/namespace, existing funded Aura payer, explicit journal/policy/publication initialization, secure nonce mode, job publication only after durable opening |
| Deployment limits and supported policy | Guide configuration table: explicit epoch N/T and byte bounds, round/reward limits, local search bounds, fee budget and confirmation policy; no defaults or auto-retarget |
| Measured mining parameters | M3 release measurements at N=8/16/32/64/128; M6/M7 real Core scenario and explicit test-only settings; no production difficulty or capacity inferred |
| Journal durability | Existing FULL/DELETE/foreign-key/immediate transaction behavior, ten-second busy timeout, coherent one-writer-domain requirement and crash tests |
| Backups | Guide quiesce/clean-close backup, wallet backup, outside-the-copy provenance, isolated restore rehearsal and no second live journal |
| Bitcoin wallet / funding | Dedicated safe confirmed sponsor outpoint, authenticated correct-network Core, signing/change/history availability, fee/dust preflight, lock reconciliation and custodial limitations |
| Monitoring | Guide names round/attempt, failure, disk/lock/RPC, payment/reorg/funding and backlog signals; deployment must supply supervisor/ingress/alerts, with measured thresholds |
| Failure / recovery | Guide table maps pending work, atomic-finalization failure, expiry, fee/broadcast ambiguity, Core restart, unknown spend, corruption and stale snapshot to existing APIs or fail-closed operator recovery |
| Security limits | No hardness/energy/non-amortization/ASIC, broad useful-work, Sybil-proof, permissionless consensus or succinct/ZK claims; operator custody/ordering and failed-candidate griefing explicit |
| Activation boundary | No live funding, reward payment, service deployment or new production parameter choice performed; separate explicit monetary approval still required |

## Validation and measurements

Targeted reconciliation first:

```sh
cargo test -p aura_sdk_v1 --offline --lib economic::journal::miner::tests::promotion
```

Both tests passed. Epoch tests reject nonzero initialization, same/skipped/MAX
rotation and a missing persisted intermediate epoch; valid consecutive rotation
survives reopen. Challenge tests independently attempt another immediate write at
entropy generation and receive SQLITE_BUSY, verify invalid input does not draw
entropy, and verify RNG failure leaves no round/counter/funding effect.

Then the existing full miner gate ran once on the corrected implementation:

```sh
BITCOIND=/tmp/aura-bitcoin-runtime/bitcoin-29.0/bin/bitcoind \
BITCOINCLI=/tmp/aura-bitcoin-runtime/bitcoin-29.0/bin/bitcoin-cli \
node scripts/verify_miner_program_v1.mjs --m7
```

[Captured M7 result](miner_protocol_v1/m7_acceptance_results.json): **11 stages
PASS**, **186 top-level Rust test entries** (including child-process helpers),
one additional nested child-test summary, **58 TS tests**, SDK library/binary/example
compile, and **17 explicit adversarial Core cases** plus the positive lifecycle.
The `--m7` evidence selector preserves the historical M6 result. No warning or
zero-test stage was accepted. [M6 evidence](AURA_MINER_M6_EVIDENCE.md) maps each
attack class to its tests; those tests all ran again after the two boundary fixes.

Final Core stage: 14,692 ms on macOS arm64, Rust 1.88.0, Node 22.22.2, Core 29.0.
Its main N=8 scenario retained one winner/obligation, two conflicting payment
versions, 214-vbyte payment, 428/2,140 sat fees and the same 48-unit burn across
crash, replacement and reorg. Test-stage time is not throughput calibration.
No new N/target benchmark was needed: unchanged M3 measurements remain the
numerical basis, with their single-worker and deterministic-nonce limitations.

Static checks verify local Markdown targets/anchors, exactly 25 registered
authoritative files, byte-preserving research archival, absence of duplicate job
preimages in the design report, M2/M3 frozen vector identity, and `git diff --check`.
No migration-wide audit or unrelated cleanup was performed.

## Master completion audit

| Node | Evidence establishing completion |
| --- | --- |
| M0 / M1 | Approved design/dependency map and explicit D1–D6 decision record, retained above; no design reopened |
| M2 | Exact shared job/profile vector, every-byte/malformed-input coverage, inclusive BE target tests; unchanged Rust/TS bytes |
| M3 | Real canonical Storm proof/search tests, frozen trial vector, nonce/rebinding experiments and recorded N scaling |
| M4 | Same-journal contention/debit/finalization tests, seven crash boundaries, separate-identity race and retry storm; one winner/obligation |
| M5 | Real Core funding/preflight, persisted combined payment, explicit conflicting fee replacement, restart/reorg/no-reburn evidence |
| M6 | Reproducible 11-stage attack/regression gate, including storage corruption and honest complete-snapshot rollback limitation |
| M7 | Existing-owner promotion, archived research, implementation/runbook map, approved-contract reconciliation and final gate above |

No required implementation node remains. This is SDK/system implementation and
operational-documentation readiness, not a deployed public miner service or an
independent security certification. Host job transport, supervision, calibrated
ingress/monitoring, deployment-specific capacity, backup restore practice and
economic exposure review remain deployment responsibilities described in the guide.
A whole consistent database rollback still needs external provenance. Production
monetary settings and live activation remain a separate user decision. No
permissionless-consensus redesign follows this milestone.
