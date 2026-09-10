# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
State: COMPLETE
Last updated: 2026-09-10

## Outer mission

Complete the approved Bitcoin economic-integration milestone from the current worktree, including durable admission, finalization, recovery, parity, owning documentation, and real Bitcoin validation. Local node completion does not complete this outer mission.

The current detailed `docs/decisions/bitcoin-economic-admission.md` contract is APPROVED FOR IMPLEMENTATION by the user. Implement it exactly. Any semantic deviation returns USER_DECISION.

Approval covers consent/W/metering, payer mapping, BIP340 signing, tariffs, tuple-scoped attempt identity, retries/no double burn, pre-admission versus chargeable failures, atomic debit and durable attempt, separate authorization records, material/FractalKey binding, atomic terminal finalization/outbox, recovery/reorgs, head V2 formulas/genesis and explicit V1 predecessor migration. The decision records approval and historical design rationale; active definitions have been promoted to their existing owners. No further approval is needed for this exact contract.

## Frozen invariants

- Storm remains the active public execution/proof interface.
- Historical cat-map, old authorization/state, and mixed-session paths remain explicit legacy imports.
- Existing hash/field, Storm recurrence, proof material, FractalKey, Authorization V2, UDOT, burn constants/meter bytes, and Bitcoin anchor wire do not change except where the approved economic-admission/head-V2 contract explicitly requires integration.
- One concept -> one canonical owner -> one canonical representation.
- No parallel authoritative specification.
- Fail closed.

## Primary authority references

- `docs/decisions/bitcoin-economic-admission.md`
- `docs/authoritative/AURA_LEDGER_AND_BURN_V1.md`
- `docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md`
- `docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md`
- `docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md`
- `docs/authoritative/AURA_REPORT_CONTRACT_V1.md`

Registry: `docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md`.

## DAG

Use only these states: READY | ACTIVE | DONE | BLOCKED | DECISION

| ID | State | Depends on | Objective | Acceptance / evidence |
|---|---|---|---|---|
| S6.0 | DONE | — | Establish approval, current work and V4 tooling | Full contract approved; V4 installed. |
| S6.1 | DONE | S6.0 | Extract existing M owner and strict typed decoder | Rust/TS parity, unchanged metering/burn fixtures; structural validation separate from chargeable failures. |
| S6.2 | DONE | S6.1 | W, consent, head V2, durable economic coordinator and atomic authorization/outbox | Exact approved bytes, all four outcomes, replay/concurrency/crash recovery; 12 durable journal tests pass. |
| S6.3 | DONE | S6.2 | Complete owner alignment and economic-to-Bitcoin acceptance evidence | Owner alignment, full milestone gate, actual regtest and acceptance audit passed. |

Meter owner: `crates/aura_l2_local_chain_v0/src/economic_meter.rs`, shared by the historical writer in `lib.rs`; matching TS owner: `packages/aura_sdk_v0_ts/src/index.ts`. Old request/head digests include fixture/tamper/expected-result metadata and do not define head V2.

Existing actual proof/material/lineage verification and nonce journal: `crates/aura_sdk_v1/src/authorization.rs`. Its unchanged verifier and shared reservation compose into `economic/journal.rs`; `economic.rs` and `economic/head.rs` own the new contract. Work remains root-local.

## Evidence

- Current observed HEAD: `2d4f239` (`slice 6`), containing economic implementation. Final documentation and focused test corrections remain in the worktree. Do not reset unrelated state.
- Historical authorization implementation moved byte-for-byte into `crates/aura_intent_lineage_v1/src/legacy_authorization_v1.rs`; canonical hash/field/Storm/proof implementations and frozen fixtures stayed unchanged.
- Prior targeted checks passed: active workspace all-target compilation, 57 Storm/proof tests, 19 core/SDK documentation tests, BIP340 acceptance, six TS parity/boundary tests and 60 local economic regressions.
- Earlier pre-integration broad run passed active-foundation and UDOT parity but stopped at sandbox `listen EPERM 127.0.0.1`. Superseded by the successful economic regtest with normal loopback escalation below; never treated as an end-to-end pass.
- V4 archive checksum verified once; seven skill payload files, TOML profile and twenty preserved explicit-only specialists verified. External rollback identity: `.codex/.aura_runtime_v4_state.json`. Model and reasoning settings unchanged.

- S6.1: strict Rust/TS M codecs and shared legacy payload writers implemented. Six focused tests in each language passed; eight new frozen production vectors agree; eight pre-extraction legacy byte/charge vectors remain identical. Rust `cargo test -p aura_l2_local_chain_v0 --lib canonical_pipeline_`: 60 passed. TS targeted canonical/attestation/burn regression: 24 passed (`/tmp/aura-meter-ts-regression.log`). Inner attestation tamper flags are fixed zero in canonical M; legacy bytes remain intact.

- S6.2: Rust economic contract tests 5 passed; combined TS meter/contract tests 11 passed. Every signed W byte is mutation-tested. All four head outcomes, strict envelopes, wrong network/lineage/target, u64 overflow and stale head/debit are covered. Authorization V2 shared vector remains identical. Eight Rust meter/local-work tests and eight Authorization V2 tests passed.
- Durable journal: 12 tests pass (`/tmp/aura-economic-journal-final.log`), covering all outcomes, consent/admission failures, idempotent re-signing/retries, nonce conflicts, competing writers, process exit, rollback after debit/outbox/terminal updates, corruption, local attestation/settlement context and explicit V1 checkpoint migration preserving authorization history.
- Actual Bitcoin Core 29 regtest passed: authenticated consent, atomic debit, restart, actual Storm proof/material/lineage verification, atomic authorization/head/outbox, publication, fees/network rejection, confirmations and reorg retry without reburn or nonce release.
- Final expanded gate passed (exit 0): `BITCOIND=/tmp/aura-bitcoin-runtime/bitcoin-29.0/bin/bitcoind bash scripts/verify_repo_truth.sh`, log `/tmp/aura-economic-final-gate.log`. It includes the 23-package Solana boundary, active foundation, shared economic/auth/Bitcoin vectors, UDOT parity and actual economic-to-Bitcoin regtest with normal loopback escalation.
- Final concurrency audit corrected retry/observation attempt reads to use one database snapshot, preventing mixed pre/post-finalization views. The 12 journal tests passed again with eight competing retry workers; the final regtest binary was rebuilt after this correction.

## Final acceptance audit

- Canonical W/M and consent have strict single encodings, explicit limits and shared Rust/TypeScript vectors. Economic consent is distinct from proof authorization; no external completion/proof argument can replace stored work.
- Atomic debit/attempt ownership precedes chargeable work. All four outcomes retain exactly one burn; only Accepted reserves authorization and writes the unchanged Bitcoin request. Head V2 and slot release share that finalization transaction.
- Existing local transfer/attestation/settlement checks, full proof/material/FractalKey/lineage verification and Authorization V2 replay order remain composed through their owning implementations.
- Restart, rollback, concurrent retry, nonce conflict, explicit V1 predecessor migration, outbox publication and Bitcoin reorg behavior passed focused and integration validation.
- Compared with pre-economic baseline `04e6e9a`, canonical hash/field/Storm/proof, material, FractalKey, UDOT and Bitcoin codec/transport sources are unchanged. Existing frozen fixtures are unchanged; only `fixtures/economic_admission_v1/` is new. Shared old metering bytes and burn outputs pass Rust/TypeScript regression checks.
- Existing authoritative owners agree with implementation. The decision is classified as approved historical design evidence; legacy fixture/head formats and standalone authorization primitives are not presented as the production coordinator. README documents the operator and developer entry paths.
- Remaining limits are explicit architectural boundaries: witness replay rather than succinct/ZK proof, coordinated local economic ledger and journal-scoped uniqueness, serialized admission, trusted V1 checkpoint/consistent backups, and operator-managed Bitcoin publication/confirmation. They are not unresolved economic integration work.

## Blockers / decisions

No semantic approval or implementation blocker is outstanding. Regtest loopback escalation was approved and the real integration run passed.

Project root-only/default-tier profile is installed; effective host settings remain unobserved until reload. No V4 usage benchmark has been measured. Tooling guidance remains subordinate to host system/developer instructions.

## Next READY node

None. The approved economic-integration milestone is complete. Further protocol work requires its own bounded objective; do not continue polishing this milestone.

## Stop condition

Stop only when the outer economic milestone is satisfied, USER_DECISION is required, TRUE_BLOCK/AUTHORITY_CONFLICT prevents safe progress, or the runtime/allowance forces termination. A local test, node, slice or commit is not global completion.
