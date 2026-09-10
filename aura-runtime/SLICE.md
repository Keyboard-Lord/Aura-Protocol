# Aura Active Slice Register

Classification: TOOLING / IMPLEMENTATION EVIDENCE; not protocol authority.
Runtime: AURA Runtime V4
State: ACTIVE
Last updated: 2026-09-10

## Outer mission

Complete the approved Bitcoin economic-integration milestone from the current worktree, including durable admission, finalization, recovery, parity, owning documentation, and real Bitcoin validation. Local node completion does not complete this outer mission.

The current detailed `docs/decisions/bitcoin-economic-admission.md` contract is APPROVED FOR IMPLEMENTATION by the user. Implement it exactly. Any semantic deviation returns USER_DECISION.

Approval covers consent/W/metering, payer mapping, BIP340 signing, tariffs, tuple-scoped attempt identity, retries/no double burn, pre-admission versus chargeable failures, atomic debit and durable attempt, separate authorization records, material/FractalKey binding, atomic terminal finalization/outbox, recovery/reorgs, head V2 formulas/genesis and explicit V1 predecessor migration. The decision document still carries its earlier proposal status; update approval evidence and promote each implemented concept into its existing owner. No further approval is needed for this exact contract.

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
| S6.0 | DONE | — | Establish approval, current work and V4 tooling | Full contract approved; V4 installed; planned economic module files are absent. |
| S6.1 | DONE | S6.0 | Extract existing M owner and strict typed decoder | Rust/TS parity, unchanged metering/burn fixtures; structural validation separate from chargeable failures. |
| S6.2 | ACTIVE | S6.1 | W, consent, head V2, durable economic coordinator and atomic authorization/outbox | Dependency only; exact approved bytes, all four outcomes, replay/concurrency/crash recovery. |
| S6.3 | BLOCKED | S6.2 | Complete owner alignment and economic-to-Bitcoin acceptance evidence | Dependency only; complete parity/negative tests and real regtest, restart and reorg. |

Meter owner: `crates/aura_l2_local_chain_v0/src/lib.rs`, especially `canonical_pipeline_burn_metered_bytes_v1`, its payload encoders, checked burn function and ledger commitments. Matching TS owner: `packages/aura_sdk_v0_ts/src/index.ts`. Extract without hidden fixture defaults. Old request/head digests also include fixture/tamper/expected-result metadata and cannot define head V2.

Existing actual proof/material/lineage verification and nonce journal: `crates/aura_sdk_v1/src/authorization.rs`. Keep acceptance order while composing its reservation into economic finalization. Economic APIs belong beside existing SDK owners. Earlier worker handles are unavailable and no economic module was delivered; continue root-local.

## Evidence

- Current observed HEAD: `04e6e9a`; prior core API isolation is present in HEAD. New economic implementation remains in the worktree. Do not reset unrelated state.
- Historical authorization implementation moved byte-for-byte into `crates/aura_intent_lineage_v1/src/legacy_authorization_v1.rs`; canonical hash/field/Storm/proof implementations and frozen fixtures stayed unchanged.
- Prior targeted checks passed: active workspace all-target compilation, 57 Storm/proof tests, 19 core/SDK documentation tests, BIP340 acceptance, six TS parity/boundary tests and 60 local economic regressions.
- Broad command: `BITCOIND=/tmp/aura-bitcoin-runtime/bitcoin-29.0/bin/bitcoind bash scripts/verify_repo_truth.sh`. Log: `/tmp/aura-bitcoin-foundation-milestone.log`. Active-foundation and UDOT parity stages passed; the following regtest stopped at `listen EPERM 127.0.0.1`. This is not an end-to-end pass. Handle 44742 is absent; do not restart the entire gate solely for this network step.
- V4 archive checksum verified once; seven skill payload files, TOML profile and twenty preserved explicit-only specialists verified. External rollback identity: `.codex/.aura_runtime_v4_state.json`. Model and reasoning settings unchanged.

- S6.1: strict Rust/TS M codecs and shared legacy payload writers implemented. Six focused tests in each language passed; eight new frozen production vectors agree; eight pre-extraction legacy byte/charge vectors remain identical. Rust `cargo test -p aura_l2_local_chain_v0 --lib canonical_pipeline_`: 60 passed. TS targeted canonical/attestation/burn regression: 24 passed (`/tmp/aura-meter-ts-regression.log`). Inner attestation tamper flags are fixed zero in canonical M; legacy bytes remain intact.

- S6.2 codec checkpoint: Rust economic contract tests 5 passed; combined TS meter/contract tests 11 passed. Every signed W byte is mutation-tested. All four head outcomes, strict envelopes, wrong network/lineage/target, u64 overflow and stale head/debit are covered. Authorization V2 shared vector remains identical. New pure local-work and ledger snapshot helpers are being validated before journal composition.

## Blockers / decisions

No semantic approval is outstanding for the exact economic contract. Regtest needs permission to bind loopback sockets when that integration node is ready; use normal sandbox escalation rather than weakening the test. Independent implementation work is ready.

Project root-only/default-tier profile is installed; effective host settings remain unobserved until reload. No V4 usage benchmark has been measured. Tooling guidance remains subordinate to host system/developer instructions.

## Next READY node

S6.2. W/consent/head V2 Rust/TS codecs and frozen contract vector are implemented. Next compose the durable coordinator. Do not repeat the completed architecture audit.

## Stop condition

Stop only when the outer economic milestone is satisfied, USER_DECISION is required, TRUE_BLOCK/AUTHORITY_CONFLICT prevents safe progress, or the runtime/allowance forces termination. A local test, node, slice or commit is not global completion.
