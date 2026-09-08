# Aura Repository Truth and Bitcoin Migration Audit V1

Status: AUDIT ONLY — supporting evidence, not a protocol specification.

## 1. Executive verdict

**Aura is not ready for a semantics-preserving Bitcoin migration from an agreed canonical baseline.** There is useful reusable implementation, but no single specification → Rust → TypeScript → fixture → test → verifier chain agrees across all canonical objects. Freeze the current implementation as a historical baseline; do not describe that freeze as complete conformance to the authoritative specification.

The most consequential blockers are:

- The root specification, subordinate derivation specification, and implemented Storm initialization disagree (F01–F03).
- Rust, TypeScript, and the authoritative STARK envelope define three different wires (F04).
- Authorization and settlement implementations embed objects explicitly forbidden by their owning specifications (F05–F06).
- Documented SHA3-512 artifact hashes conflict with implemented 32-byte SHA-256 hashes and the documented 32-byte settlement/UDOT consumers (F07).
- The active Storm proof is a transported witness verified by replay, distinct from the retained Winterfell cat-map proof and local transfer STARK (F10).
- Continuous settlement accepts caller-supplied linkage and supports persistent authority, contrary to its current owning document (F12).
- Existing checks can pass while preserving these contradictions (F15).

**No Bitcoin support was found or is claimed.** The tracked Rust, TypeScript, TOML, shell and MJS source inventory contains no `bitcoin` mention outside third-party exclusions; first-party dependency manifests declare no Bitcoin dependency. External balance/anchor fixtures are not Bitcoin verification.

### Audit baseline and method

- Repository: `https://github.com/Keyboard-Lord/Aura-Protocol.git`.
- Branch: `main`; HEAD: `c86f674306a4dc69bec3e7d0c69c4b54f9296a11`.
- `git ls-remote origin refs/heads/main` returned the same commit during this audit. No checkout, merge, fetch, commit or push was needed.
- Initial tracked modifications: `.DS_Store`, `docs/.DS_Store`. Preserved untouched.
- Inventory: 470 tracked files before this report, including 35 `.DS_Store` files. Inspected authoritative documents, all crate/package manifests, canonical code paths, fixture/test surfaces, verifier scripts and publication/hygiene inventory. No applicable `AGENTS.md` was found in the checkout or its ancestor paths.
- Evidence citations below are repository-relative paths with symbols/sections and line numbers where useful, all against the above commit. Directory classifications apply to the named component, with explicit mixed-surface exceptions.
- This is a static architecture/conformance audit with bounded corroborating tests, not a full test-suite run, formal cryptographic review, dependency vulnerability audit, PDF content review or network deployment test. Negative findings distinguish absent evidence from a proof of absence.

## 2. Current canonical architecture map

The documentation registry is `docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md`. It fixes 25 Markdown files and gives `AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md` mathematical precedence. The file set exists as advertised; its contents are not mutually consistent.

The implementation has several connected but distinct surfaces:

| Surface | Actual path and role | Relationship to declared canonical path |
|---|---|---|
| Input and field primitives | `crates/aura_intent_lineage_v1/src/aura_hash_v1.rs`, `field_521_v1.rs`, `storm_hash521_v1.rs`; TS `auraHashV1.ts`, `stormHash521V1.ts` | Text normalization and length framing survive in the legacy-named module; direct H_521 exists. A complete root-specified message-root-to-Storm entrypoint is not established. |
| Storm computation | Same Rust crate: `storm_context_v1.rs`, `storm_state_v1.rs`, `storm_execution_v1.rs`, `storm_trace_commitment_v1.rs`, `storm_claim_v1.rs`, `storm_air_v1.rs`; TS corresponding `storm*.ts` files | Chain-neutral byte inputs and recurrence; initialization differs from root authority and claims retain legacy commitments. |
| Lower-layer proof | `stark_prover_v1.rs`, `stark_verifier_v1.rs` | Active Storm witness/replay path, legacy cat-map Winterfell proof, and scaffold coexist in these files. |
| Prepared-proof reference | `aura_proof_material_v1` → `aura_fractal_key_v1` → `aura_fractal_key_integration_v1` → `aura_sdk_v1` | Hashes supplied proof/key/input bytes; does not itself prove their validity. Subject/challenge account bytes enter the reference. |
| SDK object pipeline | `crates/aura_sdk_v1/src/{submission,authorization,proof,pipeline,settlement,udot}.rs`; `packages/aura_sdk_v1_ts/src/index.ts` | Solana-oriented nested objects; Rust/TS proof wire disagreement. Not the reference-only specification. |
| Local execution/proving | `aura_l2_execution_v1` → `aura_l2_public_input_v1` → `aura_l2_trace_builder_v1` → `aura_l2_prover_v1` → `aura_l2_verifier_v1` → `aura_l2_local_settlement_v1` | Separate transfer-only 284-byte public-input contract; explicit mock and Winterfell modes. |
| Local orchestration | `aura_l2_local_chain_v0`, `aura_sdk_v0`, `packages/aura_sdk_v0_ts` | Execution/attestation reports, burn ledger, replay/head persistence and external-balance references. TS bridge validates/orchestrates; it is not an independent STARK prover. |
| Solana recording | `aura_submission_client_v1`, `packages/aura_submission_client_v1_ts`, root `src/lib.rs` | Builds/signs/submits Solana transactions and records a 32-byte commitment under challenge/PDA rules. |
| Presentation | `aura_udot_v2`, `aura_notarization_*`, CLI/demo | UDOT glyphs, receipt export/render/workbench/workflow; not settlement consensus. |

The root crate is explicitly the **frozen Solana MVP**, not the entire canonical cryptographic core (`Cargo.toml:5`, `src/lib.rs`). `default-members = ["."]` means plain root Cargo commands do not test every workspace crate. `members = [".", "crates/*"]` includes active, legacy and research crates in workspace-wide commands.

## 3. Frozen-core boundary and migration classification

`FROZEN_CORE` below means preserve the observed bytes/behavior during settlement migration. It does **not** certify security, complete specification conformance, or that a contradictory v1 wire is the correct future API. Mixed files must not receive a blanket classification.

| Files/components | Classification | Evidence and freeze interpretation |
|---|---|---|
| `crates/aura_intent_lineage_v1/src/field_521_v1.rs`; Rust `storm_state_v1.rs`, `storm_trace_commitment_v1.rs`; TS `stormStateV1.ts`, `stormTraceCommitmentV1.ts` | `FROZEN_CORE` | 66-byte field coordinates, 132-byte rows, ordered SHA3-256 trace Merkle rules. Preserve widths/order/modulus/odd-node rule. |
| Rust `storm_hash521_v1.rs`, `storm_execution_v1.rs`, `storm_context_v1.rs`; TS `stormHash521V1.ts`, `stormExecutionV1.ts`, `stormContextV1.ts` | `FROZEN_CORE` | Preserve current direct hash and recurrence as observed baseline; F01–F03 prevent declaring all specifications aligned. |
| Rust `storm_claim_v1.rs`, `storm_air_v1.rs`; TS `stormClaimV1.ts` | `BITCOIN_MIGRATION_BOUNDARY` | Core encodings must stay frozen initially, but legacy commitment fields and proof/public-input ownership require explicit version decisions. |
| Rust `stark_prover_v1.rs`, `stark_verifier_v1.rs` | `CHAIN_NEUTRAL_ACTIVE` | Active witness replay is reusable; legacy Winterfell/scaffold portions are `LEGACY_COMPATIBILITY`. Freeze proof bytes/backend parameters during adapter work. |
| `crates/aura_proof_material_v1`, `crates/aura_fractal_key_v1` | `FROZEN_CORE` | Frozen SHA-256 reference construction, fixed tags/order/32-byte components. Do not “correct” to SHA3-512 under v1. |
| `crates/aura_fractal_key_integration_v1`; SDK preparation/submission/authorization/proof/pipeline boundaries | `BITCOIN_MIGRATION_BOUNDARY` | Integration explicitly binds subject pubkey and challenge-account pubkey; v1 SDK wires retain Solana semantics. Preserve old APIs pending a separate successor boundary. |
| `crates/aura_udot_v2/src/v2.rs` and `artifact.rs` | `FROZEN_CORE` | Current glyph alphabet, reversible wallet matrix and seal derivations are fixture-pinned; wire wrappers in SDKs are a boundary (F08–F09). |
| `crates/aura_l2_execution_v1`, `aura_l2_public_input_v1`, `aura_l2_trace_builder_v1`, `aura_l2_prover_v1`, `aura_l2_verifier_v1`, `aura_l2_local_settlement_v1` | `CHAIN_NEUTRAL_ACTIVE` | Local execution/verification/acceptance; manifests have no Solana dependency. Mock mode must remain explicitly labelled. |
| `crates/aura_l2_local_chain_v0`, `crates/aura_sdk_v0`, `packages/aura_sdk_v0_ts` | `CHAIN_NEUTRAL_ACTIVE` | Local report/ledger foundation; token-anchor and external observation subobjects are `BITCOIN_MIGRATION_BOUNDARY`, not established external consensus. |
| Root `src/lib.rs`, root Solana dependencies in `Cargo.toml`, `tests/runtime_validation.rs`, `tests/fractal_key_submit_e2e.rs` | `SOLANA_V1_FROZEN` | PDA/account layouts, instructions, challenge lifecycle, rent/clock rules and runtime tests. |
| `crates/aura_submission_client_v1`, `packages/aura_submission_client_v1_ts`, `crates/aura_reference_demo_v1`, `crates/aura_sdk_v1/src/settlement.rs` | `SOLANA_V1_FROZEN` | RPC, transaction construction/signing, Solana addresses, commitment configuration; not portable by renaming. |
| `crates/aura_cli_v1` | `BITCOIN_MIGRATION_BOUNDARY` | Mixed UDOT/notarization and Solana `submit.rs`/`settle.rs`/proof/intent producers. Keep frozen commands; future routing belongs outside core math. |
| `crates/aura_notarization_export_v1`, `aura_notarization_render_v1`, `aura_notarization_export_service_v1`, `aura_notarization_workflow_v1`, `aura_notarization_workbench_v1` | `CHAIN_NEUTRAL_ACTIVE` | Manifests connect local execution and downstream receipt/render/export surfaces, not Solana RPC. Frozen summary DTOs remain compatibility obligations. |
| Rust legacy exports in `crates/aura_intent_lineage_v1/src/lib.rs`, `aura_hash_v1.rs`, DCM/cat-map and lineage compatibility modules; `packages/aura_sdk_v1_ts/src/legacy/index.ts`; UDOT `legacy_v1.rs`; `fixtures/layer4_v1` | `LEGACY_COMPATIBILITY` | Legacy namespace and registry HASH_V1 exclusion; fixtures retain old encodings. Existence does not make them active root authority. |
| `crates/aura_intent_lineage_research_v1` | `RESEARCH_ONLY` | README and module names explicitly identify EMA/network/dodecahedral research overlays. |
| `crates/aura_proof_material_v2`, `crates/aura_verifier_adapter_v2` | `RESEARCH_ONLY` | Staged off-chain boundaries; both `src/lib.rs` files deliberately `compile_error!` on `active_integration`. V2 name does not imply active support. |
| `third_party/solana-client-1.18.26` | `SOLANA_V1_FROZEN` | Root Cargo patch and `AURA_PATCH_NOTES.md`; vendored dependency is build material, not Aura math. Metadata/provenance hygiene is separate. |
| `fixtures/v1`, `fixtures/l2_*`, `packages/test_support` | `FROZEN_CORE` baseline evidence | Preserve all existing vectors during audit/migration preparation, even contradictory ones. Envelope fixtures are specifically `STALE_OR_CONTRADICTORY` relative to owner docs/Rust (F04). |
| `docs/authoritative` | Per-document authority; contradictory portions `STALE_OR_CONTRADICTORY` | Registry membership is intact, not a blanket correctness certificate. Details in §6. |
| `tasks/CURRENT_TASK.md`, alignment claims in `reports/AURA_CANONICAL_ALIGNMENT_FIX_V1.md` | `STALE_OR_CONTRADICTORY` | Obsolete architecture task/missing inputs; “100% canonical alignment” contradicted by current source. |
| `docs/research_assets`, `docs/whitepaper_assets` | `RESEARCH_ONLY` | Outside registry. Publication outputs within them are also `GENERATED_ARTIFACT`; no PDF content authority inferred. |
| `build/whitepaper_final_fixed`, generated report JSON/TXT, `target/` | `GENERATED_ARTIFACT` | Build script/output naming and Git inventory; target is ignored local build output. |
| 35 tracked `.DS_Store` files | `REPO_HYGIENE` | `git ls-files '*DS_Store'`; ignored pattern does not untrack existing entries. |

## 4. Solana dependency map

**Direct dependencies:** root `Cargo.toml:26–31` uses `solana-program`, `solana-program-test`, `solana-sdk` at 1.18.26; `crates/aura_submission_client_v1/Cargo.toml` uses `solana-client`, `solana-sdk` and program-test; `crates/aura_reference_demo_v1/Cargo.toml` uses `solana-sdk`. `Cargo.lock` and root `[patch.crates-io]` preserve the dependency graph. The `1.18.26` manifest strings are Cargo version requirements; reproducibility additionally depends on the lockfile.

**No dependency does not mean chain-neutral semantics:** SDK manifests do not import Solana, yet `authorization.rs:28–41` fixes base58 submitter/challenge binding types; `pipeline.rs:38–51` takes program/submitter/challenge keys plus RPC/commitment; `proof.rs:5–9` even re-exports Solana settlement. `lib.rs:148–173` and `aura_fractal_key_integration_v1/src/lib.rs:13–14,42–53` feed challenge-account bytes into the supposedly general proof reference. Changing those bytes changes `proof_hash` even when proof material is identical.

**Wire and fixture leakage:** `fixtures/v1/canonical_prepare/{subject_pubkey,challenge_account_pubkey}.hex`; all four JSON files in `fixtures/v1/canonical_pipeline_v1`; TS `index.ts:187–300`; Rust `submission.rs`, `authorization.rs`, `proof.rs`, `settlement.rs`. The owning authorization document itself requires Solana-style subject/freshness strings; this is not merely a stale implementation detail. `AURA_BUILD_SOURCE_OF_TRUTH.md` explicitly includes `SolanaSettlementRequestWireV1` in its active boundary.

**Transport:** Rust submission client imports `RpcClient`, `Pubkey`, `Keypair`, `Transaction`, system program and clock. TS submission client implements `ProgramDerivedAddress`, `proof-record`, `SUBMIT_PROOF_TAG_V1 = 2`, clock sysvar, Ed25519 signing and legacy-message serialization directly (`src/index.ts:1–80`). A package.json-only audit would miss this handwritten Solana implementation.

**On-chain state:** `src/lib.rs:23–24,70–322,484–705` defines config/challenge/proof-record PDAs, versioned account bytes, subject matching, one-use challenge, expiry via `Clock::unix_timestamp`, rent-exempt account creation and the stored `[u8;32]` proof hash. `process_submit_proof` records the supplied commitment; it does not verify the Storm witness or a STARK. Solana rent is not the local burn ledger.

**Weaker portability concern, not proven Solana exclusivity:** `aura_l2_local_chain_v0/src/lib.rs:894–908` includes `observed_slot`, wallet strings and caller-supplied external balance observations. “Slot” is a chain-shaped observation field, but this alone does not prove a Solana-specific implementation. Its `Local/Bridged` and `Local/External` modes are not Bitcoin headers, UTXOs, inclusion proofs or reorg handling.

## 5. Canonical wire parity matrix

Abbreviations below are exact repository prefixes: **D** = `docs/authoritative/`; **R** = `crates/aura_intent_lineage_v1/`; **S** = `crates/aura_sdk_v1/`; **T** = `packages/aura_sdk_v1_ts/`; **L** = `crates/aura_l2_local_chain_v0/`; **T0** = `packages/aura_sdk_v0_ts/`. Test names resolve under each prefix's `tests/` unless `src/` is stated. **H** = `scripts/validate_storm_hash_quantum_hardening_v1.sh`; **A** = `scripts/verify_active_foundation.sh`; **U** = `scripts/test_udot_parity.sh`; **P** = `scripts/run_canonical_pipeline_v1.sh`; **V** = `scripts/verify_repo_truth.sh`. Script references describe static reachability, not a full execution result.

| Object | Authoritative specification | Rust | TypeScript | Fixture | Tests | Verification script / verdict |
|---|---|---|---|---|---|---|
| Canonical ingestion | D CIL §§3–7; HASH_V2 §4 | R `src/aura_hash_v1.rs:57–107`: NFC/LF, UTF-8/BOM checks, u64 LE frame | T `src/auraHashV1.ts`: corresponding normalization, fatal UTF-8 decoding | `fixtures/v1/aura_text_canonicalization_profile_v1/canonical_text_profile_v1.json` | R/T `aura_text_canonicalization_profile_v1` | H invokes both. Byte utilities agree; CIL V1/V2 handoff prose conflicts; generic strict CIL object parsing is not established by these utility tests (F01). |
| H_521 / HASH_V2 | D root §1; HASH_V2 §5; DERIVATION_FUNCTIONS | R `src/storm_hash521_v1.rs:20` direct SHA3-512 reduction | T `src/stormHash521V1.ts:32` same | Storm vector supplies indirect outputs; no separate root-to-settlement H_521 identity fixture established | R `storm_hash521_v1.rs`; T `src/stormHash521V1.test.ts` | H selects parity/hardening, not every hash unit/integration test. Root formula agrees; parameter-derivation owner disagrees (F02). |
| MESSAGE_ROOT | D root §1.2; CIL §7; HASH_V1 historical | R legacy `aura_hash_v1` computes SHA-256(domain + length + bytes); direct hash helper has no message framing | T `auraHashV1.ts` legacy equivalent; direct helper unframed | `fixtures/v1/aura_hash_v1/canonical_message_hash_v1.json` pins legacy identity | R/T `aura_hash_v1` | H explicitly locks `MESSAGE_ROOT = HASH_V1(message_bytes)`, not current root specification (F01,F15). |
| Storm recurrence | D STORM_RECURSION; root §§2–3.5; DERIVATION_FUNCTIONS | R `src/storm_execution_v1.rs:77–145` derives side-based initial state and context-based a/b | T `src/stormExecutionV1.ts` same | `fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json` | R `storm_execution_v1`, `storm_parity_v1`; T src execution test and parity test | H parity agrees with current implementation; root initialization/constants disagree (F02–F03). |
| Storm context | D STORM_RECURSION input contract | R `src/storm_context_v1.rs`: 209 bytes, version 1, domain digest at 33..65 | T `src/stormContextV1.ts` | Same Storm vector | R `storm_context_v1`; T src context test | H indirect parity. Byte layout/domain agree; root fixed textual context does not (F03). |
| Storm state/claim | D TRACE_LAYOUT, PROVER_BINDING, STARK_SPEC | R `src/storm_state_v1.rs`; `storm_claim_v1.rs:40–51` includes two legacy hashes | T `src/stormStateV1.ts`, `stormClaimV1.ts`; wire in index | Storm vector and canonical envelope JSON | R `storm_claim_v1`; T src claim test, parity | H indirect. State widths agree; claim retains legacy material despite no-parallel-representation doctrine (F04,F11). |
| TRACE_ROOT | D TRACE_COMMITMENT; TRACE_LAYOUT | R `src/storm_trace_commitment_v1.rs` ordered SHA3-256, duplicate-last | T `src/stormTraceCommitmentV1.ts` same | Storm vector `trace_root`; envelope `trace_root_hex` | R `storm_trace_commitment_v1`; T src trace test | H indirect plus hardening. Inspected core rules aligned; not interchangeable with legacy DCM roots or local SHA-256 commitments. |
| STARK public inputs | D PROVER_BINDING nine fields | R `storm_claim_v1.rs:55`, `storm_air_v1.rs:16`: 402-byte compact encoding; separate L2 `aura_l2_public_input_v1/src/lib.rs` 13 fields/284 bytes | T `stormClaimV1.ts` compact binding; T0 local bridge | Storm vector; `fixtures/l2_proof_vectors_v1` | R `storm_claim_v1`, `stark_real_v1`; local public-input/prover/verifier tests | H/A cover different families. Similar names do not establish same proof statement (F10–F11). |
| StarkProofEnvelopeV1 | D STARK_SPEC: version/session/proof_hash/storm_claim only | S `src/proof.rs:56–63`: version/session/dcm_claim/authorization | T `src/index.ts:259–264`: version/session/storm_claim/legacy_dcm_claim/authorization | `fixtures/v1/canonical_pipeline_v1/stark_proof_envelope_v1.json` matches TS | S `stark_proof_envelope_v1`, `prepared_proof_pipeline_v1`; T canonical/prepared tests | U/A: separate tests pass; three-way schema disagreement (F04). |
| Proof hash / proof material | D ARTIFACT_STRUCTURE; root §16 | `aura_proof_material_v1/src/lib.rs:75–124`, `aura_fractal_key_v1/src/lib.rs`: SHA-256, fixed 32-byte components | T `index.ts:1289–1426`: same | `fixtures/v1/canonical_prepare/*` | `aura_proof_material_v1/tests/proof_material_v1.rs`; S/T prepared tests | U indirect. Implementations/fixtures agree; SHA3-512 docs do not (F07). |
| Authorization lineage | D AUTHORIZATION_LINEAGE: proof reference + six-field lineage, no submit object | S `authorization.rs:50–57` nests submit, no top-level proof hash | T `index.ts:1047–1078` same | `authorization_intent_v1.json`; `fixtures/layer4_v1` is compatibility | S `authorization_intent_v1`; T canonical test | U indirect. Six binding fields agree, envelope conflicts with owner (F05). |
| Submit-proof request | No dedicated authoritative owner field list; references in pipeline/lineage docs | S `submission.rs`: program/submitter/challenge/proof_hash/wallet_visual | T index submit generators/validators same | `submit_proof_request_v1.json` | S/T `submit_request_producer_v1`; S canonical test | U. Shared frozen Solana wire; presentation and chain keys in request, absent from pipeline stage map (F13). |
| UDOT | D UDOT_SPEC, ARTIFACT_STRUCTURE | `aura_udot_v2/src/v2.rs:23–45`; S `udot.rs` versioned wrappers | T `index.ts:2644–2665`, bundle validators | `fixtures/v1/udot_v1/test_vectors.json` | `aura_udot_v2/tests/udot_v2.rs`; S/T UDOT tests | U. Alphabet/seal hashes align; raw-nibble matrix and wrapper fields contradict docs (F08–F09). |
| Artifact derivation | D ARTIFACT_STRUCTURE five stages vs root §16 | S `lib.rs:148–185` creates proof material/FractalKey from caller-supplied bytes | T index preparation functions | `canonical_prepare/*` | S/T prepared tests | U. No root `P→M→K→H→Φ` implementation in named owner surfaces; preparation does not verify a proof (F07,F10,F13). |
| Burn/accounting | D LEDGER_AND_BURN formula and terminal rules | L `src/lib.rs:3296–3307,3534–3605,4918` calculates/validates/debits local ledger | T0 parses report/derivation inputs and invokes Rust | `fixtures/l2_canonical_pipeline_v1/accepted_*_expected_report.json` | L inline tests at 8392+, T0 `src/index.test.ts` | P/A. Formula and accepted pins align; malformed preflight/SDK errors do not universally burn (F14). |
| Continuous settlement | D CONTINUOUS_SETTLEMENT: prior_head + report, derived linkage, fixed stateless mode | L `lib.rs:879–883,1522–1526,5315–5385` accepts head fields, checks against persistence | T0 `index.ts:2122–2135` accepts same fields | `fixtures/l2_canonical_pipeline_v1/continuous_chain_v1/*` | L inline head/replay tests; T0 tests | P/A. Tests deliberately exercise supposedly unrepresentable mismatch; owner contradicts behavior (F12). |
| Settlement request | D REPORT_CONTRACT: version/RPC/commitment/proof_hash, no null | S `settlement.rs:55–63,93–115`: nested envelope, explicit nullable RPC | T `index.ts:276–280,1178–1200` nested envelope and nullable RPC | `solana_settlement_request_v1.json` | S `settlement_request_v1`, canonical test; T canonical test | U/A indirect. Matching old outer shape; nested proof differs; current owner not implemented (F06). |
| Root Solana program | Registry frozen implementation context; no complete account/instruction authority document in current set | `src/lib.rs` exact account/instruction codec and submit handler | TS submission client encodes transaction/instruction, not program execution | SDK submit fixture is input; no separate root account golden fixture established | `tests/runtime_validation.rs`, `tests/fractal_key_submit_e2e.rs`; client tests | V runtime stage. Frozen commitment recording, not proof verification or Bitcoin support (F16). |

## 6. Documentation authority and drift findings

### F01 — P0: Identity handoff is internally contradictory

CIL §2 still says `AURA_HASH_V1` is the sole identity function, while its header and §7 require V2. Its §7 hashes length-prefixed bytes without a named domain; root §1.2 specifies `H_521(domain || length || m)`. HASH_V2 §4 prohibits additional prefixes. The root does not supply the concrete message domain there. The implemented direct helper is unframed; the only explicit legacy message preimage helper is `AURA_HASH_V1 || u64_le(len) || message` (`R/src/aura_hash_v1.rs:96–124`). This prevents asserting a single exact implemented MESSAGE_ROOT contract. Preserve normalization; resolve identity ownership and framing before adding any new settlement consumer.

### F02 — P0: Parameter derivation specification does not describe current code

`AURA_DERIVATION_FUNCTIONS_V1.md` explicitly retains `SHA3-512(msg||0)` plus nine bits of `SHA3-512(msg||1)` for parameters. Both `storm_hash521_v1.rs:20–23` and `stormHash521V1.ts` use one unsuffixed SHA3-512 and field reduction. `storm_execution_v1.rs` calls that helper for all six parameter families. The fixtures and passing TS parity test pin the current direct-hash behavior. Restoring the two-digest formula would change Storm semantics and must not be smuggled into a documentation or Bitcoin adapter pass.

### F03 — P0: Root initialization and constants differ from implementation

Root §§2,3.5 require `x0=MESSAGE_ROOT`, `y0=SHA3-512(x0||"init")`, global a/b/seed and `context="AURA_V2_CANONICAL"`. The subordinate derivation document and code use separate 110-byte side inputs, context-derived a/b and a 209-byte structured context. The root does not give numeric a/b/seed values. Matching the quadratic recurrence alone does not establish root conformance.

The root also claims every state has exactly one predecessor. For fixed step injection, `(x,y)` and `(-x,-y)` produce the same quadratic next state, generally two distinct predecessors in this odd-characteristic field. This is an internal mathematical contradiction, not a request to alter the recurrence. Root §7 also opens an unclosed text fence, making later normative text render as code. HASH_V2 and CIL contain extensively escaped Markdown headings.

### F04 — P0: Three incompatible STARK envelope contracts

The field sets in §5 are exact, not cosmetic naming differences. Rust's `#[serde(deny_unknown_fields)]` rejects the fixture's `storm_claim` and `legacy_dcm_claim`; TS's strict key list rejects Rust's `dcm_claim`. Both omit the top-level `proof_hash_hex` demanded by the owner. TS explicitly calls `ensureStormLegacyCompatibilityV1`, while the owner says no parallel claims or equivalence checks exist. Do not regenerate fixtures to conceal this split.

### F05 — P0: Authorization embeds a forbidden Solana submit request

The six lineage fields agree across SDKs, including intent commitment equality, subject and freshness binding. But the owner forbids `submit_proof_request` and requires `proof_hash_hex`; both SDKs and the fixture do the reverse (`S/src/authorization.rs:50–57`, `T/src/index.ts:1047–1078`). The validators enforce equality to nested submitter/challenge keys, so flattening is a binding/API change, not a text-only cleanup.

### F06 — P0: Settlement is nested and nullable

`AURA_REPORT_CONTRACT_V1.md` forbids embedded proof/authorization and null RPC. Rust `Option<String>` with explicit-option deserialization accepts present null; its normalizer returns `Ok(None)`. TS also accepts an explicit null. Both require explicit field presence, which is weaker than the document's non-null rule. Neither emits the required top-level proof reference. The registry's reference-only settlement also conflicts with the root §8 settlement containing message root, trace root, proof, burn and lineage, and HASH_V2 §10's optional export hash.

### F07 — P0: Artifact primitive, width and construction disagree

The artifact document specifies SHA3-512 component hashes, material hash and FractalKey hash. Implemented frozen V1 uses SHA-256 throughout, with 32-byte fields and canonical serialized domain/version/type bytes. The preparation fixtures use 64 hex characters. SHA3-512 yields 64 bytes, yet REPORT_CONTRACT requires 64 hex characters and UDOT accepts 32 bytes: the current specifications are internally width-inconsistent even before comparing code.

Root §16's `P→SHA3-512(P)→SHA3-512(M||context)→SHA3-512(K)→Φ(H)` is a third construction; Φ is not concretely encoded there. No such sequence is implemented in the named SDK preparation surfaces. `ProofMaterialV1::canonical_bytes` already includes its domain; a future correction must avoid accidentally double-prefixing it when interpreting document formulas.

### F08 — P1: UDOT matrix algorithm contradicts its owner

The owner requires hashing `AURA_UDOT_MATRIX_V1 || proof_hash` before matrix glyph selection. Rust `derive_wallet_sequence_v1` and TS `deriveUdotV2` map the original hash nibbles directly. This supports the tested reversible wallet visual. Seal-line and crest hashing and the 16-glyph alphabet agree. Changing the matrix to match the prose would break wallet identity and existing vectors.

### F09 — P1: The documented canonical UDOT bundle is not the SDK wrapper

Owner fields are `proof_hash_hex, seal_line, crest, matrix_sequence`, with no version or matrix rendering. Rust `UdotArtifactBundleWireV1` and TS bundle types instead carry `udot_version`, `aura_hash_hex`, and v2 `matrix_form`, and support legacy v1. The preparation function returns proof material/FractalKey/hash, not a demonstrated single canonical `UdotBundleV2` stage. A compatibility wrapper may be legitimate, but the documentation must identify it as such rather than claim the existing wire is the new bundle.

### F10 — P0: Proof terminology exceeds the actual active proof boundary

`R/src/stark_prover_v1.rs:4–16,332–398` constructs active Storm proof bytes from claim plus full witness. `stark_verifier_v1.rs` decodes, recomputes and validates those bytes. Its module documentation expressly disclaims in-AIR SHA3. The same files retain scaffold openings and an actual Winterfell cat-map backend. Separately, `aura_l2_prover_v1/src/lib.rs:1–15` documents a Winterfell transfer STARK with host-side witness/commitment validation and algebraic backend coverage.

These are three different proof claims. Root §§5–6's fixed-AIR STARK description is not established for the active nonlinear Storm path. SDK envelope validation is yet another operation: `S/src/proof.rs:87–104` validates shape/state bytes and nested authorization, not a STARK. `prepare_submit_proof_flow_v1` verifies hashes against the same supplied bytes, not proof soundness. No migration should treat a valid envelope or a prepared hash as a cryptographically verified transition.

### F11 — P1: Canonical claim still includes legacy commitments

`StormClaim521V1` serializes `legacy_commitment_root` and `legacy_trace_commitment` (`storm_claim_v1.rs:40–51,207–219`); TS claim/wire and fixture retain them. Compact nine-field public inputs omit them, although full proof bytes bind a larger claim. The owner gives no complete claim byte-layout accounting for those fields. Removing them changes serialized claim/proof bytes. This is a version boundary, not dead-field removal.

### F12 — P0: Continuous head contract contradicts implementation and fixtures

The document accepts only prior head plus settlement report and fixes `stateless_non_authoritative`. Rust and TS parse caller-supplied previous hash and sequence. Rust has `AuthoritativePersistent` and `StatelessNonAuthoritative` modes (`L/src/lib.rs:301–304`); its mismatch checker compares requested fields against persisted state and genesis. The continuous fixtures explicitly test head mismatch/replay. Preserve existing local behavior; document or version any changed constructor separately.

### F13 — P1: “Exactly one pipeline” does not describe the callable SDK flow

The pipeline document orders material hash/proof hash/UDOT/authorization before Storm/trace/proof. Root §7 orders message/Storm/trace/proof before artifact/settlement. SDK preparation consumes proof bytes up front; `S/src/pipeline.rs:61–115` then constructs submit → authorization → DCM envelope → settlement and returns four nested/duplicated objects. It does not execute a Storm trace or invoke a prover. Local canonical reports are a separate execution/attestation pipeline. The submit request itself lacks a dedicated authoritative wire owner despite fixtures and strict validators.

### F14 — P1: “Full burn on every deviation” overstates enforcement

The local formula is implemented with checked arithmetic and matches the documented coefficients; accepted execution/attestation report fixtures pin consumed burn (for example 49 units for the accepted execution fixture). However preflight rejects an incorrect declared fee or insufficient payer balance (`L/src/lib.rs:3296–3307`), JSON parsing can fail before ledger construction, and SDK shape validators have no ledger parameter or debit operation. Root/pipeline/report documents' universal burn-on-malformed-input language is not implemented universally. Local accounting units and `PendingExternalAnchor`/`future_token_binding_units` are not evidence of a real token burn or Bitcoin fee payment.

### F15 — P0: Repository-truth checks do not establish semantic truth

`tests/repository_hardening.rs` checks file membership, phrases, selected links and absence of machine paths in a small document subset. It does not parse normative field lists, compare hash preimages, or compare Rust/TS serialization. H simultaneously locks the prose “HASH_V2 sole active identity” and the legacy `MESSAGE_ROOT=HASH_V1` strings. This is a concrete example of contradiction surviving textual locks.

U runs Rust prepared-pipeline tests that round-trip Rust's current object, and TS tests that pin the TS fixture, without exchanging the same envelope between languages. A runs local foundation tests and selected TS tests; it does not run the entire lineage crate's unit/integration suite. Root default tests are also not workspace-wide. Green selected tests therefore prove only their stated local assertions.

### F16 — P1: Frozen Solana implementation is underdocumented in current authority set

The root source and runtime tests define account layouts, instruction tags, PDA seed order, clock and rent rules. None of the 25 authoritative documents is a complete Solana account/instruction contract. REPORT_CONTRACT's “only proof_hash on-chain” is at most a statement about proof material: `ProofRecord` also stores submitter, challenge and metadata. The handler records an opaque hash, not proof verification. Preserve code/tests as frozen implementation evidence and explicitly separate their role from general protocol authority.

### F17 — P2: Stale task, metadata and success reports

`tasks/CURRENT_TASK.md` asks for a four-layer DCM-root realignment and references missing `docs/AURA_CORE_STACK_V1.md`, `FOUNDATION_BASELINE_V1.md`, and L2 scope/model/rules files. Its supporting header does not make that task current. `AURA_CANONICAL_ALIGNMENT_FIX_V1.md` claims all blockers resolved and 100% alignment, contradicted by F01–F16. The local-chain manifest still advertises “explicit mock proving” although source supports STARK too. README calls verification “what CI runs,” but no tracked `.github` workflow was found; external CI configuration was not verified. Historical reports remain evidence of previous claims, not current acceptance results.

## 7. Rust/TypeScript parity findings

Positive evidence is deliberately narrow: direct H_521, quadratic recurrence, context layout, state serialization, SHA3-256 trace commitment, SHA-256 prepared references, six-field lineage contents and current reversible wallet visuals have corresponding implementations and tests. This does not certify every integer boundary or proof consumer.

The principal cross-language failure is the STARK wire (F04), inherited by outer settlement. Both SDKs independently agree on old authorization and settlement nesting while disagreeing with docs. TS v0 uses JavaScript numbers for local head/request integers and validation; Rust uses u64. Do not assume full-u64 JSON interoperability without explicit upper-bound vectors. Text BOM diagnostic positions use Rust byte offsets (`char_indices`) versus TS UTF-16 indices (`indexOf`); equivalent rejection need not yield identical numerical diagnostic offsets after non-ASCII prefixes.

The SDKs' strict unknown-key checks are valuable, but they make their incompatible schemas decisively incompatible. There is no safe inference that a Rust envelope can be consumed by TS simply because both are called V1.

## 8. Fixture/test coverage gaps and checks performed

### Bounded checks actually executed

| Command | Observed result |
|---|---|
| `git ls-remote origin refs/heads/main` | Remote main matched audited HEAD. |
| `node --test packages/aura_sdk_v1_ts/tests/canonical_pipeline_v1.test.ts` | 4 passed, 0 failed. |
| `node --test packages/aura_sdk_v1_ts/src/stormHash521V1.test.ts packages/aura_sdk_v1_ts/tests/storm_parity_v1.test.ts packages/aura_sdk_v1_ts/tests/prepared_proof_pipeline_v1.test.ts` | 7 passed, 0 failed. |
| `cargo test -p aura_sdk_v1 --offline --locked --test stark_proof_envelope_v1 --test prepared_proof_pipeline_v1` | 6 passed, 0 failed (3 in each target). |
| Tracked-file publication SHA-256 comparison | Seven exact duplicate SVG pairs; no inference that differently named PDFs are byte-identical. |

Node was `v22.22.2`. Cargo used the existing toolchain/cache and local build output. Full V/A/U/H/P verification was **not** run; this report makes no full-green claim. Tests were diagnostic evidence, not protocol edits.

Required future verification improvements, grounded in current omissions:

1. Exchange the identical full JSON fixtures in both directions between Rust and TS, including proof/authorization/settlement; compare exact keys, values and failure acceptance, not separate language round trips.
2. Add independent known-answer vectors for direct H_521 and the separately adjudicated parameter derivation. Current Rust `hash521_single_sha3_construction` only checks field validity, which cannot distinguish one digest from another valid-field construction.
3. Pin a complete CIL → MESSAGE_ROOT → Storm initializer transition, with exact domain/length ownership. Current legacy hash and Storm-side-input fixtures do not establish that connection.
4. Give each actual proof family its own accepted statement/backend/public-input fixture and negative tests; distinguish full-witness replay from cryptographic STARK verification and SDK shape validation.
5. Cover doc-required reference-only field rejection, null rejection, legacy-field rejection and absence of embedded upstream objects. Current tests intentionally assert some of the opposite shapes.
6. Define exact hash widths and domain preimages in machine-readable golden vectors before any successor API. Do not accept regenerated expected values without independent review.
7. Test early input failures separately from terminal reports with burn. Match wording to what can actually be charged.
8. Test head constructor ownership and persistent versus stateless modes against the chosen contract; current mismatch fixtures validate the old behavior.
9. Include link/anchor checks, generated-file provenance, tracked-hygiene checks, and authority-content checks. Neither phrase locks nor warning gates detect these contradictions.

## 9. Repository hygiene findings

### F18 — P2: Tracked OS metadata

35 tracked `.DS_Store` files span root, `build`, `docs`, `fixtures`, `packages` and 25 crate directories. Examples: `.DS_Store`, `docs/.DS_Store`, `crates/aura_sdk_v1/.DS_Store`, `packages/aura_sdk_v1_ts/.DS_Store`. `.gitignore` already contains `.DS_Store`; existing tracked files remain tracked. Remove only in a future hygiene pass, preserving the user's existing modifications in this audit.

### F19 — P2: Publication duplication and misleading generated-report policy

Seven exact byte-identical SVG pairs exist between `docs/whitepaper_assets/` and `build/whitepaper_final_fixed/assets/`: `eq_binding_tuple.svg`, `eq_cat_map_matrix.svg`, `eq_cat_map_recurrence.svg`, `fig_cat_map_transform.svg`, `fig_proof_verification_flow.svg`, `fig_system_pipeline.svg`, `fig_trace_commitment.svg`.

`docs/research_assets/` contains final/fixed PDFs, HTML, TEX and Markdown; `build/whitepaper_final_fixed/` contains another Markdown/TEX/HTML output set. These are duplicated publication surfaces, not proven identical documents. `scripts/build_aura_whitepaper.py:9–17` writes root Markdown/HTML/TEX as well as build copies, whereas tracked publication files now also live under research assets. Its title/keywords still describe cat-map and Solana material. Running it can reintroduce obsolete root publications; it was not run.

`reports/README.md` says JSON and LAST_RUN are gitignored. `git ls-files reports` proves the four JSON research outputs and `reports/LAST_RUN.md` are tracked; `.gitignore` has no corresponding report rule. The README also broadly describes verification regeneration without establishing a generator for each report. Keep handwritten audit reports distinct from generated numeric evidence.

### F20 — P2: Vendored patch provenance needs preservation, not deletion

`third_party/solana-client-1.18.26/AURA_PATCH_NOTES.md` documents the narrow `collect::<Result<_>>()?` → `collect::<Result<()>>()?` warning fix in `src/send_and_confirm_transactions_in_parallel.rs`. Its header links to a missing doctrine and its body contains an obsolete `/Users/mcrae/Desktop/AURA/Cargo.toml` path. `.cargo-ok`, `.cargo_vcs_info.json`, normalized `Cargo.toml` and `Cargo.toml.orig` are tracked. Keep vendor provenance and functional patch until Solana is isolated and reproducible builds no longer need it; distinguish registry metadata from source-of-truth docs. An upstream byte-diff was not performed, so the note is evidence of the documented patch, not certification that it is the only difference.

## 10. Bitcoin migration boundary

The smallest defensible boundary is **after an explicitly verified, versioned Aura result and before chain-specific publication/observation**. That boundary is a recommendation, not an implemented interface. Existing local verification, state transition, report and ledger machinery can supply inputs, subject to the proof-scope limitations above.

A successor contract must explicitly decide which existing commitment it references, its width/preimage, proof family, authorization identity, freshness/replay domain and local-versus-external acceptance meaning. These cannot be inferred from `SolanaSettlementRequestWireV1`, generic `external` fixtures or a renamed challenge pubkey. Preserve existing cryptographic outputs and put any new chain binding in a separately versioned adapter contract.

Bitcoin-specific decisions remain outstanding: anchoring mechanism, transaction/UTXO lifecycle, fee policy, signing boundary, confirmation/reorg handling, network identifier and proof/commitment availability. This audit selects none of them. A Bitcoin publication must not be described as Bitcoin consensus verifying Aura computation unless that behavior is actually designed, implemented and tested. Local burn accounting is likewise not Bitcoin miner fees or a Bitcoin burn transaction.

## 11. Ordered P0/P1/P2/P3 work queue

| Order | Priority | Bounded work | Acceptance condition |
|---|---|---|---|
| 1 | P0 | Adjudicate F01–F03 and F07 owner conflicts; record current bytes separately from intended semantics | Exact identity, initialization, parameter/hash-width and artifact ownership decisions, without changing existing vectors. |
| 2 | P0 | Record/resolve F04–F06 and F12 under explicit version policy | One approved successor wire/head contract; old V1 decoding obligations identified. |
| 3 | P0 | Correct proof capability claims and inventory F10–F11 proof families | Each path names its verified statement, host checks, backend and limitations. |
| 4 | P0 | Close F15 verification blind spots | Shared bidirectional wire tests and independent primitive vectors expose current drift; no silent fixture replacement. |
| 5 | P1 | Separate portable verified-result interface from Solana consumer | Core output bytes unchanged; old Solana runtime/client tests remain valid. |
| 6 | P1 | Define new authorization/freshness/publication contract, including F08–F09/F13–F14 presentation and burn boundaries | No Solana account assumptions inside newly chain-neutral contract; old reference derivation preserved. |
| 7 | P2 | Repair stale links/task/metadata/reports and tracked hygiene (F17–F20) | Registry links valid, provenance documented, no tracked OS metadata, intentional generated-output policy. |
| 8 | P3 | Implement Bitcoin adapter only after prior contracts are accepted | Bounded network tests demonstrate the chosen anchoring and observation behavior; no inference from local acceptance. |
| 9 | P3 | Add operational recovery/reorg/fee/availability checks before broader rollout | Documented failure/retry behavior and reproducible tests; no changes to frozen cryptography. |

P0 here means migration-blocking architectural truth, not an assertion of an exploitable production vulnerability.

## 12. Recommended bounded implementation passes

1. **Truth reconciliation only.** Update authority/status/capability documentation and an exact wire/hash manifest. Explicitly record unresolved protocol decisions instead of choosing mathematical behavior through editorial changes. Preserve all v1 code and fixtures. Exit: an internally consistent description of implemented versus intended behavior.
2. **Verification contracts only.** Add bidirectional fixture consumption and independent known-answer assertions. Existing disagreements should remain visible until consciously resolved. Exit: each required matrix row has an owner, byte contract and named gate; accepted historical fixtures remain preserved.
3. **Versioned boundary isolation.** Introduce only the agreed portable result/authorization boundary and isolate old Solana adapter/tooling. Keep old wire behavior available; do not rewrite hashes, AIR or ledger semantics to make tests green. Exit: portable path can build/test without requiring Solana transport, while frozen Solana tests remain independently runnable.
4. **Bitcoin contract and adapter.** First fix the anchoring/confirmation/reorg/signing contract, then implement it as one bounded external adapter using preserved Aura references. Exit: controlled-network acceptance/rejection tests for the exact chosen behavior. No change to Aura core math.
5. **Operational readiness.** Add recovery/observation/availability tests and update user-facing commands/docs based on demonstrated behavior. Hygiene/publication cleanup can proceed separately after pass 1; it is not a prerequisite for inventing new protocol semantics.

These are ordered future passes, not work authorized or implemented by this report. If a decision in pass 1 requires changing cryptography, it is a separate versioned protocol effort, not part of the settlement migration sequence.

## 13. Explicit non-goals

- No Bitcoin settlement, anchoring implementation, network transaction or deployment.
- No protocol redesign, new hash construction, new AIR, new proof system or security guarantee.
- No mutation of frozen recurrence, field encoding, transcript, commitment, reference, glyph or account semantics.
- No silent schema repair, fixture regeneration, report-history rewriting or dependency upgrade.
- No deletion of Solana, legacy, research, generated or hygiene files in this pass.
- No claim that current selected test passes imply canonical conformance, full-suite success, production readiness, zero knowledge, Bitcoin verification or on-chain burn.

## 14. Files that MUST NOT be modified until a later migration phase

During truth reconciliation and Bitcoin boundary preparation, keep these files byte/behavior-stable:

- Root `src/lib.rs`, `tests/runtime_validation.rs`, `tests/fractal_key_submit_e2e.rs`; Solana dependencies/patch in `Cargo.toml`, `Cargo.lock`, `third_party/solana-client-1.18.26/**` until isolated-build verification justifies changes.
- `crates/aura_intent_lineage_v1/src/field_521_v1.rs`, `storm_hash521_v1.rs`, `storm_execution_v1.rs`, `storm_context_v1.rs`, `storm_state_v1.rs`, `storm_trace_commitment_v1.rs`, `storm_claim_v1.rs`, `storm_air_v1.rs`, `stark_prover_v1.rs`, `stark_verifier_v1.rs`, `proof_transcript_v1.rs`, `stark_trace_commitment_v1.rs`, and retained DCM/AIR/session binding implementations.
- TS counterpart `packages/aura_sdk_v1_ts/src/storm*.ts`, session/encryption primitives, and cryptographic/reference derivation portions of `src/index.ts`.
- `crates/aura_proof_material_v1/src/lib.rs`, `crates/aura_fractal_key_v1/src/lib.rs`, `crates/aura_fractal_key_integration_v1/src/lib.rs`, `crates/aura_udot_v2/src/**`.
- Existing SDK V1 wires in `crates/aura_sdk_v1/src/{proof,authorization,submission,settlement,pipeline,udot}.rs` and corresponding TS interfaces/validators until an explicit version/compatibility decision. Their contradictions are not permission to change them in place.
- `crates/aura_l2_public_input_v1/src/lib.rs`, local execution/trace/prover/verifier/settlement implementations, and local ledger/head hash derivation in `crates/aura_l2_local_chain_v0/src/lib.rs` until separately scoped contract changes are approved.
- All existing files under `fixtures/v1/`, `fixtures/layer4_v1/`, `fixtures/l2_local_v1/`, `fixtures/l2_proof_vectors_v1/`, `fixtures/l2_canonical_pipeline_v1/`. Add new versioned evidence later; never overwrite old vectors to hide drift.

The only repository deliverable created by this audit is this report. The findings preserve disagreements for review rather than resolving them implicitly.
