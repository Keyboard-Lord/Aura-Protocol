# Aura

**Classification:** `IMPLEMENTATION METADATA`

Aura is undergoing a Bitcoin migration. The current repository still contains a
Solana program and submission clients. Bitcoin anchor encoding and Core transport
are implemented and regtest-validated. BIP340 authorization now verifies the actual
Storm proof and material binding, durably reserves its nonce, and produces the
Bitcoin anchor request. Legacy SDK pipeline replacement remains unfinished.

## Start here

Read the [document registry](docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md)
first. It owns document membership, precedence, and concept ownership. The canonical documentation set is exactly the 25 files under `docs/authoritative/`.

There is exactly one canonical pipeline. This is the protocol requirement;
current SDK wires and their specifications do not yet agree. The live source and
tests establish implementation state, while the registry defines intended
authority. Passing a fixture test alone does not establish protocol conformance.

## Implementation map

| Surface | Owner / entry point | Current role |
| --- | --- | --- |
| Hash, field, Storm, trace and proof machinery | [aura_intent_lineage_v1](crates/aura_intent_lineage_v1/src/lib.rs) | Preserve cryptographic semantics. The [Storm prover](crates/aura_intent_lineage_v1/src/stark_prover_v1.rs) transports a witness for replay; its retained cat-map STARK is a separate legacy path. |
| Proof material and bound proof reference | [proof material](crates/aura_proof_material_v1/src/lib.rs), [FractalKey](crates/aura_fractal_key_v1/src/lib.rs) | Byte-level construction; the [integration adapter](crates/aura_fractal_key_integration_v1/src/lib.rs) currently supplies Solana subject/challenge account bytes. |
| SDK objects | [Rust SDK](crates/aura_sdk_v1/src/lib.rs), [TypeScript SDK](packages/aura_sdk_v1_ts/src/index.ts) | Preparation and wire validation; proof-envelope parity and reference-only boundary repairs remain outstanding. |
| Bitcoin anchoring | [Rust codec](crates/aura_bitcoin_v1/src/lib.rs), [TypeScript codec](packages/aura_bitcoin_v1_ts/src/index.ts), [Core transport](packages/aura_bitcoin_v1_ts/src/coreRpc.ts) | Approved OP_RETURN anchor, PSBT funding/signing, output checks, and reorg-aware observation. |
| Authorization | [Rust acceptance](crates/aura_sdk_v1/src/authorization.rs), [TypeScript signing](packages/aura_sdk_v1_ts/src/authorizationV2.ts) | BIP340 v2, actual proof/material/lineage verification, durable journal and idempotent retry. |
| Legacy settlement transport | [Rust client](crates/aura_submission_client_v1/src/lib.rs), [TypeScript client](packages/aura_submission_client_v1_ts/src/index.ts), [root program](src/lib.rs) | Solana transaction publication and commitment recording. |
| Local execution and settlement | [local chain](crates/aura_l2_local_chain_v0/src/lib.rs), [local verifier](crates/aura_l2_verifier_v1/src/lib.rs) | Local foundation; local acceptance is not Bitcoin inclusion or confirmation. |
| Presentation | [UDOT](crates/aura_udot_v2/src/lib.rs) | Artifact presentation, separate from settlement transport. |

## Making a change

1. Locate the concept's owning document through the registry and inspect its implementation with targeted `rg` searches.
2. Preserve canonical bytes unless a semantic change is explicitly justified. Keep legacy adapters outside canonical entry and downstream wires reference-only.
3. Run affected Rust and TypeScript tests, including shared fixtures and malformed-input rejection. Do not regenerate a mismatching fixture until the defect's owner is established.
4. Update the owning specification and implementation metadata when behavior is verified. Record remaining discrepancies rather than claiming conformance.

## Validation

Use the toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml) and Node.js
22 or newer. Plain `cargo test` targets the root Solana package, not the complete
workspace. Start with the crate or TypeScript test affected by a change.

| Command | Coverage |
| --- | --- |
| `cargo test -p <affected-crate> --offline` | Selected Rust crate |
| `node --test packages/aura_sdk_v1_ts/tests/<test>.test.ts` | Selected TypeScript regression |
| `bash scripts/verify_bitcoin_foundation_v1.sh` | Shared anchor/authorization vectors, durable replay and Core transport unit tests |
| `BITCOIND=/path/to/bitcoind node scripts/verify_bitcoin_regtest_v1.mjs` | Actual Aura authorization through Bitcoin anchoring, reorg revocation and persistent nonce retry |
| `bash scripts/verify_active_foundation.sh` | Local foundation, pipeline fixtures, and selected SDK/hash checks |
| `bash scripts/test_udot_parity.sh` | Frozen v1 SDK/CLI/UDOT checks |
| `bash scripts/verify_repo_truth.sh` | Broad milestone check, including Solana runtime and the preceding suites |

The verifier scripts' names describe their intended scope, not certification that
all authoritative requirements are satisfied. The active-foundation script does
not run every Rust SDK wire test.

## Supporting material

[Reports](reports/) are evidence or proposals, not protocol authority.
[Research code](crates/aura_intent_lineage_research_v1) and
[research assets](docs/research_assets/) do not define the active protocol.
The [Bitcoin architecture decision](docs/decisions/bitcoin-anchoring.md) is approved.
The report contract owns the anchor wire; the [authorization owner](docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md)
defines the approved BIP340 contract. Retiring the old SDK pipeline remains migration work.
