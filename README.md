# AURA

**Classification:** `IMPLEMENTATION`

The canonical documentation set is exactly the 25 files under `docs/authoritative/`.
This set contains 20 protocol-definition documents plus 5 supporting/specification documents.

## Quick Start (3 Commands for Reviewers)

```bash
git clone <repository-url> && cd AURA
cargo build --workspace
bash scripts/verify_repo_truth.sh
```

## Start Here

1. **Root Authority:** [docs/authoritative/AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md](docs/authoritative/AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md)
2. **Document Registry:** [docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md](docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md)

## Document Hierarchy

- **ROOT AUTHORITY (1):** `AURA_SINGLE_PATH_COMMITMENT_SYSTEM_V2.md` — Complete protocol spec
- **ACTIVE AUTHORITY (15):** Core protocol layer documents (L0-L5)
- **VALIDATION (4):** Invariants, failure classes, test registry, hardening log
- **FROZEN LEGACY (1):** `AURA_HASH_V1.md` — Historical V1 identity

## Quick Navigation

- Identity: [AURA_HASH_V2.md](docs/authoritative/AURA_HASH_V2.md)
- Field: [AURA_FIELD_ARITHMETIC_V1.md](docs/authoritative/AURA_FIELD_ARITHMETIC_V1.md)
- Storm: [AURA_STORM_RECURSION_V1_1.md](docs/authoritative/AURA_STORM_RECURSION_V1_1.md)
- Pipeline: [AURA_CANONICAL_PIPELINE_V1.md](docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md)
- Settlement: [AURA_REPORT_CONTRACT_V1.md](docs/authoritative/AURA_REPORT_CONTRACT_V1.md)

There is exactly one canonical pipeline.

## Canonical Verification Path

For protocol verification, run these in order:

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `bash scripts/verify_repo_truth.sh` | Full repository hardening and invariant verification |
| 2 | `bash scripts/run_canonical_pipeline_v1.sh` | Canonical pipeline fixture execution with pin verification |
| 3 | `cat reports/AURA_MANUAL_PIPELINE_WALK_V1.md` | Human-readable pipeline walkthrough output |

## Active Implementation Surfaces

**Core Protocol (Frozen v1):**
- [crates/aura_intent_lineage_v1](crates/aura_intent_lineage_v1) — HASH_V2, STORM_V1_1, trace commitment
- [crates/aura_sdk_v1](crates/aura_sdk_v1) — Rust SDK for proof-preparation flow
- [packages/aura_sdk_v1_ts](packages/aura_sdk_v1_ts) — TypeScript SDK for canonical pipeline

**L2 Local Chain (Active Foundation):**
- [crates/aura_l2_local_chain_v0](crates/aura_l2_local_chain_v0) — Local proving foundation
- [crates/aura_l2_execution_v1](crates/aura_l2_execution_v1) — Execution engine
- [crates/aura_l2_verifier_v1](crates/aura_l2_verifier_v1) — STARK proof verification
- [fixtures/l2_canonical_pipeline_v1](fixtures/l2_canonical_pipeline_v1) — Canonical pipeline fixtures

## Research / Non-Authority

- [crates/aura_intent_lineage_research_v1](crates/aura_intent_lineage_research_v1) — Research overlay, does not define protocol
- [reports/](reports/) — Generated verification reports (non-authoritative)

## Building from Source

Prerequisites:

1. **Rust** — Version automatically managed via `rust-toolchain.toml` (currently 1.88.0)
2. **Node.js** — >= 22.0.0 (specified in package.json engines)

Full verification (what CI runs):

```bash
# Build the workspace
cargo build --workspace

# Run the full verification suite
bash scripts/verify_repo_truth.sh
```

The verification script runs:
- Repository hardening invariants
- Frozen Solana MVP runtime tests
- Active local proving foundation tests
- Frozen v1 UDOT/SDK/CLI parity tests
