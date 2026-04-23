#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib/warning_gate.sh"

target_dir="${TMPDIR:-/tmp}"
target_dir="${target_dir%/}/aura_active_foundation_target"

# Node.js >= 22.0.0 must be available in PATH
# Install via official Node.js distribution or version manager (nvm, fnm, etc.)

printf 'Aura active foundation verifier\n'
printf 'Repo root: %s\n' "$repo_root"
printf 'Cargo target dir: %s\n' "$target_dir"

printf '\n[1/11] Structural execution crate tests\n'
run_with_warning_gate cargo test -p aura_l2_execution_v1 --target-dir "$target_dir" --offline

printf '\n[2/11] Public-input contract tests\n'
run_with_warning_gate cargo test -p aura_l2_public_input_v1 --target-dir "$target_dir" --offline

printf '\n[3/11] Trace-builder tests\n'
run_with_warning_gate cargo test -p aura_l2_trace_builder_v1 --target-dir "$target_dir" --offline

printf '\n[4/11] Prover tests\n'
run_with_warning_gate cargo test -p aura_l2_prover_v1 --target-dir "$target_dir" --offline

printf '\n[5/11] Verifier tests\n'
run_with_warning_gate cargo test -p aura_l2_verifier_v1 --target-dir "$target_dir" --offline

printf '\n[6/11] Local-settlement tests\n'
run_with_warning_gate cargo test -p aura_l2_local_settlement_v1 --target-dir "$target_dir" --offline

printf '\n[7/11] Local-chain integration tests\n'
run_with_warning_gate cargo test -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline

printf '\n[8/11] Canonical pipeline exact runner with execution, attestation, burn, accounting, and ledger pins\n'
bash scripts/run_canonical_pipeline_v1.sh

printf '\n[9/11] TypeScript SDK v0 canonical bridge tests\n'
run_with_warning_gate node --test packages/aura_sdk_v0_ts/src/index.test.ts packages/aura_sdk_v0_ts/src/cat_map_fixture_v1.test.ts

printf '\n[10/11] TypeScript SDK v1 canonical pipeline object tests\n'
run_with_warning_gate npm test --prefix packages/aura_sdk_v1_ts -- tests/canonical_pipeline_v1.test.ts tests/prepared_proof_pipeline_v1.test.ts

printf '\n[11/11] Storm hash + message-root hardening invariants\n'
bash scripts/validate_storm_hash_quantum_hardening_v1.sh

printf '\nAura active foundation verification passed.\n'
