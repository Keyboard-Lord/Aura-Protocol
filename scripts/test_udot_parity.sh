#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib/warning_gate.sh"

fixture_path="fixtures/v1/udot_v1/test_vectors.json"
tmp_root="${TMPDIR:-/tmp}"
target_dir="${tmp_root%/}/aura_udot_parity_target"

printf 'UDOT parity fixture: %s\n' "$fixture_path"
printf 'UDOT parity Cargo target dir: %s\n' "$target_dir"

# Node.js >= 22.0.0 must be available in PATH
# Install via official Node.js distribution or version manager (nvm, fnm, etc.)

printf '\n[1/7] Rust core fixture-backed UDOT tests\n'
run_with_warning_gate cargo test -p aura_udot_v2 --target-dir "$target_dir" --offline --test udot_v2

printf '\n[2/7] Rust SDK prepared-proof submission bridge parity\n'
run_with_warning_gate cargo test -p aura_sdk_v1 --target-dir "$target_dir" --offline --test submit_request_producer_v1

printf '\n[3/7] Rust SDK prepared-proof full-pipeline parity\n'
run_with_warning_gate cargo test -p aura_sdk_v1 --target-dir "$target_dir" --offline --test prepared_proof_pipeline_v1

printf '\n[4/7] Rust SDK fixture-backed UDOT tests\n'
run_with_warning_gate cargo test -p aura_sdk_v1 --target-dir "$target_dir" --offline --test udot_sdk_v1

printf '\n[5/7] Rust CLI fixture-backed UDOT tests\n'
run_with_warning_gate cargo test -p aura_cli_v1 --target-dir "$target_dir" --offline --test udot_cli_v1

printf '\n[6/7] TypeScript SDK prepared-proof submission bridge and full-pipeline parity\n'
run_with_warning_gate node --test \
  packages/aura_sdk_v1_ts/tests/submit_request_producer_v1.test.ts \
  packages/aura_sdk_v1_ts/tests/prepared_proof_pipeline_v1.test.ts \
  packages/aura_sdk_v1_ts/tests/canonical_pipeline_v1.test.ts

printf '\n[7/7] TypeScript SDK fixture-backed UDOT tests\n'
run_with_warning_gate node --test packages/aura_sdk_v1_ts/tests/udot_sdk_v1_ts.test.ts

printf '\nUDOT and prepared-proof producer parity suites passed.\n'
