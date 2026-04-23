#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib/warning_gate.sh"

target_dir="${TMPDIR:-/tmp}"
target_dir="${target_dir%/}/aura_repo_truth_target"

# Node.js >= 22.0.0 must be available in PATH
# Install via official Node.js distribution or version manager (nvm, fnm, etc.)

printf 'Aura repository truth verifier\n'
printf 'Repo root: %s\n' "$repo_root"
printf 'Cargo target dir: %s\n' "$target_dir"

printf '\n[1/4] Repository hardening invariants\n'
run_with_warning_gate \
  cargo test -p aura_protocol --target-dir "$target_dir" --offline --test repository_hardening

printf '\n[2/4] Frozen Solana MVP runtime tests\n'
run_with_warning_gate \
  env RUST_LOG='warn,tarpc::client=error,tarpc::server=error' \
  cargo test -p aura_protocol --target-dir "$target_dir" --offline --test runtime_validation --test fractal_key_submit_e2e

printf '\n[3/4] Active local proving foundation\n'
bash scripts/verify_active_foundation.sh

printf '\n[4/4] Frozen v1 UDOT/SDK/CLI parity\n'
bash scripts/test_udot_parity.sh

printf '\nAura repository truth verification passed.\n'
