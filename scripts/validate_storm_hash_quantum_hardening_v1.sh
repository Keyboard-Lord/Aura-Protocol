#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib/warning_gate.sh"

target_dir="${TMPDIR:-/tmp}"
target_dir="${target_dir%/}/aura_storm_hash_quantum_hardening_target"
source_of_truth_document_path="$repo_root/docs/authoritative/AURA_BUILD_SOURCE_OF_TRUTH.md"
hardening_log_document_path="$repo_root/docs/authoritative/AURA_HARDENING_LOG_V1.md"
message_hash_document_path="$repo_root/docs/authoritative/AURA_HASH_V1.md"

if [[ -f "${HOME}/.zshrc" ]]; then
  source "${HOME}/.zshrc"
fi

current_validation_stage=''
current_failure_classification=''

classify_failure() {
  printf 'Invariant failure classification: %s\n' "$current_failure_classification" >&2
}

block_progress() {
  printf 'Progress blocked at validation stage: %s\n' "$current_validation_stage" >&2
}

harden() {
  printf '%s\n' \
    'Required hardening: patch the failing surface, add or tighten the regression, and rerun before reopening progress.' >&2
}

lock_invariant() {
  printf '%s\n' \
    'Invariant lock requirement: keep the failure encoded as a test, validator rejection, or frozen fixture contract.' >&2
}

invariant_violation() {
  classify_failure
  block_progress
  harden
  lock_invariant
  exit 1
}

run_invariant_stage() {
  local stage_ordinal="$1"
  current_validation_stage="$2"
  current_failure_classification="$3"
  shift 3

  printf '\n[%s] %s\n' "$stage_ordinal" "$current_validation_stage"
  if ! "$@"; then
    invariant_violation
  fi
}

ensure_source_of_truth_lock_v1() {
  grep -Fq 'There is exactly one canonical pipeline.' "$source_of_truth_document_path"
  grep -Fq 'The canonical documentation set is exactly the 25 files under `docs/authoritative/`.' "$source_of_truth_document_path"
  grep -Fq 'No file outside `docs/authoritative/` defines:' "$source_of_truth_document_path"
}

ensure_hardening_log_lock_v1() {
  grep -Fq '`LOCK-01`: `HASH_V2` is the sole active canonical identity function (521-bit SHA3-512-based). `HASH_V1` is FROZEN LEGACY.' "$hardening_log_document_path"
  grep -Fq '`LOCK-02`: Text normalization is NFC + LF with BOM rejection only.' "$hardening_log_document_path"
  grep -Fq '`LOCK-04`: `TRACE_ROOT` uses ordered SHA3-256 Merkle reduction with duplicate-last odd-level handling.' "$hardening_log_document_path"
  grep -Fq '`LOCK-08`: Canonical UDOT is v2-only, derived directly from `proof_hash_hex`, and carries no `aura_hash_hex` alias or canonical `matrix_form`.' "$hardening_log_document_path"
}

ensure_canonical_message_encoding_document_v1() {
  grep -Fq 'MESSAGE_ROOT = HASH_V1(message_bytes)' "$message_hash_document_path"
  grep -Fq '`canonical_message_bytes_v1 = u64_le(len(message_bytes)) || message_bytes`' "$message_hash_document_path"
  grep -Fq '`HASH_V1(message_bytes) = SHA-256("AURA_HASH_V1" || canonical_message_bytes_v1)`' "$message_hash_document_path"
  grep -Fq 'Text mode is exact:' "$message_hash_document_path"
}

ensure_aura_hash_v1_is_the_only_identity_surface_v1() {
  ! rg -n 'pub fn canonical_text_message_|pub fn aura_hash_text_|export function canonicalTextMessage|export function auraHashText' \
    "$repo_root/crates/aura_intent_lineage_v1/src" \
    "$repo_root/packages/aura_sdk_v1_ts/src"
}

run_message_root_invariants_v1() {
  run_with_warning_gate \
    cargo test -p aura_intent_lineage_v1 --target-dir "$target_dir" --offline --test aura_hash_v1 -- --nocapture
  run_with_warning_gate \
    npm test --prefix packages/aura_sdk_v1_ts -- tests/aura_hash_v1.test.ts
}

run_text_profile_invariants_v1() {
  run_with_warning_gate \
    cargo test -p aura_intent_lineage_v1 --target-dir "$target_dir" --offline --test aura_text_canonicalization_profile_v1 -- --nocapture
  run_with_warning_gate \
    npm test --prefix packages/aura_sdk_v1_ts -- tests/aura_text_canonicalization_profile_v1.test.ts
}

printf 'Aura storm hash + message-root hardening validation\n'
printf 'Repo root: %s\n' "$repo_root"
printf 'Cargo target dir: %s\n' "$target_dir"

run_invariant_stage '1/10' \
  'Canonical source-of-truth lock' \
  'source_of_truth_document_drift' \
  ensure_source_of_truth_lock_v1

run_invariant_stage '2/10' \
  'Hardening log lock' \
  'hardening_log_drift' \
  ensure_hardening_log_lock_v1

run_invariant_stage '3/10' \
  'Canonical message encoding contract lock' \
  'canonical_message_encoding_contract_drift' \
  ensure_canonical_message_encoding_document_v1

run_invariant_stage '4/10' \
  'Sole canonical identity surface lock' \
  'non_hash_layer_framing_or_hash_surface_drift' \
  ensure_aura_hash_v1_is_the_only_identity_surface_v1

run_invariant_stage '5/10' \
  'Canonical message encoding + hash root invariants' \
  'canonical_message_encoding_or_hash_root_violation' \
  run_message_root_invariants_v1

run_invariant_stage '6/10' \
  'Text canonicalization profile invariants' \
  'text_canonicalization_profile_violation' \
  run_text_profile_invariants_v1

run_invariant_stage '7/10' \
  'Frozen storm parity fixtures' \
  'storm_fixture_parity_or_contract_drift' \
  run_with_warning_gate \
  cargo test -p aura_intent_lineage_v1 --target-dir "$target_dir" --offline --test storm_parity_v1 -- --nocapture

run_invariant_stage '8/10' \
  'Frozen storm-bound session encryption fixtures' \
  'storm_bound_session_binding_or_fixture_drift' \
  run_with_warning_gate \
  cargo test -p aura_intent_lineage_v1 --target-dir "$target_dir" --offline --test session_encryption_v1 -- --nocapture

run_invariant_stage '9/10' \
  'Storm hash + recurrence hardening invariants' \
  'storm_hash_recurrence_or_trace_invariant_violation' \
  run_with_warning_gate \
  cargo test -p aura_intent_lineage_v1 --target-dir "$target_dir" --offline --test storm_hash_quantum_hardening_v1 -- --nocapture

run_invariant_stage '10/10' \
  'TypeScript parity + hardening invariants' \
  'cross_language_parity_or_sdk_binding_violation' \
  run_with_warning_gate npm test --prefix packages/aura_sdk_v1_ts -- \
  src/stormExecutionV1.test.ts \
  src/stormClaimV1.test.ts \
  tests/storm_parity_v1.test.ts \
  tests/session_encryption_v1.test.ts \
  tests/storm_hash_quantum_hardening_v1.test.ts

printf '\nAura storm hash + message-root hardening validation passed.\n'
