#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/scripts/lib/warning_gate.sh"

target_dir="${TMPDIR:-/tmp}"
target_dir="${target_dir%/}/aura_canonical_pipeline_target"

request_path="fixtures/l2_canonical_pipeline_v1/accepted_transfer_request.json"
expected_path="fixtures/l2_canonical_pipeline_v1/accepted_transfer_expected_report.json"
attestation_request_path="fixtures/l2_canonical_pipeline_v1/accepted_attestation_request.json"
attestation_expected_path="fixtures/l2_canonical_pipeline_v1/accepted_attestation_expected_report.json"
tampered_attestation_request_path="fixtures/l2_canonical_pipeline_v1/tampered_attestation_request.json"
accepted_stark_attestation_request_path="fixtures/l2_canonical_pipeline_v1/accepted_stark_attestation_request.json"
tampered_stark_attestation_request_path="fixtures/l2_canonical_pipeline_v1/tampered_stark_attestation_request.json"
external_anchor_mismatch_request_path="fixtures/l2_canonical_pipeline_v1/external_anchor_mismatch_request.json"
external_anchor_disconnected_request_path="fixtures/l2_canonical_pipeline_v1/external_anchor_disconnected_request.json"
continuous_chain_dir="fixtures/l2_canonical_pipeline_v1/continuous_chain_v1"

printf 'Aura canonical pipeline runner\n'
printf 'Repo root: %s\n' "$repo_root"
printf 'Cargo target dir: %s\n' "$target_dir"
printf 'Request fixture: %s\n' "$request_path"

request_text="$(<"$request_path")"
if [[ "$request_text" != *'"economic_policy_version": 1'* ]]; then
  echo "canonical request fixture must pin economic_policy_version 1" >&2
  exit 1
fi
if [[ "$request_text" != *'"accounting_policy_version": 1'* ]]; then
  echo "canonical request fixture must pin accounting_policy_version 1" >&2
  exit 1
fi
if [[ "$request_text" != *'"ledger_policy_version": 1'* ]]; then
  echo "canonical request fixture must pin ledger_policy_version 1" >&2
  exit 1
fi
if [[ "$request_text" != *'"declared_fee_units": 49'* ]]; then
  echo "canonical request fixture must pin the accepted execution burn units" >&2
  exit 1
fi
if [[ "$request_text" != *'"payer_account_id_hex": "1111111111111111111111111111111111111111111111111111111111111111"'* ]]; then
  echo "canonical request fixture must pin the payer ledger account" >&2
  exit 1
fi

actual_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$request_path"
)"
expected_output="$(<"$expected_path")"

if [[ "$expected_output" != *'"burn_policy_version":1'* ]]; then
  echo "expected canonical report must pin burn_policy_version 1" >&2
  exit 1
fi
if [[ "$expected_output" != *'"accounting_policy_version":1'* ]]; then
  echo "expected canonical report must pin accounting_policy_version 1" >&2
  exit 1
fi
if [[ "$expected_output" != *'"ledger_policy_version":1'* ]]; then
  echo "expected canonical report must pin ledger_policy_version 1" >&2
  exit 1
fi
if [[ "$expected_output" != *'"computed_burn_units":49'* ]]; then
  echo "expected canonical report must pin the accepted execution burn units" >&2
  exit 1
fi
if [[ "$expected_output" != *'"consumed_burn_units":49'* ]]; then
  echo "expected canonical report must pin the consumed execution burn units" >&2
  exit 1
fi
if [[ "$expected_output" != *'"truth_artifact_kind":"execution_report"'* ]]; then
  echo "expected canonical report must pin the execution truth artifact kind" >&2
  exit 1
fi
if [[ "$expected_output" != *'"settlement_status":"accepted"'* ]]; then
  echo "expected canonical report must pin the accepted settlement status" >&2
  exit 1
fi
if [[ "$expected_output" != *'"ledger_account_count":2'* ]]; then
  echo "expected canonical report must pin the ledger account count" >&2
  exit 1
fi
if [[ "$expected_output" != *'"burned_supply_after":49'* ]]; then
  echo "expected canonical report must pin the ledger burned supply transition" >&2
  exit 1
fi
if [[ "$expected_output" != *'"future_token_binding_units":49'* ]]; then
  echo "expected canonical report must pin the future token anchor units" >&2
  exit 1
fi
if [[ "$expected_output" != *'"account_id_hex":"1111111111111111111111111111111111111111111111111111111111111111"'* ]]; then
  echo "expected canonical report must pin the burn payer account" >&2
  exit 1
fi

if [[ "$actual_output" != "$expected_output" ]]; then
  actual_file="$(mktemp "${TMPDIR:-/tmp}/aura_canonical_pipeline_actual.XXXXXX")"
  expected_file="$(mktemp "${TMPDIR:-/tmp}/aura_canonical_pipeline_expected.XXXXXX")"
  trap 'rm -f "$actual_file" "$expected_file"' EXIT
  printf '%s' "$actual_output" >"$actual_file"
  printf '%s' "$expected_output" >"$expected_file"
  diff -u "$expected_file" "$actual_file" || true
  echo "canonical pipeline output drifted from the pinned expected report" >&2
  exit 1
fi

attestation_request_text="$(<"$attestation_request_path")"
if [[ "$attestation_request_text" != *'"attestation_schema_version": 2'* ]]; then
  echo "canonical attestation request fixture must pin attestation_schema_version 2" >&2
  exit 1
fi
if [[ "$attestation_request_text" != *'"normalization_policy_version": 1'* ]]; then
  echo "canonical attestation request fixture must pin normalization_policy_version 1" >&2
  exit 1
fi
if [[ "$attestation_request_text" != *'"claim_kind": "normalized_json_field_equals_utf8"'* ]]; then
  echo "canonical attestation request fixture must pin the supported claim kind" >&2
  exit 1
fi
if [[ "$attestation_request_text" != *'"evidence_kind": "inline_json_utf8"'* ]]; then
  echo "canonical attestation request fixture must pin the supported evidence kind" >&2
  exit 1
fi
if [[ "$attestation_request_text" != *'"declared_fee_units": 48'* ]]; then
  echo "canonical attestation request fixture must pin the accepted attestation burn units" >&2
  exit 1
fi

attestation_actual_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$attestation_request_path"
)"
attestation_expected_output="$(<"$attestation_expected_path")"

if [[ "$attestation_expected_output" != *'"attestation_schema_version":2'* ]]; then
  echo "expected attestation report must pin attestation_schema_version 2" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"normalization_policy_version":1'* ]]; then
  echo "expected attestation report must pin normalization_policy_version 1" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"claim_kind":"normalized_json_field_equals_utf8"'* ]]; then
  echo "expected attestation report must pin the supported claim kind" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"evidence_kind":"inline_json_utf8"'* ]]; then
  echo "expected attestation report must pin the supported evidence kind" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"normalized_form":"canonical_json_utf8"'* ]]; then
  echo "expected attestation report must pin the supported normalization form" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"attestation_status":"accepted"'* ]]; then
  echo "expected attestation report must pin the accepted attestation status" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"reason":"none"'* ]]; then
  echo "expected attestation report must pin the accepted attestation failure reason" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"computed_burn_units":48'* ]]; then
  echo "expected attestation report must pin the accepted attestation burn units" >&2
  exit 1
fi
if [[ "$attestation_expected_output" != *'"relation":"normalized_json_field_equals_utf8"'* ]]; then
  echo "expected attestation report must pin the attestation consistency relation" >&2
  exit 1
fi

if [[ "$attestation_actual_output" != "$attestation_expected_output" ]]; then
  actual_file="$(mktemp "${TMPDIR:-/tmp}/aura_canonical_attestation_actual.XXXXXX")"
  expected_file="$(mktemp "${TMPDIR:-/tmp}/aura_canonical_attestation_expected.XXXXXX")"
  trap 'rm -f "$actual_file" "$expected_file"' EXIT
  printf '%s' "$attestation_actual_output" >"$actual_file"
  printf '%s' "$attestation_expected_output" >"$expected_file"
  diff -u "$expected_file" "$actual_file" || true
  echo "canonical attestation pipeline output drifted from the pinned expected report" >&2
  exit 1
fi

tampered_attestation_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$tampered_attestation_request_path"
)"

if [[ "$tampered_attestation_output" != *'"actual_result":"ExecutionRejected"'* ]]; then
  echo "tampered attestation request must fail closed as ExecutionRejected" >&2
  exit 1
fi
if [[ "$tampered_attestation_output" != *'"consumed_burn_units":48'* ]]; then
  echo "tampered attestation request must still consume the deterministic burn" >&2
  exit 1
fi
if [[ "$tampered_attestation_output" != *'"attestation_status":"rejected"'* ]]; then
  echo "tampered attestation request must pin rejected attestation status" >&2
  exit 1
fi
if [[ "$tampered_attestation_output" != *'"reason":"consistency_mismatch"'* ]]; then
  echo "tampered attestation request must pin the consistency mismatch failure reason" >&2
  exit 1
fi
if [[ "$tampered_attestation_output" != *'"settlement_status":"not_run"'* ]]; then
  echo "tampered attestation request must pin the not_run settlement status" >&2
  exit 1
fi

accepted_stark_attestation_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$accepted_stark_attestation_request_path"
)"

if [[ "$accepted_stark_attestation_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "accepted STARK attestation fixture must stay on the canonical pipeline" >&2
  exit 1
fi
if [[ "$accepted_stark_attestation_output" != *'"proof_kind":"STARK"'* ]]; then
  echo "accepted STARK attestation fixture must pin STARK proof_kind" >&2
  exit 1
fi
if [[ "$accepted_stark_attestation_output" != *'"verification_passed":true'* ]]; then
  echo "accepted STARK attestation fixture must pin successful attestation proof verification" >&2
  exit 1
fi

tampered_stark_attestation_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$tampered_stark_attestation_request_path"
)"

if [[ "$tampered_stark_attestation_output" != *'"actual_result":"VerificationRejected"'* ]]; then
  echo "tampered STARK attestation fixture must fail closed as VerificationRejected" >&2
  exit 1
fi
if [[ "$tampered_stark_attestation_output" != *'"failure_reason_code":"attestation_proof_verification_rejected"'* ]]; then
  echo "tampered STARK attestation fixture must pin attestation proof verification rejection" >&2
  exit 1
fi
if [[ "$tampered_stark_attestation_output" != *'"verification_passed":false'* ]]; then
  echo "tampered STARK attestation fixture must pin failed attestation proof verification" >&2
  exit 1
fi

external_anchor_mismatch_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$external_anchor_mismatch_request_path"
)"

if [[ "$external_anchor_mismatch_output" != *'"actual_result":"SettlementRejected"'* ]]; then
  echo "external anchor mismatch fixture must reject at settlement" >&2
  exit 1
fi
if [[ "$external_anchor_mismatch_output" != *'"anchor_verification_status":"rejected"'* ]]; then
  echo "external anchor mismatch fixture must pin rejected anchor verification" >&2
  exit 1
fi

external_anchor_disconnected_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --output json run-canonical-pipeline "$external_anchor_disconnected_request_path"
)"

if [[ "$external_anchor_disconnected_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "disconnected external anchors must remain non-authoritative" >&2
  exit 1
fi
if [[ "$external_anchor_disconnected_output" != *'"anchor_verification_status":"disconnected"'* ]]; then
  echo "disconnected external anchor fixture must pin disconnected verification status" >&2
  exit 1
fi

continuous_head_state_path="$(mktemp "${TMPDIR:-/tmp}/aura_continuous_head.XXXXXX")"
rm -f "$continuous_head_state_path"

continuous_step01_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step01_execution_accept_request.json"
)"
if [[ "$continuous_step01_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step01 must accept under authoritative persistence" >&2
  exit 1
fi
if [[ "$continuous_step01_output" != *'"authority_mode":"authoritative_persistent"'* ]]; then
  echo "continuous chain step01 must pin authoritative_persistent head mode" >&2
  exit 1
fi
head_after_step01="$(<"$continuous_head_state_path")"
if [[ "$head_after_step01" != *'"head_sequence_number": 1'* ]]; then
  echo "continuous chain step01 must persist head_sequence_number 1" >&2
  exit 1
fi

continuous_step02_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step02_head_mismatch_reject_request.json"
)"
if [[ "$continuous_step02_output" != *'"actual_result":"SettlementRejected"'* ]]; then
  echo "continuous chain step02 must reject at settlement" >&2
  exit 1
fi
if [[ "$continuous_step02_output" != *'"failure_reason_code":"settlement_head_mismatch"'* ]]; then
  echo "continuous chain step02 must pin settlement_head_mismatch" >&2
  exit 1
fi
head_after_step02="$(<"$continuous_head_state_path")"
if [[ "$head_after_step02" != "$head_after_step01" ]]; then
  echo "continuous chain step02 must not mutate authoritative head state" >&2
  exit 1
fi

continuous_step03_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step03_execution_accept_request.json"
)"
if [[ "$continuous_step03_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step03 must accept after the head mismatch replay" >&2
  exit 1
fi
head_after_step03="$(<"$continuous_head_state_path")"
if [[ "$head_after_step03" == "$head_after_step02" ]]; then
  echo "continuous chain step03 must advance authoritative head state" >&2
  exit 1
fi
if [[ "$head_after_step03" != *'"head_sequence_number": 2'* ]]; then
  echo "continuous chain step03 must persist head_sequence_number 2" >&2
  exit 1
fi

continuous_step04_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step04_anchor_mismatch_reject_request.json"
)"
if [[ "$continuous_step04_output" != *'"actual_result":"SettlementRejected"'* ]]; then
  echo "continuous chain step04 must reject at settlement" >&2
  exit 1
fi
if [[ "$continuous_step04_output" != *'"failure_reason_code":"settlement_acceptance_rejected"'* ]]; then
  echo "continuous chain step04 must pin settlement_acceptance_rejected" >&2
  exit 1
fi
head_after_step04="$(<"$continuous_head_state_path")"
if [[ "$head_after_step04" == "$head_after_step03" ]]; then
  echo "continuous chain step04 must still advance authoritative head state" >&2
  exit 1
fi
if [[ "$head_after_step04" != *'"head_sequence_number": 3'* ]]; then
  echo "continuous chain step04 must persist head_sequence_number 3" >&2
  exit 1
fi

continuous_step05_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step05_attestation_accept_request.json"
)"
if [[ "$continuous_step05_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step05 must accept the mock attestation request" >&2
  exit 1
fi

continuous_step06_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step06_disconnected_anchor_accept_request.json"
)"
if [[ "$continuous_step06_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step06 must accept with a disconnected external anchor" >&2
  exit 1
fi
if [[ "$continuous_step06_output" != *'"anchor_verification_status":"disconnected"'* ]]; then
  echo "continuous chain step06 must pin disconnected anchor verification" >&2
  exit 1
fi
head_after_step06="$(<"$continuous_head_state_path")"

continuous_step07_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step07_replay_reject_request.json"
)"
if [[ "$continuous_step07_output" != *'"actual_result":"SettlementRejected"'* ]]; then
  echo "continuous chain step07 must reject the replayed request" >&2
  exit 1
fi
if [[ "$continuous_step07_output" != *'"failure_reason_code":"settlement_head_mismatch"'* ]]; then
  echo "continuous chain step07 must pin replay rejection as settlement_head_mismatch" >&2
  exit 1
fi
head_after_step07="$(<"$continuous_head_state_path")"
if [[ "$head_after_step07" != "$head_after_step06" ]]; then
  echo "continuous chain step07 must leave authoritative head unchanged" >&2
  exit 1
fi

continuous_step08_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step08_stark_attestation_accept_request.json"
)"
if [[ "$continuous_step08_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step08 must accept the STARK attestation request" >&2
  exit 1
fi
if [[ "$continuous_step08_output" != *'"proof_kind":"STARK"'* ]]; then
  echo "continuous chain step08 must pin STARK attestation proof kind" >&2
  exit 1
fi

continuous_step09_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step09_attestation_anchor_reject_request.json"
)"
if [[ "$continuous_step09_output" != *'"actual_result":"SettlementRejected"'* ]]; then
  echo "continuous chain step09 must reject at settlement" >&2
  exit 1
fi
if [[ "$continuous_step09_output" != *'"failure_reason_code":"settlement_acceptance_rejected"'* ]]; then
  echo "continuous chain step09 must pin settlement_acceptance_rejected" >&2
  exit 1
fi

continuous_step10_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step10_execution_accept_request.json"
)"
if [[ "$continuous_step10_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step10 must accept the final execution request" >&2
  exit 1
fi

continuous_step11_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step11_tampered_stark_attestation_reject_request.json"
)"
if [[ "$continuous_step11_output" != *'"actual_result":"VerificationRejected"'* ]]; then
  echo "continuous chain step11 must reject tampered STARK attestation at verification" >&2
  exit 1
fi
if [[ "$continuous_step11_output" != *'"failure_reason_code":"attestation_proof_verification_rejected"'* ]]; then
  echo "continuous chain step11 must pin attestation_proof_verification_rejected" >&2
  exit 1
fi
head_after_step11="$(<"$continuous_head_state_path")"
if [[ "$head_after_step11" != *'"head_sequence_number": 9'* ]]; then
  echo "continuous chain step11 must still advance authoritative head state to sequence 9" >&2
  exit 1
fi

continuous_step12_output="$(
  run_with_warning_gate \
    cargo run --quiet -p aura_l2_local_chain_v0 --target-dir "$target_dir" --offline -- \
    --head-state "$continuous_head_state_path" --output json run-canonical-pipeline \
    "$continuous_chain_dir/step12_attestation_accept_request.json"
)"
if [[ "$continuous_step12_output" != *'"actual_result":"Accepted"'* ]]; then
  echo "continuous chain step12 must accept the final attestation request" >&2
  exit 1
fi
final_continuous_head="$(<"$continuous_head_state_path")"
if [[ "$final_continuous_head" != *'"head_sequence_number": 10'* ]]; then
  echo "continuous chain final authoritative head must end at sequence 10" >&2
  exit 1
fi

rm -f "$continuous_head_state_path"

printf 'Aura canonical pipeline outputs match the pinned execution report, attestation report, STARK attestation, external-anchor, and authoritative continuous-head semantics.\n'
