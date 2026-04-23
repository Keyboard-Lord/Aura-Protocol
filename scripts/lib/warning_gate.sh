#!/usr/bin/env bash

# Reject warning drift in canonical verifier output. Active verifier commands are
# expected to stay warning-clean; any warning-like output fails closed.

run_with_warning_gate() {
  local raw_output

  raw_output="$(mktemp "${TMPDIR:-/tmp}/aura_warning_gate_raw.XXXXXX")"

  if ! "$@" >"$raw_output" 2>&1; then
    cat "$raw_output"
    rm -f "$raw_output"
    return 1
  fi

  cat "$raw_output"

  if grep -Eq '(^warning:| WARN |^\(node:[0-9]+\) (ExperimentalWarning|DeprecationWarning|Warning):)' "$raw_output"; then
    echo "warning gate rejected command: $*" >&2
    rm -f "$raw_output"
    return 1
  fi

  rm -f "$raw_output"
}
