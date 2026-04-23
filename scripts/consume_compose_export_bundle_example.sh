#!/usr/bin/env bash

set -euo pipefail

# SUPPORTING_NON_AUTHORITY:
# This helper consumes the frozen notarization export bundle surface only.
# It is not part of the canonical repository verification spine.

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

bundle_path="${1:-}"
output_dir="${2:-/tmp/aura-compose-export-consumer}"

if [[ -z "$bundle_path" ]]; then
  echo "usage: $0 <compose-export-bundle.json> [output-dir]" >&2
  exit 1
fi

mkdir -p "$output_dir"

notarization_record_path="$output_dir/notarization-record.json"
receipt_markdown_path="$output_dir/receipt.md"
receipt_html_path="$output_dir/receipt.html"

cat <<EOF
Supporting frozen notarization consumer path:
- accept the compose export bundle JSON as input
- treat the bundle as immutable within the frozen notarization surface
- consume notarization_record, receipt_markdown, and receipt_html directly
- do not reinterpret this helper as active-system authority
EOF

jq -e '
  (keys | sort) == [
    "compose_request",
    "notarization_record",
    "public_statement",
    "receipt_html",
    "receipt_markdown",
    "transaction"
  ]
' "$bundle_path" >/dev/null

jq -c '.notarization_record' "$bundle_path" > "$notarization_record_path"
jq -r '.receipt_markdown' "$bundle_path" > "$receipt_markdown_path"
jq -r '.receipt_html' "$bundle_path" > "$receipt_html_path"

printf '\nWrote frozen notarization consumer artifacts:\n'
printf '  %s\n' "$notarization_record_path"
printf '  %s\n' "$receipt_markdown_path"
printf '  %s\n' "$receipt_html_path"
