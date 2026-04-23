#!/usr/bin/env bash

set -euo pipefail

# SUPPORTING_NON_AUTHORITY:
# This helper exercises the frozen notarization export bundle surface only.
# It is not part of the canonical repository verification spine.

base_url="${AURA_WORKBENCH_URL:-http://127.0.0.1:8787}"
output_dir="${1:-/tmp/aura-compose-export-handoff}"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

mkdir -p "$output_dir"

compose_request_path="$output_dir/compose-request.json"
bundle_path="$output_dir/compose-export-bundle.json"
notarization_record_path="$output_dir/notarization-record.json"
receipt_markdown_path="$output_dir/receipt.md"
receipt_html_path="$output_dir/receipt.html"

cat <<EOF
Supporting frozen notarization bundle handoff:
- load a valid compose request
- POST it to ${base_url}/api/compose/export
- treat the returned bundle as immutable within the frozen notarization surface
- use notarization_record as the machine-readable artifact
- use receipt_markdown and receipt_html exactly as returned
EOF

curl --fail --silent --show-error \
  "${base_url}/api/compose/sample" \
  > "$compose_request_path"

curl --fail --silent --show-error \
  -X POST \
  -H "Content-Type: application/json" \
  --data-binary "@${compose_request_path}" \
  "${base_url}/api/compose/export" \
  > "$bundle_path"

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

printf '\nWrote frozen notarization handoff artifacts:\n'
printf '  %s\n' "$bundle_path"
printf '  %s\n' "$notarization_record_path"
printf '  %s\n' "$receipt_markdown_path"
printf '  %s\n' "$receipt_html_path"
