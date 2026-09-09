#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test -p aura_udot_v2 --offline --test udot_v2
cargo test -p aura_sdk_v1 --offline --test udot_bundle_v2
cargo test -p aura_sdk_v1 --offline --test udot_sdk_v1
node --test packages/aura_sdk_v1_ts/tests/udot_bundle_v2.test.ts packages/aura_sdk_v1_ts/tests/udot_sdk_v1_ts.test.ts
printf 'UDOT core and Rust/TypeScript SDK parity passed.\n'
