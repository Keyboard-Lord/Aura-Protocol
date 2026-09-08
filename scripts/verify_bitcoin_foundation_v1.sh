#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test -p aura_bitcoin_v1 --offline
node --test packages/aura_bitcoin_v1_ts/tests/*.test.ts
cargo test -p aura_sdk_v1 --offline --test authorization_v2
node --test packages/aura_sdk_v1_ts/tests/authorization_v2.test.ts
# Network integration is explicit: BITCOIND=/path/to/bitcoind node scripts/verify_bitcoin_regtest_v1.mjs
