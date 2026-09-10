#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test -p aura_bitcoin_v1 --offline
node --test packages/aura_bitcoin_v1_ts/tests/*.test.ts
cargo test -p aura_sdk_v1 --offline --test authorization_v2 --test economic_contract_v1 --test economic_journal_v1
cargo test -p aura_l2_local_chain_v0 --offline --lib economic_meter::tests
# Keep historical core and SDK entry points outside canonical public imports.
cargo test -p aura_intent_lineage_v1 -p aura_sdk_v1 --offline --doc
node --test packages/aura_sdk_v1_ts/tests/authorization_v2.test.ts packages/aura_sdk_v1_ts/src/economicV1.test.ts packages/aura_sdk_v0_ts/src/economic_meter.test.ts
# Network integration is explicit: BITCOIND=/path/to/bitcoind node scripts/verify_bitcoin_regtest_v1.mjs
