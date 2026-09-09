#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${BITCOIND:?Set BITCOIND to a Bitcoin Core executable for the repository integration gate}"
node scripts/verify_bitcoin_boundary_v1.mjs
bash scripts/verify_active_foundation.sh
bash scripts/test_udot_parity.sh
BITCOIND="$BITCOIND" node scripts/verify_bitcoin_regtest_v1.mjs
printf 'Aura repository integration checks passed; protocol completion still requires the documented acceptance audit.\n'
