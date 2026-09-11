# aura_sdk_v1_ts

Classification: `IMPLEMENTATION METADATA`

The package root exposes the active Storm, proof-material and authorization helpers:

- `prepareBoundProofMaterialV1`: existing material and FractalKey bytes and hashes.
- `generateUdotBundleV2` / `validateUdotBundleV2`: fixed four-field presentation.
- BIP340 Authorization V2 signing, signature and material checks.
- Economic W codecs, distinct BIP340 consent signing/pre-admission checks, and settlement head V2 parity helpers in `economicV1.ts`.
- Existing Storm execution, claim and public-input helpers.

Actual proof verification and durable authorization acceptance are owned by the
Rust SDK, including the economic coordinator's atomic debit, recovery, head and
outbox. Bitcoin transport is owned by `packages/aura_bitcoin_v1_ts`. Economic
consent, a signature or a TypeScript material check alone does not establish
accepted authorization. The existing `aura_sdk_v0_ts` meter owner supplies the
strict M codec; economic helpers do not define another metering representation.

The root also exports the approved miner **M2 codec/profile boundary** from
`minerV1.ts`, with [shared Rust/TS frozen evidence](../../fixtures/miner_v1/README.md).
Job signature/policy checks, structural work/claim checks and the low-hash filter
do not grant PoC acceptance, admission, round ownership or rewards. The
[miner design](../../reports/AURA_MINER_PROTOCOL_V1.md) remains approved design
metadata rather than active protocol authority; miner execution is the next slice.

Versioned UDOT wrappers, old authorization intents, nested proof/settlement
envelopes and account-oriented preparation aliases require the explicit `legacy`
namespace. They preserve historical fixtures and do not enter canonical V2 admission.

Authority lives in:

- [docs/authoritative/AURA_STARK_SPEC_V1.md](../../docs/authoritative/AURA_STARK_SPEC_V1.md)
- [docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md](../../docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md)
- [docs/authoritative/AURA_REPORT_CONTRACT_V1.md](../../docs/authoritative/AURA_REPORT_CONTRACT_V1.md)
- [docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md](../../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md)
- [docs/authoritative/AURA_LEDGER_AND_BURN_V1.md](../../docs/authoritative/AURA_LEDGER_AND_BURN_V1.md)
- [docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md](../../docs/authoritative/AURA_CONTINUOUS_SETTLEMENT_V1.md)
- [docs/authoritative/AURA_UDOT_SPEC_V1.md](../../docs/authoritative/AURA_UDOT_SPEC_V1.md)
