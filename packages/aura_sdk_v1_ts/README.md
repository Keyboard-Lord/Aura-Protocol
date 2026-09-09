# aura_sdk_v1_ts

Classification: `IMPLEMENTATION METADATA`

The package root exposes the active Storm, proof-material and authorization helpers:

- `prepareBoundProofMaterialV1`: existing material and FractalKey bytes and hashes.
- `generateUdotBundleV2` / `validateUdotBundleV2`: fixed four-field presentation.
- BIP340 Authorization V2 signing, signature and material checks.
- Existing Storm execution, claim and public-input helpers.

Actual proof verification and durable authorization acceptance are owned by the
Rust SDK. Bitcoin transport is owned by `packages/aura_bitcoin_v1_ts`. A signature
or TypeScript material check alone does not establish accepted authorization.

Versioned UDOT wrappers, old authorization intents, nested proof/settlement
envelopes and account-oriented preparation aliases require the explicit `legacy`
namespace. They preserve historical fixtures and do not enter canonical V2 admission.

Authority lives in:

- [docs/authoritative/AURA_STARK_SPEC_V1.md](../../docs/authoritative/AURA_STARK_SPEC_V1.md)
- [docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md](../../docs/authoritative/AURA_CANONICAL_PIPELINE_V1.md)
- [docs/authoritative/AURA_REPORT_CONTRACT_V1.md](../../docs/authoritative/AURA_REPORT_CONTRACT_V1.md)
- [docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md](../../docs/authoritative/AURA_AUTHORIZATION_LINEAGE_V1.md)
- [docs/authoritative/AURA_UDOT_SPEC_V1.md](../../docs/authoritative/AURA_UDOT_SPEC_V1.md)
