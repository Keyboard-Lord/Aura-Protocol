# aura_intent_lineage_v1

Classification: `IMPLEMENTATION`

This crate implements the active lower-layer surfaces mapped by:

- [docs/authoritative/l0/AURA_HASH_V1_AND_CANONICAL_MESSAGE_SPEC_V1.md](../../docs/authoritative/l0/AURA_HASH_V1_AND_CANONICAL_MESSAGE_SPEC_V1.md)
- [docs/authoritative/l0/AURA_TEXT_CANONICALIZATION_PROFILE_V1.md](../../docs/authoritative/l0/AURA_TEXT_CANONICALIZATION_PROFILE_V1.md)
- [docs/authoritative/l1/AURA_STORM_RECURSION_ENGINE_V1_1.md](../../docs/authoritative/l1/AURA_STORM_RECURSION_ENGINE_V1_1.md)

Implemented scope:

- `HASH_V1`
- text canonicalization
- storm context validation
- storm recurrence
- `TRACE_ROOT`
- storm claim validation
- session-encryption bindings used by the validation surface

This crate does not define the canonical L2 proof envelope or the L3 pipeline wrapper by itself.

Research remains isolated in `crates/aura_intent_lineage_research_v1`.
