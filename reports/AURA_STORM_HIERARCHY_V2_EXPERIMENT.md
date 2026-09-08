# Experimental hierarchical Storm V2

**EXPERIMENTAL / NON-AUTHORITATIVE — 2026-09-08**

This overlay preserves the existing Storm V1 execution, row bytes, claims and
`TRACE_ROOT`. It introduces no canonical external wire and changes no proof material,
FractalKey, proof reference, authorization, Bitcoin, settlement or ledger behavior.
The implementation is research-facing through Rust's `storm_hierarchy_v2` module
and a direct TypeScript `stormHierarchyV2.ts` import; it is not a canonical SDK stage.

## Data flow

`V1 micro recurrence → epoch boundary → macro recurrence → epoch commitment → hierarchy root`

The macro update and epoch commitment both consume the completed epoch. The
commitment does not include the macro state; the macro recurrence does not consume
the epoch commitment. The ordering above describes processing, not an extra hash
or feedback dependency.

The existing V1 trace supplies `iteration_count + 1` state rows. Epoch k covers
transitions `[64k, min(64k + 64, iteration_count))` and includes both endpoint rows.
Adjacent epochs share exactly one boundary row. Counts 0, 1, 63, 64, 65, 128 and 129
produce 1, 1, 1, 1, 2, 2 and 3 epochs respectively. Zero transitions produce one
single-row epoch and one macro update. No empty hierarchy is accepted.

Each epoch reuses the V1 row encoder and V1 ordered SHA3-256 trace Merkle tree.
Its commitment is SHA3-256 over the exact concatenation:

```
"AURA_STORM_EPOCH_COMMITMENT_V2"
|| u64_le(epoch_index) || u64_le(start_step) || u64_le(transition_count)
|| initial_state_row || final_state_row || epoch_trace_root
```

Rows contain the two existing 66-byte big-endian field encodings. The commitment
is 32 bytes; there is no normalization, sorting, padding, or optional field.

Fixed constants are derived once:

```
alpha = AURA_HASH521_V1("AURA_STORM_MACRO_ALPHA_V2")
beta  = AURA_HASH521_V1("AURA_STORM_MACRO_BETA_V2")
z_0   = AURA_HASH521_V1("AURA_STORM_MACRO_INIT_V2" || context_bytes_v1 || initial_state_row)
rho_k = AURA_HASH521_V1("AURA_STORM_MACRO_RHO_V2" || context_bytes_v1 || u64_le(k))
z_(k+1) = z_k^2 + alpha*x_end + beta*y_end + rho_k mod (2^521 - 1)
```

Rust uses the existing `FieldElement521V1` operations. TypeScript reuses the V1
field decoder, modular reducer and encoder; their implementations are unchanged
and exposed through additive helper exports. No second field arithmetic is added.

Hierarchy leaves hash `"AURA_STORM_HIERARCHY_LEAF_V2" || epoch_commitment` with
SHA3-256. Parents hash `"AURA_STORM_HIERARCHY_PARENT_V2" || left || right` with
SHA3-256. Preserve order and duplicate the last node on every odd level. A singleton
root is its domain-separated leaf. The final node is `HIERARCHY_ROOT_V2`.

## Interpretation and next feedback slice

Macro state does not yet feed back into micro-state derivation. This does not yet
constitute a STARK proof or demonstrate a computational-depth/security guarantee.
The supplied-trace builder commits rows; it does not validate their recurrence.
The execution wrapper obtains rows from the existing canonical V1 executor.

An interior-only row mutation changes its epoch commitment and hierarchy root,
but leaves the macro state unchanged when endpoints and context are held fixed.
Endpoint mutations tested here propagate to the final macro state. The prescribed
formula therefore cannot support a universal claim that *any* epoch change changes
final macro state. Neither the root nor the epoch commitments directly bind z.
These are explicit properties of this experiment, not silently repaired semantics.

Future V2 work may make the macro state influence subsequent epoch derivations
after review. That slice must specify the feedback preimage, execution/version
boundary and proof obligations before implementation. There is no implementation
blocker for research, but those choices and any stronger depth claim remain open.

## Files and reproducible evidence

- `crates/aura_intent_lineage_v1/src/storm_hierarchy_v2.rs`: research result, epochs, macro recurrence and hierarchy tree.
- `crates/aura_intent_lineage_v1/src/lib.rs`: explicit experimental module registration only.
- `packages/aura_sdk_v1_ts/src/stormHierarchyV2.ts`: matching experimental implementation.
- `packages/aura_sdk_v1_ts/src/stormExecutionV1.ts`: additive export of existing field helpers only.
- `crates/aura_intent_lineage_v1/tests/storm_hierarchy_v2.rs` and `packages/aura_sdk_v1_ts/tests/storm_hierarchy_v2.test.ts`: focused tests.
- `fixtures/experimental/storm_hierarchy_v2/parity_vector_v2.json`: frozen experimental 129-transition, three-epoch vector, including inputs, boundaries, all epoch roots/commitments, all macro states, V1 trace root and hierarchy root.

The vector's final hierarchy root is
`835f23eb0cd3890e548d0e0bb1e7b6f305742d4fd6567f1ed45f73a8ae98ce43`.
It is experimental evidence, not an Aura proof reference.

Validation commands:

```
cargo test -p aura_intent_lineage_v1 --offline --test storm_hierarchy_v2
node --test packages/aura_sdk_v1_ts/tests/storm_hierarchy_v2.test.ts
cargo test -p aura_intent_lineage_v1 --offline --lib storm_
bash scripts/validate_storm_hash_quantum_hardening_v1.sh
```

The focused tests check deterministic execution, all specified epoch boundaries,
shared rows, exact commitment framing, ordered/odd-level reduction, every row and
coordinate's commitment sensitivity, canonical field recurrence, endpoint mutation
propagation and the interior-only limitation. Rust and TypeScript independently
match every experimental vector value. Pre-existing frozen fixtures and authoritative
documents are preserved byte-for-byte during this slice.

Result: all 5 focused Rust tests, 5 focused TypeScript tests, 26 Storm unit tests
and the existing 10-stage Storm hash/message-root hardening gate passed. The V1
frozen-output checks passed without regenerating any pre-existing fixture. A
before/after byte comparison found no change to the four specified Rust V1
implementation files, pre-existing fixtures, or authoritative documents. The
TypeScript V1 implementation body is unchanged; only helper exports were appended.
