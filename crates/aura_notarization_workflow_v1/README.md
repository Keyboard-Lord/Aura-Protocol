<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: aura_notarization_workflow_v1
> Scope Boundary: Current contract for the implemented package surface named by this document only. It does not redefine repository-wide protocol meaning outside that package.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# `aura_notarization_workflow_v1`

Classification: `IMPLEMENTATION`

This crate is the canonical non-CLI automation path for notarization receipt export.

Use it when you already have canonical notarization record wire JSON in memory and want the standard receipt files without reading across multiple crates or using CLI code.

High-level workflow:

1. Parse canonical notarization record wire JSON into `CanonicalTokenTransactionNotarizationRecordWireV1`.
2. Call `export_notarization_record_wire_v1(...)`.
3. Receive `NotarizationReceiptBundlePathsV1`.
4. Use the standard `<base>.md` and `<base>.html` outputs.

The canonical copy-paste reference example lives in [src/lib.rs](./src/lib.rs).

For embedders that already hold a validated application payload, the canonical structured-data-to-files path is:

1. convert the validated application payload into canonical notarization record wire `serde_json::Value`
2. call `export_notarization_record_value_v1(...)`
3. receive `NotarizationReceiptBundlePathsV1`
4. use the standard `<base>.md` and `<base>.html` outputs

No public validated application payload type is frozen in this surface yet, so the example below remains the canonical adoption path until a real stable payload type exists.

Minimal example:

```rust
use aura_notarization_workflow_v1::export_notarization_record_value_v1;

struct ValidatedApplicationNotarizationPayload<'a> {
    record_version: u32,
    proof_statement_type: u8,
    ack_digest_hex: &'a str,
    seal_payload_digest_hex: &'a str,
    udot_seed_digest_hex: &'a str,
    notarization_record_digest_hex: &'a str,
}

let payload = ValidatedApplicationNotarizationPayload {
    record_version: 1,
    proof_statement_type: 1,
    ack_digest_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    seal_payload_digest_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    udot_seed_digest_hex: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    notarization_record_digest_hex: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
};

let record_wire_value = serde_json::json!({
    "record_version": payload.record_version,
    "proof_statement_type": payload.proof_statement_type,
    "ack_digest_hex": payload.ack_digest_hex,
    "seal_payload_digest_hex": payload.seal_payload_digest_hex,
    "udot_seed_digest_hex": payload.udot_seed_digest_hex,
    "notarization_record_digest_hex": payload.notarization_record_digest_hex,
});

let receipt_paths =
    export_notarization_record_value_v1(&record_wire_value, "/tmp/aura_notarization_receipt")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```
