<!-- DOC_STATUS_HEADER_START -->
> Status: CURRENT CONTRACT
> Concept: aura_notarization_workbench_v1
> Scope Boundary: Current contract for the implemented package surface named by this document only. It does not redefine repository-wide protocol meaning outside that package.
> Canonical Reference: This document.
> Commitment Doctrine: [Aura 521-Bit Deterministic Commitment Doctrine V1](../../docs/AURA_521_BIT_DETERMINISTIC_COMMITMENT_DOCTRINE_V1.md)
> Interpretation Rule: Treat implemented behavior within this scope as current-state contract. Future-looking body text does not expand authority or defer already implemented semantics.
> Implementation State: Implemented or frozen exactly within the scope boundary above.
<!-- DOC_STATUS_HEADER_END -->

# `aura_notarization_workbench_v1`

Classification: `IMPLEMENTATION`

This crate is the local operator/workbench app for deterministic transaction composition,
authorization preparation, canonical notarization record inspection, and receipt/export bundle
handoff.

## Run

```bash
cargo run --manifest-path crates/aura_notarization_workbench_v1/Cargo.toml --offline
```

The workbench starts a local server at:

- `http://127.0.0.1:8787`

## Current System

This workbench is a local deterministic transaction + authorization + notarization workbench.

It currently provides:

- deterministic private-transfer-burn transaction construction
- canonical public statement derivation
- canonical authorization payload/sign-request preparation
- a real Ed25519 authorization boundary before notary handoff
- a file-carrier external signer workflow
- a local helper workflow for the existing `aura_authorization_signer_v1`
- canonical notarization record + summary + Markdown/HTML receipt rendering
- bounded compose export bundle handoff

Frozen downstream/output surfaces remain unchanged:

- canonical transaction bytes/digests
- canonical public-statement bytes/digests
- authorization payload/envelope semantics
- authorization sign request/response wire fields
- file-carrier request/response schema
- downstream notarization/receipt/ack/seal/export shapes
- canonical summary order and receipt renderer outputs

## Canonical Happy Paths

1. Open the workbench in your browser.
2. In `Compose`, enter rollup / asset / anchor plus input/output rows, or click `Load Compose Sample`.
3. Enter signer public key + authorization nonce, then click `Prepare Authorization`.
4. Sign the frozen payload through one of the supported local/operator flows:
   - `Run Local Signer`
   - `Load Guided Signer Response` after running the shown helper command yourself
   - `Download Sign Carrier Request` + `Import Sign Carrier Response`
   - `Local Dev Sign (Dev Only)` for fixed-key local testing only
5. Click `Complete Compose` to validate authorization and derive the canonical transaction/public statement/notarization record path plus downstream summary + receipt previews.
6. Click `Export Compose Bundle` to download the bounded canonical compose artifact set:
   `compose-request.json`, `transaction.json`, `public-statement.json`, `notarization-record.json`, `receipt.md`, `receipt.html`.
7. Click `Download Export Bundle JSON` to fetch the same bounded compose bundle through the local workbench export route as one JSON document.
8. Click `Copy Export Bundle JSON` when you want to hand the same server-backed bundle directly into downstream tooling through the clipboard.
9. Or switch to `Inspect`, click `Load Record Sample`, or paste/import canonical notarization record wire JSON.
10. Click `Inspect Record` to validate the record and build the canonical summary.
11. Review the canonical summary fields, canonical path artifacts, and the Markdown / HTML receipt previews.
12. Download or copy the receipt artifacts you need:
   `Copy Summary JSON`, `Copy Markdown Receipt`, `Copy Notarization Record Digest`, `Copy HTML Receipt`, `Download .md`, `Download .html`.

## Canonical Downstream Handoff

The compose export bundle is the canonical downstream handoff shape for local operator/tooling
flows. Use either:

- `Copy Export Bundle JSON`
- `Download Export Bundle JSON`
- `POST /api/compose/export`

Automation-facing copy-paste example:

- `scripts/compose_export_handoff_example.sh`
- `scripts/consume_compose_export_bundle_example.sh`

That script demonstrates the canonical automation handoff path:

- load a valid compose request from `GET /api/compose/sample`
- post it unchanged to `POST /api/compose/export`
- treat the returned bundle as immutable/canonical
- write `notarization_record` as the machine-readable artifact
- write `receipt_markdown` / `receipt_html` exactly as returned
- do not recompute digests, rename fields, or rerender receipts

The downstream consumer example is the canonical consumer path for the frozen export bundle:

- accept the frozen bundle JSON as input
- consume `notarization_record`, `receipt_markdown`, and `receipt_html` directly
- do not mutate or reinterpret the bundle

Tiny end-to-end chain:

```bash
./scripts/compose_export_handoff_example.sh /tmp/aura-compose-export-handoff
./scripts/consume_compose_export_bundle_example.sh \
  /tmp/aura-compose-export-handoff/compose-export-bundle.json
```

Result:

- `notarization-record.json`
- `receipt.md`
- `receipt.html`

The bundle JSON is passed unchanged from producer to consumer. Downstream tooling must treat
this bundle as canonical.

The bundle shape is fixed:

- `compose_request`
- `transaction`
- `public_statement`
- `notarization_record`
- `receipt_markdown`
- `receipt_html`

Tiny example workflow:

1. Compose a transaction in the workbench.
2. Use `Copy Export Bundle JSON` or `Download Export Bundle JSON`.
3. Hand that exact bundle into downstream tooling.
4. Use `notarization_record` as the canonical machine-readable artifact.
5. Use `receipt_markdown` and `receipt_html` directly as rendered outputs.

Downstream tooling should consume:

- `notarization_record` for canonical machine-readable notarization state
- `transaction` and `public_statement` for deterministic transaction context
- `receipt_markdown` / `receipt_html` exactly as returned when human-readable receipts are needed

Downstream tooling must not:

- recompute or “correct” canonical digests in the browser or another client
- rename, normalize, or mutate bundle fields
- rerender `receipt_markdown` or `receipt_html` through alternate formatting paths
- treat derived previews as a substitute for the canonical `notarization_record`

## Intentionally Deferred

- no live chain submission
- no browser signing
- no production wallet/account management
- no persistent signer/session storage
- no balances/history
- no networked signer transport beyond the local file carrier flow
- no browser-side protocol reimplementation
- no networking logic beyond the current local workbench scope
