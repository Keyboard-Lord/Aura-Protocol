# Economic admission vectors

`meter_vectors.json` freezes eight production M encodings and charges, checked by
Rust and TypeScript. They cover execution, all four attestation claim encodings,
external balance references, signed provenance, JSON evidence, Unicode and u64
boundaries. Some well-formed work is intentionally false: structural admission
must not grant free evaluation of chargeable work.

`legacy_meter_bytes.json` was captured from the existing Rust writer before its
extraction. Both implementations must continue emitting these exact bytes and
charges, including historical tamper flags. These are compatibility evidence,
not valid successor admission objects. Existing frozen fixture files were not
changed. Test construction explicitly selects head V2 and full-verification
tariffs for the new vectors; canonical decoding never upgrades a legacy request.

These vectors establish meter parity only. Consent, durable admission and Bitcoin
publication require their own evidence before the migration is complete.
