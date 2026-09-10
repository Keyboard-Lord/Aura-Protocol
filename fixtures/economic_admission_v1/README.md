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

`contract_vector.json` freezes exact M/W bytes, charge, consent signing digest and
signature, the unchanged Authorization V2 reference, pre/post debit ledger
commitments, V2 genesis and each terminal outcome's head. Its signing key and nonce
are public test material. Rust `economic_contract_v1` and TypeScript `economicV1`
tests reproduce it and mutate every signed W byte.

Rust `economic_journal_v1` tests cover debit/finalization rollback, all outcomes,
retry and nonce conflict, concurrent finalizers, process-exit recovery, explicit
V1 predecessor migration and fail-closed storage. The real Bitcoin Core runner
`scripts/verify_bitcoin_regtest_v1.mjs` uses this contract vector through admission,
restart, actual proof/material/lineage verification, outbox publication and reorg
retry without reburn or nonce release. These fixtures are evidence; definitions
remain in the existing authoritative owners.
