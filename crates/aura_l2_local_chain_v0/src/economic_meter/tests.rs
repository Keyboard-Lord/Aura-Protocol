use super::*;

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> CanonicalPipelineRequestV1 {
    load_canonical_pipeline_request(root().join("fixtures/l2_canonical_pipeline_v1").join(name))
        .unwrap()
}

fn active(name: &str) -> EconomicMeterV1 {
    let r = fixture(name);
    let accounts = LocalStateV1::new(r.accounts.clone())
        .unwrap()
        .ordered_accounts();
    let mut m = EconomicMeterV1::from_legacy_request(&r, &accounts);
    // Explicit test construction, not an implicit production upgrade path.
    m.head.settlement_head_version = 2;
    m.proof_system = ProofSystemSelectionV1::Stark;
    if let Some(a) = &mut m.attestation {
        a.attestation_proof_kind = CanonicalPipelineAttestationProofKindV1::Stark;
    }
    m
}

fn raw(m: &EconomicMeterV1) -> Vec<u8> {
    let mut b = CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1.to_vec();
    extend_payload(&mut b, m, [None, None]);
    b
}

fn examples() -> Vec<(&'static str, EconomicMeterV1)> {
    let mut result = vec![
        ("execution", active("accepted_transfer_request.json")),
        (
            "attestation",
            active("accepted_stark_attestation_request.json"),
        ),
        (
            "external_anchor_mismatch",
            active("external_anchor_mismatch_request.json"),
        ),
    ];
    use CanonicalPipelineAttestationClaimKindV1 as K;
    use CanonicalPipelineAttestationClaimPayloadV1 as P;
    for (name, kind, payload) in [
        (
            "root_digest",
            K::EvidenceRootDigest,
            P::EvidenceRootDigest {
                expected_evidence_root_digest: [4; 32],
            },
        ),
        (
            "evidence_digest",
            K::NormalizedEvidenceDigest,
            P::NormalizedEvidenceDigest {
                target_label: "missing".into(),
                expected_evidence_digest: [5; 32],
            },
        ),
        (
            "text_contains",
            K::NormalizedTextContainsUtf8,
            P::NormalizedTextContainsUtf8 {
                target_label: "missing".into(),
                expected_substring_utf8: "\u{feff}Aura 🟠\r\n".into(),
            },
        ),
        (
            "json_field",
            K::NormalizedJsonFieldEqualsUtf8,
            P::NormalizedJsonFieldEqualsUtf8 {
                target_label: "missing".into(),
                field_path: vec!["a".into(), "b".into()],
                expected_value_utf8: "no".into(),
            },
        ),
    ] {
        let mut m = active("accepted_stark_attestation_request.json");
        m.attestation.as_mut().unwrap().claim = CanonicalPipelineAttestationClaimV1 {
            claim_kind: kind,
            claim_payload: payload,
        };
        result.push((name, m));
    }
    let mut signed = active("accepted_stark_attestation_request.json");
    let a = signed.attestation.as_mut().unwrap();
    a.evidence_items[0].provenance = CanonicalPipelineEvidenceProvenanceV1 {
        provenance_policy_version: 1,
        provenance_type: CanonicalPipelineEvidenceProvenanceTypeV1::SignedBlob,
        source_type: "inline".into(),
        source_identifier: "signed-vector".into(),
        signature: Some(CanonicalPipelineEvidenceSignatureV1 {
            signer_public_key: [9; 32],
            signature: [8; 64],
        }),
        timestamp_unix_seconds: Some(u64::MAX),
    };
    a.evidence_items[0].evidence_kind = CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8;
    a.evidence_items[0].evidence_payload =
        CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 {
            payload_utf8: "{ \"x\": 1 }".into(),
        };
    result.push(("signed_json", signed));
    result
}

#[test]
fn legacy_meter_bytes_and_burn_are_unchanged() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/economic_admission_v1/legacy_meter_bytes.json"
    ))
    .unwrap();
    for v in vectors.as_array().unwrap() {
        let r = fixture(v["fixture"].as_str().unwrap());
        let accounts = LocalStateV1::new(r.accounts.clone())
            .unwrap()
            .ordered_accounts();
        assert_eq!(
            encode_hex(&canonical_pipeline_burn_metered_bytes_v1(&r, &accounts)),
            v["meter_hex"]
        );
        assert_eq!(
            compute_canonical_pipeline_burn_units_v1(&r, &accounts)
                .unwrap()
                .to_string(),
            v["burn_units"]
        );
    }
}

#[test]
fn frozen_active_meter_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/economic_admission_v1/meter_vectors.json"
    ))
    .unwrap();
    for ((name, m), v) in examples().into_iter().zip(vectors.as_array().unwrap()) {
        assert_eq!(name, v["name"]);
        let bytes = m.canonical_bytes().unwrap();
        assert_eq!(encode_hex(&bytes), v["meter_hex"]);
        assert_eq!(m.burn_units().unwrap().to_string(), v["burn_units"]);
        assert_eq!(EconomicMeterV1::decode(&bytes, bytes.len()).unwrap(), m);
    }
    assert_eq!(examples().len(), vectors.as_array().unwrap().len());
}

#[test]
fn rejects_truncation_trailing_bytes_wrong_domain_and_resource_overflow() {
    for (_, m) in examples() {
        let bytes = m.canonical_bytes().unwrap();
        for n in 0..bytes.len() {
            assert!(
                EconomicMeterV1::decode(&bytes[..n], bytes.len()).is_err(),
                "prefix {n}"
            );
        }
        assert!(EconomicMeterV1::decode(&bytes, bytes.len() - 1).is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(EconomicMeterV1::decode(&extended, extended.len()).is_err());
        let mut wrong = bytes.clone();
        wrong[0] ^= 1;
        assert!(EconomicMeterV1::decode(&wrong, wrong.len()).is_err());
        let start = CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1.len() + 4;
        wrong = bytes.clone();
        wrong[start..start + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(EconomicMeterV1::decode(&wrong, wrong.len()).is_err());
        wrong = bytes.clone();
        wrong[start + 8] = 0xff;
        assert!(EconomicMeterV1::decode(&wrong, wrong.len()).is_err());
    }
}

#[test]
fn strict_policy_order_ledger_and_legacy_rejections() {
    let m = active("accepted_transfer_request.json");
    let mutations: Vec<Box<dyn Fn(&mut EconomicMeterV1)>> = vec![
        Box::new(|m| m.pipeline_schema_version = 2),
        Box::new(|m| m.pipeline_id.push('x')),
        Box::new(|m| m.proof_system = ProofSystemSelectionV1::Mock),
        Box::new(|m| m.economic_policy_version = 9),
        Box::new(|m| m.accounting.accounting_policy_version = 9),
        Box::new(|m| m.head.settlement_head_version = 1),
        Box::new(|m| m.head.head_sequence_number = 0),
        Box::new(|m| m.ledger.accounts.reverse()),
        Box::new(|m| m.ledger.accounts.push(m.ledger.accounts[0].clone())),
        Box::new(|m| m.ledger.payer_account_id = [0xff; 32]),
        Box::new(|m| m.ledger.burned_supply = u64::MAX),
        Box::new(|m| m.ledger.accounts[0].balance = u64::MAX),
        Box::new(|m| m.ledger.total_supply += 1),
        Box::new(|m| m.accounts.reverse()),
        Box::new(|m| m.accounts.push(m.accounts[0])),
        Box::new(|m| m.transactions[0].tx_version = 2),
        Box::new(|m| m.wallet_binding.wallet_address = "0".into()),
        Box::new(|m| {
            m.token_anchor.enforce_external_match = true;
            m.token_anchor.expected_external_balance = None;
        }),
        Box::new(|m| m.transactions.clear()),
    ];
    for mutate in mutations {
        let mut changed = m.clone();
        mutate(&mut changed);
        assert!(changed.canonical_bytes().is_err());
        let bytes = raw(&changed);
        assert!(EconomicMeterV1::decode(&bytes, bytes.len()).is_err());
    }
}

#[test]
fn flags_and_attestation_structure_fail_closed() {
    let mut m = active("accepted_stark_attestation_request.json");
    for which in 0..2 {
        let mut bytes = CANONICAL_PIPELINE_BURN_METERING_DOMAIN_SEPARATOR_V1.to_vec();
        let tamper = ByteTamperFixtureV1 {
            byte_offset: 0,
            xor_with: 1,
        };
        let mut flags = [None, None];
        flags[which] = Some(&tamper);
        extend_payload(&mut bytes, &m, flags);
        assert!(EconomicMeterV1::decode(&bytes, bytes.len()).is_err());
    }
    // Locate the optional attestation flag through its exact header, not a guessed offset.
    let bytes = m.canonical_bytes().unwrap();
    let header = [1, 2, 0, 0, 0, 45, 0, 0, 0, 0, 0, 0, 0];
    // Scope text is 45 bytes. The test still fails if the encoding drifts.
    let offset = bytes
        .windows(header.len())
        .position(|w| w == header)
        .unwrap();
    let mut invalid_flag = bytes.clone();
    invalid_flag[offset] = 2;
    assert!(EconomicMeterV1::decode(&invalid_flag, invalid_flag.len()).is_err());
    let a = m.attestation.as_mut().unwrap();
    a.evidence_items.push(a.evidence_items[0].clone());
    assert!(m.canonical_bytes().is_err());
}

#[test]
fn chargeable_work_failures_are_not_free_structural_errors() {
    let mut m = active("accepted_transfer_request.json");
    m.transactions[0].sender_nonce = u64::MAX;
    m.transactions[0].amount = u64::MAX;
    let bytes = m.canonical_bytes().unwrap();
    assert!(EconomicMeterV1::decode(&bytes, bytes.len()).is_ok());
    assert!(m.execute_local_work().is_err());
    for (_, m) in examples() {
        // Missing claim labels and invalid provenance signatures are admitted shapes.
        assert!(m.canonical_bytes().is_ok());
    }
    let mut m = active("accepted_stark_attestation_request.json");
    m.attestation.as_mut().unwrap().evidence_items[0].evidence_payload =
        CanonicalPipelineAttestationEvidencePayloadV1::InlineJsonUtf8 {
            payload_utf8: "{bad json".into(),
        };
    m.attestation.as_mut().unwrap().evidence_items[0].evidence_kind =
        CanonicalPipelineAttestationEvidenceKindV1::InlineJsonUtf8;
    assert!(m.canonical_bytes().is_ok());
    assert!(m.execute_local_work().is_err());
}

#[test]
fn local_work_and_ledger_snapshots_use_existing_owners() {
    let m = active("accepted_transfer_request.json");
    assert!(m.execute_local_work().is_ok());
    assert!(m
        .settlement_rejection(&m.execute_local_work().unwrap())
        .is_none());
    let a = active("accepted_stark_attestation_request.json");
    assert!(a.execute_local_work().is_ok());
    for (name, m) in examples() {
        if [
            "root_digest",
            "evidence_digest",
            "text_contains",
            "json_field",
            "signed_json",
        ]
        .contains(&name)
        {
            assert!(m.execute_local_work().is_err(), "{name}");
        }
    }
    let external = active("external_anchor_mismatch_request.json");
    assert!(external.execute_local_work().is_ok());
    assert!(external
        .settlement_rejection(&external.execute_local_work().unwrap())
        .is_some());
    let mut wallet = m.clone();
    wallet.wallet_binding.account_id = [9; 32];
    assert!(wallet.execute_local_work().is_ok());
    assert!(wallet
        .settlement_rejection(&wallet.execute_local_work().unwrap())
        .is_some());
    let mut bad_batch = m.clone();
    bad_batch.batch_number = 1;
    assert!(bad_batch
        .settlement_rejection(&bad_batch.execute_local_work().unwrap())
        .is_some());
    let mut bad_parent = m.clone();
    bad_parent.parent_batch_commitment = [1; 32];
    assert!(bad_parent
        .settlement_rejection(&bad_parent.execute_local_work().unwrap())
        .is_some());
    let post = debit_economic_ledger_v1(&m.ledger, m.burn_units().unwrap()).unwrap();
    for ledger in [&m.ledger, &post] {
        let bytes = economic_ledger_bytes_v1(ledger).unwrap();
        assert_eq!(
            decode_economic_ledger_v1(&bytes, bytes.len()).unwrap(),
            *ledger
        );
        assert_eq!(
            sha256_digest_v1(&bytes),
            economic_ledger_commitment_v1(ledger).unwrap()
        );
        for n in 0..bytes.len() {
            assert!(decode_economic_ledger_v1(&bytes[..n], bytes.len()).is_err());
        }
    }
}

#[test]
fn whitespace_classification_is_explicit_for_parity() {
    let mut m = active("accepted_stark_attestation_request.json");
    m.attestation.as_mut().unwrap().evidence_items[0].label = "\u{85}".into();
    assert!(m.canonical_bytes().is_err());
    m.attestation.as_mut().unwrap().evidence_items[0].label = "\u{feff}".into();
    assert!(m.canonical_bytes().is_ok());
}
