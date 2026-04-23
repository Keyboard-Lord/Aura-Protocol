mod support;

use aura_intent_lineage_v1::{
    AccountUpdateOperationV1, AuraLayer4AccountV1, AuraLayer4ControllerBindingV1,
    AuraLayer4FeePolicyKindV1, AuraLayer4IntentBodyV1, AuraLayer4OperationBodyV1,
    AuraLayer4PrototypeStateV1, AuraLayer4StateTransitionErrorV1, AuraLayer4TxKindV1,
    AuthorizationEnvelopeAuthKindV1, AuthorizationEnvelopeLineageTransportKindV1,
    AuthorizationEnvelopeV1, AuthorizationEnvelopeValidityBoundsV1, AuthorizationLineageV1,
    DcmCommitmentKindV1, FreshnessModeV1, IntentTypeV1, SubjectBindingTypeV1,
    ValueTransferOperationV1, ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT,
    AURA_LAYER4_ACCOUNT_STATUS_ACTIVE_V1,
};

use support::encode_hex;

#[test]
fn canonical_account_update_succeeds_deterministically() {
    let account = canonical_account();
    let intent = canonical_account_update_intent(account.account_id, account.nonce);
    let envelope = canonical_native_envelope(
        account.account_id,
        account.controller_binding.binding_type,
        account.controller_binding.subject_id,
        intent.intent_hash().unwrap(),
    );
    let mut state = AuraLayer4PrototypeStateV1::new([account]).unwrap();

    let pre_state_root = state.state_root();
    let result = state.apply_account_update(&intent, &envelope, 120).unwrap();
    let updated_account = state.account(&account.account_id).unwrap();

    assert_eq!(result.account_id, account.account_id);
    assert_eq!(result.consumed_nonce, 7);
    assert_eq!(result.pre_state_root, pre_state_root);
    assert_eq!(result.post_state_root, state.state_root());
    assert_ne!(result.pre_state_root, result.post_state_root);
    assert_eq!(
        updated_account.data_commitment, [0x88; 32],
        "account_update must replace data_commitment"
    );
    assert_eq!(
        updated_account.nonce, 8,
        "account_update must increment nonce"
    );
    assert_eq!(
        updated_account.last_updated_batch, 120,
        "account_update must write last_updated_batch"
    );

    println!(
        "canonical_account_update pre_state_root={} post_state_root={}",
        encode_hex(&result.pre_state_root),
        encode_hex(&result.post_state_root)
    );
}

#[test]
fn nonce_mismatch_rejects() {
    let mut account = canonical_account();
    account.nonce = 8;

    let intent = canonical_account_update_intent(account.account_id, 7);
    let envelope = canonical_native_envelope(
        account.account_id,
        account.controller_binding.binding_type,
        account.controller_binding.subject_id,
        intent.intent_hash().unwrap(),
    );
    let mut state = AuraLayer4PrototypeStateV1::new([account]).unwrap();

    let error = state
        .apply_account_update(&intent, &envelope, 120)
        .unwrap_err();
    assert_eq!(
        error,
        AuraLayer4StateTransitionErrorV1::NonceMismatch {
            expected: 8,
            actual: 7,
        }
    );
}

#[test]
fn controller_mismatch_rejects() {
    let account = canonical_account();
    let intent = canonical_account_update_intent(account.account_id, account.nonce);
    let envelope = canonical_native_envelope(
        account.account_id,
        SubjectBindingTypeV1::RawEd25519PublicKey32,
        [0x99; 32],
        intent.intent_hash().unwrap(),
    );
    let mut state = AuraLayer4PrototypeStateV1::new([account]).unwrap();

    let error = state
        .apply_account_update(&intent, &envelope, 120)
        .unwrap_err();
    assert_eq!(
        error,
        AuraLayer4StateTransitionErrorV1::ControllerMismatch {
            expected_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            expected_subject_id: [0x55; 32],
            actual_binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            actual_subject_id: [0x99; 32],
        }
    );
}

#[test]
fn inactive_account_rejects() {
    let mut account = canonical_account();
    account.status_flags = 0;

    let intent = canonical_account_update_intent(account.account_id, account.nonce);
    let envelope = canonical_native_envelope(
        account.account_id,
        account.controller_binding.binding_type,
        account.controller_binding.subject_id,
        intent.intent_hash().unwrap(),
    );
    let mut state = AuraLayer4PrototypeStateV1::new([account]).unwrap();

    let error = state
        .apply_account_update(&intent, &envelope, 120)
        .unwrap_err();
    assert_eq!(
        error,
        AuraLayer4StateTransitionErrorV1::InactiveAccount {
            account_id: [0x22; 32],
        }
    );
}

#[test]
fn unsupported_tx_kind_rejects() {
    let account = canonical_account();
    let intent = value_transfer_intent(account.account_id, account.nonce);
    let envelope = canonical_native_envelope(
        account.account_id,
        account.controller_binding.binding_type,
        account.controller_binding.subject_id,
        intent.intent_hash().unwrap(),
    );
    let mut state = AuraLayer4PrototypeStateV1::new([account]).unwrap();

    let error = state
        .apply_account_update(&intent, &envelope, 120)
        .unwrap_err();
    assert_eq!(
        error,
        AuraLayer4StateTransitionErrorV1::UnsupportedTxKind {
            actual: AuraLayer4TxKindV1::ValueTransfer,
        }
    );
}

#[test]
fn missing_account_rejects() {
    let account = canonical_account();
    let intent = canonical_account_update_intent(account.account_id, account.nonce);
    let envelope = canonical_native_envelope(
        account.account_id,
        account.controller_binding.binding_type,
        account.controller_binding.subject_id,
        intent.intent_hash().unwrap(),
    );
    let mut state = AuraLayer4PrototypeStateV1::new([]).unwrap();

    let error = state
        .apply_account_update(&intent, &envelope, 120)
        .unwrap_err();
    assert_eq!(
        error,
        AuraLayer4StateTransitionErrorV1::MissingAccount {
            account_id: [0x22; 32],
        }
    );
}

fn canonical_account() -> AuraLayer4AccountV1 {
    AuraLayer4AccountV1 {
        account_id: [0x22; 32],
        controller_binding: AuraLayer4ControllerBindingV1 {
            binding_type: SubjectBindingTypeV1::RawEd25519PublicKey32,
            subject_id: [0x55; 32],
        },
        nonce: 7,
        data_commitment: [0x77; 32],
        status_flags: AURA_LAYER4_ACCOUNT_STATUS_ACTIVE_V1,
        last_updated_batch: 99,
    }
}

fn canonical_account_update_intent(
    sender_account_id: [u8; 32],
    sender_nonce: u64,
) -> AuraLayer4IntentBodyV1 {
    AuraLayer4IntentBodyV1 {
        intent_version: 1,
        intent_flags: 0,
        rollup_id: [0x11; 32],
        tx_kind: AuraLayer4TxKindV1::AccountUpdate,
        sender_account_id,
        sender_nonce,
        validity_flags: 0,
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
        not_before_batch_number: 0,
        not_after_batch_number: 0,
        fee_policy_kind: AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
        max_fee_native: 0,
        client_context_commitment: [0u8; 32],
        operation_body: AuraLayer4OperationBodyV1::AccountUpdate(AccountUpdateOperationV1 {
            target_account_id: sender_account_id,
            account_update_flags: ACCOUNT_UPDATE_FLAG_HAS_NEXT_DATA_COMMITMENT,
            next_authorization_policy_family: 0,
            next_authorization_policy_version: 0,
            next_authorization_policy_kind: 0,
            next_authorization_policy_flags: 0,
            next_data_commitment: [0x88; 32],
        }),
    }
}

fn value_transfer_intent(sender_account_id: [u8; 32], sender_nonce: u64) -> AuraLayer4IntentBodyV1 {
    AuraLayer4IntentBodyV1 {
        intent_version: 1,
        intent_flags: 0,
        rollup_id: [0x11; 32],
        tx_kind: AuraLayer4TxKindV1::ValueTransfer,
        sender_account_id,
        sender_nonce,
        validity_flags: 0,
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
        not_before_batch_number: 0,
        not_after_batch_number: 0,
        fee_policy_kind: AuraLayer4FeePolicyKindV1::MaxFeePerTxNative,
        max_fee_native: 0,
        client_context_commitment: [0u8; 32],
        operation_body: AuraLayer4OperationBodyV1::ValueTransfer(ValueTransferOperationV1 {
            recipient_account_id: [0x33; 32],
            amount: 1,
        }),
    }
}

fn canonical_native_envelope(
    controlled_account_id: [u8; 32],
    subject_binding_type: SubjectBindingTypeV1,
    subject_id: [u8; 32],
    intent_hash: [u8; 32],
) -> AuthorizationEnvelopeV1 {
    let lineage = AuthorizationLineageV1 {
        version: 1,
        lineage_flags: 0,
        dcm_commitment_kind: DcmCommitmentKindV1::DcmRootCommitmentV1,
        dcm_commitment_root: [0x44; 32],
        dcm_trace_commitment: [0u8; 32],
        subject_binding_type,
        subject_id,
        subject_public_key: [0u8; 32],
        intent_type: IntentTypeV1::AuraLayer4IntentHashV1,
        intent_hash,
        freshness_mode: FreshnessModeV1::NonceOnly,
        freshness_nonce: [0x66; 32],
        freshness_reference: 0,
        proof_material_v1_hash: [0u8; 32],
        fractal_key_v1_hash: [0u8; 32],
    };
    let lineage_hash = lineage.lineage_hash().unwrap();

    AuthorizationEnvelopeV1 {
        auth_version: 1,
        auth_kind: AuthorizationEnvelopeAuthKindV1::AuthorizationLineageV1ExactIntent,
        controlled_account_id,
        envelope_validity_bounds: AuthorizationEnvelopeValidityBoundsV1 {
            validity_flags: 0,
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 0,
            not_before_batch_number: 0,
            not_after_batch_number: 0,
        },
        lineage_transport_kind:
            AuthorizationEnvelopeLineageTransportKindV1::InlineAuthorizationLineageV1,
        lineage_hash,
        inline_authorization_lineage_v1: Some(lineage),
    }
}
