use super::*;
impl EconomicJournalV1 {
    pub fn install_compute(
        &mut self,
        policy: &ComputeJournalConfigV1,
    ) -> AuthorizationResultV2<()> {
        if policy.coordinator.network != self.network {
            return Err("compute install network mismatch".into());
        }
        let cfg = Config {
            network: self.network.tag(),
            key: policy.coordinator.coordinator_key,
            namespace: policy.coordinator.journal_namespace,
            limits: pack_limits(&policy.limits),
            max_record_bytes: policy.max_record_bytes,
            delivery_ms: policy.delivery_budget_ms,
        };
        cfg.validate(self.network)?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if schema(&tx)? {
            return Err("compute already installed".into());
        }
        let s = serde_json::to_string(&cfg)?;
        tx.execute_batch("CREATE TABLE compute_control(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),config TEXT NOT NULL,checksum BLOB NOT NULL);
        CREATE TABLE compute_jobs(id BLOB PRIMARY KEY CHECK(length(id)=32),requester BLOB NOT NULL CHECK(length(requester)=32),nonce BLOB NOT NULL CHECK(length(nonce)=32),state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 6),funding_txid TEXT,funding_vout INTEGER,record TEXT NOT NULL,checksum BLOB NOT NULL,UNIQUE(requester,nonce),CHECK((funding_txid IS NULL)=(funding_vout IS NULL)));
        CREATE UNIQUE INDEX compute_funding_owned ON compute_jobs(funding_txid,funding_vout) WHERE state IN (1,2,3);
        CREATE TABLE compute_entitlements(job BLOB PRIMARY KEY REFERENCES compute_jobs(id),worker BLOB NOT NULL CHECK(length(worker)=32),net TEXT NOT NULL,fee TEXT NOT NULL);")?;
        tx.execute(
            "INSERT INTO compute_control VALUES(1,1,?1,?2)",
            params![s, checksum(s.as_bytes())],
        )?;
        hook("install_before_commit")?;
        tx.commit()?;
        Ok(())
    }
    /// Trusted service receives exact request content. An open request reserves no
    /// funds and authorizes no worker; funding is acquired atomically at assignment.
    pub fn register_compute_job(
        &mut self,
        bytes: &[u8],
        signature: &[u8; 64],
        content: &ComputeJobContentV1,
    ) -> AuthorizationResultV2<[u8; 32]> {
        self.register_compute_with_clock(bytes, signature, content, super::super::miner::now)
    }
    pub(super) fn register_compute_with_clock(
        &mut self,
        bytes: &[u8],
        signature: &[u8; 64],
        content: &ComputeJobContentV1,
        clock: impl FnOnce() -> AuthorizationResultV2<u64>,
    ) -> AuthorizationResultV2<[u8; 32]> {
        let j = AuraComputeJobV1::decode(bytes)?;
        let id = j.commitment()?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cfg = config(&tx, self.network)?;
        j.verify_for_coordinator(signature, &cfg.trusted(self.network))?;
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT id FROM compute_jobs WHERE requester=?1 AND nonce=?2",
                params![j.requester_key.as_slice(), j.job_nonce.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let r = load(&tx, &old.as_slice().try_into()?, &cfg)?;
            if r.job != bytes {
                return Err("compute nonce conflicts with different signed job".into());
            }
            return Ok(id);
        }
        // Bound all uploaded content before cloning or running any adapter code.
        let total = content.payloads.iter().try_fold(0usize, |n, b| {
            n.checked_add(b.len())
                .ok_or("compute payload size overflow")
        })?;
        if total > cfg.max_record_bytes {
            return Err("compute uploaded content exceeds host bound".into());
        }
        content.validate(&j)?;
        storage_budget(&j, content, &cfg)?;
        adapters::resolve(&j, content)?.check_job(&j, content)?;
        let now = clock()?;
        j.validate_new_assignment(now, cfg.delivery_ms, &unpack_limits(cfg.limits))?;
        let r = Record {
            job: bytes.to_vec(),
            signature: signature.to_vec(),
            content: content.clone(),
            created: now,
            state: 0,
            assignment: None,
            receipt: None,
            result: None,
            funding: None,
            closed: None,
            cancel_signature: None,
        };
        let s = serde_json::to_string(&r)?;
        if s.len() > cfg.max_record_bytes {
            return Err("compute record exceeds host bound".into());
        }
        tx.execute(
            "INSERT INTO compute_jobs VALUES(?1,?2,?3,0,NULL,NULL,?4,?5)",
            params![
                id.as_slice(),
                j.requester_key.as_slice(),
                j.job_nonce.as_slice(),
                s,
                checksum(s.as_bytes())
            ],
        )?;
        hook("request_before_commit")?;
        tx.commit()?;
        Ok(id)
    }
    /// A sealed adapter owns capability measurement. Production C2 has no adapter
    /// registered; C3 must supply its reviewed real probe before this can succeed.
    pub fn measure_compute_worker(
        &self,
        id: [u8; 32],
        worker: [u8; 32],
        backend: ComputeBackendV1,
        valid_until: u64,
    ) -> AuthorizationResultV2<MeasuredComputeWorkerV1> {
        self.measure_compute_at(
            id,
            worker,
            backend,
            valid_until,
            super::super::miner::now()?,
        )
    }
    pub(super) fn measure_compute_at(
        &self,
        id: [u8; 32],
        worker: [u8; 32],
        backend: ComputeBackendV1,
        valid_until: u64,
        now: u64,
    ) -> AuthorizationResultV2<MeasuredComputeWorkerV1> {
        XOnlyPublicKey::from_byte_array(worker)?;
        if valid_until <= now {
            return Err("measurement validity window is empty".into());
        }
        let tx = self.authorizer.connection.unchecked_transaction()?;
        let cfg = config(&tx, self.network)?;
        let r = load(&tx, &id, &cfg)?;
        let j = AuraComputeJobV1::decode(&r.job)?;
        let limits = adapters::resolve(&j, &r.content)?.measure(backend)?;
        Ok(MeasuredComputeWorkerV1(Measurement {
            worker,
            adapter: j.adapter_contract_commitment,
            backend: backend as u8,
            at: now,
            until: valid_until,
            limits: pack_limits(&limits),
            provenance: if cfg!(test) {
                "C2 TEST-ONLY SEALED ADAPTER MEASUREMENT".into()
            } else {
                "reviewed adapter measurement".into()
            },
        }))
    }
    pub fn assign_compute_job(
        &mut self,
        a: &ComputeAssignmentV1,
        worker_signature: &[u8; 64],
        coordinator: &Keypair,
        measured: &MeasuredComputeWorkerV1,
        reserve: impl FnOnce(
            &AuraComputeJobV1,
            &ComputePaymentTermsV1,
        ) -> AuthorizationResultV2<funding::ComputeFundingV1>,
    ) -> AuthorizationResultV2<[u8; 64]> {
        self.assign_compute_with_clock(
            a,
            worker_signature,
            coordinator,
            measured,
            reserve,
            super::super::miner::now,
        )
    }
    pub(super) fn assign_compute_with_clock(
        &mut self,
        a: &ComputeAssignmentV1,
        worker_signature: &[u8; 64],
        coordinator: &Keypair,
        measured: &MeasuredComputeWorkerV1,
        reserve: impl FnOnce(
            &AuraComputeJobV1,
            &ComputePaymentTermsV1,
        ) -> AuthorizationResultV2<funding::ComputeFundingV1>,
        mut clock: impl FnMut() -> AuthorizationResultV2<u64>,
    ) -> AuthorizationResultV2<[u8; 64]> {
        a.verify_worker(worker_signature)?;
        let id = a.compute_job_commitment;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cfg = config(&tx, self.network)?;
        let mut r = load(&tx, &id, &cfg)?;
        let j = AuraComputeJobV1::decode(&r.job)?;
        a.verify_job(&j)?;
        if coordinator.x_only_public_key().0.serialize() != j.coordinator_key {
            return Err("compute coordinator signer mismatch".into());
        }
        if let Some(old) = &r.assignment {
            if old.bytes != a.canonical_bytes()? {
                return Err("compute assignment immutable; different worker".into());
            }
            return Ok(old.coordinator_signature.as_slice().try_into()?);
        }
        if r.state != 0 {
            return Err("terminal compute job cannot be assigned".into());
        }
        let now = clock()?;
        validate_measurement(&measured.0, &j, a, now)?;
        j.validate_new_assignment(now, cfg.delivery_ms, &unpack_limits(cfg.limits))?;
        adapters::resolve(&j, &r.content)?.check_job(&j, &r.content)?;
        let t = r.content.validate(&j)?;
        hook("before_reservation")?;
        let f = reserve(&j, &t)?.into_stored();
        f.validate(&j, &t)?;
        super::super::funding_registry::available(&tx, f.txid(), f.vout(), None)?;
        hook("after_reservation")?;
        let assigned_at = clock()?;
        if assigned_at < now {
            return Err("compute assignment clock regressed during custody verification".into());
        }
        validate_measurement(&measured.0, &j, a, assigned_at)?;
        j.validate_new_assignment(assigned_at, cfg.delivery_ms, &unpack_limits(cfg.limits))?;
        let ack = a.sign_coordinator(&j, coordinator)?;
        r.funding = Some(f);
        r.assignment = Some(Assignment {
            bytes: a.canonical_bytes()?,
            worker_signature: worker_signature.to_vec(),
            coordinator_signature: ack.to_vec(),
            at: assigned_at,
            measurement: measured.0.clone(),
        });
        r.state = 1;
        save(&tx, &id, &r, &cfg)?;
        hook("assignment_before_commit")?;
        tx.commit()?;
        hook("assignment_after_commit")?;
        Ok(ack)
    }
    pub fn receive_compute_result(
        &mut self,
        r: &ComputeReceiptV1,
        s: &[u8; 64],
        resources: &ComputeResourceAccountingV1,
        output: &[u8],
        evidence: &[u8],
        id: [u8; 32],
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        self.receive_compute_with_clock(
            r,
            s,
            resources,
            output,
            evidence,
            id,
            super::super::miner::now,
        )
    }
    pub(super) fn receive_compute_with_clock(
        &mut self,
        receipt: &ComputeReceiptV1,
        sig: &[u8; 64],
        resources: &ComputeResourceAccountingV1,
        output: &[u8],
        evidence: &[u8],
        id: [u8; 32],
        clock: impl FnOnce() -> AuthorizationResultV2<u64>,
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cfg = config(&tx, self.network)?;
        let mut r = load(&tx, &id, &cfg)?;
        let j = AuraComputeJobV1::decode(&r.job)?;
        let a = ComputeAssignmentV1::decode(
            &r.assignment.as_ref().ok_or("no durable assignment")?.bytes,
        )?;
        receipt.verify_signature(&a, sig)?;
        receipt.verify_content(&j, resources, &r.content.payloads[1], output, evidence)?;
        if let Some(old) = &r.receipt {
            if old.bytes != receipt.canonical_bytes()?
                || old.output != output
                || old.evidence != evidence
                || old.resources != resources.canonical_bytes()?
            {
                return Err("compute receipt/content is immutable".into());
            }
            return state_tag(&r);
        }
        if r.state != 1 {
            return Err("closed job cannot receive new work".into());
        }
        adapters::resolve(&j, &r.content)?.check_receipt(output, evidence)?;
        let now = clock()?;
        if now >= j.complete_by || now < r.assignment.as_ref().unwrap().at {
            return Err("compute receipt deadline or clock violation".into());
        }
        // Complete bounded artifacts and receipt are one SQLite commit. No URI,
        // filesystem path, upload start time or external non-durable reference.
        r.receipt = Some(Receipt {
            bytes: receipt.canonical_bytes()?,
            signature: sig.to_vec(),
            resources: resources.canonical_bytes()?,
            output: output.to_vec(),
            evidence: evidence.to_vec(),
            at: now,
        });
        r.state = 2;
        save(&tx, &id, &r, &cfg)?;
        hook("receipt_before_commit")?;
        tx.commit()?;
        hook("receipt_after_commit")?;
        Ok(ComputeJobStateV1::ReceiptPending)
    }
    pub fn verify_compute_result(
        &mut self,
        id: [u8; 32],
        coordinator: &Keypair,
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        self.verify_compute_with_clock(id, coordinator, super::super::miner::now)
    }
    pub(super) fn verify_compute_with_clock(
        &mut self,
        id: [u8; 32],
        coordinator: &Keypair,
        clock: impl FnOnce() -> AuthorizationResultV2<u64>,
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        let cfg = config(&self.authorizer.connection, self.network)?;
        let old = {
            let read = self.authorizer.connection.unchecked_transaction()?;
            let r = load(&read, &id, &cfg)?;
            read.commit()?;
            r
        };
        let j = AuraComputeJobV1::decode(&old.job)?;
        if coordinator.x_only_public_key().0.serialize() != j.coordinator_key {
            return Err("compute verifier signer mismatch".into());
        }
        if matches!(old.state, 3 | 4) {
            return state_tag(&old);
        }
        if old.state != 2 {
            return Err("no timely durable receipt to verify".into());
        }
        let rr = old.receipt.as_ref().unwrap();
        let adapter = adapters::resolve(&j, &old.content)?;
        adapter.check_receipt(&rr.output, &rr.evidence)?;
        // Errors preserve pending funds. Only the registered verifier's actual
        // rejection can terminally fail a well-framed durable receipt.
        let valid = adapter.verify(&j, &old.content, &rr.output, &rr.evidence)?;
        hook("after_verification")?;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut current = load(&tx, &id, &cfg)?;
        if matches!(current.state, 3 | 4) {
            return state_tag(&current);
        }
        if current.state != 2 || serde_json::to_vec(&current)? != serde_json::to_vec(&old)? {
            return Err("compute verification snapshot changed".into());
        }
        let now = clock()?;
        if now < rr.at {
            return Err("compute acceptance clock regression".into());
        }
        if valid {
            let a = ComputeAssignmentV1::decode(&old.assignment.as_ref().unwrap().bytes)?;
            let receipt = ComputeReceiptV1::decode(&rr.bytes)?;
            let result = VerifiedComputeResultV1 {
                version: 1,
                receipt_commitment: receipt.commitment()?,
                verification_verdict: 1,
            };
            let signature = result.sign(&j, &a, &receipt, coordinator)?;
            let terms = old.content.validate(&j)?;
            current.result = Some(ResultRecord {
                bytes: result.canonical_bytes()?,
                signature: signature.to_vec(),
                at: now,
                retain_until: (u128::from(now) + u128::from(terms.result_availability_seconds))
                    .to_string(),
            });
            current.state = 3;
            save(&tx, &id, &current, &cfg)?;
            hook("after_result_record")?;
            tx.execute(
                "INSERT INTO compute_entitlements VALUES(?1,?2,?3,?4)",
                params![
                    id.as_slice(),
                    a.worker_key.as_slice(),
                    j.compensation_satoshis.to_string(),
                    terms.max_payment_fee_satoshis.to_string()
                ],
            )?;
            hook("after_entitlement")?;
        } else {
            current.state = 4;
            current.closed = Some(now);
            save(&tx, &id, &current, &cfg)?;
        }
        load(&tx, &id, &cfg)?;
        hook("finalize_before_commit")?;
        tx.commit()?;
        hook("finalize_after_commit")?;
        state_tag(&current)
    }
    pub fn cancel_compute_job(
        &mut self,
        cancel: &ComputeCancelV1,
        sig: &[u8; 64],
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        self.cancel_compute_with_clock(cancel, sig, super::super::miner::now)
    }
    pub(super) fn cancel_compute_with_clock(
        &mut self,
        cancel: &ComputeCancelV1,
        sig: &[u8; 64],
        clock: impl FnOnce() -> AuthorizationResultV2<u64>,
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        let id = cancel.compute_job_commitment;
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cfg = config(&tx, self.network)?;
        let mut r = load(&tx, &id, &cfg)?;
        let j = AuraComputeJobV1::decode(&r.job)?;
        cancel.verify_signature(&j, sig)?;
        if r.state == 6 {
            return Ok(ComputeJobStateV1::Cancelled);
        }
        if r.state != 0 {
            return Err("cancellation only before assignment".into());
        }
        r.state = 6;
        r.closed = Some(clock()?);
        r.cancel_signature = Some(sig.to_vec());
        save(&tx, &id, &r, &cfg)?;
        hook("cancel_before_commit")?;
        tx.commit()?;
        Ok(ComputeJobStateV1::Cancelled)
    }
    pub fn expire_compute_job(&mut self, id: [u8; 32]) -> AuthorizationResultV2<ComputeJobStateV1> {
        self.expire_compute_with_clock(id, super::super::miner::now)
    }
    pub(super) fn expire_compute_with_clock(
        &mut self,
        id: [u8; 32],
        clock: impl FnOnce() -> AuthorizationResultV2<u64>,
    ) -> AuthorizationResultV2<ComputeJobStateV1> {
        let tx = self
            .authorizer
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cfg = config(&tx, self.network)?;
        let mut r = load(&tx, &id, &cfg)?;
        if !matches!(r.state, 0 | 1) {
            return state_tag(&r);
        }
        let j = AuraComputeJobV1::decode(&r.job)?;
        let now = clock()?;
        if now
            < (if r.state == 0 {
                j.accept_until
            } else {
                j.complete_by
            })
        {
            return Err("compute job not expired".into());
        }
        r.state = 5;
        r.closed = Some(now);
        save(&tx, &id, &r, &cfg)?;
        hook("expire_before_commit")?;
        tx.commit()?;
        Ok(ComputeJobStateV1::Expired)
    }
    pub fn compute_job_state(&self, id: [u8; 32]) -> AuthorizationResultV2<ComputeJobStateV1> {
        let read = self.authorizer.connection.unchecked_transaction()?;
        let cfg = config(&read, self.network)?;
        state_tag(&load(&read, &id, &cfg)?)
    }
    pub fn compute_entitlement(
        &self,
        id: [u8; 32],
    ) -> AuthorizationResultV2<Option<ComputeEntitlementV1>> {
        let read = self.authorizer.connection.unchecked_transaction()?;
        let cfg = config(&read, self.network)?;
        let r = load(&read, &id, &cfg)?;
        if r.state != 3 {
            return Ok(None);
        }
        let j = AuraComputeJobV1::decode(&r.job)?;
        let t = r.content.validate(&j)?;
        let a = ComputeAssignmentV1::decode(&r.assignment.unwrap().bytes)?;
        Ok(Some(ComputeEntitlementV1 {
            compute_job_commitment: id,
            worker_key: a.worker_key,
            compensation_satoshis: j.compensation_satoshis,
            fee_allowance_satoshis: t.max_payment_fee_satoshis,
        }))
    }
    pub fn compute_verified_result(
        &self,
        id: [u8; 32],
    ) -> AuthorizationResultV2<Option<(VerifiedComputeResultV1, [u8; 64])>> {
        let read = self.authorizer.connection.unchecked_transaction()?;
        let cfg = config(&read, self.network)?;
        let r = load(&read, &id, &cfg)?;
        r.result
            .map(|v| {
                Ok((
                    VerifiedComputeResultV1::decode(&v.bytes)?,
                    v.signature.as_slice().try_into()?,
                ))
            })
            .transpose()
    }
    /// Operator/service read. A network service must authenticate the requester;
    /// C2 exposes no public download endpoint or arbitrary filesystem paths.
    pub fn compute_accepted_output(&self, id: [u8; 32]) -> AuthorizationResultV2<Vec<u8>> {
        let read = self.authorizer.connection.unchecked_transaction()?;
        let cfg = config(&read, self.network)?;
        let r = load(&read, &id, &cfg)?;
        if r.state != 3 {
            return Err("compute output not yet accepted".into());
        }
        Ok(r.receipt.unwrap().output)
    }
}
