#!/usr/bin/env node

// SUPPORTING_NON_AUTHORITY:
// This script regenerates active fixture files. It is not a canonical verifier.

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixturesDir = path.join(repoRoot, "fixtures", "l2_canonical_pipeline_v1");
const sdkPath = path.join(repoRoot, "packages", "aura_sdk_v0_ts", "src", "index.ts");

function run(command, args, label) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `${label} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  return result.stdout;
}

function writeCanonicalEnvelope(filePath) {
  const envelope = run(
    "cargo",
    [
      "run",
      "-p",
      "aura_l2_local_chain_v0",
      "--offline",
      "--",
      "--output",
      "json",
      "run-canonical-pipeline",
      filePath,
    ],
    `canonical pipeline run for ${path.basename(filePath)}`,
  );
  return envelope.trim();
}

const tempDir = mkdtempSync(path.join(tmpdir(), "aura-canonical-fixtures-"));

try {
  const tempModulePath = path.join(tempDir, "index.debug.ts");
  const debugSource =
    `${readFileSync(sdkPath, "utf8")}\n` +
    "export { canonicalPipelineRequestFromBridgeOptionsV0 as __requestFromBridge, writeCanonicalPipelineRequestFileV0 as __writeRequestFile };\n";
  writeFileSync(tempModulePath, debugSource, "utf8");

  const bridgeSdk = await import(pathToFileURL(sdkPath).href);
  const sdk = await import(pathToFileURL(tempModulePath).href);
  const {
    BatchBuilderV0,
    CanonicalPipelineAttestationClaimKindV0,
    CanonicalPipelineAttestationEvidenceKindV0,
    CanonicalPipelineAttestationProofKindV0,
    CanonicalPipelineAttestationScopeV0,
    CanonicalPipelineEvidenceProvenanceTypeV0,
    CanonicalPipelineNetworkModeV0,
    CanonicalPipelineSettlementAnchorTypeV0,
    GenesisBuilderV0,
    ProofSystemV0,
    ScenarioResultV0,
    ZERO32_V0,
    __requestFromBridge,
    __writeRequestFile,
  } = sdk;
  const { runCanonicalPipelineV0 } = bridgeSdk;

  const rollupId = new Uint8Array(32).fill(0xaa);
  const payerAccountId = new Uint8Array(32).fill(0x11);
  const recipientAccountId = new Uint8Array(32).fill(0x22);

  function buildState(accountSpecs) {
    const builder = new GenesisBuilderV0();
    for (const account of accountSpecs) {
      builder.account(account.accountId, account.balance, account.nonce);
    }
    return builder.buildState();
  }

  function buildExecutionBatch(batchNumber, parentBatchCommitment, amount, senderNonce) {
    return new BatchBuilderV0(batchNumber)
      .withParentBatchCommitment(parentBatchCommitment)
      .transfer(payerAccountId, recipientAccountId, senderNonce, amount)
      .build();
  }

  function buildEmptyBatch(batchNumber, parentBatchCommitment) {
    return new BatchBuilderV0(batchNumber).withParentBatchCommitment(parentBatchCommitment).build();
  }

  function buildAttestation(expectedValueUtf8, proofKind, tamper = {}) {
    return {
      attestationSchemaVersion: 2,
      attestationScope:
        CanonicalPipelineAttestationScopeV0.ClaimConsistencyWithProvidedEvidenceOnly,
      attestationProofKind: proofKind,
      normalizationPolicyVersion: 1,
      attestationConstraints: {
        requireUniqueLabels: true,
        maxEvidenceItems: 16n,
        maxTotalNormalizedBytes: 16384n,
      },
      claim: {
        claimKind: CanonicalPipelineAttestationClaimKindV0.NormalizedJsonFieldEqualsUtf8,
        claimPayload: {
          targetLabel: "invoice_record",
          fieldPath: ["invoice", "status"],
          expectedValueUtf8,
        },
      },
      evidenceItems: [
        {
          label: "invoice_record",
          evidenceKind: CanonicalPipelineAttestationEvidenceKindV0.InlineJsonUtf8,
          evidencePayload: {
            payloadUtf8:
              '{\n  "invoice": {\n    "status": "paid",\n    "id": "INV-001"\n  },\n  "note": "Paid in full."\n}\n',
          },
          provenance: {
            provenancePolicyVersion: 1,
            provenanceType: CanonicalPipelineEvidenceProvenanceTypeV0.Inline,
            sourceType: "fixture",
            sourceIdentifier: "invoice_record",
            signature: null,
            timestampUnixSeconds: null,
          },
        },
      ],
      tamperStarkPublicInputsDigest: tamper.publicInputsDigest ?? null,
      tamperStarkProofBytes: tamper.proofBytes ?? null,
    };
  }

  function buildLedgerFromReport(report) {
    return {
      ledgerPolicyVersion: 1,
      payerAccountId,
      totalSupply: report.ledgerSummary.totalSupply,
      burnedSupply: report.ledgerSummary.burnedSupplyAfter,
      accounts: [
        {
          accountId: payerAccountId,
          balance: report.accountingSummary.burnRecord.postBalance,
        },
        {
          accountId: recipientAccountId,
          balance: 250n,
        },
      ],
    };
  }

  function ledgerPayerBalance(ledger) {
    return ledger.accounts[0].balance;
  }

  function buildHead(previousHeadHash, headSequenceNumber) {
    return {
      settlementHeadVersion: 1,
      previousHeadHash,
      headSequenceNumber,
    };
  }

  function buildBridgedTokenAnchor(observedBalance, expectedExternalBalance, connected = true) {
    return {
      tokenPolicyVersion: 1,
      networkMode: CanonicalPipelineNetworkModeV0.Bridged,
      settlementAnchorType: CanonicalPipelineSettlementAnchorTypeV0.External,
      externalBalanceReference: {
        referenceId: "solana://simulated/payer-main",
        observedBalance,
        observedSlot: 123456n,
        connected,
      },
      enforceExternalMatch: true,
      expectedExternalBalance,
    };
  }

  function requestPath(name) {
    return path.join(fixturesDir, name);
  }

  const continuousChainDir = path.join(fixturesDir, "continuous_chain_v1");
  const continuousHeadStatePath = path.join(tempDir, "continuous-chain-head-state.json");
  const continuousChainRunOptions = { headStatePath: continuousHeadStatePath };

  function continuousChainRequestPath(name) {
    return path.join(continuousChainDir, name);
  }

  function writeRequest(name, request) {
    __writeRequestFile(requestPath(name), request);
    return requestPath(name);
  }

  function writeContinuousRequest(name, request) {
    __writeRequestFile(continuousChainRequestPath(name), request);
    return continuousChainRequestPath(name);
  }

  function writeExpectedReport(name, requestName) {
    writeFileSync(
      requestPath(name),
      `${writeCanonicalEnvelope(requestPath(requestName))}\n`,
      "utf8",
    );
  }

  const state0 = buildState([
    { accountId: payerAccountId, balance: 1000n, nonce: 0n },
    { accountId: recipientAccountId, balance: 250n, nonce: 0n },
  ]);
  const batch0Transfer75 = buildExecutionBatch(0n, ZERO32_V0, 75n, 0n);
  const batch0Transfer150 = buildExecutionBatch(0n, ZERO32_V0, 150n, 0n);
  const batch0Empty = buildEmptyBatch(0n, ZERO32_V0);

  const acceptedTransferRequest = __requestFromBridge({
    fixtureName: "accepted_transfer_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Transfer75,
    proofSystem: ProofSystemV0.Stark,
    tokenAnchor: buildBridgedTokenAnchor(1000n, 1000n),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeRequest("accepted_transfer_request.json", acceptedTransferRequest);
  writeExpectedReport("accepted_transfer_expected_report.json", "accepted_transfer_request.json");

  const tamperedProofBindingRequest = __requestFromBridge({
    fixtureName: "tampered_proof_binding_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Transfer150,
    proofSystem: ProofSystemV0.Stark,
    tamperProofBindingDigest: { byteOffset: 0, xorWith: 0xff },
    tokenAnchor: buildBridgedTokenAnchor(1000n, 1000n),
    expectedResult: ScenarioResultV0.VerificationRejected,
  });
  writeRequest("tampered_proof_binding_request.json", tamperedProofBindingRequest);

  const acceptedAttestationRequest = __requestFromBridge({
    fixtureName: "accepted_attestation_mock_pipeline",
    state: state0,
    rollupId,
    batch: batch0Empty,
    proofSystem: ProofSystemV0.Mock,
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Mock),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeRequest("accepted_attestation_request.json", acceptedAttestationRequest);
  writeExpectedReport(
    "accepted_attestation_expected_report.json",
    "accepted_attestation_request.json",
  );

  const acceptedStarkAttestationRequest = __requestFromBridge({
    fixtureName: "accepted_attestation_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Empty,
    proofSystem: ProofSystemV0.Mock,
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Stark),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeRequest("accepted_stark_attestation_request.json", acceptedStarkAttestationRequest);

  const tamperedStarkAttestationRequest = __requestFromBridge({
    fixtureName: "tampered_attestation_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Empty,
    proofSystem: ProofSystemV0.Mock,
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Stark, {
      publicInputsDigest: { byteOffset: 0, xorWith: 0xff },
    }),
    expectedResult: ScenarioResultV0.VerificationRejected,
  });
  writeRequest("tampered_stark_attestation_request.json", tamperedStarkAttestationRequest);

  const tamperedAttestationRequest = __requestFromBridge({
    fixtureName: "tampered_attestation_consistency_mock_pipeline",
    state: state0,
    rollupId,
    batch: batch0Empty,
    proofSystem: ProofSystemV0.Mock,
    attestation: buildAttestation("void", CanonicalPipelineAttestationProofKindV0.Mock),
    expectedResult: ScenarioResultV0.ExecutionRejected,
  });
  writeRequest("tampered_attestation_request.json", tamperedAttestationRequest);

  const step1Request = __requestFromBridge({
    fixtureName: "ledger_replay_step1_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Transfer75,
    proofSystem: ProofSystemV0.Stark,
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeRequest("ledger_replay_step1_request.json", step1Request);
  const step1Report = runCanonicalPipelineV0(requestPath("ledger_replay_step1_request.json"));

  const state1 = buildState([
    { accountId: payerAccountId, balance: 925n, nonce: 1n },
    { accountId: recipientAccountId, balance: 325n, nonce: 0n },
  ]);
  const step1HeadHash = step1Report.headTransitionSummary.currentHeadHash;
  const step1PostStateRoot = step1Report.executedPostStateRoot;
  const step1Ledger = buildLedgerFromReport(step1Report);

  const step2Request = __requestFromBridge({
    fixtureName: "ledger_replay_step2_stark_pipeline",
    state: state1,
    rollupId,
    batch: buildExecutionBatch(1n, step1PostStateRoot, 25n, 1n),
    proofSystem: ProofSystemV0.Stark,
    ledger: step1Ledger,
    head: buildHead(step1HeadHash, 2n),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeRequest("ledger_replay_step2_request.json", step2Request);

  const mixedReplayAttestationRequest = __requestFromBridge({
    fixtureName: "mixed_replay_attestation_mock_pipeline",
    state: state1,
    rollupId,
    batch: buildEmptyBatch(1n, step1PostStateRoot),
    proofSystem: ProofSystemV0.Mock,
    ledger: step1Ledger,
    head: buildHead(step1HeadHash, 2n),
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Mock),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeRequest("mixed_replay_attestation_request.json", mixedReplayAttestationRequest);

  const externalAnchorMismatchRequest = __requestFromBridge({
    fixtureName: "external_anchor_mismatch_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Transfer75,
    proofSystem: ProofSystemV0.Stark,
    tokenAnchor: buildBridgedTokenAnchor(997n, 1000n),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeRequest("external_anchor_mismatch_request.json", externalAnchorMismatchRequest);

  const disconnectedAnchorRequest = __requestFromBridge({
    fixtureName: "external_anchor_disconnected_stark_pipeline",
    state: state0,
    rollupId,
    batch: batch0Transfer75,
    proofSystem: ProofSystemV0.Stark,
    tokenAnchor: buildBridgedTokenAnchor(null, 1000n, false),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeRequest("external_anchor_disconnected_request.json", disconnectedAnchorRequest);

  rmSync(continuousChainDir, {
    recursive: true,
    force: true,
  });
  mkdirSync(continuousChainDir, { recursive: true });

  const continuousChainReadme = `# Continuous Canonical Chain V1 Fixtures

Classification: \`ACTIVE\`

This corpus exercises the one canonical active request/report pipeline under authoritative head persistence.

Canonical use:

- run these fixtures in order with \`--head-state <path>\`
- authoritative head persistence advances on every report except \`settlement_head_mismatch\`
- settlement rejection or verification rejection still burns deterministically and still emits a canonical report
- only accepted execution commits a new state root; rejected settlement leaves the prior committed state in place

Non-authoritative use:

- running these fixtures stateless is allowed for support and diagnostics
- stateless results must not be mistaken for authoritative head truth

Sequence order:

1. \`step01_execution_accept_request.json\`
2. \`step02_head_mismatch_reject_request.json\`
3. \`step03_execution_accept_request.json\`
4. \`step04_anchor_mismatch_reject_request.json\`
5. \`step05_attestation_accept_request.json\`
6. \`step06_disconnected_anchor_accept_request.json\`
7. \`step07_replay_reject_request.json\`
8. \`step08_stark_attestation_accept_request.json\`
9. \`step09_attestation_anchor_reject_request.json\`
10. \`step10_execution_accept_request.json\`
11. \`step11_tampered_stark_attestation_reject_request.json\`
12. \`step12_attestation_accept_request.json\`
`;
  writeFileSync(path.join(continuousChainDir, "README.md"), continuousChainReadme, "utf8");

  const chainStep01Request = __requestFromBridge({
    fixtureName: "continuous_chain_step01_execution_accept",
    state: state0,
    rollupId,
    batch: batch0Transfer75,
    proofSystem: ProofSystemV0.Stark,
    tokenAnchor: buildBridgedTokenAnchor(1000n, 1000n),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step01_execution_accept_request.json", chainStep01Request);
  const chainStep01Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step01_execution_accept_request.json"),
    continuousChainRunOptions,
  );

  const stateAfterStep01 = buildState([
    { accountId: payerAccountId, balance: 925n, nonce: 1n },
    { accountId: recipientAccountId, balance: 325n, nonce: 0n },
  ]);
  const headAfterStep01 = chainStep01Report.headTransitionSummary.currentHeadHash;
  const rootAfterStep01 = chainStep01Report.executedPostStateRoot;
  const ledgerAfterStep01 = buildLedgerFromReport(chainStep01Report);

  const chainStep02Request = __requestFromBridge({
    fixtureName: "continuous_chain_step02_head_mismatch_reject",
    state: stateAfterStep01,
    rollupId,
    batch: buildExecutionBatch(0n, ZERO32_V0, 25n, 1n),
    proofSystem: ProofSystemV0.Stark,
    ledger: ledgerAfterStep01,
    head: buildHead(ZERO32_V0, 2n),
    tokenAnchor: buildBridgedTokenAnchor(
      ledgerPayerBalance(ledgerAfterStep01),
      ledgerPayerBalance(ledgerAfterStep01),
    ),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeContinuousRequest("step02_head_mismatch_reject_request.json", chainStep02Request);
  const chainStep02Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step02_head_mismatch_reject_request.json"),
    continuousChainRunOptions,
  );
  const ledgerAfterStep02 = buildLedgerFromReport(chainStep02Report);

  const chainStep03Request = __requestFromBridge({
    fixtureName: "continuous_chain_step03_execution_accept",
    state: stateAfterStep01,
    rollupId,
    batch: buildExecutionBatch(0n, ZERO32_V0, 25n, 1n),
    proofSystem: ProofSystemV0.Stark,
    ledger: ledgerAfterStep02,
    head: buildHead(headAfterStep01, 2n),
    tokenAnchor: buildBridgedTokenAnchor(
      ledgerPayerBalance(ledgerAfterStep02),
      ledgerPayerBalance(ledgerAfterStep02),
    ),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step03_execution_accept_request.json", chainStep03Request);
  const chainStep03Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step03_execution_accept_request.json"),
    continuousChainRunOptions,
  );

  const stateAfterStep03 = buildState([
    { accountId: payerAccountId, balance: 900n, nonce: 2n },
    { accountId: recipientAccountId, balance: 350n, nonce: 0n },
  ]);
  const headAfterStep03 = chainStep03Report.headTransitionSummary.currentHeadHash;
  const rootAfterStep03 = chainStep03Report.executedPostStateRoot;
  const ledgerAfterStep03 = buildLedgerFromReport(chainStep03Report);

  const chainStep04Request = __requestFromBridge({
    fixtureName: "continuous_chain_step04_anchor_mismatch_reject",
    state: stateAfterStep03,
    rollupId,
    batch: buildExecutionBatch(0n, ZERO32_V0, 10n, 2n),
    proofSystem: ProofSystemV0.Stark,
    ledger: ledgerAfterStep03,
    head: buildHead(headAfterStep03, 3n),
    tokenAnchor: buildBridgedTokenAnchor(
      ledgerPayerBalance(ledgerAfterStep03) - 3n,
      ledgerPayerBalance(ledgerAfterStep03),
    ),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeContinuousRequest("step04_anchor_mismatch_reject_request.json", chainStep04Request);
  const chainStep04Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step04_anchor_mismatch_reject_request.json"),
    continuousChainRunOptions,
  );
  const headAfterStep04 = chainStep04Report.headTransitionSummary.currentHeadHash;
  const ledgerAfterStep04 = buildLedgerFromReport(chainStep04Report);

  const chainStep05Request = __requestFromBridge({
    fixtureName: "continuous_chain_step05_attestation_accept",
    state: stateAfterStep03,
    rollupId,
    batch: buildEmptyBatch(0n, ZERO32_V0),
    proofSystem: ProofSystemV0.Mock,
    ledger: ledgerAfterStep04,
    head: buildHead(headAfterStep04, 4n),
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Mock),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step05_attestation_accept_request.json", chainStep05Request);
  const chainStep05Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step05_attestation_accept_request.json"),
    continuousChainRunOptions,
  );

  const headAfterStep05 = chainStep05Report.headTransitionSummary.currentHeadHash;
  const ledgerAfterStep05 = buildLedgerFromReport(chainStep05Report);

  const chainStep06Request = __requestFromBridge({
    fixtureName: "continuous_chain_step06_disconnected_anchor_accept",
    state: stateAfterStep03,
    rollupId,
    batch: buildExecutionBatch(0n, ZERO32_V0, 10n, 2n),
    proofSystem: ProofSystemV0.Stark,
    ledger: ledgerAfterStep05,
    head: buildHead(headAfterStep05, 5n),
    tokenAnchor: buildBridgedTokenAnchor(null, ledgerPayerBalance(ledgerAfterStep05), false),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step06_disconnected_anchor_accept_request.json", chainStep06Request);
  const chainStep06Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step06_disconnected_anchor_accept_request.json"),
    continuousChainRunOptions,
  );

  const stateAfterStep06 = buildState([
    { accountId: payerAccountId, balance: 890n, nonce: 3n },
    { accountId: recipientAccountId, balance: 360n, nonce: 0n },
  ]);
  const headAfterStep06 = chainStep06Report.headTransitionSummary.currentHeadHash;
  const rootAfterStep06 = chainStep06Report.executedPostStateRoot;
  const ledgerAfterStep06 = buildLedgerFromReport(chainStep06Report);

  const chainStep07Request = __requestFromBridge({
    fixtureName: "continuous_chain_step07_replay_reject",
    state: stateAfterStep03,
    rollupId,
    batch: buildExecutionBatch(0n, ZERO32_V0, 10n, 2n),
    proofSystem: ProofSystemV0.Stark,
    ledger: ledgerAfterStep05,
    head: buildHead(headAfterStep05, 5n),
    tokenAnchor: buildBridgedTokenAnchor(null, ledgerPayerBalance(ledgerAfterStep05), false),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeContinuousRequest("step07_replay_reject_request.json", chainStep07Request);
  const chainStep07Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step07_replay_reject_request.json"),
    continuousChainRunOptions,
  );
  const ledgerAfterStep07 = buildLedgerFromReport(chainStep07Report);

  const chainStep08Request = __requestFromBridge({
    fixtureName: "continuous_chain_step08_stark_attestation_accept",
    state: stateAfterStep06,
    rollupId,
    batch: buildEmptyBatch(0n, ZERO32_V0),
    proofSystem: ProofSystemV0.Mock,
    ledger: ledgerAfterStep07,
    head: buildHead(headAfterStep06, 6n),
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Stark),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step08_stark_attestation_accept_request.json", chainStep08Request);
  const chainStep08Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step08_stark_attestation_accept_request.json"),
    continuousChainRunOptions,
  );

  const headAfterStep08 = chainStep08Report.headTransitionSummary.currentHeadHash;
  const rootAfterStep08 = chainStep08Report.executedPostStateRoot;
  const ledgerAfterStep08 = buildLedgerFromReport(chainStep08Report);

  const chainStep09Request = __requestFromBridge({
    fixtureName: "continuous_chain_step09_attestation_anchor_reject",
    state: stateAfterStep06,
    rollupId,
    batch: buildEmptyBatch(0n, ZERO32_V0),
    proofSystem: ProofSystemV0.Mock,
    ledger: ledgerAfterStep08,
    head: buildHead(headAfterStep08, 7n),
    tokenAnchor: buildBridgedTokenAnchor(
      ledgerPayerBalance(ledgerAfterStep08) - 7n,
      ledgerPayerBalance(ledgerAfterStep08),
    ),
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Mock),
    expectedResult: ScenarioResultV0.SettlementRejected,
  });
  writeContinuousRequest("step09_attestation_anchor_reject_request.json", chainStep09Request);
  const chainStep09Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step09_attestation_anchor_reject_request.json"),
    continuousChainRunOptions,
  );
  const headAfterStep09 = chainStep09Report.headTransitionSummary.currentHeadHash;
  const ledgerAfterStep09 = buildLedgerFromReport(chainStep09Report);

  const chainStep10Request = __requestFromBridge({
    fixtureName: "continuous_chain_step10_execution_accept",
    state: stateAfterStep06,
    rollupId,
    batch: buildExecutionBatch(0n, ZERO32_V0, 5n, 3n),
    proofSystem: ProofSystemV0.Stark,
    ledger: ledgerAfterStep09,
    head: buildHead(headAfterStep09, 8n),
    tokenAnchor: buildBridgedTokenAnchor(
      ledgerPayerBalance(ledgerAfterStep09),
      ledgerPayerBalance(ledgerAfterStep09),
    ),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step10_execution_accept_request.json", chainStep10Request);
  const chainStep10Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step10_execution_accept_request.json"),
    continuousChainRunOptions,
  );

  const stateAfterStep10 = buildState([
    { accountId: payerAccountId, balance: 885n, nonce: 4n },
    { accountId: recipientAccountId, balance: 365n, nonce: 0n },
  ]);
  const headAfterStep10 = chainStep10Report.headTransitionSummary.currentHeadHash;
  const rootAfterStep10 = chainStep10Report.executedPostStateRoot;
  const ledgerAfterStep10 = buildLedgerFromReport(chainStep10Report);

  const chainStep11Request = __requestFromBridge({
    fixtureName: "continuous_chain_step11_tampered_stark_attestation_reject",
    state: stateAfterStep10,
    rollupId,
    batch: buildEmptyBatch(0n, ZERO32_V0),
    proofSystem: ProofSystemV0.Mock,
    ledger: ledgerAfterStep10,
    head: buildHead(headAfterStep10, 9n),
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Stark, {
      publicInputsDigest: { byteOffset: 0, xorWith: 0xff },
    }),
    expectedResult: ScenarioResultV0.VerificationRejected,
  });
  writeContinuousRequest("step11_tampered_stark_attestation_reject_request.json", chainStep11Request);
  const chainStep11Report = runCanonicalPipelineV0(
    continuousChainRequestPath("step11_tampered_stark_attestation_reject_request.json"),
    continuousChainRunOptions,
  );
  const headAfterStep11 = chainStep11Report.headTransitionSummary.currentHeadHash;
  const ledgerAfterStep11 = buildLedgerFromReport(chainStep11Report);

  const chainStep12Request = __requestFromBridge({
    fixtureName: "continuous_chain_step12_attestation_accept",
    state: stateAfterStep10,
    rollupId,
    batch: buildEmptyBatch(0n, ZERO32_V0),
    proofSystem: ProofSystemV0.Mock,
    ledger: ledgerAfterStep11,
    head: buildHead(headAfterStep11, 10n),
    attestation: buildAttestation("paid", CanonicalPipelineAttestationProofKindV0.Mock),
    expectedResult: ScenarioResultV0.Accepted,
  });
  writeContinuousRequest("step12_attestation_accept_request.json", chainStep12Request);
  runCanonicalPipelineV0(
    continuousChainRequestPath("step12_attestation_accept_request.json"),
    continuousChainRunOptions,
  );

  process.stdout.write("Canonical pipeline fixtures regenerated.\n");
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
