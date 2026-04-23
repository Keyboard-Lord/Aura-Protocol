import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AuraTypescriptSdkErrorV0,
  BatchBuilderV0,
  bytesFromHexV0,
  CanonicalPipelineRequestKindV0,
  computeCanonicalPipelineBurnUnitsV0,
  deriveTransitionArtifactsV0,
  executeBatchV0,
  GenesisBuilderV0,
  hexFromBytesV0,
  loadCanonicalPipelineRequestV0,
  loadGenesisFixtureV0,
  loadProofVectorV0,
  parseRustCanonicalPipelineReportJsonV0,
  ProofSystemV0,
  PUBLIC_INPUT_SCHEMA_LEN_V0,
  parseRustProofVectorReportJsonV0,
  parseRustScenarioReportJsonV0,
  runCanonicalPipelineV0,
  runProofVectorV0,
  runRustFlowV0,
  runRustScenarioV0,
  ScenarioResultV0,
  transferTxV0,
  verifyProofVectorV0,
  ZERO32_V0,
} from "./index.ts";

function repoRootV0(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
}

function withTempProofVectorMutationV0(
  fixtureName: string,
  mutate: (value: any) => void,
  run: (filePath: string) => void,
): void {
  const dir = mkdtempSync(path.join(tmpdir(), "aura-sdk-v0-ts-proof-vector-"));
  try {
    const root = repoRootV0();
    const sourcePath = path.join(root, "fixtures/l2_proof_vectors_v1", fixtureName);
    const filePath = path.join(dir, fixtureName);
    const parsed = JSON.parse(readFileSync(sourcePath, "utf8"));
    mutate(parsed);
    writeFileSync(filePath, JSON.stringify(parsed, null, 2), "utf8");
    run(filePath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function withTempCanonicalPipelineMutationV0(
  fixtureName: string,
  mutate: (value: Record<string, unknown>) => void,
  run: (filePath: string) => void,
): void {
  const dir = mkdtempSync(path.join(tmpdir(), "aura-sdk-v0-ts-canonical-pipeline-fixture-"));
  try {
    const sourcePath = path.join(repoRootV0(), "fixtures/l2_canonical_pipeline_v1", fixtureName);
    const filePath = path.join(dir, fixtureName);
    const parsed = JSON.parse(readFileSync(sourcePath, "utf8")) as Record<string, unknown>;
    mutate(parsed);
    writeFileSync(filePath, JSON.stringify(parsed, null, 2), "utf8");
    run(filePath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function withTempHeadStateV0(run: (headStatePath: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "aura-sdk-v0-ts-head-state-"));
  try {
    run(path.join(dir, "head-state.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function canonicalStateAndBatchV0() {
  const rollupId = new Uint8Array(32).fill(0xaa);
  const state = new GenesisBuilderV0()
    .account(new Uint8Array(32).fill(0x11), 90n, 0n)
    .account(new Uint8Array(32).fill(0x22), 10n, 0n)
    .buildState();
  const batch = new BatchBuilderV0(0n)
    .withParentBatchCommitment(ZERO32_V0)
    .transfer(new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22), 0n, 9n)
    .build();
  return { rollupId, state, batch };
}

function stateFromAccountsV0(accounts: ReadonlyArray<{ accountId: Uint8Array; balance: bigint; nonce: bigint }>) {
  const builder = new GenesisBuilderV0();
  for (const account of accounts) {
    builder.account(account.accountId, account.balance, account.nonce);
  }
  return builder.buildState();
}

function canonicalPipelineFixturePathV0(name: string): string {
  return path.join(repoRootV0(), "fixtures/l2_canonical_pipeline_v1", name);
}

function canonicalPipelineExpectedReportEnvelopeV0(): Record<string, any> {
  return JSON.parse(
    readFileSync(canonicalPipelineFixturePathV0("accepted_transfer_expected_report.json"), "utf8"),
  ) as Record<string, any>;
}

function canonicalPipelineBridgeEnvelopeFromFixtureV0(fixtureName: string): Record<string, any> {
  const root = repoRootV0();
  const requestPath = canonicalPipelineFixturePathV0(fixtureName);
  const result = spawnSync(
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
      requestPath,
    ],
    {
      cwd: root,
      encoding: "utf8",
    },
  );

  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout) as Record<string, any>;
}

const textEncoderV0 = new TextEncoder();
const ATTESTATION_EVIDENCE_DIGEST_HEX_V0 =
  "c4042fb44511abd94098ab34a5287ad28cd0cad007ce17586e17be3d013719e9";

function u32LeV0(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function u64LeV0(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
}

function concatBytesTestV0(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function lenPrefixedBytesTestV0(bytes: Uint8Array): Uint8Array {
  return concatBytesTestV0(u64LeV0(bytes.length), bytes);
}

function canonicalPipelineProvenanceSignatureMessageBytesTestV0(
  label: string,
  provenance: Record<string, any>,
): Uint8Array {
  return concatBytesTestV0(
    textEncoderV0.encode("AURA_L2_CANONICAL_PIPELINE_ATTESTATION_SIGNATURE_V1"),
    lenPrefixedBytesTestV0(textEncoderV0.encode(label)),
    bytesFromHexV0(ATTESTATION_EVIDENCE_DIGEST_HEX_V0),
    u32LeV0(provenance.provenance_policy_version as number),
    lenPrefixedBytesTestV0(textEncoderV0.encode(provenance.provenance_type as string)),
    lenPrefixedBytesTestV0(textEncoderV0.encode(provenance.source_type as string)),
    lenPrefixedBytesTestV0(textEncoderV0.encode(provenance.source_identifier as string)),
    provenance.timestamp_unix_seconds === undefined
      ? Uint8Array.of(0)
      : concatBytesTestV0(Uint8Array.of(1), u64LeV0(provenance.timestamp_unix_seconds as number)),
  );
}

function setSignedProvenanceJsonV0(parsed: Record<string, any>, validSignature: boolean): void {
  const attestation = parsed.attestation as Record<string, any>;
  const evidenceItem = (attestation.evidence_items as Array<Record<string, any>>)[0]!;
  const provenance = evidenceItem.provenance as Record<string, any>;
  provenance.provenance_type = "signed_blob";
  provenance.source_type = "signed_fixture";
  provenance.source_identifier = "invoice_record:signed";
  provenance.timestamp_unix_seconds = 1711111111;
  delete provenance.signature;

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const message = canonicalPipelineProvenanceSignatureMessageBytesTestV0(
    evidenceItem.label as string,
    provenance,
  );
  const signature = cryptoSign(null, Buffer.from(message), privateKey);
  if (!validSignature) {
    signature[0] ^= 0xff;
  }
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const signerPublicKey = publicKeyDer.subarray(publicKeyDer.length - 32);
  provenance.signature = {
    signer_public_key_hex: signerPublicKey.toString("hex"),
    signature_hex: signature.toString("hex"),
  };
}

test("native transition/public-input derivation stays deterministic", () => {
  const { rollupId, state, batch } = canonicalStateAndBatchV0();
  const first = deriveTransitionArtifactsV0(executeBatchV0(state, rollupId, batch));
  const second = deriveTransitionArtifactsV0(executeBatchV0(state, rollupId, batch));

  assert.equal(first.publicInputBytes.length, PUBLIC_INPUT_SCHEMA_LEN_V0);
  assert.equal(
    hexFromBytesV0(first.transitionBindingHash),
    hexFromBytesV0(second.transitionBindingHash),
  );
  assert.equal(
    hexFromBytesV0(first.publicInputs.rollupId),
    hexFromBytesV0(second.publicInputs.rollupId),
  );
});

test("typescript public-input derivation matches rust bridge binding hash", () => {
  const { rollupId, state, batch } = canonicalStateAndBatchV0();
  const native = deriveTransitionArtifactsV0(executeBatchV0(state, rollupId, batch));
  const bridged = runRustFlowV0({
    state,
    rollupId,
    batch,
    proofSystem: ProofSystemV0.Mock,
  });

  assert.equal(bridged.report.actualResult, ScenarioResultV0.Accepted);
  assert.equal(
    hexFromBytesV0(native.transitionBindingHash),
    hexFromBytesV0(bridged.report.transitionBindingHash!),
  );
});

test("typescript sdk native flow matches rust bridge state roots and binding hash", () => {
  const { rollupId, state, batch } = canonicalStateAndBatchV0();
  const native = deriveTransitionArtifactsV0(executeBatchV0(state, rollupId, batch));
  const bridged = runRustFlowV0({
    state,
    rollupId,
    batch,
    proofSystem: ProofSystemV0.Stark,
  });

  assert.equal(bridged.report.actualResult, ScenarioResultV0.Accepted);
  assert.equal(
    hexFromBytesV0(native.transition.preStateRoot),
    hexFromBytesV0(bridged.report.preStateRoot),
  );
  assert.equal(
    hexFromBytesV0(native.transition.postStateRoot),
    hexFromBytesV0(bridged.report.postStateRoot!),
  );
  assert.equal(
    hexFromBytesV0(native.transitionBindingHash),
    hexFromBytesV0(bridged.report.transitionBindingHash!),
  );
});

test("mock scenario flow succeeds through rust bridge", () => {
  const root = repoRootV0();
  const report = runRustScenarioV0(
    path.join(root, "fixtures/l2_local_v1/genesis_state.json"),
    path.join(root, "fixtures/l2_local_v1/accepted_transition_example.json"),
    ProofSystemV0.Mock,
  );
  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
});

test("real stark scenario flow succeeds through rust bridge", () => {
  const root = repoRootV0();
  const report = runRustScenarioV0(
    path.join(root, "fixtures/l2_local_v1/genesis_state.json"),
    path.join(root, "fixtures/l2_local_v1/accepted_transition_example.json"),
    ProofSystemV0.Stark,
  );
  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
});

test("tampered scenario rejects where supported", () => {
  const root = repoRootV0();
  const report = runRustScenarioV0(
    path.join(root, "fixtures/l2_local_v1/genesis_state.json"),
    path.join(root, "fixtures/l2_local_v1/tampered_proof_artifact.json"),
    ProofSystemV0.Stark,
  );
  assert.equal(report.actualResult, ScenarioResultV0.VerificationRejected);
});

test("canonical pipeline request fixture loads with the pinned contract", () => {
  const request = loadCanonicalPipelineRequestV0(
    canonicalPipelineFixturePathV0("accepted_transfer_request.json"),
  );

  assert.equal(request.pipelineId, "aura_local_pipeline_v1");
  assert.equal(request.proofSystem, ProofSystemV0.Stark);
  assert.equal(request.expectedResult, ScenarioResultV0.Accepted);
  assert.equal(request.economic.requestKind, CanonicalPipelineRequestKindV0.Execution);
  assert.equal(request.economic.declaredFeeUnits, 49n);
  assert.equal(computeCanonicalPipelineBurnUnitsV0(request), 49n);
  assert.equal(request.accounting.paymentIntent, "burn_to_produce_canonical_truth");
  assert.equal(request.ledger.totalSupply, 1250n);
  assert.equal(request.batch.transactions.length, 1);
  assert.equal(request.head.headSequenceNumber, 1n);
  assert.equal(request.walletBinding.walletBindingVersion, 1);
  assert.equal(request.tokenAnchor.networkMode, "bridged");
});

test("canonical pipeline accepted request matches the pinned expected report", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("accepted_transfer_request.json"),
  );
  const expected = parseRustCanonicalPipelineReportJsonV0(
    readFileSync(
      canonicalPipelineFixturePathV0("accepted_transfer_expected_report.json"),
      "utf8",
    ),
  );

  assert.deepEqual(report, expected);
});

test("canonical pipeline rejection request fails closed through the same command", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("tampered_proof_binding_request.json"),
  );

  assert.equal(report.actualResult, ScenarioResultV0.VerificationRejected);
  assert.equal(report.burnSummary.computedBurnUnits, 49n);
  assert.equal(report.publicInputs !== null, true);
  assert.equal(report.proofArtifact !== null, true);
  assert.equal(report.publicInputs?.requestSummaryConsistency?.allFieldsMatch, true);
  assert.equal(report.proofArtifact?.consistency.proofBindingDigestMatchesRecomputed, false);
  assert.equal(report.accountingSummary.settlementRecord.settlementStatus, "rejected");
  assert.equal(report.accountingSummary.consumedBurnUnits, 49n);
});

test("wallet binding mismatch is loader-valid but settlement-rejected", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.wallet_binding as Record<string, unknown>).account_id_hex = "22".repeat(32);
      parsed.expected_result = "SETTLEMENT_REJECTED";
    },
    (filePath) => {
      const request = loadCanonicalPipelineRequestV0(filePath);
      const report = runCanonicalPipelineV0(filePath);

      assert.equal(hexFromBytesV0(request.walletBinding.accountId), "22".repeat(32));
      assert.equal(report.actualResult, ScenarioResultV0.SettlementRejected);
      assert.equal(report.statusExplanation.failureReasonCode, "wallet_binding_mismatch");
      assert.equal(report.walletBindingSummary.bindingConsistentWithAccount, false);
      assert.equal(report.accountingSummary.settlementRecord.settlementStatus, "rejected");
      assert.equal(report.burnSummary.consumedBurnUnits, 49n);
      assert.notEqual(report.publicInputs, null);
      assert.notEqual(report.proofArtifact, null);
    },
  );
});

test("canonical attestation request stays on the same pipeline with deterministic burn", () => {
  const request = loadCanonicalPipelineRequestV0(
    canonicalPipelineFixturePathV0("accepted_attestation_request.json"),
  );
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("accepted_attestation_request.json"),
  );

  assert.equal(request.economic.requestKind, CanonicalPipelineRequestKindV0.Attestation);
  assert.equal(request.batch.transactions.length, 0);
  assert.equal(computeCanonicalPipelineBurnUnitsV0(request), 48n);
  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
  assert.equal(report.requestAudit.txCount, 0n);
  assert.equal(report.burnSummary.requestKind, CanonicalPipelineRequestKindV0.Attestation);
  assert.equal(report.burnSummary.computedBurnUnits, 48n);
  assert.equal(
    hexFromBytesV0(report.attestationSummary!.evidenceSummary.evidenceRootDigest),
    "987eed3779fdbc0008b7b3e8a5bff4b64252c53105d6aa440e74fbe710e977fc",
  );
  assert.equal(report.attestationSummary?.consistencyResult.consistent, true);
});

test("canonical attestation request matches the pinned expected report", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("accepted_attestation_request.json"),
  );
  const expected = parseRustCanonicalPipelineReportJsonV0(
    readFileSync(
      canonicalPipelineFixturePathV0("accepted_attestation_expected_report.json"),
      "utf8",
    ),
  );

  assert.deepEqual(report, expected);
});

test("provenance without signature relevance keeps the attestation outcome stable", () => {
  const baseline = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("accepted_attestation_request.json"),
  );

  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      const provenance = ((((parsed.attestation as Record<string, unknown>).evidence_items as Array<Record<string, unknown>>)[0]
        .provenance) as Record<string, unknown>);
      provenance.source_type = "archive";
      provenance.source_identifier = "invoice_replay";
    },
    (filePath) => {
      const variant = runCanonicalPipelineV0(filePath);
      const baselineItem = baseline.attestationSummary!.evidenceSummary.evidenceItems[0]!;
      const variantItem = variant.attestationSummary!.evidenceSummary.evidenceItems[0]!;

      assert.equal(variant.actualResult, ScenarioResultV0.Accepted);
      assert.equal(
        baseline.attestationSummary?.attestationStatus,
        variant.attestationSummary?.attestationStatus,
      );
      assert.deepEqual(
        baseline.attestationSummary?.consistencyResult,
        variant.attestationSummary?.consistencyResult,
      );
      assert.equal(
        hexFromBytesV0(baseline.attestationSummary!.evidenceSummary.evidenceRootDigest),
        hexFromBytesV0(variant.attestationSummary!.evidenceSummary.evidenceRootDigest),
      );
      assert.equal(
        hexFromBytesV0(baselineItem.evidenceDigest),
        hexFromBytesV0(variantItem.evidenceDigest),
      );
      assert.equal(baselineItem.normalizedPayloadUtf8, variantItem.normalizedPayloadUtf8);
      assert.notEqual(
        hexFromBytesV0(baselineItem.provenanceDigest),
        hexFromBytesV0(variantItem.provenanceDigest),
      );
      assert.notEqual(
        hexFromBytesV0(baseline.provenanceSummary!.provenanceRootDigest),
        hexFromBytesV0(variant.provenanceSummary!.provenanceRootDigest),
      );
    },
  );
});

test("valid versus invalid provenance signatures only change signature validation surfaces", () => {
  let validReport: ReturnType<typeof runCanonicalPipelineV0> | null = null;

  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      setSignedProvenanceJsonV0(parsed, true);
      (parsed.economic as Record<string, unknown>).declared_fee_units = 52;
    },
    (filePath) => {
      validReport = runCanonicalPipelineV0(filePath);
    },
  );

  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      setSignedProvenanceJsonV0(parsed, false);
      (parsed.economic as Record<string, unknown>).declared_fee_units = 52;
      parsed.expected_result = "EXECUTION_REJECTED";
    },
    (filePath) => {
      const invalidReport = runCanonicalPipelineV0(filePath);
      const validItem = validReport!.attestationSummary!.evidenceSummary.evidenceItems[0]!;
      const invalidItem = invalidReport.attestationSummary!.evidenceSummary.evidenceItems[0]!;

      assert.equal(
        hexFromBytesV0(validReport!.attestationSummary!.evidenceSummary.evidenceRootDigest),
        hexFromBytesV0(invalidReport.attestationSummary!.evidenceSummary.evidenceRootDigest),
      );
      assert.equal(hexFromBytesV0(validItem.evidenceDigest), hexFromBytesV0(invalidItem.evidenceDigest));
      assert.equal(validItem.normalizedPayloadUtf8, invalidItem.normalizedPayloadUtf8);
      assert.notEqual(
        hexFromBytesV0(validItem.provenanceDigest),
        hexFromBytesV0(invalidItem.provenanceDigest),
      );
      assert.equal(
        validReport!.attestationSummary!.consistencyResult.consistent,
        invalidReport.attestationSummary!.consistencyResult.consistent,
      );
      assert.equal(validReport!.provenanceSummary?.allSignatureChecksPassed, true);
      assert.equal(invalidReport.provenanceSummary?.allSignatureChecksPassed, false);
      assert.equal(invalidReport.statusExplanation.failureReasonCode, "provenance_signature_invalid");
      assert.equal(invalidReport.publicInputs, null);
      assert.equal(invalidReport.proofArtifact, null);
    },
  );
});

test("canonical pipeline reports remain identical across duplicate runs", () => {
  const fixturePath = canonicalPipelineFixturePathV0("accepted_transfer_request.json");
  const first = runCanonicalPipelineV0(fixturePath);
  const second = runCanonicalPipelineV0(fixturePath);

  assert.deepEqual(first, second);
});

test("canonical pipeline ledger replay stays deterministic across sequential burns", () => {
  const step1Path = canonicalPipelineFixturePathV0("ledger_replay_step1_request.json");
  const step2Path = canonicalPipelineFixturePathV0("ledger_replay_step2_request.json");
  const step1First = runCanonicalPipelineV0(step1Path);
  const step1Second = runCanonicalPipelineV0(step1Path);
  const step2 = runCanonicalPipelineV0(step2Path);

  assert.deepEqual(step1First, step1Second);
  assert.equal(step1First.actualResult, ScenarioResultV0.Accepted);
  assert.equal(step2.actualResult, ScenarioResultV0.SettlementRejected);
  assert.equal(step1First.accountingSummary.burnRecord.postBalance, step2.accountingSummary.burnRecord.preBalance);
  assert.equal(step1First.ledgerSummary.burnedSupplyAfter, step2.ledgerSummary.burnedSupplyBefore);
  assert.equal(step2.accountingSummary.settlementRecord.settlementStatus, "rejected");
  assert.equal(step2.ledgerSummary.burnedSupplyAfter, 94n);
  assert.equal(step2.headTransitionSummary.headSequenceNumber, 2n);
});

test("canonical tampered attestation request fails closed on the same pipeline", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("tampered_attestation_request.json"),
  );

  assert.equal(report.actualResult, ScenarioResultV0.ExecutionRejected);
  assert.equal(report.burnSummary.requestKind, CanonicalPipelineRequestKindV0.Attestation);
  assert.equal(report.burnSummary.computedBurnUnits, 48n);
  assert.equal(report.burnSummary.burnConsumed, true);
  assert.equal(report.publicInputs, null);
  assert.equal(report.proofArtifact, null);
  assert.equal(report.attestationSummary?.attestationStatus, "rejected");
  assert.equal(report.attestationSummary?.consistencyResult.consistent, false);
  assert.equal(report.attestationSummary?.attestationFailureReason.reason, "consistency_mismatch");
  assert.equal(report.attestationProofSummary?.proofKind, "MOCK");
  assert.equal(report.attestationProofSummary?.verificationPassed, false);
  assert.equal(report.accountingSummary.settlementRecord.settlementStatus, "not_run");
});

test("canonical mixed execution and attestation replay stays deterministic", () => {
  const execution = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("ledger_replay_step1_request.json"),
  );
  const attestationFirst = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("mixed_replay_attestation_request.json"),
  );
  const attestationSecond = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("mixed_replay_attestation_request.json"),
  );

  assert.deepEqual(attestationFirst, attestationSecond);
  assert.equal(execution.actualResult, ScenarioResultV0.Accepted);
  assert.equal(attestationFirst.actualResult, ScenarioResultV0.SettlementRejected);
  assert.equal(execution.accountingSummary.burnRecord.postBalance, attestationFirst.accountingSummary.burnRecord.preBalance);
  assert.equal(execution.ledgerSummary.burnedSupplyAfter, attestationFirst.ledgerSummary.burnedSupplyBefore);
  assert.equal(attestationFirst.attestationSummary?.attestationStatus, "rejected");
  assert.equal(attestationFirst.attestationSummary?.consistencyResult.consistent, true);
  assert.equal(attestationFirst.attestationSummary?.attestationFailureReason.reason, "settlement_layer_failure");
  assert.equal(attestationFirst.accountingSummary.settlementRecord.settlementStatus, "rejected");
  assert.equal(attestationFirst.attestationProofSummary?.verificationPassed, true);
  assert.equal(attestationFirst.ledgerSummary.burnedSupplyAfter, 95n);
});

test("wallet, anchor, and provenance interactions use wallet precedence", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      (parsed.wallet_binding as Record<string, unknown>).account_id_hex = "22".repeat(32);
      parsed.token_anchor = JSON.parse(
        readFileSync(
          canonicalPipelineFixturePathV0("external_anchor_mismatch_request.json"),
          "utf8",
        ),
      ).token_anchor;
      (parsed.economic as Record<string, unknown>).declared_fee_units = 51;
      parsed.expected_result = "SETTLEMENT_REJECTED";
    },
    (filePath) => {
      const report = runCanonicalPipelineV0(filePath);

      assert.equal(report.actualResult, ScenarioResultV0.SettlementRejected);
      assert.equal(report.statusExplanation.failureReasonCode, "wallet_binding_mismatch");
      assert.equal(report.walletBindingSummary.bindingConsistentWithAccount, false);
      assert.equal(report.tokenAnchorSummary.anchorVerificationStatus, "rejected");
      assert.equal(report.attestationSummary?.consistencyResult.consistent, true);
      assert.equal(report.provenanceSummary?.allSignatureChecksPassed, true);
    },
  );
});

test("attestation provenance tamper precedence fails in execution before verification", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_stark_attestation_request.json",
    (parsed) => {
      setSignedProvenanceJsonV0(parsed, false);
      (parsed.attestation as Record<string, unknown>).tamper_stark_proof_bytes = {
        byte_offset: 0,
        xor_with: 1,
      };
      (parsed.economic as Record<string, unknown>).declared_fee_units = 53;
      parsed.expected_result = "EXECUTION_REJECTED";
    },
    (filePath) => {
      const report = runCanonicalPipelineV0(filePath);

      assert.equal(report.actualResult, ScenarioResultV0.ExecutionRejected);
      assert.equal(report.statusExplanation.failureReasonCode, "provenance_signature_invalid");
      assert.equal(report.publicInputs, null);
      assert.equal(report.proofArtifact, null);
    },
  );
});

test("canonical pipeline authoritative head persistence follows the continuous chain corpus", () => {
  withTempHeadStateV0((headStatePath) => {
    const step1 = runCanonicalPipelineV0(
      canonicalPipelineFixturePathV0("continuous_chain_v1/step01_execution_accept_request.json"),
      { headStatePath },
    );
    const headAfterStep1 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<string, unknown>;

    assert.equal(step1.actualResult, ScenarioResultV0.Accepted);
    assert.equal(step1.headTransitionSummary.authorityMode, "authoritative_persistent");
    assert.equal(headAfterStep1.head_sequence_number, 1);
    assert.equal(
      headAfterStep1.current_head_hash_hex,
      hexFromBytesV0(step1.headTransitionSummary.currentHeadHash),
    );

    const step2 = runCanonicalPipelineV0(
      canonicalPipelineFixturePathV0("continuous_chain_v1/step02_head_mismatch_reject_request.json"),
      { headStatePath },
    );
    const headAfterStep2 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<string, unknown>;

    assert.equal(step2.actualResult, ScenarioResultV0.SettlementRejected);
    assert.equal(step2.statusExplanation.failureReasonCode, "settlement_head_mismatch");
    assert.deepEqual(headAfterStep2, headAfterStep1);

    const step3 = runCanonicalPipelineV0(
      canonicalPipelineFixturePathV0("continuous_chain_v1/step03_execution_accept_request.json"),
      { headStatePath },
    );
    const headAfterStep3 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<string, unknown>;

    assert.equal(step3.actualResult, ScenarioResultV0.Accepted);
    assert.notDeepEqual(headAfterStep3, headAfterStep2);
    assert.equal(headAfterStep3.head_sequence_number, 2);
    assert.equal(
      headAfterStep3.current_head_hash_hex,
      hexFromBytesV0(step3.headTransitionSummary.currentHeadHash),
    );

    const step4 = runCanonicalPipelineV0(
      canonicalPipelineFixturePathV0("continuous_chain_v1/step04_anchor_mismatch_reject_request.json"),
      { headStatePath },
    );
    const headAfterStep4 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<string, unknown>;

    assert.equal(step4.actualResult, ScenarioResultV0.SettlementRejected);
    assert.equal(step4.statusExplanation.failureReasonCode, "settlement_acceptance_rejected");
    assert.notDeepEqual(headAfterStep4, headAfterStep3);
    assert.equal(headAfterStep4.head_sequence_number, 3);
    assert.equal(
      headAfterStep4.current_head_hash_hex,
      hexFromBytesV0(step4.headTransitionSummary.currentHeadHash),
    );
  });
});

test("authoritative head progression advances on every non-head result and stops on head mismatch", () => {
  withTempHeadStateV0((headStatePath) => {
    const step1 = runCanonicalPipelineV0(
      canonicalPipelineFixturePathV0("accepted_transfer_request.json"),
      { headStatePath },
    );
    const headAfterStep1 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<string, any>;

    withTempCanonicalPipelineMutationV0(
      "tampered_attestation_request.json",
      (parsed) => {
        (parsed.head as Record<string, unknown>).previous_head_hash_hex =
          headAfterStep1.current_head_hash_hex;
        (parsed.head as Record<string, unknown>).head_sequence_number = 2;
      },
      (filePath) => {
        const step2 = runCanonicalPipelineV0(filePath, { headStatePath });
        const headAfterStep2 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
          string,
          any
        >;
        assert.equal(step2.actualResult, ScenarioResultV0.ExecutionRejected);
        assert.equal(headAfterStep2.head_sequence_number, 2);

        withTempCanonicalPipelineMutationV0(
          "tampered_stark_attestation_request.json",
          (parsed) => {
            (parsed.head as Record<string, unknown>).previous_head_hash_hex =
              headAfterStep2.current_head_hash_hex;
            (parsed.head as Record<string, unknown>).head_sequence_number = 3;
          },
          (filePath2) => {
            const step3 = runCanonicalPipelineV0(filePath2, { headStatePath });
            const headAfterStep3 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
              string,
              any
            >;
            assert.equal(step3.actualResult, ScenarioResultV0.VerificationRejected);
            assert.equal(headAfterStep3.head_sequence_number, 3);

            withTempCanonicalPipelineMutationV0(
              "external_anchor_mismatch_request.json",
              (parsed) => {
                (parsed.head as Record<string, unknown>).previous_head_hash_hex =
                  headAfterStep3.current_head_hash_hex;
                (parsed.head as Record<string, unknown>).head_sequence_number = 4;
              },
              (filePath3) => {
                const step4 = runCanonicalPipelineV0(filePath3, { headStatePath });
                const headAfterStep4 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
                  string,
                  any
                >;
                assert.equal(step4.actualResult, ScenarioResultV0.SettlementRejected);
                assert.equal(step4.statusExplanation.failureReasonCode, "settlement_acceptance_rejected");
                assert.equal(headAfterStep4.head_sequence_number, 4);

                withTempCanonicalPipelineMutationV0(
                  "accepted_transfer_request.json",
                  (parsed) => {
                    (parsed.head as Record<string, unknown>).previous_head_hash_hex =
                      "00".repeat(32);
                    (parsed.head as Record<string, unknown>).head_sequence_number = 5;
                    parsed.expected_result = "SETTLEMENT_REJECTED";
                  },
                  (filePath4) => {
                    const step5 = runCanonicalPipelineV0(filePath4, { headStatePath });
                    const headAfterStep5 = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
                      string,
                      any
                    >;
                    assert.equal(step5.actualResult, ScenarioResultV0.SettlementRejected);
                    assert.equal(step5.statusExplanation.failureReasonCode, "settlement_head_mismatch");
                    assert.deepEqual(headAfterStep5, headAfterStep4);
                  },
                );
              },
            );
          },
        );
      },
    );
  });
});

test("head mismatch overrides wallet and anchor settlement rejections", () => {
  withTempHeadStateV0((headStatePath) => {
    runCanonicalPipelineV0(canonicalPipelineFixturePathV0("accepted_transfer_request.json"), {
      headStatePath,
    });
    const headAfterAccepted = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
      string,
      any
    >;

    withTempCanonicalPipelineMutationV0(
      "accepted_transfer_request.json",
      (parsed) => {
        (parsed.wallet_binding as Record<string, unknown>).account_id_hex = "22".repeat(32);
        (parsed.head as Record<string, unknown>).previous_head_hash_hex = "00".repeat(32);
        (parsed.head as Record<string, unknown>).head_sequence_number = 2;
        parsed.expected_result = "SETTLEMENT_REJECTED";
      },
      (filePath) => {
        const walletReport = runCanonicalPipelineV0(filePath, { headStatePath });
        const headAfterWallet = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
          string,
          any
        >;
        assert.equal(walletReport.statusExplanation.failureReasonCode, "settlement_head_mismatch");
        assert.equal(walletReport.walletBindingSummary.bindingConsistentWithAccount, false);
        assert.deepEqual(headAfterWallet, headAfterAccepted);

        withTempCanonicalPipelineMutationV0(
          "external_anchor_mismatch_request.json",
          (parsed) => {
            (parsed.head as Record<string, unknown>).previous_head_hash_hex = "00".repeat(32);
            (parsed.head as Record<string, unknown>).head_sequence_number = 2;
          },
          (filePath2) => {
            const anchorReport = runCanonicalPipelineV0(filePath2, { headStatePath });
            const headAfterAnchor = JSON.parse(readFileSync(headStatePath, "utf8")) as Record<
              string,
              any
            >;
            assert.equal(anchorReport.statusExplanation.failureReasonCode, "settlement_head_mismatch");
            assert.equal(anchorReport.tokenAnchorSummary.anchorVerificationStatus, "rejected");
            assert.deepEqual(headAfterAnchor, headAfterAccepted);
          },
        );
      },
    );
  });
});

test("stateless mode never persists head state", () => {
  withTempHeadStateV0((headStatePath) => {
    const report = runCanonicalPipelineV0(
      canonicalPipelineFixturePathV0("accepted_transfer_request.json"),
      { headStatePath, stateless: true },
    );

    assert.equal(report.headTransitionSummary.authorityMode, "stateless_non_authoritative");
    assert.equal(existsSync(headStatePath), false);
  });
});

test("rust local chain CLI JSON contract is versioned and self-describing", () => {
  const root = repoRootV0();
  const requestPath = canonicalPipelineFixturePathV0("accepted_transfer_request.json");
  const result = spawnSync(
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
      requestPath,
    ],
    {
      cwd: root,
      encoding: "utf8",
    },
  );

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.bridge_schema_version, 1);
  assert.equal(parsed.report_kind, "canonical_pipeline_report_v1");
  assert.equal(parsed.command, "run-canonical-pipeline");
  assert.equal(parsed.report.pipeline_id, "aura_local_pipeline_v1");
  assert.equal(parsed.report.fixture_name, "accepted_transfer_stark_pipeline");
  assert.equal(parsed.report.burn_summary.burn_policy_version, 1);
  assert.equal(parsed.report.burn_summary.request_kind, "execution");
  assert.equal(parsed.report.burn_summary.computed_burn_units, 49);
  assert.equal(parsed.report.accounting_summary.declared_fee_units, 49);
  assert.equal(parsed.report.ledger_summary.ledger_policy_version, 1);
  assert.equal(parsed.report.ledger_summary.burned_supply_after, 49);
  assert.equal(parsed.report.status_explanation.truth_artifact_kind, "execution_report");
  assert.equal(parsed.report.genesis_accounts.ordered_accounts.length, 2);
  assert.equal(parsed.report.ledger_accounts.ordered_accounts.length, 2);
  assert.equal(
    parsed.report.commitment_expansions.transactions.ordered_transactions.length,
    1,
  );
  assert.match(parsed.report.public_inputs.transition_binding_hash_hex, /^[0-9a-f]{64}$/);
});

test("rust local chain CLI rejects unsupported output format", () => {
  const root = repoRootV0();
  const requestPath = canonicalPipelineFixturePathV0("accepted_transfer_request.json");
  const result = spawnSync(
    "cargo",
    [
      "run",
      "-p",
      "aura_l2_local_chain_v0",
      "--offline",
      "--",
      "--output",
      "yaml",
      "run-canonical-pipeline",
      requestPath,
    ],
    {
      cwd: root,
      encoding: "utf8",
    },
  );

  assert.notEqual(result.status, 0);
  assert.match(result.stderr || result.stdout, /unsupported output format/);
});

test("parseRustCanonicalPipelineReportJsonV0 rejects malformed JSON", () => {
  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0("{not-json"),
    /rust local chain bridge returned invalid JSON/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unsupported pipeline schema versions", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.pipeline_schema_version = 99;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /unsupported canonical pipeline schema version/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects empty fixture names", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.fixture_name = "   ";

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /fixtureName must not be empty|fixture_name/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unexpected report fields", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.unexpected_field = true;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /unexpected field/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unexpected nested report fields", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.commitment_expansions.transactions.unexpected_field = true;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /unexpected field/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent genesis account material", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.genesis_accounts.ordered_accounts.reverse();

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /genesisAccounts|strictly ordered/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent transactions expansion", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.commitment_expansions.transactions.transactions_commitment_hex =
    `ff${envelope.report.commitment_expansions.transactions.transactions_commitment_hex.slice(2)}`;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /commitmentExpansions\.transactions|orderedTransactions/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent outcomes expansion", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.commitment_expansions.outcomes.outcomes[0].touched_accounts_commitment_hex =
    `ff${envelope.report.commitment_expansions.outcomes.outcomes[0].touched_accounts_commitment_hex.slice(2)}`;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /commitmentExpansions\.outcomes|appliedSteps/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent batch-context expansion", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.commitment_expansions.batch_context.fee_parameters.fee_per_transfer = 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /commitmentExpansions\.batchContext|batch_context/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent fee-summary expansion", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.commitment_expansions.fee_summary.fee_summary.tx_count += 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /commitmentExpansions\.feeSummary|fee_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unsupported burn policy versions", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.burn_summary.burn_policy_version = 99;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /unsupported canonical pipeline burn policy version/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unsupported accounting policy versions", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.accounting_summary.accounting_policy_version = 99;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /unsupported canonical pipeline accounting policy version/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unsupported ledger policy versions", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.ledger_summary.ledger_policy_version = 99;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /unsupported canonical pipeline ledger policy version/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects tampered burn summaries", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.burn_summary.computed_burn_units += 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /burnSummary|burn_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects contradictory burn outcome states", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.burn_summary.burn_consumed = false;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /burnSummary must pin full-burn fail-closed semantics|burnSummary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects mismatched accounting summaries", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.accounting_summary.settlement_record.future_token_binding_units += 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /accountingSummary contradicts burnSummary or settlement result|accounting_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects tampered burn records", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.accounting_summary.burn_record.pre_balance += 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /accountingSummary contradicts burnSummary or settlement result|accounting_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent ledger summaries", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.ledger_summary.burned_supply_after += 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /ledgerSummary contradicts the canonical ledger burn transition|ledger_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects mismatched burn derivation inputs", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.burn_summary.burn_derivation_inputs.metered_request_size_bytes += 1;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /burnSummary|burn_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects missing requestSummaryConsistency on decoded public inputs", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  delete envelope.report.public_inputs.request_summary_consistency;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /requestSummaryConsistency|request_summary_consistency/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects contradictory requestSummaryConsistency", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.public_inputs.request_summary_consistency.all_fields_match = false;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /requestSummaryConsistency|request_summary_consistency/,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects unsupported proof versions fail-closed", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.proof_artifact.proof_version = 99;
  envelope.report.proof_artifact.consistency.proof_version_supported = false;
  envelope.report.proof_artifact.consistency.proof_binding_digest_matches_recomputed = false;
  envelope.report.proof_artifact.consistency.all_fields_match = false;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /proofArtifact\.consistency|proof version/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects contradictory proof artifact consistency", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.proof_artifact.consistency.proof_binding_digest_matches_recomputed = false;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /proofArtifact\.consistency|proof artifact/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects verification-rejected reports without a verification mismatch", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.actual_result = "VerificationRejected";
  envelope.report.stage_outcomes.verification_status = "rejected";
  envelope.report.stage_outcomes.settlement_status = "rejected";
  delete envelope.report.settlement_committed_state_root_hex;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /statusExplanation contradicts request kind or actualResult|status_explanation/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 accepts consistent settlement-rejected accounting surfaces", () => {
  const envelope = canonicalPipelineBridgeEnvelopeFromFixtureV0(
    "external_anchor_mismatch_request.json",
  );

  const parsed = parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope));
  assert.equal(parsed.actualResult, ScenarioResultV0.SettlementRejected);
  assert.equal(parsed.accountingSummary.settlementRecord.settlementStatus, "rejected");
  assert.equal(parsed.accountingSummary.consumedBurnUnits, 49n);
  assert.equal(parsed.tokenAnchorSummary.anchorVerificationStatus, "rejected");
});

test("loadCanonicalPipelineRequestV0 rejects unexpected top-level fields", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      parsed.unexpected_field = true;
    },
    (filePath) => {
      assert.throws(() => loadCanonicalPipelineRequestV0(filePath), /unexpected field/);
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects unsupported pipeline ids", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      parsed.pipeline_id = "wrong_pipeline";
    },
    (filePath) => {
      assert.throws(() => loadCanonicalPipelineRequestV0(filePath), /unsupported canonical pipeline id/);
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects unsupported economic policy versions", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.economic as Record<string, unknown>).economic_policy_version = 99;
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /unsupported canonical pipeline economic_policy_version/,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects unsupported accounting policy versions", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.accounting as Record<string, unknown>).accounting_policy_version = 99;
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /unsupported canonical pipeline accounting_policy_version/,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects unsupported ledger policy versions", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.ledger as Record<string, unknown>).ledger_policy_version = 99;
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /unsupported canonical pipeline ledger_policy_version/,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects malformed economic sections", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.economic as Record<string, unknown>).unexpected_field = true;
    },
    (filePath) => {
      assert.throws(() => loadCanonicalPipelineRequestV0(filePath), /unexpected field/);
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects malformed accounting sections", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.accounting as Record<string, unknown>).unexpected_field = true;
    },
    (filePath) => {
      assert.throws(() => loadCanonicalPipelineRequestV0(filePath), /unexpected field/);
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects malformed ledger sections", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.ledger as Record<string, unknown>).unexpected_field = true;
    },
    (filePath) => {
      assert.throws(() => loadCanonicalPipelineRequestV0(filePath), /unexpected field/);
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects unsupported request kinds", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.economic as Record<string, unknown>).request_kind = "invalid_kind";
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /unsupported canonical pipeline request kind|request_kind/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects declared fee drift", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.economic as Record<string, unknown>).declared_fee_units = 41;
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /declaredFeeUnits must equal computed burn units|declared_fee_units/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects insufficient ledger balance for burn", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      (parsed.ledger as Record<string, unknown>).total_supply = 291;
      ((parsed.ledger as Record<string, unknown>).accounts as Array<Record<string, unknown>>)[0].balance = 41;
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /ledger payer balance is insufficient for computed burn/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects execution requests carrying attestation material", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_transfer_request.json",
    (parsed) => {
      parsed.attestation = {
        attestation_schema_version: 2,
        attestation_scope: "claim_consistency_with_provided_evidence_only",
        attestation_proof_kind: "MOCK",
        normalization_policy_version: 1,
        attestation_constraints: {
          require_unique_labels: true,
          max_evidence_items: 16,
          max_total_normalized_bytes: 16384,
        },
        claim: {
          claim_kind: "normalized_text_contains_utf8",
          claim_payload: {
            target_label: "synthetic_evidence",
            expected_substring_utf8: "execution requests must not carry attestation material",
          },
        },
        evidence_items: [
          {
            label: "synthetic_evidence",
            evidence_kind: "inline_utf8",
            evidence_payload: {
              payload_utf8: "execution requests must not carry attestation material",
            },
            provenance: {
              provenance_policy_version: 1,
              provenance_type: "inline",
              source_type: "fixture",
              source_identifier: "synthetic_evidence",
            },
          },
        ],
      };
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /request_kind execution must not carry attestation material/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects malformed attestation evidence", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      (((parsed.attestation as Record<string, unknown>).evidence_items as Array<Record<string, unknown>>)[0]
        .evidence_payload as Record<string, unknown>).payload_utf8 = "";
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /payloadUtf8 must not be empty|payload_utf8/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects unsupported provenance types", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      ((((parsed.attestation as Record<string, unknown>).evidence_items as Array<Record<string, unknown>>)[0]
        .provenance) as Record<string, unknown>).provenance_type = "unsupported";
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /unsupported canonical pipeline provenance type|evidence_provenance_type/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects malformed provenance signatures", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      const provenance = ((((parsed.attestation as Record<string, unknown>).evidence_items as Array<
        Record<string, unknown>
      >)[0].provenance) as Record<string, unknown>);
      provenance.provenance_type = "signed_blob";
      provenance.signature = {
        signer_public_key_hex: "11".repeat(32),
        signature_hex: "22".repeat(63),
      };
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /signatureHex|signature_hex|64 bytes/i,
      );
    },
  );
});

test("loadCanonicalPipelineRequestV0 rejects inconsistent attestation requests", () => {
  withTempCanonicalPipelineMutationV0(
    "accepted_attestation_request.json",
    (parsed) => {
      (parsed.batch as Record<string, unknown>).transactions = [
        {
          sender_account_id_hex: "11".repeat(32),
          recipient_account_id_hex: "22".repeat(32),
          sender_nonce: 0,
          amount: 1,
        },
      ];
    },
    (filePath) => {
      assert.throws(
        () => loadCanonicalPipelineRequestV0(filePath),
        /requestKind attestation requires zero transactions|request_kind attestation requires zero transactions/i,
      );
    },
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects inconsistent attestation material", () => {
  const envelope = canonicalPipelineBridgeEnvelopeFromFixtureV0("accepted_attestation_request.json");
  envelope.report.attestation_summary.evidence_summary.evidence_root_digest_hex =
    `ff${envelope.report.attestation_summary.evidence_summary.evidence_root_digest_hex.slice(2)}`;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /attestationSummary contradicts the embedded attestation material|attestation_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects normalization drift", () => {
  const envelope = canonicalPipelineBridgeEnvelopeFromFixtureV0("accepted_attestation_request.json");
  envelope.report.attestation_summary.evidence_summary.evidence_items[0].normalized_payload_utf8 += "!";

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /attestationSummary contradicts the embedded attestation material|attestation_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects tampered wallet binding summaries", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.wallet_binding_summary.wallet_binding_digest_hex =
    `ff${envelope.report.wallet_binding_summary.wallet_binding_digest_hex.slice(2)}`;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /walletBindingSummary contradicts the embedded wallet binding|wallet_binding_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects tampered provenance summaries", () => {
  const envelope = canonicalPipelineBridgeEnvelopeFromFixtureV0("accepted_attestation_request.json");
  envelope.report.provenance_summary.provenance_root_digest_hex =
    `ff${envelope.report.provenance_summary.provenance_root_digest_hex.slice(2)}`;

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /provenanceSummary contradicts the embedded provenance material|provenance_summary/i,
  );
});

test("parseRustCanonicalPipelineReportJsonV0 rejects tampered accepted status explanations", () => {
  const envelope = canonicalPipelineExpectedReportEnvelopeV0();
  envelope.report.status_explanation.detail = "tampered accepted detail";

  assert.throws(
    () => parseRustCanonicalPipelineReportJsonV0(JSON.stringify(envelope)),
    /accepted statusExplanation|accepted status_explanation/i,
  );
});

test("canonical STARK attestation request stays on the same pipeline", () => {
  const request = loadCanonicalPipelineRequestV0(
    canonicalPipelineFixturePathV0("accepted_stark_attestation_request.json"),
  );
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("accepted_stark_attestation_request.json"),
  );

  assert.equal(request.attestation?.attestationProofKind, "STARK");
  assert.equal(request.proofSystem, ProofSystemV0.Mock);
  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
  assert.equal(report.attestationProofSummary?.proofKind, "STARK");
  assert.equal(report.attestationProofSummary?.verificationPassed, true);
  assert.notEqual(report.attestationProofSummary?.starkPublicInputsDigest, null);
  assert.notEqual(report.attestationProofSummary?.starkProofBytesDigest, null);
  assert.notEqual(report.attestationProofSummary?.starkProofBindingDigest, null);
});

test("tampered STARK attestation request fails closed inside verification", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("tampered_stark_attestation_request.json"),
  );

  assert.equal(report.actualResult, ScenarioResultV0.VerificationRejected);
  assert.equal(
    report.statusExplanation.failureReasonCode,
    "attestation_proof_verification_rejected",
  );
  assert.equal(report.burnSummary.computedBurnUnits, 49n);
  assert.equal(report.attestationSummary?.attestationStatus, "rejected");
  assert.equal(
    report.attestationSummary?.attestationFailureReason.reason,
    "attestation_proof_verification_failure",
  );
  assert.equal(report.attestationProofSummary?.proofKind, "STARK");
  assert.equal(report.attestationProofSummary?.verificationPassed, false);
});

test("external anchor mismatch rejects in settlement without altering canonical execution", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("external_anchor_mismatch_request.json"),
  );

  assert.equal(report.actualResult, ScenarioResultV0.SettlementRejected);
  assert.equal(report.statusExplanation.failureReasonCode, "settlement_acceptance_rejected");
  assert.equal(report.tokenAnchorSummary.anchorVerificationStatus, "rejected");
  assert.equal(report.accountingSummary.settlementRecord.settlementStatus, "rejected");
  assert.equal(report.burnSummary.computedBurnUnits, 49n);
  assert.equal(report.publicInputs?.requestSummaryConsistency?.allFieldsMatch, true);
  assert.equal(report.proofArtifact?.consistency.allFieldsMatch, true);
});

test("disconnected external anchors remain non-authoritative", () => {
  const report = runCanonicalPipelineV0(
    canonicalPipelineFixturePathV0("external_anchor_disconnected_request.json"),
  );

  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
  assert.equal(report.tokenAnchorSummary.anchorVerificationStatus, "disconnected");
  assert.equal(report.accountingSummary.settlementRecord.settlementStatus, "accepted");
  assert.equal(report.burnSummary.computedBurnUnits, 49n);
});

test("parseRustScenarioReportJsonV0 rejects malformed JSON", () => {
  assert.throws(
    () => parseRustScenarioReportJsonV0("{not-json"),
    /rust local chain bridge returned invalid JSON|rust local chain bridge returned invalid JSON/i,
  );
});

test("parseRustScenarioReportJsonV0 rejects unsupported schema versions", () => {
  assert.throws(
    () =>
      parseRustScenarioReportJsonV0(
        JSON.stringify({
          bridge_schema_version: 99,
          report_kind: "scenario_report_v1",
          command: "run-scenario",
          report: {
            fixture_name: "accepted_transition_example",
            expected_result: "Accepted",
            actual_result: "Accepted",
            pre_state_root_hex: "11".repeat(32),
          },
        }),
      ),
    /unsupported rust bridge schema version/,
  );
});

test("parseRustProofVectorReportJsonV0 rejects missing required fields", () => {
  assert.throws(
    () =>
      parseRustProofVectorReportJsonV0(
        JSON.stringify({
          bridge_schema_version: 1,
          report_kind: "proof_vector_report_v1",
          command: "run-proof-vector",
          report: {
            fixture_name: "minimal_single_transfer_real_stark_proof_vector",
            proof_system: "stark",
            expected_result: "Accepted",
            actual_result: "Accepted",
            pre_state_root_hex: "11".repeat(32),
            transition_binding_hash_hex: "22".repeat(32),
            public_inputs_hash_hex: "33".repeat(32),
            trace_digest_hex: "44".repeat(32),
            proof_binding_digest_hex: "55".repeat(32),
          },
        }),
      ),
    /trace_layout_digest_hex/,
  );
});

test("parseRustScenarioReportJsonV0 rejects unexpected envelope fields", () => {
  assert.throws(
    () =>
      parseRustScenarioReportJsonV0(
        JSON.stringify({
          bridge_schema_version: 1,
          report_kind: "scenario_report_v1",
          command: "run-scenario",
          report: {
            fixture_name: "accepted_transition_example",
            expected_result: "Accepted",
            actual_result: "Accepted",
            pre_state_root_hex: "11".repeat(32),
          },
          unexpected_field: true,
        }),
      ),
    /unexpected field/,
  );
});

test("parseRustProofVectorReportJsonV0 rejects unexpected report fields", () => {
  assert.throws(
    () =>
      parseRustProofVectorReportJsonV0(
        JSON.stringify({
          bridge_schema_version: 1,
          report_kind: "proof_vector_report_v1",
          command: "verify-proof-vector",
          report: {
            fixture_name: "minimal_single_transfer_real_stark_proof_vector",
            proof_system: "stark",
            expected_result: "Accepted",
            actual_result: "Accepted",
            pre_state_root_hex: "11".repeat(32),
            transition_binding_hash_hex: "22".repeat(32),
            public_inputs_hash_hex: "33".repeat(32),
            trace_digest_hex: "44".repeat(32),
            trace_layout_digest_hex: "55".repeat(32),
            proof_binding_digest_hex: "66".repeat(32),
            extra_hex: "77".repeat(32),
          },
        }),
      ),
    /unexpected field/,
  );
});

test("parseRustScenarioReportJsonV0 rejects commands outside the report kind", () => {
  assert.throws(
    () =>
      parseRustScenarioReportJsonV0(
        JSON.stringify({
          bridge_schema_version: 1,
          report_kind: "scenario_report_v1",
          command: "run-proof-vector",
          report: {
            fixture_name: "accepted_transition_example",
            expected_result: "Accepted",
            actual_result: "Accepted",
            pre_state_root_hex: "11".repeat(32),
          },
        }),
      ),
    /unexpected rust bridge command/,
  );
});

test("fixture loading and object builders remain compatible", () => {
  const root = repoRootV0();
  const genesis = loadGenesisFixtureV0(
    path.join(root, "fixtures/l2_local_v1/genesis_state.json"),
  );
  const tx = transferTxV0(
    bytesFromHexV0("11".repeat(32)),
    bytesFromHexV0("22".repeat(32)),
    0n,
    9n,
  );
  const state = new GenesisBuilderV0()
    .account(genesis.state.orderedAccounts()[0].accountId, 90n, 0n)
    .account(genesis.state.orderedAccounts()[1].accountId, 10n, 0n)
    .buildState();
  const batch = new BatchBuilderV0(0n)
    .withParentBatchCommitment(ZERO32_V0)
    .transfer(tx.senderAccountId, tx.recipientAccountId, tx.senderNonce, tx.amount)
    .build();

  const executed = executeBatchV0(state, genesis.rollupId, batch);
  assert.equal(executed.txCount, 1n);
  assert.equal(executed.outcomes.length, 1);
  assert.equal(executed.appliedSteps[0].amount, 9n);
  assert.deepEqual(
    executed.preState.orderedAccounts().map((account) => hexFromBytesV0(account.accountId)),
    state.orderedAccounts().map((account) => hexFromBytesV0(account.accountId)),
  );
});

test("proof vector fixture loads with canonical public-input bytes", () => {
  const root = repoRootV0();
  const fixture = loadProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
  );

  assert.equal(fixture.proofSystem, ProofSystemV0.Stark);
  assert.equal(fixture.expectedPublicInputs.publicInputBytes.length, PUBLIC_INPUT_SCHEMA_LEN_V0);
  assert.equal(fixture.expectedResult, ScenarioResultV0.Accepted);
});

test("loaded proof vector matches native execution-derived transition and public inputs", () => {
  const root = repoRootV0();
  const fixture = loadProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
  );
  const executed = executeBatchV0(
    new GenesisBuilderV0()
      .account(fixture.genesis.accounts[0].accountId, fixture.genesis.accounts[0].balance, fixture.genesis.accounts[0].nonce)
      .account(fixture.genesis.accounts[1].accountId, fixture.genesis.accounts[1].balance, fixture.genesis.accounts[1].nonce)
      .buildState(),
    fixture.genesis.rollupId,
    fixture.batch,
  );
  const derived = deriveTransitionArtifactsV0(executed);

  assert.equal(
    hexFromBytesV0(derived.transition.postStateRoot),
    hexFromBytesV0(fixture.expectedTransition.postStateRoot),
  );
  assert.equal(
    hexFromBytesV0(derived.transitionBindingHash),
    hexFromBytesV0(fixture.expectedPublicInputs.transitionBindingHash),
  );
  assert.equal(
    hexFromBytesV0(derived.publicInputBytes),
    hexFromBytesV0(fixture.expectedPublicInputs.publicInputBytes),
  );
});

test("proof vector run flow succeeds through rust bridge", () => {
  const root = repoRootV0();
  const report = runProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/multi_transfer_proof.json"),
  );

  assert.equal(report.proofSystem, ProofSystemV0.Stark);
  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
});

test("proof vector verify flow accepts canonical stored proof", () => {
  const root = repoRootV0();
  const report = verifyProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/small_trace_edge_case.json"),
  );

  assert.equal(report.proofSystem, ProofSystemV0.Stark);
  assert.equal(report.actualResult, ScenarioResultV0.Accepted);
});

test("tampered proof vector rejects through rust bridge", () => {
  const root = repoRootV0();
  const report = verifyProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/tampered_proof_case.json"),
  );

  assert.equal(report.actualResult, ScenarioResultV0.VerificationRejected);
});

test("proof vector duplicate run reports remain deterministic", () => {
  const root = repoRootV0();
  const first = runProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
  );
  const second = runProofVectorV0(
    path.join(root, "fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json"),
  );

  assert.equal(
    hexFromBytesV0(first.transitionBindingHash),
    hexFromBytesV0(second.transitionBindingHash),
  );
  assert.equal(hexFromBytesV0(first.publicInputsHash), hexFromBytesV0(second.publicInputsHash));
  assert.equal(hexFromBytesV0(first.proofBindingDigest), hexFromBytesV0(second.proofBindingDigest));
});

test("proof vector bridge reports remain identical across twelve runs", () => {
  const root = repoRootV0();
  const vectorPath = path.join(
    root,
    "fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json",
  );
  const baseline = runProofVectorV0(vectorPath);

  for (let i = 0; i < 12; i += 1) {
    const report = runProofVectorV0(vectorPath);
    assert.deepEqual(report, baseline);
  }
});

test("all canonical proof vectors preserve native derivation and bridge parity", () => {
  const root = repoRootV0();
  const vectorDir = path.join(root, "fixtures/l2_proof_vectors_v1");
  for (const fixtureName of [
    "minimal_single_transfer_proof.json",
    "multi_transfer_proof.json",
    "small_trace_edge_case.json",
    "tampered_proof_case.json",
  ]) {
    const vectorPath = path.join(vectorDir, fixtureName);
    const fixture = loadProofVectorV0(vectorPath);
    const native = deriveTransitionArtifactsV0(
      executeBatchV0(
        stateFromAccountsV0(fixture.genesis.accounts),
        fixture.genesis.rollupId,
        fixture.batch,
      ),
    );
    const runReport = runProofVectorV0(vectorPath);
    const verifyReport = verifyProofVectorV0(vectorPath);

    assert.equal(
      hexFromBytesV0(native.publicInputBytes),
      hexFromBytesV0(fixture.expectedPublicInputs.publicInputBytes),
    );
    assert.equal(
      hexFromBytesV0(native.transitionBindingHash),
      hexFromBytesV0(fixture.expectedPublicInputs.transitionBindingHash),
    );
    assert.equal(runReport.expectedResult, fixture.expectedResult);
    assert.equal(verifyReport.expectedResult, fixture.expectedResult);
    assert.equal(
      hexFromBytesV0(runReport.transitionBindingHash),
      hexFromBytesV0(fixture.expectedPublicInputs.transitionBindingHash),
    );
  }
});

test("proof vector load rejects unsupported proof system", () => {
  withTempProofVectorMutationV0(
    "minimal_single_transfer_proof.json",
    (value) => {
      value.proof_system = "MOCK";
    },
    (filePath) => {
      assert.throws(() => loadProofVectorV0(filePath), /only the STARK proof system/);
    },
  );
});

test("loadGenesisFixture rejects unsupported schema versions", () => {
  const root = repoRootV0();
  const dir = mkdtempSync(path.join(tmpdir(), "aura-sdk-v0-ts-genesis-version-"));
  try {
    const sourcePath = path.join(root, "fixtures/l2_local_v1/genesis_state.json");
    const filePath = path.join(dir, "invalid_genesis_schema.json");
    const parsed = JSON.parse(readFileSync(sourcePath, "utf8"));
    parsed.fixture_schema_version = 99;
    writeFileSync(filePath, JSON.stringify(parsed, null, 2), "utf8");
    assert.throws(
      () => loadGenesisFixtureV0(filePath),
      /unsupported genesis fixture_schema_version/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadProofVector rejects unexpected top-level fields", () => {
  withTempProofVectorMutationV0(
    "minimal_single_transfer_proof.json",
    (value) => {
      value.unexpected_field = true;
    },
    (filePath) => {
      assert.throws(
        () => loadProofVectorV0(filePath),
        /unexpected field/,
      );
    },
  );
});

test("proof vector load rejects malformed public-input bytes", () => {
  withTempProofVectorMutationV0(
    "minimal_single_transfer_proof.json",
    (value) => {
      value.expected_public_inputs.public_input_bytes_hex =
        value.expected_public_inputs.public_input_bytes_hex.slice(0, -2);
    },
    (filePath) => {
      assert.throws(() => loadProofVectorV0(filePath), /invalid proof vector public-input length|public-input bytes do not match/);
    },
  );
});

test("proof vector load rejects unsafe integer fields", () => {
  withTempProofVectorMutationV0(
    "minimal_single_transfer_proof.json",
    (value) => {
      value.batch.batch_number = Number.MAX_SAFE_INTEGER + 1;
    },
    (filePath) => {
      assert.throws(() => loadProofVectorV0(filePath), /must be a non-negative safe integer/);
    },
  );
});

test("loadGenesisFixture rejects malformed top-level structure cleanly", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "aura-sdk-v0-ts-genesis-"));
  try {
    const filePath = path.join(dir, "invalid_genesis.json");
    writeFileSync(filePath, JSON.stringify(["not-an-object"]), "utf8");
    assert.throws(() => loadGenesisFixtureV0(filePath), /genesis fixture must be a JSON object/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadGenesisFixture rejects unreadable path cleanly", () => {
  assert.throws(
    () => loadGenesisFixtureV0(path.join(tmpdir(), "aura-sdk-v0-ts-does-not-exist.json")),
    /genesis fixture could not be read/,
  );
});

test("typescript builders reject fractional runtime values", () => {
  assert.throws(
    () => new GenesisBuilderV0().account(new Uint8Array(32).fill(0x11), 1.5, 0),
    /must be an integer number or bigint/,
  );
  assert.throws(
    () => new BatchBuilderV0(0).transfer(new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22), 0, 1.25),
    /must be an integer number or bigint/,
  );
});

test("runRustFlow rejects unsupported runtime proof-system values before bridging", () => {
  const { rollupId, state, batch } = canonicalStateAndBatchV0();
  assert.throws(
    () =>
      runRustFlowV0({
        state,
        rollupId,
        batch,
        proofSystem: "bogus" as unknown as typeof ProofSystemV0[keyof typeof ProofSystemV0],
      }),
    (error: unknown) =>
      error instanceof AuraTypescriptSdkErrorV0 &&
      error.code === "InvalidFixture" &&
      /unsupported proof system/.test(error.message),
  );
});

test("runRustFlow rejects unsupported runtime expected-result values before bridging", () => {
  const { rollupId, state, batch } = canonicalStateAndBatchV0();
  assert.throws(
    () =>
      runRustFlowV0({
        state,
        rollupId,
        batch,
        proofSystem: ProofSystemV0.Mock,
        expectedResult: "bogus" as unknown as ScenarioResultV0,
      }),
    (error: unknown) =>
      error instanceof AuraTypescriptSdkErrorV0 &&
      error.code === "InvalidFixture" &&
      /unsupported scenario result/.test(error.message),
  );
});

test("runRustFlow rejects malformed batch shape before bridging", () => {
  const { rollupId, state } = canonicalStateAndBatchV0();
  assert.throws(
    () =>
      runRustFlowV0({
        state,
        rollupId,
        batch: null as unknown as ReturnType<BatchBuilderV0["build"]>,
        proofSystem: ProofSystemV0.Mock,
      }),
    (error: unknown) =>
      error instanceof AuraTypescriptSdkErrorV0 &&
      error.code === "InvalidFixture" &&
      /batch must be a batch-like object/.test(error.message),
  );
});

test("runProofVector rejects malformed local fixture before rust bridge", () => {
  withTempProofVectorMutationV0(
    "minimal_single_transfer_proof.json",
    (value) => {
      value.canonical_stark_proof_artifact.proof_bytes_hex = "";
    },
    (filePath) => {
      assert.throws(() => runProofVectorV0(filePath), /proof bytes must not be empty/);
      assert.throws(() => verifyProofVectorV0(filePath), /proof bytes must not be empty/);
    },
  );
});

test("all canonical proof vectors reject bridge verification after proof-byte tamper", () => {
  for (const fixtureName of [
    "minimal_single_transfer_proof.json",
    "multi_transfer_proof.json",
    "small_trace_edge_case.json",
  ]) {
    withTempProofVectorMutationV0(
      fixtureName,
      (value) => {
        value.proof_tamper = { target: "PROOF_BYTES", byte_offset: 0, xor_with: 1 };
        value.expected_result = "VERIFICATION_REJECTED";
      },
      (filePath) => {
        const report = verifyProofVectorV0(filePath);
        assert.equal(report.actualResult, ScenarioResultV0.VerificationRejected);
      },
    );
  }
});
