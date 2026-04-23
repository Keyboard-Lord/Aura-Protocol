import {
  BatchBuilderV0,
  GenesisBuilderV0,
  hexFromBytesV0,
  ProofSystemV0,
  runRustFlowV0,
  ZERO32_V0,
} from "../src/index.ts";

const rollupId = new Uint8Array(32).fill(0xaa);
const state = new GenesisBuilderV0()
  .account(new Uint8Array(32).fill(0x11), 90n, 0n)
  .account(new Uint8Array(32).fill(0x22), 10n, 0n)
  .buildState();
const batch = new BatchBuilderV0(0n)
  .withParentBatchCommitment(ZERO32_V0)
  .transfer(new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22), 0n, 9n)
  .build();

const bridged = runRustFlowV0({
  state,
  rollupId,
  batch,
  proofSystem: ProofSystemV0.Mock,
});

console.log(`proof_system=${bridged.proofArtifact.proofSystem}`);
console.log(`actual_result=${bridged.report.actualResult}`);
console.log(
  `transition_binding_hash=${hexFromBytesV0(bridged.report.transitionBindingHash!)}`,
);
// Non-canonical compatibility example. The active authority path is run-canonical-pipeline.
