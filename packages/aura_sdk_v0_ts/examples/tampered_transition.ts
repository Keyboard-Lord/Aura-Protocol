import path from "node:path";
import { fileURLToPath } from "node:url";

import { ProofSystemV0, runRustScenarioV0 } from "../src/index.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const report = runRustScenarioV0(
  path.join(root, "fixtures/l2_local_v1/genesis_state.json"),
  path.join(root, "fixtures/l2_local_v1/tampered_proof_artifact.json"),
  ProofSystemV0.Stark,
);

console.log(`fixture_name=${report.fixtureName}`);
console.log(`actual_result=${report.actualResult}`);
// Non-canonical compatibility example. The active authority path is run-canonical-pipeline.
