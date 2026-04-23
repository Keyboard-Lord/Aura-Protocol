import path from "node:path";
import { fileURLToPath } from "node:url";

import { runProofVectorV0, verifyProofVectorV0 } from "../src/index.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const vectorPath = path.join(
  repoRoot,
  "fixtures/l2_proof_vectors_v1/minimal_single_transfer_proof.json",
);

const runReport = runProofVectorV0(vectorPath);
const verifyReport = verifyProofVectorV0(vectorPath);

console.log(`fixture_name: ${runReport.fixtureName}`);
console.log(`run_actual_result: ${runReport.actualResult}`);
console.log(`verify_actual_result: ${verifyReport.actualResult}`);
// Non-canonical reproducibility example. The active authority path is run-canonical-pipeline.
