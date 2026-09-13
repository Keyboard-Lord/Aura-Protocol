// C2 contract and durable lifecycle freeze gate. Test-only adapter and Core fixtures; no live activation.
// Expected fixtures are read-only: this gate never invokes a vector generator.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { arch, platform } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const evidence = join(root, "reports/compute_network_v1/c2_freeze_results.json");
const fixtures = [
  "fixtures/compute_result_v1/result_vectors_v1.json",
  "fixtures/compute_job_v1/job_vectors_v1.json",
  "fixtures/compute_job_v1/core_policy_vectors_v1.json",
  "fixtures/miner_v1/job_profile_vector_v1.json",
];
async function hashes() {
  return Object.fromEntries(await Promise.all(fixtures.map(async path =>
    [path, createHash("sha256").update(await readFile(join(root, path))).digest("hex")])));
}
const result = {
  classification: "C2 CONTRACT AND DURABILITY EVIDENCE; NO REAL WORKLOAD OR LIVE PAYMENT",
  status: "RUNNING", recorded_at: new Date().toISOString(),
  environment: { node: process.version, platform: platform(), arch: arch(),
    rust: spawnSync("rustc", ["--version"], { encoding: "utf8" }).stdout.trim() },
  fixture_sha256: await hashes(), stages: [],
  limitations: ["Node native TypeScript runtime/syntax checks are not a standalone tsc typecheck.",
    "C2 uses a sealed test-only deterministic replay adapter; production has no registered workload until C3.",
    "Funding uses trusted Core RPC fixtures here; no real Bitcoin payment or public worker execution is exercised.",
    "Coherent whole-database rollback requires external backup provenance; checksums are corruption detection, not a trustless journal."],
};
async function persist() {
  await mkdir(join(root, "reports/compute_network_v1"), { recursive: true });
  await writeFile(evidence, JSON.stringify(result, null, 2) + "\n");
}
async function stage(name, command, args, expectedCounts = null) {
  const started = performance.now(); let output = "";
  const code = await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", b => output += b); child.stderr.on("data", b => output += b);
    child.on("error", reject); child.on("close", resolve);
  });
  const counts = [...output.matchAll(/test result: ok\. (\d+) passed;|^# pass (\d+)$/gm)]
    .map(m => Number(m[1] ?? m[2]));
  const entry = { name, command: [command, ...args], exit_code: code,
    elapsed_ms: Math.round(performance.now() - started), passed_test_counts: counts, status: "PASS" };
  result.stages.push(entry);
  try {
    assert.equal(code, 0); if (expectedCounts === null) assert(counts.reduce((a,b)=>a+b,0)>0, "missing tests"); else assert.deepEqual(counts, expectedCounts);
    assert(!/^warning:|^\(node:\d+\) (ExperimentalWarning|DeprecationWarning|Warning):/m.test(output), "unexpected warning");
  } catch (error) {
    entry.status = "FAIL"; entry.output = output; throw new Error(`${name}: ${error}\n${output}`);
  }
  await persist(); console.log(`PASS ${name} (${entry.elapsed_ms} ms)`);
}
try {
  await persist();
  await stage("c2_rust_canonical_vectors_mutations", "cargo", ["test", "-p", "aura_sdk_v1", "--offline", "--test", "compute_result_v1"], [5]);
  await stage("c2_independent_typescript_parity", "node", ["--test", "packages/aura_sdk_v1_ts/src/computeResultV1.test.ts"], [6]);
  await stage("c2_durable_lifecycle_crash_races_funding", "cargo", ["test", "-p", "aura_sdk_v1", "--offline", "--lib", "economic::journal::compute::tests"], [12]);
  await stage("existing_miner_journal_regression", "cargo", ["test", "-p", "aura_sdk_v1", "--offline", "--lib", "economic::journal::miner"]);
  await stage("existing_economic_journal_regression", "cargo", ["test", "-p", "aura_sdk_v1", "--offline", "--test", "economic_journal_v1"]);
  await stage("opaque_funding_cannot_deserialize_client_claims", "cargo", ["test", "-p", "aura_sdk_v1", "--offline", "--doc", "compute::funding::ComputeFundingV1"], [1]);
  await stage("entire_frozen_c1_m2_gate_and_affected_sdk_compile", "node", ["scripts/verify_compute_job_v1.mjs"], []);
  const c1=JSON.parse(await readFile(join(root,"reports/compute_network_v1/c1_freeze_results.json"),"utf8"));
  assert.equal(c1.status,"PASS");result.c1_gate=c1;
  await stage("c2_typescript_syntax", "node", ["--check", "packages/aura_sdk_v1_ts/src/computeResultV1.ts"], []);
  await stage("c2_public_sdk_exports", "node", ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import * as sdk from './packages/aura_sdk_v1_ts/src/index.ts';
    assert.deepEqual([sdk.COMPUTE_ASSIGNMENT_V1_BYTE_LEN,sdk.COMPUTE_RECEIPT_V1_BYTE_LEN,sdk.COMPUTE_RESULT_V1_BYTE_LEN,sdk.COMPUTE_CANCEL_V1_BYTE_LEN,sdk.COMPUTE_RESOURCE_ACCOUNTING_V1_BYTE_LEN],[91,152,56,55,25]);
    for (const name of ['encodeComputeAssignmentV1','decodeComputeAssignmentV1',
      'encodeComputeReceiptV1','decodeComputeReceiptV1','encodeVerifiedComputeResultV1',
      'decodeVerifiedComputeResultV1','computeResultCommitmentV1',
      'verifyComputeResultSignatureV1','verifyComputeReceiptContentV1',
      'encodeComputeCancelV1','decodeComputeResourceAccountingV1'])
      assert.equal(typeof sdk[name], 'function', name);
  `], []);
  assert.deepEqual(await hashes(), result.fixture_sha256, "validation modified expected fixtures");
  result.status = "PASS"; await persist();
  console.log(`PASS C2 freeze gate: ${result.stages.length} stages; ${evidence}`);
} catch (error) {
  result.status = "FAIL"; result.failure = String(error); await persist(); throw error;
}
