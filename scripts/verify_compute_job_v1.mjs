// Bounded C1 contract freeze gate. No journal, adapter, miner search or Bitcoin run.
// Expected fixtures are read-only: this gate never invokes a vector generator.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { arch, platform } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const evidence = join(root, "reports/compute_network_v1/c1_freeze_results.json");
const fixtures = [
  "fixtures/compute_job_v1/job_vectors_v1.json",
  "fixtures/compute_job_v1/core_policy_vectors_v1.json",
  "fixtures/miner_v1/job_profile_vector_v1.json",
];
async function hashes() {
  return Object.fromEntries(await Promise.all(fixtures.map(async path =>
    [path, createHash("sha256").update(await readFile(join(root, path))).digest("hex")])));
}
const result = {
  classification: "C1 CONTRACT VALIDATION EVIDENCE; NOT DEPLOYMENT OR PAYMENT EVIDENCE",
  status: "RUNNING", recorded_at: new Date().toISOString(),
  environment: { node: process.version, platform: platform(), arch: arch(),
    rust: spawnSync("rustc", ["--version"], { encoding: "utf8" }).stdout.trim() },
  fixture_sha256: await hashes(), stages: [],
  limitations: ["Node native TypeScript runtime/syntax checks are not a standalone tsc typecheck.",
    "No durable compute lifecycle, real workload, isolation or monetary execution is tested in C1."],
};
async function persist() {
  await mkdir(join(root, "reports/compute_network_v1"), { recursive: true });
  await writeFile(evidence, JSON.stringify(result, null, 2) + "\n");
}
async function stage(name, command, args, expectedCounts = []) {
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
    assert.equal(code, 0); assert.deepEqual(counts, expectedCounts);
    assert(!/^warning:|^\(node:\d+\) (ExperimentalWarning|DeprecationWarning|Warning):/m.test(output), "unexpected warning");
  } catch (error) {
    entry.status = "FAIL"; entry.output = output; throw new Error(`${name}: ${error}\n${output}`);
  }
  await persist(); console.log(`PASS ${name} (${entry.elapsed_ms} ms)`);
}
try {
  await persist();
  await stage("rust_c1_and_frozen_m2", "cargo", ["test", "-p", "aura_sdk_v1", "--offline", "--test", "compute_job_v1", "--test", "miner_v1"], [10, 9]);
  await stage("independent_typescript_c1_and_frozen_m2", "node", ["--test", "packages/aura_sdk_v1_ts/src/computeJobV1.test.ts", "packages/aura_sdk_v1_ts/src/minerV1.test.ts"], [23]);
  await stage("affected_rust_sdk_and_examples", "cargo", ["check", "-p", "aura_sdk_v1", "--offline", "--lib", "--examples"]);
  await stage("typescript_syntax", "node", ["--check", "packages/aura_sdk_v1_ts/src/computeJobV1.ts"]);
  await stage("public_sdk_exports", "node", ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import * as sdk from './packages/aura_sdk_v1_ts/src/index.ts';
    assert.equal(sdk.COMPUTE_JOB_V1_BYTE_LEN, 546);
    assert.equal(sdk.COMPUTE_PAYMENT_TERMS_V1_BYTE_LEN, 17);
    for (const name of ['encodeComputeJobV1', 'decodeComputeJobV1', 'verifyComputeRequestV1',
      'classifyComputeRetryV1', 'computeMinerSideV1', 'computeFixedCorePolicyPayloadV1',
      'validateComputeFixedCorePolicyV1', 'encodeComputePaymentTermsV1',
      'decodeComputePaymentTermsV1', 'computePaymentTermsCommitmentV1',
      'validateComputePublicationFeeV1', 'verifyComputeCorePoliciesV1'])
      assert.equal(typeof sdk[name], 'function', name);
  `]);
  assert.deepEqual(await hashes(), result.fixture_sha256, "validation modified expected fixtures");
  result.status = "PASS"; await persist();
  console.log(`PASS C1 freeze gate: ${result.stages.length} stages; ${evidence}`);
} catch (error) {
  result.status = "FAIL"; result.failure = String(error); await persist(); throw error;
}
