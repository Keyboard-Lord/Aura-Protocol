// Interoperability only: Rust owns actual witness proving and verification.
import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {decodeMinerJobV1, validateMinerWorkProfileV1, passesMinerHashFilterV1} from "./minerV1.ts";
import {decodeEconomicWorkV1, encodeEconomicWorkV1} from "./economicV1.ts";
import {prepareBoundProofMaterialV1} from "./sdkCoreV1.ts";

test("M3 Rust proof bytes retain existing TS work/material/FractalKey reference interoperability", async () => {
  const v=JSON.parse(readFileSync(new URL("../../../fixtures/miner_v1/trial_vector_v1.json",import.meta.url),"utf8"));
  const bytes=(s:string)=>Uint8Array.from(Buffer.from(s,"hex"));
  const hex=(b:Uint8Array)=>Buffer.from(b).toString("hex");
  const job=decodeMinerJobV1(bytes(v.job_hex));
  const work=decodeEconomicWorkV1(bytes(v.work_hex),{maxWorkBytes:100000,maxMeterBytes:90000,maxIterations:128n});
  validateMinerWorkProfileV1(job,work);
  assert.equal(hex(encodeEconomicWorkV1(work)),v.work_hex);
  const prepared=await prepareBoundProofMaterialV1(work.storm.contextBytesV1.slice(145,177),
    work.storm.contextBytesV1.slice(97,129),bytes(v.proof_hex),bytes(v.public_inputs_hex),new Uint8Array());
  assert.equal(hex(prepared.proofMaterialHash),v.proof_material_hash_hex);
  assert.equal(hex(prepared.proofHash),v.proof_hash_hex);
  assert.equal(passesMinerHashFilterV1(job,prepared.proofHash),v.qualifies);
  // These assertions are not a TS proof-verification or authorization verdict.
});
