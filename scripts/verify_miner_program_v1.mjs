// Full-system miner acceptance. --m7 preserves M6's historical result separately.
// No migration-wide audit, deployment, monetary activation or new protocol values.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, writeFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { arch, platform } from "node:os";

assert(process.env.BITCOIND && process.env.BITCOINCLI,"Set BITCOIND and BITCOINCLI; the gate requires real isolated Core regtest");
const root=fileURLToPath(new URL("../",import.meta.url));
const milestone=process.argv.includes("--m7")?"M7":"M6";
const evidence=join(root,`reports/miner_protocol_v1/${milestone.toLowerCase()}_acceptance_results.json`);
const result={classification:`${milestone} TEST EVIDENCE; NOT PROTOCOL AUTHORITY`,status:"RUNNING",environment:{node:process.version,platform:platform(),arch:arch(),rust:spawnSync("rustc",["--version"],{encoding:"utf8"}).stdout.trim()},stages:[],limitations:["An internally consistent whole-journal rollback requires external backup provenance; SQLite alone cannot identify its own old snapshot."]};
async function persist(){await mkdir(join(root,"reports/miner_protocol_v1"),{recursive:true});await writeFile(evidence,JSON.stringify(result,null,2)+"\n");}
async function stage(name,command,args,{tests=true,core=false}={}) {
  const started=performance.now();let output="";
  const code=await new Promise((resolve,reject)=>{
    const child=spawn(command,args,{cwd:root,env:process.env,stdio:["ignore","pipe","pipe"]});
    child.stdout.on("data",b=>output+=b);child.stderr.on("data",b=>output+=b);child.on("error",reject);child.on("close",resolve);
  });
  const rust=[...output.matchAll(/test result: ok\. (\d+) passed;/g)].map(m=>Number(m[1]));
  const node=[...output.matchAll(/^# tests (\d+)$/gm)].map(m=>Number(m[1]));
  const warnings=/(^warning:| WARN |^\(node:\d+\) (ExperimentalWarning|DeprecationWarning|Warning):)/m.test(output);
  const entry={name,command:[command,...args],exit_code:code,elapsed_ms:Math.round(performance.now()-started),rust_test_summaries:rust,node_test_summaries:node,status:"PASS"};
  let failure=code!==0 || warnings || (tests && rust.concat(node).reduce((a,b)=>a+b,0)===0);
  if(core && !failure) {
    try {
      entry.core_result=JSON.parse(output.trim().split("\n").at(-1));
      const expected=["wrong_bitcoin_network","crash_after_transaction_creation","fee_metadata","changed_anchor","changed_reward","removed_reserved_input","simultaneous_publication_retries","delayed_confirmation","duplicate_observation","delete_history","partial_snapshot","outbox","observation","observation_outbox_split","older_version_confirmed","unknown_spend","stale_snapshot_contradicted_by_bitcoin"];
      assert.equal(entry.core_result.status,"PASS");assert.deepEqual([...entry.core_result.adversarial_cases].sort(),expected.sort());
    }catch(error){failure=true;entry.core_error=String(error);}
  }
  if(failure){entry.status="FAIL";entry.output=output;result.stages.push(entry);await persist();throw new Error(`${name} failed\n${output}`);}
  result.stages.push(entry);await persist();console.log(`PASS ${name} (${entry.elapsed_ms} ms)`);
}
try {
  await persist();
  await stage("miner_search_coordination_publication_attacks","cargo",["test","-p","aura_sdk_v1","--offline","--lib"]);
  await stage("frozen_m2_authorization_economics_head","cargo",["test","-p","aura_sdk_v1","--offline","--test","miner_v1","--test","authorization_v2","--test","economic_contract_v1","--test","economic_journal_v1"]);
  await stage("active_hash_v2_owner","cargo",["test","-p","aura_intent_lineage_v1","--offline","--lib","storm_hash521_v1"]);
  await stage("canonical_field_owner","cargo",["test","-p","aura_intent_lineage_v1","--offline","--lib","field_521_v1"]);
  await stage("storm_trace_claim_frozen_parity","cargo",["test","-p","aura_intent_lineage_v1","--offline","--test","storm_hash521_v1","--test","storm_execution_v1","--test","storm_trace_commitment_v1","--test","storm_claim_v1","--test","storm_parity_v1","--test","storm_hash_quantum_hardening_v1"]);
  await stage("actual_storm_verifier","cargo",["test","-p","aura_intent_lineage_v1","--offline","--lib","stark_verifier_v1::tests::storm_real"]);
  await stage("material_fractal_key_bitcoin_wire","cargo",["test","-p","aura_proof_material_v1","-p","aura_fractal_key_v1","-p","aura_bitcoin_v1","--offline"]);
  await stage("udot_rust_typescript_parity","bash",["scripts/test_udot_parity.sh"]);
  const bitcoin=(await readdir(join(root,"packages/aura_bitcoin_v1_ts/tests"))).filter(f=>f.endsWith(".test.ts")).map(f=>`packages/aura_bitcoin_v1_ts/tests/${f}`);
  await stage("typescript_frozen_crypto_miner_economic_bitcoin","node",["--test",
    "packages/aura_sdk_v1_ts/src/stormHash521V1.test.ts","packages/aura_sdk_v1_ts/src/stormExecutionV1.test.ts","packages/aura_sdk_v1_ts/src/stormClaimV1.test.ts","packages/aura_sdk_v1_ts/tests/storm_parity_v1.test.ts",
    "packages/aura_sdk_v1_ts/src/minerV1.test.ts","packages/aura_sdk_v1_ts/src/minerSearchV1.test.ts","packages/aura_sdk_v1_ts/tests/authorization_v2.test.ts","packages/aura_sdk_v1_ts/src/economicV1.test.ts",...bitcoin]);
  await stage("sdk_production_compile","cargo",["check","-p","aura_sdk_v1","--offline","--lib","--bins","--examples"],{tests:false});
  await stage("bitcoin_adversarial_end_to_end","node",["scripts/verify_miner_regtest_v1.mjs","--adversarial"],{tests:false,core:true});
  result.status="PASS";await persist();console.log(`PASS Aura Miner V1 ${milestone} acceptance: ${result.stages.length} stages; evidence ${evidence}`);
}catch(error){result.status="FAIL";result.failure=String(error);await persist();throw error;}
