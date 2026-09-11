// Isolated M5 acceptance: real local mining/coordinator and sponsor-funded Core payment.
// All policy values below are research fixtures, not deployment defaults.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { bitcoinCoreRpcV1 } from "../packages/aura_bitcoin_v1_ts/src/coreRpc.ts";

const adversarial=process.argv.includes("--adversarial");
assert(process.env.BITCOIND && process.env.BITCOINCLI, "Set BITCOIND and BITCOINCLI explicitly");
const root=fileURLToPath(new URL("../",import.meta.url));
const built=spawnSync("cargo",["build","-p","aura_sdk_v1","--offline","--example","miner_m5_regtest"],{cwd:root,encoding:"utf8"});
assert.equal(built.status,0,built.stderr);
const server=createServer();await new Promise(r=>server.listen(0,"127.0.0.1",r));const port=server.address().port;await new Promise(r=>server.close(r));
const directory=await mkdtemp(join(tmpdir(),"aura-miner-regtest-"));
const coreArgs=["-regtest",`-datadir=${directory}`,"-server=1","-listen=0","-connect=0","-dnsseed=0","-discover=0","-rpcbind=127.0.0.1",`-rpcport=${port}`,"-printtoconsole=0"];
let child,exited,rpc,wallet,stderr="",spawnError;
async function startCore() {
  rpc=undefined;spawnError=undefined;
  child=spawn(process.env.BITCOIND,coreArgs,{stdio:["ignore","ignore","pipe"]});
  child.stderr.on("data",b=>stderr+=b);child.on("error",e=>spawnError=e);exited=new Promise(r=>child.once("close",r));
  for(let i=0;i<100;i++) {
    if(spawnError || child.exitCode!==null) throw new Error(`Core start failed: ${spawnError??stderr}`);
    try {const cookie=(await readFile(join(directory,"regtest",".cookie"),"utf8")).trim();rpc=bitcoinCoreRpcV1(`http://127.0.0.1:${port}`,cookie);await rpc("getblockchaininfo",[]);
      wallet=bitcoinCoreRpcV1(`http://127.0.0.1:${port}/wallet/aura-miner-test`,cookie);return;}
    catch{rpc=undefined;await delay(100);}
  }
  assert(rpc,`Core RPC unavailable: ${stderr}`);
}
try {
  await startCore();
  await rpc("createwallet",["aura-miner-test"]);
  const executable=join(root,"target/debug/examples/miner_m5_regtest");const journal=join(directory,"miner.sqlite");
  function runner(path) {
    const commandArgs=(command,args)=>[command==="publish-crash"?"publish":command==="prepare-crash"?"prepare":command,path,...args.map(String)];
    const env=(command)=>({...process.env,AURA_M5_CORE_DATADIR:directory,AURA_M5_CORE_PORT:String(port),AURA_M5_CRASH_AFTER_BROADCAST:command==="publish-crash"?"1":"0",AURA_M6_CRASH_AFTER_TRANSACTION:command==="prepare-crash"?"1":"0"});
    const run=(command,...args)=>spawnSync(executable,commandArgs(command,args),{cwd:root,encoding:"utf8",env:env(command)});
    const read=(command,...args)=>{const p=run(command,...args);assert.equal(p.status,0,`${command}: ${p.stderr}`);return JSON.parse(p.stdout);};
    const concurrent=(command,...args)=>new Promise((resolve,reject)=>{const child=spawn(executable,commandArgs(command,args),{cwd:root,env:env(command)});let out="",err="";child.stdout.on("data",b=>out+=b);child.stderr.on("data",b=>err+=b);child.on("error",reject);child.on("close",code=>code===0?resolve(JSON.parse(out)):reject(new Error(err)));});
    return {run,read,concurrent};
  }
  const {run,read,concurrent}=runner(journal);
  const attacks=[];
  function mutate(path,mode,payment) {
    const script=`import sqlite3,json,sys
c=sqlite3.connect(sys.argv[1]);mode=sys.argv[2]
if mode=='payment':
 p=json.loads(sys.argv[3]);c.execute('UPDATE miner_payment_versions SET txid=?,payment=? WHERE revision=?',(p['txid'],json.dumps(p),p['revision']))
elif mode=='delete_history':
 c.execute('DELETE FROM miner_payment_observations');c.execute('DELETE FROM miner_payment_versions')
elif mode=='partial_snapshot': c.execute('UPDATE economic_state SET ledger=initial_ledger')
elif mode=='outbox': c.execute("UPDATE economic_outbox SET txid=?",('88'*32,))
elif mode=='observation':
 w=json.loads(c.execute('SELECT observation FROM miner_payment_observations').fetchone()[0]);w['observed_tip']='00';c.execute('UPDATE miner_payment_observations SET observation=?',(json.dumps(w),))
elif mode=='observation_outbox_split':
 old=c.execute('SELECT txid FROM miner_payment_versions ORDER BY revision LIMIT 1').fetchone()[0];w=json.loads(c.execute('SELECT observation FROM miner_payment_observations').fetchone()[0]);w['txid']=old;c.execute('UPDATE miner_payment_observations SET observation=?',(json.dumps(w),))
c.commit();c.close()`;
    const result=spawnSync("python3",["-c",script,path,mode,JSON.stringify(payment??null)],{encoding:"utf8"});assert.equal(result.status,0,result.stderr);
  }
  const address=await wallet("getnewaddress",[]);await rpc("generatetoaddress",[adversarial?104:101,address]);
  for(const config of [[1,2],[1_000_000_000_000,2],[10_000,1000]]) {
    const rejected=run("setup",...config);assert.notEqual(rejected.status,0,`pre-open rejection missing: ${config}`);
    assert.deepEqual(await wallet("listlockunspent",[]),[]);
    await rm(journal,{force:true});
  }
  const setup=read("setup");assert.equal(setup.attempt_id,1);assert.equal(setup.reward_satoshis,10_000);
  const initial=read("status");assert.equal(initial.obligations,1);assert.equal(initial.burned_supply,setup.burn_units);assert.equal(initial.outbox.length,1);
  assert.equal((await wallet("listlockunspent",[])).some(o=>o.txid===setup.funding_txid&&o.vout===setup.funding_vout),true);
  const rejected=run("prepare",1,2,1);assert.notEqual(rejected.status,0);assert.deepEqual(read("payments"),[]);
  if(adversarial) {
    assert.match(run("wrong-network").stderr,/network mismatch/);attacks.push("wrong_bitcoin_network");
    assert.equal(run("prepare-crash",1,2,20_000).status,87);assert.deepEqual(read("payments"),[]);assert.deepEqual(await rpc("getrawmempool",[]),[]);attacks.push("crash_after_transaction_creation");
  }
  const first=read("prepare",1,2,20_000);assert.equal(first.revision,1);assert(first.fee_satoshis>0&&first.fee_satoshis<=20_000);
  assert.deepEqual(read("prepare",1,10,20_000),first); // Fee retry cannot create another payment.
  const decoded=await wallet("decoderawtransaction",[first.transaction_hex]);
  const expectedReward=`5120${setup.subject}`;
  const checkPayment=tx=>{
    assert.equal(tx.vin.filter(i=>i.txid===setup.funding_txid&&i.vout===setup.funding_vout).length,1);
    const reward=tx.vout.filter(o=>o.scriptPubKey.hex===expectedReward);assert.equal(reward.length,1);assert.equal(Math.round(reward[0].value*1e8),10_000);
    const anchors=tx.vout.filter(o=>o.scriptPubKey.hex.startsWith("6a2641555241"));assert.equal(anchors.length,1);assert.equal(anchors[0].value,0);
    assert.equal(anchors[0].scriptPubKey.hex,`6a26415552410103${setup.proof_hash}`);
  };checkPayment(decoded);
  await rpc("stop",[]);await exited;await startCore();
  if(!(await rpc("listwallets",[])).includes("aura-miner-test")) await rpc("loadwallet",["aura-miner-test"]);
  assert.equal((await wallet("listlockunspent",[])).length,0);
  assert.equal(read("observe",1,2).status,"unbroadcast");
  assert.equal((await wallet("listlockunspent",[])).some(o=>o.txid===setup.funding_txid&&o.vout===setup.funding_vout),true);
  // Every command is a fresh process. Signed bytes survive preparation/restart.
  assert.deepEqual(read("payments"),[first]);
  if(adversarial) {
    const alternate=(await wallet("listunspent",[1])).find(c=>c.txid!==setup.funding_txid&&c.vout===setup.funding_vout);
    assert(alternate,"need another wallet input for reserved-input mutation");
    const u64le=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b.toString("hex");};
    for(const mode of ["fee_metadata","changed_anchor","changed_reward","removed_reserved_input"]) {
      const bad=join(directory,`${mode}.sqlite`);await copyFile(journal,bad);const p={...first};
      if(mode==="fee_metadata")p.fee_satoshis++;
      if(mode==="changed_anchor")p.transaction_hex=p.transaction_hex.replace(`6a26415552410103${setup.proof_hash}`,`6a26415552410103${"cd".repeat(32)}`);
      if(mode==="changed_reward")p.transaction_hex=p.transaction_hex.replace(`${u64le(10_000)}22${expectedReward}`,`${u64le(10_001)}22${expectedReward}`);
      if(mode==="removed_reserved_input")p.transaction_hex=p.transaction_hex.replace(Buffer.from(setup.funding_txid,"hex").reverse().toString("hex"),Buffer.from(alternate.txid,"hex").reverse().toString("hex"));
      if(mode!=="fee_metadata") {
        assert.notEqual(p.transaction_hex,first.transaction_hex);p.txid=(await wallet("decoderawtransaction",[p.transaction_hex])).txid;
        p.transaction_checksum=createHash("sha256").update(Buffer.from(p.transaction_hex,"hex")).digest("hex");
      }
      mutate(bad,"payment",p);const rejected=runner(bad).run("publish",1,2);assert.notEqual(rejected.status,0,mode);
      assert.match(rejected.stderr,/payment|reward|Aura anchor|reserved/);assert.deepEqual(await rpc("getrawmempool",[]),[]);attacks.push(mode);
    }
  }
  assert.equal(run("publish-crash",1,2).status,86);
  assert.equal(read("status").outbox[0].txid,null);
  assert.deepEqual(await rpc("getrawmempool",[]),[first.txid]);
  assert.equal(read("publish",1,2).txid,first.txid);
  if(adversarial) {
    const retried=await Promise.all(Array.from({length:4},()=>concurrent("publish",1,2)));assert(retried.every(o=>o.txid===first.txid));
    for(let i=0;i<3;i++)assert.equal(read("observe",1,2).status,"pending");
    attacks.push("simultaneous_publication_retries","delayed_confirmation","duplicate_observation");
  }
  const second=read("replace",1,first.txid,10,20_000);assert.equal(second.revision,2);assert(second.fee_satoshis>first.fee_satoshis);assert.notEqual(second.txid,first.txid);
  checkPayment(await wallet("decoderawtransaction",[second.transaction_hex]));
  assert.equal(read("publish",1,2).txid,second.txid);
  assert.notEqual(run("replace",1,first.txid,12,20_000).status,0);
  assert.deepEqual(await rpc("getrawmempool",[]),[second.txid]);
  const [paymentBlock]=await rpc("generatetoaddress",[1,address]);
  const included=read("observe",1,2);assert.equal(included.status,"included");assert.equal(included.confirmations,1);
  await rpc("generatetoaddress",[1,address]);const confirmed=read("observe",1,2);assert.equal(confirmed.status,"confirmed");assert.equal(confirmed.confirmations,2);
  assert.notEqual(run("replace",1,second.txid,12,20_000).status,0);
  await rpc("invalidateblock",[paymentBlock]);
  const reorg=read("observe",1,2);assert(["pending","unbroadcast"].includes(reorg.status),JSON.stringify(reorg));
  assert.equal(read("publish",1,2).status,"pending");const forkAddress=await wallet("getnewaddress",[]);await rpc("generatetoaddress",[2,forkAddress]);assert.equal(read("observe",1,2).status,"confirmed");
  const retry=read("retry");assert.deepEqual(retry.head,setup.head);assert.equal(retry.burn_units,setup.burn_units);
  const final=read("status");assert.deepEqual(final.head,initial.head);assert.equal(final.burned_supply,initial.burned_supply);assert.equal(final.obligations,1);assert.equal(final.outbox[0].txid,second.txid);
  assert.equal(read("payments").length,2);
  if(adversarial) {
    for(const mode of ["delete_history","partial_snapshot","outbox","observation","observation_outbox_split"]) {
      const bad=join(directory,`${mode}.sqlite`);await copyFile(journal,bad);mutate(bad,mode);assert.notEqual(runner(bad).run("payments").status,0,mode);attacks.push(mode);
    }
    // A prepared later revision cannot override an older payment confirmed by Core.
    const oldPath=join(directory,"older-confirmed.sqlite");const older=runner(oldPath);const os=older.read("setup");
    const op=older.read("prepare",1,2,20_000);older.read("publish",1,1);const replacement=older.read("replace",1,op.txid,10,20_000);
    await rpc("generatetoaddress",[1,await wallet("getnewaddress",[])]);
    const actual=older.read("publish",1,1);assert.equal(actual.status,"confirmed");assert.equal(actual.txid,op.txid);assert.notEqual(actual.txid,replacement.txid);
    assert.equal(older.read("status").obligations,1);assert.equal(older.read("status").burned_supply,os.burn_units);attacks.push("older_version_confirmed");
    // Sponsor deliberately spends an owned reservation outside the miner publisher.
    const lostPath=join(directory,"unknown-spend.sqlite");const lost=runner(lostPath);const ls=lost.read("setup");const lp=lost.read("prepare",1,2,20_000);
    const snapshot=join(directory,"stale-payment-snapshot.sqlite");await copyFile(lostPath,snapshot);
    const recipient=await wallet("getnewaddress",[]);
    const funded=await wallet("walletcreatefundedpsbt",[[{txid:ls.funding_txid,vout:ls.funding_vout}],[{[recipient]:0.0002}],0,{add_inputs:false,fee_rate:2}]);
    const signed=await wallet("walletprocesspsbt",[funded.psbt]);const finalized=await wallet("finalizepsbt",[signed.psbt]);assert.equal(finalized.complete,true);
    const unknown=await wallet("sendrawtransaction",[finalized.hex]);assert.notEqual(unknown,lp.txid);
    assert.equal(lost.read("publish",1,2).status,"recovery_required");assert.equal(runner(snapshot).read("publish",1,2).status,"recovery_required");
    assert.equal(lost.read("payments").length,1);assert.equal(lost.read("status").burned_supply,ls.burn_units);assert.equal(lost.read("status").obligations,1);
    assert.deepEqual(await rpc("getrawmempool",[]),[unknown]);attacks.push("unknown_spend","stale_snapshot_contradicted_by_bitcoin");
  }
  console.log(JSON.stringify({status:"PASS",core_version:(await rpc("getnetworkinfo",[])).version,iteration_count:8,target:"7f"+"ff".repeat(31),
    reward_satoshis:10_000,initial_fee_satoshis:first.fee_satoshis,replacement_fee_satoshis:second.fee_satoshis,payment_vsize:second.virtual_size,
    accepted_winners:1,reward_obligations:1,payment_versions:2,burn_units:setup.burn_units,confirmed_after_reorg:true,broadcast_crash_recovered:true,core_restart_lock_restored:true,pre_open_dust_funding_fee_rejections:3,adversarial_cases:attacks}));
} catch(error) {
  try {console.error((await readFile(join(directory,"regtest","debug.log"),"utf8")).split("\n").slice(-20).join("\n"));}catch{}
  throw error;
} finally {
  try{if(rpc)await rpc("stop",[]);else child.kill("SIGTERM");}catch{child.kill("SIGTERM");}
  const timer=setTimeout(()=>{if(child.exitCode===null)child.kill("SIGKILL");},10_000);timer.unref();await exited;clearTimeout(timer);
  await rm(directory,{recursive:true,force:true});
}
