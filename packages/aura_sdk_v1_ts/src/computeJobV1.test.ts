import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as c from './computeJobV1.ts';
import * as m from './minerV1.ts';
import { job,key,signature,payload,hex,unhex,snapshot,baseMiner } from '../tests/support/computeJobVectorsV1.ts';
const vector=JSON.parse(readFileSync(new URL('../../../fixtures/compute_job_v1/job_vectors_v1.json',import.meta.url),'utf8'));
const host=()=>({maxInputBytes:0xffffffffffffffffn,maxOutputBytes:0xffffffffffffffffn,maxEvidenceBytes:0xffffffffffffffffn,maxMemoryBytes:0xffffffffffffffffn,maxScratchBytes:0xffffffffffffffffn,maxExecutionMs:0xffffffffffffffffn});
const policy=(j:m.MinerJobV1)=>({network:j.network,operatorKey:j.operatorKey,journalNamespace:j.journalNamespace,policyEpoch:j.policyEpoch,iterationCount:j.iterationCount,target:j.target,maxWorkBytes:j.maxWorkBytes,maxMeterBytes:j.maxMeterBytes});
const limits={maxWorkBytes:100000,maxMeterBytes:90000,maxIterations:100n};

test('independent TS construction equals every Rust-generated canonical byte vector',()=>{
  // Hex equality is exact byte equality, not merely equality of decoded objects.
  assert.deepEqual(snapshot(),vector);
  assert.equal(c.COMPUTE_JOB_V1_BYTE_LEN,546);
  assert.deepEqual(c.encodeComputeJobV1(job()),Buffer.from(vector.base.job_hex,'hex'));
  const decoded=c.decodeComputeJobV1(unhex(vector.base.job_hex));
  for(const [name,value] of Object.entries(job())) {
    const actual=decoded[name as keyof typeof decoded];
    if(value instanceof Uint8Array) assert.equal(hex(actual as Uint8Array),hex(value));
    else assert.equal(actual,value);
  }
  for(const x of vector.valid_jobs){const j=c.decodeComputeJobV1(unhex(x.job_hex));
    assert.equal(hex(c.encodeComputeJobV1(j)),x.job_hex);assert.equal(hex(c.computeJobCommitmentV1(j)),x.commitment_hex);
    assert.equal(hex(c.computeJobSigningDigestV1(j)),x.signing_digest_hex);c.verifyComputeRequestV1(j,unhex(x.signature_hex));
  }
  assert.equal(Buffer.from(c.encodeComputeJobV1(job())).readBigUInt64LE(473),10000n);
});
test('every field occupies its exact approved byte offset and width',()=>{
  const spec=readFileSync(new URL('../../../reports/AURA_COMPUTE_JOB_V1_C1_DESIGN.md',import.meta.url),'utf8');
  const rows=[...spec.matchAll(/^\| (\d+) \| (\d+) \| `([^`]+)` \|/gm)];
  const j=job(), b=Buffer.from(c.encodeComputeJobV1(j));let end=0;
  assert.equal(rows.length,30);
  for(const [,o,w,name] of rows){const offset=Number(o),width=Number(w);assert.equal(offset,end);end+=width;
    const actual=b.subarray(offset,offset+width);
    if(name==='domain'){assert.equal(actual.toString('ascii'),'AURA_COMPUTE_JOB_V1');continue;}
    const camel=name.replace(/_([a-z])/g,(_,x)=>x.toUpperCase());const value=j[camel as keyof typeof j];
    if(value instanceof Uint8Array)assert.equal(actual.toString('hex'),hex(value));
    else if(typeof value==='bigint')assert.equal(actual.readBigUInt64LE(),value);
    else if(name==='network')assert.equal(actual[0],unhex(vector.valid_jobs.find((x:any)=>x.name==='regtest').job_hex)[20]);
    else assert.equal(width===2?actual.readUInt16LE():actual[0],value);
  }
  assert.equal(end,546);
});
test('all 546 job bytes and all 64 signature bytes reject unauthenticated changes',()=>{
  const b=unhex(vector.base.job_hex),sig=unhex(vector.base.signature_hex);
  assert.equal(vector.single_bit_mutation_decodes.length,546);
  for(let i=0;i<546;i++){
    const changed=Uint8Array.from(b);changed[i]^=1;let j:c.AuraComputeJobV1|undefined;
    try{j=c.decodeComputeJobV1(changed);}catch{}
    assert.equal(!!j,vector.single_bit_mutation_decodes[i]==='1',`decode ${i}`);
    if(j){assert.equal(hex(c.encodeComputeJobV1(j)),hex(changed));assert.notEqual(hex(c.computeJobCommitmentV1(j)),vector.base.commitment_hex);assert.throws(()=>c.verifyComputeRequestV1(j!,sig));}
  }
  for(let i=0;i<64;i++){const s=Uint8Array.from(sig);s[i]^=1;assert.throws(()=>c.verifyComputeRequestV1(job(),s));}
  for(const n of [0,1,32,63,65,128])assert.throws(()=>c.verifyComputeRequestV1(job(),new Uint8Array(n)));
});
test('framing, unsupported tags, invalid keys and scalar boundary mutations reject',()=>{
  const b=unhex(vector.base.job_hex);
  for(let i=0;i<546;i++)assert.throws(()=>c.decodeComputeJobV1(b.subarray(0,i)));
  for(const n of [1,32,546])assert.throws(()=>c.decodeComputeJobV1(Buffer.concat([b,Buffer.alloc(n)])));
  for(const x of vector.invalid_patches){const b=unhex(vector.base.job_hex);b.set(unhex(x.replacement_hex),x.offset);assert.throws(()=>c.decodeComputeJobV1(b),x.name);}
  for(const [offset,start] of [[20,5],[311,8],[344,5],[545,2]])for(let tag=start;tag<256;tag++){const a=Uint8Array.from(b);a[offset]=tag;assert.throws(()=>c.decodeComputeJobV1(a));}
});
test('TS API rejects coercion, aliases, missing properties and invalid widths',()=>{
  const j=job();
  for(const value of [1,10000,'10000',null,undefined,-1n,1n<<64n,NaN,Infinity])assert.throws(()=>c.encodeComputeJobV1({...j,compensationSatoshis:value} as any));
  for(const field of ['workloadClass','verificationClass','privacyClass','miningMode'])for(const value of [-0,-1,0.5,NaN,Infinity,'0',null,undefined])assert.throws(()=>c.encodeComputeJobV1({...j,[field]:value} as any));
  for(const field of Object.keys(j)){
    const missing={...j} as any;delete missing[field];assert.throws(()=>c.encodeComputeJobV1(missing));
    if(j[field as keyof typeof j] instanceof Uint8Array)for(const v of [new Uint8Array(31),new Uint8Array(33),[], '00'.repeat(32),null])assert.throws(()=>c.encodeComputeJobV1({...j,[field]:v} as any));
  }
  assert.throws(()=>c.encodeComputeJobV1({...j,job_version:1} as any));
  assert.throws(()=>c.encodeComputeJobV1({...j,[Symbol('extra')]:0} as any));
  const accessor={...j};let reads=0;
  Object.defineProperty(accessor,'compensationSatoshis',{get(){reads++;return 10000n;},enumerable:true});
  assert.throws(()=>c.encodeComputeJobV1(accessor));assert.equal(reads,0);
  assert.throws(()=>c.decodeComputeJobV1(vector.base.job_hex as any));
});
test('request authentication and retry classification preserve exact scope and signature independence',()=>{
  const j=job(),sig=unhex(vector.base.signature_hex),scope={network:j.network,coordinatorKey:j.coordinatorKey,journalNamespace:j.journalNamespace};
  c.verifyComputeCoordinatorV1(j,sig,scope);
  for(const bad of [{...scope,network:'mainnet' as const},{...scope,coordinatorKey:schnorr.getPublicKey(key(4))},{...scope,journalNamespace:new Uint8Array(32)}])assert.throws(()=>c.verifyComputeCoordinatorV1(j,sig,bad));
  const outcomes=['idempotent','conflict','distinct_scope','distinct_scope','distinct_scope','distinct_scope','distinct_scope','conflict'];
  for(const [i,x] of vector.retry_cases.entries()){
    const incoming=c.decodeComputeJobV1(unhex(x.job_hex));assert.equal(c.classifyComputeRetryV1(j,incoming,unhex(x.signature_hex)),outcomes[i]);
    assert.throws(()=>c.classifyComputeRetryV1(j,incoming,new Uint8Array(64)));
  }
  assert.notEqual(vector.base.signature_hex,vector.alternate_signature_hex);
  assert.throws(()=>c.validateComputeAssignmentV1(j,j.completeBy,0n,host()));
  assert.equal(c.classifyComputeRetryV1(j,j,unhex(vector.alternate_signature_hex)),'idempotent');
  c.verifyComputeRequestV1(j,c.signComputeRequestV1(j,key(3)));assert.throws(()=>c.signComputeRequestV1(j,key(4)));
});
test('host bounds, exclusive receipt deadline and wide budget arithmetic',()=>{
  const j=job();c.validateComputeAssignmentV1(j,2000000000n,1000n,host());assert.throws(()=>c.validateComputeAssignmentV1(j,j.acceptUntil,0n,host()));
  const x={...j,acceptUntil:2n,completeBy:3n,maxExecutionMs:1000n,maxScratchBytes:1n};
  c.validateComputeAssignmentV1(x,1n,999n,host());assert.throws(()=>c.validateComputeAssignmentV1(x,1n,1000n,host()));
  for(const f of Object.keys(host()))assert.throws(()=>c.validateComputeAssignmentV1(x,1n,0n,{...host(),[f]:0n}));
  const y={...x,acceptUntil:0xfffffffffffffffen,completeBy:0xffffffffffffffffn,maxExecutionMs:0xffffffffffffffffn};
  c.validateComputeAssignmentV1(y,0n,0xffffffffffffffffn,host());assert.throws(()=>c.validateComputeAssignmentV1(y,0xfffffffffffffffdn,0xffffffffffffffffn,host()));
});
test('exact content payloads include domain and length with no normalization',()=>{
  const j=job();
  for(const kind of c.COMPUTE_CONTENT_KINDS_V1){const p=payload(kind);c.verifyComputeContentV1(j,kind,p);
    for(let i=0;i<p.length;i++){const q=Uint8Array.from(p);q[i]^=1;assert.throws(()=>c.verifyComputeContentV1(j,kind,q));}
    assert.throws(()=>c.verifyComputeContentV1(j,kind,Buffer.concat([p,Buffer.from([0])])));
    for(const other of c.COMPUTE_CONTENT_KINDS_V1)if(kind!==other)assert.notEqual(hex(c.computeContentCommitmentV1(kind,p)),hex(c.computeContentCommitmentV1(other,p)));
  }
  assert.throws(()=>c.computeContentCommitmentV1('unknown' as any,new Uint8Array()));
  assert.throws(()=>c.verifyComputeContentV1({...j,maxInputBytes:0n},'INPUT',payload('INPUT')));
});
test('result binding requires the exact signed sides and existing miner verification',()=>{
  const j=job();const draft=JSON.parse(readFileSync(new URL('../../../reports/compute_network_v1/c1_binding_candidate_vectors.json',import.meta.url),'utf8'));
  for(const [index,x] of vector.bindings.entries()){
    const r=unhex(x.result_hex),miner=m.decodeMinerJobV1(unhex(x.miner_job_hex));c.validateComputeMinerBindingV1(j,miner,r);
    m.verifyMinerJobForPolicyV1(miner,unhex(x.miner_signature_hex),policy(miner),limits);
    for(let lane=0;lane<2;lane++)assert.equal(hex(c.computeMinerSideV1(r,lane)),draft.cases[index].lanes[lane].side_hex);
    const wrong=Uint8Array.from(r);wrong[31]^=1;assert.throws(()=>c.validateComputeMinerBindingV1(j,miner,wrong));
    const swapped={...miner,sideA:miner.sideB,sideB:miner.sideA};assert.throws(()=>c.validateComputeMinerBindingV1(j,swapped,r));
    assert.throws(()=>m.verifyMinerJobForPolicyV1(swapped,unhex(x.miner_signature_hex),policy(swapped),limits));
    const blocks=[];for(let i=1;i<=4;i++){const counter=Buffer.alloc(4);counter.writeUInt32LE(i);blocks.push(createHash('sha256').update(Buffer.concat([Buffer.from('AURA_COMPUTE_MINER_SIDE_V1'),Uint8Array.of(0),r,counter])).digest());}
    assert.throws(()=>c.validateComputeMinerBindingV1(j,{...miner,sideA:Buffer.concat(blocks).subarray(0,110)},r));
    const changed={...miner,sideA:Uint8Array.from(miner.sideA)};changed.sideA[109]^=1;assert.throws(()=>c.validateComputeMinerBindingV1(j,changed,r));
    assert.throws(()=>c.validateComputeMinerBindingV1({...j,miningMode:0},miner,r));
    assert.throws(()=>c.validateComputeMinerBindingV1(j,baseMiner(),r));
    for(const lane of [2,-1,-0,0.5,NaN])assert.throws(()=>c.computeMinerSideV1(r,lane));
    for(const bad of [r.subarray(1),new Uint8Array(33),hex(r)])assert.throws(()=>c.computeMinerSideV1(bad as any,0));
  }
});
