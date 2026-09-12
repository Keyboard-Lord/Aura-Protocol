// Independent TS fixture construction. Test-only keys and unsupported policy payloads.
import { readFileSync } from 'node:fs';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as c from '../../src/computeJobV1.ts';
import * as m from '../../src/minerV1.ts';
import { decodeEconomicMeterV1 } from '../../../aura_sdk_v0_ts/src/index.ts';
import { encodeEconomicWorkV1 } from '../../src/economicV1.ts';
export const hex=(b:Uint8Array)=>Buffer.from(b).toString('hex');
export const unhex=(s:string)=>Uint8Array.from(Buffer.from(s,'hex'));
export const m2=JSON.parse(readFileSync(new URL('../../../../fixtures/miner_v1/job_profile_vector_v1.json',import.meta.url),'utf8'));
export const key=(n:number)=>{const k=new Uint8Array(32);k[31]=n;return k;};
export const baseMiner=()=>m.decodeMinerJobV1(unhex(m2.job_hex));
export const payload=(kind:c.ComputeContentKindV1)=>Buffer.concat([Buffer.from(`TEST_ONLY/AURA_COMPUTE_${kind}_V1`,'ascii'),Buffer.from([0,255])]);
const content=(kind:c.ComputeContentKindV1)=>c.computeContentCommitmentV1(kind,payload(kind));
export function job():c.AuraComputeJobV1{
  const miner=baseMiner();
  return {jobVersion:1,network:'regtest',coordinatorKey:miner.operatorKey,journalNamespace:miner.journalNamespace,
    requesterKey:schnorr.getPublicKey(key(3)),jobNonce:Uint8Array.from({length:32},(_,i)=>i),workloadClass:0,
    adapterContractCommitment:content('ADAPTER_CONTRACT'),inputCommitment:content('INPUT'),programCommitment:content('PROGRAM'),
    executionSpecCommitment:content('EXECUTION_SPEC'),outputSpecCommitment:content('OUTPUT_SPEC'),verificationClass:0,
    verificationSpecCommitment:content('VERIFICATION_SPEC'),privacyClass:1,privacyPolicyCommitment:content('PRIVACY_POLICY'),
    hardwareRequirementsCommitment:content('HARDWARE_REQUIREMENTS'),maxInputBytes:4096n,maxOutputBytes:8192n,maxEvidenceBytes:16384n,
    maxMemoryBytes:1048576n,maxScratchBytes:0n,maxExecutionMs:1000n,acceptUntil:2000000100n,completeBy:2000000200n,
    compensationSatoshis:10000n,paymentTermsCommitment:content('PAYMENT_TERMS'),dataRightsCommitment:content('DATA_RIGHTS'),miningMode:1};
}
export const signature=(j:c.AuraComputeJobV1,n:number,aux:number)=>schnorr.sign(c.computeJobSigningDigestV1(j),key(n),new Uint8Array(32).fill(aux));
const record=(name:string,j:c.AuraComputeJobV1,n=3)=>({name,job_hex:hex(c.encodeComputeJobV1(j)),commitment_hex:hex(c.computeJobCommitmentV1(j)),signing_digest_hex:hex(c.computeJobSigningDigestV1(j)),signature_hex:hex(signature(j,n,0))});
const le=(v:bigint)=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(v);return b;};
export function snapshot(){
  const j=job(),b=c.encodeComputeJobV1(j),valid_jobs=[];
  for(const network of ['mainnet','testnet3','signet','regtest','testnet4'] as const)valid_jobs.push(record(network,{...j,network}));
  for(const amount of [1n,9007199254740993n,0xffffffffffffffffn])valid_jobs.push(record(`compensation_${amount}`,{...j,compensationSatoshis:amount}));
  valid_jobs.push(record('class_limit_extremes',{...j,workloadClass:10,verificationClass:7,privacyClass:4,miningMode:0,maxInputBytes:0n,maxScratchBytes:0xffffffffffffffffn,maxMemoryBytes:0xffffffffffffffffn,completeBy:0xffffffffffffffffn}));
  const single_bit_mutation_decodes=Array.from(b,(_,i)=>{const changed=Uint8Array.from(b);changed[i]^=1;try{c.decodeComputeJobV1(changed);return '1';}catch{return '0';}}).join('');
  const patches:[string,number,Uint8Array][]=[
    ['version',19,Uint8Array.of(2)],['network',20,Uint8Array.of(255)],['coordinator',21,new Uint8Array(32).fill(255)],['requester',85,new Uint8Array(32).fill(255)],
    ['workload',149,Uint8Array.of(11,0)],['workload_big_endian',149,Uint8Array.of(0,10)],['verification',311,Uint8Array.of(8)],['privacy',344,Uint8Array.of(5)],
    ['output_zero',417,le(0n)],['evidence_zero',425,le(0n)],['memory_zero',433,le(0n)],['execution_zero',449,le(0n)],['accept_zero',457,le(0n)],
    ['equal_deadlines',465,le(j.acceptUntil)],['reward_zero',473,le(0n)],['mining_mode',545,Uint8Array.of(2)]];
  const incoming=[j,{...j,compensationSatoshis:j.compensationSatoshis+1n},{...j,jobNonce:Uint8Array.from(j.jobNonce,(x,i)=>i===0?x^1:x)},
    {...j,journalNamespace:Uint8Array.from(j.journalNamespace,(x,i)=>i===0?x^1:x)},{...j,network:'mainnet' as const},
    {...j,coordinatorKey:schnorr.getPublicKey(key(4))},{...j,requesterKey:schnorr.getPublicKey(key(4))},{...j,completeBy:j.completeBy+1n}];
  const names=['same','new_compensation','new_nonce','new_namespace','new_network','new_coordinator','new_requester','new_deadline'];
  const retry_cases=incoming.map((x,i)=>{const sig=signature(x,i===6?4:3,1);return {name:names[i],job_hex:hex(c.encodeComputeJobV1(x)),signature_hex:hex(sig),outcome:c.classifyComputeRetryV1(j,x,sig)};});
  const meter=decodeEconomicMeterV1(unhex(m2.meter_hex),90000);
  const inputs=[new Uint8Array(32),Uint8Array.from({length:32},(_,i)=>i),Uint8Array.from({length:32},(_,i)=>i===0?1:0),new Uint8Array(32).fill(255)];
  const bindings=inputs.map((r,i)=>{
    const miner={...baseMiner(),sideA:c.computeMinerSideV1(r,0),sideB:c.computeMinerSideV1(r,1)};
    const work=m.buildMinerWorkV1(miner,meter,unhex(m2.nonce_hex));
    const digest=m.minerJobSigningDigestV1(miner);
    return {name:['zero','incrementing','one_bit','all_ff'][i],result_hex:hex(r),side_a_hex:hex(miner.sideA),side_b_hex:hex(miner.sideB),
      miner_job_hex:hex(m.encodeMinerJobV1(miner)),miner_commitment_hex:hex(m.minerJobCommitmentV1(miner)),miner_signing_digest_hex:hex(digest),
      miner_signature_hex:hex(schnorr.sign(digest,unhex(m2.test_only_operator_secret_hex),new Uint8Array(32))),
      intent_hex:hex(m.minerIntentCommitmentV1(miner,meter)),context_hex:hex(work.storm.contextBytesV1),work_hex:hex(encodeEconomicWorkV1(work)),route_hex:hex(m.minerRouteTagV1())};
  });
  return {classification:'C1 CODEC VECTORS; TEST-ONLY KEYS/POLICY PAYLOADS; NOT FUNDED OR VERIFIED COMPUTE',base:record('base',j),alternate_signature_hex:hex(signature(j,3,1)),valid_jobs,single_bit_mutation_decodes,
    invalid_patches:patches.map(([name,offset,replacement])=>({name,offset,replacement_hex:hex(replacement)})),retry_cases,
    contents:c.COMPUTE_CONTENT_KINDS_V1.map(k=>({domain:`AURA_COMPUTE_${k}_V1`,payload_hex:hex(payload(k)),commitment_hex:hex(content(k))})),bindings};
}
