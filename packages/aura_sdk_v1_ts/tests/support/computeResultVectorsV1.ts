import { schnorr } from '@noble/curves/secp256k1.js';
import * as c from '../../src/computeJobV1.ts';
import * as r from '../../src/computeResultV1.ts';
import {job as priorJob,payload} from './computeJobVectorsV1.ts';
export const hex=(b:Uint8Array)=>Buffer.from(b).toString('hex');
export const unhex=(h:string)=>Buffer.from(h,'hex');
export const key=(n:number)=>{const b=new Uint8Array(32);b[31]=n;return b;};
export const job=()=>({...priorJob(),coordinatorKey:schnorr.getPublicKey(key(1))});
export const input=()=>payload('INPUT');
export const sign=(d:Uint8Array,k:number)=>schnorr.sign(d,key(k),new Uint8Array(32));
function item(b:Uint8Array,commit:Uint8Array|null,digests:[string,Uint8Array,number][],decode:(b:Uint8Array)=>unknown){let mutations='';for(let i=0;i<b.length;i++){const m=Uint8Array.from(b);m[i]^=1;try{decode(m);mutations+='1';}catch{mutations+='0';}}
return {bytes_hex:hex(b),commitment_hex:commit?hex(commit):null,signatures:digests.map(([role,d,k])=>({role,key_hex:hex(schnorr.getPublicKey(key(k))),digest_hex:hex(d),signature_hex:hex(sign(d,k))})),single_bit_mutation_decodes:mutations};}
export function snapshot(){const j=job();const cases=([ [1,new Uint8Array(),new Uint8Array()], [2,Uint8Array.of(0,255,1),Uint8Array.of(5,6,255)], [4,new Uint8Array(32).fill(255),new Uint8Array(32)] ] as const).map(([worker,out,evidence])=>{
 const a={version:1,computeJobCommitment:c.computeJobCommitmentV1(j),workerKey:schnorr.getPublicKey(key(worker))};
 const counts={version:1,inputBytes:BigInt(input().length),outputBytes:BigInt(out.length),evidenceBytes:BigInt(evidence.length)};
 const receipt={version:1,assignmentCommitment:r.computeAssignmentCommitmentV1(a),outputCommitment:r.computeResultContentCommitmentV1('OUTPUT',out),executionEvidenceCommitment:r.computeResultContentCommitmentV1('EXECUTION_EVIDENCE',evidence),resourceAccountingCommitment:r.computeResourceAccountingCommitmentV1(counts)};
 const result={version:1,receiptCommitment:r.computeReceiptCommitmentV1(receipt),verificationVerdict:1};
 return {worker_secret_test_only:worker,output_hex:hex(out),evidence_hex:hex(evidence),
 assignment:item(r.encodeComputeAssignmentV1(a),r.computeAssignmentCommitmentV1(a),[['worker',r.computeAssignmentWorkerDigestV1(a),worker],['coordinator',r.computeAssignmentCoordinatorDigestV1(a),1]],r.decodeComputeAssignmentV1),
 accounting:item(r.encodeComputeResourceAccountingV1(counts),r.computeResourceAccountingCommitmentV1(counts),[],r.decodeComputeResourceAccountingV1),
 receipt:item(r.encodeComputeReceiptV1(receipt),r.computeReceiptCommitmentV1(receipt),[['worker',r.computeReceiptSigningDigestV1(receipt),worker]],r.decodeComputeReceiptV1),
 result:item(r.encodeVerifiedComputeResultV1(result),r.computeResultCommitmentV1(result),[['coordinator',r.computeResultSigningDigestV1(result),1]],r.decodeVerifiedComputeResultV1),
 miner_side_a_hex:hex(c.computeMinerSideV1(r.computeResultCommitmentV1(result),0)),miner_side_b_hex:hex(c.computeMinerSideV1(r.computeResultCommitmentV1(result),1))};
});
const cancel={version:1,computeJobCommitment:c.computeJobCommitmentV1(j)};
const accounting=([ [0n,0n,0n], [1n,9007199254740993n,0xffffffffffffffffn], [0xffffffffffffffffn,0xffffffffffffffffn,0xffffffffffffffffn] ]).map(([i,o,e])=>{const a={version:1,inputBytes:i,outputBytes:o,evidenceBytes:e};return {input_bytes:i.toString(),output_bytes:o.toString(),evidence_bytes:e.toString(),bytes_hex:hex(r.encodeComputeResourceAccountingV1(a)),commitment_hex:hex(r.computeResourceAccountingCommitmentV1(a))};});
return {classification:'C2 CODEC TEST VECTORS; NO VERIFIER ACCEPTANCE, HARDWARE OR PAYMENT CLAIM',job_hex:hex(c.encodeComputeJobV1(j)),request_signature_hex:hex(sign(c.computeJobSigningDigestV1(j),3)),input_hex:hex(input()),cases,cancel:item(r.encodeComputeCancelV1(cancel),null,[['requester',r.computeCancelSigningDigestV1(cancel),3]],r.decodeComputeCancelV1),accounting_extremes:accounting};}
