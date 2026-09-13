// C2 codecs/authentication only. No client boolean or signature creates a verifier verdict.
import { createHash } from 'node:crypto';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { computeJobCommitmentV1, verifyComputeContentV1 } from './computeJobV1.ts';
import type { AuraComputeJobV1 } from './computeJobV1.ts';
import { computeContentDigest } from './computeContentInternalV1.ts';
export const COMPUTE_ASSIGNMENT_V1_BYTE_LEN=91, COMPUTE_RECEIPT_V1_BYTE_LEN=152, COMPUTE_RESULT_V1_BYTE_LEN=56, COMPUTE_CANCEL_V1_BYTE_LEN=55, COMPUTE_RESOURCE_ACCOUNTING_V1_BYTE_LEN=25;
export type ComputeAssignmentV1={version:number;computeJobCommitment:Uint8Array;workerKey:Uint8Array};
export type ComputeReceiptV1={version:number;assignmentCommitment:Uint8Array;outputCommitment:Uint8Array;executionEvidenceCommitment:Uint8Array;resourceAccountingCommitment:Uint8Array};
export type VerifiedComputeResultV1={version:number;receiptCommitment:Uint8Array;verificationVerdict:number};
export type ComputeCancelV1={version:number;computeJobCommitment:Uint8Array};
export type ComputeResourceAccountingV1={version:number;inputBytes:bigint;outputBytes:bigint;evidenceBytes:bigint};
function ensure(x:unknown,msg:string):asserts x{if(!x)throw new Error(msg);}
function bytes(x:unknown,n?:number):asserts x is Uint8Array{ensure(x instanceof Uint8Array&&(n===undefined||x.length===n),'invalid compute bytes');}
function fields(x:unknown,ks:string[]):void{ensure(typeof x==='object'&&x!==null&&!Array.isArray(x)&&Reflect.ownKeys(x).length===ks.length&&ks.every(k=>{const d=Object.getOwnPropertyDescriptor(x,k);return d&&Object.hasOwn(d,'value');}),'noncanonical compute lifecycle fields');}
function eq(a:Uint8Array,b:Uint8Array):boolean{return Buffer.from(a).equals(Buffer.from(b));}
function sha(...b:Uint8Array[]):Uint8Array{const h=createHash('sha256');for(const x of b)h.update(x);return h.digest();}
function tagged(t:string,b:Uint8Array):Uint8Array{const h=sha(Buffer.from(t,'ascii'));return sha(h,h,b);}
function frame(d:string,v:number,...fs:Uint8Array[]):Uint8Array{ensure(v===1,'unsupported compute version');return Buffer.concat([Buffer.from(d,'ascii'),Uint8Array.of(v),...fs]);}
function payload(b:Uint8Array,d:string,n:number):Buffer{bytes(b,n);const dom=Buffer.from(d,'ascii');ensure(eq(b.subarray(0,dom.length),dom)&&b[dom.length]===1,'noncanonical compute framing');return Buffer.from(b.subarray(dom.length+1));}
function key(k:Uint8Array):void{bytes(k,32);secp256k1.Point.fromHex(`02${Buffer.from(k).toString('hex')}`);}
function verify(k:Uint8Array,d:Uint8Array,s:Uint8Array):void{key(k);bytes(s,64);ensure(schnorr.verify(s,d,k),'invalid compute lifecycle signature');}
function sign(k:Uint8Array,expected:Uint8Array,d:Uint8Array):Uint8Array{bytes(k,32);ensure(eq(schnorr.getPublicKey(k),expected),'compute signer mismatch');return schnorr.sign(d,k);}
export function encodeComputeAssignmentV1(a:ComputeAssignmentV1):Uint8Array{fields(a,['version','computeJobCommitment','workerKey']);bytes(a.computeJobCommitment,32);key(a.workerKey);return frame('AURA_COMPUTE_ASSIGNMENT_V1',a.version,a.computeJobCommitment,a.workerKey);}
export function decodeComputeAssignmentV1(b:Uint8Array):ComputeAssignmentV1{const p=payload(b,'AURA_COMPUTE_ASSIGNMENT_V1',91),a={version:1,computeJobCommitment:p.subarray(0,32),workerKey:p.subarray(32)};encodeComputeAssignmentV1(a);return a;}
export function computeAssignmentCommitmentV1(a:ComputeAssignmentV1):Uint8Array{return sha(encodeComputeAssignmentV1(a));}
export function computeAssignmentWorkerDigestV1(a:ComputeAssignmentV1):Uint8Array{return tagged('AURA_COMPUTE_ASSIGN_WORKER_V1',encodeComputeAssignmentV1(a));}
export function computeAssignmentCoordinatorDigestV1(a:ComputeAssignmentV1):Uint8Array{return tagged('AURA_COMPUTE_ASSIGN_COORDINATOR_V1',encodeComputeAssignmentV1(a));}
export function verifyComputeAssignmentJobV1(a:ComputeAssignmentV1,j:AuraComputeJobV1):void{encodeComputeAssignmentV1(a);ensure(eq(a.computeJobCommitment,computeJobCommitmentV1(j)),'assignment job mismatch');}
export function verifyComputeAssignmentWorkerV1(a:ComputeAssignmentV1,s:Uint8Array):void{verify(a.workerKey,computeAssignmentWorkerDigestV1(a),s);}
export function signComputeAssignmentWorkerV1(a:ComputeAssignmentV1,k:Uint8Array):Uint8Array{return sign(k,a.workerKey,computeAssignmentWorkerDigestV1(a));}
export function verifyComputeAssignmentCoordinatorV1(a:ComputeAssignmentV1,j:AuraComputeJobV1,s:Uint8Array):void{verifyComputeAssignmentJobV1(a,j);verify(j.coordinatorKey,computeAssignmentCoordinatorDigestV1(a),s);}
export function signComputeAssignmentCoordinatorV1(a:ComputeAssignmentV1,j:AuraComputeJobV1,k:Uint8Array):Uint8Array{verifyComputeAssignmentJobV1(a,j);return sign(k,j.coordinatorKey,computeAssignmentCoordinatorDigestV1(a));}
export type ComputeResultContentKindV1='OUTPUT'|'EXECUTION_EVIDENCE'|'RESOURCE_ACCOUNTING';
export function computeResultContentCommitmentV1(k:ComputeResultContentKindV1,b:Uint8Array):Uint8Array{ensure(['OUTPUT','EXECUTION_EVIDENCE','RESOURCE_ACCOUNTING'].includes(k),'unsupported result content kind');return computeContentDigest(`AURA_COMPUTE_${k}_V1`,b);}
function le(x:bigint):Uint8Array{ensure(typeof x==='bigint'&&x>=0n&&x<=0xffffffffffffffffn,'invalid compute u64');const b=Buffer.alloc(8);b.writeBigUInt64LE(x);return b;}
export function encodeComputeResourceAccountingV1(r:ComputeResourceAccountingV1):Uint8Array{fields(r,['version','inputBytes','outputBytes','evidenceBytes']);return frame('',r.version,le(r.inputBytes),le(r.outputBytes),le(r.evidenceBytes));}
export function decodeComputeResourceAccountingV1(b:Uint8Array):ComputeResourceAccountingV1{const p=payload(b,'',25);return {version:1,inputBytes:p.readBigUInt64LE(0),outputBytes:p.readBigUInt64LE(8),evidenceBytes:p.readBigUInt64LE(16)};}
export function computeResourceAccountingCommitmentV1(r:ComputeResourceAccountingV1):Uint8Array{return computeResultContentCommitmentV1('RESOURCE_ACCOUNTING',encodeComputeResourceAccountingV1(r));}
export function validateComputeResourceAccountingV1(r:ComputeResourceAccountingV1,j:AuraComputeJobV1,input:Uint8Array,output:Uint8Array,evidence:Uint8Array):void{encodeComputeResourceAccountingV1(r);bytes(output);bytes(evidence);verifyComputeContentV1(j,'INPUT',input);ensure(r.inputBytes===BigInt(input.length)&&r.outputBytes===BigInt(output.length)&&r.evidenceBytes===BigInt(evidence.length)&&r.outputBytes<=j.maxOutputBytes&&r.evidenceBytes<=j.maxEvidenceBytes,'compute resource count or limit');}
export function encodeComputeReceiptV1(r:ComputeReceiptV1):Uint8Array{const fs=['assignmentCommitment','outputCommitment','executionEvidenceCommitment','resourceAccountingCommitment'] as const;fields(r,['version',...fs]);for(const f of fs)bytes(r[f],32);return frame('AURA_COMPUTE_RECEIPT_V1',r.version,...fs.map(f=>r[f]));}
export function decodeComputeReceiptV1(b:Uint8Array):ComputeReceiptV1{const p=payload(b,'AURA_COMPUTE_RECEIPT_V1',152);return {version:1,assignmentCommitment:p.subarray(0,32),outputCommitment:p.subarray(32,64),executionEvidenceCommitment:p.subarray(64,96),resourceAccountingCommitment:p.subarray(96)};}
export function computeReceiptCommitmentV1(r:ComputeReceiptV1):Uint8Array{return sha(encodeComputeReceiptV1(r));}
export function computeReceiptSigningDigestV1(r:ComputeReceiptV1):Uint8Array{return tagged('AURA_COMPUTE_RECEIPT_SIGNATURE_V1',encodeComputeReceiptV1(r));}
export function verifyComputeReceiptAssignmentV1(r:ComputeReceiptV1,a:ComputeAssignmentV1):void{ensure(eq(r.assignmentCommitment,computeAssignmentCommitmentV1(a)),'receipt assignment mismatch');}
export function verifyComputeReceiptSignatureV1(r:ComputeReceiptV1,a:ComputeAssignmentV1,s:Uint8Array):void{verifyComputeReceiptAssignmentV1(r,a);verify(a.workerKey,computeReceiptSigningDigestV1(r),s);}
export function signComputeReceiptV1(r:ComputeReceiptV1,a:ComputeAssignmentV1,k:Uint8Array):Uint8Array{verifyComputeReceiptAssignmentV1(r,a);return sign(k,a.workerKey,computeReceiptSigningDigestV1(r));}
export function verifyComputeReceiptContentV1(r:ComputeReceiptV1,j:AuraComputeJobV1,c:ComputeResourceAccountingV1,input:Uint8Array,output:Uint8Array,evidence:Uint8Array):void{encodeComputeReceiptV1(r);validateComputeResourceAccountingV1(c,j,input,output,evidence);ensure(eq(r.outputCommitment,computeResultContentCommitmentV1('OUTPUT',output))&&eq(r.executionEvidenceCommitment,computeResultContentCommitmentV1('EXECUTION_EVIDENCE',evidence))&&eq(r.resourceAccountingCommitment,computeResourceAccountingCommitmentV1(c)),'receipt content mismatch');}
export function encodeVerifiedComputeResultV1(r:VerifiedComputeResultV1):Uint8Array{fields(r,['version','receiptCommitment','verificationVerdict']);bytes(r.receiptCommitment,32);ensure(r.verificationVerdict===1,'not a verified compute verdict');return frame('AURA_COMPUTE_RESULT_V1',r.version,r.receiptCommitment,Uint8Array.of(1));}
export function decodeVerifiedComputeResultV1(b:Uint8Array):VerifiedComputeResultV1{const p=payload(b,'AURA_COMPUTE_RESULT_V1',56),r={version:1,receiptCommitment:p.subarray(0,32),verificationVerdict:p[32]!};encodeVerifiedComputeResultV1(r);return r;}
export function computeResultCommitmentV1(r:VerifiedComputeResultV1):Uint8Array{return sha(encodeVerifiedComputeResultV1(r));}
export function computeResultSigningDigestV1(r:VerifiedComputeResultV1):Uint8Array{return tagged('AURA_COMPUTE_RESULT_SIGNATURE_V1',encodeVerifiedComputeResultV1(r));}
export function verifyComputeResultLineageV1(v:VerifiedComputeResultV1,j:AuraComputeJobV1,a:ComputeAssignmentV1,r:ComputeReceiptV1):void{verifyComputeAssignmentJobV1(a,j);verifyComputeReceiptAssignmentV1(r,a);encodeVerifiedComputeResultV1(v);ensure(eq(v.receiptCommitment,computeReceiptCommitmentV1(r)),'result receipt mismatch');}
export function verifyComputeResultSignatureV1(v:VerifiedComputeResultV1,j:AuraComputeJobV1,a:ComputeAssignmentV1,r:ComputeReceiptV1,s:Uint8Array):void{verifyComputeResultLineageV1(v,j,a,r);verify(j.coordinatorKey,computeResultSigningDigestV1(v),s);}
export function signComputeResultV1(v:VerifiedComputeResultV1,j:AuraComputeJobV1,a:ComputeAssignmentV1,r:ComputeReceiptV1,k:Uint8Array):Uint8Array{verifyComputeResultLineageV1(v,j,a,r);return sign(k,j.coordinatorKey,computeResultSigningDigestV1(v));}
export function encodeComputeCancelV1(c:ComputeCancelV1):Uint8Array{fields(c,['version','computeJobCommitment']);bytes(c.computeJobCommitment,32);return frame('AURA_COMPUTE_CANCEL_V1',c.version,c.computeJobCommitment);}
export function decodeComputeCancelV1(b:Uint8Array):ComputeCancelV1{const p=payload(b,'AURA_COMPUTE_CANCEL_V1',55);return {version:1,computeJobCommitment:p};}
export function computeCancelSigningDigestV1(c:ComputeCancelV1):Uint8Array{return tagged('AURA_COMPUTE_CANCEL_SIGNATURE_V1',encodeComputeCancelV1(c));}
function cancelJob(c:ComputeCancelV1,j:AuraComputeJobV1):void{ensure(eq(c.computeJobCommitment,computeJobCommitmentV1(j)),'cancel job mismatch');}
export function verifyComputeCancelSignatureV1(c:ComputeCancelV1,j:AuraComputeJobV1,s:Uint8Array):void{cancelJob(c,j);verify(j.requesterKey,computeCancelSigningDigestV1(c),s);}
export function signComputeCancelV1(c:ComputeCancelV1,j:AuraComputeJobV1,k:Uint8Array):Uint8Array{cancelJob(c,j);return sign(k,j.requesterKey,computeCancelSigningDigestV1(c));}
