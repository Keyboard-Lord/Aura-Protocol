// C3 candidate client codec. Not registered as a production SDK adapter.
// These routines verify membership/framing, never cryptographic receipt validity.
import {createHash} from 'node:crypto';
import {computeContentCommitmentV1} from '../../packages/aura_sdk_v1_ts/src/computeJobV1.ts';
export const inputDomain=Buffer.from('AURA_C3_MERKLE_INPUT_V1');
export const journalDomain=Buffer.from('AURA_C3_MERKLE_JOURNAL_V1');
export const outputDomain=Buffer.from('AURA_C3_RISC0_SUCCINCT_V1');
const header=inputDomain.length+37;
export const maxInput=header+64*(36+32*32);
export const journalLength=journalDomain.length+100;
export const outputHeader=outputDomain.length+journalLength+32+4+8*32+4;
export const maxOutput=outputHeader+4*262144;
const hash=(b:Uint8Array)=>createHash('sha256').update(b).digest();
const requireThat=(b:boolean,s:string)=>{if(!b)throw new Error(s);};
export function checkBatch(input:Uint8Array){
  requireThat(input.length>=header && input.length<=maxInput,'input limit');
  const b=Buffer.from(input);requireThat(b.subarray(0,inputDomain.length).equals(inputDomain),'input domain');
  const count=b.readUInt32LE(inputDomain.length),depth=b[inputDomain.length+4],root=b.subarray(inputDomain.length+5,header);
  requireThat(count>=1&&count<=64&&depth<=32,'dimensions');
  const stride=36+32*depth;requireThat(b.length===header+count*stride,'exact input length');
  for(let i=0;i<count;i++){
    const row=b.subarray(header+i*stride,header+(i+1)*stride),index=row.readUInt32LE();
    requireThat(index<2**depth,'tree index');let node=hash(Buffer.concat([Buffer.of(0),row.subarray(4,36)]));
    for(let h=0;h<depth;h++){
      const sibling=row.subarray(36+h*32,68+h*32);
      node=hash(Buffer.concat((BigInt(index)&(1n<<BigInt(h)))===0n?[Buffer.of(1),node,sibling]:[Buffer.of(1),sibling,node]));
    }
    requireThat(node.equals(root),'membership');
  }
  return {count,depth,root:Buffer.from(root)};
}
export function expectedJournal(job:Uint8Array,input:Uint8Array):Buffer{
  requireThat(job.length===32,'job commitment length');const batch=checkBatch(input),n=Buffer.alloc(4);n.writeUInt32LE(batch.count);
  return Buffer.concat([journalDomain,job,computeContentCommitmentV1('INPUT',input),batch.root,n]);
}
export function checkProofFraming(output:Uint8Array):void{
  requireThat(output.length>=outputHeader&&output.length<=maxOutput,'output limit');const b=Buffer.from(output);
  requireThat(b.subarray(0,outputDomain.length).equals(outputDomain),'output domain');
  const p=outputDomain.length,j=b.subarray(p,p+journalLength);
  requireThat(j.subarray(0,journalDomain.length).equals(journalDomain),'journal domain');
  const count=j.readUInt32LE(j.length-4);requireThat(count>=1&&count<=64,'journal dimensions');
  requireThat(b.readUInt32LE(p+journalLength+32)<256,'control index');
  const words=b.readUInt32LE(outputHeader-4);requireThat(words>0&&words<=262144&&b.length===outputHeader+words*4,'seal bound or length');
}
