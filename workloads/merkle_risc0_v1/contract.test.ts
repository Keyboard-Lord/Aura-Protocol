import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {computeContentCommitmentV1} from '../../packages/aura_sdk_v1_ts/src/computeJobV1.ts';
import {checkBatch,expectedJournal,checkProofFraming,outputDomain,outputHeader,inputDomain,journalLength} from './codec.ts';
const cases=JSON.parse(readFileSync(new URL('./vectors/batch-v1.json',import.meta.url),'utf8')).cases;
test('independent TS relation and C1 owner equal Python/Rust candidate vectors',()=>{
  for(const v of cases){const b=Buffer.from(v.input_hex,'hex');const parsed=checkBatch(b);
    assert.equal(parsed.depth,v.depth);assert.equal(parsed.count,v.indices.length);
    assert.equal(Buffer.from(computeContentCommitmentV1('INPUT',b)).toString('hex'),v.input_commitment_hex);
    assert.equal(expectedJournal(Buffer.from(v.job_commitment_hex,'hex'),b).toString('hex'),v.journal_hex);
  }
  assert.notEqual(cases[2].input_commitment_hex,cases[3].input_commitment_hex);
});
test('every input mutation, truncation, limits and trailing bytes',()=>{
  const b=Buffer.from(cases[2].input_hex,'hex');
  for(let i=0;i<b.length;i++){const bad=Buffer.from(b);bad[i]^=1;assert.throws(()=>checkBatch(bad));assert.throws(()=>checkBatch(b.subarray(0,i)));}
  assert.throws(()=>checkBatch(Buffer.concat([b,Buffer.of(0)])));
  for(const count of [0,65,0xffffffff]){const bad=Buffer.from(b);bad.writeUInt32LE(count,inputDomain.length);assert.throws(()=>checkBatch(bad));}
  const bad=Buffer.from(b);bad[inputDomain.length+4]=33;assert.throws(()=>checkBatch(bad));
});
test('flat proof parser has no recursive or unbounded fields',()=>{
  const b=Buffer.alloc(outputHeader+4);outputDomain.copy(b);Buffer.from(cases[2].journal_hex,'hex').copy(b,outputDomain.length);b.writeUInt32LE(1,outputHeader-4);
  checkProofFraming(b); // Structural fixture only; not a valid proof.
  for(let i=0;i<b.length;i++)assert.throws(()=>checkProofFraming(b.subarray(0,i)));
  for(const n of [0,262145,0xffffffff]){const bad=Buffer.from(b);bad.writeUInt32LE(n,outputHeader-4);assert.throws(()=>checkProofFraming(bad));}
  const bad=Buffer.from(b);bad.writeUInt32LE(256,outputDomain.length+journalLength+32);assert.throws(()=>checkProofFraming(bad));
  assert.throws(()=>checkProofFraming(Buffer.concat([b,Buffer.of(0)])));
});
