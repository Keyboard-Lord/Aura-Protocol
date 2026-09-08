import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { buildStormHierarchyV2, executeStormHierarchyV2, computeHierarchyRootV2 } from "../src/stormHierarchyV2.ts";
import { buildStormTrace, bigIntToFieldHex, fieldHexToBigInt, mod521, encodeStepU64Le } from "../src/stormExecutionV1.ts";
import { auraHash521V1, concatBytesV1 } from "../src/stormHash521V1.ts";
import { computeStormTraceRoot } from "../src/stormTraceCommitmentV1.ts";
import { encodeStormRowBytesV1 } from "../src/stormStateV1.ts";

const v=JSON.parse(readFileSync(new URL("../../../fixtures/experimental/storm_hierarchy_v2/parity_vector_v2.json",import.meta.url),"utf8"));
const hex=(b:Uint8Array)=>Buffer.from(b).toString("hex");
const inputs=(n:bigint)=>({sideA:Buffer.from(v.side_a_hex,"hex"),sideB:Buffer.from(v.side_b_hex,"hex"),contextBytesV1:Buffer.from(v.context_bytes_v1_hex,"hex"),iterationCount:n});
const hash=(tag:string,...parts:Uint8Array[])=>{const h=createHash("sha3-256").update(tag);for(const p of parts)h.update(p);return new Uint8Array(h.digest());};
const fieldHash=(tag:string,...parts:Uint8Array[])=>fieldHexToBigInt(hex(auraHash521V1(concatBytesV1(new TextEncoder().encode(tag),...parts))),"field hash");

test("experimental Rust/TS vector and deterministic repeated execution",()=>{
  const i=inputs(129n); const h=executeStormHierarchyV2(i);
  assert.deepEqual(h,executeStormHierarchyV2(i)); assert.equal(Number(h.epochCount),v.epoch_count);
  assert.equal(h.initialMacroState,v.initial_macro_state_hex); assert.equal(h.finalMacroState,v.final_macro_state_hex);
  assert.equal(hex(h.hierarchyRoot),v.hierarchy_root_hex);
  assert.equal(hex(computeStormTraceRoot(buildStormTrace(i))),v.v1_trace_root_hex);
  assert.deepEqual(h.epochs.map(e=>({epoch_index:Number(e.epochIndex),start_step:Number(e.startStep),transition_count:Number(e.transitionCount),initial_state:e.initialState,final_state:e.finalState,epoch_trace_root_hex:hex(e.epochTraceRoot),epoch_commitment_hex:hex(e.epochCommitment),macro_state_before_hex:e.macroStateBefore,macro_state_after_hex:e.macroStateAfter})),v.epochs);
});

test("zero and transition boundaries share exact state rows without mutating V1",()=>{
  for(const n of [0n,1n,63n,64n,65n,128n,129n]){
    const i=inputs(n),trace=buildStormTrace(i),saved=structuredClone(trace);
    const h=buildStormHierarchyV2(i.contextBytesV1,trace);
    assert.equal(h.epochCount,n===0n?1n:(n-1n)/64n+1n); assert.equal(h.iterationCount,n);
    for(const [k,e] of h.epochs.entries()){
      assert.equal(e.epochIndex,BigInt(k));assert.equal(e.startStep,BigInt(k)*64n);
      assert.equal(e.transitionCount,n-e.startStep<64n?n-e.startStep:64n);
      const end=Number(e.startStep+e.transitionCount);
      assert.deepEqual(e.initialState,trace[Number(e.startStep)]); assert.deepEqual(e.finalState,trace[end]);
      assert.deepEqual(e.epochTraceRoot,computeStormTraceRoot(trace.slice(Number(e.startStep),end+1)));
      if(k>0){assert.deepEqual(encodeStormRowBytesV1(h.epochs[k-1]!.finalState),encodeStormRowBytesV1(e.initialState));assert.equal(h.epochs[k-1]!.macroStateAfter,e.macroStateBefore);}
    }
    assert.deepEqual(trace,saved);
    if(n===0n){assert.deepEqual(h.epochs[0]!.initialState,h.epochs[0]!.finalState);assert.notEqual(h.initialMacroState,h.finalMacroState);}
  }
});

test("commitment framing, order, singleton and odd-level duplication",()=>{
  const h=executeStormHierarchyV2(inputs(129n)); const e=h.epochs[1]!;
  assert.deepEqual(e.epochCommitment,hash("AURA_STORM_EPOCH_COMMITMENT_V2",encodeStepU64Le(1n),encodeStepU64Le(64n),encodeStepU64Le(64n),encodeStormRowBytesV1(e.initialState),encodeStormRowBytesV1(e.finalState),e.epochTraceRoot));
  const cs=h.epochs.map(e=>e.epochCommitment),ls=cs.map(c=>hash("AURA_STORM_HIERARCHY_LEAF_V2",c));
  const parent=(a:Uint8Array,b:Uint8Array)=>hash("AURA_STORM_HIERARCHY_PARENT_V2",a,b);
  assert.deepEqual(h.hierarchyRoot,parent(parent(ls[0]!,ls[1]!),parent(ls[2]!,ls[2]!)));
  assert.notDeepEqual(h.hierarchyRoot,computeHierarchyRootV2([...cs].reverse()));
  assert.deepEqual(computeHierarchyRootV2(cs.slice(0,1)),ls[0]);
  assert.throws(()=>computeHierarchyRootV2([]));assert.throws(()=>computeHierarchyRootV2([new Uint8Array(31)]));
});

test("every row and coordinate changes each containing epoch commitment",()=>{
  const i=inputs(65n),trace=buildStormTrace(i),base=buildStormHierarchyV2(i.contextBytesV1,trace);
  for(let row=0;row<trace.length;row++)for(const key of ["xHex66Be","yHex66Be"] as const){
    const changed=structuredClone(trace);changed[row]![key]=bigIntToFieldHex(fieldHexToBigInt(changed[row]![key],key)+1n);
    const h=buildStormHierarchyV2(i.contextBytesV1,changed);
    base.epochs.forEach((old,k)=>{const relevant=BigInt(row)>=old.startStep&&BigInt(row)<=old.startStep+old.transitionCount;
      if(relevant)assert.notDeepEqual(h.epochs[k]!.epochCommitment,old.epochCommitment);else assert.deepEqual(h.epochs[k]!.epochCommitment,old.epochCommitment);
    });
  }
});

test("macro uses V1 field reduction and endpoint changes propagate; interior-only changes do not",()=>{
  const i=inputs(129n),trace=buildStormTrace(i),base=buildStormHierarchyV2(i.contextBytesV1,trace);
  const alpha=fieldHash("AURA_STORM_MACRO_ALPHA_V2"),beta=fieldHash("AURA_STORM_MACRO_BETA_V2");
  for(const e of base.epochs){
    const z=fieldHexToBigInt(e.macroStateBefore,"z");
    const expected=mod521(z*z+alpha*fieldHexToBigInt(e.finalState.xHex66Be,"x")+beta*fieldHexToBigInt(e.finalState.yHex66Be,"y")+fieldHash("AURA_STORM_MACRO_RHO_V2",i.contextBytesV1,encodeStepU64Le(e.epochIndex)));
    assert.equal(e.macroStateAfter,bigIntToFieldHex(expected));
    const changed=structuredClone(trace),idx=Number(e.startStep+e.transitionCount);
    changed[idx]!.xHex66Be=bigIntToFieldHex(fieldHexToBigInt(changed[idx]!.xHex66Be,"x")+1n);
    assert.notEqual(base.finalMacroState,buildStormHierarchyV2(i.contextBytesV1,changed).finalMacroState);
  }
  const changed=structuredClone(trace);changed[1]!.xHex66Be=bigIntToFieldHex(fieldHexToBigInt(changed[1]!.xHex66Be,"x")+1n);
  const interior=buildStormHierarchyV2(i.contextBytesV1,changed);
  assert.notDeepEqual(base.hierarchyRoot,interior.hierarchyRoot);assert.equal(base.finalMacroState,interior.finalMacroState);
  assert.throws(()=>buildStormHierarchyV2(i.contextBytesV1,[]));
});
