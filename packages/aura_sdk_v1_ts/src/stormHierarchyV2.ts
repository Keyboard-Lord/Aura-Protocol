/** Experimental / non-authoritative. Deliberately absent from the canonical SDK entry. */
import { createHash } from "node:crypto";
import { auraHash521V1, bytesToHexLowerV1, concatBytesV1 } from "./stormHash521V1.ts";
import { buildStormTrace, encodeStepU64Le, fieldHexToBigInt, bigIntToFieldHex, mod521 } from "./stormExecutionV1.ts";
import type { StormExecutionInputsV1 } from "./stormExecutionV1.ts";
import { validateStormContextBytesV1 } from "./stormContextV1.ts";
import { encodeStormRowBytesV1 } from "./stormStateV1.ts";
import type { StormState521V1 } from "./stormStateV1.ts";
import { computeStormTraceRoot } from "./stormTraceCommitmentV1.ts";

export const STORM_EPOCH_TRANSITIONS_V2 = 64n;
export type StormEpochV2 = {
  epochIndex: bigint; startStep: bigint; transitionCount: bigint;
  initialState: StormState521V1; finalState: StormState521V1;
  epochTraceRoot: Uint8Array; epochCommitment: Uint8Array;
  macroStateBefore: string; macroStateAfter: string;
};
export type StormHierarchyV2 = {
  iterationCount: bigint; epochCount: bigint; epochs: StormEpochV2[];
  initialMacroState: string; finalMacroState: string; hierarchyRoot: Uint8Array;
};
const ascii = (text: string) => new TextEncoder().encode(text);
const alpha = fieldHexToBigInt(bytesToHexLowerV1(auraHash521V1(ascii("AURA_STORM_MACRO_ALPHA_V2"))), "macro alpha");
const beta = fieldHexToBigInt(bytesToHexLowerV1(auraHash521V1(ascii("AURA_STORM_MACRO_BETA_V2"))), "macro beta");
const fieldHash = (tag: string, ...parts: Uint8Array[]) => bytesToHexLowerV1(auraHash521V1(concatBytesV1(ascii(tag), ...parts)));
function hash256(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha3-256").update(tag);
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

export function executeStormHierarchyV2(inputs: StormExecutionInputsV1): StormHierarchyV2 {
  return buildStormHierarchyV2(inputs.contextBytesV1, buildStormTrace(inputs));
}

/** Commits supplied rows; does not verify their V1 recurrence. No input mutation. */
export function buildStormHierarchyV2(context: Uint8Array, trace: readonly StormState521V1[]): StormHierarchyV2 {
  validateStormContextBytesV1(context);
  if (trace.length === 0) throw new TypeError("hierarchy requires a nonempty Storm trace");
  const iterationCount = BigInt(trace.length - 1);
  const epochCount = iterationCount === 0n ? 1n : (iterationCount - 1n) / STORM_EPOCH_TRANSITIONS_V2 + 1n;
  const initialMacroState = fieldHash("AURA_STORM_MACRO_INIT_V2", context, encodeStormRowBytesV1(trace[0]!));
  let z = fieldHexToBigInt(initialMacroState, "initial macro state");
  const epochs: StormEpochV2[] = [];
  for (let k = 0n; k < epochCount; k++) {
    const startStep = k * STORM_EPOCH_TRANSITIONS_V2;
    const remaining = iterationCount - startStep;
    const transitionCount = remaining < STORM_EPOCH_TRANSITIONS_V2 ? remaining : STORM_EPOCH_TRANSITIONS_V2;
    const rows = trace.slice(Number(startStep), Number(startStep + transitionCount) + 1);
    const initialState = { ...rows[0]! }; const finalState = { ...rows[rows.length - 1]! };
    const epochTraceRoot = computeStormTraceRoot(rows);
    const epochCommitment = hash256("AURA_STORM_EPOCH_COMMITMENT_V2", encodeStepU64Le(k), encodeStepU64Le(startStep),
      encodeStepU64Le(transitionCount), encodeStormRowBytesV1(initialState), encodeStormRowBytesV1(finalState), epochTraceRoot);
    const rho = fieldHexToBigInt(fieldHash("AURA_STORM_MACRO_RHO_V2", context, encodeStepU64Le(k)), "macro rho");
    const before = bigIntToFieldHex(z);
    // Same V1 canonical field decoding, modular reduction and encoding; no alternate arithmetic.
    z = mod521(z * z + alpha * fieldHexToBigInt(finalState.xHex66Be, "epoch x")
      + beta * fieldHexToBigInt(finalState.yHex66Be, "epoch y") + rho);
    epochs.push({ epochIndex: k, startStep, transitionCount, initialState, finalState,
      epochTraceRoot, epochCommitment, macroStateBefore: before, macroStateAfter: bigIntToFieldHex(z) });
  }
  return { iterationCount, epochCount, epochs, initialMacroState, finalMacroState: bigIntToFieldHex(z),
    hierarchyRoot: computeHierarchyRootV2(epochs.map(e => e.epochCommitment)) };
}

export function computeHierarchyRootV2(commitments: readonly Uint8Array[]): Uint8Array {
  if (commitments.length === 0 || commitments.some(c => !(c instanceof Uint8Array) || c.length !== 32)) {
    throw new TypeError("hierarchy requires nonempty ordered 32-byte commitments");
  }
  let level = commitments.map(c => hash256("AURA_STORM_HIERARCHY_LEAF_V2", c));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hash256("AURA_STORM_HIERARCHY_PARENT_V2", level[i]!, level[i + 1] ?? level[i]!));
    }
    level = next;
  }
  return level[0]!;
}
