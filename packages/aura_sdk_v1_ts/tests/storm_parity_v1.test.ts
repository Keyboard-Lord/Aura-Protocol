import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildStormClaimV1, buildStormPublicInputsV1 } from "../src/stormClaimV1.ts";
import {
  deriveA,
  deriveB,
  derivePhiN,
  derivePsiN,
  deriveX0,
  deriveY0,
  executeStormV1,
} from "../src/stormExecutionV1.ts";
import {
  auraHash521V1,
  bytesToHexLowerV1,
  decodeCanonicalFixedHexBytesV1,
} from "../src/stormHash521V1.ts";
import { encodeStormRowBytesV1 } from "../src/stormStateV1.ts";
import { computeStormTraceRoot } from "../src/stormTraceCommitmentV1.ts";

type StormParityFixtureV1 = {
  contract: string;
  fixture_name: string;
  aura_hash521_v1_message_hex: string;
  side_a_hex: string;
  side_b_hex: string;
  context_bytes_v1_hex: string;
  iteration_count: number;
  expected: {
    aura_hash521_v1_hex: string;
    x0_hex: string;
    y0_hex: string;
    a_hex: string;
    b_hex: string;
    phi_0_hex: string;
    psi_0_hex: string;
    phi_last_hex: string;
    psi_last_hex: string;
    initial_state: {
      x_hex: string;
      y_hex: string;
    };
    initial_row_hex: string;
    final_state: {
      x_hex: string;
      y_hex: string;
    };
    final_row_hex: string;
    trace_root_hex: string;
    claim_trace_root_hex: string;
    storm_claim_wire: {
      version: number;
      modulus_id: number;
      iteration_count: number;
      side_a_hex: string;
      side_b_hex: string;
      context_bytes_hex: string;
      initial_state: {
        x_hex_66_be: string;
        y_hex_66_be: string;
      };
      final_state: {
        x_hex_66_be: string;
        y_hex_66_be: string;
      };
      trace_root_hex: string;
      legacy_commitment_root_hex: string;
      legacy_trace_commitment_hex: string;
    };
    public_inputs: {
      version: number;
      modulus_id: number;
      iteration_count: number;
      side_a_hash_hex: string;
      side_b_hash_hex: string;
      context_hash_hex: string;
      initial_state: {
        x_hex_66_be: string;
        y_hex_66_be: string;
      };
      final_state: {
        x_hex_66_be: string;
        y_hex_66_be: string;
      };
      trace_root_hex: string;
    };
  };
};

test("typescript matches the shared storm execution parity vector", () => {
  const fixture = loadFixture();
  assert.equal(fixture.contract, "AURA_STORM_EXECUTION_PARITY_VECTOR_V1");
  assert.equal(fixture.fixture_name, "storm_execution_parity_vector_v1");

  const sideA = decodeCanonicalFixedHexBytesV1(fixture.side_a_hex, 110, "side_a_hex");
  const sideB = decodeCanonicalFixedHexBytesV1(fixture.side_b_hex, 110, "side_b_hex");
  const contextBytesV1 = decodeCanonicalFixedHexBytesV1(
    fixture.context_bytes_v1_hex,
    209,
    "context_bytes_v1_hex",
  );
  const inputs = {
    sideA,
    sideB,
    contextBytesV1,
    iterationCount: BigInt(fixture.iteration_count),
  };

  const execution = executeStormV1(inputs);
  const claim = buildStormClaimV1(inputs);
  const publicInputs = buildStormPublicInputsV1(claim);

  assert.equal(
    bytesToHexLowerV1(
      auraHash521V1(
        decodeCanonicalFixedHexBytesV1(
          fixture.aura_hash521_v1_message_hex,
          fixture.aura_hash521_v1_message_hex.length / 2,
          "aura_hash521_v1_message_hex",
        ),
      ),
    ),
    fixture.expected.aura_hash521_v1_hex,
  );
  assert.equal(deriveX0(sideA), fixture.expected.x0_hex);
  assert.equal(deriveY0(sideB), fixture.expected.y0_hex);
  assert.equal(deriveA(contextBytesV1), fixture.expected.a_hex);
  assert.equal(deriveB(contextBytesV1), fixture.expected.b_hex);
  assert.equal(derivePhiN(sideA, sideB, contextBytesV1, 0n), fixture.expected.phi_0_hex);
  assert.equal(derivePsiN(sideA, sideB, contextBytesV1, 0n), fixture.expected.psi_0_hex);
  assert.equal(
    derivePhiN(sideA, sideB, contextBytesV1, BigInt(fixture.iteration_count - 1)),
    fixture.expected.phi_last_hex,
  );
  assert.equal(
    derivePsiN(sideA, sideB, contextBytesV1, BigInt(fixture.iteration_count - 1)),
    fixture.expected.psi_last_hex,
  );
  assert.equal(execution.initialState.xHex66Be, fixture.expected.initial_state.x_hex);
  assert.equal(execution.initialState.yHex66Be, fixture.expected.initial_state.y_hex);
  assert.equal(
    bytesToHexLowerV1(encodeStormRowBytesV1(execution.initialState)),
    fixture.expected.initial_row_hex,
  );
  assert.equal(execution.finalState.xHex66Be, fixture.expected.final_state.x_hex);
  assert.equal(execution.finalState.yHex66Be, fixture.expected.final_state.y_hex);
  assert.equal(
    bytesToHexLowerV1(encodeStormRowBytesV1(execution.finalState)),
    fixture.expected.final_row_hex,
  );
  assert.equal(
    bytesToHexLowerV1(computeStormTraceRoot(execution.trace)),
    fixture.expected.trace_root_hex,
  );
  assert.equal(claim.traceRootHex, fixture.expected.claim_trace_root_hex);
  assert.deepEqual(
    {
      version: claim.version,
      modulus_id: claim.modulusId,
      iteration_count: Number(claim.iterationCount),
      side_a_hex: claim.sideAHex,
      side_b_hex: claim.sideBHex,
      context_bytes_hex: claim.contextBytesHex,
      initial_state: {
        x_hex_66_be: claim.initialState.xHex66Be,
        y_hex_66_be: claim.initialState.yHex66Be,
      },
      final_state: {
        x_hex_66_be: claim.finalState.xHex66Be,
        y_hex_66_be: claim.finalState.yHex66Be,
      },
      trace_root_hex: claim.traceRootHex,
      legacy_commitment_root_hex: claim.legacyCommitmentRootHex,
      legacy_trace_commitment_hex: claim.legacyTraceCommitmentHex,
    },
    fixture.expected.storm_claim_wire,
  );
  assert.deepEqual(
    {
      version: publicInputs.version,
      modulus_id: publicInputs.modulusId,
      iteration_count: Number(publicInputs.iterationCount),
      side_a_hash_hex: publicInputs.sideAHashHex,
      side_b_hash_hex: publicInputs.sideBHashHex,
      context_hash_hex: publicInputs.contextHashHex,
      initial_state: {
        x_hex_66_be: publicInputs.initialState.xHex66Be,
        y_hex_66_be: publicInputs.initialState.yHex66Be,
      },
      final_state: {
        x_hex_66_be: publicInputs.finalState.xHex66Be,
        y_hex_66_be: publicInputs.finalState.yHex66Be,
      },
      trace_root_hex: publicInputs.traceRootHex,
    },
    fixture.expected.public_inputs,
  );
});

function loadFixture(): StormParityFixtureV1 {
  return JSON.parse(
    readFileSync(
      new URL(
        "../../../fixtures/v1/storm_v1/storm_execution_parity_vector_v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as StormParityFixtureV1;
}
