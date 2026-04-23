import test from "node:test";
import assert from "node:assert/strict";

import { computeStormTraceRoot } from "./stormTraceCommitmentV1.ts";
import type { StormState521V1 } from "./stormStateV1.ts";

const trace: StormState521V1[] = [
  {
    xHex66Be: `00${"00".repeat(64)}01`,
    yHex66Be: `00${"00".repeat(64)}02`,
  },
  {
    xHex66Be: `00${"00".repeat(64)}03`,
    yHex66Be: `00${"00".repeat(64)}04`,
  },
];

test("storm trace root is deterministic", () => {
  assert.deepEqual(computeStormTraceRoot(trace), computeStormTraceRoot(trace));
});
