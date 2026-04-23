/*
Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
Matrix: [[1,1],[1,2]] mod (2^521-1)
Date: 2026-03-26
*/
import test from "node:test";

import {
  assertCatMapFixtureSchemaV1,
  assertProductionVectorsMatchReferenceV1,
  assertToyPrimeCycleSuitesV1,
  loadCatMapTestVectorsV1,
} from "../../test_support/cat_map_fixture_v1.ts";

test("aura_submission_client_v1_ts consumes the canonical cat-map production vectors", () => {
  const fixture = loadCatMapTestVectorsV1();
  assertCatMapFixtureSchemaV1(fixture);
  assertProductionVectorsMatchReferenceV1(fixture);
});

test("aura_submission_client_v1_ts consumes the canonical cat-map toy-prime suites", () => {
  const fixture = loadCatMapTestVectorsV1();
  assertToyPrimeCycleSuitesV1(fixture);
});
