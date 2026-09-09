import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as sdk from "../src/index.ts";
import type { UdotBundleV2 } from "../src/index.ts";

const bundles: UdotBundleV2[] = JSON.parse(readFileSync(
  new URL("../../../fixtures/udot_v2/bundles.json", import.meta.url), "utf8",
));
const fields = ["proof_hash_hex", "seal_line", "crest", "matrix_sequence"] as const;
const first = bundles[0]!;

test("canonical UDOT bundles match all frozen Rust/TypeScript parity vectors", async () => {
  assert.equal(bundles.length, 3);
  for (const expected of bundles) {
    const generated = await sdk.generateUdotBundleV2(expected.proof_hash_hex);
    assert.deepEqual(Object.keys(generated), fields);
    assert.deepEqual(generated, expected);
    assert.deepEqual(
      await sdk.validateUdotBundleV2(JSON.parse(JSON.stringify(expected)), expected.proof_hash_hex),
      expected,
    );
    assert.deepEqual(await sdk.generateUdotBundleV2(expected.proof_hash_hex), generated);
  }
});

test("bundle generation and validation reject noncanonical proof hashes without normalization", async () => {
  for (const hash of [
    "AB".repeat(32), "0x" + "ab".repeat(32), "ab".repeat(31), "ab".repeat(33),
    "g".repeat(64), " ".repeat(64), "ab".repeat(32) + "\n", "", null, 42,
  ]) {
    await assert.rejects(sdk.generateUdotBundleV2(hash as string));
    await assert.rejects(sdk.validateUdotBundleV2({ ...first, proof_hash_hex: hash }, first.proof_hash_hex));
    await assert.rejects(sdk.validateUdotBundleV2(first, hash as string));
  }
});

test("canonical bundles reject missing, null, extra and legacy fields", async () => {
  for (const value of [null, undefined, [], "bundle", 1, true, Object.create(first)]) {
    await assert.rejects(sdk.validateUdotBundleV2(value, first.proof_hash_hex));
  }
  for (const field of fields) {
    const missing: Record<string, unknown> = { ...first };
    delete missing[field];
    await assert.rejects(sdk.validateUdotBundleV2(missing, first.proof_hash_hex));
    for (const value of [null, undefined, 1, []]) {
      await assert.rejects(sdk.validateUdotBundleV2({ ...first, [field]: value }, first.proof_hash_hex));
    }
  }
  for (const [field, value] of [
    ["extra", true], ["aura_hash_hex", first.proof_hash_hex],
    ["proofHashHex", first.proof_hash_hex], ["udot_version", "v2"],
    ["udotVersion", "v2"], ["matrix_form", "unused"], ["matrix_form", null],
    ["artifact_kind", "seal-line"], ["value", first.seal_line],
  ] as const) {
    await assert.rejects(sdk.validateUdotBundleV2({ ...first, [field]: value }, first.proof_hash_hex));
  }
  await assert.rejects(sdk.validateUdotBundleV2({ ...first, [Symbol("extra")]: true }, first.proof_hash_hex));
  const alias = { ...first, aura_hash_hex: first.proof_hash_hex } as Record<string, unknown>;
  delete alias.proof_hash_hex;
  await assert.rejects(sdk.validateUdotBundleV2(alias, first.proof_hash_hex));
});

test("every glyph position is bound to the expected proof hash", async () => {
  for (const field of ["seal_line", "crest", "matrix_sequence"] as const) {
    const glyphs = Array.from(first[field]);
    for (let index = 0; index < glyphs.length; index++) {
      const changed = [...glyphs];
      // Choose another valid V2 glyph so rejection proves binding, not just syntax.
      changed[index] = glyphs[index] === "∘" ? "•" : "∘";
      await assert.rejects(
        sdk.validateUdotBundleV2({ ...first, [field]: changed.join("") }, first.proof_hash_hex),
        (error: unknown) => error instanceof sdk.AuraSdkErrorV1 && error.code === "UdotArtifactValidationFailed",
      );
    }
    for (const value of ["", first[field] + "\n", "x" + first[field].slice(1)]) {
      await assert.rejects(sdk.validateUdotBundleV2({ ...first, [field]: value }, first.proof_hash_hex));
    }
  }
  const otherHash = first.proof_hash_hex === "00".repeat(32) ? "ff".repeat(32) : "00".repeat(32);
  await assert.rejects(
    sdk.validateUdotBundleV2(first, otherHash),
    (error: unknown) => error instanceof sdk.AuraSdkErrorV1 && error.code === "UdotBundleHashMismatch",
  );
  await assert.rejects(sdk.validateUdotBundleV2({ ...first, proof_hash_hex: otherHash }, otherHash));
});

test("retired UDOT APIs require the explicit legacy namespace", async () => {
  for (const name of [
    "generateUdotArtifactsV1", "parseUdotArtifactV1", "validateUdotArtifactV1",
    "generateUdotArtifactBundleWireV1", "parseUdotArtifactWireV1",
    "parseUdotArtifactBundleWireV1", "validateUdotArtifactWireV1",
    "validateUdotArtifactBundleWireV1",
  ]) {
    assert.equal(Object.hasOwn(sdk, name), false, name);
    assert.equal(typeof sdk.legacy[name as keyof typeof sdk.legacy], "function", name);
  }
  const historical = await sdk.legacy.generateUdotArtifactBundleWireV1({
    udot_version: "v2", aura_hash_hex: first.proof_hash_hex,
  });
  assert.equal(historical.seal_line, first.seal_line);
  assert.equal(historical.crest, first.crest);
  assert.equal(historical.udot_version, "v2");
  if (historical.udot_version === "v2") {
    assert.equal(historical.matrix_sequence, first.matrix_sequence);
    assert.equal(historical.matrix_form, await sdk.generateWalletVisualV1(first.proof_hash_hex));
  }
  await assert.rejects(sdk.validateUdotBundleV2(historical, first.proof_hash_hex));
});
