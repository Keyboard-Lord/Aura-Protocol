// Workspace isolation is an implementation invariant, not a protocol serialization rule.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../", import.meta.url));
const cargo = args => execFileSync("cargo", args, { cwd: root, encoding: "utf8" });
const metadata = JSON.parse(cargo(["metadata", "--format-version", "1", "--no-deps", "--offline"]));
const retired = new Set(["aura_protocol", "aura_cli_v1", "aura_submission_client_v1", "aura_reference_demo_v1"]);
const active = metadata.packages.filter(p => metadata.workspace_members.includes(p.id));
const forbidden = name => retired.has(name) || /^solana(?:-|_)/.test(name);
for (const pkg of active) {
  assert(!forbidden(pkg.name), `${pkg.name} must remain outside the active workspace`);
  for (const dep of pkg.dependencies) assert(!forbidden(dep.name), `${pkg.name} still depends on ${dep.name}`);
}
const defaults = metadata.workspace_default_members.map(id => active.find(p => p.id === id)?.name).sort();
assert.deepEqual(defaults, ["aura_bitcoin_v1", "aura_intent_lineage_v1", "aura_sdk_v1"]);
// The active lockfile covers supporting workspace packages as well as the default spine.
const lock = readFileSync(new URL("../Cargo.lock", import.meta.url), "utf8");
for (const [,name] of lock.matchAll(/^name = "([^"]+)"$/gm)) assert(!forbidden(name), `active lockfile contains ${name}`);
const tree = cargo(["tree", "--offline", "--locked", "--edges", "normal,build", "--prefix", "none",
  "-p", "aura_sdk_v1", "-p", "aura_bitcoin_v1", "-p", "aura_intent_lineage_v1"]);
assert(!/^(?:solana[-_]|aura_protocol\s|aura_submission_client_v1\s)/m.test(tree));
console.log(`PASS: ${active.length} active workspace packages, default proof/authorization/Bitcoin dependency tree, and lockfile exclude retired Solana packages`);
