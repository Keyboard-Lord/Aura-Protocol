// Isolated Rust authorization and actual Aura proof admission through Bitcoin anchoring.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { bitcoinCoreRpcV1, prepareBitcoinAnchorV1, broadcastBitcoinAnchorV1, observeBitcoinAnchorV1 }
  from "../packages/aura_bitcoin_v1_ts/src/coreRpc.ts";

if (!process.env.BITCOIND) throw new Error("Set BITCOIND to a Bitcoin Core bitcoind executable");
const root = fileURLToPath(new URL("../", import.meta.url));
const build = spawnSync("cargo", ["build", "-p", "aura_sdk_v1", "--offline", "--bin", "aura-authorizer"], { cwd: root, encoding: "utf8" });
assert.equal(build.status, 0, build.stderr);
const authorizer = join(root, "target/debug/aura-authorizer");
const server = createServer();
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
await new Promise(resolve => server.close(resolve));
const directory = await mkdtemp(join(tmpdir(), "aura-bitcoin-regtest-"));
const child = spawn(process.env.BITCOIND, ["-regtest", `-datadir=${directory}`, "-server=1", "-listen=0",
  "-connect=0", "-dnsseed=0", "-discover=0", "-rpcbind=127.0.0.1", `-rpcport=${port}`, "-printtoconsole=0"],
  { stdio: ["ignore", "ignore", "pipe"] });
let stderr = "";
child.stderr.on("data", data => { stderr += data; });
let spawnError;
child.on("error", error => { spawnError = error; });
const exited = new Promise(resolve => child.once("close", resolve));
let rpc;
try {
  const vector = JSON.parse(await readFile(new URL("../fixtures/authorization_v2/authorization_vector_v2.json", import.meta.url), "utf8"));
  const journal = join(directory, "authorizer.sqlite");
  const authorizationFile = join(directory, "authorization.json");
  const proofFile = join(directory, "proof.bin");
  await writeFile(authorizationFile, JSON.stringify(vector.authorization));
  await writeFile(proofFile, Buffer.from(vector.proof_bytes_hex, "hex"));
  const runAuthorizer = args => spawnSync(authorizer, args, { cwd: root, encoding: "utf8" });
  assert.equal(runAuthorizer(["init", journal]).status, 0);
  const accept = () => runAuthorizer(["accept", journal, "regtest", authorizationFile, proofFile, "10", "1048576"]);
  const invalid = structuredClone(vector.authorization); invalid.signature_hex = "00".repeat(64);
  await writeFile(authorizationFile, JSON.stringify(invalid));
  const rejected = accept();
  assert.notEqual(rejected.status, 0); assert.equal(rejected.stdout, "");
  await writeFile(authorizationFile, JSON.stringify(vector.authorization));
  const admission = accept();
  assert.equal(admission.status, 0, admission.stderr);
  assert.equal(admission.stderr.trim(), "reserved");
  const request = JSON.parse(admission.stdout);
  assert.equal(request.proof_hash_hex, vector.authorization.proof_hash_hex);
  for (let attempt = 0; attempt < 100; attempt++) {
    if (spawnError || child.exitCode !== null) throw new Error(`regtest node failed: ${spawnError ?? stderr}`);
    try {
      const cookie = (await readFile(join(directory, "regtest", ".cookie"), "utf8")).trim();
      rpc = bitcoinCoreRpcV1(`http://127.0.0.1:${port}`, cookie);
      await rpc("getblockchaininfo", []);
      break;
    } catch { rpc = undefined; await delay(100); }
  }
  if (!rpc) throw new Error(`regtest RPC did not start: ${stderr}`);
  await rpc("createwallet", ["aura-anchor-test"]);
  const cookie = (await readFile(join(directory, "regtest", ".cookie"), "utf8")).trim();
  const wallet = bitcoinCoreRpcV1(`http://127.0.0.1:${port}/wallet/aura-anchor-test`, cookie);
  const address = await wallet("getnewaddress", []);
  await rpc("generatetoaddress", [101, address]);
  await assert.rejects(prepareBitcoinAnchorV1(wallet, { ...request, network: "mainnet" }, 2, 10000n), /network mismatch/);
  await assert.rejects(prepareBitcoinAnchorV1(wallet, request, 2, 1n), /fee exceeds/);
  const prepared = await prepareBitcoinAnchorV1(wallet, request, 2, 10000n);
  assert(prepared.fee_sat > 0n && prepared.fee_sat <= 10000n);
  const changed = prepared.transaction_hex.replace(`6a26415552410103${request.proof_hash_hex}`,
    `6a26415552410103${"43".repeat(32)}`);
  assert.notEqual(changed, prepared.transaction_hex);
  await assert.rejects(broadcastBitcoinAnchorV1(wallet, request, changed, 10000n), /does not match/);
  await assert.rejects(broadcastBitcoinAnchorV1(wallet, request, prepared.transaction_hex, 1n), /fee exceeds/);
  const published = await broadcastBitcoinAnchorV1(wallet, request, prepared.transaction_hex, 10000n);
  assert.equal(published.txid, prepared.txid);
  assert.equal((await observeBitcoinAnchorV1(wallet, request, published.txid, 2)).status, "pending");
  const [anchorBlock] = await rpc("generatetoaddress", [1, address]);
  const included = await observeBitcoinAnchorV1(wallet, request, published.txid, 2);
  assert.equal(included.status, "included");
  assert.equal(included.confirmations, 1);
  await rpc("generatetoaddress", [1, address]);
  const confirmed = await observeBitcoinAnchorV1(wallet, request, published.txid, 2);
  assert.equal(confirmed.status, "confirmed");
  assert.equal(confirmed.confirmations, 2);
  await rpc("invalidateblock", [anchorBlock]);
  const revoked = await observeBitcoinAnchorV1(wallet, request, published.txid, 2);
  assert.equal(revoked.status, "pending");
  assert.equal(revoked.confirmations, 0);
  const retry = accept();
  assert.equal(retry.status, 0, retry.stderr);
  assert.equal(retry.stderr.trim(), "same_action_retry");
  assert.deepEqual(JSON.parse(retry.stdout), request);
  console.log("PASS: BIP340 authorization, actual Aura proof/material/lineage verification, durable reservation, regtest anchoring, fees, network rejection, confirmations, reorg revocation, and restart retry without releasing nonce");
} finally {
  try { if (rpc) await rpc("stop", []); } catch { child.kill("SIGTERM"); }
  if (!rpc) child.kill("SIGTERM");
  const killTimer = setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); }, 10_000);
  killTimer.unref();
  await exited;
  clearTimeout(killTimer);
  await rm(directory, { recursive: true, force: true });
}
