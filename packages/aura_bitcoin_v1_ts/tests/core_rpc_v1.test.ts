import test from "node:test";
import assert from "node:assert/strict";
import { encodeBitcoinAnchorScriptV1 } from "../src/index.ts";
import { prepareBitcoinAnchorV1, broadcastBitcoinAnchorV1, observeBitcoinAnchorV1 } from "../src/coreRpc.ts";

const request = { anchor_version: "v1", network: "regtest", proof_hash_hex: "42".repeat(32) } as const;
const txid = "11".repeat(32), block = "22".repeat(32), tip = "33".repeat(32);
const decoded = () => ({ txid, vout: [{ n: 0, value: 0,
  scriptPubKey: { hex: Buffer.from(encodeBitcoinAnchorScriptV1(request)).toString("hex") } }] });
function mock(overrides: Record<string, (...args: any[]) => any> = {}) {
  const calls: string[] = [];
  const methods: Record<string, (...args: any[]) => any> = {
    getblockchaininfo: () => ({ chain: "regtest", blocks: 10, bestblockhash: tip }),
    walletcreatefundedpsbt: () => ({ psbt: "funded", fee: 0.000001 }),
    walletprocesspsbt: () => ({ psbt: "signed" }),
    finalizepsbt: () => ({ complete: true, hex: "aa" }),
    decoderawtransaction: decoded,
    testmempoolaccept: () => [{ txid, allowed: true, fees: { base: 0.000001 } }],
    sendrawtransaction: () => txid,
    gettransaction: () => ({ hex: "aa", confirmations: 2, blockhash: block }),
    getblockheader: () => ({ height: 9, confirmations: 2 }),
    getblockhash: () => block,
    getrawtransaction: () => ({ txid, hex: "aa" }),
    ...overrides,
  };
  return { calls, rpc: async (method: string, params: unknown[]) => {
    calls.push(method);
    assert(method in methods, `unexpected RPC ${method}`);
    return methods[method as keyof typeof methods](...params);
  } };
}

test("funding enforces fee ceiling before signing, and final outputs before returning", async () => {
  const expensive = mock();
  await assert.rejects(prepareBitcoinAnchorV1(expensive.rpc, request, 2, 1n), /fee exceeds/);
  assert(!expensive.calls.includes("walletprocesspsbt"));
  const tampered = mock({ decoderawtransaction: () => {
    const value = decoded(); value.vout[0]!.scriptPubKey.hex = "51"; return value;
  } });
  await assert.rejects(prepareBitcoinAnchorV1(tampered.rpc, request, 2, 1000n), /missing Aura/);
  assert(!tampered.calls.includes("sendrawtransaction"));
});

test("publication checks actual transaction fee before sending", async () => {
  const excessive = mock();
  await assert.rejects(broadcastBitcoinAnchorV1(excessive.rpc, request, "aa", 1n), /fee exceeds/);
  assert(!excessive.calls.includes("sendrawtransaction"));
  const rejected = mock({ testmempoolaccept: () => [{ txid, allowed: false }] });
  await assert.rejects(broadcastBitcoinAnchorV1(rejected.rpc, request, "aa", 1000n), /mempool acceptable/);
  assert(!rejected.calls.includes("sendrawtransaction"));
});

test("confirmation observation is fresh, depth-aware, and revocable", async () => {
  const confirmed = await observeBitcoinAnchorV1(mock().rpc, request, txid, 2);
  assert.equal(confirmed.status, "confirmed");
  assert.equal(confirmed.confirmations, 2);
  assert.equal((await observeBitcoinAnchorV1(mock().rpc, request, txid, 3)).status, "included");
  for (const [confirmations, status] of [[0, "pending"], [-1, "conflicted"]] as const) {
    const changed = mock({ gettransaction: () => ({ hex: "aa", confirmations }) });
    const observed = await observeBitcoinAnchorV1(changed.rpc, request, txid, 2);
    assert.equal(observed.status, status);
    assert.equal(observed.confirmations, 0);
  }
});

test("observation rejects inconsistent inclusion or a moving chain tip", async () => {
  for (const overrides of [
    { getblockhash: () => "44".repeat(32) },
    { getrawtransaction: () => ({ txid: "55".repeat(32), hex: "aa" }) },
    { decoderawtransaction: () => ({ ...decoded(), txid: "55".repeat(32) }) },
  ]) await assert.rejects(observeBitcoinAnchorV1(mock(overrides).rpc, request, txid, 2));
  let reads = 0;
  const moving = mock({ getblockchaininfo: () => ({ chain: "regtest", blocks: 10,
    bestblockhash: ++reads === 1 ? tip : "44".repeat(32) }) });
  await assert.rejects(observeBitcoinAnchorV1(moving.rpc, request, txid, 2), /tip changed/);
});
