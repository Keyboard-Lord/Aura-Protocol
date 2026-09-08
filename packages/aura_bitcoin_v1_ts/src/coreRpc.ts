import {
  encodeBitcoinAnchorScriptV1, validateBitcoinAnchorRequestV1, validateBitcoinAnchorOutputsV1,
} from "./index.ts";
import type { BitcoinAnchorRequestV1, BitcoinNetworkV1 } from "./index.ts";

/** Operational transport, outside the canonical wire. The node is the trust boundary. */
export type BitcoinCoreRpcV1 = (method: string, params: unknown[]) => Promise<any>;

export function bitcoinCoreRpcV1(url: string, cookie: string): BitcoinCoreRpcV1 {
  const endpoint = new URL(url);
  if (!["http:", "https:"].includes(endpoint.protocol) || endpoint.username || endpoint.password) {
    throw new TypeError("invalid Bitcoin Core RPC endpoint");
  }
  let id = 0;
  return async (method, params) => {
    const requestId = ++id;
    const response = await fetch(endpoint, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(30_000),
      headers: { "Content-Type": "application/json", Authorization: `Basic ${Buffer.from(cookie).toString("base64")}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
    });
    if (!response.ok) throw new Error(`Bitcoin Core HTTP failure: ${response.status}`);
    const body = await response.json();
    if (body.id !== requestId || body.error != null || !Object.hasOwn(body, "result")) {
      throw new Error(`Bitcoin Core RPC failed: ${method}`);
    }
    return body.result;
  };
}

const CORE_NETWORK = { mainnet: "main", testnet3: "test", signet: "signet", regtest: "regtest", testnet4: "testnet4" };
async function chainInfo(rpc: BitcoinCoreRpcV1, network: BitcoinNetworkV1) {
  const info = await rpc("getblockchaininfo", []);
  if (info.chain !== CORE_NETWORK[network]) throw new Error("Bitcoin Core network mismatch");
  hash(info.bestblockhash);
  integer(info.blocks);
  return info;
}

function hash(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("invalid Core hash");
  return value;
}
function integer(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error("invalid Core integer");
  return value;
}
function hex(value: unknown): string {
  if (typeof value !== "string" || !/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("invalid Core hex");
  return value;
}
function satoshis(value: unknown): bigint {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 21_000_000) {
    throw new Error("invalid Core BTC amount");
  }
  const sats = BigInt(value.toFixed(8).replace(".", ""));
  if (Number(sats) / 1e8 !== value) throw new Error("Core amount has sub-satoshi precision");
  return sats;
}

async function checkTransaction(rpc: BitcoinCoreRpcV1, transactionHex: string, request: BitcoinAnchorRequestV1) {
  const decoded = await rpc("decoderawtransaction", [hex(transactionHex)]);
  const txid = hash(decoded.txid);
  if (!Array.isArray(decoded.vout)) throw new Error("invalid Core transaction outputs");
  const outputs = decoded.vout.map((out: any, index: number) => {
    if (out.n !== index) throw new Error("invalid Core output ordering");
    return { value_sat: satoshis(out.value), script_pubkey: Buffer.from(hex(out.scriptPubKey.hex), "hex") };
  });
  return { txid, output_index: validateBitcoinAnchorOutputsV1(outputs, request) };
}

/** Builds and signs; does not publish or certify Aura proof validity. */
export async function prepareBitcoinAnchorV1(
  rpc: BitcoinCoreRpcV1, value: BitcoinAnchorRequestV1,
  feeRateSatVb: number, maxFeeSat: bigint,
): Promise<{ transaction_hex: string; txid: string; output_index: number; fee_sat: bigint }> {
  const request = validateBitcoinAnchorRequestV1(value);
  if (!Number.isFinite(feeRateSatVb) || feeRateSatVb <= 0 || typeof maxFeeSat !== "bigint" || maxFeeSat <= 0n) {
    throw new TypeError("explicit positive fee rate and fee ceiling required");
  }
  await chainInfo(rpc, request.network);
  const payload = Buffer.from(encodeBitcoinAnchorScriptV1(request).slice(2)).toString("hex");
  const funded = await rpc("walletcreatefundedpsbt", [[], [{ data: payload }], 0,
    { add_inputs: true, include_unsafe: false, minconf: 1, fee_rate: feeRateSatVb, replaceable: true }]);
  const fee = satoshis(funded.fee);
  if (fee > maxFeeSat) throw new Error("anchor fee exceeds configured ceiling");
  const signed = await rpc("walletprocesspsbt", [funded.psbt, true, "ALL"]);
  const final = await rpc("finalizepsbt", [signed.psbt]);
  if (final.complete !== true) throw new Error("Bitcoin anchor signing incomplete");
  const transactionHex = hex(final.hex);
  const checked = await checkTransaction(rpc, transactionHex, request);
  return { transaction_hex: transactionHex, ...checked, fee_sat: fee };
}

/** Low-level publication. The Aura pipeline must authorize and verify before calling. */
export async function broadcastBitcoinAnchorV1(
  rpc: BitcoinCoreRpcV1, request: BitcoinAnchorRequestV1, transactionHex: string, maxFeeSat: bigint,
): Promise<{ txid: string; output_index: number }> {
  const expected = validateBitcoinAnchorRequestV1(request);
  if (typeof maxFeeSat !== "bigint" || maxFeeSat <= 0n) throw new TypeError("positive fee ceiling required");
  await chainInfo(rpc, expected.network);
  const checked = await checkTransaction(rpc, transactionHex, expected);
  const acceptance = await rpc("testmempoolaccept", [[transactionHex]]);
  if (!Array.isArray(acceptance) || acceptance.length !== 1 || acceptance[0].txid !== checked.txid
    || acceptance[0].allowed !== true) throw new Error("anchor transaction is not mempool acceptable");
  if (satoshis(acceptance[0].fees?.base) > maxFeeSat) throw new Error("anchor fee exceeds configured ceiling");
  const txid = await rpc("sendrawtransaction", [transactionHex]);
  if (txid !== checked.txid) throw new Error("broadcast transaction ID mismatch");
  return checked;
}

export type BitcoinAnchorObservationV1 = {
  txid: string; output_index: number; observed_tip: string;
} & ({ status: "pending" | "conflicted"; confirmations: 0 }
  | { status: "included" | "confirmed"; confirmations: number; block_hash: string; block_height: number });

/** Fresh wallet-based observation; never trusts a persisted confirmation count. */
export async function observeBitcoinAnchorV1(
  rpc: BitcoinCoreRpcV1, value: BitcoinAnchorRequestV1, txid: string, requiredConfirmations: number,
): Promise<BitcoinAnchorObservationV1> {
  const request = validateBitcoinAnchorRequestV1(value);
  hash(txid);
  if (!Number.isSafeInteger(requiredConfirmations) || requiredConfirmations < 1) {
    throw new TypeError("positive confirmation threshold required");
  }
  const before = await chainInfo(rpc, request.network);
  const transaction = await rpc("gettransaction", [txid]);
  const checked = await checkTransaction(rpc, hex(transaction.hex), request);
  if (checked.txid !== txid) throw new Error("observed transaction ID mismatch");
  if (!Number.isSafeInteger(transaction.confirmations)) throw new Error("invalid Core confirmations");
  let observation: BitcoinAnchorObservationV1 = {
    ...checked, observed_tip: before.bestblockhash,
    status: transaction.confirmations < 0 ? "conflicted" : "pending", confirmations: 0,
  };
  if (transaction.confirmations > 0) {
    const blockHash = hash(transaction.blockhash);
    const header = await rpc("getblockheader", [blockHash]);
    const height = integer(header.height);
    if (height > before.blocks) throw new Error("block exceeds observed chain tip");
    const activeHash = await rpc("getblockhash", [height]);
    if (activeHash !== blockHash || header.confirmations < 1) throw new Error("anchor block is no longer active; retry observation");
    const included = await rpc("getrawtransaction", [txid, true, blockHash]);
    if (included.txid !== txid || included.hex !== transaction.hex) throw new Error("anchor inclusion mismatch");
    const confirmations = before.blocks - height + 1;
    observation = { ...checked, observed_tip: before.bestblockhash, block_hash: blockHash,
      block_height: height, confirmations, status: confirmations >= requiredConfirmations ? "confirmed" : "included" };
  }
  const after = await chainInfo(rpc, request.network);
  if (after.bestblockhash !== before.bestblockhash) throw new Error("Bitcoin tip changed; retry observation");
  return observation;
}
