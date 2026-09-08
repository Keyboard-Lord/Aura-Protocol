// Bitcoin publication evidence is separate from Aura proof verification.
const NETWORKS = ["mainnet", "testnet3", "signet", "regtest", "testnet4"] as const;
export type BitcoinNetworkV1 = typeof NETWORKS[number];
export function bitcoinNetworkTagV1(network: BitcoinNetworkV1): number {
  const tag = NETWORKS.indexOf(network);
  if (tag < 0) throw new TypeError("unknown Bitcoin network");
  return tag;
}
export type BitcoinAnchorRequestV1 = Readonly<{
  anchor_version: "v1";
  network: BitcoinNetworkV1;
  proof_hash_hex: string;
}>;

export function validateBitcoinAnchorRequestV1(value: unknown): BitcoinAnchorRequestV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("anchor request must be an object");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || !["anchor_version", "network", "proof_hash_hex"].every(k => keys.includes(k))) {
    throw new TypeError("anchor request must contain exactly anchor_version, network, proof_hash_hex");
  }
  const { anchor_version, network, proof_hash_hex } = value as Record<string, unknown>;
  if (anchor_version !== "v1") throw new TypeError("unsupported anchor version");
  if (typeof network !== "string" || !NETWORKS.includes(network as BitcoinNetworkV1)) {
    throw new TypeError("unknown Bitcoin network");
  }
  if (typeof proof_hash_hex !== "string" || !/^[0-9a-f]{64}$/.test(proof_hash_hex)) {
    throw new TypeError("proof_hash_hex must be canonical lowercase 64-hex");
  }
  return Object.freeze({ anchor_version: "v1", network: network as BitcoinNetworkV1,
    proof_hash_hex });
}

export function encodeBitcoinAnchorScriptV1(value: BitcoinAnchorRequestV1): Uint8Array {
  const request = validateBitcoinAnchorRequestV1(value);
  return Uint8Array.from([0x6a, 38, 65, 85, 82, 65, 1, bitcoinNetworkTagV1(request.network),
    ...Buffer.from(request.proof_hash_hex, "hex")]);
}

export function decodeBitcoinAnchorScriptV1(script: Uint8Array): BitcoinAnchorRequestV1 {
  if (!(script instanceof Uint8Array) || script.length !== 40
    || ![0x6a, 38, 65, 85, 82, 65, 1].every((b, i) => script[i] === b)) {
    throw new TypeError("non-canonical Aura anchor script");
  }
  return validateBitcoinAnchorRequestV1({ anchor_version: "v1", network: NETWORKS[script[7]!],
    proof_hash_hex: Buffer.from(script.subarray(8)).toString("hex") });
}

export type BitcoinOutputV1 = { value_sat: bigint; script_pubkey: Uint8Array };

export function validateBitcoinAnchorOutputsV1(
  outputs: readonly BitcoinOutputV1[], expected: BitcoinAnchorRequestV1,
): number {
  const request = validateBitcoinAnchorRequestV1(expected);
  let found: number | undefined;
  for (const [index, output] of outputs.entries()) {
    if (typeof output.value_sat !== "bigint" || output.value_sat < 0n
      || output.value_sat > 0xffff_ffff_ffff_ffffn || !(output.script_pubkey instanceof Uint8Array)) {
      throw new TypeError("invalid decoded Bitcoin output");
    }
    if (!isAuraCandidate(output.script_pubkey)) continue;
    if (found !== undefined) throw new TypeError("duplicate Aura anchor output");
    if (output.value_sat !== 0n) throw new TypeError("Aura output must have zero value");
    const actual = decodeBitcoinAnchorScriptV1(output.script_pubkey);
    if (actual.network !== request.network || actual.proof_hash_hex !== request.proof_hash_hex) {
      throw new TypeError("Aura anchor does not match expected network and proof reference");
    }
    found = index;
  }
  if (found === undefined) throw new TypeError("missing Aura anchor output");
  return found;
}

function isAuraCandidate(script: Uint8Array): boolean {
  if (script[0] !== 0x6a) return false;
  const push = script[1]!;
  const offset = push >= 1 && push <= 75 ? 2 : push === 0x4c ? 3 : push === 0x4d ? 4 : push === 0x4e ? 6 : -1;
  return offset >= 0 && [65, 85, 82, 65].every((b, i) => script[offset + i] === b);
}
