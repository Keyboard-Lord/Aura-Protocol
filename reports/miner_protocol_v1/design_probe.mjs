// Research-only design evidence. No production miner, ledger or consensus implementation.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { encodeStormContextV1 } from '../../packages/aura_sdk_v1_ts/src/stormContextV1.ts';
import { executeStormV1, derivePhiN, derivePsiN, encodeStepU64Le } from '../../packages/aura_sdk_v1_ts/src/stormExecutionV1.ts';
import { computeStormTraceRoot } from '../../packages/aura_sdk_v1_ts/src/stormTraceCommitmentV1.ts';
import { decodeEconomicWorkV1, encodeEconomicWorkV1 } from '../../packages/aura_sdk_v1_ts/src/economicV1.ts';
import { encodeEconomicMeterV1 } from '../../packages/aura_sdk_v0_ts/src/index.ts';
import { prepareBoundProofMaterialV1 } from '../../packages/aura_sdk_v1_ts/src/sdkCoreV1.ts';
import { signAuthorizationV2, verifyAuthorizationMaterialBindingV2 } from '../../packages/aura_sdk_v1_ts/src/authorizationV2.ts';

const hex = x => Buffer.from(x).toString('hex');
const bytes = x => Buffer.from(x, 'hex');
const h = (...parts) => { const x = createHash('sha256'); for (const p of parts) x.update(p); return x.digest(); };
const u64 = n => encodeStepU64Le(BigInt(n));
const vector = name => JSON.parse(readFileSync(new URL(`../../fixtures/${name}`, import.meta.url)));
const econ = vector('economic_admission_v1/contract_vector.json');
const auth = vector('authorization_v2/authorization_vector_v2.json');
const work = decodeEconomicWorkV1(bytes(econ.work_hex), {maxWorkBytes: 100000, maxMeterBytes: 90000, maxIterations: 100n});
const M = encodeEconomicMeterV1(work.meter);
const subject = bytes(auth.authorization.authorization_lineage.subject_binding);
const namespace = h(Buffer.from('RESEARCH_ONLY_MINER_NAMESPACE'));
const challenge = h(Buffer.from('RESEARCH_ONLY_JOB_CHALLENGE'));
const target = (1n << 252n) - 1n;
const targetBytes = bytes(target.toString(16).padStart(64, '0'));
// Proposed fixed J framing, in the field order defined by the companion proposal.
const J = Buffer.concat([Buffer.from('AURA_MINER_JOB_V1'), Buffer.from([1, 3]),
  subject, namespace, u64(0), u64(1), u64(0), Buffer.alloc(32), challenge,
  work.storm.sideA, work.storm.sideB, u64(64), targetBytes,
  u64(100000), u64(90000), u64(2000000000), u64(2000000600), u64(10000)]);
const job = h(J);
const intent = (m = M, j = job) => h(Buffer.from('AURA_MINER_INTENT_V1'), j, u64(m.length), m);
const nonce = n => h(Buffer.from(`RESEARCH_ONLY_NONCE_${n}`));
const context = (r, i = intent(), key = subject) => encodeStormContextV1({contextVersion: 1,
  networkId: namespace, intentHash: i, freshnessNonce: r, validFrom: 0n, validUntil: 0n,
  controllerId: key, routeTag: h(Buffer.from('AURA_MINER_PROTOCOL_V1'))});
const inputs = (r, i = intent(), n = 64n) => ({sideA: work.storm.sideA, sideB: work.storm.sideB,
  contextBytesV1: context(r, i), iterationCount: n});
const root = execution => hex(computeStormTraceRoot(execution.trace));
const a = inputs(nonce(0)), b = inputs(nonce(1));
const ea = executeStormV1(a), eb = executeStormV1(b);
assert.deepEqual(ea, executeStormV1(a));
assert.deepEqual(ea.initialState, eb.initialState); // x0/y0 depend on the fixed sides.
assert.notEqual(ea.aHex66Be, eb.aHex66Be);
assert.notEqual(ea.bHex66Be, eb.bHex66Be);
for (let n = 0n; n < 64n; n++) {
  assert.notEqual(derivePhiN(a.sideA, a.sideB, a.contextBytesV1, n), derivePhiN(b.sideA, b.sideB, b.contextBytesV1, n));
  assert.notEqual(derivePsiN(a.sideA, a.sideB, a.contextBytesV1, n), derivePsiN(b.sideA, b.sideB, b.contextBytesV1, n));
}
assert.notEqual(root(ea), root(eb));
const changedWork = structuredClone(work);
changedWork.meter.batch.batchNumber += 1n; // Structurally canonical; settlement may reject later.
const changedM = encodeEconomicMeterV1(changedWork.meter);
assert.notEqual(root(ea), root(executeStormV1(inputs(nonce(0), intent(changedM)))));
for (let offset = 0; offset < J.length; offset++) {
  const changed = Buffer.from(J); changed[offset] ^= 1;
  assert.notEqual(hex(intent()), hex(intent(M, h(changed))));
}
assert.deepEqual(decodeEconomicWorkV1(encodeEconomicWorkV1({...work, storm: a}),
  {maxWorkBytes: 100000, maxMeterBytes: 90000, maxIterations: 64n}).storm, a);
assert.equal(root(executeStormV1(inputs(nonce(0), intent(), 0n))),
  root(executeStormV1(inputs(nonce(1), intent(), 0n)))); // A zero-step profile cannot price Storm recurrence.

// Direct integer comparison, not a new hash. Test inclusive target and strict 32-byte width.
const score = b => { assert.equal(b.length, 32); return BigInt(`0x${hex(b)}`); };
assert.equal(score(targetBytes) <= target, true);
assert.equal(score(bytes((target + 1n).toString(16).padStart(64, '0'))) <= target, false);
assert.throws(() => score(Buffer.alloc(31)));
assert.equal((1n << 256n) / (target + 1n), 16n);

// Demonstrate the cheap-rebinding attack a signature/material-only PoW gate would accept.
// Keep one actual frozen proof; vary only FractalKey's external nonce until its hash is low.
const proof = bytes(auth.proof_bytes_hex), pi = bytes(auth.public_inputs_hex);
const secret = bytes(auth.test_only_secret_key_hex);
const baseline = await prepareBoundProofMaterialV1(subject,
  bytes(auth.authorization.authorization_lineage.freshness_binding), proof, pi, Buffer.alloc(0));
assert.equal(hex(baseline.proofHash), auth.authorization.proof_hash_hex);
let forged, tries = 0;
for (; tries < 4096; tries++) {
  const r = nonce(tries + 1000);
  const bound = await prepareBoundProofMaterialV1(subject, r, proof, pi, Buffer.alloc(0));
  if (score(bound.proofHash) <= target) {
    forged = signAuthorizationV2('regtest', hex(bound.proofHash),
      auth.authorization.authorization_lineage.intent_commitment_hex, hex(r), secret);
    break;
  }
}
assert.ok(forged, 'fixed research search must find its pinned low-hash rebinding');
await verifyAuthorizationMaterialBindingV2(forged, 'regtest', proof, pi);
const temporary = mkdtempSync(join(tmpdir(), 'aura-miner-design-'));
let rejection;
try {
  const binary = fileURLToPath(new URL('../../target/debug/aura-authorizer', import.meta.url));
  const journal = join(temporary, 'journal.db'), authorization = join(temporary, 'auth.json'), proofFile = join(temporary, 'proof.bin');
  writeFileSync(authorization, JSON.stringify(forged)); writeFileSync(proofFile, proof);
  const init = spawnSync(binary, ['init', journal], {encoding: 'utf8'});
  assert.equal(init.status, 0, init.error?.message ?? init.stderr);
  const result = spawnSync(binary, ['accept', journal, 'regtest', authorization, proofFile, '100', '100000'], {encoding: 'utf8'});
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /nonce|freshness|lineage/i);
  rejection = result.stderr.trim();
} finally { rmSync(temporary, {recursive: true, force: true}); }
console.log(JSON.stringify({classification: 'RESEARCH EVIDENCE; NOT A MINER IMPLEMENTATION',
  job_bytes: J.length, job_commitment_hex: hex(job), intent_commitment_hex: hex(intent()),
  iterations: 64, nonce_0_trace_root: root(ea), nonce_1_trace_root: root(eb),
  all_64_forcing_pairs_changed: true, deterministic: true, exact_W_roundtrip: true,
  changed_M_changes_trace: true, every_job_byte_bound: true, zero_steps_share_trace: true,
  target_hex: hex(targetBytes), assumed_expected_trials: '16',
  cheap_rebinding_trials: tries + 1, cheap_rebinding_hash: forged.proof_hash_hex,
  signature_and_material_only_accept: true, full_Rust_authorizer_rejection: rejection,
  limits: 'Does not establish sequential hardness, non-amortization, economic viability, useful demand, miner consensus or new Rust/TS miner parity.'}, null, 2));
