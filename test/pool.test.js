// Privacy-pool circuit tests — Phase 6.2.
//
//  1. Production-key tests (always run): the committed withdrawal fixture in
//     test/fixtures/pool/ was generated with the production proving key whose
//     verification key is transcribed into the on-chain WithdrawalVerifier.
//     Verifying it here pins that vkey.
//  2. Fresh-pipeline round-trips (run when v2/build/ + pot16_final.ptau exist,
//     i.e. in CI after build + download:ptau): witness → fresh setup → prove →
//     verify, for both withdrawal.circom and association.circom; asserts the
//     constraint counts fit pot16 and the public-signal shapes are stable.

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const FIXTURES = path.join(__dirname, "fixtures", "pool");
const BUILD = path.join(__dirname, "..", "v2", "build");
const W_WASM = path.join(BUILD, "withdrawal_js", "withdrawal.wasm");
const W_R1CS = path.join(BUILD, "withdrawal.r1cs");
const A_WASM = path.join(BUILD, "association_js", "association.wasm");
const A_R1CS = path.join(BUILD, "association.r1cs");
const PTAU = path.join(__dirname, "..", "pot16_final.ptau");
const LEVELS = 20;

const load = (f) => JSON.parse(fs.readFileSync(path.join(FIXTURES, f), "utf8"));

after(async () => {
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
});

// ── 1. Production verification key (withdrawal) ─────────────────────────────

test("withdrawal fixture proof verifies against the production vkey", async () => {
  const ok = await snarkjs.groth16.verify(load("verification_key.json"), load("public.json"), load("proof.json"));
  assert.equal(ok, true);
});

test("tampered public signal is rejected", async () => {
  const pub = load("public.json");
  pub[3] = (BigInt(pub[3]) ^ 1n).toString(); // flip nullifier_hash
  assert.equal(await snarkjs.groth16.verify(load("verification_key.json"), pub, load("proof.json")), false);
});

test("tampered proof is rejected", async () => {
  const proof = load("proof.json");
  [proof.pi_a[0], proof.pi_a[1]] = [proof.pi_a[1], proof.pi_a[0]];
  assert.equal(await snarkjs.groth16.verify(load("verification_key.json"), load("public.json"), proof), false);
});

// ── 2. Fresh-pipeline round-trips (CI) ──────────────────────────────────────

const canWithdraw = fs.existsSync(W_R1CS) && fs.existsSync(W_WASM) && fs.existsSync(PTAU);

test(
  "withdrawal: fresh setup → prove → verify; pot16 fits; 6 public signals",
  { skip: canWithdraw ? false : "needs v2/build/ (circom 2.x) and pot16_final.ptau" },
  async () => {
    const info = await snarkjs.r1cs.info(W_R1CS);
    assert.ok(info.nConstraints <= 65536, `withdrawal has ${info.nConstraints} constraints; pot16 caps at 65536`);
    assert.equal(Number(info.nPubInputs) + Number(info.nOutputs), 6, "withdrawal must expose 6 public signals");

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pool-w-"));
    const wtns = path.join(tmp, "w.wtns");
    const zkey = path.join(tmp, "fresh.zkey");
    await snarkjs.wtns.calculate(load("input.json"), W_WASM, wtns);
    await snarkjs.zKey.newZKey(W_R1CS, PTAU, zkey);
    const freshVkey = await snarkjs.zKey.exportVerificationKey(zkey);
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
    assert.deepEqual(publicSignals, load("public.json"), "public signals must match the committed fixture");
    assert.equal(await snarkjs.groth16.verify(freshVkey, publicSignals, proof), true);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
);

test(
  "association: fresh setup → prove → verify; label membership",
  { skip: fs.existsSync(A_R1CS) && fs.existsSync(A_WASM) && fs.existsSync(PTAU) ? false : "needs v2/build/ + pot16" },
  async () => {
    const info = await snarkjs.r1cs.info(A_R1CS);
    assert.ok(info.nConstraints <= 65536, `association has ${info.nConstraints} constraints`);
    assert.equal(Number(info.nPubInputs) + Number(info.nOutputs), 2, "association exposes asp_root + label");

    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const H = (xs) => F.toObject(poseidon(xs));
    const zeros = [0n];
    for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));
    const label = H([424242n, 0n]);
    let root = label;
    for (let i = 0; i < LEVELS; i++) root = H([root, zeros[i]]);
    const input = {
      label: label.toString(),
      asp_root: root.toString(),
      siblings: zeros.slice(0, LEVELS).map(String),
      index: Array(LEVELS).fill(0),
    };

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pool-a-"));
    const wtns = path.join(tmp, "a.wtns");
    const zkey = path.join(tmp, "fresh.zkey");
    await snarkjs.wtns.calculate(input, A_WASM, wtns);
    await snarkjs.zKey.newZKey(A_R1CS, PTAU, zkey);
    const vkey = await snarkjs.zKey.exportVerificationKey(zkey);
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
    assert.equal(await snarkjs.groth16.verify(vkey, publicSignals, proof), true);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
);
