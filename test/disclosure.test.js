// Conditional-disclosure circuit tests — Phase 7.2.
//
//  1. Production-key tests (always run): the committed fixture in
//     test/fixtures/disclosure/ was generated with the production proving key
//     whose verification key is transcribed into the on-chain disclosure
//     verifiers. Verifying it here pins that vkey.
//  2. Fresh-pipeline round-trip (run when v2/build/ + pot16_final.ptau exist,
//     i.e. in CI after build + download:ptau): witness → fresh setup → prove →
//     verify; asserts the constraint count fits pot16 and the 6-signal shape.
//  3. Qualification: a below-threshold witness is unsatisfiable (this is the
//     constraint custodians rely on when authorizing blind).

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const snarkjs = require("snarkjs");

const FIXTURES = path.join(__dirname, "fixtures", "disclosure");
const BUILD = path.join(__dirname, "..", "v2", "build");
const D_WASM = path.join(BUILD, "conditional_disclosure_js", "conditional_disclosure.wasm");
const D_R1CS = path.join(BUILD, "conditional_disclosure.r1cs");
const PTAU = path.join(__dirname, "..", "pot16_final.ptau");

const load = (f) => JSON.parse(fs.readFileSync(path.join(FIXTURES, f), "utf8"));

after(async () => {
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
});

// ── 1. Production verification key ──────────────────────────────────────────

test("disclosure fixture proof verifies against the production vkey", async () => {
  const ok = await snarkjs.groth16.verify(load("verification_key.json"), load("public.json"), load("proof.json"));
  assert.equal(ok, true);
});

test("tampered public signal is rejected", async () => {
  const pub = load("public.json");
  pub[4] = (BigInt(pub[4]) ^ 1n).toString(); // flip disclosure_nullifier
  assert.equal(await snarkjs.groth16.verify(load("verification_key.json"), pub, load("proof.json")), false);
});

test("tampered disclosed value is rejected", async () => {
  const pub = load("public.json");
  pub[0] = (BigInt(pub[0]) + 1n).toString(); // claim a different amount
  assert.equal(await snarkjs.groth16.verify(load("verification_key.json"), pub, load("proof.json")), false);
});

test("tampered proof is rejected", async () => {
  const proof = load("proof.json");
  [proof.pi_a[0], proof.pi_a[1]] = [proof.pi_a[1], proof.pi_a[0]];
  assert.equal(await snarkjs.groth16.verify(load("verification_key.json"), load("public.json"), proof), false);
});

// ── 2 + 3. Fresh-pipeline round-trip + qualification (CI) ───────────────────

const canProve = fs.existsSync(D_R1CS) && fs.existsSync(D_WASM) && fs.existsSync(PTAU);

test(
  "disclosure: fresh setup → prove → verify; pot16 fits; 6 public signals",
  { skip: canProve ? false : "needs v2/build/ (circom 2.x) and pot16_final.ptau" },
  async () => {
    const info = await snarkjs.r1cs.info(D_R1CS);
    assert.ok(info.nConstraints <= 65536, `disclosure has ${info.nConstraints} constraints; pot16 caps at 65536`);
    assert.equal(Number(info.nPubInputs) + Number(info.nOutputs), 6, "disclosure must expose 6 public signals");

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "disc-"));
    const wtns = path.join(tmp, "d.wtns");
    const zkey = path.join(tmp, "fresh.zkey");
    await snarkjs.wtns.calculate(load("input.json"), D_WASM, wtns);
    await snarkjs.zKey.newZKey(D_R1CS, PTAU, zkey);
    const freshVkey = await snarkjs.zKey.exportVerificationKey(zkey);
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
    assert.deepEqual(publicSignals, load("public.json"), "public signals must match the committed fixture");
    assert.equal(await snarkjs.groth16.verify(freshVkey, publicSignals, proof), true);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
);

test(
  "a below-threshold note is unsatisfiable",
  { skip: fs.existsSync(D_WASM) ? false : "needs v2/build/ (circom 2.x)" },
  async () => {
    const input = load("input.json");
    input.threshold = input.value; // value > threshold now false (strict)
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "disc-neg-"));
    await assert.rejects(
      snarkjs.wtns.calculate(input, D_WASM, path.join(tmp, "bad.wtns")),
      /Assert Failed|Error/,
      "witness for a non-qualifying note must fail",
    );
    fs.rmSync(tmp, { recursive: true, force: true });
  }
);
