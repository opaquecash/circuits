// V2 (stealth_reputation) verification tests — Phase 1.2.
//
// Two layers:
//
//  1. Production-key tests (always run): the committed fixture proof in
//     test/fixtures/v2/ was generated with the production proving key — the
//     same setup whose verification key is hard-coded in
//     ethereum/infra/contracts/Groth16VerifierV2.sol and the Solana
//     groth16-verifier program. Verifying it here pins the vkey; the
//     consumer repos verify the identical fixture on-chain.
//
//  2. Fresh-pipeline round-trip (runs when v2/build/ and pot16_final.ptau
//     exist, i.e. in CI after `npm run build` + `npm run download:ptau`):
//     witness → fresh Groth16 setup → prove → verify. Proves the committed
//     circuit source still compiles to a provable circuit and that pot16
//     suffices for the constraint count.

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const snarkjs = require("snarkjs");

const FIXTURES = path.join(__dirname, "fixtures", "v2");
const V2_BUILD = path.join(__dirname, "..", "v2", "build");
const WASM = path.join(V2_BUILD, "stealth_reputation_js", "stealth_reputation.wasm");
const R1CS = path.join(V2_BUILD, "stealth_reputation.r1cs");
const PTAU = path.join(__dirname, "..", "pot16_final.ptau");

const load = (f) => JSON.parse(fs.readFileSync(path.join(FIXTURES, f), "utf8"));

after(async () => {
  // snarkjs leaves curve worker threads alive; terminate so node:test exits
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
});

// ── 1. Production verification key ─────────────────────────────────────────

test("fixture proof verifies against the production V2 vkey", async () => {
  const ok = await snarkjs.groth16.verify(
    load("verification_key.json"),
    load("public.json"),
    load("proof.json")
  );
  assert.equal(ok, true);
});

test("tampered public signal is rejected", async () => {
  const pub = load("public.json");
  // flip the nullifier_hash (signal [3])
  pub[3] = (BigInt(pub[3]) ^ 1n).toString();
  const ok = await snarkjs.groth16.verify(
    load("verification_key.json"),
    pub,
    load("proof.json")
  );
  assert.equal(ok, false);
});

test("tampered proof is rejected", async () => {
  const proof = load("proof.json");
  [proof.pi_a[0], proof.pi_a[1]] = [proof.pi_a[1], proof.pi_a[0]];
  const ok = await snarkjs.groth16.verify(
    load("verification_key.json"),
    load("public.json"),
    proof
  );
  assert.equal(ok, false);
});

// ── 2. Fresh-pipeline round-trip (CI) ───────────────────────────────────────

const canRoundTrip = fs.existsSync(R1CS) && fs.existsSync(WASM) && fs.existsSync(PTAU);

test(
  "fresh setup → prove → verify round-trip; pot16 fits",
  { skip: canRoundTrip ? false : "needs v2/build/ (circom 2.x) and pot16_final.ptau" },
  async () => {
    // pot16 strategy: assert the circuit still fits 2^16 constraints
    const info = await snarkjs.r1cs.info(R1CS);
    assert.ok(
      info.nConstraints <= 65536,
      `V2 has ${info.nConstraints} constraints; pot16 caps at 65536 — switch download_ptau.sh to 17`
    );
    assert.equal(Number(info.nPubInputs) + Number(info.nOutputs), 4, "V2 must expose 4 public signals");

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "v2-roundtrip-"));
    const wtns = path.join(tmp, "witness.wtns");
    const zkey = path.join(tmp, "fresh.zkey");

    await snarkjs.wtns.calculate(load("input.json"), WASM, wtns);
    await snarkjs.zKey.newZKey(R1CS, PTAU, zkey);
    const freshVkey = await snarkjs.zKey.exportVerificationKey(zkey);
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);

    assert.deepEqual(publicSignals, load("public.json"), "public signals must match the committed fixture");
    assert.equal(await snarkjs.groth16.verify(freshVkey, publicSignals, proof), true);

    // a fresh setup must NOT verify under the production vkey (different toxic waste)
    assert.equal(
      await snarkjs.groth16.verify(load("verification_key.json"), publicSignals, proof),
      false,
      "fresh-setup proof unexpectedly verified against the production vkey"
    );

    fs.rmSync(tmp, { recursive: true, force: true });
  }
);
