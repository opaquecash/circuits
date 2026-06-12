#!/usr/bin/env node
// Generate the committed conditional-disclosure fixture (test/fixtures/disclosure/).
//
// Builds a deterministic, valid witness for conditional_disclosure.circom: a
// deposit commitment in a depth-20 state tree (single leaf at index 0), a
// qualifying threshold below the note value, and the disclosure nullifier
// Poseidon(nullifier, context, DOMAIN_DISCLOSURE). Proves with the production
// zkey and verifies. Zero-subtree values MUST match the pool contract's
// empty-tree zeros (spec/privacy-pool.md §2).
//
// Usage: node scripts/generate_disclosure_fixture.js <conditional_disclosure.wasm> <conditional_disclosure_final.zkey>

const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");

const LEVELS = 20;
const FIXTURE_DIR = path.join(__dirname, "..", "test", "fixtures", "disclosure");
// keccak256("opaque/disclosure/v1") mod r — spec/conditional-disclosure.md §7.
const DOMAIN_DISCLOSURE =
  2892858644728810973983554811705195156385130922452064297470708309156017996001n;

async function main() {
  const [wasmPath, zkeyPath] = process.argv.slice(2);
  if (!wasmPath || !zkeyPath) {
    console.error(
      "usage: generate_disclosure_fixture.js <conditional_disclosure.wasm> <conditional_disclosure_final.zkey>",
    );
    process.exit(2);
  }
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (xs) => F.toObject(poseidon(xs));

  // Zero-subtree roots: zeros[0] = empty-leaf value 0; zeros[i] = Poseidon(z,z).
  const zeros = [0n];
  for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));
  function singleLeafRoot(leaf) {
    let node = leaf;
    for (let i = 0; i < LEVELS; i++) node = H([node, zeros[i]]);
    return node;
  }

  // Note openings (arbitrary but stable; distinct from the pool fixture's).
  const value = 2_000_000_000_000_000_000n; // 2e18
  const label = H([515151n, 0n]); // = Poseidon(scope, depositIndex) stand-in
  const nullifier = 555555555555555555555555555n;
  const secret = 666666666666666666666666666n;
  const commitment = H([value, label, H([nullifier, secret])]);

  // Policy + request bindings.
  const threshold = 500_000_000_000_000_000n; // 0.5e18 < value → qualifies
  const context = 0xfedcba9876543210n; // stand-in for keccak(policyId,caseId,requester) mod r
  const disclosure_nullifier = H([nullifier, context, DOMAIN_DISCLOSURE]);
  const state_root = singleLeafRoot(commitment);

  const input = {
    nullifier: nullifier.toString(),
    secret: secret.toString(),
    state_siblings: zeros.slice(0, LEVELS).map(String),
    state_index: Array(LEVELS).fill(0),
    value: value.toString(),
    label: label.toString(),
    threshold: threshold.toString(),
    state_root: state_root.toString(),
    disclosure_nullifier: disclosure_nullifier.toString(),
    context: context.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  const vkey = JSON.parse(
    fs.readFileSync(
      path.join(path.dirname(zkeyPath), "conditional_disclosure_vkey.json"),
      "utf8",
    ),
  );
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) throw new Error("fixture proof failed to verify");

  // Public signal order (snarkjs): value, label, threshold, state_root,
  // disclosure_nullifier, context.
  console.log("public signals:", publicSignals);

  fs.mkdirSync(FIXTURE_DIR, { recursive: true });
  fs.writeFileSync(path.join(FIXTURE_DIR, "input.json"), JSON.stringify(input, null, 2));
  fs.writeFileSync(path.join(FIXTURE_DIR, "proof.json"), JSON.stringify(proof, null, 2));
  fs.writeFileSync(path.join(FIXTURE_DIR, "public.json"), JSON.stringify(publicSignals, null, 2));
  fs.writeFileSync(
    path.join(FIXTURE_DIR, "verification_key.json"),
    JSON.stringify(vkey, null, 2),
  );
  console.log("verified; wrote", FIXTURE_DIR);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
