#!/usr/bin/env node
// Generate the committed privacy-pool withdrawal fixture (test/fixtures/pool/).
//
// Builds a deterministic, valid witness for withdrawal.circom: a deposit commitment
// in a depth-20 state tree (single leaf at index 0), its label in a depth-20
// association tree (single leaf at index 0), a partial withdrawal, and the remainder
// commitment. Proves with the production zkey and verifies. The zero-subtree values
// here MUST match the contract's empty-tree zeros (spec/privacy-pool.md §2).
//
// Usage: node scripts/generate_pool_fixture.js <withdrawal.wasm> <withdrawal_final.zkey>

const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");

const LEVELS = 20;
const FIXTURE_DIR = path.join(__dirname, "..", "test", "fixtures", "pool");

async function main() {
  const [wasmPath, zkeyPath] = process.argv.slice(2);
  if (!wasmPath || !zkeyPath) {
    console.error("usage: generate_pool_fixture.js <withdrawal.wasm> <withdrawal_final.zkey>");
    process.exit(2);
  }
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (xs) => F.toObject(poseidon(xs));

  // Zero-subtree roots: zeros[0] = empty-leaf value 0; zeros[i] = Poseidon(z,z).
  const zeros = [0n];
  for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

  // Single leaf at index 0: siblings are the zero-subtrees, all direction bits 0.
  function singleLeafRoot(leaf) {
    let node = leaf;
    for (let i = 0; i < LEVELS; i++) node = H([node, zeros[i]]);
    return node;
  }
  const zeroPath = { siblings: zeros.slice(0, LEVELS), index: Array(LEVELS).fill(0) };

  // Deposit openings (arbitrary but stable).
  const value = 1_000_000_000_000_000_000n; // 1e18
  const label = H([424242n, 0n]); // = Poseidon(scope, depositIndex) stand-in
  const nullifier = 111111111111111111111111111n;
  const secret = 222222222222222222222222222n;
  const precommitment = H([nullifier, secret]);
  const commitment = H([value, label, precommitment]);

  // Remainder openings.
  const withdrawn_value = 400_000_000_000_000_000n; // 0.4e18
  const remainder = value - withdrawn_value;
  const new_nullifier = 333333333333333333333333333n;
  const new_secret = 444444444444444444444444444n;
  const new_commitment = H([remainder, label, H([new_nullifier, new_secret])]);

  const nullifier_hash = H([nullifier]);
  const state_root = singleLeafRoot(commitment);
  const asp_root = singleLeafRoot(label);
  // Context: an opaque field element the contract recomputes from the withdrawal.
  const context = 0x1234567890abcdefn;

  const input = {
    value: value.toString(),
    label: label.toString(),
    nullifier: nullifier.toString(),
    secret: secret.toString(),
    new_nullifier: new_nullifier.toString(),
    new_secret: new_secret.toString(),
    state_siblings: zeroPath.siblings.map(String),
    state_index: zeroPath.index,
    asp_siblings: zeroPath.siblings.map(String),
    asp_index: zeroPath.index,
    withdrawn_value: withdrawn_value.toString(),
    state_root: state_root.toString(),
    asp_root: asp_root.toString(),
    nullifier_hash: nullifier_hash.toString(),
    new_commitment: new_commitment.toString(),
    context: context.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  const vkey = JSON.parse(
    fs.readFileSync(path.join(path.dirname(zkeyPath), "withdrawal_vkey.json"), "utf8"),
  );
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) throw new Error("fixture proof failed to verify");

  // Public signal order (snarkjs): withdrawn_value, state_root, asp_root,
  // nullifier_hash, new_commitment, context.
  console.log("public signals:", publicSignals);

  fs.mkdirSync(FIXTURE_DIR, { recursive: true });
  fs.writeFileSync(path.join(FIXTURE_DIR, "input.json"), JSON.stringify(input, null, 2));
  fs.writeFileSync(path.join(FIXTURE_DIR, "proof.json"), JSON.stringify(proof, null, 2));
  fs.writeFileSync(path.join(FIXTURE_DIR, "public.json"), JSON.stringify(publicSignals, null, 2));
  // Also record the zero-subtree constants so the contract + SDK stay in sync.
  fs.writeFileSync(
    path.join(FIXTURE_DIR, "zeros.json"),
    JSON.stringify(zeros.map(String), null, 2),
  );
  console.log("verified; wrote", FIXTURE_DIR);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
