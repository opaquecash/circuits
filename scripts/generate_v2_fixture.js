#!/usr/bin/env node
// Generate the committed V2 proof fixture (test/fixtures/v2/).
//
// Builds a deterministic, valid witness input for stealth_reputation.circom,
// then proves it with the production proving key (the same zkey shipped in
// app/public/circuits/v2/ whose verification key is transcribed into
// ethereum/infra/contracts/Groth16VerifierV2.sol and the Solana
// groth16-verifier program).
//
// Usage:
//   node scripts/generate_v2_fixture.js <stealth_reputation.wasm> <stealth_reputation_final.zkey>
//
// The fixture is deterministic: fixed private inputs, all-zero-ish Merkle
// siblings, leaf always the left child. Re-running produces identical
// input.json/public.json (proof.json differs per run — Groth16 proofs are
// randomised — but any run verifies against the same vkey).

const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");

const LEVELS = 20;
const FIXTURE_DIR = path.join(__dirname, "..", "test", "fixtures", "v2");

async function main() {
  const [wasmPath, zkeyPath] = process.argv.slice(2);
  if (!wasmPath || !zkeyPath) {
    console.error("usage: generate_v2_fixture.js <circuit.wasm> <final.zkey>");
    process.exit(2);
  }

  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (inputs) => F.toObject(poseidon(inputs));

  // Fixed private inputs (arbitrary but stable field elements)
  const stealth_pk = 12345678901234567890123456789012345678901234567890n;
  const schema_id = 777000777000777n;
  const issuer_pk_x = 999888777666555444333222111n;
  const trait_data_hash = H([42n, 43n]);
  const nonce = 31337n;
  const external_nullifier = 0xdeadbeefn;

  // leaf = Poseidon(stealth_pk, schema_id, issuer_pk_x, trait_data_hash, nonce)
  const leaf = H([stealth_pk, schema_id, issuer_pk_x, trait_data_hash, nonce]);

  // Merkle path: sibling at level i is Poseidon(i, i); leaf stays left (index 0)
  const merkle_path = [];
  const merkle_path_indices = [];
  let node = leaf;
  for (let i = 0; i < LEVELS; i++) {
    const sibling = H([BigInt(i), BigInt(i)]);
    merkle_path.push(sibling.toString());
    merkle_path_indices.push("0");
    node = H([node, sibling]);
  }
  const merkle_root = node;

  const nullifier_hash = H([stealth_pk, external_nullifier]);

  const input = {
    stealth_pk: stealth_pk.toString(),
    schema_id: schema_id.toString(),
    issuer_pk_x: issuer_pk_x.toString(),
    trait_data_hash: trait_data_hash.toString(),
    nonce: nonce.toString(),
    merkle_path,
    merkle_path_indices,
    merkle_root: merkle_root.toString(),
    attestation_id: schema_id.toString(),
    external_nullifier: external_nullifier.toString(),
    nullifier_hash: nullifier_hash.toString(),
  };

  fs.mkdirSync(FIXTURE_DIR, { recursive: true });
  fs.writeFileSync(
    path.join(FIXTURE_DIR, "input.json"),
    JSON.stringify(input, null, 2)
  );

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  fs.writeFileSync(
    path.join(FIXTURE_DIR, "proof.json"),
    JSON.stringify(proof, null, 2)
  );
  fs.writeFileSync(
    path.join(FIXTURE_DIR, "public.json"),
    JSON.stringify(publicSignals, null, 2)
  );

  const vkey = JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, "verification_key.json"), "utf8")
  );
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) throw new Error("generated proof does not verify against vkey");
  console.log("fixture written to", FIXTURE_DIR, "— proof verifies ✓");
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
