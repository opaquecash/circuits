# Opaque — Circuits

[![CI](https://github.com/opaquecash/circuits/actions/workflows/circuit-test.yml/badge.svg)](https://github.com/opaquecash/circuits/actions/workflows/circuit-test.yml)

Canonical source of truth for the Opaque zero-knowledge circuits. The `ethereum` and
`solana` repos consume this repo as a git submodule, so a circuit change happens here
once. Proof system: **Groth16** (BN254), Poseidon hashing, depth-20 Merkle trees,
all inside the pinned `pot16` Powers of Tau (65,536-constraint ceiling — `npm test`
asserts every circuit still fits).

## Circuits

| Circuit | Constraints | Public signals | Spec |
|---|---|---|---|
| `v2/stealth_reputation.circom` | 5,421 | `merkle_root, attestation_id, external_nullifier, nullifier_hash` | [PSR](https://github.com/opaquecash/spec/blob/main/PSR.md) |
| `v2/withdrawal.circom` | 23,852 | `withdrawn_value, state_root, asp_root, nullifier_hash, new_commitment, context` | [privacy-pool §4.1](https://github.com/opaquecash/spec/blob/main/privacy-pool.md) |
| `v2/association.circom` | minimal | `asp_root, label` (off-chain ASP statement) | [privacy-pool §4.2](https://github.com/opaquecash/spec/blob/main/privacy-pool.md) |
| `v2/conditional_disclosure.circom` | 12,517 | `value, label, threshold, state_root, disclosure_nullifier, context` | [conditional-disclosure §4](https://github.com/opaquecash/spec/blob/main/conditional-disclosure.md) |

> V1 (`stealth_attestation`) was retired 2026-06-10; no deployed verifier accepts V1
> proofs. It lives in git history only.

## Build & test

Prerequisites: [circom](https://docs.circom.io) 2.1.6+, Node 18+.

```bash
npm install
npm run download:ptau    # pot16_final.ptau (~75 MB, not committed)
npm run build            # all circuits → r1cs + wasm under v2/build/
npm run setup            # Groth16 trusted setup (development only)
npm test                 # see below
```

Each circuit has a committed fixture under `test/fixtures/` — a **real proof made with
the production proving key** whose verification key is transcribed into the on-chain
verifiers. The tests verify it (pinning the production vkey in CI), reject tampered
variants, and — when `v2/build/` + the ptau exist — run a fresh setup→prove→verify
round-trip. The disclosure suite additionally asserts a below-threshold witness is
unsatisfiable. Regenerate fixtures after a circuit change with the matching
`npm run generate:*-fixture` script.

`scripts/export_solana_vk.py <vkey.json> <NAME>` prints the Rust vkey constants the
Solana programs embed.

> **Trusted setup is development-only.** Production requires an audited multi-party
> ceremony (tracked in `ethereum`'s audit plan).

## Test vectors

`test/test_vectors.json` holds the canonical DKSAP vectors, cross-validated
byte-for-byte against the Rust scanner, the `@noble` TypeScript SDK, and the Python
generator (`test/generate_vectors.py`); referenced by
[CSAP.md](https://github.com/opaquecash/spec/blob/main/CSAP.md).

## License

MIT.
