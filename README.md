# Opaque Cash — Circuits

[![CI](https://github.com/opaquecash/circuits/actions/workflows/circuit-test.yml/badge.svg)](https://github.com/opaquecash/circuits/actions/workflows/circuit-test.yml)

Canonical source of truth for the Opaque Cash zero-knowledge circuits. Both chains
consume this repo as a git submodule, so a circuit change happens here once.

Proof system: **Groth16** (BN254 / alt_bn128). Tree depth: **20**.

## Circuits

| File | Version | Status |
|:---|:---|:---|
| `v2/stealth_reputation.circom` | **V2** | **Canonical.** Schema-bound issuance; verified on both chains. |

V2 binds the leaf to `Poseidon(stealth_pk, schema_id, issuer_pk_x, trait_data_hash, nonce)`
and takes `nullifier_hash` as a public input; public signals are
`[merkle_root, attestation_id, external_nullifier, nullifier_hash]`. See the `.circom`
header for the full signal layout.

> **V1 (`stealth_attestation`) was retired 2026-06-10.** No deployed verifier accepts V1
> proofs (the Solana V1 path never functioned — see `spec/changelog.md` — and Ethereum is
> V2-only). The file lives in git history before this date if ever needed for archaeology.

## Layout

```
circuits/
├── v2/stealth_reputation.circom V2 circuit (canonical)
├── scripts/download_ptau.sh      fetches the Powers of Tau (not committed)
├── scripts/generate_v2_fixture.js regenerates test/fixtures/v2/ from the production zkey
├── test/
│   ├── v2.test.js               V2 verification tests (npm test)
│   ├── fixtures/v2/             production vkey + real proof fixture (committed)
│   ├── test_vectors.json        DKSAP test vectors (cross-validated)
│   └── generate_vectors.py      reproducible vector generator
├── package.json
└── .gitignore                   excludes build/, *.ptau, *.zkey, *.sym
```

## Build

Prerequisites: [circom](https://docs.circom.io) 2.1.6+, [snarkjs](https://github.com/iden3/snarkjs) 0.7+, Node 18+.

```bash
npm install              # circomlib (resolved at node_modules/ for the V2 includes)
npm run download:ptau    # fetch pot16_final.ptau (~75 MB, NOT committed)
npm run build            # V2 → r1cs + wasm under v2/build/
npm run setup            # Groth16 trusted setup (dev only)
```

The `*.ptau`, `*.zkey`, `build/` artifacts are intentionally git-ignored and regenerated
locally / in CI. `npm run build` drops the C++ witness generator (`--c`); proving runs
in-browser via the WASM generator.

> **Trusted setup is development-only.** The Hermez Phase-1 ptau plus a local Phase-2
> contribution is fine for testing; a production deployment requires an audited
> multi-party ceremony.

### Powers of Tau strategy

`pot16` (2^16 = 65,536 constraints) is the pinned ceremony file. Measured size:
V2 `stealth_reputation` = 5,421 constraints —
it fits with an order of magnitude of headroom, so no switch to
`powersOfTau28_hez_final_17.ptau` is needed. `npm test` asserts the V2 constraint
count still fits pot16 and fails the build if a circuit change outgrows it.

## Tests

```bash
npm test
```

`test/v2.test.js` runs two layers:

1. **Production-key checks** (no build needed): the committed fixture in
   `test/fixtures/v2/` is a *real* Groth16 proof generated with the production
   proving key — the same setup whose verification key is transcribed into
   `ethereum`'s `Groth16VerifierV2.sol` and `solana`'s `groth16-verifier` program.
   The tests verify it (and reject tampered variants) against the committed
   `verification_key.json`, pinning the production vkey in CI.
2. **Live round-trip** (CI, needs `npm run build` + `npm run download:ptau`):
   witness → fresh Groth16 setup → prove → verify, plus a negative check that a
   fresh-setup proof does *not* verify under the production vkey.

Regenerate the fixture after a circuit change (requires the production wasm/zkey):

```bash
npm run generate:fixture -- <stealth_reputation.wasm> <stealth_reputation_final.zkey>
```

## Test vectors

`test/test_vectors.json` holds the canonical DKSAP vectors (one HKDF derivation vector
plus three round trips). They are verified byte-for-byte across three independent
implementations — the Rust scanner (`k256`), the `@noble` TypeScript SDK, and the
pure-Python generator — and are referenced by `spec/CSAP.md`. Regenerate with:

```bash
python3 test/generate_vectors.py
```

## Consumers

The Ethereum and Solana repos consume this repo as a git submodule, so a circuit change is
a single PR here. Keep this repo the source of truth and update consumers via the submodule.
