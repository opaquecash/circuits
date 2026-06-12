pragma circom 2.1.6;

// =============================================================================
// Privacy Pool Withdrawal Circuit — V1 (Opaque Cash)  ·  spec/privacy-pool.md §4.1
//
// Proves, in one Groth16 proof, that a value-bearing commitment can be partially
// withdrawn:
//   1. commitment = Poseidon(value, label, Poseidon(nullifier, secret)) is in the
//      append-only STATE tree at `state_root` (depth-20 Merkle inclusion).
//   2. `label` is in the ASSOCIATION tree at `asp_root` (depth-20 Merkle inclusion) —
//      the compliance statement: the deposit is in the "clean" set.
//   3. nullifier_hash = Poseidon(nullifier), bound to the SAME nullifier as the
//      commitment, so a depositor cannot withdraw twice under different hashes.
//   4. Value accounting: value, withdrawn_value < 2^128, withdrawn_value <= value,
//      remainder = value - withdrawn_value, and
//      new_commitment = Poseidon(remainder, label, Poseidon(new_nullifier, new_secret)).
//      The remainder keeps the SAME label, so it stays in the association set.
//   5. `context` is bound into the proof (front-running / malleability protection):
//      the contract recomputes it from the withdrawal recipient/fee/scope.
//
// Public signals (snarkjs order): withdrawn_value, state_root, asp_root,
//                                 nullifier_hash, new_commitment, context.
// =============================================================================

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// Depth-`levels` Merkle inclusion of `leaf` under `root`, given siblings + direction bits.
template MerkleInclusion(levels) {
    signal input leaf;
    signal input root;
    signal input siblings[levels];
    signal input index[levels];          // 0 = leaf on the left, 1 = on the right

    component hashers[levels];
    component mux_left[levels];
    component mux_right[levels];
    signal path[levels + 1];
    path[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        index[i] * (1 - index[i]) === 0; // binary

        mux_left[i] = Mux1();
        mux_left[i].c[0] <== path[i];
        mux_left[i].c[1] <== siblings[i];
        mux_left[i].s <== index[i];

        mux_right[i] = Mux1();
        mux_right[i].c[0] <== siblings[i];
        mux_right[i].c[1] <== path[i];
        mux_right[i].s <== index[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux_left[i].out;
        hashers[i].inputs[1] <== mux_right[i].out;
        path[i + 1] <== hashers[i].out;
    }

    root === path[levels];
}

template Withdrawal(levels) {
    // ── Private: the spent commitment's openings ──────────────────────────────
    signal input value;
    signal input label;
    signal input nullifier;
    signal input secret;
    // ── Private: the remainder commitment's openings ──────────────────────────
    signal input new_nullifier;
    signal input new_secret;
    // ── Private: Merkle paths ─────────────────────────────────────────────────
    signal input state_siblings[levels];
    signal input state_index[levels];
    signal input asp_siblings[levels];
    signal input asp_index[levels];

    // ── Public ────────────────────────────────────────────────────────────────
    signal input withdrawn_value;
    signal input state_root;
    signal input asp_root;
    signal input nullifier_hash;
    signal input new_commitment;
    signal input context;

    // ── Reconstruct the commitment ────────────────────────────────────────────
    component precommit = Poseidon(2);
    precommit.inputs[0] <== nullifier;
    precommit.inputs[1] <== secret;

    component commit = Poseidon(3);
    commit.inputs[0] <== value;
    commit.inputs[1] <== label;
    commit.inputs[2] <== precommit.out;

    // ── 1. commitment ∈ state tree ────────────────────────────────────────────
    component state_proof = MerkleInclusion(levels);
    state_proof.leaf <== commit.out;
    state_proof.root <== state_root;
    for (var i = 0; i < levels; i++) {
        state_proof.siblings[i] <== state_siblings[i];
        state_proof.index[i] <== state_index[i];
    }

    // ── 2. label ∈ association tree ───────────────────────────────────────────
    component asp_proof = MerkleInclusion(levels);
    asp_proof.leaf <== label;
    asp_proof.root <== asp_root;
    for (var i = 0; i < levels; i++) {
        asp_proof.siblings[i] <== asp_siblings[i];
        asp_proof.index[i] <== asp_index[i];
    }

    // ── 3. nullifier binding ──────────────────────────────────────────────────
    component null_hasher = Poseidon(1);
    null_hasher.inputs[0] <== nullifier;
    null_hasher.out === nullifier_hash;

    // ── 4. value accounting ───────────────────────────────────────────────────
    // Range-check value and withdrawn_value to 128 bits (prevents field wraparound).
    component value_bits = Num2Bits(128);
    value_bits.in <== value;
    component withdrawn_bits = Num2Bits(128);
    withdrawn_bits.in <== withdrawn_value;

    // withdrawn_value <= value
    component le = LessEqThan(128);
    le.in[0] <== withdrawn_value;
    le.in[1] <== value;
    le.out === 1;

    signal remainder;
    remainder <== value - withdrawn_value;

    component new_precommit = Poseidon(2);
    new_precommit.inputs[0] <== new_nullifier;
    new_precommit.inputs[1] <== new_secret;

    component new_commit = Poseidon(3);
    new_commit.inputs[0] <== remainder;
    new_commit.inputs[1] <== label;          // remainder keeps the same label
    new_commit.inputs[2] <== new_precommit.out;
    new_commit.out === new_commitment;

    // ── 5. context binding ────────────────────────────────────────────────────
    // Bind `context` into the constraint system so the proof is non-malleable w.r.t.
    // the withdrawal recipient/fee/scope the contract recomputes. The squaring is a
    // dummy constraint that forces `context` to be a real public signal.
    signal context_sq;
    context_sq <== context * context;
}

// Depth 20 (~1.05M leaves) for both the state and association trees.
component main {public [
    withdrawn_value,
    state_root,
    asp_root,
    nullifier_hash,
    new_commitment,
    context
]} = Withdrawal(20);
