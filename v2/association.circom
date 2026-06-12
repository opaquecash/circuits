pragma circom 2.1.6;

// =============================================================================
// Association-Set Membership Circuit — V1 (Opaque Cash)  ·  spec/privacy-pool.md §4.2
//
// Standalone statement: `label` is a member of the association tree at `asp_root`.
// NOT used on-chain — the pool's withdrawal proof (withdrawal.circom) folds this
// membership in, so there is no cross-proof binding gap. This circuit is the building
// block Association Set Providers use off-chain to issue / verify set-membership
// statements about a deposit's label, and documents the sub-statement in isolation.
//
// Public signals (snarkjs order): asp_root, label.
// =============================================================================

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template Association(levels) {
    signal input label;                   // public
    signal input asp_root;                // public
    signal input siblings[levels];        // private
    signal input index[levels];           // private (0 = left, 1 = right)

    component hashers[levels];
    component mux_left[levels];
    component mux_right[levels];
    signal path[levels + 1];
    path[0] <== label;

    for (var i = 0; i < levels; i++) {
        index[i] * (1 - index[i]) === 0;

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

    asp_root === path[levels];
}

component main {public [label, asp_root]} = Association(20);
