pragma circom 2.1.6;

// =============================================================================
// Conditional Disclosure Circuit — V1 (Opaque Cash)  ·  spec/conditional-disclosure.md §4
//
// Proves, in one Groth16 proof, that a privacy-pool note QUALIFIES for
// disclosure and discloses it:
//   1. commitment = Poseidon(value, label, Poseidon(nullifier, secret)) is in the
//      pool's append-only STATE tree at `state_root` (depth-20 Merkle inclusion).
//   2. Qualification: value > threshold (both range-checked < 2^128). A proof for
//      a below-threshold note is unsatisfiable — custodians can authorize a
//      disclosure request blind and rely on this constraint.
//   3. disclosure_nullifier = Poseidon(nullifier, context, DOMAIN_DISCLOSURE),
//      consumed once per (note, context) in the disclosure verifier's registry
//      (spec/nullifier-registry.md). This constraint also binds `context` — the
//      keccak commitment to (policyId, caseId, requester) that the custodian
//      quorum FROST-signs — so no dummy-square binding is needed.
//   4. `value` and `label` are PUBLIC: they are the disclosed data. `label`
//      links the note to its Deposit event (provenance); `value` is the hidden
//      amount being reported.
//
// The proof deliberately does NOT include association-set membership: disclosure
// is orthogonal to withdrawal compliance (a tainted deposit must be disclosable).
//
// Public signals (snarkjs order): value, label, threshold, state_root,
//                                 disclosure_nullifier, context.
// =============================================================================

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// keccak256("opaque/disclosure/v1") mod r  (spec/conditional-disclosure.md §7)
function DOMAIN_DISCLOSURE() {
    return 2892858644728810973983554811705195156385130922452064297470708309156017996001;
}

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

template ConditionalDisclosure(levels) {
    // ── Private: the note's secret openings ───────────────────────────────────
    signal input nullifier;
    signal input secret;
    // ── Private: state-tree path ──────────────────────────────────────────────
    signal input state_siblings[levels];
    signal input state_index[levels];

    // ── Public (declared in the §4 public-signal order) ───────────────────────
    signal input value;                  // disclosed amount
    signal input label;                  // disclosed deposit identifier
    signal input threshold;              // policy qualification bound
    signal input state_root;             // a known pool state root
    signal input disclosure_nullifier;   // consumed on-chain
    signal input context;                // binds (policyId, caseId, requester)

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

    // ── 2. qualification: value > threshold ───────────────────────────────────
    // Range-check both to 128 bits (prevents field wraparound in the comparator).
    component value_bits = Num2Bits(128);
    value_bits.in <== value;
    component threshold_bits = Num2Bits(128);
    threshold_bits.in <== threshold;

    component gt = GreaterThan(128);
    gt.in[0] <== value;
    gt.in[1] <== threshold;
    gt.out === 1;

    // ── 3. disclosure nullifier (also binds context) ──────────────────────────
    component null_hasher = Poseidon(3);
    null_hasher.inputs[0] <== nullifier;
    null_hasher.inputs[1] <== context;
    null_hasher.inputs[2] <== DOMAIN_DISCLOSURE();
    null_hasher.out === disclosure_nullifier;
}

// Depth 20, matching the pool's state tree.
component main {public [
    value,
    label,
    threshold,
    state_root,
    disclosure_nullifier,
    context
]} = ConditionalDisclosure(20);
