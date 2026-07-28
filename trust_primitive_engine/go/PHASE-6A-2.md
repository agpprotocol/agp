# Go TPE Phase 6A-2 — Leaf Primitive Evaluation Parity

This phase establishes executable Python/Go evaluation parity for the complete
leaf primitive inventory.

The parity runner covers all 27 leaf primitives with exactly two vectors per
primitive:

- one satisfied evaluation;
- one unsatisfied evaluation.

Each vector builds a complete Trust Policy and Signed Decision Context input.
The Python runtime evaluates the input through `evaluate_verified_object`, and
the Go runtime evaluates the same input through the existing
`agp-tpe26-reproduce` command.

The resulting canonical JSON is compared byte for byte. The suite therefore
checks status, signer projection, requirement results, observed and expected
values, failure codes, and top-level evaluation assembly without introducing a
parallel evaluation API.

Coverage: 54/54 executable vectors across 27/27 leaf primitives.
