# Phase 6A-3A — Mixed Leaf Composition Evaluation Parity

Phase 6A-3A extends Python/Go evaluation parity from individual leaf primitives to mixed structural compositions.

The executable parity suite covers 12 deterministic vectors using all_of, any_of, not, signer primitives, context primitives, evidence primitives, and evaluation-time primitives.

The corpus includes satisfied and unsatisfied trees, nested mixed-family requirements, multi-branch failure projection, suppression behavior for any_of and not, and deterministic top-level failure ordering.

Each vector builds a complete Trust Policy and Signed Decision Context, evaluates it with Python evaluate_verified_object, executes the existing Go agp-tpe26-reproduce command, and requires byte-identical canonical JSON output.

Expected result: TPE Python/Go mixed composition evaluation parity: 12/12 passed
