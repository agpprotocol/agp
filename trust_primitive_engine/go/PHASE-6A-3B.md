# Phase 6A-3B — Mixed Policy-Reference Evaluation Parity

Phase 6A-3B extends Python/Go byte-identical evaluation parity to mixed compositions containing policy_reference nodes.

The executable suite contains 12 deterministic vectors covering direct, transitive, and shared policy references combined with signer, context, evidence, and evaluation-time primitives inside all_of, any_of, and not.

The phase also fixes Go matched_signers projection for policy_reference results. Signers matched inside a referenced policy are now projected to the reference node and can be aggregated by enclosing compositions.

Each vector builds a complete Trust Policy, policy set, and Signed Decision Context, evaluates through Python evaluate_verified_object and Go agp-tpe26-reproduce, and requires byte-identical canonical JSON output.

Expected result: TPE Python/Go mixed policy-reference evaluation parity: 12/12 passed
