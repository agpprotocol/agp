# Go TPE Phase 4.1D Role Threshold Primitives

This increment ports `role_threshold` and `role_weight_threshold`.

Both primitives evaluate only authenticated signers that already survived the
root policy authorization and eligible-role projection. Participant role and
weight values are read from the verified Decision Context and remain available
through recursive composition and policy-reference evaluation.
