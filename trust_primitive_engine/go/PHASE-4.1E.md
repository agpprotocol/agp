# Go TPE Phase 4.1E Global Threshold Primitives

This increment ports `global_signature_threshold` and
`global_weight_threshold`.

Global signature count is the number of distinct matched signer identities,
not the number of verified signature objects. Multiple verified keys for one
identity therefore count once. Global weight is the deterministic sum of the
verified Decision Context participant weights for those matched identities.
