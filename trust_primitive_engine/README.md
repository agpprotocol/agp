# AGP Trust Primitive Engine (TPE)

TPE evaluates deterministic trust primitives over cryptographically verified
signer identities bound to an AGP Signed Decision Context.

## Phase 1 primitives

- `required_signer`
- `signer_threshold`
- `global_signature_threshold`
- `global_weight_threshold`

All requirements use AND composition in Trust Policy 2.0 Phase 1.

## Compatibility

Trust Policy 1.0 remains unchanged. TPE 2.0 uses a separate object type,
schema, evaluator, and evaluation result object.
