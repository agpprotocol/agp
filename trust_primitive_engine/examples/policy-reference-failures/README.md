# TPE 2.3 Policy Reference Failure Examples

Executable negative examples for deterministic `policy_reference` behavior.

Cases:

- `digest_mismatch` → `POLICY_REFERENCE_DIGEST_MISMATCH`
- `missing_policy` → `POLICY_REFERENCE_NOT_FOUND`
- `ineligible_role` → `POLICY_REFERENCE_NOT_SATISFIED`
- `cycle_detected` → `POLICY_REFERENCE_CYCLE`

Run from the repository root:

```bash
bash trust_primitive_engine/examples/policy-reference-failures/run_examples.sh
```

Expected final line:

```text
POLICY_REFERENCE_FAILURE_EXAMPLES_PASS
```

The example reuses the deterministic demonstration keys from the positive
policy-reference example. Those keys are public test material and must never
be used in production.
