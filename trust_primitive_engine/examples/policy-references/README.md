# TPE 2.3 Policy Reference Example

This example demonstrates a complete verified evaluation using:

- one root Trust Policy;
- one referenced Trust Policy;
- an explicit policy set;
- independent `eligible_roles`;
- two deterministic Ed25519 demonstration keys;
- an AGP Decision Context 2;
- a doubly signed AGP Signed Decision Context 2;
- TPE 2.3 recursive policy evaluation.

Run from the repository root:

```bash
bash trust_primitive_engine/examples/policy-references/run_example.sh
```

Expected final status:

```text
POLICY_REFERENCE_EXAMPLE_PASS
```

The generated evaluation is written to:

```text
trust_primitive_engine/examples/policy-references/evaluation-result.json
```

## Security warning

The private-key seeds in this example are deterministic and public.

They exist only to make the example reproducible. Never use these keys outside
tests, examples, or conformance fixtures.
