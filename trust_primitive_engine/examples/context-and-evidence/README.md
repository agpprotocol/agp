# TPE 2.4 Context and Evidence Examples

This executable example demonstrates all five TPE 2.4 requirements over a
verified AGP Decision Context 2:

- `context_value_present`
- `context_value_equals`
- `context_integer_at_least`
- `context_integer_at_most`
- `evidence_present`

The requirements are evaluated inside a referenced policy, proving that the
same verified Decision Context is propagated across `policy_reference`
boundaries.

## Run

From the repository root:

```bash
bash trust_primitive_engine/examples/context-and-evidence/run_examples.sh
```

Expected final marker:

```text
TPE_2_4_CONTEXT_EVIDENCE_EXAMPLES_PASS
```

## Scenarios

The runner generates, signs, evaluates, and verifies four deterministic
scenarios:

| Scenario | Expected result |
|---|---|
| `satisfied` | All context and evidence requirements are satisfied. |
| `wrong-environment` | `CONTEXT_VALUE_NOT_EQUAL` is projected through the policy reference. |
| `missing-evidence` | Evidence status is `absent`. |
| `digest-mismatch` | Evidence status is `digest_mismatch`. |

Unsatisfied scenarios exit from the evaluator with code `2`. The runner treats
that as a completed deterministic policy decision, not as an infrastructure
failure.

Generated signed contexts and evaluation results remain local and are ignored
by Git.

## Security warning

The private-key seeds in this example are deterministic and public.

They exist only to make the example reproducible. Never use these keys outside
tests, examples, or conformance fixtures.
