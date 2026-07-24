# TPE 2.3 Policy Reference Conformance Corpus

This corpus freezes deterministic end-to-end behavior for Trust Policy
references.

Each case contains:

- `root-policy.json`
- `policy-set.json`
- `evaluation-input.json`
- `expected-evaluation.json`

The corpus covers:

- direct satisfied and unsatisfied references;
- nested references;
- shared references and observable multiplicity;
- independent `eligible_roles`;
- references inside `all_of`, `any_of`, and `not`;
- recursive result evidence;
- recursive failure projection;
- deterministic replay.

`expected-evaluation.json` is authoritative. Implementations must produce
the same logical JSON value and canonical compact serialization.
