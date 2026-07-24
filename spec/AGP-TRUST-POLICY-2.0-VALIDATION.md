# AGP Trust Policy 2.0 — Schema/runtime validation note

The JSON Schema defines the portable structural contract. The Python runtime
MUST reject every policy rejected by the shared structural contract.

The runtime additionally enforces canonical ordering invariants that are not
expressible through the current JSON Schema without custom vocabulary:

- `eligible_roles` must be lexicographically sorted;
- `requirements` must be sorted by `requirement_id`;
- signer and role identifier arrays must be lexicographically sorted.

These runtime-only restrictions are intentional and are covered by the
schema/runtime parity suite.
