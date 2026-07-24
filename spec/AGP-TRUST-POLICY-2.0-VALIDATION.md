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

## Trust Primitive Engine 2.2 recursive validation

The shared JSON Schema additionally validates the recursive structural shape
of `all_of`, `any_of`, and `not`, including required members, closed objects,
child types, and minimum composition arity.

The runtime additionally enforces recursive invariants that require complete
tree analysis:

- child arrays of `all_of` and `any_of` are lexicographically ordered by
  `requirement_id`;
- every `requirement_id` is globally unique across all branches;
- requirement-tree depth does not exceed 8;
- the complete requirement tree does not exceed 256 nodes;
- every nested primitive is supported and valid before evaluation begins.

The schema/runtime parity suite distinguishes shared structural rejection from
intentional runtime-only canonical or relational rejection.

The reference complete validation suite currently passes 353 of 353 checks.
Property hardening covers 8 properties with 2,000 generated examples, and the
versioned golden compatibility corpus contains 22 cases.
