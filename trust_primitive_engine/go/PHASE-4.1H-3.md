# Go TPE Phase 4.1H-3 Context Set and Path Predicates

This increment adds reusable Go validation, evaluation, and engine
dispatch for `context_value_in` and `context_path_equals`.

`context_value_in` enforces homogeneous scalar sets of one to 64 entries,
canonical ordering, duplicate rejection, safe integers, and bounded
strings. Evaluation uses strict JSON scalar type and value equality.

`context_path_equals` requires two distinct canonical paths and compares
only found comparable scalars with identical JSON types. Missing paths,
traversal mismatches, containers, type mismatches, and unequal values are
ordinary unsatisfied results.

The normative failure codes are `CONTEXT_VALUE_NOT_IN_SET` and
`CONTEXT_PATH_VALUES_NOT_EQUAL`.
