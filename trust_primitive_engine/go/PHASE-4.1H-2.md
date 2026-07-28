# Go TPE Phase 4.1H-2 Basic Context Predicates

This increment adds reusable Go validation, evaluation, and engine
dispatch for:

- `context_value_present`;
- `context_value_equals`;
- `context_integer_at_least`;
- `context_integer_at_most`.

The implementation uses the Phase 4.1H-1 restricted path resolver,
preserves strict scalar type equality, enforces AGP safe integers and
bounded expected strings, omits containers and oversized strings from
result values, emits empty matched-signers lists, and preserves the
normative failure codes.
