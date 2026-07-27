# Go TPE Phase 2A Strict JSON Parsing

## Scope

This increment extracts strict JSON loading and scalar conversion helpers from
the bounded reproducer into `internal/parser`.

The CLI keeps its existing local helper names as thin delegates, preserving
messages, exit behavior, receipts, evaluation, and byte output.

Requirement, policy, composition, and policy-reference validation remain
unchanged for the next controlled extraction.
