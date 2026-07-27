# Go TPE Phase 4.1C Signer Cardinality Primitives

This increment ports `at_least_n_signers`, `at_most_n_signers`, and
`exactly_n_signers`.

All three primitives evaluate against the deterministic authorized and
role-eligible signer projection already threaded through recursive evaluation.
Validation preserves canonical signer ordering, uniqueness, minimum set size,
and Python-compatible cardinality bounds.
