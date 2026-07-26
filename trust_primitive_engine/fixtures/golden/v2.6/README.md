# TPE 2.6 Evidence Provenance Golden Corpus

This corpus freezes deterministic end-to-end behavior for
`evidence_issuer_in`, `evidence_type_in`, and
`evidence_distinct_issuers_at_least`.

It covers satisfied evaluation, one independent failure per predicate, empty
Decision Context 3 evidence, unavailable provenance in Decision Context 2,
recursive failure projection, deterministic replay, compact serialization, and
SHA-256 result hashes.

The provenance fields are context-attested declarations. This corpus does not
assert independent authentication of external evidence issuers.
