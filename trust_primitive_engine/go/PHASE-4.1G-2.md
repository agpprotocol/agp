# Go TPE Phase 4.1G-2 Evidence Presence and Count Primitives

This increment adds reusable Go evaluation and validation for:

- `evidence_present`;
- `evidence_count_at_least`.

The implementation preserves the Python semantics for exact evidence-ID
presence, optional digest and media-type bindings, mismatch observations,
unique evidence counting, optional media-type filtering, sorted evidence
identifiers, failure codes, and empty matched-signers projections.

Evidence declarations are evaluated only from the supplied verified
Decision Context. External evidence content is never fetched or parsed.
