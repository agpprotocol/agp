# Go TPE Phase 4.1G-1 Evidence Manifest Projection

This increment completes the bounded Go evidence-manifest projection by
preserving `digest` and `media_type` alongside `id`, `evidence_type`, and
`issuer_id`.

The public TPE representation, internal model, JSON decoding path used by
`EvaluateSigned`, and public-to-internal conversion now retain the complete
Decision Context 3 evidence entry required by the evidence presence and
cardinality primitives.

This phase intentionally does not add new primitive evaluation semantics.
