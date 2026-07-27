# Go TPE Phase 4.1H-1 Context Projection and Path Resolution

This increment adds the bounded proposal projection required by contextual
predicates and a deterministic restricted path resolver.

The public and internal Go context models now preserve `proposal.type` and
`proposal.payload`. The Signed Decision Context path decodes the verified
context with `UseNumber` semantics, and public-to-internal conversion
deeply detaches JSON objects and arrays.

The reusable resolver implements the canonical `/proposal/payload/` path
grammar, JSON Pointer escapes, canonical array indexes, safe-integer
handling, exact object lookup, and the `found`, `missing`, and
`type_mismatch` outcomes.

This phase intentionally adds no new trust primitive dispatch.
