# AGP Conformance Profile 0.3

This profile tests resolution semantics independently of transport, storage,
identity providers and language-specific cryptography libraries.

## Input profile

Each vector contains:

- `proposal_id`
- `snapshot_id`
- `members`
- `rule`
- `ballots`
- `objections`
- `revocations`
- `active_evidence_manifest`
- `closing_time`

Inputs are assumed to have passed envelope parsing. The resolver still validates:

- membership;
- proposal and snapshot references;
- positions;
- duplicate/equivocating ballots;
- revocation policy;
- evidence-manifest freshness;
- quorum;
- role vetoes;
- blocking objections;
- tie policy.

## Canonical output

Both implementations MUST emit UTF-8 JSON with:

- lexicographically sorted object keys;
- no insignificant whitespace;
- arrays sorted where the profile defines set semantics;
- integral tally values;
- a final newline.

`input_root` is SHA-256 over the canonical JSON encoding of the normalized,
valid resolution inputs.

## Required outcome order

1. review-triggering validation issue;
2. role veto;
3. blocking objection;
4. quorum failure;
5. approval threshold;
6. tie policy;
7. rejection.

## Conformance criterion

A vector passes only when the Python and Go output files are byte-for-byte
identical and the result matches the vector's expected outcome.
