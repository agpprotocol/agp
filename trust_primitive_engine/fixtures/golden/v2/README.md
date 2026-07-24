# AGP Trust Policy 2.x Golden Compatibility Corpus

This directory freezes representative compatibility expectations for version 2.

Categories:

- schema accept / runtime accept
- schema reject / runtime reject
- schema accept / runtime reject for canonical or relational constraints
- recursive composition coverage for `all_of`, `any_of`, and `not`

Rules:

1. Existing fixtures should not be edited casually.
2. Intentional compatibility changes require a manifest update and review.
3. New regressions should add a minimal fixture.
4. Every JSON fixture must be listed exactly once in `manifest.json`.
