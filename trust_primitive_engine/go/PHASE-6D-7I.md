# Phase 6D-7I — Reusable release readiness preflight

Phase 6D-7I extracts release-readiness checks from inline workflow Python into
a repository-owned command:

```text
trust_primitive_engine/tools/release_readiness_preflight.py
```

The preflight runs after creating an annotated candidate tag and before
creating the corresponding GitHub Release. The publish workflow invokes the
same command again after checking out the released tag and before build or
publication.

The command fails closed unless:

- `pyproject.toml` declares package `agp-tpe`;
- the tag is exactly `tpe-v<project.version>`;
- the tag exists and is annotated;
- the checked-out commit equals the peeled tag commit;
- the exact package version is not already published on PyPI.

This phase does not create tags, releases, or PyPI distributions. The current
`tpe-v2.6.0` tag remains historical and points 129 commits behind the Phase
6D-7H main revision. A future release requires a version bump and a new
annotated tag.
