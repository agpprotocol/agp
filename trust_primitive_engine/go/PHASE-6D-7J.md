# Phase 6D-7J — Non-destructive candidate release preparation

Phase 6D-7J adds a repository-owned command that validates and records a future
Python release candidate without creating a tag, GitHub Release, or PyPI
publication:

```text
trust_primitive_engine/tools/prepare_release_candidate.py
```

The command requires a stable `X.Y.Z` version that already matches
`pyproject.toml`. It then fails closed unless:

- the tracked worktree and index are clean;
- package identity remains `agp-tpe`;
- the corresponding `tpe-vX.Y.Z` tag is absent locally and remotely;
- the exact version is absent from PyPI;
- complete TPE development validation succeeds.

Successful preparation writes deterministic JSON, Markdown, and the complete
validation log. Those files are evidence for a later, separately authorized
tag and GitHub Release operation.

Historical release statements remain historical evidence. In particular, the
TPE 2.6.0 statements that record `796/796` must not be rewritten to claim the
current `1177/1177` validation result.
