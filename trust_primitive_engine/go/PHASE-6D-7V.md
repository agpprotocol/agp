# Phase 6D-7V — Controlled recovery of preexisting candidate evidence

The normal candidate-preparation tool intentionally rejects an existing local
or remote release tag. This preserves the original ordering:

```text
candidate → authorization → local tag → remote tag → draft → publication
```

For `tpe-v2.6.0`, the exact annotated tag already exists while the GitHub
Release and PyPI version remain absent. No historical candidate JSON or
authorization file is available.

Phase 6D-7V adds a separate, read-only recovery path. It does not weaken or
modify normal candidate preparation.

Recovery requires:

1. an explicit full source commit and detached worktree at that commit;
2. package version alignment;
3. an exact local annotated tag peeling to the source commit;
4. an exact remote tag object and peeled commit match;
5. absence of the GitHub Release;
6. absence of the package version on PyPI;
7. a fresh complete `1317/1317` validation run.

The tool emits:

- canonical `release-candidate.json`;
- separate `release-candidate-recovery.json`;
- complete validation log.

The recovery report binds the candidate SHA-256, tag object, peeled commit,
repository, validation result, and absence proofs. It explicitly records that
no Git, GitHub Release, PyPI, workflow, or authorization mutation occurred.

Recovery evidence is not authorization. A later operator decision must remain
separate and explicit.
