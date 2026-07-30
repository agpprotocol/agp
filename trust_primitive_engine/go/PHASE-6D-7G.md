# Phase 6D-7G — Trusted release recovery execution

Phase 6D-7G separates trusted recovery tooling from historical release source.

The workflow keeps the reviewed verifier on the workflow revision, fetches the
requested historical tag as data, resolves it to a commit, mounts that commit in
a detached `released-source` worktree, runs verification in that historical
source context, and writes evidence outside the worktree.

It never executes repository tooling from the historical tag and remains
verification-only.

Existing releases through `tpe-v2.5.0` lack the required GitHub Release assets,
so they are expected to fail closed until a future release contains wheel,
source distribution, `SHA256SUMS`, and CycloneDX SBOM assets.
