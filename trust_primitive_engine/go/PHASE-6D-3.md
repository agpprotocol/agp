# Phase 6D-3 — GitHub Actions supply-chain hardening

Phase 6D-3 hardens the workflows that publish the AGP website and the
`agp-tpe` Python package.

## Scope

The phase covers four privileged action references:

```text
actions/configure-pages
actions/upload-pages-artifact
actions/deploy-pages
pypa/gh-action-pypi-publish
```

Each action is upgraded to the reviewed release and pinned to its full
immutable commit SHA:

```text
actions/configure-pages
  45bfe0192ca1faeb007ade9deae92b16b8254a0d  # v6.0.0

actions/upload-pages-artifact
  7b1f4a764d45c48632c6b24a0339c27f5614fb0b  # v4.0.0

actions/deploy-pages
  cd2ce8fcbc39b97be8ca5fce6e763baed58fa128  # v5.0.0

pypa/gh-action-pypi-publish
  dc37677b2e1c63e2034f94d8a5b11f265b73ba33  # v1.14.2
```

For the PyPI action, the pinned commit is both the peeled commit for
the annotated `v1.14.2` tag and the `release/v1` branch tip at the
time of review.

## Security properties preserved

The Pages workflow retains:

- read-only repository contents;
- `pages: write`;
- `id-token: write`;
- the protected `github-pages` environment;
- bounded deployment concurrency.

The PyPI workflow retains:

- release-event-only execution;
- the `tpe-v` tag guard;
- checkout of the released tag with credentials disabled;
- package/tag version matching;
- refusal to republish an existing version;
- distribution validation;
- OIDC Trusted Publishing through the `pypi` environment.

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_actions_supply_chain_contract.py
```

It validates eight requirements:

1. the reviewed privileged references are present;
2. all four references use full commit SHAs;
3. moving tags are absent for privileged actions;
4. Pages permissions remain least privilege;
5. Pages deployment remains environment-bound;
6. PyPI publishing retains OIDC Trusted Publishing;
7. PyPI checkout remains bound to the released tag;
8. PyPI release guards and non-republishing checks remain present.

Expected marker:

```text
AGP GitHub Actions supply-chain contract: 8/8 passed
```

The contract contributes eight checks to complete TPE development
validation, increasing its expected total from 965 to 973.
