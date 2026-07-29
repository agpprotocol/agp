# Phase 6D-2 — GitHub Actions runtime maintenance

Phase 6D-2 migrates the official repository setup actions to their current
Node.js 24-compatible major releases.

## Scope

The migration applies to all repository workflows under:

```text
.github/workflows/
```

The updated official actions are:

```text
actions/checkout@v7
actions/setup-go@v7
actions/setup-python@v7
```

The migration preserves each workflow's existing inputs, permissions,
triggers, timeouts, concurrency rules, language versions, and release
behavior.

## Privileged action families

Phase 6D-2 originally left the Pages and PyPI publishing action
families unchanged for separate compatibility and supply-chain
review.

Phase 6D-3 subsequently completed that review and pinned those
privileged actions to immutable commit SHAs. The runtime contract now
verifies that the reviewed references remain present while the
dedicated Phase 6D-3 contract enforces their supply-chain properties.

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_actions_runtime_contract.py
```

It validates nine requirements:

1. the expected workflow inventory is present;
2. checkout usage is migrated to v7;
3. setup-go usage is migrated to v7;
4. setup-python usage is migrated to v7;
5. legacy official action versions are absent;
6. Go release integrity retains full tag checkout and stable Go;
7. TPE conformance retains full history and Python 3.12;
8. historical AGP conformance uses the current stable Go toolchain;
9. privileged action families remain explicitly reviewed.

Expected marker:

```text
AGP GitHub Actions runtime contract: 9/9 passed
```

The contract contributes nine checks to complete TPE development
validation, increasing its expected total from 956 to 965.
